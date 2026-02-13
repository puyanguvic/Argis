"""Safe URL fetch and HTML risk analysis."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import shlex
import socket
import subprocess
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPErrorProcessor, Request, build_opener


@dataclass
class SafeFetchPolicy:
    enabled: bool = False
    timeout_s: float = 8.0
    connect_timeout_s: float = 3.0
    max_redirects: int = 3
    max_bytes: int = 1_000_000
    allow_private_network: bool = False
    user_agent: str = "ArgisSafeFetcher/3.0"
    sandbox_backend: str = "internal"
    sandbox_exec_timeout_s: float = 20.0
    firejail_bin: str = "firejail"
    docker_bin: str = "docker"
    docker_image: str = "python:3.11-slim"
    docker_workdir: str = "/workspace"


class _NoRedirect(HTTPErrorProcessor):
    def http_response(self, request, response):  # type: ignore[no-untyped-def]
        return response

    https_response = http_response


class _HtmlFeatureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.form_count = 0
        self.password_fields = 0
        self.otp_fields = 0
        self.iframe_count = 0
        self.external_scripts = 0
        self.external_links = 0
        self.title = ""
        self._in_title = False
        self.text_fragments: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if lower == "title":
            self._in_title = True
        if lower == "form":
            self.form_count += 1
        elif lower == "input" and attr_map.get("type", "").lower() == "password":
            self.password_fields += 1
        elif lower == "input":
            input_type = attr_map.get("type", "").lower()
            input_name = attr_map.get("name", "").lower()
            if "otp" in input_type or "otp" in input_name or "code" in input_name:
                self.otp_fields += 1
        elif lower == "iframe":
            self.iframe_count += 1
        elif lower == "script":
            src = attr_map.get("src", "").strip().lower()
            if src.startswith(("http://", "https://", "//")):
                self.external_scripts += 1
        elif lower == "link":
            href = attr_map.get("href", "").strip().lower()
            if href.startswith(("http://", "https://", "//")):
                self.external_links += 1

    def handle_data(self, data: str) -> None:
        clean = " ".join(data.split())
        if clean:
            self.text_fragments.append(clean)
            if self._in_title and not self.title:
                self.title = clean[:160]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False


def _repo_root() -> Path:
    # .../src/phish_email_detection_agent/tools/url_fetch/service.py -> repo root
    return Path(__file__).resolve().parents[4]


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_unspecified
    )


def _check_network_target(url: str, allow_private: bool) -> tuple[bool, str | None]:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        return False, "unsupported_scheme"
    host = parsed.hostname or ""
    if not host:
        return False, "missing_host"

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "dns_resolution_failed"

    for entry in infos:
        addr = entry[4][0]
        if not allow_private and _is_private_ip(addr):
            return False, "private_network_blocked"
    return True, None


def _read_body(response, max_bytes: int) -> tuple[bytes, bool]:  # type: ignore[no-untyped-def]
    chunks: list[bytes] = []
    total = 0
    truncated = False
    while True:
        block = response.read(min(65536, max_bytes - total + 1))
        if not block:
            break
        chunks.append(block)
        total += len(block)
        if total > max_bytes:
            truncated = True
            break
    data = b"".join(chunks)
    if truncated:
        data = data[:max_bytes]
    return data, truncated


def _safe_fetch_url_internal(url: str, cfg: SafeFetchPolicy) -> dict[str, Any]:
    opener = build_opener(_NoRedirect())
    redirect_chain: list[str] = []
    current = url
    final_status = 0
    html = ""

    for _ in range(cfg.max_redirects + 1):
        req = Request(current, method="GET", headers={"User-Agent": cfg.user_agent})
        try:
            with opener.open(req, timeout=cfg.timeout_s) as response:
                status = int(getattr(response, "status", 200))
                final_status = status
                headers = response.headers
                location = headers.get("Location")
                if location and status in {301, 302, 303, 307, 308}:
                    next_url = urljoin(current, location)
                    redirect_chain.append(next_url)
                    current = next_url
                    ok, reason = _check_network_target(current, cfg.allow_private_network)
                    if not ok:
                        return {
                            "url": url,
                            "final_url": current,
                            "redirect_chain": redirect_chain,
                            "status": "blocked",
                            "blocked_reason": reason,
                        }
                    continue

                raw_content_length = headers.get("Content-Length")
                if raw_content_length and raw_content_length.isdigit():
                    if int(raw_content_length) > cfg.max_bytes:
                        return {
                            "url": url,
                            "final_url": current,
                            "redirect_chain": redirect_chain,
                            "status_code": status,
                            "status": "blocked",
                            "blocked_reason": "response_too_large",
                        }

                content_type = (headers.get("Content-Type") or "").lower()
                if "application/x-msdownload" in content_type or "application/octet-stream" in content_type:
                    return {
                        "url": url,
                        "final_url": current,
                        "redirect_chain": redirect_chain,
                        "status_code": status,
                        "status": "blocked",
                        "blocked_reason": "binary_download_blocked",
                        "content_type": content_type,
                    }

                raw, truncated = _read_body(response, cfg.max_bytes)
                if "html" in content_type:
                    html = raw.decode("utf-8", errors="replace")
                return {
                    "url": url,
                    "final_url": current,
                    "redirect_chain": redirect_chain,
                    "status": "ok",
                    "status_code": status,
                    "content_type": content_type,
                    "truncated": truncated,
                    "html": html,
                }
        except HTTPError as exc:
            final_status = int(exc.code)
            return {
                "url": url,
                "final_url": current,
                "redirect_chain": redirect_chain,
                "status": "http_error",
                "status_code": final_status,
            }
        except URLError:
            return {
                "url": url,
                "final_url": current,
                "redirect_chain": redirect_chain,
                "status": "network_error",
            }
        except TimeoutError:
            return {
                "url": url,
                "final_url": current,
                "redirect_chain": redirect_chain,
                "status": "timeout",
            }
    return {
        "url": url,
        "final_url": current,
        "redirect_chain": redirect_chain,
        "status": "blocked",
        "blocked_reason": "redirect_limit_exceeded",
        "status_code": final_status,
    }


def _worker_args(url: str, cfg: SafeFetchPolicy, python_cmd: str) -> list[str]:
    args = [
        python_cmd,
        "-m",
        "phish_email_detection_agent.tools.url_fetch.worker",
        "--url",
        url,
        "--timeout",
        str(cfg.timeout_s),
        "--max-redirects",
        str(cfg.max_redirects),
        "--max-bytes",
        str(cfg.max_bytes),
        "--user-agent",
        cfg.user_agent,
    ]
    if cfg.allow_private_network:
        args.append("--allow-private-network")
    return args


def _invoke_sandbox_worker(url: str, cfg: SafeFetchPolicy) -> dict[str, Any]:
    backend = cfg.sandbox_backend.strip().lower()
    repo_root = _repo_root()
    command: list[str] = []

    if backend == "firejail":
        command = [
            cfg.firejail_bin,
            "--quiet",
            "--noprofile",
            "--private",
            "--caps.drop=all",
            "--seccomp",
            *_worker_args(url, cfg, sys.executable),
        ]
    elif backend == "docker":
        command = [
            cfg.docker_bin,
            "run",
            "--rm",
            "--network",
            "bridge",
            "--cpus",
            "0.5",
            "--memory",
            "256m",
            "--pids-limit",
            "64",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=64m",
            "-e",
            "PYTHONPATH=/workspace/src",
            "-v",
            f"{repo_root}:/workspace:ro",
            "-w",
            cfg.docker_workdir,
            cfg.docker_image,
            *_worker_args(url, cfg, "python"),
        ]
    else:
        return {"url": url, "status": "blocked", "blocked_reason": "invalid_sandbox_backend"}

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=cfg.sandbox_exec_timeout_s,
            check=False,
        )
    except FileNotFoundError:
        return {
            "url": url,
            "status": "sandbox_error",
            "blocked_reason": "sandbox_backend_unavailable",
            "sandbox_backend": backend,
        }
    except subprocess.TimeoutExpired:
        return {
            "url": url,
            "status": "timeout",
            "blocked_reason": "sandbox_execution_timeout",
            "sandbox_backend": backend,
        }

    if completed.returncode != 0:
        return {
            "url": url,
            "status": "sandbox_error",
            "blocked_reason": "sandbox_worker_failed",
            "sandbox_backend": backend,
            "stderr": (completed.stderr or "")[:500],
            "command": shlex.join(command[:8]),
        }

    raw = (completed.stdout or "").strip()
    if not raw:
        return {
            "url": url,
            "status": "sandbox_error",
            "blocked_reason": "sandbox_worker_empty_output",
            "sandbox_backend": backend,
        }
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "url": url,
            "status": "sandbox_error",
            "blocked_reason": "sandbox_worker_invalid_json",
            "sandbox_backend": backend,
            "stdout": raw[:500],
        }
    if not isinstance(payload, dict):
        return {
            "url": url,
            "status": "sandbox_error",
            "blocked_reason": "sandbox_worker_invalid_payload",
            "sandbox_backend": backend,
        }
    payload["sandbox_backend"] = backend
    return payload


def safe_fetch_url(url: str, policy: SafeFetchPolicy | None = None) -> dict[str, Any]:
    cfg = policy or SafeFetchPolicy()
    clean_url = (url or "").strip()
    if not clean_url:
        return {"url": clean_url, "status": "blocked", "blocked_reason": "empty_url"}
    if not cfg.enabled:
        return {"url": clean_url, "status": "skipped", "blocked_reason": "network_fetch_disabled"}

    ok, reason = _check_network_target(clean_url, cfg.allow_private_network)
    if not ok:
        return {"url": clean_url, "status": "blocked", "blocked_reason": reason}

    backend = cfg.sandbox_backend.strip().lower()
    if backend == "internal":
        result = _safe_fetch_url_internal(clean_url, cfg)
        result["sandbox_backend"] = "internal"
        return result
    if backend in {"firejail", "docker"}:
        return _invoke_sandbox_worker(clean_url, cfg)
    return {
        "url": clean_url,
        "status": "blocked",
        "blocked_reason": "invalid_sandbox_backend",
        "sandbox_backend": backend,
    }


def analyze_html_content(html: str) -> dict[str, Any]:
    parser = _HtmlFeatureParser()
    parser.feed(html or "")
    full_text = " ".join(parser.text_fragments).lower()
    suspicious_keywords = [
        token
        for token in (
            "verify account",
            "password",
            "urgent",
            "suspended",
            "security check",
            "wallet",
            "invoice",
            "mfa",
        )
        if token in full_text
    ]
    brand_hits = [
        token
        for token in ("microsoft", "paypal", "apple", "google", "dhl", "amazon", "bank")
        if token in full_text
    ]

    score = 0
    score += min(20, parser.form_count * 8)
    score += min(20, parser.password_fields * 12)
    external_resource_count = parser.external_scripts + parser.external_links + parser.iframe_count
    score += min(15, parser.external_scripts * 5)
    score += min(10, parser.iframe_count * 5)
    score += min(20, len(suspicious_keywords) * 6)
    if brand_hits and (parser.password_fields > 0 or parser.form_count > 0):
        score += 15
    return {
        "login_forms": parser.form_count,
        "form_count": parser.form_count,
        "password_fields": parser.password_fields,
        "has_password_field": parser.password_fields > 0,
        "has_otp_field": parser.otp_fields > 0,
        "otp_fields": parser.otp_fields,
        "external_scripts": parser.external_scripts,
        "external_resource_count": external_resource_count,
        "iframes": parser.iframe_count,
        "title": parser.title,
        "suspicious_keywords": suspicious_keywords,
        "brand_hits": brand_hits,
        "impersonation_score": min(100, score),
    }


def analyze_url_target(url: str, policy: SafeFetchPolicy | None = None) -> dict[str, Any]:
    fetch = safe_fetch_url(url, policy=policy)
    html_analysis: dict[str, Any] = {}
    if fetch.get("status") == "ok" and isinstance(fetch.get("html"), str):
        html_analysis = analyze_html_content(fetch.get("html", ""))
    result = {
        "url": url,
        "fetch": fetch,
        "html_analysis": html_analysis,
    }
    risk = 0
    if fetch.get("status") in {"blocked", "network_error", "timeout", "sandbox_error"}:
        risk += 20
    if isinstance(html_analysis, dict):
        risk += int(html_analysis.get("impersonation_score", 0) * 0.6)
    result["risk_score"] = min(100, risk)
    return result
