"""Safe URL fetch and HTML risk analysis."""

from __future__ import annotations

from dataclasses import dataclass
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

from phish_email_detection_agent.tools.text.encoding import analyze_url_obfuscation
from phish_email_detection_agent.tools.url_fetch.html_compaction import compact_html


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
    compacted = compact_html(html or "")
    features = compacted.get("features", {}) if isinstance(compacted.get("features"), dict) else {}

    form_count = int(features.get("form_count", 0) or 0)
    password_fields = int(features.get("password_fields", 0) or 0)
    otp_fields = int(features.get("otp_fields", 0) or 0)
    iframe_count = int(features.get("iframes", 0) or 0)
    external_scripts = int(features.get("external_scripts", 0) or 0)
    external_links = int(features.get("external_links", 0) or 0)
    external_resource_count = external_scripts + external_links + iframe_count

    suspicious_keywords = compacted.get("suspicious_keywords", [])
    brand_hits = compacted.get("brand_hits", [])

    score = 0
    score += min(20, form_count * 8)
    score += min(20, password_fields * 12)
    score += min(15, external_scripts * 5)
    score += min(10, iframe_count * 5)
    if isinstance(suspicious_keywords, list):
        score += min(20, len(suspicious_keywords) * 6)
    if brand_hits and (password_fields > 0 or form_count > 0):
        score += 15
    if compacted.get("meta_refresh"):
        score += 4
    if isinstance(compacted.get("data_uri_reports"), list) and compacted["data_uri_reports"]:
        score += 3

    return {
        "login_forms": form_count,
        "form_count": form_count,
        "password_fields": password_fields,
        "has_password_field": password_fields > 0,
        "has_otp_field": otp_fields > 0,
        "otp_fields": otp_fields,
        "external_scripts": external_scripts,
        "external_resource_count": external_resource_count,
        "iframes": iframe_count,
        "title": str(compacted.get("title", ""))[:160],
        "suspicious_keywords": suspicious_keywords if isinstance(suspicious_keywords, list) else [],
        "brand_hits": brand_hits if isinstance(brand_hits, list) else [],
        "impersonation_score": min(100, score),
        # Context compaction fields (bounded; safe to include in precheck evidence).
        "visible_text_sample": str(compacted.get("visible_text_sample", ""))[:4000],
        "snippets": compacted.get("snippets", []),
        "outbound_links": compacted.get("outbound_links", []),
        "outbound_domains": compacted.get("outbound_domains", []),
        "external_script_srcs": compacted.get("external_script_srcs", []),
        "form_actions": compacted.get("form_actions", []),
        "meta_refresh": bool(compacted.get("meta_refresh", False)),
        "meta_refresh_targets": compacted.get("meta_refresh_targets", []),
        "data_uri_reports": compacted.get("data_uri_reports", []),
        "decode": compacted.get("decode", {}),
    }


def analyze_url_target(url: str, policy: SafeFetchPolicy | None = None) -> dict[str, Any]:
    fetch = safe_fetch_url(url, policy=policy)
    html_analysis: dict[str, Any] = {}
    if fetch.get("status") == "ok" and isinstance(fetch.get("html"), str):
        html_analysis = analyze_html_content(fetch.get("html", ""))
    obfuscation = analyze_url_obfuscation(str(fetch.get("final_url") or url))
    result = {
        "url": url,
        "fetch": fetch,
        "html_analysis": html_analysis,
        "url_obfuscation": obfuscation,
    }
    risk = 0
    if fetch.get("status") in {"blocked", "network_error", "timeout", "sandbox_error"}:
        risk += 20
    if isinstance(html_analysis, dict):
        risk += int(html_analysis.get("impersonation_score", 0) * 0.6)
    if isinstance(obfuscation, dict) and obfuscation.get("flags"):
        risk += 6
    result["risk_score"] = min(100, risk)
    return result
