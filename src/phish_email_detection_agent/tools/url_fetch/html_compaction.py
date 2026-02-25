"""Deterministic HTML compaction and feature extraction.

This module converts raw HTML into bounded, audit-friendly signals:

- Visible text sample + ranked snippet candidates
- Form/password/OTP heuristics
- Outbound link/script references (bounded)
- Meta refresh indicators
- Data URI decoding (bounded; text-like only)
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from phish_email_detection_agent.tools.text.encoding import DecodeBudget, normalize_text_layers, parse_data_uri

_SKIP_TEXT_TAGS = {"script", "style", "noscript"}


@dataclass(frozen=True)
class HtmlCompactionPolicy:
    max_visible_text_chars: int = 20_000
    max_fragments: int = 1_000
    max_snippets: int = 8
    max_snippet_chars: int = 280

    max_outbound_links: int = 40
    max_external_scripts: int = 20
    max_form_actions: int = 10
    max_meta_refresh_targets: int = 5
    max_data_uri_reports: int = 3

    decode_budget: DecodeBudget = DecodeBudget()


def _clip_text(value: str, max_chars: int) -> str:
    text = value or ""
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars]


def _is_external_ref(value: str) -> bool:
    raw = (value or "").strip().lower()
    return raw.startswith(("http://", "https://", "//"))


def _maybe_extract_domain(value: str) -> str:
    try:
        parsed = urlparse(value)
    except Exception:
        return ""
    return (parsed.hostname or "").lower()


class _HtmlCompactor(HTMLParser):
    def __init__(self, policy: HtmlCompactionPolicy) -> None:
        super().__init__()
        self.policy = policy

        self._in_title = False
        self._skip_text_depth = 0
        self.title = ""

        self.form_count = 0
        self.password_fields = 0
        self.otp_fields = 0
        self.iframe_count = 0
        self.external_scripts = 0
        self.external_links = 0
        self.meta_refresh = False

        self.text_fragments: list[str] = []
        self._visible_text_len = 0

        self.outbound_links: list[str] = []
        self.external_script_srcs: list[str] = []
        self.form_actions: list[str] = []
        self.meta_refresh_targets: list[str] = []
        self.data_uri_values: list[str] = []

    def _add_text_fragment(self, text: str) -> None:
        if not text:
            return
        if len(self.text_fragments) >= self.policy.max_fragments:
            return
        remaining = max(0, int(self.policy.max_visible_text_chars) - self._visible_text_len)
        if remaining <= 0:
            return
        clipped = text if len(text) <= remaining else text[:remaining]
        if clipped:
            self.text_fragments.append(clipped)
            self._visible_text_len += len(clipped)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if lower == "title":
            self._in_title = True
            return

        if lower in _SKIP_TEXT_TAGS:
            self._skip_text_depth += 1

        if lower == "form":
            self.form_count += 1
            action = (attr_map.get("action") or "").strip()
            if action and len(self.form_actions) < self.policy.max_form_actions:
                self.form_actions.append(_clip_text(action, 300))
        elif lower == "input":
            input_type = (attr_map.get("type") or "").strip().lower()
            input_name = (attr_map.get("name") or "").strip().lower()
            if input_type == "password":
                self.password_fields += 1
            if "otp" in input_type or "otp" in input_name or "code" in input_name:
                self.otp_fields += 1
        elif lower == "iframe":
            self.iframe_count += 1
        elif lower == "script":
            src = (attr_map.get("src") or "").strip()
            if src and _is_external_ref(src):
                self.external_scripts += 1
                if len(self.external_script_srcs) < self.policy.max_external_scripts:
                    self.external_script_srcs.append(_clip_text(src, 300))
        elif lower in {"a", "link"}:
            href = (attr_map.get("href") or "").strip()
            if href and _is_external_ref(href):
                self.external_links += 1
                if len(self.outbound_links) < self.policy.max_outbound_links:
                    self.outbound_links.append(_clip_text(href, 500))
        elif lower == "meta":
            http_equiv = (attr_map.get("http-equiv") or "").strip().lower()
            content = (attr_map.get("content") or "").strip()
            if http_equiv == "refresh" and content:
                self.meta_refresh = True
                if len(self.meta_refresh_targets) < self.policy.max_meta_refresh_targets:
                    self.meta_refresh_targets.append(_clip_text(content, 240))

        # Data URIs commonly appear in img/src, a/href, iframe/src, etc.
        if len(self.data_uri_values) < self.policy.max_data_uri_reports:
            for value in attr_map.values():
                if value and value.strip().lower().startswith("data:"):
                    self.data_uri_values.append(_clip_text(value.strip(), 1200))
                    if len(self.data_uri_values) >= self.policy.max_data_uri_reports:
                        break

    def handle_endtag(self, tag: str) -> None:
        lower = tag.lower()
        if lower == "title":
            self._in_title = False
        if lower in _SKIP_TEXT_TAGS and self._skip_text_depth > 0:
            self._skip_text_depth -= 1

    def handle_data(self, data: str) -> None:
        clean = " ".join((data or "").split())
        if not clean:
            return
        if self._in_title and not self.title:
            self.title = clean[:160]
        if self._skip_text_depth > 0:
            return
        self._add_text_fragment(clean)


def _rank_snippets(fragments: list[str], *, policy: HtmlCompactionPolicy, keywords: set[str]) -> list[str]:
    candidates: list[tuple[int, int, str]] = []
    for idx, fragment in enumerate(fragments):
        lowered = fragment.lower()
        score = 0
        score += 5 if "password" in lowered else 0
        score += 4 if "verify" in lowered else 0
        score += 4 if "login" in lowered else 0
        score += 3 if "mfa" in lowered or "otp" in lowered else 0
        score += 3 if "invoice" in lowered or "payment" in lowered else 0
        score += 2 if "urgent" in lowered or "immediately" in lowered else 0
        score += 2 if any(token in lowered for token in keywords) else 0
        if score <= 0:
            continue
        candidates.append((score, idx, fragment))

    candidates.sort(key=lambda item: (-item[0], item[1]))
    selected: list[str] = []
    for _, _, fragment in candidates[: max(0, int(policy.max_snippets))]:
        selected.append(_clip_text(fragment, policy.max_snippet_chars))
    if not selected:
        selected = [_clip_text(fragment, policy.max_snippet_chars) for fragment in fragments[: policy.max_snippets]]
    return [item for item in selected if item]


def compact_html(html_text: str, *, policy: HtmlCompactionPolicy | None = None) -> dict[str, Any]:
    cfg = policy or HtmlCompactionPolicy()
    parser = _HtmlCompactor(cfg)
    parser.feed(html_text or "")

    visible_text = " ".join(parser.text_fragments)
    normalized = normalize_text_layers(visible_text, budget=cfg.decode_budget)
    normalized_text = str(normalized.get("normalized_sample") or "")

    full_text_lower = normalized_text.lower()
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
        if token in full_text_lower
    ]
    brand_hits = [
        token
        for token in ("microsoft", "paypal", "apple", "google", "dhl", "amazon", "bank")
        if token in full_text_lower
    ]

    data_uri_reports: list[dict[str, Any]] = []
    for value in parser.data_uri_values[: cfg.max_data_uri_reports]:
        report = parse_data_uri(value, budget=cfg.decode_budget)
        if isinstance(report, dict):
            data_uri_reports.append(report)

    outbound_domains = [
        domain
        for domain in (_maybe_extract_domain(item) for item in parser.outbound_links + parser.external_script_srcs)
        if domain
    ]
    outbound_domains = list(dict.fromkeys(outbound_domains))

    snippets = _rank_snippets(parser.text_fragments, policy=cfg, keywords=set(brand_hits))

    return {
        "title": parser.title,
        "visible_text_sample": _clip_text(visible_text, cfg.max_visible_text_chars),
        "snippets": snippets,
        "outbound_links": list(dict.fromkeys(parser.outbound_links))[: cfg.max_outbound_links],
        "outbound_domains": outbound_domains[: cfg.max_outbound_links],
        "external_script_srcs": list(dict.fromkeys(parser.external_script_srcs))[: cfg.max_external_scripts],
        "form_actions": list(dict.fromkeys(parser.form_actions))[: cfg.max_form_actions],
        "meta_refresh": bool(parser.meta_refresh),
        "meta_refresh_targets": list(dict.fromkeys(parser.meta_refresh_targets))[: cfg.max_meta_refresh_targets],
        "data_uri_reports": data_uri_reports,
        "decode": normalized,
        "features": {
            "form_count": parser.form_count,
            "password_fields": parser.password_fields,
            "otp_fields": parser.otp_fields,
            "iframes": parser.iframe_count,
            "external_scripts": parser.external_scripts,
            "external_links": parser.external_links,
        },
        "suspicious_keywords": suspicious_keywords,
        "brand_hits": brand_hits,
    }

