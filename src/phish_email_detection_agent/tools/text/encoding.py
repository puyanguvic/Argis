"""Encoding normalization utilities.

These helpers are deterministic and budgeted. They are intended to surface
common obfuscation layers (percent-encoding, HTML entities, base64, data URIs)
without executing any decoded content.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import html
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from phish_email_detection_agent.domain.url.extract import extract_urls

_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HTML_ENTITY_RE = re.compile(r"&(?:#\d{1,7}|#x[0-9A-Fa-f]{1,6}|[A-Za-z]{2,32});")
_BASE64_ALLOWED_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL_ALLOWED_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_DATA_URI_RE = re.compile(r"^data:(?P<mime>[^;,]*)(?P<params>(?:;[^,]*)*?),(?P<data>.*)$", re.IGNORECASE)


@dataclass(frozen=True)
class DecodeBudget:
    max_input_chars: int = 12_000
    max_output_chars: int = 12_000
    max_decode_rounds: int = 2

    max_query_params: int = 30
    max_param_value_chars: int = 800
    max_param_samples: int = 8

    max_base64_input_chars: int = 4_000
    max_base64_output_bytes: int = 4_000
    max_base64_text_sample_chars: int = 600

    max_nested_urls: int = 8

    max_data_uris: int = 3
    max_data_uri_input_chars: int = 6_000


def _clip_text(value: str, max_chars: int) -> tuple[str, bool]:
    text = value or ""
    if max_chars <= 0:
        return "", bool(text)
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def _percent_sequence_count(value: str) -> int:
    return len(_PERCENT_ENCODED_RE.findall(value or ""))


def _html_entity_count(value: str) -> int:
    return len(_HTML_ENTITY_RE.findall(value or ""))


def normalize_text_layers(value: str, *, budget: DecodeBudget | None = None) -> dict[str, Any]:
    """Normalize common encodings (HTML entities, percent-encoding) under explicit budgets.

    Returns a small, audit-friendly object suitable for attaching to evidence/provenance.
    """

    cfg = budget or DecodeBudget()
    raw = value or ""
    raw_sample, input_truncated = _clip_text(raw, cfg.max_input_chars)

    percent_count = _percent_sequence_count(raw_sample)
    entity_count = _html_entity_count(raw_sample)

    steps: list[str] = []
    normalized = raw_sample
    output_truncated = False

    if entity_count:
        unescaped = html.unescape(normalized)
        if unescaped != normalized:
            steps.append("html_unescape")
            normalized = unescaped
            normalized, clipped = _clip_text(normalized, cfg.max_output_chars)
            output_truncated = output_truncated or clipped

    for _ in range(max(0, int(cfg.max_decode_rounds))):
        if _percent_sequence_count(normalized) == 0:
            break
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        steps.append("percent_decode")
        normalized = decoded
        normalized, clipped = _clip_text(normalized, cfg.max_output_chars)
        output_truncated = output_truncated or clipped

    return {
        "input_sample": raw_sample,
        "normalized_sample": normalized,
        "decode_steps": steps,
        "input_truncated": input_truncated,
        "output_truncated": output_truncated,
        "percent_encoded_sequences": int(percent_count),
        "html_entity_like_sequences": int(entity_count),
    }


def _pad_base64(value: str) -> str:
    missing = (-len(value)) % 4
    if missing:
        return value + ("=" * missing)
    return value


def _looks_like_base64(value: str) -> bool:
    candidate = (value or "").strip()
    if len(candidate) < 16:
        return False
    if len(candidate) > 50_000:
        return False
    if candidate.count("=") > 2:
        return False
    return bool(_BASE64_ALLOWED_RE.fullmatch(candidate) or _BASE64URL_ALLOWED_RE.fullmatch(candidate))


def try_decode_base64_text(value: str, *, budget: DecodeBudget | None = None) -> dict[str, Any] | None:
    """Try to decode a base64/base64url string into a bounded text sample.

    Returns None when the input does not look like base64 or cannot be decoded safely.
    """

    cfg = budget or DecodeBudget()
    candidate = (value or "").strip()
    if not _looks_like_base64(candidate):
        return None
    if len(candidate) > cfg.max_base64_input_chars:
        return {
            "kind": "base64",
            "status": "skipped",
            "reason": "input_too_large",
            "input_len": len(candidate),
        }

    urlsafe = bool(_BASE64URL_ALLOWED_RE.fullmatch(candidate) and not _BASE64_ALLOWED_RE.fullmatch(candidate))
    padded = _pad_base64(candidate)
    try:
        raw = padded.encode("ascii")
    except UnicodeEncodeError:
        return None

    try:
        decoded = base64.b64decode(
            raw,
            altchars=b"-_" if urlsafe else None,
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None

    if not decoded:
        return None
    if len(decoded) > cfg.max_base64_output_bytes:
        decoded = decoded[: cfg.max_base64_output_bytes]
        truncated_bytes = True
    else:
        truncated_bytes = False

    text = decoded.decode("utf-8", errors="replace")
    sample, truncated_text = _clip_text(text, cfg.max_base64_text_sample_chars)
    if not sample.strip():
        return None

    printable_ratio = 0.0
    if sample:
        printable_ratio = round(sum(1 for ch in sample if ch.isprintable()) / len(sample), 2)

    return {
        "kind": "base64url" if urlsafe else "base64",
        "status": "ok",
        "input_len": len(candidate),
        "decoded_bytes": len(decoded),
        "decoded_bytes_truncated": truncated_bytes,
        "text_sample": sample,
        "text_truncated": truncated_text,
        "printable_ratio": printable_ratio,
    }


def parse_data_uri(value: str, *, budget: DecodeBudget | None = None) -> dict[str, Any] | None:
    """Parse and boundedly decode a data URI.

    For safety and resource control, this returns only small metadata and an optional
    decoded text sample. It never executes decoded content.
    """

    cfg = budget or DecodeBudget()
    raw = (value or "").strip()
    if not raw.lower().startswith("data:"):
        return None
    if len(raw) > cfg.max_data_uri_input_chars:
        return {
            "status": "skipped",
            "reason": "input_too_large",
            "input_len": len(raw),
        }
    match = _DATA_URI_RE.match(raw)
    if not match:
        return {"status": "error", "reason": "invalid_data_uri"}

    mime = (match.group("mime") or "").strip().lower()
    params = (match.group("params") or "").lower()
    data = match.group("data") or ""
    is_base64 = ";base64" in params

    decoded_bytes = b""
    decoded_text_sample = ""
    decoded_truncated = False
    if is_base64:
        b64 = data.strip()
        b64 = _pad_base64(b64)
        try:
            decoded_bytes = base64.b64decode(b64.encode("ascii"), validate=False)
        except Exception:
            return {"status": "error", "reason": "base64_decode_failed", "mime": mime, "is_base64": True}
        if len(decoded_bytes) > cfg.max_base64_output_bytes:
            decoded_bytes = decoded_bytes[: cfg.max_base64_output_bytes]
            decoded_truncated = True
        if mime.startswith("text/") or mime in {"application/json", "application/xml"} or mime.endswith("+xml"):
            decoded_text_sample, clipped = _clip_text(
                decoded_bytes.decode("utf-8", errors="replace"), cfg.max_base64_text_sample_chars
            )
            decoded_truncated = decoded_truncated or clipped
    else:
        decoded_text_sample, clipped = _clip_text(unquote(data), cfg.max_base64_text_sample_chars)
        decoded_truncated = decoded_truncated or clipped

    return {
        "status": "ok",
        "mime": mime,
        "is_base64": bool(is_base64),
        "decoded_bytes": len(decoded_bytes) if is_base64 else 0,
        "decoded_sample": decoded_text_sample,
        "decoded_truncated": decoded_truncated,
    }


def analyze_url_obfuscation(url: str, *, budget: DecodeBudget | None = None) -> dict[str, Any]:
    """Analyze URL query values for common obfuscation layers and nested URLs.

    This does not fetch the URL. It performs deterministic parsing and bounded decoding only.
    """

    cfg = budget or DecodeBudget()
    raw = (url or "").strip()
    parsed = urlparse(raw)
    query = parsed.query or ""
    if not query:
        return {"url": raw, "query_param_count": 0, "flags": [], "nested_urls": [], "decoded_params_sample": []}

    pairs = parse_qsl(query, keep_blank_values=True)
    if len(pairs) > cfg.max_query_params:
        pairs = pairs[: cfg.max_query_params]
        truncated_params = True
    else:
        truncated_params = False

    flags: set[str] = set()
    nested: list[str] = []
    param_samples: list[dict[str, Any]] = []

    query_percent = _percent_sequence_count(query)
    if query_percent:
        flags.add("percent_encoded_query")
    if truncated_params:
        flags.add("query_param_cap_hit")

    for key, value in pairs:
        if not value:
            continue
        raw_value, raw_value_truncated = _clip_text(str(value), cfg.max_param_value_chars)
        analysis = normalize_text_layers(raw_value, budget=cfg)

        interesting = bool(analysis["decode_steps"]) or analysis["percent_encoded_sequences"] or raw_value_truncated
        decoded_value = str(analysis["normalized_sample"] or "")

        found_urls = extract_urls(decoded_value)
        if found_urls:
            flags.add("nested_url_in_query")
            nested.extend(found_urls)
            interesting = True

        base64_report = try_decode_base64_text(decoded_value, budget=cfg) or try_decode_base64_text(raw_value, budget=cfg)
        if isinstance(base64_report, dict) and base64_report.get("status") == "ok":
            decoded_text = str(base64_report.get("text_sample") or "")
            if "http://" in decoded_text or "https://" in decoded_text or "<html" in decoded_text.lower():
                flags.add("base64_decoded_query_value")
                nested.extend(extract_urls(decoded_text))
                interesting = True

        if interesting and len(param_samples) < cfg.max_param_samples:
            entry: dict[str, Any] = {
                "key": _clip_text(str(key), 80)[0],
                "value_sample": raw_value,
                "value_truncated": bool(raw_value_truncated),
                "normalized_sample": _clip_text(decoded_value, 600)[0],
                "decode_steps": list(analysis.get("decode_steps", [])),
            }
            if base64_report:
                entry["base64"] = base64_report
            param_samples.append(entry)

    nested = list(dict.fromkeys(item for item in nested if item))
    if len(nested) > cfg.max_nested_urls:
        nested = nested[: cfg.max_nested_urls]
        flags.add("nested_url_cap_hit")

    return {
        "url": raw,
        "query_param_count": len(pairs),
        "flags": sorted(flags),
        "nested_urls": nested,
        "decoded_params_sample": param_samples,
    }
