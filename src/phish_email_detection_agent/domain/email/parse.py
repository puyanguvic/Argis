"""Input normalization and EML parsing utilities."""

from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

from phish_email_detection_agent.domain.email.models import EmailInput
from phish_email_detection_agent.domain.url.extract import extract_urls
from phish_email_detection_agent.tools.text.text_model import normalize_text


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.anchor_pairs: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value for key, value in attrs}
        if tag.lower() == "a":
            href = (attrs_map.get("href") or "").strip()
            self._current_href = href if href else None
            self._anchor_text = []
            if href.startswith(("http://", "https://")):
                self.urls.append(href)

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._current_href is None:
            return
        text = normalize_text("".join(self._anchor_text))
        self.anchor_pairs.append((self._current_href, text))
        self._current_href = None
        self._anchor_text = []


def _looks_like_eml(raw: str) -> bool:
    text = raw.replace("\r\n", "\n").lstrip()
    if not text:
        return False
    if "\n\n" not in text:
        return False
    headers = text.split("\n\n", maxsplit=1)[0].lower()
    return "subject:" in headers and ("from:" in headers or "to:" in headers)


def _coerce_attachment_names(raw: Any) -> list[str]:
    if isinstance(raw, list):
        values: list[str] = []
        for item in raw:
            if isinstance(item, str):
                if item.strip():
                    values.append(item.strip())
            elif isinstance(item, dict):
                name = str(item.get("name") or item.get("filename") or "").strip()
                if name:
                    values.append(name)
        return list(dict.fromkeys(values))
    return []


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    for name in (charset, "utf-8", "latin-1"):
        try:
            return payload.decode(name, errors="replace")
        except Exception:
            continue
    return ""


def _parse_address_list(raw_value: str) -> list[str]:
    pairs = getaddresses([raw_value or ""])
    values: list[str] = []
    for _, addr in pairs:
        clean = normalize_text(addr)
        if clean:
            values.append(clean)
    return list(dict.fromkeys(values))


def _extract_body_parts(message: Message) -> tuple[str, str]:
    body_text: list[str] = []
    body_html: list[str] = []
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        content_disposition = (part.get("Content-Disposition") or "").lower()
        if "attachment" in content_disposition:
            continue
        content_type = (part.get_content_type() or "").lower()
        content = _decode_part(part)
        if not content:
            continue
        if content_type == "text/plain":
            body_text.append(content)
        elif content_type == "text/html":
            body_html.append(content)
    return "\n".join(body_text), "\n".join(body_html)


def _hash_payload(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_urls_from_html(html: str) -> dict[str, list[str]]:
    parser = _LinkCollector()
    parser.feed(html or "")
    href_urls = list(dict.fromkeys(parser.urls))
    text_urls = extract_urls(html or "")

    hidden_links: list[str] = []
    for href, text in parser.anchor_pairs:
        text_urls_in_anchor = extract_urls(text)
        if not text_urls_in_anchor:
            continue
        href_domain = urlparse(href).netloc.lower()
        for shown_url in text_urls_in_anchor:
            shown_domain = urlparse(shown_url).netloc.lower()
            if shown_domain and shown_domain != href_domain:
                hidden_links.append(href)
    return {
        "urls": list(dict.fromkeys(href_urls + text_urls)),
        "hidden_links": list(dict.fromkeys(hidden_links)),
    }


def parse_eml_content(raw_eml: str) -> EmailInput:
    message = BytesParser(policy=policy.default).parsebytes(raw_eml.encode("utf-8", errors="ignore"))
    headers = {key.lower(): str(value) for key, value in message.items()}
    headers_raw = "\n".join(f"{key}: {value}" for key, value in message.items())
    subject = str(message.get("Subject") or "")
    sender = str(message.get("From") or "")
    to = _parse_address_list(str(message.get("To") or ""))
    cc = _parse_address_list(str(message.get("Cc") or ""))
    reply_to = str(message.get("Reply-To") or "")
    return_path = str(message.get("Return-Path") or "")
    message_id = str(message.get("Message-ID") or "")
    sent_date = str(message.get("Date") or "")
    body_text, body_html = _extract_body_parts(message)
    html_urls = extract_urls_from_html(body_html)
    text_urls = extract_urls(body_text)

    attachments: list[str] = []
    attachment_hashes: dict[str, str] = {}
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        clean_name = normalize_text(filename)
        if not clean_name:
            continue
        attachments.append(clean_name)
        payload = part.get_payload(decode=True) or b""
        if payload:
            attachment_hashes[clean_name] = _hash_payload(payload)

    return EmailInput(
        message_id=message_id,
        date=sent_date,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        to=to,
        cc=cc,
        headers=headers,
        headers_raw=headers_raw,
        urls=list(dict.fromkeys(text_urls + html_urls["urls"])),
        attachments=list(dict.fromkeys(attachments)),
        attachment_hashes=attachment_hashes,
    )


def parse_input_payload(raw: str) -> EmailInput:
    original = raw or ""
    stripped = original.strip()
    if not stripped:
        return EmailInput()

    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            payload = json.loads(stripped)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            eml_raw = payload.get("eml") or payload.get("eml_raw")
            eml_path = payload.get("eml_path")
            base = EmailInput()
            if isinstance(eml_raw, str) and eml_raw.strip():
                base = parse_eml_content(eml_raw)
            elif isinstance(eml_path, str) and eml_path.strip():
                p = Path(eml_path.strip())
                if p.exists():
                    base = parse_eml_content(p.read_text(encoding="utf-8", errors="ignore"))

            if isinstance(payload.get("headers"), dict):
                base.headers.update(
                    {str(key).lower(): str(value) for key, value in payload.get("headers", {}).items()}
                )
                base.headers_raw = "\n".join(f"{key}: {value}" for key, value in base.headers.items())

            urls = payload.get("urls")
            attachments = payload.get("attachments")
            subject = payload.get("subject")
            sender = payload.get("sender")
            reply_to = payload.get("reply_to")
            return_path = payload.get("return_path")
            message_id = payload.get("message_id")
            sent_date = payload.get("date")
            to = payload.get("to")
            cc = payload.get("cc")
            body_html = payload.get("body_html")
            body_text = payload.get("body_text")
            text = payload.get("text")
            if isinstance(subject, str) and subject.strip():
                base.subject = subject.strip()
            if isinstance(sender, str) and sender.strip():
                base.sender = sender.strip()
            if isinstance(reply_to, str) and reply_to.strip():
                base.reply_to = reply_to.strip()
            if isinstance(return_path, str) and return_path.strip():
                base.return_path = return_path.strip()
            if isinstance(message_id, str) and message_id.strip():
                base.message_id = message_id.strip()
            if isinstance(sent_date, str) and sent_date.strip():
                base.date = sent_date.strip()
            if isinstance(to, list):
                base.to = list(
                    dict.fromkeys([str(item).strip() for item in to if isinstance(item, str) and item.strip()])
                )
            if isinstance(cc, list):
                base.cc = list(
                    dict.fromkeys([str(item).strip() for item in cc if isinstance(item, str) and item.strip()])
                )
            if isinstance(body_html, str) and body_html.strip():
                base.body_html = body_html
                html_urls = extract_urls_from_html(body_html)
                base.urls = list(dict.fromkeys(base.urls + html_urls["urls"]))
            if isinstance(body_text, str) and body_text.strip():
                base.body_text = body_text
                base.urls = list(dict.fromkeys(base.urls + extract_urls(body_text)))
            if isinstance(text, str) and text.strip():
                base.text = text
                base.urls = list(dict.fromkeys(base.urls + extract_urls(text)))
            if isinstance(urls, list):
                base.urls = list(dict.fromkeys(base.urls + [str(item).strip() for item in urls if str(item).strip()]))
            if attachments is not None:
                base.attachments = list(dict.fromkeys(base.attachments + _coerce_attachment_names(attachments)))
            base = EmailInput.model_validate(base.model_dump(mode="json"))
            return base

    if _looks_like_eml(raw):
        return parse_eml_content(raw)

    clean = normalize_text(original)
    return EmailInput(text=clean, urls=extract_urls(clean))


def summarize_chain_flags(email: EmailInput) -> list[str]:
    flags: list[str] = []
    if email.urls:
        flags.append("contains_url")
    if email.attachments:
        flags.append("contains_attachment")
    if email.body_html and re.search(r"<form|<iframe", email.body_html, flags=re.IGNORECASE):
        flags.append("html_active_content")
    if email.urls and email.attachments:
        flags.append("url_to_attachment_chain")
    return flags
