"""Raw email parsing utilities."""

from __future__ import annotations

from datetime import datetime, timezone
from email import message_from_string
from email.message import Message
from email.utils import parsedate_to_datetime

from schemas.email_schema import EmailInput
from tools.url_utils import extract_urls


def _extract_body(msg: Message, content_type: str) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == content_type and not part.get_filename():
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode(errors="ignore"))
        return "\n".join(parts)
    if msg.get_content_type() == content_type:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(errors="ignore")
    return ""


def _parse_received_ts(msg: Message) -> datetime:
    raw_date = msg.get("Date")
    if not raw_date:
        return datetime.now(timezone.utc)
    parsed = parsedate_to_datetime(raw_date)
    if parsed is None:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_raw_email(raw_email: str) -> EmailInput:
    """Parse raw email content into an EmailInput."""

    msg = message_from_string(raw_email)
    body_text = _extract_body(msg, "text/plain") or None
    body_html = _extract_body(msg, "text/html") or None
    raw_headers = "\n".join(f"{key}: {value}" for key, value in msg.items())
    reply_to = msg.get("Reply-To")
    urls = extract_urls([body_text, body_html])
    return EmailInput(
        raw_headers=raw_headers,
        subject=msg.get("Subject", ""),
        sender=msg.get("From", ""),
        reply_to=reply_to,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=[],
        received_ts=_parse_received_ts(msg),
    )
