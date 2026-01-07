"""Raw email parsing utilities."""

from __future__ import annotations

from email import message_from_string
from email.message import Message

from schemas.email_schema import EmailSchema


def _extract_body(msg: Message) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode(errors="ignore"))
        return "\n".join(parts)
    payload = msg.get_payload(decode=True)
    if payload:
        return payload.decode(errors="ignore")
    return ""


def parse_raw_email(raw_email: str) -> EmailSchema:
    msg = message_from_string(raw_email)
    body = _extract_body(msg)

    raw_headers = {k: v for (k, v) in msg.items()}
    to_list = [addr.strip() for addr in (msg.get("To") or "").split(",") if addr.strip()]
    cc_list = [addr.strip() for addr in (msg.get("Cc") or "").split(",") if addr.strip()]

    return EmailSchema(
        subject=msg.get("Subject"),
        sender=msg.get("From"),
        to=to_list,
        cc=cc_list,
        body=body,
        raw_headers=raw_headers,
    )
