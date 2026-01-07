"""Static attachment scanning (deterministic)."""

from __future__ import annotations

from schemas.email_schema import AttachmentMeta
from schemas.evidence_schema import AttachmentScanItem, AttachmentScanResult

_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
_EXECUTABLE_EXTENSIONS = {".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1"}


def _extension(name: str) -> str:
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def attachment_static_scan(attachments: list[AttachmentMeta]) -> AttachmentScanResult:
    """Inspect attachments for macro and executable indicators."""

    items: list[AttachmentScanItem] = []
    for attachment in attachments:
        ext = _extension(attachment.filename)
        has_macro = ext in _MACRO_EXTENSIONS
        is_executable = ext in _EXECUTABLE_EXTENSIONS
        flags = list(attachment.flags or [])
        if has_macro:
            flags.append("macro_extension")
        if is_executable:
            flags.append("executable_extension")
        items.append(
            AttachmentScanItem(
                sha256=attachment.sha256,
                has_macro=has_macro,
                is_executable=is_executable,
                flags=flags,
            )
        )
    return AttachmentScanResult(items=items)
