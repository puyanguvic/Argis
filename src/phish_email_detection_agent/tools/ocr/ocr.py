"""OCR worker APIs."""

from __future__ import annotations

from pathlib import Path


def run_image_ocr(path: Path, *, backend: str = "tesseract", languages: str = "eng") -> tuple[str, str, str | None]:
    if backend.strip().lower() != "tesseract":
        return "", backend, "unsupported_ocr_backend"
    try:
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore
    except Exception:
        return "", "tesseract", "tesseract_dependencies_missing"
    try:
        text = pytesseract.image_to_string(Image.open(path), lang=languages or "eng")
        return text, "tesseract", None
    except Exception as exc:
        return "", "tesseract", f"tesseract_error:{type(exc).__name__}"
