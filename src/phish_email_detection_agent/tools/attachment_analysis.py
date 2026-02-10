"""Attachment deep analysis with safe static inspection."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any
import zipfile

from phish_email_detection_agent.tools.email import classify_attachment, extract_urls
from phish_email_detection_agent.tools.url_analysis import analyze_html_content


@dataclass
class AttachmentPolicy:
    max_read_bytes: int = 4_000_000
    enable_ocr: bool = False
    ocr_backend: str = "tesseract"
    ocr_languages: str = "eng"
    enable_qr_decode: bool = True
    enable_audio_transcription: bool = False
    audio_backend: str = "openai"
    audio_model: str = "gpt-4o-mini-transcribe"
    audio_local_model_size: str = "small"
    whisper_cli_path: str = "whisper"
    openai_api_key: str | None = None
    openai_base_url: str | None = None


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _read_head(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(max_bytes)


def _detect_magic_type(data: bytes, filename: str) -> str:
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image"
    if data.startswith(b"\xff\xd8\xff"):
        return "image"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image"
    if data.startswith((b"RIFF", b"ID3")):
        return "audio"
    if data.lstrip().startswith((b"<!doctype html", b"<html", b"<HTML", b"<?xml")):
        return "html"

    lower = filename.lower()
    if lower.endswith(".pdf"):
        return "pdf"
    if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")):
        return "image"
    if lower.endswith((".wav", ".mp3", ".m4a", ".ogg", ".flac")):
        return "audio"
    if lower.endswith((".docx", ".xlsx", ".pptx", ".zip")):
        return "zip"
    if lower.endswith((".doc", ".xls", ".ppt")):
        return "ole"
    if lower.endswith((".htm", ".html")):
        return "html"
    return "unknown"


def _analyze_pdf(data: bytes) -> dict[str, Any]:
    lower = data.lower()
    js_flags = [token.decode("ascii") for token in (b"/javascript", b"/js") if token in lower]
    form_like = b"/acform" in lower or b"/annots" in lower
    decoded = data.decode("latin-1", errors="ignore")
    urls = extract_urls(decoded)
    score = min(100, len(js_flags) * 30 + (20 if form_like else 0) + min(20, len(urls) * 4))
    return {
        "embedded_javascript": bool(js_flags),
        "js_markers": js_flags,
        "form_like_objects": bool(form_like),
        "urls": urls,
        "risk_score": score,
    }


def _analyze_zip_office(path: Path) -> dict[str, Any]:
    suspicious_entries: list[str] = []
    macro_like = False
    urls: list[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            for name in names:
                lower = name.lower()
                if "vba" in lower or lower.endswith("vbaproject.bin"):
                    macro_like = True
                    suspicious_entries.append(name)
                if lower.endswith((".xml", ".rels")):
                    try:
                        payload = zf.read(name)
                    except Exception:
                        continue
                    urls.extend(extract_urls(payload.decode("utf-8", errors="ignore")))
    except zipfile.BadZipFile:
        return {"macro_like": False, "suspicious_entries": [], "urls": [], "risk_score": 0}

    score = (40 if macro_like else 0) + min(20, len(urls) * 4)
    return {
        "macro_like": macro_like,
        "suspicious_entries": suspicious_entries,
        "urls": list(dict.fromkeys(urls)),
        "risk_score": min(100, score),
    }


def _analyze_html_attachment(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8", errors="replace")
    html = analyze_html_content(text)
    urls = extract_urls(text)
    score = min(100, int(html.get("impersonation_score", 0) * 0.8) + min(20, len(urls) * 3))
    return {
        "html_features": html,
        "urls": urls,
        "risk_score": score,
    }


def _run_image_ocr(path: Path, policy: AttachmentPolicy) -> tuple[str, str, str | None]:
    backend = policy.ocr_backend.strip().lower()
    if backend == "tesseract":
        try:
            import pytesseract  # type: ignore
            from PIL import Image  # type: ignore
        except Exception:
            return "", "tesseract", "tesseract_dependencies_missing"
        try:
            text = pytesseract.image_to_string(Image.open(path), lang=policy.ocr_languages or "eng")
            return text, "tesseract", None
        except Exception as exc:
            return "", "tesseract", f"tesseract_error:{type(exc).__name__}"
    return "", backend, "unsupported_ocr_backend"


def _decode_qr_codes(path: Path) -> tuple[list[str], str | None]:
    try:
        import cv2  # type: ignore
        from pyzbar.pyzbar import decode  # type: ignore
    except Exception:
        return [], "qr_dependencies_missing"
    try:
        image = cv2.imread(str(path))
        if image is None:
            return [], "qr_image_read_failed"
        decoded = decode(image)
    except Exception as exc:
        return [], f"qr_decode_error:{type(exc).__name__}"
    urls: list[str] = []
    for item in decoded:
        try:
            data = item.data.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
        if data:
            urls.append(data)
    return list(dict.fromkeys(urls)), None


def _transcribe_with_openai(path: Path, policy: AttachmentPolicy) -> tuple[str, str, str | None]:
    api_key = policy.openai_api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "", "openai", "missing_openai_api_key"
    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return "", "openai", "openai_dependency_missing"

    kwargs: dict[str, Any] = {"api_key": api_key}
    base_url = policy.openai_base_url or os.getenv("OPENAI_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url

    try:
        client = OpenAI(**kwargs)
        with path.open("rb") as audio_file:
            response = client.audio.transcriptions.create(model=policy.audio_model, file=audio_file)
        text = getattr(response, "text", None)
        if text is None and isinstance(response, dict):
            text = response.get("text")
        return str(text or ""), "openai", None
    except Exception as exc:
        return "", "openai", f"openai_transcription_error:{type(exc).__name__}"


def _transcribe_with_faster_whisper(path: Path, policy: AttachmentPolicy) -> tuple[str, str, str | None]:
    try:
        from faster_whisper import WhisperModel  # type: ignore
    except Exception:
        return "", "faster-whisper", "faster_whisper_dependency_missing"
    try:
        model = WhisperModel(policy.audio_local_model_size or "small", device="cpu", compute_type="int8")
        segments, _ = model.transcribe(str(path), vad_filter=True)
        text = " ".join(seg.text.strip() for seg in segments if getattr(seg, "text", "").strip())
        return text, "faster-whisper", None
    except Exception as exc:
        return "", "faster-whisper", f"faster_whisper_error:{type(exc).__name__}"


def _transcribe_with_whisper_cli(path: Path, policy: AttachmentPolicy) -> tuple[str, str, str | None]:
    with tempfile.TemporaryDirectory(prefix="argis_whisper_") as tmpdir:
        cmd = [
            policy.whisper_cli_path or "whisper",
            str(path),
            "--model",
            policy.audio_local_model_size or "small",
            "--output_format",
            "txt",
            "--output_dir",
            tmpdir,
        ]
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        except FileNotFoundError:
            return "", "whisper-cli", "whisper_cli_not_found"
        except subprocess.TimeoutExpired:
            return "", "whisper-cli", "whisper_cli_timeout"
        if completed.returncode != 0:
            return "", "whisper-cli", "whisper_cli_failed"
        transcript_path = Path(tmpdir) / f"{path.stem}.txt"
        if not transcript_path.exists():
            return "", "whisper-cli", "whisper_cli_output_missing"
        try:
            return transcript_path.read_text(encoding="utf-8", errors="replace"), "whisper-cli", None
        except Exception as exc:
            return "", "whisper-cli", f"whisper_cli_read_error:{type(exc).__name__}"


def _transcribe_audio(path: Path, policy: AttachmentPolicy) -> tuple[str, str, str | None]:
    backend = policy.audio_backend.strip().lower()
    if backend == "openai":
        return _transcribe_with_openai(path, policy)
    if backend in {"faster-whisper", "faster_whisper"}:
        return _transcribe_with_faster_whisper(path, policy)
    if backend in {"whisper-cli", "whisper_cli"}:
        return _transcribe_with_whisper_cli(path, policy)
    return "", backend, "unsupported_audio_backend"


def _analyze_image(path: Path, policy: AttachmentPolicy) -> dict[str, Any]:
    hints = [
        token
        for token in ("invoice", "login", "verify", "qr", "payment", "account", "microsoft", "bank")
        if token in path.name.lower()
    ]

    ocr_text = ""
    ocr_backend = policy.ocr_backend
    ocr_error = None
    if policy.enable_ocr:
        ocr_text, ocr_backend, ocr_error = _run_image_ocr(path, policy)

    qr_urls: list[str] = []
    qr_error = None
    if policy.enable_qr_decode:
        qr_urls, qr_error = _decode_qr_codes(path)

    text_hits = [
        token
        for token in ("password", "verify", "urgent", "scan qr", "login", "account suspended")
        if token in ocr_text.lower()
    ]
    brand_hits = [token for token in ("microsoft", "paypal", "apple", "google", "bank") if token in ocr_text.lower()]

    score = 0
    score += len(hints) * 6
    score += len(text_hits) * 14
    score += len(brand_hits) * 8
    if qr_urls:
        score += 25

    return {
        "filename_hints": hints,
        "ocr_enabled": policy.enable_ocr,
        "ocr_backend": ocr_backend,
        "ocr_error": ocr_error,
        "ocr_text_sample": ocr_text[:600],
        "ocr_hits": text_hits,
        "brand_hits": brand_hits,
        "qr_decode_enabled": policy.enable_qr_decode,
        "qr_error": qr_error,
        "qr_payloads": qr_urls,
        "risk_score": min(100, score),
    }


def _analyze_audio(path: Path, policy: AttachmentPolicy) -> dict[str, Any]:
    filename_hits = [
        token
        for token in ("ceo", "urgent", "wire", "transfer", "payment", "invoice")
        if token in path.name.lower()
    ]
    transcript = ""
    backend = policy.audio_backend
    transcribe_error = None
    if policy.enable_audio_transcription:
        transcript, backend, transcribe_error = _transcribe_audio(path, policy)

    transcript_hits = [
        token
        for token in (
            "wire transfer",
            "urgent",
            "immediately",
            "confidential",
            "don't call",
            "payment today",
        )
        if token in transcript.lower()
    ]
    score = min(100, len(filename_hits) * 10 + len(transcript_hits) * 15)
    return {
        "transcription_enabled": policy.enable_audio_transcription,
        "transcription_backend": backend,
        "transcription_error": transcribe_error,
        "filename_hints": filename_hits,
        "transcript_sample": transcript[:600],
        "transcript_hits": transcript_hits,
        "risk_score": score,
    }


def analyze_single_attachment(
    item: str,
    policy: AttachmentPolicy | None = None,
) -> dict[str, Any]:
    cfg = policy or AttachmentPolicy()
    filename = (item or "").strip()
    if not filename:
        return {"name": "", "type": "unknown", "risk_score": 0, "indicators": ["empty_attachment_name"]}

    path = Path(filename)
    exists = path.exists() and path.is_file()
    heuristic_risk = classify_attachment(filename)
    base_indicators = [f"filename_risk:{heuristic_risk}"]
    report: dict[str, Any] = {
        "name": filename,
        "exists": exists,
        "risk_score": 0,
        "type": "unknown",
        "indicators": base_indicators[:],
        "extracted_urls": [],
        "sha256": None,
        "details": {},
    }

    if not exists:
        risk = {"low_risk": 8, "macro_risk": 55, "high_risk": 70}.get(heuristic_risk, 10)
        report["risk_score"] = risk
        report["type"] = "filename_only"
        if heuristic_risk in {"high_risk", "macro_risk"}:
            report["indicators"].append("extension_high_risk")
        return report

    try:
        data = _read_head(path, cfg.max_read_bytes)
    except Exception:
        report["indicators"].append("read_error")
        report["risk_score"] = 30
        return report

    report["sha256"] = _sha256_file(path)
    file_type = _detect_magic_type(data, filename)
    report["type"] = file_type

    details: dict[str, Any] = {}
    extracted_urls: list[str] = []
    deep_score = 0

    if file_type == "pdf":
        details = _analyze_pdf(data)
        extracted_urls = details.get("urls", [])
        deep_score = int(details.get("risk_score", 0))
    elif file_type in {"zip", "ole"}:
        if file_type == "zip":
            details = _analyze_zip_office(path)
            deep_score = int(details.get("risk_score", 0))
            extracted_urls = details.get("urls", [])
        else:
            text = data.decode("latin-1", errors="ignore")
            macro_like = "vba" in text.lower()
            deep_score = 40 if macro_like else 12
            details = {"macro_like": macro_like, "risk_score": deep_score}
    elif file_type == "html":
        details = _analyze_html_attachment(data)
        extracted_urls = details.get("urls", [])
        deep_score = int(details.get("risk_score", 0))
    elif file_type == "image":
        details = _analyze_image(path, cfg)
        extracted_urls = list(dict.fromkeys(details.get("qr_payloads", [])))
        deep_score = int(details.get("risk_score", 0))
    elif file_type == "audio":
        details = _analyze_audio(path, cfg)
        deep_score = int(details.get("risk_score", 0))
    else:
        decoded = data.decode("latin-1", errors="ignore")
        extracted_urls = extract_urls(decoded)
        if extracted_urls:
            deep_score = min(40, len(extracted_urls) * 8)
            details = {"urls": extracted_urls, "risk_score": deep_score}

    report["details"] = details
    report["extracted_urls"] = list(dict.fromkeys(extracted_urls))
    score_from_name = {"low_risk": 8, "macro_risk": 55, "high_risk": 70}.get(heuristic_risk, 10)
    report["risk_score"] = min(100, max(score_from_name, deep_score))
    if report["risk_score"] >= 60:
        report["indicators"].append("attachment_high_risk")
    if report["extracted_urls"]:
        report["indicators"].append("attachment_contains_url")
    if re.search(r"(invoice|payment|login|verify)", filename, flags=re.IGNORECASE):
        report["indicators"].append("social_engineering_filename")
    return report


def analyze_attachments(items: list[str], policy: AttachmentPolicy | None = None) -> dict[str, Any]:
    reports = [analyze_single_attachment(item, policy=policy) for item in (items or [])]
    risky = [report["name"] for report in reports if int(report.get("risk_score", 0)) >= 60]
    extracted_urls: list[str] = []
    for report in reports:
        extracted_urls.extend(report.get("extracted_urls", []))
    return {
        "total": len(reports),
        "risky": risky,
        "risky_count": len(risky),
        "reports": reports,
        "extracted_urls": list(dict.fromkeys(extracted_urls)),
    }

