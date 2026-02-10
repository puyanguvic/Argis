import zipfile

import phish_email_detection_agent.tools.attachment_analysis as attachment_analysis
from phish_email_detection_agent.tools.attachment_analysis import AttachmentPolicy, analyze_single_attachment


def test_pdf_attachment_detects_embedded_javascript(tmp_path):
    pdf_path = tmp_path / "suspicious.pdf"
    pdf_path.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /JavaScript /JS >>\nstream\nhttps://evil.example/login\nendstream\n%%EOF"
    )
    report = analyze_single_attachment(str(pdf_path))
    assert report["type"] == "pdf"
    assert report["risk_score"] >= 60
    assert "attachment_contains_url" in report["indicators"]


def test_office_zip_detects_macro_like_content(tmp_path):
    docx_path = tmp_path / "invoice.docm"
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"macro")
        zf.writestr("word/_rels/document.xml.rels", b'https://phish.example/path')
    report = analyze_single_attachment(str(docx_path))
    assert report["type"] == "zip"
    assert report["risk_score"] >= 55
    assert "attachment_contains_url" in report["indicators"]


def test_image_attachment_ocr_and_qr_pipeline(tmp_path, monkeypatch):
    image_path = tmp_path / "verify-login.png"
    image_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)

    monkeypatch.setattr(
        attachment_analysis,
        "_run_image_ocr",
        lambda _path, _policy: ("Microsoft account suspended, verify now", "tesseract", None),
    )
    monkeypatch.setattr(
        attachment_analysis,
        "_decode_qr_codes",
        lambda _path: (["https://qr-phish.example/login"], None),
    )

    report = analyze_single_attachment(
        str(image_path),
        policy=AttachmentPolicy(enable_ocr=True, enable_qr_decode=True),
    )
    assert report["type"] == "image"
    assert "attachment_contains_url" in report["indicators"]
    assert "https://qr-phish.example/login" in report["extracted_urls"]
    assert report["details"]["ocr_backend"] == "tesseract"


def test_audio_attachment_openai_transcription_pipeline(tmp_path, monkeypatch):
    audio_path = tmp_path / "ceo-urgent.wav"
    audio_path.write_bytes(b"RIFF" + b"0" * 64)

    monkeypatch.setattr(
        attachment_analysis,
        "_transcribe_audio",
        lambda _path, _policy: ("Please make wire transfer immediately", "openai", None),
    )
    report = analyze_single_attachment(
        str(audio_path),
        policy=AttachmentPolicy(enable_audio_transcription=True, audio_backend="openai"),
    )
    assert report["type"] == "audio"
    assert report["details"]["transcription_backend"] == "openai"
    assert "wire transfer" in report["details"]["transcript_hits"]
