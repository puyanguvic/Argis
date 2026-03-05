import pytest

pytest.importorskip("fastapi")
from fastapi import HTTPException

from phish_email_detection_agent.api import app as api_app


class _FakeAgent:
    def analyze(self, text: str) -> dict[str, object]:
        return {"verdict": "benign", "echo": text}


def test_analyze_exposes_skillpack_summary(monkeypatch):
    runtime = {
        "profile": "ollama",
        "provider": "local",
        "model": "ollama/qwen2.5:7b",
        "skillpacks_dir": "/tmp/skillpacks",
        "installed_skillpacks": [
            {"name": "image-ocr", "description": "ocr"},
            {"name": "pdf-reading", "description": "pdf"},
        ],
        "builtin_tools": [
            {"name": "normalize_text", "description": "normalize", "module": "tools.openai.builtin"},
            {"name": "extract_urls", "description": "urls", "module": "tools.openai.builtin"},
        ],
    }

    def _fake_create_agent(*, model_override=None):
        return _FakeAgent(), runtime

    monkeypatch.setattr(api_app, "create_agent", _fake_create_agent)
    result = api_app.analyze({"text": "hello"})

    assert result["runtime"] == runtime
    assert result["skillpacks"] == {
        "dir": "/tmp/skillpacks",
        "count": 2,
        "names": ["image-ocr", "pdf-reading"],
        "installed": runtime["installed_skillpacks"],
    }
    assert "skills" not in result
    assert result["tools"] == {
        "count": 2,
        "names": ["normalize_text", "extract_urls"],
        "builtin": runtime["builtin_tools"],
    }


def test_analyze_rejects_eml_path(monkeypatch):
    def _should_not_run(*, model_override=None):
        raise AssertionError("create_agent should not be called for rejected payload")

    monkeypatch.setattr(api_app, "create_agent", _should_not_run)
    with pytest.raises(HTTPException) as exc_info:
        api_app.analyze({"text": '{"eml_path":"/etc/passwd","subject":"hello"}'})

    detail = exc_info.value.detail
    assert exc_info.value.status_code == 400
    assert isinstance(detail, dict)
    assert detail.get("code") == "unsupported_eml_path"


def test_analyze_rejects_path_like_attachment_name(monkeypatch):
    def _should_not_run(*, model_override=None):
        raise AssertionError("create_agent should not be called for rejected payload")

    monkeypatch.setattr(api_app, "create_agent", _should_not_run)
    with pytest.raises(HTTPException) as exc_info:
        api_app.analyze({"text": '{"attachments":[{"name":"../secret/invoice.pdf"}]}'})

    detail = exc_info.value.detail
    assert exc_info.value.status_code == 400
    assert isinstance(detail, dict)
    assert detail.get("code") == "unsafe_attachment_path"


def test_analyze_rejects_raw_attachment_strings(monkeypatch):
    def _should_not_run(*, model_override=None):
        raise AssertionError("create_agent should not be called for rejected payload")

    monkeypatch.setattr(api_app, "create_agent", _should_not_run)
    with pytest.raises(HTTPException) as exc_info:
        api_app.analyze({"text": '{"attachments":["invoice.pdf"]}'})

    detail = exc_info.value.detail
    assert exc_info.value.status_code == 400
    assert isinstance(detail, dict)
    assert detail.get("code") == "invalid_attachment_schema"


def test_analyze_accepts_structured_attachment_identifiers(monkeypatch):
    runtime = {
        "profile": "ollama",
        "provider": "local",
        "model": "ollama/qwen2.5:7b",
        "skillpacks_dir": "/tmp/skillpacks",
        "installed_skillpacks": [],
        "builtin_tools": [],
    }

    def _fake_create_agent(*, model_override=None):
        return _FakeAgent(), runtime

    monkeypatch.setattr(api_app, "create_agent", _fake_create_agent)
    result = api_app.analyze(
        {
            "text": (
                '{"subject":"hello","attachments":[{"name":"invoice.pdf"},{"filename":"q1-report.docx"}]}'
            )
        }
    )
    assert result["verdict"] == "benign"


def test_analyze_sanitizes_sensitive_evidence_by_default(monkeypatch):
    runtime = {
        "profile": "ollama",
        "provider": "local",
        "model": "ollama/qwen2.5:7b",
        "skillpacks_dir": "/tmp/skillpacks",
        "installed_skillpacks": [],
        "builtin_tools": [],
    }

    class _EvidenceAgent:
        def analyze(self, text: str) -> dict[str, object]:
            return {
                "verdict": "phishing",
                "precheck": {
                    "attachment_reports": [
                        {
                            "name": "invoice.pdf",
                            "risk_score": 80,
                            "exists": True,
                            "sha256": "abc123",
                            "details": {"macro": True},
                        }
                    ],
                    "url_target_reports": [
                        {
                            "fetch": {
                                "status": "sandbox_error",
                                "stderr": "trace",
                                "command": "docker run ...",
                            }
                        }
                    ],
                },
                "evidence": {
                    "precheck": {
                        "attachment_reports": [
                            {
                                "name": "invoice.pdf",
                                "risk_score": 80,
                                "exists": True,
                                "sha256": "abc123",
                                "details": {"macro": True},
                            }
                        ],
                        "url_target_reports": [
                            {
                                "fetch": {
                                    "status": "sandbox_error",
                                    "stderr": "trace",
                                    "command": "docker run ...",
                                }
                            }
                        ],
                    }
                },
            }

    def _fake_create_agent(*, model_override=None):
        return _EvidenceAgent(), runtime

    monkeypatch.setattr(api_app, "create_agent", _fake_create_agent)
    result = api_app.analyze({"text": "hello"})

    report = result["precheck"]["attachment_reports"][0]
    assert "exists" not in report
    assert "sha256" not in report
    assert "details" not in report
    fetch = result["precheck"]["url_target_reports"][0]["fetch"]
    assert "stderr" not in fetch
    assert "command" not in fetch

    evidence_report = result["evidence"]["precheck"]["attachment_reports"][0]
    assert "exists" not in evidence_report
    assert "sha256" not in evidence_report
    assert "details" not in evidence_report


def test_analyze_keeps_full_evidence_in_debug_mode(monkeypatch):
    runtime = {
        "profile": "ollama",
        "provider": "local",
        "model": "ollama/qwen2.5:7b",
        "skillpacks_dir": "/tmp/skillpacks",
        "installed_skillpacks": [],
        "builtin_tools": [],
    }

    class _EvidenceAgent:
        def analyze(self, text: str) -> dict[str, object]:
            return {
                "verdict": "phishing",
                "precheck": {
                    "attachment_reports": [
                        {
                            "name": "invoice.pdf",
                            "risk_score": 80,
                            "exists": True,
                            "sha256": "abc123",
                            "details": {"macro": True},
                        }
                    ],
                },
            }

    def _fake_create_agent(*, model_override=None):
        return _EvidenceAgent(), runtime

    monkeypatch.setattr(api_app, "create_agent", _fake_create_agent)
    result = api_app.analyze({"text": "hello", "debug_evidence": True})

    report = result["precheck"]["attachment_reports"][0]
    assert report["exists"] is True
    assert report["sha256"] == "abc123"
    assert report["details"] == {"macro": True}
