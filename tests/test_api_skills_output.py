import pytest

pytest.importorskip("fastapi")

from phish_email_detection_agent.api import app as api_app


class _FakeAgent:
    def analyze(self, text: str) -> dict[str, object]:
        return {"verdict": "benign", "echo": text}


def test_analyze_exposes_skills_summary(monkeypatch):
    runtime = {
        "profile": "ollama",
        "provider": "local",
        "model": "ollama/qwen2.5:7b",
        "skills_dir": "/tmp/skills",
        "installed_skills": [
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
    assert result["skills"] == {
        "dir": "/tmp/skills",
        "count": 2,
        "names": ["image-ocr", "pdf-reading"],
        "installed": runtime["installed_skills"],
    }
    assert result["tools"] == {
        "count": 2,
        "names": ["normalize_text", "extract_urls"],
        "builtin": runtime["builtin_tools"],
    }
