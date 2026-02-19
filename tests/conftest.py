from __future__ import annotations

import json

import pytest

from phish_email_detection_agent.cli import run_once


@pytest.fixture
def configure_fallback_env(monkeypatch):
    def _configure() -> None:
        monkeypatch.setenv("MY_AGENT_APP_PROFILE", "openai")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    return _configure


@pytest.fixture
def run_fallback_once(monkeypatch):
    def _run(text: str, *, model: str = "gpt-4.1-mini") -> dict[str, object]:
        monkeypatch.setenv("MY_AGENT_APP_PROFILE", "openai")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        return json.loads(run_once(text, model=model))

    return _run
