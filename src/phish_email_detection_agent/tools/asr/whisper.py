"""Audio transcription APIs."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def transcribe_audio_openai(
    path: Path,
    *,
    model: str = "gpt-4o-mini-transcribe",
    api_key: str | None = None,
    base_url: str | None = None,
) -> tuple[str, str, str | None]:
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        return "", "openai", "missing_openai_api_key"
    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return "", "openai", "openai_dependency_missing"

    kwargs: dict[str, Any] = {"api_key": key}
    if base_url:
        kwargs["base_url"] = base_url

    try:
        client = OpenAI(**kwargs)
        with path.open("rb") as audio_file:
            response = client.audio.transcriptions.create(model=model, file=audio_file)
        text = getattr(response, "text", None)
        if text is None and isinstance(response, dict):
            text = response.get("text")
        return str(text or ""), "openai", None
    except Exception as exc:
        return "", "openai", f"openai_transcription_error:{type(exc).__name__}"
