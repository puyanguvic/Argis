"""Runner wrappers for CLI and UI."""

from __future__ import annotations

import json

from phish_email_detection_agent.app.build_agent import create_agent
from phish_email_detection_agent.app.sessions import InMemorySession


def run_once(text: str, model: str | None = None) -> str:
    agent, runtime = create_agent(model_override=model)
    result = agent.analyze(text)
    result["runtime"] = runtime
    return json.dumps(result, ensure_ascii=True)


def run_chat() -> None:
    agent, runtime = create_agent()
    session = InMemorySession()
    print(f"chat started provider={runtime['provider']} model={runtime['model']}")
    while True:
        raw = input("> ").strip()
        if raw.lower() in {"exit", "quit"}:
            break
        result = agent.analyze(raw)
        session.add(result)
        print(json.dumps(result, ensure_ascii=True))
