"""Runner wrappers for CLI and UI."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json

from phish_email_detection_agent.agents.build import create_agent


@dataclass
class InMemorySession:
    history: list[dict[str, object]] = field(default_factory=list)

    def add(self, item: dict[str, object]) -> None:
        self.history.append(item)


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phish-email-detection-agent")
    parser.add_argument("--text", help="Run once with a single input text.")
    parser.add_argument("--model", help="Override model for this run, e.g. ollama/qwen2.5:1b.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.text:
        print(run_once(args.text, model=args.model))
        return
    run_chat()
