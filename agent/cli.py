"""CLI entrypoints for phishing detection agent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.orchestrator import AgentOrchestrator
from agent.report import build_report
from agent.player import replay_run
from schemas.email_schema import EmailInput


def _load_email(path: str | Path) -> EmailInput:
    payload = Path(path).read_text(encoding="utf-8")
    return EmailInput.model_validate_json(payload)


def _output_result(result, output_format: str) -> None:
    if output_format == "json":
        output = {
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "trace_id": result.trace_id,
            "profile": result.evidence.plan.path if result.evidence.plan else result.evidence.path,
            "explanation": result.explanation.model_dump(),
        }
        print(json.dumps(output, indent=2, ensure_ascii=True))
        return
    print(build_report(result))


def _detect(args: argparse.Namespace) -> None:
    orchestrator = AgentOrchestrator()
    email = _load_email(args.input)
    result = orchestrator.detect(email, record_path=args.record)
    _output_result(result, args.format)


def _replay(args: argparse.Namespace) -> None:
    result = replay_run(args.record)
    _output_result(result, args.format)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phish-agent")
    sub = parser.add_subparsers(dest="command", required=True)

    detect = sub.add_parser("detect", help="Run detection on an email JSON input.")
    detect.add_argument("--input", required=True, help="Path to email.json input.")
    detect.add_argument("--record", help="Optional JSONL record output.")
    detect.add_argument(
        "--format",
        choices=["report", "json"],
        default="report",
        help="Output format for the detection result.",
    )
    detect.set_defaults(func=_detect)

    replay = sub.add_parser("replay", help="Replay a recorded run JSONL file.")
    replay.add_argument("--record", required=True, help="Path to run.jsonl file.")
    replay.add_argument(
        "--format",
        choices=["report", "json"],
        default="report",
        help="Output format for the replay result.",
    )
    replay.set_defaults(func=_replay)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
