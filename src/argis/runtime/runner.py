"""Runner facade used by CLI and UI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from argis.agents.base import MainAgent


def _load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run_detect(input_path: str, output_format: str = "report", record: str | None = None) -> str:
    agent = MainAgent()
    payload = _load_json(input_path)
    artifacts = agent.run("email_json", payload, record_path=record)
    if output_format == "json":
        return json.dumps(artifacts.get("detection_result", {}), indent=2, ensure_ascii=True)
    report = artifacts.get("report_md", {}).get("text")
    if not report:
        raise RuntimeError("Missing report output.")
    return report


def run_replay(record_path: str, output_format: str = "report") -> str:
    agent = MainAgent()
    artifacts = agent.run("recording", record_path)
    if output_format == "json":
        return json.dumps(artifacts.get("detection_result", {}), indent=2, ensure_ascii=True)
    report = artifacts.get("report_md", {}).get("text")
    if not report:
        raise RuntimeError("Missing report output.")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argis")
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

    replay = sub.add_parser("replay", help="Replay a recorded run JSONL file.")
    replay.add_argument("--record", required=True, help="Path to run.jsonl file.")
    replay.add_argument(
        "--format",
        choices=["report", "json"],
        default="report",
        help="Output format for the replay result.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "detect":
            print(run_detect(args.input, args.format, args.record))
        elif args.command == "replay":
            print(run_replay(args.record, args.format))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
