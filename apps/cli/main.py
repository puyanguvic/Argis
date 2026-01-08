"""CLI entrypoint for the protocol-driven engine."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid

from engine.argis import ArgisEngine
from protocol.events import Error, TaskComplete
from protocol.op import UserInput


def _load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _extract_task_artifacts(events) -> dict[str, dict]:
    artifacts: dict[str, dict] = {}
    for event in events:
        if isinstance(event, Error):
            raise RuntimeError(event.message)
        if isinstance(event, TaskComplete):
            for artifact in event.artifacts:
                artifacts[artifact.kind] = artifact.payload
    return artifacts


def _emit_output(artifacts: dict[str, dict], output_format: str) -> None:
    if output_format == "json":
        payload = artifacts.get("detection_result")
        if payload is None:
            raise RuntimeError("Missing detection_result artifact.")
        output = {
            "verdict": payload.get("verdict"),
            "risk_score": payload.get("risk_score"),
            "trace_id": payload.get("trace_id"),
            "profile": payload.get("profile"),
            "explanation": payload.get("explanation"),
        }
        print(json.dumps(output, indent=2, ensure_ascii=True))
        return
    report = artifacts.get("report_md", {}).get("text")
    if report is None:
        raise RuntimeError("Missing report_md artifact.")
    print(report)


def _submit_input(
    engine: ArgisEngine,
    input_kind: str,
    payload: object,
    record_path: str | None,
    output_format: str,
) -> None:
    session_id = "cli"
    task_id = f"task-{uuid.uuid4().hex[:8]}"
    options = {"record_path": record_path} if record_path else {}
    events = engine.submit(
        UserInput(
            session_id=session_id,
            task_id=task_id,
            input_kind=input_kind,
            payload=payload,
            options=options,
        )
    )
    artifacts = _extract_task_artifacts(events)
    _emit_output(artifacts, output_format=output_format)


def _detect(args: argparse.Namespace) -> None:
    engine = ArgisEngine()
    payload = _load_json(args.input)
    _submit_input(engine, "email_json", payload, args.record, args.format)


def _replay(args: argparse.Namespace) -> None:
    engine = ArgisEngine()
    _submit_input(engine, "recording", args.record, None, args.format)


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
    try:
        args.func(args)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
