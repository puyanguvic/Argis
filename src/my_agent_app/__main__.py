"""CLI entrypoint for my_agent_app."""

from __future__ import annotations

import argparse

from my_agent_app.app.run import run_chat, run_once


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="my-agent-app")
    parser.add_argument("--text", help="Run once with a single input text.")
    parser.add_argument("--chat", action="store_true", help="Start interactive chat mode.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.chat:
        run_chat()
        return
    if not args.text:
        raise SystemExit("Provide --text or use --chat")
    print(run_once(args.text))


if __name__ == "__main__":
    main()
