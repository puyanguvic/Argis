"""CLI entrypoint for my_agent_app."""

from __future__ import annotations

import argparse

from my_agent_app.app.run import run_chat, run_once


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="my-agent-app")
    parser.add_argument("--text", help="Run once with a single input text.")
    parser.add_argument("--model", help="Override model for this run, e.g. ollama/qwen2.5:1b.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.text:
        print(run_once(args.text, model=args.model))
        return
    # No-arg startup for easier local usage.
    run_chat()


if __name__ == "__main__":
    main()
