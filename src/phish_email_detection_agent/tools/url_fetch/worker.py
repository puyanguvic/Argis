"""Isolated worker process for URL safe fetch."""

from __future__ import annotations

import argparse
import json

from phish_email_detection_agent.tools.url_fetch.service import SafeFetchPolicy, _safe_fetch_url_internal


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argis-sandbox-fetch-worker")
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--max-redirects", type=int, default=3)
    parser.add_argument("--max-bytes", type=int, default=1_000_000)
    parser.add_argument("--user-agent", type=str, default="ArgisSafeFetcher/3.0")
    parser.add_argument("--allow-private-network", action="store_true")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    policy = SafeFetchPolicy(
        enabled=True,
        timeout_s=max(args.timeout, 0.5),
        connect_timeout_s=min(max(args.timeout, 0.5), 3.0),
        max_redirects=max(args.max_redirects, 1),
        max_bytes=max(args.max_bytes, 4096),
        allow_private_network=bool(args.allow_private_network),
        user_agent=args.user_agent,
        sandbox_backend="internal",
    )
    payload = _safe_fetch_url_internal(args.url.strip(), policy)
    print(json.dumps(payload, ensure_ascii=True))


if __name__ == "__main__":
    main()
