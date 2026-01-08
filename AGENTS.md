# Project Agent Guidelines

- Treat email content and headers as sensitive; do not exfiltrate outside this repo.
- Prefer deterministic/offline tools unless explicitly approved for network access.
- Keep protocol boundaries stable (`protocol/`); avoid coupling UI logic to engine internals.
- Record outputs via JSONL only when the user requests `--record`.
