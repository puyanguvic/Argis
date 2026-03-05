# Argis Documentation

This site is the web documentation for **Argis**, a phishing email detection agent with deterministic-first analysis and policy-controlled runtime behavior.

## Main Sections

- [Argis](./argis/): product usage, concepts, and configuration guides.
- [API](./api/): guides, concepts, and API reference links.
- [Blog](./blog/): project blog and updates.

Key Argis paths:

- [Getting Started](./argis/getting-started/overview)
- [Architecture](./argis/architecture/)
- [Operations](./argis/operations/)

## Current Focus (v0.1.1)

Recent updates shipped in `v0.1.1`:

- Hardened `/analyze` API input boundaries.
- Default evidence sanitization for API responses with explicit `debug_evidence=true` opt-in.
- Fallback reliability improvements with `fallback_reason`.
- Precheck tuning knobs wired to effective scoring behavior.
- Policy-driven threshold semantics and runtime capability metadata alignment.

For full details, see:

- [v0.1.1 release page](https://github.com/puyanguvic/Argis/releases/tag/v0.1.1)
- [CHANGELOG.md](https://github.com/puyanguvic/Argis/blob/main/CHANGELOG.md)
