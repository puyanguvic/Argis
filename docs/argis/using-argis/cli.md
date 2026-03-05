---
title: CLI
description: Local operator workflow for running Argis interactively, testing structured input, and debugging profile or model behavior.
---

# CLI

Use CLI mode for local analysis, debugging, and rapid iteration.

## When CLI Is The Right Tool

CLI mode is best when:

- you are operating in a trusted local environment
- you want fast feedback while tuning prompts, profiles, or capabilities
- you need to test local EML-based workflows
- you want to inspect how configuration changes affect runtime behavior before exposing them through the API

## Interactive Session

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent
```

## Single Input

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text "review this email"
```

## Model Override

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --model ollama/qwen2.5:7b --text "review this email"
```

## Structured JSON Input

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text '{"text":"Urgent: login now","urls":["https://bit.ly/reset"],"attachments":["invoice.zip"]}'
```

## EML Input (CLI only)

```bash
PYTHONPATH=src uv run python -m phish_email_detection_agent --text '{"eml_path":"/path/to/sample.eml"}'
```

## What CLI Can Do That API Mode Cannot

- read local file paths such as `eml_path`
- operate comfortably in developer or analyst workstations
- support direct local experimentation without transport-layer request shaping

That flexibility is useful, but it also means CLI assumptions must not be copied directly into API integrations.

## Practical Usage Tips

### Use structured JSON for repeatable testing

Even in CLI mode, structured JSON input is often better than raw text when you want to compare runs or evaluate URL and attachment handling deterministically.

### Use model overrides for targeted checks

The `--model` flag is useful when you want to compare provider behavior without rewriting the base config profile.

### Watch for fallback behavior

If the configured provider cannot be used, the CLI still returns deterministic fallback output. Treat that as a valid runtime mode and inspect `provider_used` and `fallback_reason` accordingly.

## Related Docs

- [Quickstart](/argis/getting-started/quickstart)
- [Config File](/argis/configurations/config-file)
- [Security Boundary](/argis/operations/security-boundary)
