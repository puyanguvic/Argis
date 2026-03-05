# CLI

Use CLI mode for local analysis, debugging, and rapid iteration.

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

For full behavior details: [Manual](/manual).
