---
title: Gradio Demo
---

# Gradio demo

A minimal web UI for manual testing of the phishing email detection agent.

## Run locally

```
python apps/demo/gradio_app.py
```

## Input format

Paste the raw email (`.eml`) content into the text box. The demo converts it into `EmailInput` and runs a detection turn.

## Data handling

- Use only with test/sanitized emails.
- Avoid screenshots/logging with real headers or bodies.
