---
layout: default
title: Benchmark Scenarios
---

# Benchmark scenarios

Suggested scenarios for regression tests and weight/rule tuning.

## 1) Typical credential phishing

- DMARC fail + URL with `login/verify` keywords
- Expect: `phishing` (or hard rule) + high score

## 2) Shorteners / suspicious TLDs

- URL uses shortener (`bit.ly`) or suspicious TLD (`.zip`, `.click`)
- Expect: `suspicious` or `phishing` based on combined signals

## 3) Lookalike domain + credential intent

- Brand lookalike (e.g., `micros0ft`) + credential intent
- Expect: high score; with SPF fail, may trigger hard rule

## 4) Collaboration/OAuth low-noise abuse

- `semantic.intent == oauth_consent` + brand entity + external sender
- Expect: FAST → STANDARD contextual escalation with `degradations` flag and URL evidence

## 5) Malware delivery via attachment

- `semantic.intent == "malware_delivery"` + `.exe/.js/.ps1` attachment
- Expect: `malware_intent_executable_attachment` hard rule or high score

## 6) Benign control

- allowlisted internal domain, no URLs, no auth failures, no malicious intent
- Expect: `benign` + low score

## Implementation guidance

- Convert scenarios into `EmailInput` JSON samples in `examples/` or tests in `tests/`.
- Record expected `verdict`, score range, and key `top_signals`.
