---
title: Config File
description: How Argis resolves YAML defaults, profiles, environment overrides, capability flags, and policy thresholds.
---

# Config File

Configuration comes from YAML defaults and environment variables.

## Source of Truth

- defaults: `src/phish_email_detection_agent/config/defaults.yaml`
- loader: `src/phish_email_detection_agent/config/settings.py::load_config`
- env example: `.env.example`

## How Configuration Is Resolved

At startup, Argis loads defaults from YAML, selects the active profile, then applies environment overrides. In practice this means:

1. repository defaults establish the baseline
2. the selected profile provides a coherent provider/model bundle
3. environment variables override the active profile for deployment-specific needs

This is why `MY_AGENT_APP_PROFILE` is the most important first choice and individual env vars are the next layer.

## Common Runtime Variables

### Provider and profile

- `MY_AGENT_APP_PROFILE`
- `MY_AGENT_APP_PROVIDER`
- `MY_AGENT_APP_MODEL`
- `OPENAI_API_KEY`

Use these when choosing between local and remote execution or when overriding the active model.

### Deep analysis controls

- `MY_AGENT_APP_ENABLE_DEEP_ANALYSIS`
- `MY_AGENT_APP_ENABLE_OCR`
- `MY_AGENT_APP_ENABLE_AUDIO_TRANSCRIPTION`
- `MY_AGENT_APP_ENABLE_URL_FETCH`
- `MY_AGENT_APP_ALLOW_PRIVATE_NETWORK`

`MY_AGENT_APP_ENABLE_DEEP_ANALYSIS=true` is a one-switch bundle. If individual flags such as `MY_AGENT_APP_ENABLE_URL_FETCH` are unset, the config loader will turn them on automatically. Explicit per-capability env vars still win.

### URL fetch limits

- `MY_AGENT_APP_FETCH_TIMEOUT_S`
- `MY_AGENT_APP_FETCH_MAX_REDIRECTS`
- `MY_AGENT_APP_FETCH_MAX_BYTES`
- `MY_AGENT_APP_URL_FETCH_BACKEND=internal|firejail|docker`

These values are part of the side-effect boundary and should be treated as operational safety limits, not mere performance knobs.

### Policy thresholds

- `MY_AGENT_APP_PRE_SCORE_REVIEW_THRESHOLD`
- `MY_AGENT_APP_PRE_SCORE_DEEP_THRESHOLD`
- `MY_AGENT_APP_CONTEXT_TRIGGER_SCORE`
- `MY_AGENT_APP_SUSPICIOUS_MIN_SCORE`
- `MY_AGENT_APP_SUSPICIOUS_MAX_SCORE`
- `MY_AGENT_APP_JUDGE_ALLOW_MODE`
- `MY_AGENT_APP_JUDGE_ALLOW_SAMPLE_RATE`

These values shape routing and judge usage. They have behavioral impact and should be changed deliberately.

## Configuration Patterns

### Conservative default deployment

- keep deep-analysis features off
- block private-network fetches
- use deterministic fallback as the baseline safety net

### Rich internal analysis deployment

- enable selected deep-analysis capabilities
- keep fetch bounds explicit
- use `debug_evidence=true` only in controlled operator paths

### Local developer workstation

- use the `ollama` profile
- override model choices as needed
- keep API trust-boundary assumptions separate from CLI-only experiments

## Practical Rule

Enable only the capabilities you need and keep side-effectful features bounded by explicit limits.

Related docs:

- [Using Argis](/argis/using-argis/)
- [Security Boundary](/argis/operations/security-boundary)
- [Release Gates](/argis/operations/release-gates)
