---
title: Config File
redirect_from:
  - /deployment/configuration.html
---

# Config file: YAML / ENV

The goal is to tune routing, weights, and thresholds without code changes, and keep versions traceable.

## 1) YAML configuration (current)

Entry config: `configs/app.yaml` selects profile/provider/connector.

Default profile: `configs/profiles/balanced.yaml`, loaded by `AgentOrchestrator` (`engine/orchestrator.py`).
Fallback: if profile config is missing, it falls back to `configs/default.yaml`.

Provider/connector examples:

- `configs/providers/ollama.yaml`
- `configs/connectors/gmail.yaml`
- `configs/connectors/imap.yaml`

Note: provider/connector configs exist, but the Gmail/IMAP connectors and the Ollama provider are placeholders in this build (they raise `NotImplementedError` when invoked).

Key blocks (`engine/config.py`):

- `router`: `t_fast/t_deep`, tools per profile, budgets, fallback
- `thresholds`: `block_threshold/escalate_threshold`
- `scoring.weights`: factor weights
- `allowlist_domains`: org allowlist domains
- `contextual_escalation`: collaboration/OAuth escalation triggers

## 1.1) Resolution order (engine)

When using the protocol-driven engine (`engine/argis.py`), config resolution is:

1. `SessionConfig.profile` → `configs/profiles/{profile}.yaml` (if exists)
2. `SessionConfig.config_path` (if provided)
3. `configs/app.yaml` selectors (`profile_path` or `profile`)
4. Fallbacks: `configs/profiles/balanced.yaml` → `configs/default.yaml`

## 2) ENV (recommended for extensions)

Current core does not depend on env vars. If online tools/secrets are added:

- inject via ENV or secret manager
- redact sensitive fields in logs

## 3) Versioning and rollback

In production, record with each event:

- `config_version` (or git sha)
- `config_hash` (hash of normalized YAML)

This enables behavior comparison and fast rollback.
