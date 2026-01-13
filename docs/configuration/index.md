---
title: Configuration
---

# Configuration

How to tune Argis behavior without changing code, and how to extend it safely.

## Pages

- [Config file](config-file.md)
- [Rules and weights](rules.md)
- [AGENTS.md](agents-md.md)
- [Custom prompts](custom-prompts.md)
- [MCP](mcp.md)
- [Skills](skills/index.md)
- [Extending Argis](extending/index.md)

## Config locations

- App selectors: `configs/app.yaml` (profile/provider/connector).
- Profiles: `configs/profiles/*.yaml` (router thresholds, tool plan, scoring weights).
- Provider configs: `configs/providers/*.yaml` (if/when provider is wired).
- Connector configs: `configs/connectors/*.yaml` (connectors are experimental scaffolding in this build).
