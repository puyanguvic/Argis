---
layout: default
title: Configuration
---

# Configuration

How to tune Argis behavior without changing code, and how to extend it safely.

## Pages

- [Config file](config-file.html)
- [Rules and weights](rules.html)
- [AGENTS.md](agents-md.html)
- [Custom prompts](custom-prompts.html)
- [MCP](mcp.html)
- [Skills](skills/index.html)
- [Extending Argis](extending/index.html)

## Config locations

- App selectors: `configs/app.yaml` (profile/provider/connector).
- Profiles: `configs/profiles/*.yaml` (router thresholds, tool plan, scoring weights).
- Provider configs: `configs/providers/*.yaml` (if/when provider is wired).
- Connector configs: `configs/connectors/*.yaml` (connectors are experimental scaffolding in this build).
