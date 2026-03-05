# Configurations

This section documents the main control surfaces that shape Argis runtime behavior.

## What You Can Configure

- [Config File](./config-file): runtime profiles, provider settings, deep-analysis toggles, and bounded fetch limits.
- [Rules](./rules): where routing, scoring, validation, and retry behavior live in the codebase.
- [Agents.md](./agents-md): repository-level engineering and architecture constraints.
- [MCP](./mcp): context-loading guidance when MCP servers are available.
- [Skills](./skills): local skillpack structure, installation, and discovery behavior.
- [Context Manage](./context-manage): evidence handling and reproducibility guidance.

## Configuration Principles

- keep policy decisions explicit
- keep side effects opt-in and bounded
- keep evidence references reproducible
- keep trust boundaries visible in API-facing behavior

## Related Docs

- [Architecture](/argis/architecture/)
- [Security Boundary](/argis/operations/security-boundary)
- [Release Gates](/argis/operations/release-gates)
