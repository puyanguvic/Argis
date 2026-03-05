# MCP

MCP usage depends on connected MCP servers and runtime environment.

## Usage Guidelines

- load only necessary context/resources
- keep execution explicit and auditable
- avoid unbounded or implicit side effects
- keep fallback behavior deterministic where feasible

## Documentation Workflow Suggestion

When using MCP for docs or code work:

1. discover resources/templates first
2. fetch only relevant entries
3. keep cross-source assumptions explicit

Reference architecture constraints: [Design](/design) and `AGENTS.md`.
