# Using Argis

This section covers the practical ways people interact with Argis once the project is installed.

## Choose a Workflow

- Use [CLI](./cli) for local triage, debugging, experiments, and direct operator workflows.
- Use [App](./app) when Argis needs to run as an HTTP inference service.
- Use [Integrations](./integrations) when embedding Argis into workers, queues, or larger systems.

## What Changes Between Workflows

- the entry point you run
- which input shapes are appropriate
- what trust boundary applies to local files and evidence detail
- which observability fields matter most in production

## Related Docs

- [Quickstart](/argis/getting-started/quickstart)
- [Configurations](/argis/configurations/)
- [API](/api/)
- [Operations](/argis/operations/)
