# API

Use this section when you are integrating Argis into services, workers, queues, or internal tooling. The API docs are separate from the product guides so callers can find request and response details quickly.

## Start Here

- Read [Guides and Concepts](./guides-concepts) for production integration patterns.
- Read [API Reference](./reference) for request, response, and error shape details.
- Read [API Contract](./contract) for the low-level stable wire contract.
- Read [Migration Guide](./migration-guide) when updating callers across API behavior changes.

## Entry Points

- Primary endpoint: `POST /analyze`
- Health endpoint: `GET /health`

## What This Section Covers

- how to send plain-text and structured JSON inputs
- which input modes are allowed in API context
- what response metadata is stable and useful for observability
- how fallback behavior and evidence sanitization show up in results

## Related Product Docs

- [Using Argis: App](/argis/using-argis/app)
- [Operations: Runbook](/argis/operations/runbook)
- [Operations: Security Boundary](/argis/operations/security-boundary)
