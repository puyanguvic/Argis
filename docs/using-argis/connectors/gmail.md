---
title: Gmail Connector
---

# Gmail connector

Implementation: `connectors/gmail/connector.py`.

## Configuration

Example config: `configs/connectors/gmail.yaml`.

Expected fields (not exhaustive):

- `enabled`: must be `true` to load the connector.
- `credentials`: connector-specific secret material (keep out of git).
- `scopes`: OAuth scopes (if/when OAuth is wired in).

## Usage

Argis can run a turn from a connector by submitting a `UserInput` with `input_kind: "connector"` and a `message_id` payload. (The CLI currently accepts JSON input only.)

## Implementation status

- `connectors/gmail/client.py` and `connectors/gmail/oauth.py` are placeholders.
- To make this connector functional, implement `GmailClient.fetch_message()` and the mapper to return a payload compatible with `schemas/email_schema.py`.
