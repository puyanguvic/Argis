---
title: IMAP Connector
---

# IMAP connector

Implementation: `connectors/imap/connector.py`.

## Configuration

Example config: `configs/connectors/imap.yaml`.

Expected fields (not exhaustive):

- `enabled`: must be `true` to load the connector.
- `host`: IMAP host.
- `credentials`: connector-specific secret material (keep out of git).

## Usage

Argis can run a turn from a connector by submitting a `UserInput` with `input_kind: "connector"` and a `message_id` payload. (The CLI currently accepts JSON input only.)

## Implementation status

- `connectors/imap/client.py` and `connectors/imap/mapper.py` are placeholders.
- To make this connector functional, implement `ImapClient.fetch_message()` and `map_imap_message()` to return a payload compatible with `schemas/email_schema.py`.
