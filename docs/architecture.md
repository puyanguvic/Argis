# Architecture

## Overview

The project now exposes an application package under `src/argis` and keeps the existing
engine/protocol modules stable.

- `src/argis/core`: settings, logging, errors, shared utilities.
- `src/argis/llm`: provider enum/model defaults/factory.
- `src/argis/agents`: app-facing agent wrapper and router/prompt adapters.
- `src/argis/tools`: reusable utility tools for text/files/safety/debug.
- `src/argis/runtime`: runner, tracing toggle, session state.
- `src/argis/ui`: Gradio app entrypoint and optional components.

## Boundary rules

- Protocol contracts remain in `protocol/` and are unchanged.
- Engine internals stay in `engine/` and are consumed via wrappers.
- UI uses runtime/agent wrappers instead of directly implementing engine flow.
