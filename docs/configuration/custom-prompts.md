---
layout: default
title: Custom Prompts
---

# Custom prompts

This build is **deterministic by default** and does not ship a prompt-tuning surface yet.

If/when provider-backed LLM steps are introduced, this page should document:

- where prompts live (config vs. code)
- how prompts are versioned and reviewed
- how prompt outputs are recorded/redacted

## Where prompt code would plug in

- Provider interface: `providers/model/base.py` (`ModelProvider.generate()`).
- Orchestrator: keep tool outputs structured and route them into `EvidenceStore` fields before scoring/rules.
