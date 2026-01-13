---
layout: default
title: Attachment Risk Analysis
redirect_from:
  - /skills/attachment-analysis.html
---

# Attachment risk analysis

Attachments are a primary malware delivery path. The current implementation uses static metadata only, focusing on macro docs and executable/script extensions.

## Core signals

- Macro document extensions: `.docm`, `.xlsm`, `.pptm`
- Executable/script extensions: `.exe`, `.js`, `.vbs`, `.scr`, `.bat`, `.cmd`, `.ps1`

## Current implementation

Tool: `attachment_static_scan(attachments)` (`tools_builtin/attachment_analyzer.py`)

- Input: `EmailInput.attachments` (`schemas/email_schema.py` `AttachmentMeta`)
- Output: `AttachmentScanResult(items=[AttachmentScanItem...])`
- Behavior:
  - set `has_macro` / `is_executable` by extension
  - write flags like `macro_extension`

## Semantic/rule integration

Hard rule example (`scoring/rules.py`):

- `malware_intent_executable_attachment`
  - Condition: `semantic.intent == "malware_delivery"` and `is_executable` present

Fusion factors (`scoring/fusion.py`):

- `attachment_macro`
- `attachment_executable`

## Extensions

For stronger attachment coverage (in an isolated environment):

- Unpack and scan content (OLE/macros, script APIs, signatures/entropy)
- Recursive archive extraction (zip/iso/img)
- Hash reputation (internal IOCs / intel feeds)

Outputs should remain structured evidence, without executing content.
