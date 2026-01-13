---
title: BEC Detection
redirect_from:
  - /skills/bec-detection.html
---

# Business Email Compromise (BEC) detection

BEC is about impersonation and business-process abuse rather than technical payloads. This skill depends on organizational context; without context, the system should lean `suspicious` and escalate for human review.

## Key risk signals

- Reply-To differs from From (reply-hijacking)
- Payment/invoice/transfer intent with high urgency
- Mismatch with historical thread/contact relationship (not integrated yet)
- Directive actions: “reply”, “transfer”, “change bank details”

## Current coverage

### 1) Reply-To mismatch (quick feature)

- Location: `engine/router.py`
- Feature: `QuickFeatures.reply_to_mismatch`
- Used in routing and fusion scoring (`reply_to_mismatch`)

### 2) Semantic intent and urgency (rules)

Tool: `semantic_extract()` (`tools_builtin/content_analyzer.py`)

- `intent` may include:
  - `invoice_payment`
  - `credential_theft`
  - `oauth_consent` (collaboration intent)
- `urgency`: 0–3 (keyword-based)

Note: `scoring/fusion.py` currently weights `semantic_urgency` and some intents (credential/oauth). `invoice_payment` is not yet a distinct scoring factor.

## Recommended handling without context

- When payment/transfer intent exists but technical evidence is weak:
  - prefer `suspicious`
  - recommend out-of-band verification (phone/IM/finance system)

## Extensions to make BEC useful

1. Add evidence sources via connectors:
   - org directory / contact history
   - historical payment patterns (new payee, first-time vendor)
   - thread context (In-Reply-To / References)
2. Include `invoice_payment` in risk fusion:
   - add a factor in `scoring/fusion.py` (e.g., `semantic_invoice_intent`)
   - set weights in `configs/profiles/balanced.yaml` and add tests
