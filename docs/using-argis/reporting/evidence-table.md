---
layout: default
title: Evidence Table
redirect_from:
  - /reporting/evidence-table.html
---

# Evidence table definition

The evidence table decomposes complex results into auditable evidence items for reports, SIEMs, or ticketing.

## Evidence item fields (current)

`engine/report.py` uses `EvidenceLine` with:

- `section`: category (Sender authentication / URL / Domain / Content / Attachments)
- `severity`: LOW / MED / HIGH
- `message`: human-readable description
- `evidence_id`: stable identifier (e.g., `ev-0010`)
- `score_hint`: suggested contribution for ordering

## Usage guidance

- Map `evidence_id` to rules/factors for audit and governance.
- `severity` is not the same as `risk_score`; it reflects evidence strength.
- For repeated evidence (e.g., multiple URLs):
  - show top 1–3 in the report
  - include the rest as an appendix/expanded section

## Relationship to EvidenceStore

Evidence items should link back to `EvidenceStore` fields:

- Header: `evidence.header_auth`
- URL: `evidence.url_chain`
- Domain: `evidence.domain_risk`
- Content: `evidence.semantic`
- Attachments: `evidence.attachment_scan`
