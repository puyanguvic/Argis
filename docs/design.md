# Argis Phishing Email Detection Agent: Design

Status: Living document
Last updated: 2026-02-25

## 1. Executive Summary

Argis is a phishing email detection system built as an agentic control stack with a deterministic kernel.

Key design choices:

1. Deterministic-first: construct an `EvidencePack` and a calibrated pre-score before any model involvement.
2. Layered architecture: `policy` (what/when) + `tools` (atomic capabilities) + `orchestrator` (control flow) + delivery interfaces.
3. Evidence-backed outcomes: high-risk verdicts must be supported by explicit, machine-referenceable signals.
4. Policy-gated side effects: network fetching, OCR, and audio transcription are opt-in and bounded.
5. Optional judge: a model can act as a constrained advisor; its output is merged by explicit rules and validated online.
6. Software-engineering KPIs still apply: accuracy, latency, CPU/memory/network cost, stability, reliability, and auditability.
7. Budgeted context: large artifacts (attachments/pages) are processed into bounded summaries and machine-referenceable evidence, not blindly inlined into model prompts.

References:

1. `docs/architecture.md` (current pipeline and code layout)
2. `AGENTS.md` (engineering rules and architectural boundaries)
3. Online pipeline: `src/phish_email_detection_agent/orchestrator/pipeline.py`

## 2. Positioning: Agent Engineering as Software Engineering Evolution

This project treats agent engineering as an evolution of software engineering, not a replacement.

1. Traditional software building blocks still exist: modules, contracts, deterministic logic, tests, and SLOs.
2. The model introduces a new control pattern: probabilistic reasoning under explicit policy constraints.
3. `tools` and `skills` preserve composability and auditability by keeping the system modular.

Concept mapping:

| Traditional software engineering | Argis agent engineering |
| --- | --- |
| Functions/modules | `tools` (atomic deterministic capabilities) |
| Workflows | `skills` (policy-declared units and execution intent) |
| Orchestration | `orchestrator` control stack |
| Configuration/rules | pipeline policy + safety flags |
| Logs/tracing | trace events + provenance + `skill_trace` |
| Release gates | ruff/pytest + offline evaluation regression checks |

## 3. Scope and Non-Goals

In scope:

1. Online inference flow: `api/ui/cli` -> `orchestrator` -> `policy` + `tools`.
2. Deterministic evidence building, pre-score routing, and controlled deep context collection.
3. Optional judge invocation and verdict merge.
4. Safety posture, traceability, and evaluation/quality gates.

Non-goals:

1. A purely model-driven detector that bypasses deterministic evidence construction.
2. Unbounded network execution or private-network traversal by default.
3. Mixing offline experimental logic into the online serving path.
4. Silent API breaks or indefinite compatibility layers.

## 4. Terms and Contracts

Definitions used throughout this document:

| Term | Meaning in Argis |
| --- | --- |
| Tool | An atomic capability (typically deterministic) that can be executed by code and optionally exposed to the model as a function tool. |
| Skill | A policy-declared unit of workflow intent, composed of tool calls and deterministic logic, enforced by a whitelist. |
| Artifact | Raw or large derived content (attachment bytes, fetched HTML, extracted text) stored separately and referenced from evidence. |
| EvidencePack | Structured evidence object (`domain/evidence.py::EvidencePack`) produced by the deterministic kernel. |
| Precheck | A deterministic diagnostics bundle built alongside `EvidencePack` (`EvidenceStage.build()` output). |
| Pre-score route | Deterministic route label `allow|review|deep` stored in `EvidencePack.pre_score.route`. |
| Execution path | High-level processing depth `FAST|STANDARD|DEEP` derived from routing decisions. |
| JudgeContext | A bounded, redacted view of evidence prepared for the judge prompt (summaries/snippets + stable references). |
| Context budget | Explicit caps (tokens/bytes/items) that bound extraction, storage, and judge input size. |
| Judge | A constrained model pass that reads a `JudgeContext` and proposes a verdict/score. |
| Validator | Online guardrails to reject invalid outputs (`orchestrator/validator.py`). |

Primary output contract:

1. `TriageResult` (`domain/evidence.py::TriageResult`) is the emitted payload.
2. Invariants: `risk_score` is integer-like and in `[0, 100]`; verdict is one of `benign|suspicious|phishing`.

## 5. Requirements

### 5.1 Functional Requirements

1. Accept email-like inputs (text/JSON/EML path) and normalize to `EmailInput`.
2. Extract and score phishing-relevant signals across the attack chain: headers, URLs/domains, attachments, and optional web/attachment deep context.
3. Produce a verdict + risk score + indicators + recommended actions.
4. Provide evidence and provenance for auditability and debugging.
5. Support optional model-assisted judging under explicit policy gating.

### 5.2 Non-Functional Requirements

1. Deterministic by default: no external side effects unless explicitly enabled.
2. Bounded side effects: timeouts, redirect limits, byte caps, attachment read caps.
3. Reliability: always return a valid result via deterministic fallback.
4. Maintainability: stable contracts, clear boundaries, no import-cycle regressions.
5. Operational performance: predictable latency profiles with stage-level visibility.

## 6. Architecture Overview

Argis follows a control-stack architecture (layered design):

1. `policy` layer: what to do and in what order.
2. `tools` layer: atomic capabilities (bounded execution).
3. `orchestrator` layer: runtime wiring, routing, judge merge, validation.
4. delivery interfaces: `api/ui/cli` call orchestrator only.

Dependency direction (enforced):

1. `policy` -> `domain`.
2. `tools` -> `domain`, `infra`.
3. `orchestrator` -> `policy`, `tools`, `domain`, `providers`.
4. `api/ui/cli` -> `orchestrator`.

High-level component diagram:

```mermaid
flowchart LR
  UI[api/ui/cli] --> ORCH[orchestrator]
  ORCH --> POL[policy]
  ORCH --> TOOLS[tools]
  ORCH --> DOM[domain]
  ORCH --> PROVIDERS[providers]
  TOOLS --> DOM
  TOOLS --> INFRA[infra]
  POL --> DOM
```

Key implementation anchors:

1. Composition root: `src/phish_email_detection_agent/orchestrator/build.py::create_agent`.
2. Online service: `src/phish_email_detection_agent/orchestrator/pipeline.py::AgentService`.
3. Deterministic kernel: `src/phish_email_detection_agent/orchestrator/stages/evidence_stage.py::EvidenceStage`.
4. Routing: `src/phish_email_detection_agent/orchestrator/skill_router.py::SkillRouter`.
5. Judge: `src/phish_email_detection_agent/orchestrator/stages/judge.py::JudgeEngine`.
6. Guardrails: `src/phish_email_detection_agent/orchestrator/validator.py::OnlineValidator`.

### 6.1 Providers and Runtime Configuration

Runtime configuration is loaded from YAML + environment and then wired into `AgentService`.

1. Config loader: `src/phish_email_detection_agent/config/settings.py::load_config`.
2. Provider/model wiring: `src/phish_email_detection_agent/providers/llm_openai.py::build_model_reference`.
3. Tool registration for Agents runtime: `src/phish_email_detection_agent/tools/registry.py::ToolRegistry`.

Operationally relevant behaviors:

1. `AgentService.can_call_remote()` returns false when the Agents SDK is unavailable (`importlib.util.find_spec(\"agents\") is None`).
2. For `provider=openai`, judge/model calls require an API key (`MY_AGENT_APP_API_KEY` or `OPENAI_API_KEY`).
3. For local providers (LiteLLM/Ollama path), the model reference is a `LitellmModel` adapter (`providers/llm_ollama.py`).

Safety-relevant config switches (selected):

1. `MY_AGENT_APP_ENABLE_URL_FETCH` (default false)
2. `MY_AGENT_APP_ALLOW_PRIVATE_NETWORK` (default false)
3. `MY_AGENT_APP_FETCH_TIMEOUT_S`, `MY_AGENT_APP_FETCH_MAX_REDIRECTS`, `MY_AGENT_APP_FETCH_MAX_BYTES`
4. `MY_AGENT_APP_ATTACHMENT_MAX_READ_BYTES`
5. `MY_AGENT_APP_ENABLE_OCR`, `MY_AGENT_APP_ENABLE_AUDIO_TRANSCRIPTION`
6. `MY_AGENT_APP_ENABLE_DEEP_ANALYSIS` (enables URL fetch/OCR/ASR unless explicitly overridden)

## 7. Data and Interface Contracts

### 7.1 Inputs

Primary normalized input: `domain/email/models.py::EmailInput`.

Important fields (conceptual):

1. `text`, `body_text`, `body_html`
2. `headers`, `headers_raw`
3. `urls` (explicit user-provided)
4. `attachments` (file paths)

Parsing entrypoint (online): `domain/email/parse.py::parse_input_payload`.

### 7.2 EvidencePack

`domain/evidence.py::EvidencePack` is the deterministic evidence container.

It includes:

1. `email_meta`: sender/subject/date and counts.
2. `header_signals`: SPF/DKIM/DMARC and relay anomalies.
3. `url_signals`: URL and domain risk flags.
4. `web_signals`: optional safe-fetch HTML indicators.
5. `attachment_signals`: attachment surface heuristics.
6. `nlp_cues`: social-engineering and credential-theft cues.
7. `pre_score`: risk score + route + reasons.
8. `provenance`: timing, limits, and error markers.

### 7.3 TriageResult

`domain/evidence.py::TriageResult` is the emitted output payload.

Minimum online invariants:

1. `verdict` in `{benign, suspicious, phishing}`.
2. `risk_score` in `[0, 100]`.
3. `phishing` verdict should include non-empty `indicators` and an `evidence` payload.

### 7.4 API Surface

Current FastAPI endpoint: `src/phish_email_detection_agent/api/app.py`.

1. `POST /analyze`: accepts `{ "text": "...", "model": "optional" }`.
2. Returns analysis result plus `runtime`, `skillpacks`, and `tools` metadata.

## 8. Runtime Flow and Failure Semantics

Online execution is orchestrated by `orchestrator/stages/executor.py::PipelineExecutor`.

Sequence (simplified):

```mermaid
sequenceDiagram
  participant C as Client
  participant A as AgentService
  participant E as EvidenceStage
  participant R as SkillRouter
  participant J as JudgeEngine
  participant V as OnlineValidator

  C->>A: analyze(text)
  A->>E: build EvidencePack + precheck
  E-->>A: evidence_pack, precheck
  A->>R: plan(route, has_content, can_call_remote)
  R-->>A: should_invoke_judge + path
  alt judge disabled/unavailable
    A-->>C: deterministic fallback result
  else judge enabled
    A->>J: evaluate(redacted JudgeContext)
    J->>V: validate merged result
    alt validation error or judge error
      A-->>C: deterministic fallback result
    else ok
      A-->>C: final merged result
    end
  end
```

Failure semantics (must hold):

1. Empty input returns deterministic fallback.
2. Remote/model path unavailable returns deterministic fallback.
3. Judge failure or invalid output returns deterministic fallback.

## 9. Deterministic Kernel Design

### 9.1 Fixed Skill Chain

The deterministic kernel uses a fixed whitelist-driven chain (executed inside `EvidenceStage.build()`):

`EmailSurface -> HeaderAnalysis -> URLRisk -> NLPCues -> AttachmentSurface -> (optional) PageContentAnalysis -> (optional) AttachmentDeepAnalysis -> RiskFusion`

Properties:

1. Skills are registered in a whitelist-backed `SkillRegistry` (`policy/registry.py`).
2. Skill metadata is fixed and capped at `max_steps <= 5` (`policy/fixed_chain.py`).
3. Every skill execution records `status` and `elapsed_ms` into `precheck.skill_trace`.

### 9.2 Deep Context Trigger

Deep context collection is conditional:

1. Triggered by risk score threshold (`context_trigger_score`) and/or risky URL/attachment flags.
2. Implemented by `orchestrator/precheck.py::should_collect_deep_context`.

### 9.3 Pre-Score Routing

Pre-score is computed via `orchestrator/precheck.py::compute_pre_score`.

Key parameters (defaults from `orchestrator/pipeline_policy.py`):

| Parameter | Default | Meaning |
| --- | --- | --- |
| `pre_score_review_threshold` | 30 | `risk_score <= threshold` routes to `allow` |
| `pre_score_deep_threshold` | 70 | `risk_score > threshold` routes to `deep` |
| `context_trigger_score` | 35 | threshold to enable deep context collection |
| `suspicious_min_score` | 30 | low band for ambiguous verdict calibration |
| `suspicious_max_score` | 34 | high band for ambiguous verdict calibration |

Important distinction:

1. `allow|review|deep` is a deterministic routing label for workflow selection.
2. Final `verdict` is separately derived/merged and can still be `phishing` at lower routes.

### 9.4 Determinism and Reproducibility Boundaries

Argis is deterministic by default, but determinism depends on enabled capabilities.

1. Deterministic kernel (default posture): with URL fetch, OCR, and audio transcription disabled, outputs are reproducible for the same normalized input and attachment bytes.
2. Network-enabled posture: when URL fetch is enabled, results can change over time (remote content, redirects, availability). In this mode, auditability is preserved by including fetch reports and provenance, but strict reproducibility requires capturing fetched artifacts.
3. Provenance: `EvidencePack.provenance` and `precheck.fetch_policy` are treated as part of the reproducibility contract (what limits were applied, what was skipped/blocked).

### 9.5 Context Management and Evidence Compaction

Phishing analysis can produce more context than a model can (or should) ingest: long email bodies, multiple attachments, and multiple fetched pages. Treating "context" as a chat transcript and dumping everything into the judge is not scalable, is costly, and increases prompt injection risk.

Design goal:

1. Preserve all relevant information as machine-referenceable evidence and artifacts.
2. Provide the judge with a budgeted `JudgeContext` that contains only selected, redacted summaries/snippets and stable references.

#### 9.5.1 Artifact vs. EvidencePack vs. JudgeContext

1. Artifacts: raw bytes and large derived text (attachment bytes, fetched HTML, extracted text). Stored separately (ideally via `orchestrator/evidence_store.py`) with stable IDs and content hashes.
2. EvidencePack: the canonical deterministic container. Stores compact signals, risk flags, extracted entities (URLs/domains), and small snippets (with offsets/anchors) plus `artifact_id` references.
3. JudgeContext: a redacted + compacted projection of `EvidencePack` built under explicit budgets. It is the only object intended to be serialized into the judge prompt.

#### 9.5.2 Compaction pipeline (conceptual)

For each content source (email body, attachment, fetched page), tools should follow an explicit compaction pipeline:

1. Extract (bounded): read at most N bytes; extract text/URLs/metadata deterministically.
2. Sanitize: remove scripts/styles, normalize whitespace, decode common encodings, redact secrets, strip binary-ish sections.
3. Segment: chunk into logical units (paragraphs, pages, sections) with stable anchors.
4. Score: rank chunks by phishing relevance (credential requests, urgency, payment, brand + login forms, suspicious domains).
5. Select: keep top-K snippets per artifact and top-M artifacts overall (prioritized by pre-score and risk flags).
6. Summarize (optional, gated): generate short per-artifact summaries only from selected snippets/signals; never require the full raw artifact in the prompt.
7. Record omissions: if truncation happens, record what was omitted and why in provenance.

This is intentionally tool-driven and deterministic-first: the judge should not be responsible for reading full artifacts.

#### 9.5.3 Budget controls (to codify in config/policy)

Budgets should be explicit and observable (not implicit "whatever fits"):

1. Judge prompt budget: `judge_context_max_tokens`.
2. Per-source budgets: `max_email_body_chars`, `max_extracted_text_chars_per_artifact`.
3. Entity budgets: `max_urls_in_context`, `max_pages_fetched`, `max_attachments_in_context`.
4. Snippet budgets: `max_snippets_per_artifact`, `max_chars_per_snippet`.
5. Deep-analysis budgets: `max_deep_urls`, `max_deep_attachments`, plus existing fetch/attachment byte caps.

Budget enforcement requirements:

1. If budgets are exceeded, the system must degrade gracefully (keep strongest signals + record truncation).
2. Truncation must never remove all evidence for a high-risk verdict; prefer dropping low-signal artifacts first.
3. Provenance must capture applied budgets so results remain auditable.

#### 9.5.4 Tool cooperation patterns (email + attachments + web)

1. URL flow: `EmailSurface` and `AttachmentSurface` extract URLs -> `URLRisk` scores them -> `PageContentAnalysis` fetches only top-risk URLs -> results become compact `web_signals` + snippets with `artifact_id` references.
2. Attachment flow: `AttachmentSurface` emits metadata + embedded URLs + lightweight strings -> `AttachmentDeepAnalysis` runs only for top-risk attachment candidates -> emits compact signals (macro flags, embedded objects, extracted URLs, suspicious strings) and top snippets.
3. Cross-linking: when a URL is extracted from an attachment/page, record `(source_artifact_id, url)` so the attack chain remains traceable without inlining the full source.
4. Evidence identity: every snippet included in `JudgeContext` should carry enough reference info (`artifact_id`, page/offset, extractor/tool name) to locate its origin.

#### 9.5.5 HTML compaction and encoding normalization (recommended tools)

Fetched web pages and attachments commonly contain HTML noise and obfuscation layers. To keep context bounded and improve signal extraction, treat HTML parsing + decoding as first-class deterministic tool capabilities.

HTML compaction (fetched pages):

1. Prefer DOM parsing over regex (e.g., BeautifulSoup/bs4 or an equivalent tolerant HTML parser).
2. Drop `script/style/noscript`, comments, and boilerplate; normalize whitespace.
3. Extract phishing-relevant structures as compact signals:
   - forms (`<form action=...>`, `password` inputs, hidden inputs), meta refresh, external script sources, and outbound links/domains
4. Produce bounded snippet candidates from visible text (title + top-K high-signal paragraphs) with stable anchors (offsets/selectors) and a truncation marker when applicable.

Encoding normalization (URLs + text + HTML attributes):

1. Normalize common encodings used for obfuscation: percent-encoding (URL encoding), HTML entities, and safe charset decoding (from headers/meta).
2. Detect and boundedly decode base64 in common places (query params, hidden fields, `data:` URIs), with strict limits:
   - max decode bytes
   - max expansion ratio
   - max decode depth (e.g., URL-encoded -> base64 -> text)
3. Always record a decode chain in provenance (what transforms were applied, what failed, what was skipped due to budgets).
4. Never execute decoded content; treat it as untrusted text/bytes for analysis only.

## 10. Judge Integration Design

The judge is treated as a constrained advisor.

Judge inputs:

1. A redacted, budgeted `JudgeContext` built from `EvidencePack` (`evidence/redact.py::redact_value`).
2. The prompt explicitly treats evidence text as untrusted.

Judge outputs:

1. A structured `JudgeOutput` JSON (`domain/evidence.py::JudgeOutput`).
2. Merged by explicit rules (`orchestrator/verdict_routing.py`).
3. Validated by `OnlineValidator` (`orchestrator/validator.py`).

Merge principles:

1. Deterministic score >= phishing threshold remains phishing.
2. Judge can promote/demote based on confidence and policy thresholds.
3. Online product decision currently collapses `suspicious` to `phishing` after merge (binary-facing triage).

Safety note (design requirement):

1. The tool surface exposed to the judge must not allow bypassing runtime side-effect policy.
2. Function tools should enforce enablement from runtime config, not model-controlled flags.

### 10.1 Side-Effect Policy Enforcement (Important)

Do not rely on prompts alone to enforce safety. Side-effect policy must be enforced in code.

1. If a function tool accepts a model-controlled `enable_*` flag for side effects (fetch/OCR/ASR), it creates a policy bypass risk.
2. Preferred pattern: the tool implementation derives enablement from `AgentService` (or an equivalent runtime policy object) rather than from model-supplied arguments.
3. If a tool must expose a toggle (for interactive use), it must still hard-check the runtime policy and refuse when disabled.

## 11. Tools, Skills, and Governance

### 11.1 Tools

Tools are atomic capabilities with explicit constraints.

In this repo, tools exist in two forms:

1. Deterministic analyzers under `src/phish_email_detection_agent/tools/`.
2. Function tools registered for Agents runtime (`tools/registry.py`, `tools/openai/builtin.py`).

Tool requirements:

1. Deterministic outputs for deterministic inputs (when no external side effects are enabled).
2. Explicit bounding policy for any side-effectful operations.
3. Clear contracts and test coverage.

### 11.2 Skills

Skills represent policy-declared workflow units.

Current online deterministic execution uses fixed built-in skills (`policy/fixed_chain.py`) executed inside `EvidenceStage`.

Skillpacks:

1. Local skillpacks are discovered and surfaced in runtime metadata (`policy/catalog.py`).
2. Skillpack discovery is currently informational (UI/API metadata) rather than altering the fixed deterministic chain.

### 11.3 Current Gaps and Follow-ups

These items are important to track explicitly because they affect safety, maintainability, and long-term architecture hygiene.

1. `orchestrator/evidence_store.py` provides stable evidence IDs, but the online pipeline currently relies on `EvidencePack` as the primary evidence container (no store/graph integration yet).
2. `orchestrator/tool_executor.py` provides a normalized execution wrapper, but the deterministic kernel currently calls tools directly (no unified retry/telemetry contract yet).
3. Skillpacks are discovered and surfaced, but do not currently participate in the default deterministic skill chain. If skillpacks become executable policy, the integration must preserve whitelist semantics and bounded side effects.
4. Routing has two representations in the repo (`allow|review|deep` vs `FAST|STANDARD|DEEP`). Keep contracts explicit to avoid confusing UI/API consumers.
5. Judge context budgeting/compaction is currently described as a design requirement, but needs to be made a first-class module (explicit budgets, truncation provenance, and a `JudgeContext` builder) to prevent prompt bloat and improve tool-to-judge handoff quality.

## 12. Safety, Security, and Privacy

### 12.1 Safety Defaults

Safe defaults are configured in `config/settings.py`:

1. URL fetch disabled by default (`MY_AGENT_APP_ENABLE_URL_FETCH=false`).
2. Private network blocked by default (`MY_AGENT_APP_ALLOW_PRIVATE_NETWORK=false`).
3. OCR and audio transcription disabled by default.
4. Redirect, timeout, and max-byte caps on fetch.
5. Attachment read cap via `AttachmentPolicy.max_read_bytes`.

One-switch deep analysis:

1. `MY_AGENT_APP_ENABLE_DEEP_ANALYSIS=true` enables URL fetch, OCR, and audio transcription unless explicitly overridden.

### 12.2 Threat Model (Selected)

1. Prompt injection via email/web content.
2. SSRF and private-network probing via URL fetch.
3. Malicious or oversized content (attachments, HTML, redirect chains).
4. Brand impersonation and IDN/punycode spoofing.
5. Model output invalidity (schema violations, hallucinated evidence).
6. Obfuscation via multi-layer encodings (percent-encoding, HTML entities, base64, `data:` URIs).

Mitigations (current and required):

1. Redact evidence before judge; treat all content as untrusted.
2. Safe fetch enforces scheme allowlist, DNS resolution checks, private IP blocking, redirect limits, and byte caps.
3. Attachment analysis is static-first with explicit read caps and optional OCR/ASR.
4. Online validator rejects invalid outputs.
5. Deterministic fallback is always available.
6. Deterministic HTML compaction + encoding normalization with explicit budgets and decode-chain provenance (see §9.5).

### 12.3 Privacy

1. Redaction masks emails and obvious tokens and sanitizes URL query params.
2. Judge receives redacted evidence; raw content should be treated as sensitive.
3. Any future persistence of evidence should have an explicit retention policy.

## 13. Observability and Operations

Current visibility:

1. `AgentService.analyze_stream()` emits stage events with `stage/status/message/data`.
2. Evidence provenance includes timings and limits/errors.

Recommended production instrumentation (to implement and enforce):

1. Stage latency histograms per stage name.
2. Counters: total requests, judge invoked, judge failed, fallback returned, validation errors.
3. Side-effect counters: bytes fetched, redirects followed, attachments analyzed, OCR/ASR enabled rates.
4. Resource tracking: CPU and RSS per request at service boundary.
5. Context budgeting metrics: truncation rate, selected snippets count, and judge-context size (tokens/bytes).

Operational playbooks:

1. Degraded mode: disable judge and deep context collection, rely on deterministic kernel.
2. Incident response: investigate spikes in fallback rate, validation errors, or fetch blocks.

## 14. Evaluation and Quality

Evaluation must account for both correctness and system properties.

Quality dimensions:

1. Detection quality: precision/recall/F1, false positives/negatives, evidence-backed verdict rate.
2. Performance: end-to-end p50/p95/p99, stage latency, throughput.
3. Efficiency: CPU/memory/network, model-call cost, deep-analysis frequency.
4. Reliability: success rate, timeout rate, judge failure rate, validation issue rate.

Offline evaluation:

1. `orchestrator/evaluator.py` provides binary metrics (with configurable suspicious handling).
2. Offline evaluation is the correct place for calibration experiments and regression tracking.

## 15. Testing and Release Gates

Mandatory repo checks:

```bash
uv sync
ruff check src tests docs scripts
pytest -k 'not hf_phishing_email_balanced_sample'
```

Recommended for control-stack changes:

```bash
pytest tests/orchestrator/test_control_stack.py
pytest tests/orchestrator/test_text_prescore.py tests/orchestrator/test_pipeline_smoke.py
```

Release discipline:

1. No architecture boundary violations.
2. No import-cycle regressions.
3. Changes to outputs require docs/tests updates in the same change.

### 15.1 Change Management and API Stability

Argis should evolve like a production service, not like an experimental notebook.

1. Avoid breaking response keys unless explicitly approved; if change is required, ship a migration plan and a removal milestone.
2. Treat tool and skill interfaces as public contracts once exposed via API/runtime metadata.
3. If compatibility layers are introduced, time-bound them and document the removal criteria.

## 16. One-Page Review Summary

### 16.1 Architecture Snapshot

```mermaid
flowchart LR
    A[Email Input\ntext/html/headers/attachments] --> B[Deterministic Evidence Stage\nEmailSurface/HeaderAnalysis/URLRisk/NLPCues/AttachmentSurface]
    B --> C[Risk Fusion + Pre-Score\nallow/review/deep]
    C --> D{Judge Needed?}
    D -- No --> E[Deterministic Fallback Result]
    D -- Yes --> F[Judge Engine\nredacted JudgeContext]
    F --> G[Verdict Merge + Calibration]
    G --> H[Online Validator]
    H --> I[Final Triage Result\nverdict/risk/evidence/metadata]
    H -->|validation error| E
```

### 16.2 KPI and SLO Framework

The following are initial targets and must be agreed with product/security stakeholders.

| Domain | KPI | Target / SLO |
| --- | --- | --- |
| Detection Quality | Phishing Recall | >= 0.92 on agreed benchmark set |
| Detection Quality | Precision | >= 0.90 on agreed benchmark set |
| Detection Quality | F1 | >= 0.91 |
| Reliability | Successful Response Rate | >= 99.9% |
| Reliability | Deterministic Fallback Rate | <= 5% (excluding planned degraded windows) |
| Latency | End-to-End p95 | <= 2.5s (FAST/STANDARD mixed profile) |
| Latency | End-to-End p99 | <= 5.0s |
| Efficiency | CPU per request | baseline tracked, <= 15% regression per release |
| Efficiency | Memory per request | baseline tracked, <= 15% regression per release |
| Cost | Judge Invocation Rate | policy controlled and budget-aligned |
| Trust | Evidence-backed High-Risk Verdict Rate | 100% for phishing verdicts |
| Safety | Private-Network Access Violations | 0 |

Metric definitions (operationally important):

1. Successful Response Rate: fraction of requests returning a valid `TriageResult` payload (validator passes, required keys present).
2. Deterministic Fallback Rate: fraction of requests that return the deterministic fallback path (for example, `provider_used` ends with `:fallback`).
3. Latency percentiles: measured at the service boundary for the full request, and stage-level where available.

### 16.3 12-Month Roadmap (Engineering View)

| Phase | Time Window | Primary Objective | Deliverables |
| --- | --- | --- | --- |
| Phase 1 | M1-M3 | Measurement foundation | end-to-end telemetry, stage-level dashboards, baseline benchmark suite |
| Phase 2 | M4-M6 | Quality and calibration hardening | threshold tuning playbook, judge calibration experiments, FP/FN analysis |
| Phase 3 | M7-M9 | Reliability and scaling | load validation, fallback taxonomy, resilience drills |
| Phase 4 | M10-M12 | Governance and productization | formal SLO policy, release gates, architecture review checklist |
