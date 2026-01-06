# PhishAgent

**An Explainable AI Agent for Phishing Email Detection**

---

## Abstract

Phishing email detection remains a critical challenge in modern communication systems, where attacks continuously evolve in content, structure, and delivery strategies. While machine-learning-based classifiers have achieved strong performance on curated datasets, they often struggle with distribution shifts, limited interpretability, and high false-positive costs in real-world deployments.

This project presents **PhishAgent**, an explainable AI agent for phishing email detection that integrates **structured email analysis**, **tool-based evidence extraction**, **lightweight machine learning models**, and **large language model (LLM) reasoning** within a unified decision-making framework. Rather than treating phishing detection as a standalone classification task, PhishAgent formulates it as an **evidence-driven risk assessment problem**, producing interpretable decisions with explicit security rationales.

---

## Problem Setting

We consider the problem of detecting phishing emails from raw email inputs (e.g., `.eml` files), where each email consists of heterogeneous components including headers, body content, embedded URLs, and attachments. The detector must operate under the following constraints:

* **Interpretability**: Decisions must be supported by explicit, human-readable evidence.
* **Low false-positive tolerance**: Incorrect blocking of benign emails is costly.
* **Robustness to distribution shift**: Attack patterns and linguistic styles evolve rapidly.
* **Extensibility**: New attack vectors should be incorporable without retraining the entire system.

---

## Methodology

PhishAgent adopts a **multi-stage, agent-based architecture** that decomposes phishing detection into structured analysis and expert-driven reasoning.

### 1. Email Canonicalization

Incoming emails are first normalized into a canonical structured representation capturing:

* Header fields and delivery paths
* Authentication signals (e.g., identity consistency)
* Plain-text and HTML bodies
* Embedded URLs and attachments

This step isolates semantic content from transport-level noise and enables modular downstream analysis.

### 2. Evidence Extraction via Tools

A collection of specialized analysis tools is applied to extract security-relevant signals, including:

* **Identity and header inconsistencies**
* **URL deception patterns and redirect behaviors**
* **Linguistic intent signals such as urgency, impersonation, and credential requests**
* **Attachment-based risk indicators**

Each tool outputs explicit evidence rather than implicit embeddings.

### 3. Multi-Expert Risk Evaluation

Extracted evidence is evaluated through complementary expert mechanisms:

* **Rule-based heuristics** for high-precision indicators
* **Lightweight machine learning classifiers** for scalable statistical detection
* **LLM-based reasoning modules** for ambiguity resolution and explanation generation

LLMs are selectively invoked only in uncertain cases, ensuring cost efficiency and reducing hallucination risks.

### 4. Risk Fusion and Decision Policy

The final decision is produced by a policy layer that fuses multi-source evidence into:

* A continuous risk score
* A discrete security verdict (benign, suspicious, phishing)
* A structured explanation and recommended mitigation action

---

## Output Representation

PhishAgent outputs security-oriented decisions rather than binary labels, including:

* Risk scores and confidence levels
* Categorized evidence chains
* Actionable recommendations suitable for automated or human-in-the-loop systems

This design enables seamless integration with security operations workflows.

---

## Contributions

The key contributions of this project are:

1. **A unified agent-based framework** for phishing detection emphasizing evidence-driven reasoning.
2. **A hybrid intelligence architecture** combining rules, small models, and LLMs in a principled manner.
3. **Explainable security outputs** that support auditing, debugging, and user trust.
4. **An extensible system design** adaptable to evolving phishing strategies.

---

## Intended Use

PhishAgent is intended for:

* Research on AI agents for security
* Prototyping phishing detection systems
* Studying robustness and interpretability under dataset shift

Public demonstrations use sanitized or synthetic data only.
