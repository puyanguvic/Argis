"""Unified evidence/report structures."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RouterDecision(BaseModel):
    path: Literal["FAST", "STANDARD", "DEEP"]
    needs_deep: bool
    rationale: str = Field(min_length=2)


class InvestigationReport(BaseModel):
    suspicious_urls: list[str] = Field(default_factory=list)
    risky_attachments: list[str] = Field(default_factory=list)
    keyword_hits: list[str] = Field(default_factory=list)
    chain_signals: list[str] = Field(default_factory=list)
    artifact_reports: dict[str, object] = Field(default_factory=dict)
    risk_score: int = Field(ge=0, le=100, default=0)
    summary: str = Field(min_length=2)


class EmailMeta(BaseModel):
    message_id: str = ""
    date: str = ""
    sender: str = ""
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    reply_to: str = ""
    return_path: str = ""
    urls_count: int = 0
    attachments_count: int = 0


class AuthResult(BaseModel):
    result: str = "none"
    domain: str = ""
    policy: str = ""


class HeaderSignals(BaseModel):
    spf: AuthResult = Field(default_factory=AuthResult)
    dkim: AuthResult = Field(default_factory=AuthResult)
    dmarc: AuthResult = Field(default_factory=AuthResult)
    from_replyto_mismatch: bool = False
    received_hops: int = 0
    suspicious_received_patterns: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class BrandSimilarity(BaseModel):
    brand: str = ""
    similarity: float = Field(default=0.0, ge=0.0, le=1.0)


class UrlSignal(BaseModel):
    url: str
    normalized: str = ""
    is_shortlink: bool = False
    expanded_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    final_domain: str = ""
    is_punycode: bool = False
    looks_like_brand: BrandSimilarity = Field(default_factory=BrandSimilarity)
    has_login_keywords: bool = False
    risk_flags: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class WebSignal(BaseModel):
    url: str
    fetch_ok: bool = False
    http_status: int = 0
    final_url: str = ""
    title: str = ""
    form_count: int = 0
    has_password_field: bool = False
    has_otp_field: bool = False
    external_resource_count: int = 0
    text_brand_hints: list[str] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AttachmentSignal(BaseModel):
    filename: str
    mime: str = ""
    size: int = 0
    extension_mismatch: bool = False
    is_archive: bool = False
    is_executable_like: bool = False
    macro_suspected: bool = False
    risk_flags: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class NlpCues(BaseModel):
    urgency: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_language: float = Field(default=0.0, ge=0.0, le=1.0)
    payment_or_giftcard: float = Field(default=0.0, ge=0.0, le=1.0)
    credential_request: float = Field(default=0.0, ge=0.0, le=1.0)
    action_request: float = Field(default=0.0, ge=0.0, le=1.0)
    account_takeover_intent: float = Field(default=0.0, ge=0.0, le=1.0)
    subject_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    phishing_keyword_hits: int = Field(default=0, ge=0)
    impersonation: list[str] = Field(default_factory=list)
    highlights: list[str] = Field(default_factory=list)


class PreScore(BaseModel):
    risk_score: int = Field(ge=0, le=100, default=0)
    route: Literal["allow", "review", "deep"] = "allow"
    reasons: list[str] = Field(default_factory=list)


class Provenance(BaseModel):
    timing_ms: dict[str, int] = Field(default_factory=dict)
    limits_hit: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class EvidencePack(BaseModel):
    email_meta: EmailMeta
    header_signals: HeaderSignals
    url_signals: list[UrlSignal] = Field(default_factory=list)
    web_signals: list[WebSignal] = Field(default_factory=list)
    attachment_signals: list[AttachmentSignal] = Field(default_factory=list)
    nlp_cues: NlpCues = Field(default_factory=NlpCues)
    pre_score: PreScore = Field(default_factory=PreScore)
    provenance: Provenance = Field(default_factory=Provenance)


class TopEvidence(BaseModel):
    claim: str = Field(min_length=2)
    evidence_path: str = Field(min_length=2)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class JudgeOutput(BaseModel):
    verdict: Literal["benign", "suspicious", "phishing"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    top_evidence: list[TopEvidence] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    missing_info: list[str] = Field(default_factory=list)
    reason: str = "Evidence-based assessment."


class TriageOutput(BaseModel):
    verdict: Literal["phishing", "benign", "suspicious"]
    reason: str = Field(min_length=2)
    path: Literal["FAST", "STANDARD", "DEEP"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    indicators: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    verdict: Literal["phishing", "benign", "suspicious"]
    reason: str
    path: Literal["FAST", "STANDARD", "DEEP"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    indicators: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    input: str
    urls: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)
    provider_used: str
    evidence: dict[str, object] = Field(default_factory=dict)
