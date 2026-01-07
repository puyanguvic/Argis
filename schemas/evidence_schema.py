"""Evidence and tool result schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class HeaderAuthResult(BaseModel):
    """Parsed header authentication results."""

    spf: str
    dkim: str
    dmarc: str
    aligned: bool
    anomalies: List[str] = Field(default_factory=list)


class UrlChainHop(BaseModel):
    """Single hop in a URL resolution chain."""

    url: str


class UrlChainItem(BaseModel):
    """Resolved URL chain information."""

    input: str
    hops: List[UrlChainHop]
    final_url: str
    final_domain: str
    has_ip: bool
    suspicious_tld: bool
    shortener: bool
    contains_login_keywords: bool


class UrlChainResult(BaseModel):
    """URL chain resolution results."""

    chains: List[UrlChainItem] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class DomainRiskItem(BaseModel):
    """Risk assessment for a domain."""

    domain: str
    levenshtein_to_brand: int
    homoglyph_suspected: bool
    age_days: Optional[int] = None
    risk_flags: List[str] = Field(default_factory=list)


class DomainRiskResult(BaseModel):
    """Aggregated domain risk result."""

    items: List[DomainRiskItem] = Field(default_factory=list)


class SemanticResult(BaseModel):
    """Semantic signal extraction."""

    intent: str
    model_config = ConfigDict(populate_by_name=True)
    urgency_level: int = Field(alias="urgency")
    brand_entities: List[str] = Field(default_factory=list)
    requested_actions: List[str] = Field(default_factory=list)
    confidence: float

    @property
    def urgency(self) -> int:
        return self.urgency_level


class AttachmentScanItem(BaseModel):
    """Static attachment scan output."""

    sha256: str
    has_macro: Optional[bool] = None
    is_executable: Optional[bool] = None
    flags: List[str] = Field(default_factory=list)


class AttachmentScanResult(BaseModel):
    """Attachment scan results."""

    items: List[AttachmentScanItem] = Field(default_factory=list)


class QuickFeatures(BaseModel):
    """Deterministic router features."""

    from_domain_mismatch: bool = False
    reply_to_mismatch: bool = False
    has_urls: bool = False
    suspicious_subject: bool = False


class PlanSpec(BaseModel):
    """Structured plan for tool execution."""

    path: str
    tools: List[str] = Field(default_factory=list)
    budget_ms: int = 0
    timeout_s: float = 0.0
    fallback: str = "STANDARD"


class EvidenceStore(BaseModel):
    """Container for all tool outputs."""

    header_auth: Optional[HeaderAuthResult] = None
    url_chain: Optional[UrlChainResult] = None
    domain_risk: Optional[DomainRiskResult] = None
    semantic: Optional[SemanticResult] = None
    attachment_scan: Optional[AttachmentScanResult] = None
    quick_features: Optional[QuickFeatures] = None
    preliminary_score: Optional[float] = None
    path: Optional[str] = None
    plan: Optional[PlanSpec] = None
    hard_rule_matches: List[str] = Field(default_factory=list)
    degradations: List[str] = Field(default_factory=list)
