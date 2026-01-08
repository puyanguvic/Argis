"""Main agent orchestrator using router + scoring."""

from __future__ import annotations

from email.utils import parseaddr
from hashlib import sha256
from pathlib import Path
import time

import yaml

from engine.config import AgentConfig
from engine.explanation import build_explanation
from engine.policy import PolicyEngine
from engine.recorder import RunRecorder
from engine.router import plan_routes
from engine.state import DetectionResult
from schemas.email_schema import EmailInput
from schemas.evidence_schema import EvidenceStore
from tools_builtin.attachment_analyzer import attachment_static_scan
from tools_builtin.content_analyzer import semantic_extract
from tools_builtin.domain_risk import domain_risk_assess
from tools_builtin.parser import parse_raw_email
from tools_builtin.url_analyzer import url_chain_resolve
from tools_builtin.url_utils import extract_urls


DEFAULT_CONFIG_PATHS = (
    Path("configs/profiles/balanced.yaml"),
    Path("configs/default.yaml"),
)


class AgentOrchestrator:
    """Coordinates routing, tools, scoring, and explanations."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config = self._load_config(config_path)
        self.policy = PolicyEngine(self.config)

    def detect(self, email: EmailInput, record_path: str | Path | None = None) -> DetectionResult:
        recorder = RunRecorder(record_path) if record_path else None
        start = time.perf_counter()
        try:
            result = self._detect_with_recorder(email, recorder)
            elapsed_ms = int(round((time.perf_counter() - start) * 1000))
            return DetectionResult(
                email=result.email,
                evidence=result.evidence,
                verdict=result.verdict,
                risk_score=result.risk_score,
                explanation=result.explanation,
                trace_id=result.trace_id,
                runtime_ms=elapsed_ms,
            )
        finally:
            if recorder:
                recorder.close()

    def detect_raw(self, raw_email: str, record_path: str | Path | None = None) -> DetectionResult:
        email = parse_raw_email(raw_email)
        return self.detect(email, record_path=record_path)

    def _detect_with_recorder(
        self,
        email: EmailInput,
        recorder: RunRecorder | None,
    ) -> DetectionResult:
        evidence = plan_routes(email, self.config.router)

        if recorder:
            recorder.record(
                "router",
                {"email": email, "evidence": evidence},
                {
                    "quick_features": evidence.quick_features,
                    "preliminary_score": evidence.preliminary_score,
                    "path": evidence.path,
                    "plan": evidence.plan,
                },
            )

        tool_map = _build_tool_map(email, evidence)
        executed_tools: set[str] = set()
        if evidence.plan:
            for tool_name in evidence.plan.tools:
                tool = tool_map.get(tool_name)
                if tool is None:
                    continue
                observation = tool()
                _assign_observation(evidence, tool_name, observation)
                executed_tools.add(tool_name)
                if recorder:
                    recorder.record(tool_name, {"email": email}, observation)

        if _should_escalate_contextually(email, evidence, self.config):
            _apply_contextual_escalation(
                email,
                evidence,
                self.config,
                tool_map,
                executed_tools,
                recorder,
            )

        verdict, risk_score, breakdown = self.policy.decide(evidence)
        explanation = build_explanation(evidence, verdict, risk_score, breakdown)
        if recorder:
            recorder.record(
                "final",
                {"email": email, "evidence": evidence},
                {
                    "verdict": verdict,
                    "risk_score": risk_score,
                    "hard_rules": evidence.hard_rule_matches,
                },
            )
        trace_id = _make_trace_id(email)
        return DetectionResult(
            email=email,
            evidence=evidence,
            verdict=verdict,
            risk_score=risk_score,
            explanation=explanation,
            trace_id=trace_id,
            runtime_ms=0,
        )

    @staticmethod
    def _load_config(config_path: str | Path | None) -> AgentConfig:
        if not config_path:
            for candidate in DEFAULT_CONFIG_PATHS:
                if candidate.exists():
                    config_path = candidate
                    break
        if not config_path:
            return AgentConfig()
        path = Path(config_path)
        if not path.exists():
            return AgentConfig()
        data = yaml.safe_load(path.read_text()) or {}
        return AgentConfig.from_mapping(data)


def _collect_domains(email: EmailInput, evidence: EvidenceStore) -> list[str]:
    domains: list[str] = []
    if evidence.url_chain:
        domains.extend(
            [item.final_domain for item in evidence.url_chain.chains if item.final_domain]
        )
    sender_domain = email.sender.split("@")[-1] if "@" in email.sender else ""
    if sender_domain:
        domains.append(sender_domain)
    return sorted(set(domains))


def _make_trace_id(email: EmailInput) -> str:
    date = email.received_ts.date()
    stamp = date.strftime("%Y%m%d")
    payload = f"{email.sender}|{email.subject}|{email.received_ts.isoformat()}".encode("utf-8")
    digest = sha256(payload).hexdigest()[:6]
    return f"phish-{stamp}-{digest}"


def _build_tool_map(email: EmailInput, evidence: EvidenceStore) -> dict[str, callable]:
    urls = email.urls or extract_urls([email.body_text, email.body_html])

    def _header():
        return evidence.header_auth

    def _semantic():
        return semantic_extract(email.subject, email.body_text, email.body_html)

    def _urls():
        return url_chain_resolve(urls)

    def _domain():
        domains = _collect_domains(email, evidence)
        return domain_risk_assess(domains)

    def _attachments():
        return attachment_static_scan(email.attachments)

    return {
        "header_auth_check": _header,
        "semantic_extract": _semantic,
        "url_chain_resolve": _urls,
        "domain_risk_assess": _domain,
        "attachment_static_scan": _attachments,
    }


def _assign_observation(evidence: EvidenceStore, tool_name: str, observation: object) -> None:
    if tool_name == "header_auth_check":
        evidence.header_auth = observation
    elif tool_name == "semantic_extract":
        evidence.semantic = observation
    elif tool_name == "url_chain_resolve":
        evidence.url_chain = observation
    elif tool_name == "domain_risk_assess":
        evidence.domain_risk = observation
    elif tool_name == "attachment_static_scan":
        evidence.attachment_scan = observation


def _domain_from_sender(sender: str) -> str:
    _, address = parseaddr(sender or "")
    if "@" not in address:
        return ""
    return address.split("@", 1)[-1].lower()


def _body_and_subject(email: EmailInput) -> str:
    parts = [email.subject or ""]
    if email.body_text:
        parts.append(email.body_text)
    if email.body_html:
        parts.append(email.body_html)
    return "\n".join(parts).lower()


def _should_escalate_contextually(
    email: EmailInput,
    evidence: EvidenceStore,
    config: AgentConfig,
) -> bool:
    if not config.contextual_escalation.enabled:
        return False
    if evidence.path != "FAST":
        return False
    semantic = evidence.semantic
    if not semantic:
        return False
    sender_domain = _domain_from_sender(email.sender)
    allowlist = {domain.lower() for domain in config.allowlist_domains}
    sender_external = not allowlist or sender_domain not in allowlist
    if not sender_external:
        return False

    intents = {intent.lower() for intent in config.contextual_escalation.intents}
    if semantic.intent.lower() not in intents:
        return False

    brands = {brand.lower() for brand in semantic.brand_entities}
    contextual_brands = {brand.lower() for brand in config.contextual_escalation.brands}
    brand_match = bool(brands & contextual_brands)

    keywords = [keyword.lower() for keyword in config.contextual_escalation.keywords]
    text = _body_and_subject(email)
    keyword_match = any(keyword in text for keyword in keywords)

    return brand_match or keyword_match


def _apply_contextual_escalation(
    email: EmailInput,
    evidence: EvidenceStore,
    config: AgentConfig,
    tool_map: dict[str, callable],
    executed_tools: set[str],
    recorder: RunRecorder | None,
) -> None:
    if not evidence.plan:
        return
    if evidence.plan.path != "FAST":
        return

    evidence.degradations.append("profile_escalated_contextual_signal")
    evidence.path = "STANDARD"
    evidence.plan.path = "STANDARD"
    standard_tools = list(config.router.standard_tools)
    evidence.plan.tools = standard_tools

    for tool_name in standard_tools:
        if tool_name in executed_tools:
            continue
        tool = tool_map.get(tool_name)
        if tool is None:
            continue
        observation = tool()
        _assign_observation(evidence, tool_name, observation)
        executed_tools.add(tool_name)
        if recorder:
            recorder.record(tool_name, {"email": email}, observation)
