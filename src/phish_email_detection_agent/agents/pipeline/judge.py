"""Judge stage for evidence-pack based final decision."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from phish_email_detection_agent.agents.contracts import JudgeOutput, TriageResult
from phish_email_detection_agent.agents.pipeline.router import (
    compute_confidence,
    map_route_to_path,
    merge_judge_verdict,
    normalize_score_for_verdict,
)
from phish_email_detection_agent.agents.pipeline.runtime import PipelineRuntime
from phish_email_detection_agent.agents.prompts import JUDGE_PROMPT
from phish_email_detection_agent.evidence.redact import redact_value
from phish_email_detection_agent.tools.text.text_model import derive_email_labels


@dataclass
class JudgeRunResult:
    final_result: dict[str, Any] | None
    judge_output: JudgeOutput | None
    error: Exception | None = None


class JudgeEngine:
    def evaluate(
        self,
        *,
        service: PipelineRuntime,
        email: Any,
        evidence_pack: Any,
        precheck: dict[str, Any],
        fallback: Any,
    ) -> JudgeRunResult:
        try:
            from agents import Agent, AgentOutputSchema, Runner

            common = service.build_common_kwargs()
            judge_agent = Agent(
                name="argis-evidence-judge-agent",
                instructions=JUDGE_PROMPT,
                output_type=AgentOutputSchema(JudgeOutput, strict_json_schema=False),
                **common,
            )
            redacted_pack = redact_value(evidence_pack.model_dump(mode="json"))
            judge_run = Runner.run_sync(
                judge_agent,
                json.dumps({"evidence_pack": redacted_pack}, ensure_ascii=True),
                max_turns=service.max_turns,
            )
            judge_output = JudgeOutput.model_validate(getattr(judge_run, "final_output", {}))

            deterministic_score = int(evidence_pack.pre_score.risk_score)
            judge_score = max(0, min(100, int(judge_output.risk_score)))
            merged_score = max(deterministic_score, judge_score)
            merged_verdict = merge_judge_verdict(
                deterministic_score=deterministic_score,
                judge_verdict=judge_output.verdict,
                judge_confidence=float(judge_output.confidence),
                suspicious_min_score=service.pipeline_policy.suspicious_min_score,
                suspicious_max_score=service.pipeline_policy.suspicious_max_score,
                policy=service.pipeline_policy,
            )
            merged_score = normalize_score_for_verdict(
                merged_score,
                merged_verdict,
                suspicious_min_score=service.pipeline_policy.suspicious_min_score,
                suspicious_max_score=service.pipeline_policy.suspicious_max_score,
            )
            # Final product decision is binary: collapse the ambiguous bucket.
            if merged_verdict == "suspicious":
                merged_verdict = "phishing"
                merged_score = max(35, int(merged_score))
            merged_confidence = compute_confidence(
                score=merged_score,
                verdict=merged_verdict,
                judge_confidence=float(judge_output.confidence),
                missing_count=len(judge_output.missing_info),
            )
            labels = derive_email_labels(
                verdict=merged_verdict,
                risk_score=merged_score,
                subject=getattr(email, "subject", ""),
                text=getattr(email, "text", ""),
                urls=list(precheck.get("combined_urls", [])),
            )

            merged_actions = list(
                dict.fromkeys(
                    list(getattr(fallback, "recommended_actions", []))
                    + list(judge_output.recommended_actions)
                )
            )
            merged_indicators = list(
                dict.fromkeys(
                    list(precheck.get("indicators", []))
                    + [item.claim for item in judge_output.top_evidence]
                )
            )

            final = TriageResult(
                verdict=merged_verdict,
                reason=judge_output.reason.strip() or str(getattr(fallback, "reason", "")),
                path=map_route_to_path(evidence_pack.pre_score.route),
                risk_score=merged_score,
                confidence=merged_confidence,
                email_label=str(labels.get("email_label", "benign")),
                is_spam=bool(labels.get("is_spam", False)),
                is_phish_email=bool(labels.get("is_phish_email", False)),
                spam_score=int(labels.get("spam_score", 0)),
                threat_tags=list(labels.get("threat_tags", [])),
                indicators=merged_indicators,
                recommended_actions=merged_actions,
                input=email.text,
                urls=list(precheck.get("combined_urls", [])),
                attachments=email.attachments,
                provider_used=service.provider,
                evidence={
                    "evidence_pack": evidence_pack.model_dump(mode="json"),
                    "judge": judge_output.model_dump(mode="json"),
                    "precheck": precheck,
                },
            ).model_dump(mode="json")
            final["precheck"] = precheck
            return JudgeRunResult(final_result=final, judge_output=judge_output, error=None)
        except Exception as exc:
            return JudgeRunResult(final_result=None, judge_output=None, error=exc)
