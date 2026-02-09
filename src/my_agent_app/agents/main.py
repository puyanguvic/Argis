"""Main business agent definition."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import json
import os

from my_agent_app.agents.router import route_text
from my_agent_app.tools.text import contains_phishing_keywords, normalize_text


def _heuristic_result(text: str) -> dict[str, object]:
    phishing = contains_phishing_keywords(text)
    return {
        "path": route_text(text),
        "verdict": "phishing" if phishing else "benign",
        "reason": "matched phishing keywords" if phishing else "no strong phishing signal",
        "input": text,
    }


def _extract_json_block(payload: str) -> str:
    text = (payload or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            return "\n".join(lines[1:-1]).strip()
    return text


@dataclass
class MainAgent:
    instructions: str
    provider: str
    model: str
    temperature: float = 0.0
    api_base: str | None = None
    api_key: str | None = None

    def _run_with_agents_sdk(self, text: str) -> str:
        from agents import Agent, ModelSettings, Runner

        model_ref: object = self.model
        if self.provider == "litellm":
            from agents.extensions.models.litellm_model import LitellmModel

            model_ref = LitellmModel(
                model=self.model,
                api_base=self.api_base,
                api_key=self.api_key,
            )

        agent = Agent(
            name="email-risk-triage",
            instructions=self.instructions,
            model=model_ref,
            model_settings=ModelSettings(temperature=self.temperature),
        )
        result = Runner.run_sync(agent, text)
        final_output = getattr(result, "final_output", "")
        return final_output if isinstance(final_output, str) else str(final_output)

    def analyze(self, text: str) -> dict[str, object]:
        clean = normalize_text(text)
        fallback = _heuristic_result(clean)

        # Keep local tests/dev usable even when SDK or API credentials are unavailable.
        effective_key = self.api_key or os.getenv("OPENAI_API_KEY")
        if importlib.util.find_spec("agents") is None:
            return fallback
        if self.provider == "openai" and not effective_key:
            return fallback

        try:
            raw = self._run_with_agents_sdk(clean)
            parsed = json.loads(_extract_json_block(raw))
            verdict = parsed.get("verdict")
            reason = parsed.get("reason")
            path = parsed.get("path")
            if verdict not in {"phishing", "benign"} or not isinstance(reason, str):
                return fallback
            if path not in {"FAST", "STANDARD", "DEEP"}:
                path = route_text(clean)
            return {
                "path": path,
                "verdict": verdict,
                "reason": reason.strip() or fallback["reason"],
                "input": clean,
            }
        except Exception:
            return fallback
