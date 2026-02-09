"""Main business agent definition."""

from __future__ import annotations

from dataclasses import dataclass

from my_agent_app.agents.router import route_text
from my_agent_app.tools.text import contains_phishing_keywords, normalize_text


@dataclass
class MainAgent:
    instructions: str

    def analyze(self, text: str) -> dict[str, object]:
        clean = normalize_text(text)
        path = route_text(clean)
        phishing = contains_phishing_keywords(clean)
        verdict = "phishing" if phishing else "benign"
        reason = "matched phishing keywords" if phishing else "no strong phishing signal"
        return {
            "path": path,
            "verdict": verdict,
            "reason": reason,
            "input": clean,
        }
