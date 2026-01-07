"""Configuration models for the agent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = "huggingface_local"
    model: str = "Qwen/Qwen2.5-1.5B-Instruct"
    endpoint: str | None = None
    api_token_env: str = "HF_API_TOKEN"
    temperature: float = 0.2
    max_tokens: int = 256
    timeout_s: float = 20.0
    llm_weight: float = 0.5
    use_tao: bool = False
    tao_max_cycles: int = 6
    tao_actions: tuple[str, ...] = ("headers", "urls", "content", "attachments")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "LLMConfig":
        if not data:
            return cls()

        return cls(
            enabled=bool(data.get("enabled", False)),
            provider=str(data.get("provider", "huggingface_local")),
            model=str(data.get("model", cls.model)),
            endpoint=data.get("endpoint"),
            api_token_env=str(data.get("api_token_env", "HF_API_TOKEN")),
            temperature=float(data.get("temperature", cls.temperature)),
            max_tokens=int(data.get("max_tokens", cls.max_tokens)),
            timeout_s=float(data.get("timeout_s", cls.timeout_s)),
            llm_weight=float(data.get("llm_weight", cls.llm_weight)),
            use_tao=bool(data.get("use_tao", cls.use_tao)),
            tao_max_cycles=int(data.get("tao_max_cycles", cls.tao_max_cycles)),
            tao_actions=tuple(data.get("tao_actions", cls.tao_actions)),
        )
