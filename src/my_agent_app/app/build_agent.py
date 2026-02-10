"""Build and wire application agent."""

from __future__ import annotations

from my_agent_app.agents.service import AgentService
from my_agent_app.core.config import load_config


def create_agent(*, model_override: str | None = None) -> tuple[AgentService, dict[str, object]]:
    env_cfg, yaml_cfg = load_config()
    active_model = model_override or env_cfg.model
    agent = AgentService(
        provider=env_cfg.provider,
        model=active_model,
        temperature=env_cfg.temperature,
        api_base=env_cfg.api_base,
        api_key=env_cfg.api_key,
        max_turns=env_cfg.max_turns,
    )
    runtime = {
        "profile": env_cfg.profile,
        "provider": env_cfg.provider,
        "model": active_model,
        "temperature": env_cfg.temperature,
        "api_base": env_cfg.api_base,
        "model_choices": env_cfg.model_choices,
        "max_turns": env_cfg.max_turns,
        "agents_sdk": True,
        "config": yaml_cfg,
    }
    return agent, runtime
