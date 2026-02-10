"""Build and wire application agent."""

from __future__ import annotations

from my_agent_app.agents.service import AgentService
from my_agent_app.core.config import load_config


def create_agent(
    *,
    profile_override: str | None = None,
    model_override: str | None = None,
) -> tuple[AgentService, dict[str, object]]:
    env_cfg, yaml_cfg = load_config(profile_override=profile_override)
    active_model = model_override or env_cfg.model
    profiles = yaml_cfg.get("profiles")
    profile_map = profiles if isinstance(profiles, dict) else {}
    profile_choices = [str(item) for item in profile_map.keys() if str(item).strip()]
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
        "profile_choices": profile_choices,
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
