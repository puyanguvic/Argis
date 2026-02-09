"""Build and wire application agent."""

from __future__ import annotations

from my_agent_app.agents.main import MainAgent
from my_agent_app.agents.prompts import SYSTEM_PROMPT
from my_agent_app.core.config import load_config
from my_agent_app.models.factory import get_model


def create_agent() -> tuple[MainAgent, dict[str, object]]:
    env_cfg, yaml_cfg = load_config()
    model = get_model(env_cfg.provider, env_cfg.model, env_cfg.temperature)
    agent = MainAgent(instructions=SYSTEM_PROMPT)
    runtime = {
        "provider": model.provider,
        "model": model.model,
        "temperature": model.temperature,
        "config": yaml_cfg,
    }
    return agent, runtime
