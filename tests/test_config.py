import os

from my_agent_app.core.config import load_config


def test_load_config():
    cfg, raw = load_config()
    assert cfg.provider
    assert isinstance(raw, dict)


def test_load_config_profile_override():
    old = os.environ.get("MY_AGENT_APP_PROFILE")
    os.environ["MY_AGENT_APP_PROFILE"] = "litellm"
    try:
        cfg, _ = load_config()
        assert cfg.profile == "litellm"
        assert cfg.provider == "litellm"
    finally:
        if old is None:
            os.environ.pop("MY_AGENT_APP_PROFILE", None)
        else:
            os.environ["MY_AGENT_APP_PROFILE"] = old


def test_load_config_model_choices_from_env():
    old = os.environ.get("MY_AGENT_APP_MODEL_CHOICES")
    os.environ["MY_AGENT_APP_MODEL_CHOICES"] = "ollama/qwen2.5:1b,ollama/qwen2.5:3b"
    try:
        cfg, _ = load_config()
        assert cfg.model_choices == ["ollama/qwen2.5:1b", "ollama/qwen2.5:3b"]
    finally:
        if old is None:
            os.environ.pop("MY_AGENT_APP_MODEL_CHOICES", None)
        else:
            os.environ["MY_AGENT_APP_MODEL_CHOICES"] = old
