from my_agent_app.core.config import load_config


def test_load_config():
    cfg, raw = load_config()
    assert cfg.provider
    assert isinstance(raw, dict)
