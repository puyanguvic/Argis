import os

from phish_email_detection_agent.core.config import load_config


def test_load_config():
    cfg, raw = load_config()
    assert cfg.provider
    assert isinstance(raw, dict)


def test_load_config_profile_override():
    old = os.environ.get("MY_AGENT_APP_PROFILE")
    os.environ["MY_AGENT_APP_PROFILE"] = "ollama"
    try:
        cfg, _ = load_config()
        assert cfg.profile == "ollama"
        assert cfg.provider == "local"
    finally:
        if old is None:
            os.environ.pop("MY_AGENT_APP_PROFILE", None)
        else:
            os.environ["MY_AGENT_APP_PROFILE"] = old


def test_load_config_model_choices_from_env():
    old_profile = os.environ.get("MY_AGENT_APP_PROFILE")
    old_model = os.environ.get("MY_AGENT_APP_MODEL")
    old = os.environ.get("MY_AGENT_APP_MODEL_CHOICES")
    os.environ["MY_AGENT_APP_PROFILE"] = "ollama"
    os.environ["MY_AGENT_APP_MODEL"] = "ollama/qwen2.5:1b"
    os.environ["MY_AGENT_APP_MODEL_CHOICES"] = "ollama/qwen2.5:1b,ollama/qwen2.5:3b"
    try:
        cfg, _ = load_config()
        assert cfg.model_choices == ["ollama/qwen2.5:1b", "ollama/qwen2.5:3b"]
    finally:
        if old_profile is None:
            os.environ.pop("MY_AGENT_APP_PROFILE", None)
        else:
            os.environ["MY_AGENT_APP_PROFILE"] = old_profile
        if old_model is None:
            os.environ.pop("MY_AGENT_APP_MODEL", None)
        else:
            os.environ["MY_AGENT_APP_MODEL"] = old_model
        if old is None:
            os.environ.pop("MY_AGENT_APP_MODEL_CHOICES", None)
        else:
            os.environ["MY_AGENT_APP_MODEL_CHOICES"] = old


def test_load_config_security_pipeline_overrides():
    env_vars = {
        "MY_AGENT_APP_URL_FETCH_BACKEND": "firejail",
        "MY_AGENT_APP_OCR_BACKEND": "tesseract",
        "MY_AGENT_APP_AUDIO_TRANSCRIPTION_BACKEND": "openai",
    }
    backup = {name: os.environ.get(name) for name in env_vars}
    try:
        for name, value in env_vars.items():
            os.environ[name] = value
        cfg, _ = load_config()
        assert cfg.url_fetch_backend == "firejail"
        assert cfg.ocr_backend == "tesseract"
        assert cfg.audio_transcription_backend == "openai"
    finally:
        for name, value in backup.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_load_config_deep_analysis_one_switch_enables_pipeline():
    names = [
        "MY_AGENT_APP_ENABLE_DEEP_ANALYSIS",
        "MY_AGENT_APP_ENABLE_URL_FETCH",
        "MY_AGENT_APP_ENABLE_OCR",
        "MY_AGENT_APP_ENABLE_AUDIO_TRANSCRIPTION",
    ]
    backup = {name: os.environ.get(name) for name in names}
    try:
        os.environ["MY_AGENT_APP_ENABLE_DEEP_ANALYSIS"] = "true"
        os.environ.pop("MY_AGENT_APP_ENABLE_URL_FETCH", None)
        os.environ.pop("MY_AGENT_APP_ENABLE_OCR", None)
        os.environ.pop("MY_AGENT_APP_ENABLE_AUDIO_TRANSCRIPTION", None)
        cfg, _ = load_config()
        assert cfg.enable_deep_analysis is True
        assert cfg.enable_url_fetch is True
        assert cfg.enable_ocr is True
        assert cfg.enable_audio_transcription is True
    finally:
        for name, value in backup.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
