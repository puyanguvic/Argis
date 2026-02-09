from argis.core.settings import load_settings


def test_load_settings_defaults():
    bundle = load_settings()
    assert bundle.settings.profile
    assert isinstance(bundle.config, dict)
