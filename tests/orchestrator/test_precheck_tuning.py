import json

from phish_email_detection_agent.cli import run_once
from phish_email_detection_agent.config.settings import load_config


SUSPICIOUS_FINANCE_SAMPLE = """Subject: Action Required: Updated Invoice and Payment Verification

Dear Mick,
Please review and confirm payment information using:
https://accounts-secure-verification.com/finance/portal/invoice

This verification link remains active for 24 hours.
If no confirmation is received, the invoice may be placed on temporary hold.
"""
URL_LOGIN_SAMPLE = """Subject: Hi

Please check https://example-login-test.com/account now.
"""
LIGHT_TEXT_SAMPLE = """Subject: Notice

account information
"""


def test_load_config_reads_precheck_tuning_from_yaml(tmp_path):
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(
        """
profile: openai
precheck_url_suspicious_weight: 31
precheck_domain_synthetic_bonus: 27
profiles:
  openai:
    provider: openai
    model: gpt-4.1-mini
    precheck_url_suspicious_weight: 31
    precheck_domain_synthetic_bonus: 27
""".strip(),
        encoding="utf-8",
    )
    cfg, _ = load_config(path=cfg_path, profile_override="openai")
    assert cfg.precheck_url_suspicious_weight == 31
    assert cfg.precheck_domain_synthetic_bonus == 27


def test_env_override_precheck_weight_changes_score(monkeypatch):
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MY_AGENT_APP_PRECHECK_URL_SUSPICIOUS_WEIGHT", "24")
    baseline = json.loads(run_once(URL_LOGIN_SAMPLE))
    monkeypatch.setenv("MY_AGENT_APP_PRECHECK_URL_SUSPICIOUS_WEIGHT", "1")
    tuned = json.loads(run_once(URL_LOGIN_SAMPLE))
    assert int(tuned["risk_score"]) < int(baseline["risk_score"])


def test_env_override_text_keyword_weight_changes_score(monkeypatch):
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MY_AGENT_APP_PRECHECK_TEXT_KEYWORD_WEIGHT", "9")
    baseline = json.loads(run_once(LIGHT_TEXT_SAMPLE))
    monkeypatch.setenv("MY_AGENT_APP_PRECHECK_TEXT_KEYWORD_WEIGHT", "1")
    tuned = json.loads(run_once(LIGHT_TEXT_SAMPLE))
    assert int(tuned["risk_score"]) < int(baseline["risk_score"])


def test_env_override_url_path_token_bonus_changes_score(monkeypatch):
    monkeypatch.setenv("MY_AGENT_APP_PROFILE", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MY_AGENT_APP_PRECHECK_URL_PATH_TOKEN_BONUS", "8")
    baseline = json.loads(run_once(URL_LOGIN_SAMPLE))
    monkeypatch.setenv("MY_AGENT_APP_PRECHECK_URL_PATH_TOKEN_BONUS", "1")
    tuned = json.loads(run_once(URL_LOGIN_SAMPLE))
    assert int(tuned["risk_score"]) < int(baseline["risk_score"])
