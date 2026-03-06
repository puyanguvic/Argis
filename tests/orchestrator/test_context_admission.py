from phish_email_detection_agent.orchestrator.precheck import (
    should_collect_attachment_context,
    should_collect_web_context,
)


def test_web_context_triggered_by_risky_url_flags():
    decision = should_collect_web_context(
        {"risk_score": 10},
        [{"risk_flags": ["shortlink"], "url": "https://bit.ly/reset"}],
        35,
    )

    assert decision == {"collect": True, "reason": "url_flag:shortlink"}


def test_attachment_context_triggered_by_risky_attachment_flags():
    decision = should_collect_attachment_context(
        {"risk_score": 10},
        [{"risk_flags": ["executable-like"], "filename": "invoice.exe"}],
        35,
    )

    assert decision == {"collect": True, "reason": "attachment_flag:executable-like"}


def test_context_admission_distinguishes_web_only_attachment_only_both_and_neither(run_fallback_once):
    web_only = run_fallback_once('{"subject":"Notice","urls":["https://bit.ly/reset"]}')
    attachment_only = run_fallback_once('{"subject":"Notice","attachments":[{"name":"invoice.exe"}]}')
    both = run_fallback_once(
        '{"subject":"Notice","urls":["https://bit.ly/reset"],"attachments":[{"name":"invoice.exe"}]}'
    )
    neither = run_fallback_once("hello team")

    web_only_decisions = web_only["precheck"]["context_decisions"]
    web_only_admissions = web_only["precheck"]["context_admissions"]
    assert web_only_decisions["web"]["collected"] is False
    assert web_only_decisions["web"]["status"] == "skipped_by_policy"
    assert web_only_admissions["web"]["status"] == "skipped_by_policy"
    assert web_only_decisions["attachment"]["collected"] is False

    attachment_only_decisions = attachment_only["precheck"]["context_decisions"]
    attachment_only_admissions = attachment_only["precheck"]["context_admissions"]
    assert attachment_only_decisions["web"]["collected"] is False
    assert attachment_only_decisions["attachment"]["collected"] is True
    assert attachment_only_admissions["attachment"]["status"] == "admitted"

    both_decisions = both["precheck"]["context_decisions"]
    both_admissions = both["precheck"]["context_admissions"]
    assert both_decisions["web"]["collected"] is False
    assert both_admissions["web"]["status"] == "skipped_by_policy"
    assert both_decisions["attachment"]["collected"] is True

    neither_decisions = neither["precheck"]["context_decisions"]
    neither_admissions = neither["precheck"]["context_admissions"]
    assert neither_decisions["web"]["collected"] is False
    assert neither_decisions["attachment"]["collected"] is False
    assert neither_admissions["web"]["status"] in {"skipped_by_signal", "skipped_by_score"}
    assert neither_admissions["attachment"]["status"] == "skipped_by_signal"
