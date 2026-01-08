from __future__ import annotations

from tools_builtin.content_analyzer import semantic_extract


def test_intent_delegated_access() -> None:
    result = semantic_extract(
        subject="SharePoint delegated access request",
        body_text="Please grant access to the shared mailbox.",
        body_html=None,
    )
    assert result.intent == "delegated_access"
    assert "SharePoint" in result.brand_entities
    assert "grant access" in result.requested_actions


def test_intent_access_review() -> None:
    result = semantic_extract(
        subject="Access review required",
        body_text="Review access for Google Drive folders.",
        body_html=None,
    )
    assert result.intent == "access_review"
    assert "Google Drive" in result.brand_entities
    assert "review access" in result.requested_actions


def test_intent_permission_change() -> None:
    result = semantic_extract(
        subject="Permissions update notice",
        body_text="We are processing a permission change on this file.",
        body_html=None,
    )
    assert result.intent == "permission_change"


def test_intent_oauth_consent() -> None:
    result = semantic_extract(
        subject="Authorize OneDrive sync",
        body_text="OAuth consent is required to authorize this app.",
        body_html=None,
    )
    assert result.intent == "oauth_consent"
    assert "OneDrive" in result.brand_entities
    assert "authorize" in result.requested_actions
