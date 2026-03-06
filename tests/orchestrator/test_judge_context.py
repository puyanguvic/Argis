from phish_email_detection_agent.domain.evidence import EvidencePack
from phish_email_detection_agent.orchestrator.judge_context import build_judge_context


def _sample_pack(route: str) -> EvidencePack:
    return EvidencePack.model_validate(
        {
            "email_meta": {
                "message_id": "m1",
                "date": "2026-03-05",
                "sender": "alerts@example.com",
                "subject": "Verify your account",
                "reply_to": "ops@example.net",
                "urls_count": 3,
                "attachments_count": 2,
            },
            "header_signals": {
                "spf": {"result": "fail"},
                "dkim": {"result": "pass"},
                "dmarc": {"result": "fail"},
                "from_replyto_mismatch": True,
                "received_hops": 4,
                "suspicious_received_patterns": ["private-hop"],
                "confidence": 0.82,
            },
            "url_signals": [
                {
                    "url": "https://bit.ly/reset",
                    "expanded_url": "https://login-example.top/reset",
                    "redirect_chain": ["https://redir.example/reset"],
                    "final_domain": "login-example.top",
                    "is_shortlink": True,
                    "has_login_keywords": True,
                    "nested_urls": ["https://nested.example/1"],
                    "looks_like_brand": {"brand": "microsoft", "similarity": 0.92},
                    "domain_risk_score": 72,
                    "risk_flags": ["shortlink", "brand-spoof", "login-intent"],
                    "confidence": 0.93,
                },
                {
                    "url": "https://safe.example/info",
                    "final_domain": "safe.example",
                    "risk_flags": [],
                    "confidence": 0.12,
                },
                {
                    "url": "https://verify-account.example",
                    "final_domain": "verify-account.example",
                    "risk_flags": ["login-intent"],
                    "confidence": 0.61,
                },
            ],
            "web_signals": [
                {
                    "url": "https://bit.ly/reset",
                    "fetch_ok": True,
                    "http_status": 200,
                    "final_url": "https://login-example.top/reset",
                    "title": "Microsoft Sign In",
                    "form_count": 1,
                    "has_password_field": True,
                    "has_otp_field": False,
                    "text_brand_hints": ["microsoft"],
                    "risk_flags": ["credential-harvest", "brand-impersonation"],
                    "confidence": 0.88,
                }
            ],
            "attachment_signals": [
                {
                    "filename": "invoice.pdf",
                    "mime": "application/pdf",
                    "macro_suspected": False,
                    "extension_mismatch": False,
                    "is_archive": False,
                    "is_executable_like": False,
                    "risk_flags": ["attachment-url-chain"],
                    "confidence": 0.55,
                },
                {
                    "filename": "urgent-login.html",
                    "mime": "text/html",
                    "macro_suspected": False,
                    "extension_mismatch": True,
                    "is_archive": False,
                    "is_executable_like": False,
                    "risk_flags": ["extension-mismatch", "attachment-url-chain"],
                    "confidence": 0.77,
                },
            ],
            "nlp_cues": {
                "urgency": 0.8,
                "threat_language": 0.6,
                "credential_request": 0.9,
                "action_request": 0.8,
                "phishing_keyword_hits": 4,
                "impersonation": ["help desk"],
                "highlights": [
                    "verify now",
                    "account disabled",
                    "click the secure link",
                    "password required",
                ],
            },
            "pre_score": {
                "risk_score": 65 if route == "deep" else 42 if route == "review" else 10,
                "route": route,
                "reasons": ["url:login_intent", "header:dmarc_weak"],
            },
            "provenance": {
                "limits_hit": ["web_snapshot_url_cap"],
                "errors": ["web_snapshot:https://bit.ly/reset:timeout"],
            },
        }
    )


def _sample_precheck() -> dict[str, object]:
    return {
        "heuristic_score": 42,
        "indicators": ["url:login_intent", "header:dmarc_weak"],
        "chain_flags": ["contains_url", "hidden_html_links"],
        "suspicious_urls": ["https://bit.ly/reset"],
        "risky_attachments": ["urgent-login.html"],
        "hidden_links": ["https://bit.ly/reset"],
        "combined_urls": [
            "https://bit.ly/reset",
            "https://safe.example/info",
            "https://verify-account.example",
        ],
        "nested_urls_from_query": ["https://nested.example/1"],
        "component_scores": {"text": 42, "url": 51, "domain": 33, "attachment": 25, "ocr": 0},
        "domain_reports": [
            {
                "domain": "login-example.top",
                "base_domain": "example.top",
                "risk_score": 72,
                "indicators": ["risky_tld", "brand_typosquat"],
                "typosquat_brands": ["microsoft"],
                "suspicious_tokens": ["login", "account"],
            }
        ],
        "attachment_reports": [
            {
                "name": "urgent-login.html",
                "type": "html",
                "risk_score": 78,
                "indicators": ["attachment_high_risk", "attachment_contains_url"],
                "extracted_urls": ["https://nested.example/1", "https://nested.example/2"],
                "details": {
                    "brand_hits": ["microsoft"],
                    "urls": ["https://nested.example/1", "https://nested.example/2"],
                    "risk_score": 66,
                },
            }
        ],
        "url_target_reports": [
            {
                "url": "https://bit.ly/reset",
                "risk_score": 81,
                "fetch": {
                    "status": "ok",
                    "status_code": 200,
                    "final_url": "https://login-example.top/reset",
                },
                "html_analysis": {
                    "title": "Microsoft Sign In",
                    "form_count": 1,
                    "has_password_field": True,
                    "has_otp_field": False,
                    "brand_hits": ["microsoft"],
                    "impersonation_score": 71,
                },
                "url_obfuscation": {"flags": ["nested_url_in_query"]},
            }
        ],
    }


def test_fast_judge_context_stays_minimal():
    context = build_judge_context(evidence_pack=_sample_pack("allow"), precheck=_sample_precheck())

    assert context["path"] == "FAST"
    assert context["pre_score"]["evidence_id"].startswith("evd_")
    assert "selected_web_signals" not in context
    assert "selected_attachment_reports" not in context
    assert "selected_url_target_reports" not in context
    assert len(context["selected_url_signals"]) <= 2
    assert context["selected_url_signals"][0]["evidence_id"].startswith("evd_")
    assert "redirect_chain" not in context["selected_url_signals"][0]
    assert context["evidence_refs"]


def test_standard_judge_context_adds_selected_web_summary_without_deep_artifacts():
    context = build_judge_context(evidence_pack=_sample_pack("review"), precheck=_sample_precheck())

    assert context["path"] == "STANDARD"
    assert "selected_web_signals" in context
    assert "selected_attachment_reports" not in context
    assert "selected_url_target_reports" not in context
    assert len(context["selected_url_signals"]) <= 4
    assert context["selected_web_signals"][0]["evidence_path"] == "selected_web_signals[0]"
    assert "redirect_chain" not in context["selected_url_signals"][0]


def test_deep_judge_context_includes_bounded_deep_artifacts():
    context = build_judge_context(evidence_pack=_sample_pack("deep"), precheck=_sample_precheck())

    assert context["path"] == "DEEP"
    assert "selected_web_signals" in context
    assert "selected_attachment_reports" in context
    assert "selected_url_target_reports" in context
    assert context["selected_url_signals"][0]["redirect_chain"] == ["https://redir.example/reset"]
    assert context["selected_attachment_reports"][0]["evidence_id"].startswith("evd_")
    assert context["selected_attachment_reports"][0]["details"]["brand_hits"] == ["microsoft"]
