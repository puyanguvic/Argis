def test_result_contains_evidence_pack_contract(run_fallback_once):
    payload = """Subject: Action required

Please verify your account:
https://bit.ly/reset-account
"""
    result = run_fallback_once(payload)
    evidence = result.get("evidence", {})
    pack = evidence.get("evidence_pack", {})
    assert isinstance(pack, dict)
    assert "email_meta" in pack
    assert "header_signals" in pack
    assert "url_signals" in pack
    assert "nlp_cues" in pack
    assert "pre_score" in pack
    assert "provenance" in pack
    assert isinstance(pack.get("provenance", {}).get("context_admissions"), dict)
    refs = evidence.get("evidence_refs", [])
    assert isinstance(refs, list)
    assert refs
    assert refs[0]["evidence_id"].startswith("evd_")
    judge_context = evidence.get("judge_context", {})
    assert judge_context.get("pre_score", {}).get("evidence_id", "").startswith("evd_")
    pre_score = pack.get("pre_score", {})
    assert pre_score.get("route") in {"allow", "review", "deep"}
    assert 0.0 <= float(result.get("confidence", 0.0)) <= 1.0
