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
    pre_score = pack.get("pre_score", {})
    assert pre_score.get("route") in {"allow", "review", "deep"}
    assert 0.0 <= float(result.get("confidence", 0.0)) <= 1.0
