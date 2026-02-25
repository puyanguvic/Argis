def test_precheck_includes_nested_urls_from_query(run_fallback_once):
    payload = run_fallback_once("See https://tracker.example.com/?u=https%3A%2F%2Fevil.com%2Flogin")
    precheck = payload["evidence"]["precheck"]
    assert "https://evil.com/login" in precheck.get("nested_urls_from_query", [])
    assert "https://evil.com/login" in precheck.get("combined_urls", [])

