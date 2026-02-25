from phish_email_detection_agent.orchestrator.precheck import infer_url_signals
from phish_email_detection_agent.tools.intel.domain_intel import DomainIntelPolicy
from phish_email_detection_agent.tools.url_fetch.service import SafeFetchPolicy


class _DummyService:
    enable_url_fetch = False


def test_infer_url_signals_marks_encoded_nested_query_url():
    provenance = {"limits_hit": [], "errors": []}
    url = "https://tracker.example.com/?u=https%3A%2F%2Fevil.com%2Flogin"
    signals, _domain_reports = infer_url_signals(
        [url],
        service=_DummyService(),
        fetch_policy=SafeFetchPolicy(enabled=False),
        domain_policy=DomainIntelPolicy(),
        provenance=provenance,
    )
    assert signals
    flags = set(signals[0]["risk_flags"])
    assert "encoded-query" in flags
    assert "nested-url-param" in flags
    assert "query-redirect" in flags
    assert "https://evil.com/login" in signals[0]["nested_urls"]

