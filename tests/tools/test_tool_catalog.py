from phish_email_detection_agent.tools.catalog import discover_builtin_tools


EXPECTED_TOOL_NAMES = [
    "normalize_text",
    "keyword_scan",
    "route_path",
    "extract_urls",
    "check_url",
    "attachment_risk",
    "parse_email",
    "url_target",
    "domain_intel",
    "attachments_deep",
]


def test_discover_builtin_tools_order_is_stable():
    tools = discover_builtin_tools()
    assert [item.name for item in tools] == EXPECTED_TOOL_NAMES


def test_discover_builtin_tools_has_docs_and_modules():
    tools = discover_builtin_tools()
    assert all(item.description for item in tools)
    assert all(item.module for item in tools)
