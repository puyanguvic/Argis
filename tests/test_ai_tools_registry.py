import sys
import types

from phish_email_detection_agent.tools.openai import openai_tool_functions
from phish_email_detection_agent.tools.registry import ToolRegistry


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


def test_openai_tool_functions_are_stable():
    functions = openai_tool_functions()
    assert [item.__name__ for item in functions] == EXPECTED_TOOL_NAMES


def test_registry_exports_all_tools(monkeypatch):
    def _fake_function_tool(func):
        return {"name": func.__name__}

    monkeypatch.setitem(sys.modules, "agents", types.SimpleNamespace(function_tool=_fake_function_tool))

    registry = ToolRegistry()
    registry.register_all()
    exported = registry.export()
    assert len(exported) == len(EXPECTED_TOOL_NAMES)
    assert all(isinstance(item, dict) and "name" in item for item in exported)
