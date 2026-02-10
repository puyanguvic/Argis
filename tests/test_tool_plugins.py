from phish_email_detection_agent.agents.tool_registry import ToolRegistry


class DummyRegistry(ToolRegistry):
    def __init__(self):
        super().__init__()
        self.names = []

    def register_callable(self, func):  # type: ignore[override]
        self.names.append(func.__name__)


def test_plugin_autodiscovery_registers_default_plugin_tools():
    reg = DummyRegistry()
    reg.register_plugin_tools()
    assert "tool_extract_urls" in reg.names
    assert "tool_analyze_urls" in reg.names
    assert "tool_analyze_attachments" in reg.names
