from argis.agents.base import MainAgent


def test_main_agent_smoke_with_recording():
    agent = MainAgent()
    artifacts = agent.run("recording", "run.jsonl")
    assert "detection_result" in artifacts
