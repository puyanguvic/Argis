import json

from my_agent_app.app.run import run_once


def test_agent_smoke():
    payload = json.loads(run_once("hello team"))
    assert payload["verdict"] in {"benign", "phishing"}


def test_agent_smoke_model_override():
    payload = json.loads(run_once("hello team", model="ollama/qwen2.5:1b"))
    assert payload["runtime"]["model"] == "ollama/qwen2.5:1b"
