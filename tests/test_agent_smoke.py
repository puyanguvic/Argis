import json

from my_agent_app.app.run import run_once


def test_agent_smoke():
    payload = json.loads(run_once("hello team"))
    assert payload["verdict"] in {"benign", "phishing"}
