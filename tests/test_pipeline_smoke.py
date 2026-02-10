import json

from phish_email_detection_agent.cli import run_once


def test_pipeline_smoke():
    payload = json.loads(run_once("hello team"))
    assert payload["verdict"] in {"benign", "phishing"}
