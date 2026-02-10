import os

from phish_email_detection_agent.app.run import run_once

os.environ.setdefault("MY_AGENT_APP_PROFILE", "ollama")
print(run_once("Internal notice: quarterly review schedule", model="ollama/qwen2.5:1b"))
