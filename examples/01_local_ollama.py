import os

from my_agent_app.app.run import run_once

os.environ.setdefault("MY_AGENT_APP_PROVIDER", "ollama")
os.environ.setdefault("MY_AGENT_APP_MODEL", "llama3.1:8b")
print(run_once("Internal notice: quarterly review schedule"))
