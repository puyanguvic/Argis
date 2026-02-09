import os

from my_agent_app.app.run import run_once

os.environ.setdefault("MY_AGENT_APP_PROFILE", "litellm")
print(run_once("Internal notice: quarterly review schedule"))
