import os

from my_agent_app.app.run import run_once

for profile in ("ollama", "openai"):
    os.environ["MY_AGENT_APP_PROFILE"] = profile
    model = "ollama/qwen2.5:1b" if profile == "ollama" else None
    print(profile, run_once("Wire transfer request needs urgent action", model=model))
