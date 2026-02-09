import os

from my_agent_app.app.run import run_once

for provider in ("litellm", "openai", "ollama"):
    os.environ["MY_AGENT_APP_PROVIDER"] = provider
    print(provider, run_once("Wire transfer request needs urgent action"))
