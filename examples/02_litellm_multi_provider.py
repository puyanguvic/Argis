import os

from my_agent_app.app.run import run_once

for profile in ("litellm", "openai"):
    os.environ["MY_AGENT_APP_PROFILE"] = profile
    print(profile, run_once("Wire transfer request needs urgent action"))
