"""FastAPI entrypoint for future productization."""

from __future__ import annotations

from fastapi import FastAPI

from phish_email_detection_agent.orchestrator.build import create_agent

app = FastAPI(title="phish-email-detection-agent")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(payload: dict[str, object]) -> dict[str, object]:
    text = str(payload.get("text", ""))
    model = payload.get("model")
    model_override = str(model) if isinstance(model, str) and model.strip() else None
    agent, runtime = create_agent(model_override=model_override)
    result = agent.analyze(text)
    installed_skillpacks = runtime.get("installed_skillpacks", [])
    skillpacks_dir = str(runtime.get("skillpacks_dir", ""))
    builtin_tools = runtime.get("builtin_tools", [])
    names = [
        str(item.get("name", "")).strip()
        for item in installed_skillpacks
        if isinstance(item, dict) and str(item.get("name", "")).strip()
    ]
    result["runtime"] = runtime
    result["skillpacks"] = {
        "dir": skillpacks_dir,
        "count": len(names),
        "names": names,
        "installed": installed_skillpacks if isinstance(installed_skillpacks, list) else [],
    }
    tool_names = [
        str(item.get("name", "")).strip()
        for item in builtin_tools
        if isinstance(item, dict) and str(item.get("name", "")).strip()
    ]
    result["tools"] = {
        "count": len(tool_names),
        "names": tool_names,
        "builtin": builtin_tools if isinstance(builtin_tools, list) else [],
    }
    return result
