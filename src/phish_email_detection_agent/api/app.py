"""FastAPI entrypoint for future productization."""

from __future__ import annotations

from fastapi import FastAPI

from phish_email_detection_agent.agents.build import create_agent

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
    result["runtime"] = runtime
    return result
