"""FastAPI entrypoint for future productization."""

from __future__ import annotations

import json
import re

from fastapi import FastAPI
from fastapi import HTTPException

from phish_email_detection_agent.orchestrator.build import create_agent

app = FastAPI(title="phish-email-detection-agent")
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _bad_request(*, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=400, detail={"code": code, "message": message})


def _looks_like_filesystem_path(raw: str) -> bool:
    value = str(raw or "").strip()
    if not value:
        return False
    lowered = value.lower()
    if lowered.startswith("file://"):
        return True
    if value in {".", ".."}:
        return True
    if value.startswith(("/", "\\", "~", "./", "../", ".\\", "..\\")):
        return True
    if "/" in value or "\\" in value:
        return True
    if _DRIVE_PATH_RE.match(value):
        return True
    return False


def _validate_json_text_input(text: str) -> None:
    stripped = text.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict):
        return

    eml_path = payload.get("eml_path")
    if isinstance(eml_path, str) and eml_path.strip():
        raise _bad_request(
            code="unsupported_eml_path",
            message="`eml_path` is not allowed in API requests. Use `eml` or `eml_raw` content instead.",
        )

    attachments = payload.get("attachments")
    if attachments is None:
        return
    if not isinstance(attachments, list):
        raise _bad_request(
            code="invalid_attachment_schema",
            message="`attachments` must be a list of objects containing `name` or `filename`.",
        )
    for item in attachments:
        if not isinstance(item, dict):
            raise _bad_request(
                code="invalid_attachment_schema",
                message="`attachments` entries must be objects containing `name` or `filename`.",
            )
        name = item.get("name")
        filename = item.get("filename")
        raw_name = name if isinstance(name, str) else filename if isinstance(filename, str) else ""
        clean_name = raw_name.strip()
        if not clean_name:
            raise _bad_request(
                code="invalid_attachment_schema",
                message="Each attachment object must include non-empty `name` or `filename`.",
            )
        if _looks_like_filesystem_path(clean_name):
            raise _bad_request(
                code="unsafe_attachment_path",
                message="Attachment names must be logical identifiers, not filesystem paths.",
            )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(payload: dict[str, object]) -> dict[str, object]:
    raw_text = payload.get("text", "")
    if not isinstance(raw_text, str):
        raise _bad_request(
            code="invalid_text_type",
            message="`text` must be a string.",
        )
    text = raw_text
    _validate_json_text_input(text)
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
