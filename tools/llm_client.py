"""LLM client helpers for phishing analysis."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Tuple

import requests

from agent.config import LLMConfig

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)
_JSON_FENCE_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
_LOCAL_PIPELINE: Tuple[str, Any] | None = None


def _notify_local_model_loading(message: str) -> None:
    print(message, flush=True)


def analyze_phishing(text: str, config: LLMConfig) -> Dict[str, Any]:
    if not text.strip():
        return {"score": 0.0, "reasons": ["empty_body"]}

    prompt = (
        "You are a phishing detection assistant. "
        "Given the email text, return ONLY JSON with keys: "
        '"risk" (number 0-1) and "reasons" (list of short strings).\n\n'
        f"Email:\n{text}\n"
    )

    try:
        if config.provider == "huggingface_api":
            output = _call_huggingface_api(prompt, config)
        elif config.provider == "huggingface_local":
            output = _call_huggingface_local(prompt, config)
        else:
            return {
                "score": 0.0,
                "reasons": ["unsupported_provider"],
                "error": f"provider={config.provider}",
            }
    except Exception as exc:  # noqa: BLE001 - capture network/parse errors
        return {"score": 0.0, "reasons": ["llm_error"], "error": str(exc)}

    parsed = _extract_json(output)
    if not parsed:
        return {"score": 0.0, "reasons": ["llm_parse_failed"], "raw": output}

    score = float(parsed.get("risk", 0.0))
    reasons = parsed.get("reasons", [])
    return {"score": min(max(score, 0.0), 1.0), "reasons": reasons}


def analyze_decision(text: str, evidence: Dict[str, Any], config: LLMConfig) -> Dict[str, Any]:
    if not text.strip():
        return {"risk": 0.0, "label": "benign", "evidence": ["empty_body"]}

    prompt = (
        "You are a phishing detection assistant. "
        "Given the email text and extracted signals, return ONLY JSON with keys: "
        '"risk" (number 0-1), "label" ("phishing" or "benign"), and '
        '"evidence" (list of short, human-readable reasons).\n\n'
        f"Signals JSON:\n{json.dumps(evidence, ensure_ascii=True)}\n\n"
        f"Email:\n{text}\n"
    )

    try:
        if config.provider == "huggingface_api":
            output = _call_huggingface_api(prompt, config)
        elif config.provider == "huggingface_local":
            output = _call_huggingface_local(prompt, config)
        else:
            return {
                "risk": 0.0,
                "label": "benign",
                "evidence": ["unsupported_provider"],
                "error": f"provider={config.provider}",
            }
    except Exception as exc:  # noqa: BLE001 - capture network/parse errors
        return {"risk": 0.0, "label": "benign", "evidence": ["llm_error"], "error": str(exc)}

    parsed = _extract_json(output)
    if not parsed:
        return {"risk": 0.0, "label": "benign", "evidence": ["llm_parse_failed"], "raw": output}

    risk = float(parsed.get("risk", 0.0))
    label = parsed.get("label", "benign")
    reasons = parsed.get("evidence", [])
    return {
        "risk": min(max(risk, 0.0), 1.0),
        "label": "phishing" if str(label).lower() == "phishing" else "benign",
        "evidence": reasons,
    }


def analyze_tao_action(
    text: str,
    evidence: Dict[str, Any],
    remaining_actions: list[str],
    tool_descriptions: str,
    config: LLMConfig,
) -> Dict[str, Any]:
    if not text.strip():
        return {"action": "final", "reason": "empty_body"}

    prompt = (
        "You are a phishing detection assistant running a tool loop. "
        "Pick the NEXT action and return ONLY JSON with keys: "
        '"action" (one of: remaining actions or "final") and '
        '"reason" (short string).\n\n'
        f"Tools:\n{tool_descriptions}\n\n"
        f"Remaining actions: {remaining_actions}\n\n"
        f"Signals JSON:\n{json.dumps(evidence, ensure_ascii=True)}\n\n"
        f"Email:\n{text}\n"
    )

    try:
        if config.provider == "huggingface_api":
            output = _call_huggingface_api(prompt, config)
        elif config.provider == "huggingface_local":
            output = _call_huggingface_local(prompt, config)
        else:
            return {"action": "final", "reason": f"unsupported_provider:{config.provider}"}
    except Exception as exc:  # noqa: BLE001 - capture network/parse errors
        return {"action": "final", "reason": f"llm_error:{exc}"}

    parsed = _extract_json(output)
    if not parsed:
        return {"action": "final", "reason": "llm_parse_failed"}

    action = str(parsed.get("action", "final")).lower()
    reason = str(parsed.get("reason", ""))
    return {"action": action, "reason": reason}


def _extract_json(text: str) -> Dict[str, Any] | None:
    fenced = _JSON_FENCE_RE.search(text)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            return None
    match = _JSON_RE.search(text)
    if not match:
        return None
    candidate = match.group(0)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return _extract_json_loose(candidate)


def _extract_json_loose(text: str) -> Dict[str, Any] | None:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                snippet = text[start : idx + 1]
                try:
                    return json.loads(snippet)
                except json.JSONDecodeError:
                    return None
    return None


def _call_huggingface_api(prompt: str, config: LLMConfig) -> str:
    endpoint = config.endpoint or f"https://api-inference.huggingface.co/models/{config.model}"
    headers = {"Accept": "application/json"}
    token = os.getenv(config.api_token_env)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": config.max_tokens,
            "temperature": config.temperature,
            "return_full_text": False,
        },
    }
    response = requests.post(endpoint, json=payload, headers=headers, timeout=config.timeout_s)
    response.raise_for_status()
    data = response.json()

    if isinstance(data, list) and data and "generated_text" in data[0]:
        return str(data[0]["generated_text"])
    if isinstance(data, dict) and "generated_text" in data:
        return str(data["generated_text"])
    return json.dumps(data)


def _call_huggingface_local(prompt: str, config: LLMConfig) -> str:
    global _LOCAL_PIPELINE

    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
    except ImportError as exc:
        raise RuntimeError("transformers is required for huggingface_local mode") from exc

    if _LOCAL_PIPELINE is None or _LOCAL_PIPELINE[0] != config.model:
        _notify_local_model_loading(
            f"[llm] Loading local model {config.model} (may download weights on first run)."
        )
        tokenizer = AutoTokenizer.from_pretrained(config.model)
        model = AutoModelForCausalLM.from_pretrained(config.model)
        text_gen = pipeline("text-generation", model=model, tokenizer=tokenizer)
        _LOCAL_PIPELINE = (config.model, text_gen)
        _notify_local_model_loading(f"[llm] Local model ready: {config.model}.")

    text_gen = _LOCAL_PIPELINE[1]
    outputs = text_gen(
        prompt,
        max_new_tokens=config.max_tokens,
        temperature=config.temperature,
        do_sample=True,
    )
    if outputs and isinstance(outputs, list) and "generated_text" in outputs[0]:
        return str(outputs[0]["generated_text"])
    return json.dumps(outputs)
