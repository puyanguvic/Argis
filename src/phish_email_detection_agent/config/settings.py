"""Config loader from env + yaml."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Any

import yaml
from pydantic import BaseModel, Field

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PACKAGE_ROOT / "config" / "defaults.yaml"


class AppConfig(BaseModel):

    profile: str = Field(default="ollama")
    provider: str = Field(default="local")
    model: str = Field(default="ollama/qwen2.5:7b")
    temperature: float = Field(default=0.0)
    api_base: str | None = Field(default=None)
    api_key: str | None = Field(default=None)
    model_choices: list[str] = Field(default_factory=list)
    max_turns: int = Field(default=8)
    enable_deep_analysis: bool = Field(default=False)
    enable_url_fetch: bool = Field(default=False)
    fetch_timeout_s: float = Field(default=5.0)
    fetch_max_redirects: int = Field(default=4)
    fetch_max_bytes: int = Field(default=1_000_000)
    allow_private_network: bool = Field(default=False)
    url_fetch_backend: str = Field(default="internal")
    url_sandbox_exec_timeout_s: float = Field(default=20.0)
    url_firejail_bin: str = Field(default="firejail")
    url_docker_bin: str = Field(default="docker")
    url_docker_image: str = Field(default="python:3.11-slim")
    attachment_max_read_bytes: int = Field(default=4_000_000)
    enable_ocr: bool = Field(default=False)
    ocr_backend: str = Field(default="tesseract")
    ocr_languages: str = Field(default="eng")
    enable_qr_decode: bool = Field(default=True)
    enable_audio_transcription: bool = Field(default=False)
    audio_transcription_backend: str = Field(default="openai")
    audio_transcription_model: str = Field(default="gpt-4o-mini-transcribe")
    audio_local_model_size: str = Field(default="small")
    whisper_cli_path: str = Field(default="whisper")
    audio_openai_api_key: str | None = Field(default=None)
    audio_openai_base_url: str | None = Field(default=None)
    precheck_domain_suspicious_threshold: int = Field(default=35)
    precheck_text_keyword_weight: int = Field(default=9)
    precheck_text_urgency_weight: int = Field(default=8)
    precheck_text_action_weight: int = Field(default=8)
    precheck_text_core_bonus: int = Field(default=15)
    precheck_text_finance_combo_bonus: int = Field(default=12)
    precheck_text_suspicious_finance_bonus: int = Field(default=12)
    precheck_text_suspicious_urgency_bonus: int = Field(default=8)
    precheck_url_suspicious_weight: int = Field(default=24)
    precheck_url_path_token_bonus: int = Field(default=8)
    precheck_url_path_bonus_cap: int = Field(default=24)
    precheck_url_domain_context_divisor: int = Field(default=2)
    precheck_url_domain_context_cap: int = Field(default=20)
    precheck_domain_token_cap: int = Field(default=30)
    precheck_domain_synthetic_bonus: int = Field(default=18)
    default_config_path: str = Field(default=str(DEFAULT_CONFIG_PATH))


def _normalize_provider(raw: Any) -> str:
    provider = str(raw or "").strip().lower()
    if provider in {"ollama", "local"}:
        return "local"
    return provider or "openai"


def load_yaml(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    payload = yaml.safe_load(p.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _pick_env(name: str, fallback: Any) -> Any:
    value = os.getenv(name)
    return value if value not in (None, "") else fallback


def _parse_model_choices(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return list(dict.fromkeys(item.strip() for item in raw.split(",") if item.strip()))
    if isinstance(raw, list):
        return list(dict.fromkeys(str(item).strip() for item in raw if str(item).strip()))
    return []


def _parse_int(raw: Any, fallback: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return fallback
    return value if value > 0 else fallback


def _parse_float(raw: Any, fallback: float) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return fallback


def _parse_bool(raw: Any, fallback: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return fallback
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return fallback


def _parse_str(raw: Any, fallback: str) -> str:
    value = str(raw if raw is not None else "").strip()
    return value or fallback


def _resolve_default_config_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path)
    env_default_path = os.getenv("MY_AGENT_APP_DEFAULT_CONFIG_PATH")
    if env_default_path:
        return Path(env_default_path)
    return DEFAULT_CONFIG_PATH


def load_config(
    path: str | Path | None = None,
    *,
    profile_override: str | None = None,
) -> tuple[AppConfig, dict[str, Any]]:
    default_path = _resolve_default_config_path(path)
    merged = load_yaml(default_path)
    profiles = merged.get("profiles")
    profile_map = profiles if isinstance(profiles, dict) else {}

    active_profile = str(profile_override or _pick_env("MY_AGENT_APP_PROFILE", merged.get("profile", "ollama")))
    selected_profile = profile_map.get(active_profile, {})
    selected = selected_profile if isinstance(selected_profile, dict) else {}
    # When profile is explicitly chosen (e.g. by UI dropdown), keep model/provider
    # settings deterministic from that profile and avoid cross-profile env leakage.
    use_selector_env = profile_override is None

    def _pick_selector_env(name: str, fallback: Any) -> Any:
        if use_selector_env:
            return _pick_env(name, fallback)
        return fallback

    selected_provider = _normalize_provider(
        _pick_selector_env(
            "MY_AGENT_APP_PROVIDER",
            selected.get("provider", merged.get("provider", "local")),
        )
    )

    raw_temp = _pick_selector_env(
        "MY_AGENT_APP_TEMPERATURE",
        selected.get("temperature", merged.get("temperature", 0.0)),
    )
    raw_choices = _pick_selector_env(
        "MY_AGENT_APP_MODEL_CHOICES",
        selected.get("model_choices", merged.get("model_choices", [])),
    )
    raw_turns = _pick_selector_env(
        "MY_AGENT_APP_MAX_TURNS",
        selected.get("max_turns", merged.get("max_turns", 8)),
    )
    selected_model = _pick_selector_env(
        "MY_AGENT_APP_MODEL",
        selected.get("model", merged.get("model", "ollama/qwen2.5:7b")),
    )

    parsed_choices = _parse_model_choices(raw_choices)
    if not parsed_choices and isinstance(profile_map, dict):
        for profile_cfg in profile_map.values():
            if not isinstance(profile_cfg, dict):
                continue
            profile_provider = _normalize_provider(profile_cfg.get("provider", ""))
            if profile_provider != str(selected_provider).strip():
                continue
            parsed_choices.extend(_parse_model_choices(profile_cfg.get("model_choices", [])))
            model_value = str(profile_cfg.get("model", "")).strip()
            if model_value:
                parsed_choices.append(model_value)
        parsed_choices = list(dict.fromkeys(item for item in parsed_choices if item))

    if selected_model and selected_model not in parsed_choices:
        parsed_choices.insert(0, str(selected_model))

    payload = {
        "profile": active_profile,
        "provider": selected_provider,
        "model": selected_model,
        "temperature": _parse_float(raw_temp, 0.0),
        "api_base": _pick_env("MY_AGENT_APP_API_BASE", selected.get("api_base", merged.get("api_base"))),
        "api_key": _pick_env("MY_AGENT_APP_API_KEY", selected.get("api_key", merged.get("api_key"))),
        "model_choices": parsed_choices,
        "max_turns": _parse_int(raw_turns, 8),
        "enable_deep_analysis": _parse_bool(
            _pick_env(
                "MY_AGENT_APP_ENABLE_DEEP_ANALYSIS",
                selected.get("enable_deep_analysis", merged.get("enable_deep_analysis", False)),
            ),
            False,
        ),
        "enable_url_fetch": _parse_bool(
            _pick_env(
                "MY_AGENT_APP_ENABLE_URL_FETCH",
                selected.get("enable_url_fetch", merged.get("enable_url_fetch", False)),
            ),
            False,
        ),
        "fetch_timeout_s": _parse_float(
            _pick_env(
                "MY_AGENT_APP_FETCH_TIMEOUT_S",
                selected.get("fetch_timeout_s", merged.get("fetch_timeout_s", 5.0)),
            ),
            5.0,
        ),
        "fetch_max_redirects": _parse_int(
            _pick_env(
                "MY_AGENT_APP_FETCH_MAX_REDIRECTS",
                selected.get("fetch_max_redirects", merged.get("fetch_max_redirects", 4)),
            ),
            4,
        ),
        "fetch_max_bytes": _parse_int(
            _pick_env(
                "MY_AGENT_APP_FETCH_MAX_BYTES",
                selected.get("fetch_max_bytes", merged.get("fetch_max_bytes", 1_000_000)),
            ),
            1_000_000,
        ),
        "allow_private_network": _parse_bool(
            _pick_env(
                "MY_AGENT_APP_ALLOW_PRIVATE_NETWORK",
                selected.get("allow_private_network", merged.get("allow_private_network", False)),
            ),
            False,
        ),
        "url_fetch_backend": _parse_str(
            _pick_env(
                "MY_AGENT_APP_URL_FETCH_BACKEND",
                selected.get("url_fetch_backend", merged.get("url_fetch_backend", "internal")),
            ),
            "internal",
        ),
        "url_sandbox_exec_timeout_s": _parse_float(
            _pick_env(
                "MY_AGENT_APP_URL_SANDBOX_EXEC_TIMEOUT_S",
                selected.get("url_sandbox_exec_timeout_s", merged.get("url_sandbox_exec_timeout_s", 20.0)),
            ),
            20.0,
        ),
        "url_firejail_bin": _parse_str(
            _pick_env(
                "MY_AGENT_APP_URL_FIREJAIL_BIN",
                selected.get("url_firejail_bin", merged.get("url_firejail_bin", "firejail")),
            ),
            "firejail",
        ),
        "url_docker_bin": _parse_str(
            _pick_env(
                "MY_AGENT_APP_URL_DOCKER_BIN",
                selected.get("url_docker_bin", merged.get("url_docker_bin", "docker")),
            ),
            "docker",
        ),
        "url_docker_image": _parse_str(
            _pick_env(
                "MY_AGENT_APP_URL_DOCKER_IMAGE",
                selected.get("url_docker_image", merged.get("url_docker_image", "python:3.11-slim")),
            ),
            "python:3.11-slim",
        ),
        "attachment_max_read_bytes": _parse_int(
            _pick_env(
                "MY_AGENT_APP_ATTACHMENT_MAX_READ_BYTES",
                selected.get("attachment_max_read_bytes", merged.get("attachment_max_read_bytes", 4_000_000)),
            ),
            4_000_000,
        ),
        "enable_ocr": _parse_bool(
            _pick_env(
                "MY_AGENT_APP_ENABLE_OCR",
                selected.get("enable_ocr", merged.get("enable_ocr", False)),
            ),
            False,
        ),
        "ocr_backend": _parse_str(
            _pick_env(
                "MY_AGENT_APP_OCR_BACKEND",
                selected.get("ocr_backend", merged.get("ocr_backend", "tesseract")),
            ),
            "tesseract",
        ),
        "ocr_languages": _parse_str(
            _pick_env(
                "MY_AGENT_APP_OCR_LANGUAGES",
                selected.get("ocr_languages", merged.get("ocr_languages", "eng")),
            ),
            "eng",
        ),
        "enable_qr_decode": _parse_bool(
            _pick_env(
                "MY_AGENT_APP_ENABLE_QR_DECODE",
                selected.get("enable_qr_decode", merged.get("enable_qr_decode", True)),
            ),
            True,
        ),
        "enable_audio_transcription": _parse_bool(
            _pick_env(
                "MY_AGENT_APP_ENABLE_AUDIO_TRANSCRIPTION",
                selected.get("enable_audio_transcription", merged.get("enable_audio_transcription", False)),
            ),
            False,
        ),
        "audio_transcription_backend": _parse_str(
            _pick_env(
                "MY_AGENT_APP_AUDIO_TRANSCRIPTION_BACKEND",
                selected.get("audio_transcription_backend", merged.get("audio_transcription_backend", "openai")),
            ),
            "openai",
        ),
        "audio_transcription_model": _parse_str(
            _pick_env(
                "MY_AGENT_APP_AUDIO_TRANSCRIPTION_MODEL",
                selected.get("audio_transcription_model", merged.get("audio_transcription_model", "gpt-4o-mini-transcribe")),
            ),
            "gpt-4o-mini-transcribe",
        ),
        "audio_local_model_size": _parse_str(
            _pick_env(
                "MY_AGENT_APP_AUDIO_LOCAL_MODEL_SIZE",
                selected.get("audio_local_model_size", merged.get("audio_local_model_size", "small")),
            ),
            "small",
        ),
        "whisper_cli_path": _parse_str(
            _pick_env(
                "MY_AGENT_APP_WHISPER_CLI_PATH",
                selected.get("whisper_cli_path", merged.get("whisper_cli_path", "whisper")),
            ),
            "whisper",
        ),
        "audio_openai_api_key": _pick_env(
            "MY_AGENT_APP_AUDIO_OPENAI_API_KEY",
            selected.get("audio_openai_api_key", merged.get("audio_openai_api_key")),
        ),
        "audio_openai_base_url": _pick_env(
            "MY_AGENT_APP_AUDIO_OPENAI_BASE_URL",
            selected.get("audio_openai_base_url", merged.get("audio_openai_base_url")),
        ),
        "precheck_domain_suspicious_threshold": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_DOMAIN_SUSPICIOUS_THRESHOLD",
                selected.get(
                    "precheck_domain_suspicious_threshold",
                    merged.get("precheck_domain_suspicious_threshold", 35),
                ),
            ),
            35,
        ),
        "precheck_text_keyword_weight": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_TEXT_KEYWORD_WEIGHT",
                selected.get("precheck_text_keyword_weight", merged.get("precheck_text_keyword_weight", 9)),
            ),
            9,
        ),
        "precheck_text_urgency_weight": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_TEXT_URGENCY_WEIGHT",
                selected.get("precheck_text_urgency_weight", merged.get("precheck_text_urgency_weight", 8)),
            ),
            8,
        ),
        "precheck_text_action_weight": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_TEXT_ACTION_WEIGHT",
                selected.get("precheck_text_action_weight", merged.get("precheck_text_action_weight", 8)),
            ),
            8,
        ),
        "precheck_text_core_bonus": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_TEXT_CORE_BONUS",
                selected.get("precheck_text_core_bonus", merged.get("precheck_text_core_bonus", 15)),
            ),
            15,
        ),
        "precheck_text_finance_combo_bonus": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_TEXT_FINANCE_COMBO_BONUS",
                selected.get(
                    "precheck_text_finance_combo_bonus",
                    merged.get("precheck_text_finance_combo_bonus", 12),
                ),
            ),
            12,
        ),
        "precheck_text_suspicious_finance_bonus": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_TEXT_SUSPICIOUS_FINANCE_BONUS",
                selected.get(
                    "precheck_text_suspicious_finance_bonus",
                    merged.get("precheck_text_suspicious_finance_bonus", 12),
                ),
            ),
            12,
        ),
        "precheck_text_suspicious_urgency_bonus": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_TEXT_SUSPICIOUS_URGENCY_BONUS",
                selected.get(
                    "precheck_text_suspicious_urgency_bonus",
                    merged.get("precheck_text_suspicious_urgency_bonus", 8),
                ),
            ),
            8,
        ),
        "precheck_url_suspicious_weight": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_URL_SUSPICIOUS_WEIGHT",
                selected.get(
                    "precheck_url_suspicious_weight",
                    merged.get("precheck_url_suspicious_weight", 24),
                ),
            ),
            24,
        ),
        "precheck_url_path_token_bonus": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_URL_PATH_TOKEN_BONUS",
                selected.get(
                    "precheck_url_path_token_bonus",
                    merged.get("precheck_url_path_token_bonus", 8),
                ),
            ),
            8,
        ),
        "precheck_url_path_bonus_cap": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_URL_PATH_BONUS_CAP",
                selected.get("precheck_url_path_bonus_cap", merged.get("precheck_url_path_bonus_cap", 24)),
            ),
            24,
        ),
        "precheck_url_domain_context_divisor": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_URL_DOMAIN_CONTEXT_DIVISOR",
                selected.get(
                    "precheck_url_domain_context_divisor",
                    merged.get("precheck_url_domain_context_divisor", 2),
                ),
            ),
            2,
        ),
        "precheck_url_domain_context_cap": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_URL_DOMAIN_CONTEXT_CAP",
                selected.get(
                    "precheck_url_domain_context_cap",
                    merged.get("precheck_url_domain_context_cap", 20),
                ),
            ),
            20,
        ),
        "precheck_domain_token_cap": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_DOMAIN_TOKEN_CAP",
                selected.get("precheck_domain_token_cap", merged.get("precheck_domain_token_cap", 30)),
            ),
            30,
        ),
        "precheck_domain_synthetic_bonus": _parse_int(
            _pick_env(
                "MY_AGENT_APP_PRECHECK_DOMAIN_SYNTHETIC_BONUS",
                selected.get(
                    "precheck_domain_synthetic_bonus",
                    merged.get("precheck_domain_synthetic_bonus", 18),
                ),
            ),
            18,
        ),
        "default_config_path": str(default_path),
    }

    if payload["enable_deep_analysis"]:
        # One-switch enablement for full pipeline, while preserving explicit env overrides.
        if os.getenv("MY_AGENT_APP_ENABLE_URL_FETCH") in (None, ""):
            payload["enable_url_fetch"] = True
        if os.getenv("MY_AGENT_APP_ENABLE_OCR") in (None, ""):
            payload["enable_ocr"] = True
        if os.getenv("MY_AGENT_APP_ENABLE_AUDIO_TRANSCRIPTION") in (None, ""):
            payload["enable_audio_transcription"] = True

    cfg = AppConfig.model_validate(payload)
    return cfg, merged
