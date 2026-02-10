"""Build and wire application agent."""

from __future__ import annotations

from phish_email_detection_agent.orchestrator.pipeline import AgentService
from phish_email_detection_agent.config.settings import load_config


def create_agent(
    *,
    profile_override: str | None = None,
    model_override: str | None = None,
) -> tuple[AgentService, dict[str, object]]:
    env_cfg, yaml_cfg = load_config(profile_override=profile_override)
    active_model = model_override or env_cfg.model
    profiles = yaml_cfg.get("profiles")
    profile_map = profiles if isinstance(profiles, dict) else {}
    profile_choices = [str(item) for item in profile_map.keys() if str(item).strip()]
    agent = AgentService(
        provider=env_cfg.provider,
        model=active_model,
        temperature=env_cfg.temperature,
        api_base=env_cfg.api_base,
        api_key=env_cfg.api_key,
        max_turns=env_cfg.max_turns,
        enable_url_fetch=env_cfg.enable_url_fetch,
        fetch_timeout_s=env_cfg.fetch_timeout_s,
        fetch_max_redirects=env_cfg.fetch_max_redirects,
        fetch_max_bytes=env_cfg.fetch_max_bytes,
        allow_private_network=env_cfg.allow_private_network,
        url_fetch_backend=env_cfg.url_fetch_backend,
        url_sandbox_exec_timeout_s=env_cfg.url_sandbox_exec_timeout_s,
        url_firejail_bin=env_cfg.url_firejail_bin,
        url_docker_bin=env_cfg.url_docker_bin,
        url_docker_image=env_cfg.url_docker_image,
        attachment_max_read_bytes=env_cfg.attachment_max_read_bytes,
        enable_ocr=env_cfg.enable_ocr,
        ocr_backend=env_cfg.ocr_backend,
        ocr_languages=env_cfg.ocr_languages,
        enable_qr_decode=env_cfg.enable_qr_decode,
        enable_audio_transcription=env_cfg.enable_audio_transcription,
        audio_transcription_backend=env_cfg.audio_transcription_backend,
        audio_transcription_model=env_cfg.audio_transcription_model,
        audio_local_model_size=env_cfg.audio_local_model_size,
        whisper_cli_path=env_cfg.whisper_cli_path,
        audio_openai_api_key=env_cfg.audio_openai_api_key,
        audio_openai_base_url=env_cfg.audio_openai_base_url,
    )
    runtime = {
        "profile": env_cfg.profile,
        "profile_choices": profile_choices,
        "provider": env_cfg.provider,
        "model": active_model,
        "temperature": env_cfg.temperature,
        "api_base": env_cfg.api_base,
        "model_choices": env_cfg.model_choices,
        "max_turns": env_cfg.max_turns,
        "enable_deep_analysis": env_cfg.enable_deep_analysis,
        "enable_url_fetch": env_cfg.enable_url_fetch,
        "url_fetch_backend": env_cfg.url_fetch_backend,
        "allow_private_network": env_cfg.allow_private_network,
        "fetch_max_bytes": env_cfg.fetch_max_bytes,
        "enable_ocr": env_cfg.enable_ocr,
        "ocr_backend": env_cfg.ocr_backend,
        "enable_qr_decode": env_cfg.enable_qr_decode,
        "enable_audio_transcription": env_cfg.enable_audio_transcription,
        "audio_transcription_backend": env_cfg.audio_transcription_backend,
        "audio_transcription_model": env_cfg.audio_transcription_model,
        "agents_sdk": True,
        "config": yaml_cfg,
    }
    return agent, runtime
