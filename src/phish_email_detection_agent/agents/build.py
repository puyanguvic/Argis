"""Build and wire application agent."""

from __future__ import annotations

from phish_email_detection_agent.agents.pipeline.policy import PipelinePolicy
from phish_email_detection_agent.agents.skills import default_skills_dir, discover_installed_skills
from phish_email_detection_agent.orchestrator.pipeline import AgentService
from phish_email_detection_agent.config.settings import load_config


def create_agent(
    *,
    profile_override: str | None = None,
    model_override: str | None = None,
) -> tuple[AgentService, dict[str, object]]:
    env_cfg, yaml_cfg = load_config(profile_override=profile_override)
    local_skills = discover_installed_skills()
    active_model = model_override or env_cfg.model
    profiles = yaml_cfg.get("profiles")
    profile_map = profiles if isinstance(profiles, dict) else {}
    profile_choices = [str(item) for item in profile_map.keys() if str(item).strip()]
    pipeline_policy = PipelinePolicy(
        pre_score_review_threshold=env_cfg.pre_score_review_threshold,
        pre_score_deep_threshold=env_cfg.pre_score_deep_threshold,
        context_trigger_score=env_cfg.context_trigger_score,
        suspicious_min_score=env_cfg.suspicious_min_score,
        suspicious_max_score=env_cfg.suspicious_max_score,
        judge_allow_mode=env_cfg.judge_allow_mode,
        judge_allow_sample_rate=env_cfg.judge_allow_sample_rate,
        judge_allow_sample_salt=env_cfg.judge_allow_sample_salt,
    ).normalized()
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
        precheck_domain_suspicious_threshold=env_cfg.precheck_domain_suspicious_threshold,
        precheck_text_keyword_weight=env_cfg.precheck_text_keyword_weight,
        precheck_text_urgency_weight=env_cfg.precheck_text_urgency_weight,
        precheck_text_action_weight=env_cfg.precheck_text_action_weight,
        precheck_text_core_bonus=env_cfg.precheck_text_core_bonus,
        precheck_text_finance_combo_bonus=env_cfg.precheck_text_finance_combo_bonus,
        precheck_text_suspicious_finance_bonus=env_cfg.precheck_text_suspicious_finance_bonus,
        precheck_text_suspicious_urgency_bonus=env_cfg.precheck_text_suspicious_urgency_bonus,
        precheck_url_suspicious_weight=env_cfg.precheck_url_suspicious_weight,
        precheck_url_path_token_bonus=env_cfg.precheck_url_path_token_bonus,
        precheck_url_path_bonus_cap=env_cfg.precheck_url_path_bonus_cap,
        precheck_url_domain_context_divisor=env_cfg.precheck_url_domain_context_divisor,
        precheck_url_domain_context_cap=env_cfg.precheck_url_domain_context_cap,
        precheck_domain_token_cap=env_cfg.precheck_domain_token_cap,
        precheck_domain_synthetic_bonus=env_cfg.precheck_domain_synthetic_bonus,
        pipeline_policy=pipeline_policy,
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
        "precheck_domain_suspicious_threshold": env_cfg.precheck_domain_suspicious_threshold,
        "precheck_url_suspicious_weight": env_cfg.precheck_url_suspicious_weight,
        "precheck_domain_token_cap": env_cfg.precheck_domain_token_cap,
        "precheck_domain_synthetic_bonus": env_cfg.precheck_domain_synthetic_bonus,
        "pre_score_review_threshold": env_cfg.pre_score_review_threshold,
        "pre_score_deep_threshold": env_cfg.pre_score_deep_threshold,
        "context_trigger_score": env_cfg.context_trigger_score,
        "suspicious_min_score": env_cfg.suspicious_min_score,
        "suspicious_max_score": env_cfg.suspicious_max_score,
        "judge_allow_mode": env_cfg.judge_allow_mode,
        "judge_allow_sample_rate": env_cfg.judge_allow_sample_rate,
        "judge_allow_sample_salt": env_cfg.judge_allow_sample_salt,
        "skills_dir": str(default_skills_dir()),
        "installed_skills": [
            {
                "name": item.name,
                "description": item.description,
                "directory": item.directory,
            }
            for item in local_skills
        ],
        "agents_sdk": True,
        "config": yaml_cfg,
    }
    return agent, runtime
