"""Model provider adapters."""

from phish_email_detection_agent.providers.llm_ollama import build_ollama_model_reference
from phish_email_detection_agent.providers.llm_openai import ProviderConfig, build_model_reference

__all__ = ["ProviderConfig", "build_model_reference", "build_ollama_model_reference"]
