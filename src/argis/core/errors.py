"""Custom exceptions for Argis."""


class ArgisError(Exception):
    """Base exception for application-level errors."""


class ConfigError(ArgisError):
    """Raised when configuration cannot be loaded or validated."""
