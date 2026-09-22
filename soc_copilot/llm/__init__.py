"""Pluggable LLM backends.

Import from here, never from a concrete backend module — that is what keeps the
rest of the system unaware of which one is active.
"""

from soc_copilot.llm.base import (
    BACKEND_ANTHROPIC,
    BACKEND_OLLAMA,
    ENV_BACKEND,
    ENV_MODEL,
    KNOWN_BACKENDS,
    NO_BACKEND_MESSAGE,
    LLMBackend,
    LLMConfig,
    LLMError,
    LLMNotConfigured,
    LLMUnavailable,
    SecretLeakError,
    assert_no_secrets,
    build_backend,
    collect_forbidden_secrets,
    resolve_config,
)

__all__ = [
    "BACKEND_ANTHROPIC",
    "BACKEND_OLLAMA",
    "ENV_BACKEND",
    "ENV_MODEL",
    "KNOWN_BACKENDS",
    "NO_BACKEND_MESSAGE",
    "LLMBackend",
    "LLMConfig",
    "LLMError",
    "LLMNotConfigured",
    "LLMUnavailable",
    "SecretLeakError",
    "assert_no_secrets",
    "build_backend",
    "collect_forbidden_secrets",
    "resolve_config",
]
