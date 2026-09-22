"""The pluggable LLM interface.

One interface, two backends. The rest of SOC Copilot must not know which is
active — that is what makes air-gapped operation a configuration choice rather
than a fork of the codebase.

The contract is deliberately tiny:

    complete(system: str, user: str) -> str

Everything above it (prompt construction, JSON parsing, SPL validation) is
deterministic Python and lives in :mod:`soc_copilot.generator`. Everything below
it is backend-specific transport. A backend never sees a schema, a question or a
piece of SPL as anything but opaque text.

Secret hygiene is enforced here, at the boundary: :func:`assert_no_secrets` runs
on every prompt before it leaves the process. ``SPLUNK_TOKEN`` belongs to the
deterministic Splunk client and must never reach a model, least of all a hosted
one.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

log = logging.getLogger(__name__)

ENV_BACKEND: Final[str] = "SOC_LLM_BACKEND"
ENV_MODEL: Final[str] = "SOC_LLM_MODEL"
ENV_MAX_TOKENS: Final[str] = "SOC_LLM_MAX_TOKENS"
ENV_TIMEOUT: Final[str] = "SOC_LLM_TIMEOUT"
ENV_TEMPERATURE: Final[str] = "SOC_LLM_TEMPERATURE"

ENV_ANTHROPIC_KEY: Final[str] = "ANTHROPIC_API_KEY"
ENV_OLLAMA_HOST: Final[str] = "OLLAMA_HOST"

BACKEND_ANTHROPIC: Final[str] = "anthropic"
BACKEND_OLLAMA: Final[str] = "ollama"
KNOWN_BACKENDS: Final[tuple[str, ...]] = (BACKEND_ANTHROPIC, BACKEND_OLLAMA)

DEFAULT_ANTHROPIC_MODEL: Final[str] = "claude-opus-5"
DEFAULT_OLLAMA_MODEL: Final[str] = "qwen2.5-coder:7b"
DEFAULT_OLLAMA_HOST: Final[str] = "http://localhost:11434"

DEFAULT_MAX_TOKENS: Final[int] = 4096
#: Per-request timeouts, split by backend because the two paths fail differently.
#:
#: A hosted API that has not answered in two minutes is broken, and waiting
#: longer only delays a legible error. A local model is a different animal: on
#: ordinary hardware a 14B reasoning over a full transcript takes ~90-120s *per
#: turn* as a matter of course, and a 7B is not much faster once the prompt is
#: large. Under the old single 120s default that normal working speed surfaced
#: as a timeout — the air-gapped path looked broken when it was merely slow,
#: which is the opposite of failing legibly. So the local default is generous on
#: purpose: it is sized so that "no answer yet" means something is actually
#: wrong, not that the machine is thinking.
DEFAULT_TIMEOUT_API: Final[float] = 120.0
DEFAULT_TIMEOUT_LOCAL: Final[float] = 900.0
#: Kept as the name other modules and tests import; it is the hosted value.
DEFAULT_TIMEOUT: Final[float] = DEFAULT_TIMEOUT_API
#: SPL generation wants the least creative answer available. Backends that
#: reject a sampling parameter ignore this (see :class:`LLMConfig.temperature`).
DEFAULT_TEMPERATURE: Final[float] = 0.0

NO_BACKEND_MESSAGE: Final[str] = f"""\
No LLM backend is configured, so no SPL can be generated.

SOC Copilot will not guess SPL. Choose a backend explicitly by setting
{ENV_BACKEND} — as an environment variable or in your local .env file:

  Local / air-gapped (nothing leaves this machine):
      {ENV_BACKEND}=ollama
      {ENV_MODEL}={DEFAULT_OLLAMA_MODEL}          # optional
      {ENV_OLLAMA_HOST}={DEFAULT_OLLAMA_HOST}   # optional
    Requires a running Ollama with that model pulled. Expect ~90-120s per turn
    on ordinary hardware; that is normal, not a hang, which is why the local
    timeout defaults to {DEFAULT_TIMEOUT_LOCAL:.0f}s.

  Hosted API (the question and the discovered schema leave this machine):
      {ENV_BACKEND}=anthropic
      {ENV_ANTHROPIC_KEY}=<your key>
      {ENV_MODEL}={DEFAULT_ANTHROPIC_MODEL}        # optional
    Requires: pip install anthropic

SPLUNK_TOKEN is never sent to any backend.\
"""


class LLMError(RuntimeError):
    """Base class for backend failures. ``str()`` is analyst-facing."""


class LLMNotConfigured(LLMError):
    """No backend was selected, or the selected one is missing a prerequisite."""


class LLMUnavailable(LLMError):
    """The backend is configured but could not be reached or refused the call."""


class SecretLeakError(LLMError):
    """A prompt contained a value that must never reach a model.

    Raised before any network call. This is a hard stop, not a warning.
    """


@dataclass(frozen=True)
class LLMConfig:
    """Resolved backend settings. The API key is kept out of ``repr``."""

    backend: str
    model: str
    api_key: str = field(default="", repr=False)
    base_url: str = ""
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: float = DEFAULT_TIMEOUT
    #: Applied only by backends that accept a sampling parameter. The current
    #: Claude models reject ``temperature`` outright (HTTP 400), so the Anthropic
    #: backend does not send it; Ollama does, where 0.0 is worth having.
    temperature: float = DEFAULT_TEMPERATURE

    def describe(self) -> str:
        """A one-line summary that never contains the key."""
        where = self.base_url or "api.anthropic.com"
        key = f"key set ({len(self.api_key)} chars, not shown)" if self.api_key else "no key"
        return f"backend={self.backend} model={self.model} endpoint={where} {key}"

    @property
    def is_local(self) -> bool:
        """True when inference happens on this machine (air-gapped operation)."""
        return self.backend == BACKEND_OLLAMA


@runtime_checkable
class LLMBackend(Protocol):
    """The only thing the rest of the system may depend on."""

    #: Stable identifier used in logs and in generated-query provenance.
    name: str
    config: LLMConfig

    def complete(self, *, system: str, user: str) -> str:
        """Return the model's text response to ``user`` under ``system``.

        Raises:
            LLMUnavailable: the backend could not produce a response.
            SecretLeakError: a prompt contained a forbidden secret.
        """
        ...


# --------------------------------------------------------------------------
# Secret hygiene
# --------------------------------------------------------------------------


def collect_forbidden_secrets(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Values that must never appear in a prompt.

    ``SPLUNK_TOKEN`` is the one that matters: it is a live credential for the
    deterministic side of the system, and CLAUDE.md forbids it reaching a model.
    """
    source = os.environ if env is None else env
    secrets = []
    for key in ("SPLUNK_TOKEN", ENV_ANTHROPIC_KEY):
        value = (source.get(key) or "").strip()
        # Very short values would cause false positives against ordinary text.
        if len(value) >= 8:
            secrets.append(value)
    return tuple(secrets)


def assert_no_secrets(text: str, secrets: tuple[str, ...] | None = None) -> None:
    """Fail closed if ``text`` contains a credential.

    Raises:
        SecretLeakError: naming which variable leaked, never the value itself.
    """
    if secrets is None:
        secrets = collect_forbidden_secrets()
    if not text or not secrets:
        return

    env = os.environ
    for secret in secrets:
        if secret in text:
            names = [k for k in ("SPLUNK_TOKEN", ENV_ANTHROPIC_KEY) if env.get(k) == secret]
            leaked = names[0] if names else "a configured credential"
            raise SecretLeakError(
                f"Refusing to send this prompt: it contains the value of {leaked}. "
                "Credentials belong to the deterministic Splunk client and must "
                "never reach an LLM. This is a bug in prompt construction."
            )


# --------------------------------------------------------------------------
# Backend selection
# --------------------------------------------------------------------------


def resolve_config(env: Mapping[str, str] | None = None) -> LLMConfig:
    """Resolve backend settings from the environment.

    Selection is explicit and opt-in: with no :data:`ENV_BACKEND` set this raises
    rather than picking one, because silently defaulting to a hosted API would
    send an analyst's question off the machine without them asking for it.

    Raises:
        LLMNotConfigured: with actionable instructions.
    """
    source = os.environ if env is None else env
    backend = (source.get(ENV_BACKEND) or "").strip().lower()

    if not backend:
        raise LLMNotConfigured(NO_BACKEND_MESSAGE)
    if backend not in KNOWN_BACKENDS:
        raise LLMNotConfigured(
            f"{ENV_BACKEND}={backend!r} is not a known backend. "
            f"Choose one of: {', '.join(KNOWN_BACKENDS)}."
        )

    model = (source.get(ENV_MODEL) or "").strip()
    default_timeout = (
        DEFAULT_TIMEOUT_LOCAL if backend == BACKEND_OLLAMA else DEFAULT_TIMEOUT_API
    )
    common: dict[str, Any] = {
        "max_tokens": _as_int(source.get(ENV_MAX_TOKENS), DEFAULT_MAX_TOKENS),
        "timeout": _as_float(source.get(ENV_TIMEOUT), default_timeout),
        "temperature": _as_float(source.get(ENV_TEMPERATURE), DEFAULT_TEMPERATURE),
    }

    if backend == BACKEND_ANTHROPIC:
        api_key = (source.get(ENV_ANTHROPIC_KEY) or "").strip()
        if not api_key:
            raise LLMNotConfigured(
                f"{ENV_BACKEND}=anthropic but {ENV_ANTHROPIC_KEY} is not set.\n\n"
                f"Set {ENV_ANTHROPIC_KEY} in the environment or your local .env "
                f"file, or switch to the local backend with {ENV_BACKEND}=ollama "
                "to keep everything on this machine."
            )
        return LLMConfig(
            backend=backend,
            model=model or DEFAULT_ANTHROPIC_MODEL,
            api_key=api_key,
            **common,
        )

    return LLMConfig(
        backend=backend,
        model=model or DEFAULT_OLLAMA_MODEL,
        base_url=(source.get(ENV_OLLAMA_HOST) or DEFAULT_OLLAMA_HOST).rstrip("/"),
        **common,
    )


def build_backend(
    config: LLMConfig | None = None,
    env: Mapping[str, str] | None = None,
) -> LLMBackend:
    """Construct the configured backend.

    Imports the backend module lazily so that neither the ``anthropic`` package
    nor a reachable Ollama is needed to run the rest of the system.
    """
    resolved = config if config is not None else resolve_config(env)

    if resolved.backend == BACKEND_ANTHROPIC:
        from soc_copilot.llm.anthropic_backend import AnthropicBackend

        return AnthropicBackend(resolved)

    from soc_copilot.llm.ollama_backend import OllamaBackend

    return OllamaBackend(resolved)


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_float(value: str | None, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default
