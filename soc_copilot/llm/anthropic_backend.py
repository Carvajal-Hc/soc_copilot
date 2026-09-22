"""Anthropic API backend.

The hosted option. Using it means the analyst's question and the discovered
schema leave this machine; ``SPLUNK_TOKEN`` never does — that is enforced by
:func:`~soc_copilot.llm.base.assert_no_secrets` before any request is made.

Requires ``pip install anthropic``. The import is deliberately lazy so the rest
of SOC Copilot runs without the package installed.
"""

from __future__ import annotations

import logging

from soc_copilot.llm.base import (
    LLMConfig,
    LLMNotConfigured,
    LLMUnavailable,
    assert_no_secrets,
)

log = logging.getLogger(__name__)

MISSING_PACKAGE_MESSAGE = """\
The 'anthropic' package is not installed, so the Anthropic backend cannot run.

  pip install anthropic

Or switch to the local backend to keep everything on this machine:
  SOC_LLM_BACKEND=ollama\
"""


class AnthropicBackend:
    """Single-shot text completion via the Messages API."""

    name = "anthropic"

    def __init__(self, config: LLMConfig) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise LLMNotConfigured(MISSING_PACKAGE_MESSAGE) from exc

        self.config = config
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(
            api_key=config.api_key,
            timeout=config.timeout,
        )
        log.info("LLM backend ready: %s", config.describe())

    def complete(self, *, system: str, user: str) -> str:
        assert_no_secrets(system)
        assert_no_secrets(user)

        anthropic = self._anthropic
        try:
            # No `temperature`: current Claude models reject sampling parameters
            # outright (HTTP 400). Determinism is instead pursued through a
            # tightly specified prompt and deterministic post-validation.
            response = self._client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.AuthenticationError as exc:
            raise LLMUnavailable(
                "Anthropic rejected the API key (HTTP 401). Check "
                "ANTHROPIC_API_KEY, or switch to SOC_LLM_BACKEND=ollama."
            ) from exc
        except anthropic.NotFoundError as exc:
            raise LLMUnavailable(
                f"Anthropic does not recognise the model {self.config.model!r}. "
                "Set SOC_LLM_MODEL to a model your key can reach."
            ) from exc
        except anthropic.RateLimitError as exc:
            retry = exc.response.headers.get("retry-after", "a moment")
            raise LLMUnavailable(
                f"Anthropic rate-limited the request. Retry after {retry}s."
            ) from exc
        except anthropic.APIStatusError as exc:
            raise LLMUnavailable(
                f"Anthropic returned HTTP {exc.status_code}: {exc.message}"
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise LLMUnavailable(
                f"Could not reach the Anthropic API: {exc}. If this machine is "
                "air-gapped, use SOC_LLM_BACKEND=ollama instead."
            ) from exc

        if response.stop_reason == "refusal":
            raise LLMUnavailable(
                "The model declined to answer this request, so no SPL was "
                "generated. Nothing was fabricated in its place."
            )

        # Only a text block carries ``.text``; the SDK's content union also
        # holds tool-use and thinking blocks, which this backend never asks for
        # but must not crash on if a future model returns one.
        text = "".join(
            block.text
            for block in response.content
            if getattr(block, "type", "") == "text" and hasattr(block, "text")
        ).strip()

        if not text:
            raise LLMUnavailable(
                "Anthropic returned an empty response; no SPL was generated."
            )
        if response.stop_reason == "max_tokens":
            log.warning(
                "Response hit max_tokens (%d); the SPL may be truncated. "
                "Raise SOC_LLM_MAX_TOKENS if generation looks cut off.",
                self.config.max_tokens,
            )
        return text
