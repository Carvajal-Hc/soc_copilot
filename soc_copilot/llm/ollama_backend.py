"""Ollama backend — local inference, nothing leaves the machine.

This is the backend that makes SOC Copilot usable where a cloud assistant is
forbidden: sensitive evidence, restricted networks, air-gapped labs. It speaks
Ollama's HTTP API over ``requests`` (already a dependency), so there is no extra
package to install on a machine that may not have a package index.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from soc_copilot.llm.base import (
    ENV_TIMEOUT,
    LLMConfig,
    LLMUnavailable,
    assert_no_secrets,
)

log = logging.getLogger(__name__)


class OllamaBackend:
    """Single-shot chat completion against a local Ollama server."""

    name = "ollama"

    def __init__(self, config: LLMConfig, session: Any | None = None) -> None:
        self.config = config
        self._session = session if session is not None else requests.Session()
        log.info("LLM backend ready: %s (inference stays on this machine)", config.describe())

    def complete(self, *, system: str, user: str) -> str:
        assert_no_secrets(system)
        assert_no_secrets(user)

        payload = {
            "model": self.config.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {
                # Ollama, unlike the current Claude models, does accept a
                # sampling temperature — and 0.0 is what we want for SPL.
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        url = f"{self.config.base_url}/api/chat"
        try:
            response = self._session.post(url, json=payload, timeout=self.config.timeout)
        except requests.exceptions.Timeout as exc:
            # Distinguished from "unreachable" because the fixes are opposite:
            # a timeout here usually means the model is working and this machine
            # is slow, not that anything is broken. Saying so is the difference
            # between an analyst tuning a number and an analyst abandoning the
            # air-gapped path believing it does not work.
            raise LLMUnavailable(
                f"{self.config.model} did not finish within "
                f"{self.config.timeout:.0f}s.\n\n"
                "Local inference is slow by nature — a 14B model reasoning over a "
                "full transcript takes roughly 90-120s per turn on ordinary "
                "hardware, and longer as the transcript grows. This is a speed "
                "limit, not a failure: Ollama answered nothing yet, but nothing "
                "went wrong.\n\n"
                "Either raise the ceiling:\n"
                f"  {ENV_TIMEOUT}=1800\n"
                "or use a smaller model, at the cost of the harder reasoning "
                "steps (a 7B will not reliably pivot on an identifier):\n"
                "  SOC_LLM_MODEL=qwen2.5-coder:7b"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise LLMUnavailable(
                f"Could not reach Ollama at {self.config.base_url}: {exc}\n\n"
                "Start it with 'ollama serve', and make sure the model is pulled:\n"
                f"  ollama pull {self.config.model}"
            ) from exc

        if response.status_code == 404:
            raise LLMUnavailable(
                f"Ollama does not have the model {self.config.model!r}. Pull it "
                f"first:\n  ollama pull {self.config.model}\n"
                "Or point SOC_LLM_MODEL at a model you already have "
                "('ollama list' shows them)."
            )
        if response.status_code >= 400:
            raise LLMUnavailable(
                f"Ollama returned HTTP {response.status_code}: {_short(response.text)}"
            )

        try:
            payload_out = response.json()
        except ValueError as exc:
            raise LLMUnavailable(
                f"Ollama returned a non-JSON response: {_short(response.text)}"
            ) from exc

        text = ""
        message = payload_out.get("message")
        if isinstance(message, dict):
            text = str(message.get("content") or "")

        text = text.strip()
        if not text:
            raise LLMUnavailable(
                f"Ollama returned an empty response from {self.config.model!r}; "
                "no SPL was generated."
            )
        return text


def _short(value: Any, limit: int = 300) -> str:
    text = str(value).strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
