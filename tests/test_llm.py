"""Backend selection, the fail-closed path, and secret hygiene."""

from __future__ import annotations

from typing import ClassVar

import pytest

from soc_copilot.llm.base import (
    BACKEND_ANTHROPIC,
    BACKEND_OLLAMA,
    DEFAULT_OLLAMA_HOST,
    LLMConfig,
    LLMNotConfigured,
    LLMUnavailable,
    SecretLeakError,
    assert_no_secrets,
    collect_forbidden_secrets,
    resolve_config,
)
from soc_copilot.llm.ollama_backend import OllamaBackend


class TestBackendSelection:
    def test_no_backend_configured_fails_with_instructions(self):
        with pytest.raises(LLMNotConfigured) as exc:
            resolve_config({})

        message = str(exc.value)
        # Must never silently guess SPL, and must say how to fix it.
        assert "will not guess SPL" in message
        assert "SOC_LLM_BACKEND=ollama" in message
        assert "SOC_LLM_BACKEND=anthropic" in message

    def test_unknown_backend_is_rejected(self):
        with pytest.raises(LLMNotConfigured, match="not a known backend"):
            resolve_config({"SOC_LLM_BACKEND": "gpt4all"})

    def test_ollama_needs_no_key_and_defaults_to_localhost(self):
        config = resolve_config({"SOC_LLM_BACKEND": "ollama"})

        assert config.backend == BACKEND_OLLAMA
        assert config.base_url == DEFAULT_OLLAMA_HOST
        assert config.is_local

    def test_anthropic_without_a_key_fails_and_suggests_the_local_backend(self):
        with pytest.raises(LLMNotConfigured) as exc:
            resolve_config({"SOC_LLM_BACKEND": "anthropic"})

        assert "ANTHROPIC_API_KEY" in str(exc.value)
        assert "SOC_LLM_BACKEND=ollama" in str(exc.value)

    def test_anthropic_with_a_key_resolves(self):
        config = resolve_config(
            {"SOC_LLM_BACKEND": "anthropic", "ANTHROPIC_API_KEY": "sk-test-12345678"}
        )

        assert config.backend == BACKEND_ANTHROPIC
        assert not config.is_local

    def test_model_and_tuning_come_from_the_environment(self):
        config = resolve_config(
            {
                "SOC_LLM_BACKEND": "ollama",
                "SOC_LLM_MODEL": "llama3.1:8b",
                "SOC_LLM_MAX_TOKENS": "8192",
                "SOC_LLM_TIMEOUT": "45",
            }
        )

        assert config.model == "llama3.1:8b"
        assert config.max_tokens == 8192
        assert config.timeout == 45.0

    def test_backend_name_is_case_insensitive(self):
        assert resolve_config({"SOC_LLM_BACKEND": "OLLAMA"}).backend == BACKEND_OLLAMA


class TestSecretsNeverReachAModel:
    def test_config_describe_never_prints_the_key(self):
        config = LLMConfig(backend="anthropic", model="m", api_key="sk-super-secret-xyz")

        assert "sk-super-secret-xyz" not in config.describe()
        assert "sk-super-secret-xyz" not in repr(config)

    def test_a_prompt_containing_the_splunk_token_is_refused(self, monkeypatch):
        token = "eyJraWQiOiJzcGx1bmsuc2VjcmV0In0-TESTTOKEN"
        monkeypatch.setenv("SPLUNK_TOKEN", token)

        with pytest.raises(SecretLeakError, match="SPLUNK_TOKEN"):
            assert_no_secrets(f"the token is {token}", (token,))

    def test_an_unidentified_secret_is_still_refused(self):
        # The value is not traceable to a known variable, but it must not be sent.
        with pytest.raises(SecretLeakError, match="configured credential"):
            assert_no_secrets("leaking some-configured-secret", ("some-configured-secret",))

    def test_the_refusal_message_does_not_repeat_the_secret(self):
        token = "eyJraWQiOiJzcGx1bmsuc2VjcmV0In0-TESTTOKEN"

        with pytest.raises(SecretLeakError) as exc:
            assert_no_secrets(f"leak: {token}", (token,))

        assert token not in str(exc.value)

    def test_a_clean_prompt_passes(self):
        assert_no_secrets("index=logforge | stats count", ("some-secret-value",))

    def test_short_values_are_not_treated_as_secrets(self):
        # Guards against a two-character token turning every prompt into a leak.
        secrets = collect_forbidden_secrets({"SPLUNK_TOKEN": "abc"})

        assert secrets == ()

    def test_the_splunk_token_is_collected_when_long_enough(self):
        secrets = collect_forbidden_secrets({"SPLUNK_TOKEN": "long-enough-token-value"})

        assert secrets == ("long-enough-token-value",)


class _FakeResponse:
    def __init__(self, payload=None, status_code=200, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _FakeSession:
    def __init__(self, response=None, raises=None):
        self.response = response
        self.raises = raises
        self.calls = []

    def post(self, url, json=None, timeout=None):
        if self.raises:
            raise self.raises
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        return self.response


class TestOllamaBackend:
    def _config(self):
        return LLMConfig(
            backend="ollama", model="test-model", base_url=DEFAULT_OLLAMA_HOST
        )

    def test_returns_the_message_content(self):
        session = _FakeSession(_FakeResponse({"message": {"content": "  spl here  "}}))

        result = OllamaBackend(self._config(), session=session).complete(
            system="sys", user="usr"
        )

        assert result == "spl here"

    def test_sends_both_prompts_and_a_zero_temperature(self):
        session = _FakeSession(_FakeResponse({"message": {"content": "x"}}))

        OllamaBackend(self._config(), session=session).complete(system="S", user="U")

        body = session.calls[0]["json"]
        assert body["messages"] == [
            {"role": "system", "content": "S"},
            {"role": "user", "content": "U"},
        ]
        assert body["options"]["temperature"] == 0.0
        assert body["stream"] is False

    def test_a_missing_model_says_how_to_pull_it(self):
        session = _FakeSession(_FakeResponse(status_code=404, text="not found"))

        with pytest.raises(LLMUnavailable, match="ollama pull test-model"):
            OllamaBackend(self._config(), session=session).complete(system="s", user="u")

    def test_an_unreachable_server_says_how_to_start_it(self):
        import requests

        session = _FakeSession(raises=requests.exceptions.ConnectionError("refused"))

        with pytest.raises(LLMUnavailable, match="ollama serve"):
            OllamaBackend(self._config(), session=session).complete(system="s", user="u")

    def test_an_empty_response_is_an_error_not_empty_spl(self):
        session = _FakeSession(_FakeResponse({"message": {"content": "   "}}))

        with pytest.raises(LLMUnavailable, match="empty"):
            OllamaBackend(self._config(), session=session).complete(system="s", user="u")

    def test_secrets_are_checked_before_the_request_is_made(self, monkeypatch):
        monkeypatch.setenv("SPLUNK_TOKEN", "a-very-secret-splunk-token")
        session = _FakeSession(_FakeResponse({"message": {"content": "x"}}))

        with pytest.raises(SecretLeakError):
            OllamaBackend(self._config(), session=session).complete(
                system="s", user="token: a-very-secret-splunk-token"
            )

        assert session.calls == []


# --------------------------------------------------------------------------
# Local inference is slow on purpose, and must not look broken
# --------------------------------------------------------------------------


def test_the_local_backend_gets_a_generous_default_timeout() -> None:
    """120s is a hosted-API number. A local 14B needs ~90-120s per *turn*."""
    from soc_copilot.llm.base import DEFAULT_TIMEOUT_LOCAL, resolve_config

    config = resolve_config({"SOC_LLM_BACKEND": "ollama"})

    assert config.timeout == DEFAULT_TIMEOUT_LOCAL
    assert config.timeout >= 600


def test_the_hosted_backend_keeps_the_short_timeout() -> None:
    """An API that has not answered in two minutes is broken, not thinking."""
    from soc_copilot.llm.base import DEFAULT_TIMEOUT_API, resolve_config

    config = resolve_config(
        {"SOC_LLM_BACKEND": "anthropic", "ANTHROPIC_API_KEY": "k" * 20}
    )

    assert config.timeout == DEFAULT_TIMEOUT_API


def test_an_explicit_timeout_still_wins_for_either_backend() -> None:
    from soc_copilot.llm.base import resolve_config

    local = resolve_config({"SOC_LLM_BACKEND": "ollama", "SOC_LLM_TIMEOUT": "45"})
    hosted = resolve_config(
        {"SOC_LLM_BACKEND": "anthropic", "ANTHROPIC_API_KEY": "k" * 20,
         "SOC_LLM_TIMEOUT": "1800"}
    )

    assert local.timeout == 45.0
    assert hosted.timeout == 1800.0


def test_a_local_timeout_reads_as_slow_not_as_broken() -> None:
    """Fail legibly: the fix for slow is a bigger number, not a bug report."""
    import requests

    from soc_copilot.llm.base import LLMConfig, LLMUnavailable
    from soc_copilot.llm.ollama_backend import OllamaBackend

    class TimingOutSession:
        headers: ClassVar[dict] = {}

        def post(self, url, json=None, timeout=None):
            raise requests.exceptions.Timeout("timed out")

    backend = OllamaBackend(
        LLMConfig(backend="ollama", model="qwen2.5-coder:14b", timeout=900.0),
        session=TimingOutSession(),
    )

    with pytest.raises(LLMUnavailable) as excinfo:
        backend.complete(system="s", user="u")

    message = str(excinfo.value)
    assert "did not finish within 900s" in message
    assert "not a failure" in message
    assert "SOC_LLM_TIMEOUT" in message
    # It must not read like an outage, which is the wrong diagnosis entirely.
    assert "Could not reach" not in message
