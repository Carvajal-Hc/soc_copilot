from __future__ import annotations

import pytest

from soc_copilot.config import (
    DEFAULT_SPLUNK_HOST,
    ENV_HOST,
    ENV_TOKEN,
    ConfigError,
    SplunkConfig,
    is_local_host,
    load_config,
)


def test_missing_token_raises_actionable_error() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(env={})
    message = str(excinfo.value)
    assert ENV_TOKEN in message
    assert "Settings > Tokens" in message
    assert ".env" in message


def test_blank_token_is_treated_as_missing() -> None:
    with pytest.raises(ConfigError):
        load_config(env={ENV_TOKEN: "   "})


def test_host_defaults_when_unset() -> None:
    config = load_config(env={ENV_TOKEN: "abc"})
    assert config.host == DEFAULT_SPLUNK_HOST
    assert config.is_local is True


def test_malformed_host_rejected() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(env={ENV_TOKEN: "abc", ENV_HOST: "localhost:8089"})
    assert ENV_HOST in str(excinfo.value)


@pytest.mark.parametrize(
    "host",
    ["https://localhost:8089", "https://127.0.0.1:8089", "http://LOCALHOST:8089"],
)
def test_loopback_hosts_relax_tls(host: str) -> None:
    config = load_config(env={ENV_TOKEN: "abc", ENV_HOST: host})
    assert is_local_host(host) is True
    assert config.is_local is True
    assert config.verify_tls is False
    assert "RELAXED" in config.describe()


def test_remote_host_keeps_tls_verification() -> None:
    config = load_config(
        env={ENV_TOKEN: "abc", ENV_HOST: "https://splunk.example.com:8089"}
    )
    assert config.is_local is False
    assert config.verify_tls is True
    assert "verified" in config.describe()


def test_relaxed_tls_is_impossible_for_remote_hosts() -> None:
    with pytest.raises(ConfigError) as excinfo:
        SplunkConfig(
            host="https://splunk.example.com:8089",
            token="abc",
            verify_tls=False,
            is_local=False,
        )
    assert "Refusing to disable TLS verification" in str(excinfo.value)


def test_token_never_appears_in_repr_or_describe() -> None:
    secret = "super-secret-token-value"
    config = load_config(env={ENV_TOKEN: secret})
    assert secret not in repr(config)
    assert secret not in config.describe()
    assert secret not in str(config)
    # The value is still available to the deterministic client.
    assert config.token == secret


def test_base_url_strips_trailing_slash() -> None:
    config = load_config(env={ENV_TOKEN: "abc", ENV_HOST: "https://localhost:8089/"})
    assert config.base_url == "https://localhost:8089"


def test_environment_takes_precedence_over_dotenv(tmp_path, monkeypatch) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        f"{ENV_TOKEN}=token-from-dotenv\n{ENV_HOST}=https://127.0.0.1:8089\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(ENV_TOKEN, "token-from-environment")
    monkeypatch.delenv(ENV_HOST, raising=False)

    config = load_config(dotenv_path=dotenv)

    # Environment wins for the key it sets...
    assert config.token == "token-from-environment"
    # ...and .env still supplies keys the environment does not define.
    assert config.host == "https://127.0.0.1:8089"


def test_dotenv_used_when_environment_is_empty(tmp_path, monkeypatch) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"{ENV_TOKEN}=token-from-dotenv\n", encoding="utf-8")
    monkeypatch.delenv(ENV_TOKEN, raising=False)
    monkeypatch.delenv(ENV_HOST, raising=False)

    config = load_config(dotenv_path=dotenv)

    assert config.token == "token-from-dotenv"
    assert config.host == DEFAULT_SPLUNK_HOST
