"""Configuration for the deterministic Splunk layer.

Values are read from environment variables first, then from a local ``.env``
file via python-dotenv. The environment always wins. Nothing is hardcoded and
nothing is ever prompted for interactively.

``SPLUNK_TOKEN`` is a secret that belongs exclusively to this deterministic side
of the system. It must never be placed into an LLM prompt or accepted through a
chat interface. ``SplunkConfig`` therefore keeps the token out of its ``repr``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dotenv import find_dotenv, load_dotenv

log = logging.getLogger(__name__)

ENV_HOST = "SPLUNK_HOST"
ENV_TOKEN = "SPLUNK_TOKEN"

DEFAULT_SPLUNK_HOST = "https://localhost:8089"

#: Hostnames that mean "this machine". Only these are allowed to relax TLS
#: certificate verification, because a local Splunk install ships a self-signed
#: management certificate. Anything else must present a valid chain.
LOCAL_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})

MISSING_TOKEN_MESSAGE = f"""\
{ENV_TOKEN} is not set, so there is no way to authenticate to Splunk.

Create a token in Splunk Web under Settings > Tokens > New Token, then provide
it in one of two ways:

  1. As an environment variable (this takes precedence):
       PowerShell:  $env:SPLUNK_TOKEN = '<token>'
       bash:        export SPLUNK_TOKEN='<token>'

  2. In a local .env file at the project root (git-ignored, never committed):
       copy .env.example to .env and set SPLUNK_TOKEN=<token>

{ENV_HOST} is optional and defaults to {DEFAULT_SPLUNK_HOST}.\
"""


class ConfigError(RuntimeError):
    """Configuration is missing or unusable. Carries an actionable message."""


def is_local_host(host: str) -> bool:
    """True if ``host`` points at this machine (loopback)."""
    hostname = urlparse(host).hostname
    return hostname is not None and hostname.lower() in LOCAL_HOSTNAMES


@dataclass(frozen=True)
class SplunkConfig:
    """Resolved connection settings for the Splunk management endpoint."""

    host: str
    #: Never rendered by ``repr`` — this value must not leak into logs.
    token: str = field(repr=False)
    #: False only for loopback hosts (local self-signed management cert).
    verify_tls: bool
    is_local: bool

    def __post_init__(self) -> None:
        parsed = urlparse(self.host)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ConfigError(
                f"{ENV_HOST} must be a full URL such as {DEFAULT_SPLUNK_HOST!r}; "
                f"got {self.host!r}."
            )
        if not self.token:
            raise ConfigError(MISSING_TOKEN_MESSAGE)
        if self.verify_tls is False and self.is_local is False:
            # Belt and braces: relaxed TLS is a loopback-only concession.
            raise ConfigError(
                "Refusing to disable TLS verification for the non-local host "
                f"{self.host!r}."
            )

    @property
    def base_url(self) -> str:
        """Host with any trailing slash removed."""
        return self.host.rstrip("/")

    @property
    def hostname(self) -> str:
        return urlparse(self.host).hostname or ""

    def describe(self) -> str:
        """A human-readable summary that never contains the token."""
        tls = (
            "verified"
            if self.verify_tls
            else "RELAXED (loopback only — local self-signed cert)"
        )
        return (
            f"host={self.base_url}  tls={tls}  "
            f"token=set ({len(self.token)} chars, not shown)"
        )


def _apply_dotenv(dotenv_path: str | Path | None) -> str | None:
    """Load a ``.env`` file without overriding real environment variables.

    Returns the path that was loaded, or ``None`` if no file was found.
    """
    path = str(dotenv_path) if dotenv_path is not None else find_dotenv(usecwd=True)
    if not path or not Path(path).is_file():
        return None
    # override=False is what makes the environment take precedence over .env.
    load_dotenv(path, override=False)
    return path


def load_config(
    *,
    env: Mapping[str, str] | None = None,
    dotenv_path: str | Path | None = None,
) -> SplunkConfig:
    """Build a :class:`SplunkConfig` from the environment and/or a ``.env`` file.

    Args:
        env: Mapping to read from instead of :data:`os.environ`. Used by tests;
            when supplied, no ``.env`` file is consulted.
        dotenv_path: Explicit ``.env`` location. Defaults to the nearest ``.env``
            found upward from the current working directory.

    Raises:
        ConfigError: with an actionable message when ``SPLUNK_TOKEN`` is missing
            or ``SPLUNK_HOST`` is malformed.
    """
    if env is None:
        loaded = _apply_dotenv(dotenv_path)
        if loaded:
            log.debug("Loaded .env from %s (environment still takes precedence)", loaded)
        env = os.environ

    host = (env.get(ENV_HOST) or "").strip() or DEFAULT_SPLUNK_HOST
    token = (env.get(ENV_TOKEN) or "").strip()

    if not token:
        raise ConfigError(MISSING_TOKEN_MESSAGE)

    local = is_local_host(host)
    return SplunkConfig(
        host=host,
        token=token,
        verify_tls=not local,
        is_local=local,
    )
