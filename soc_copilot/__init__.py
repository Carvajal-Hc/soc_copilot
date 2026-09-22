"""SOC Copilot — a natural-language triage assistant over Splunk.

The package root re-exports Stage 1 only: configuration, the authenticated
read-only REST client, and schema discovery. That layer contains no LLM code of
any kind, and it is the foundation everything above it is grounded in — every
literal in an answer traces back to a row it returned.

The later stages are imported from their own modules, so that nothing pulls in a
model backend by importing the package:

* :mod:`soc_copilot.generator` — question to SPL, grounded in the live schema
* :mod:`soc_copilot.agent` — the tool-using loop
* :mod:`soc_copilot.guardrails` — read-only enforcement, literal anchoring,
  untrusted-input defence
* :mod:`soc_copilot.views` — one result rendered as human, spl or json
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = [
    "ConfigError",
    "SplunkAuthError",
    "SplunkClient",
    "SplunkConfig",
    "SplunkConnectionError",
    "SplunkError",
    "SplunkSearchError",
    "discover_schema",
    "load_config",
]

from soc_copilot.config import ConfigError, SplunkConfig, load_config
from soc_copilot.schema import discover_schema
from soc_copilot.splunk_client import (
    SplunkAuthError,
    SplunkClient,
    SplunkConnectionError,
    SplunkError,
    SplunkSearchError,
)
