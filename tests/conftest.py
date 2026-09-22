"""Shared test doubles and fixtures.

No test in this suite touches a real Splunk instance or a real model. The
scripted backend and client below are the two seams that make that possible:
one plays the model, one plays Splunk, and both record what they were asked
so a test can assert on what the system sent as well as on what it did.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

import pytest

from soc_copilot.config import SplunkConfig
from soc_copilot.library import load_library
from soc_copilot.llm.base import LLMConfig
from soc_copilot.payload_shape import EventTypeShape, PayloadShape
from soc_copilot.schema import FieldInfo, IndexInfo, Schema


class FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(
        self,
        payload: Any = None,
        *,
        status_code: int = 200,
        text: str | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("response body is not JSON")
        return self._payload


class FakeSession:
    """Routes ``(method, path)`` to a scripted queue of responses.

    The last response for a route repeats once the queue is exhausted, which
    keeps polling tests short.
    """

    def __init__(
        self,
        routes: dict[tuple[str, str], Iterable[FakeResponse] | FakeResponse],
        *,
        raises: BaseException | None = None,
    ) -> None:
        self.routes: dict[tuple[str, str], list[FakeResponse]] = {}
        for key, value in routes.items():
            self.routes[key] = (
                [value] if isinstance(value, FakeResponse) else list(value)
            )
        self.raises = raises
        self.headers: dict[str, str] = {}
        self.verify: bool = True
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        if self.raises is not None:
            raise self.raises
        path = urlparse(url).path
        self.calls.append({"method": method, "url": url, "path": path, **kwargs})
        queue = self.routes.get((method.upper(), path))
        if queue is None:
            raise AssertionError(f"unexpected request: {method} {path}")
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def close(self) -> None:
        self.closed = True

    # -- assertions helpers ------------------------------------------------

    def calls_to(self, method: str, path: str) -> list[dict[str, Any]]:
        return [
            c for c in self.calls if c["method"].upper() == method.upper() and c["path"] == path
        ]


def job_status(
    *, is_done: bool = True, is_failed: bool = False, **content: Any
) -> FakeResponse:
    """Build a ``/services/search/jobs/<sid>`` status payload."""
    return FakeResponse(
        {
            "entry": [
                {
                    "content": {
                        "isDone": is_done,
                        "isFailed": is_failed,
                        "dispatchState": "DONE" if is_done else "RUNNING",
                        **content,
                    }
                }
            ]
        }
    )


def results(rows: list[dict[str, Any]]) -> FakeResponse:
    return FakeResponse({"results": rows, "fields": [], "preview": False})


@pytest.fixture(autouse=True)
def _isolate_splunk_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep real SPLUNK_* variables, and anything ``load_dotenv`` writes, out of
    the way. ``load_dotenv`` mutates ``os.environ`` directly, so tests that touch
    a .env file would otherwise leak into their neighbours."""
    import os

    for key in ("SPLUNK_HOST", "SPLUNK_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(os, "environ", dict(os.environ))


@pytest.fixture
def local_config() -> SplunkConfig:
    return SplunkConfig(
        host="https://localhost:8089",
        token="test-token",
        verify_tls=False,
        is_local=True,
    )


@pytest.fixture
def remote_config() -> SplunkConfig:
    return SplunkConfig(
        host="https://splunk.example.com:8089",
        token="test-token",
        verify_tls=True,
        is_local=False,
    )


# ------------------------------------------------------------------------
# Stage 2-4: standing in for the model and for the search layer
# ------------------------------------------------------------------------


class ScriptedBackend:
    """Replays a fixed list of replies, recording every prompt it was given."""

    name = "scripted"

    def __init__(self, *replies: str | dict[str, Any]) -> None:
        self.config = LLMConfig(backend="scripted", model="scripted-model")
        self.replies = [
            json.dumps(r) if isinstance(r, dict) else r for r in replies
        ]
        self.prompts: list[str] = []
        self.systems: list[str] = []

    def complete(self, *, system: str, user: str) -> str:
        self.systems.append(system)
        self.prompts.append(user)
        if not self.replies:
            raise AssertionError("the loop asked for more turns than were scripted")
        return self.replies.pop(0)


class ScriptedClient:
    """Stands in for ``SplunkClient``: returns rows per search, records calls."""

    def __init__(self, *responses: list[dict[str, Any]] | BaseException) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, str]] = []

    def run_search(
        self, spl: str, earliest: str = "0", latest: str = ""
    ) -> list[dict[str, Any]]:
        self.calls.append({"spl": spl, "earliest": earliest, "latest": latest})
        if not self.responses:
            return []
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


@pytest.fixture
def schema() -> Schema:
    return Schema(
        index="logforge",
        indexes=[
            IndexInfo(
                name="logforge",
                event_count=60132,
                earliest="2024-11-06T14:49:02-0700",
                latest="2025-08-11T07:50:30-0700",
                disabled=False,
                is_internal=False,
            )
        ],
        fields=[
            FieldInfo(name=n, event_count=100, distinct_count=5, is_exact=True)
            for n in ("Channel", "EventId", "Computer", "Payload", "_time")
        ],
    )


@pytest.fixture
def shape() -> PayloadShape:
    return PayloadShape(
        index="logforge",
        container="Payload",
        encoding="json",
        layout="name-value-array",
        name_path="EventData.Data{}.@Name",
        text_path="EventData.Data{}.#text",
        nested_names=("ProcessGuid", "ParentProcessGuid", "Image", "CommandLine"),
        stratified_by=("EventId",),
        event_types=(
            EventTypeShape(
                key=("1",),
                nested_names=("ProcessGuid", "Image", "CommandLine"),
                label="Process creation",
            ),
        ),
        sampled_events=725,
    )


@pytest.fixture
def library():
    return load_library().with_index("logforge")
