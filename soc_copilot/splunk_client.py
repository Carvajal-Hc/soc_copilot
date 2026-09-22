"""Deterministic, read-only Splunk REST client.

This module is the *only* thing in SOC Copilot that talks to Splunk, and it is
entirely deterministic: no LLM, no guessing. It authenticates with a bearer
token, dispatches a search job, polls it to completion and returns the rows
Splunk produced.

Two invariants from CLAUDE.md are enforced here in code:

* **Read-only.** Search commands that mutate Splunk state (``delete``,
  ``collect``, ``outputlookup``, …) are rejected before dispatch.
* **Explicit time range.** ``run_search`` takes ``earliest``/``latest`` as
  first-class parameters and defaults to an all-time window, never Splunk's
  relative "last 24 hours" habit. The lab data is historical (~Nov 2024).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Final, Self
from urllib.parse import quote

import requests

from soc_copilot.config import SplunkConfig
from soc_copilot.guardrails import ReadOnlyViolation, enforce_read_only

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Time range
# --------------------------------------------------------------------------
#: Epoch 0 — no lower bound. The lab index holds ~Nov 2024 events, so any
#: relative default such as "-24h" would return nothing at all.
ALL_TIME_EARLIEST: Final[str] = "0"
#: Empty string means "omit the parameter", i.e. no upper bound.
ALL_TIME_LATEST: Final[str] = ""

DEFAULT_TIMEOUT: Final[float] = 30.0
DEFAULT_POLL_TIMEOUT: Final[float] = 300.0
#: Splunk caps a single results page at ``maxresultrows`` (50000 by default).
RESULTS_PAGE_SIZE: Final[int] = 50_000

AUTH_FAILURE_MESSAGE: Final[str] = """\
Splunk rejected the authentication token (HTTP 401).

The token is expired or invalid. Regenerate it in Splunk Web under
Settings > Tokens, then re-provide it as SPLUNK_TOKEN — either as an
environment variable or in your local .env file.\
"""

PERMISSION_FAILURE_MESSAGE: Final[str] = """\
Splunk accepted the token but refused the request (HTTP 403).

The token's user lacks capability for this endpoint. Grant the account the
'search' capability (and read access to the target index) in Splunk Web under
Settings > Roles, or issue the token for a user that already has it.\
"""

#: Which commands may run, and why a refusal says what it says, lives in
#: :mod:`soc_copilot.guardrails`. It is kept there rather than here because the
#: same policy has to hold for every query the system considers, not only the
#: ones that reach this client.

#: Commands that generate their own results and therefore must not be prefixed
#: with ``search``; they need a leading pipe instead.
_GENERATING_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "datamodel",
        "dbinspect",
        "eventcount",
        "from",
        "inputcsv",
        "inputlookup",
        "loadjob",
        "makeresults",
        "metadata",
        "mstats",
        "rest",
        "savedsearch",
        "tstats",
        "union",
    }
)


class SplunkError(RuntimeError):
    """Base class for legible Splunk failures. ``str()`` is analyst-facing."""


class SplunkAuthError(SplunkError):
    """HTTP 401/403 — the token was rejected or lacks capability."""


class SplunkConnectionError(SplunkError):
    """The management endpoint could not be reached at all."""


class SplunkSearchError(SplunkError):
    """Splunk accepted the request but the search itself failed."""


def normalize_spl(spl: str) -> str:
    """Return ``spl`` in the form Splunk's REST API expects.

    The REST search endpoint requires an explicit leading ``search`` command (or
    a leading pipe for generating commands). Analysts and, later, the translator
    write ``index=logforge | stats ...``, so normalise that here rather than
    scattering the rule across callers.
    """
    stripped = spl.strip()
    if not stripped:
        raise ValueError("SPL query is empty.")
    if stripped.startswith("|"):
        return stripped

    first_word = stripped.split(None, 1)[0].lower()
    if first_word == "search":
        return stripped
    if first_word in _GENERATING_COMMANDS:
        return f"| {stripped}"
    return f"search {stripped}"


def assert_read_only(spl: str) -> None:
    """Reject SPL that would mutate Splunk state.

    Delegates to :func:`soc_copilot.guardrails.enforce_read_only` and re-raises
    its refusal as a Splunk error, so callers of this client keep one exception
    type while the policy itself lives in one place.

    Raises:
        SplunkSearchError: naming the offending command and why it is refused.
    """
    try:
        enforce_read_only(spl)
    except ReadOnlyViolation as exc:
        raise SplunkSearchError(str(exc)) from exc


class SplunkClient:
    """A thin, blocking, read-only wrapper over the Splunk search REST API."""

    def __init__(
        self,
        config: SplunkConfig,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        poll_timeout: float = DEFAULT_POLL_TIMEOUT,
        poll_interval: float = 0.25,
        max_poll_interval: float = 2.0,
        search_level: str = "verbose",
        session: Any | None = None,
    ) -> None:
        """
        Args:
            search_level: ``adhoc_search_level`` for dispatched jobs. "verbose"
                guarantees full field extraction, which schema discovery relies
                on to see the index's real field names.
            session: Injectable ``requests.Session`` replacement (tests).
        """
        self.config = config
        self.timeout = timeout
        self.poll_timeout = poll_timeout
        self.poll_interval = poll_interval
        self.max_poll_interval = max_poll_interval
        self.search_level = search_level

        self._session = session if session is not None else requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {config.token}",
                "Accept": "application/json",
            }
        )
        self._session.verify = config.verify_tls

        if not config.verify_tls:
            # Explicit, scoped and loud: this concession exists solely because a
            # local Splunk install ships a self-signed management certificate.
            # config.verify_tls can only be False for loopback (see SplunkConfig).
            log.warning(
                "TLS certificate verification is RELAXED for %s because it is a "
                "loopback address with Splunk's self-signed management cert. "
                "Verification remains enabled for every non-local host.",
                config.hostname,
            )
            self._silence_self_signed_warning()
        else:
            log.info("TLS certificate verification is enabled for %s", config.hostname)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        close = getattr(self._session, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @staticmethod
    def _silence_self_signed_warning() -> None:
        """Mute urllib3's per-request warning for the loopback case only.

        The condition is already logged once, above; repeating it on every HTTP
        call buries the actual output. This does not change verification
        behaviour anywhere.
        """
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning

            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:  # pragma: no cover - urllib3 always ships with requests
            log.debug("Could not silence InsecureRequestWarning", exc_info=True)

    # -- HTTP --------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}/{path.lstrip('/')}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        url = self._url(path)
        try:
            response = self._session.request(
                method,
                url,
                params=params,
                data=data,
                timeout=self.timeout,
            )
        except requests.exceptions.SSLError as exc:
            raise SplunkConnectionError(
                f"TLS handshake with {self.config.base_url} failed: {exc}\n"
                "If this is a remote Splunk instance, install a certificate the "
                "machine trusts. Verification is only relaxed for localhost."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise SplunkConnectionError(
                f"Could not reach the Splunk management endpoint at "
                f"{self.config.base_url}: {exc}\n"
                "Check that Splunk is running and that SPLUNK_HOST points at the "
                "management port (default 8089), not Splunk Web (8000)."
            ) from exc

        status = response.status_code
        if status == 401:
            raise SplunkAuthError(AUTH_FAILURE_MESSAGE)
        if status == 403:
            raise SplunkAuthError(PERMISSION_FAILURE_MESSAGE)
        if status >= 400:
            raise SplunkSearchError(
                f"Splunk returned HTTP {status} for {method} {path}: "
                f"{_short(_response_text(response))}"
            )
        return response

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> dict:
        params = {**(params or {}), "output_mode": "json"}
        response = self._request("GET", path, params=params)
        return _parse_json(response, path)

    # -- public API --------------------------------------------------------

    def rest_entries(
        self, path: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET a Splunk REST collection and return its ``entry`` list.

        Used by schema discovery for endpoints such as ``/services/data/indexes``.
        """
        payload = self._get_json(path, {"count": 0, **(params or {})})
        entries = payload.get("entry") or []
        return [e for e in entries if isinstance(e, dict)]

    def run_search(
        self,
        spl: str,
        earliest: str = ALL_TIME_EARLIEST,
        latest: str = ALL_TIME_LATEST,
    ) -> list[dict[str, Any]]:
        """Run ``spl`` to completion and return its result rows.

        Args:
            spl: The search. A leading ``search`` command is added when needed.
            earliest: Splunk time modifier for the start of the window. Defaults
                to epoch 0 (no lower bound) — deliberately *not* a relative
                default like "-24h", because the lab data is from ~Nov 2024.
            latest: Splunk time modifier for the end of the window. Empty string
                means no upper bound.

        Returns:
            One dict per result row, with Splunk's field names as keys.

        Raises:
            SplunkAuthError: on HTTP 401/403, carrying an actionable message
                rather than a raw HTTP exception.
            SplunkConnectionError: if the endpoint is unreachable.
            SplunkSearchError: if the SPL is rejected, mutating, or the job fails.
        """
        assert_read_only(spl)
        query = normalize_spl(spl)

        log.info("Dispatching search (earliest=%r latest=%r): %s", earliest, latest, query)
        sid = self._create_job(query, earliest, latest)
        log.debug("Search job sid=%s", sid)

        content = self._wait_for_job(sid)
        rows = self._fetch_results(sid)
        log.info(
            "Search sid=%s complete: %s result row(s) from %s scanned event(s)",
            sid,
            len(rows),
            content.get("scanCount", "?"),
        )
        return rows

    # -- job lifecycle -----------------------------------------------------

    def _create_job(self, query: str, earliest: str, latest: str) -> str:
        data: dict[str, Any] = {
            "search": query,
            "exec_mode": "normal",
            "output_mode": "json",
            "adhoc_search_level": self.search_level,
            "earliest_time": earliest,
        }
        # An empty latest means "no upper bound": omit it entirely.
        if latest:
            data["latest_time"] = latest

        response = self._request("POST", "/services/search/jobs", data=data)
        payload = _parse_json(response, "/services/search/jobs")
        sid = payload.get("sid")
        if not sid:
            raise SplunkSearchError(
                f"Splunk accepted the search but returned no job id: {_short(payload)}"
            )
        return str(sid)

    def _wait_for_job(self, sid: str) -> dict[str, Any]:
        path = f"/services/search/jobs/{quote(sid, safe='')}"
        deadline = time.monotonic() + self.poll_timeout
        interval = self.poll_interval

        while True:
            payload = self._get_json(path)
            content = _entry_content(payload)

            if _as_bool(content.get("isFailed")):
                raise SplunkSearchError(
                    "Splunk could not run that search:\n"
                    + _format_messages(content.get("messages"))
                )
            if _as_bool(content.get("isDone")):
                return content

            if time.monotonic() >= deadline:
                state = content.get("dispatchState", "UNKNOWN")
                raise SplunkSearchError(
                    f"Search job {sid} did not finish within {self.poll_timeout:.0f}s "
                    f"(last state: {state}). Narrow the time range or the search."
                )
            time.sleep(interval)
            interval = min(interval * 1.5, self.max_poll_interval)

    def _fetch_results(self, sid: str) -> list[dict[str, Any]]:
        path = f"/services/search/jobs/{quote(sid, safe='')}/results"
        rows: list[dict[str, Any]] = []
        offset = 0

        while True:
            payload = self._get_json(
                path, {"count": RESULTS_PAGE_SIZE, "offset": offset}
            )
            page = payload.get("results") or []
            rows.extend(row for row in page if isinstance(row, dict))
            if len(page) < RESULTS_PAGE_SIZE:
                return rows
            offset += len(page)


# --------------------------------------------------------------------------
# Small parsing helpers
# --------------------------------------------------------------------------


def _response_text(response: Any) -> str:
    return getattr(response, "text", "") or ""


def _parse_json(response: Any, path: str) -> dict:
    try:
        payload = response.json()
    except ValueError as exc:
        raise SplunkSearchError(
            f"Splunk returned a non-JSON response for {path}: "
            f"{_short(_response_text(response))}"
        ) from exc
    if not isinstance(payload, dict):
        raise SplunkSearchError(
            f"Splunk returned an unexpected JSON shape for {path}: {_short(payload)}"
        )
    return payload


def _entry_content(payload: dict) -> dict[str, Any]:
    entries = payload.get("entry") or []
    if not entries or not isinstance(entries[0], dict):
        raise SplunkSearchError(f"Unexpected job status payload: {_short(payload)}")
    content = entries[0].get("content")
    return content if isinstance(content, dict) else {}


def _as_bool(value: Any) -> bool:
    """Splunk's JSON reports booleans as ``true``/``"1"``/``"0"`` depending on age."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def _format_messages(messages: Any) -> str:
    if not isinstance(messages, list) or not messages:
        return "  (Splunk reported no detail.)"
    lines = []
    for message in messages:
        if isinstance(message, dict):
            lines.append(
                f"  [{message.get('type', 'ERROR')}] {message.get('text', '')}".rstrip()
            )
        else:
            lines.append(f"  {message}")
    return "\n".join(lines)


def _short(value: Any, limit: int = 300) -> str:
    text = str(value).strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
