from __future__ import annotations

import logging

import pytest
import requests

from soc_copilot import splunk_client as sc
from soc_copilot.splunk_client import (
    ALL_TIME_EARLIEST,
    ALL_TIME_LATEST,
    SplunkAuthError,
    SplunkClient,
    SplunkConnectionError,
    SplunkError,
    SplunkSearchError,
    assert_read_only,
    normalize_spl,
)
from tests.conftest import FakeResponse, FakeSession, job_status, results

JOBS = "/services/search/jobs"
SID = "1700000000.42"
STATUS = f"{JOBS}/{SID}"
RESULTS = f"{JOBS}/{SID}/results"


def make_client(session: FakeSession, config, **kwargs) -> SplunkClient:
    kwargs.setdefault("poll_interval", 0)
    kwargs.setdefault("max_poll_interval", 0)
    return SplunkClient(config, session=session, **kwargs)


def happy_session(rows: list[dict] | None = None, **status: object) -> FakeSession:
    return FakeSession(
        {
            ("POST", JOBS): FakeResponse({"sid": SID}),
            ("GET", STATUS): job_status(**status),
            ("GET", RESULTS): results(rows if rows is not None else []),
        }
    )


# --------------------------------------------------------------------------
# SPL normalisation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("index=logforge | stats count", "search index=logforge | stats count"),
        ("  index=logforge  ", "search index=logforge"),
        ("search index=logforge", "search index=logforge"),
        (
            "| metadata type=sourcetypes index=logforge",
            "| metadata type=sourcetypes index=logforge",
        ),
        ("metadata type=sourcetypes index=logforge", "| metadata type=sourcetypes index=logforge"),
        ("tstats count where index=logforge", "| tstats count where index=logforge"),
        ("SEARCH index=logforge", "SEARCH index=logforge"),
    ],
)
def test_normalize_spl(raw: str, expected: str) -> None:
    assert normalize_spl(raw) == expected


def test_normalize_spl_rejects_empty() -> None:
    with pytest.raises(ValueError):
        normalize_spl("   ")


# --------------------------------------------------------------------------
# Read-only guard
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spl",
    [
        "index=logforge | delete",
        "index=logforge | collect index=summary",
        "index=logforge | outputlookup hosts.csv",
        "index=logforge | stats count | SENDEMAIL to=a@b.c",
        "index=logforge |delete",
    ],
)
def test_mutating_spl_is_refused(spl: str) -> None:
    with pytest.raises(SplunkSearchError, match="read-only"):
        assert_read_only(spl)


@pytest.mark.parametrize(
    "spl",
    [
        "index=logforge | stats count by Computer, EventId",
        "index=logforge Computer=deleted-host | head 5",
        "index=logforge | eval note=\"collect the evidence\"",
    ],
)
def test_read_only_spl_is_allowed(spl: str) -> None:
    assert_read_only(spl)  # does not raise


def test_run_search_refuses_mutation_before_dispatch(local_config) -> None:
    session = happy_session()
    client = make_client(session, local_config)
    with pytest.raises(SplunkSearchError, match="read-only"):
        client.run_search("index=logforge | delete")
    assert session.calls == []


# --------------------------------------------------------------------------
# Search happy path
# --------------------------------------------------------------------------


def test_run_search_returns_rows(local_config) -> None:
    rows = [
        {"Computer": "DESKTOP-01", "EventId": "4624", "count": "120"},
        {"Computer": "DESKTOP-02", "EventId": "4688", "count": "97"},
    ]
    session = happy_session(rows, scanCount="60000")
    client = make_client(session, local_config)

    assert client.run_search("index=logforge | stats count by Computer, EventId") == rows


def test_run_search_polls_until_done(local_config) -> None:
    session = FakeSession(
        {
            ("POST", JOBS): FakeResponse({"sid": SID}),
            ("GET", STATUS): [
                job_status(is_done=False),
                job_status(is_done=False),
                job_status(is_done=True),
            ],
            ("GET", RESULTS): results([{"count": "1"}]),
        }
    )
    client = make_client(session, local_config)

    assert client.run_search("index=logforge") == [{"count": "1"}]
    assert len(session.calls_to("GET", STATUS)) == 3


def test_splunk_reports_booleans_as_strings(local_config) -> None:
    """Older Splunk builds return isDone as "0"/"1" rather than a JSON bool."""
    session = FakeSession(
        {
            ("POST", JOBS): FakeResponse({"sid": SID}),
            ("GET", STATUS): [
                job_status(is_done="0", is_failed="0"),
                job_status(is_done="1", is_failed="0"),
            ],
            ("GET", RESULTS): results([{"count": "1"}]),
        }
    )
    client = make_client(session, local_config)
    assert client.run_search("index=logforge") == [{"count": "1"}]


def test_results_are_paged(local_config, monkeypatch) -> None:
    monkeypatch.setattr(sc, "RESULTS_PAGE_SIZE", 2)
    session = FakeSession(
        {
            ("POST", JOBS): FakeResponse({"sid": SID}),
            ("GET", STATUS): job_status(),
            ("GET", RESULTS): [
                results([{"n": "1"}, {"n": "2"}]),
                results([{"n": "3"}]),
            ],
        }
    )
    client = make_client(session, local_config)

    assert client.run_search("index=logforge") == [{"n": "1"}, {"n": "2"}, {"n": "3"}]
    offsets = [c["params"]["offset"] for c in session.calls_to("GET", RESULTS)]
    assert offsets == [0, 2]


# --------------------------------------------------------------------------
# Time range
# --------------------------------------------------------------------------


def test_default_time_range_is_all_time_not_relative(local_config) -> None:
    session = happy_session([{"count": "1"}])
    client = make_client(session, local_config)
    client.run_search("index=logforge")

    posted = session.calls_to("POST", JOBS)[0]["data"]
    assert posted["earliest_time"] == ALL_TIME_EARLIEST == "0"
    # Empty latest means "no upper bound", so the parameter is omitted entirely.
    assert ALL_TIME_LATEST == ""
    assert "latest_time" not in posted
    # Nothing resembling Splunk's relative default may sneak in.
    assert "-24h" not in str(posted)


def test_explicit_time_range_is_passed_through(local_config) -> None:
    session = happy_session([{"count": "1"}])
    client = make_client(session, local_config)
    client.run_search(
        "index=logforge",
        earliest="11/01/2024:00:00:00",
        latest="12/01/2024:00:00:00",
    )

    posted = session.calls_to("POST", JOBS)[0]["data"]
    assert posted["earliest_time"] == "11/01/2024:00:00:00"
    assert posted["latest_time"] == "12/01/2024:00:00:00"


# --------------------------------------------------------------------------
# Failure modes
# --------------------------------------------------------------------------


def test_401_gives_actionable_message_not_raw_exception(local_config) -> None:
    session = FakeSession({("POST", JOBS): FakeResponse(None, status_code=401, text="")})
    client = make_client(session, local_config)

    with pytest.raises(SplunkAuthError) as excinfo:
        client.run_search("index=logforge")

    message = str(excinfo.value)
    assert "401" in message
    assert "expired or invalid" in message
    assert "Settings > Tokens" in message
    assert "SPLUNK_TOKEN" in message
    # It is a legible domain error, not a bare requests/HTTP exception.
    assert isinstance(excinfo.value, SplunkError)
    assert not isinstance(excinfo.value, requests.exceptions.RequestException)


def test_401_during_polling_is_also_handled(local_config) -> None:
    session = FakeSession(
        {
            ("POST", JOBS): FakeResponse({"sid": SID}),
            ("GET", STATUS): FakeResponse(None, status_code=401, text=""),
        }
    )
    client = make_client(session, local_config)
    with pytest.raises(SplunkAuthError, match="Settings > Tokens"):
        client.run_search("index=logforge")


def test_403_explains_missing_capability(local_config) -> None:
    session = FakeSession({("POST", JOBS): FakeResponse(None, status_code=403, text="")})
    client = make_client(session, local_config)
    with pytest.raises(SplunkAuthError, match="403"):
        client.run_search("index=logforge")


def test_failed_job_surfaces_splunk_message(local_config) -> None:
    """A query the guardrails allow, that Splunk itself then rejects.

    The SPL has to be one the read-only allowlist passes, or the refusal would
    come from us and this would not be testing what it says it tests.
    """
    session = FakeSession(
        {
            ("POST", JOBS): FakeResponse({"sid": SID}),
            ("GET", STATUS): job_status(
                is_done=False,
                is_failed=True,
                messages=[
                    {"type": "FATAL", "text": "Error in 'stats' command: invalid argument."}
                ],
            ),
        }
    )
    client = make_client(session, local_config)
    with pytest.raises(SplunkSearchError) as excinfo:
        client.run_search("index=logforge | stats count by NoSuchField")
    assert "invalid argument" in str(excinfo.value)


def test_job_that_never_finishes_times_out(local_config) -> None:
    session = FakeSession(
        {
            ("POST", JOBS): FakeResponse({"sid": SID}),
            ("GET", STATUS): job_status(is_done=False),
        }
    )
    client = make_client(session, local_config, poll_timeout=0)
    with pytest.raises(SplunkSearchError, match="did not finish"):
        client.run_search("index=logforge")


def test_missing_sid_is_reported(local_config) -> None:
    session = FakeSession({("POST", JOBS): FakeResponse({"messages": ["nope"]})})
    client = make_client(session, local_config)
    with pytest.raises(SplunkSearchError, match="no job id"):
        client.run_search("index=logforge")


def test_http_500_is_reported_legibly(local_config) -> None:
    session = FakeSession(
        {("POST", JOBS): FakeResponse(None, status_code=500, text="internal error")}
    )
    client = make_client(session, local_config)
    with pytest.raises(SplunkSearchError, match="HTTP 500"):
        client.run_search("index=logforge")


def test_unreachable_endpoint_explains_the_management_port(local_config) -> None:
    session = FakeSession({}, raises=requests.exceptions.ConnectionError("refused"))
    client = make_client(session, local_config)
    with pytest.raises(SplunkConnectionError) as excinfo:
        client.run_search("index=logforge")
    assert "8089" in str(excinfo.value)


def test_tls_error_mentions_localhost_only_relaxation(remote_config) -> None:
    session = FakeSession({}, raises=requests.exceptions.SSLError("bad cert"))
    client = make_client(session, remote_config)
    with pytest.raises(SplunkConnectionError, match="localhost"):
        client.run_search("index=logforge")


def test_non_json_response_is_reported(local_config) -> None:
    session = FakeSession(
        {("POST", JOBS): FakeResponse(None, status_code=200, text="<html>oops</html>")}
    )
    client = make_client(session, local_config)
    with pytest.raises(SplunkSearchError, match="non-JSON"):
        client.run_search("index=logforge")


# --------------------------------------------------------------------------
# Transport wiring
# --------------------------------------------------------------------------


def test_bearer_token_is_sent(local_config) -> None:
    session = happy_session()
    make_client(session, local_config)
    assert session.headers["Authorization"] == "Bearer test-token"


def test_tls_relaxed_only_for_loopback_and_logged(local_config, caplog) -> None:
    session = happy_session()
    with caplog.at_level(logging.WARNING, logger="soc_copilot.splunk_client"):
        make_client(session, local_config)
    assert session.verify is False
    assert "RELAXED" in caplog.text
    assert "loopback" in caplog.text


def test_tls_verified_for_remote_host(remote_config, caplog) -> None:
    session = happy_session()
    with caplog.at_level(logging.WARNING, logger="soc_copilot.splunk_client"):
        make_client(session, remote_config)
    assert session.verify is True
    assert "RELAXED" not in caplog.text


def test_context_manager_closes_session(local_config) -> None:
    session = happy_session()
    with make_client(session, local_config):
        pass
    assert session.closed is True


def test_rest_entries_returns_entry_list(local_config) -> None:
    session = FakeSession(
        {
            ("GET", "/services/data/indexes"): FakeResponse(
                {"entry": [{"name": "logforge", "content": {"totalEventCount": "60000"}}]}
            )
        }
    )
    client = make_client(session, local_config)
    entries = client.rest_entries("/services/data/indexes")
    assert entries[0]["name"] == "logforge"
    assert session.calls[0]["params"]["output_mode"] == "json"
