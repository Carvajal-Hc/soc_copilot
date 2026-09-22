"""The web skin: it must change how you talk to the tool, not what the tool does.

Two kinds of test here, and the first kind matters more.

**Containment.** This process holds a Splunk token and can read evidence, so the
tests pin the properties that keep it on this machine: the bind address is
loopback and there is no way to change it, a request not addressed to loopback is
refused, and no response ever carries the token or the environment. A regression
in any of those is a disclosure, not a bug.

**Equivalence.** The web path must produce the same guardrail outcomes as the CLI
path for the same investigation. The point of the skin is that it is a skin.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from soc_copilot.agent import investigate
from soc_copilot.views import to_payload
from soc_copilot.web import (
    HOST,
    Engine,
    Handler,
    error_event,
    result_event,
    serve,
    step_event,
)
from tests.conftest import ScriptedBackend, ScriptedClient

TOKEN = "super-secret-splunk-token-value-0123456789"

GUID = "{a1b2c3d4-1111-2222-3333-444455556666}"
CMD = "C:\\Windows\\System32\\cmd.exe"


def _extract(name: str) -> str:
    return (
        f"| eval {name} = mvindex('EventData.Data{{}}.#text', "
        f"mvfind('EventData.Data{{}}.@Name', \"^{name}$\"))"
    )


FIND_SPL = (
    "index=logforge EventId=1 | spath input=Payload "
    + _extract("ProcessGuid")
    + " "
    + _extract("Image")
    + " | table ProcessGuid, Image"
)


@pytest.fixture
def engine(schema, shape, library):
    backend = ScriptedBackend(
        {"action": "search", "purpose": "find it", "spl": FIND_SPL,
         "earliest": "0", "latest": ""},
        {"action": "answer", "answer": f"The process was {GUID} running {CMD}.",
         "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID, "Image": CMD}])
    return Engine(client, schema, library, backend, shape)


@pytest.fixture
def server(engine):
    """A real server on an ephemeral loopback port."""
    httpd = serve(engine, port=0, open_browser=False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def _url(httpd, path: str) -> str:
    return f"http://{HOST}:{httpd.server_address[1]}{path}"


def _post(
    httpd,
    path: str,
    body: dict,
    host_header: str | None = None,
    origin: str | None = None,
    content_type: str = "application/json",
):
    request = urllib.request.Request(
        _url(httpd, path),
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": content_type},
        method="POST",
    )
    if host_header:
        request.add_header("Host", host_header)
    if origin:
        request.add_header("Origin", origin)
    return urllib.request.urlopen(request, timeout=30)


# --------------------------------------------------------------------------
# Containment
# --------------------------------------------------------------------------


def test_the_server_binds_to_loopback_and_nothing_else(server) -> None:
    """0.0.0.0 would put an unauthenticated evidence interface on every network
    the machine is attached to."""
    assert server.server_address[0] == "127.0.0.1"
    assert HOST == "127.0.0.1"


def test_there_is_no_flag_to_change_the_bind_address() -> None:
    """Making this configurable is how it ends up misconfigured.

    A port is a convenience; a host is a security boundary, and this one is not
    negotiable from the command line.
    """
    from soc_copilot.cli import build_parser

    help_text = build_parser().format_help()
    parser = build_parser()

    assert "--host" not in help_text
    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--host", "0.0.0.0"])


def test_a_post_from_another_origin_is_refused(server) -> None:
    """The Host check does not cover this case.

    A hostile page does not have to rebind DNS: it can post straight at
    127.0.0.1, and the Host header the browser sends is then a loopback name
    that passes every check above. What gives it away is the Origin.
    """
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(server, "/ask", {"question": "hello"}, origin="https://evil.example.com")
    assert excinfo.value.code == 403


def test_a_post_that_could_skip_the_cors_preflight_is_refused(server) -> None:
    """The content type is the guard that actually holds.

    ``application/json`` is not a CORS "simple request", so a cross-origin page
    must win a preflight before the browser will send it — and this server
    answers no preflight. ``text/plain`` needs no permission, which is exactly
    why a body arriving under it is refused however loopback it looks.
    """
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(server, "/ask", {"question": "hello"}, content_type="text/plain")
    assert excinfo.value.code == 415


def test_a_preflight_is_not_answered(server) -> None:
    """No OPTIONS handler and no Access-Control-* header: nothing to grant."""
    request = urllib.request.Request(_url(server, "/ask"), method="OPTIONS")
    request.add_header("Origin", "https://evil.example.com")
    request.add_header("Access-Control-Request-Method", "POST")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=30)
    assert excinfo.value.code in (400, 405, 501)
    assert not any(h.lower().startswith("access-control-") for h in excinfo.value.headers)


def test_the_page_own_request_shape_is_accepted(server) -> None:
    """The guards must not break the one caller that is supposed to work.

    The page fetches same-origin with a JSON content type; browsers send an
    Origin on that too. If this ever fails, the UI is dead.
    """
    port = server.server_address[1]
    response = _post(
        server,
        "/ask",
        {"question": "what ran?"},
        origin=f"http://127.0.0.1:{port}",
    )
    assert response.status == 200


def test_an_oversized_body_is_refused_before_it_is_read(server) -> None:
    """A declared Content-Length must not be able to size an allocation."""
    from soc_copilot.web import MAX_BODY_BYTES

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(server, "/ask", {"question": "x" * (MAX_BODY_BYTES + 1)})
    assert excinfo.value.code == 413


def test_a_request_not_addressed_to_loopback_is_refused(server) -> None:
    """DNS rebinding: the socket is unreachable remotely, but a hostile page in
    the analyst's own browser can still resolve its own name to 127.0.0.1."""
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(server, "/ask", {"question": "hello"}, host_header="evil.example.com")

    assert excinfo.value.code == 403


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "127.0.0.1:1234"])
def test_loopback_host_headers_are_accepted(server, host) -> None:
    """The guard must not be so strict it refuses the real page."""
    handler = Handler.__new__(Handler)
    handler.headers = {"Host": host}

    assert handler._host_is_local()


def test_no_response_carries_the_token_or_the_environment(server, engine, monkeypatch) -> None:
    """The browser sends a question and receives an answer. Nothing else."""
    monkeypatch.setenv("SPLUNK_TOKEN", TOKEN)

    page = urllib.request.urlopen(_url(server, "/"), timeout=10).read().decode()
    session = urllib.request.urlopen(_url(server, "/session"), timeout=10).read().decode()
    stream = _post(server, "/ask", {"question": "what ran"}).read().decode()

    for body in (page, session, stream):
        assert TOKEN not in body
        assert "SPLUNK_TOKEN" not in body


def test_the_session_endpoint_exposes_no_secrets(server) -> None:
    body = json.loads(urllib.request.urlopen(_url(server, "/session"), timeout=10).read())

    assert set(body) == {
        "index", "fields", "nested", "backend", "model", "local", "max_steps"
    }
    assert "token" not in json.dumps(body).lower()
    assert "api_key" not in json.dumps(body).lower()


def test_the_browser_cannot_ask_for_arbitrary_spl_to_be_run(server) -> None:
    """The only input is a question. There is no endpoint that takes SPL."""
    for path in ("/search", "/spl", "/run", "/query"):
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _post(server, path, {"spl": "index=logforge | delete"})
        assert excinfo.value.code == 404


def test_the_page_is_self_contained(server) -> None:
    """No CDN, no external font, no analytics — it has to work air-gapped."""
    page = urllib.request.urlopen(_url(server, "/"), timeout=10).read().decode()

    for marker in ("http://", "https://", "//cdn", "integrity=", "crossorigin"):
        assert marker not in page.replace("http://127.0.0.1", ""), marker
    assert "localStorage" not in page
    assert "sessionStorage" not in page
    assert "indexedDB" not in page


def test_an_empty_question_is_rejected_without_running_anything(server, engine) -> None:
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(server, "/ask", {"question": "   "})

    assert excinfo.value.code == 400
    assert engine.client.calls == []


def test_an_absurdly_long_question_is_rejected(server) -> None:
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(server, "/ask", {"question": "x" * 5000})

    assert excinfo.value.code == 400


# --------------------------------------------------------------------------
# Equivalence — the skin does not change the engine
# --------------------------------------------------------------------------


def test_the_stream_ends_with_the_same_payload_the_cli_view_produces(
    server, schema, shape, library
) -> None:
    """One serialiser, one set of guardrail outcomes, two front ends."""
    raw = _post(server, "/ask", {"question": "what ran"}).read().decode()
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    web_result = next(e for e in events if e["type"] == "result")["investigation"]

    backend = ScriptedBackend(
        {"action": "search", "purpose": "find it", "spl": FIND_SPL,
         "earliest": "0", "latest": ""},
        {"action": "answer", "answer": f"The process was {GUID} running {CMD}.",
         "evidence": "step 1"},
    )
    cli_result = to_payload(
        investigate(
            "what ran", schema, library,
            client=ScriptedClient([{"ProcessGuid": GUID, "Image": CMD}]),
            backend=backend, shape=shape,
        )
    )

    assert web_result["answer"] == cli_result["answer"]
    assert web_result["guardrails"] == cli_result["guardrails"]
    assert web_result["anchored_rows"] == cli_result["anchored_rows"]


def test_steps_stream_before_the_result(server) -> None:
    """The whole reason for streaming: minutes of silence reads as a hang."""
    raw = _post(server, "/ask", {"question": "what ran"}).read().decode()
    kinds = [json.loads(line)["type"] for line in raw.splitlines() if line.strip()]

    assert kinds[0] == "started"
    assert "step" in kinds
    assert kinds.index("step") < kinds.index("result")
    assert kinds[-1] == "result"


def test_the_guardrails_still_fire_through_the_web_path(
    server, schema, shape, library
) -> None:
    """A mutating query refused, and a fabricated literal marked, over HTTP."""
    backend = ScriptedBackend(
        {"action": "search", "spl": "index=logforge | delete"},
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "It dropped C:\\evil\\backdoor.exe.",
         "evidence": "step 2"},
    )
    engine = Engine(
        ScriptedClient([{"ProcessGuid": GUID}]), schema, library, backend, shape
    )
    httpd = serve(engine, port=0, open_browser=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        raw = _post(httpd, "/ask", {"question": "what was dropped"}).read().decode()
    finally:
        httpd.shutdown()
        httpd.server_close()

    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    inv = next(e for e in events if e["type"] == "result")["investigation"]

    refused = inv["guardrails"]["read_only"]["refused"]
    assert len(refused) == 1 and "delete" in refused[0]["reason"]
    assert inv["answer"]["fully_anchored"] is False
    assert "[UNVERIFIED: C:\\evil\\backdoor.exe]" in inv["answer"]["text"]


def test_a_backend_failure_reaches_the_page_as_its_own_message(
    server, schema, shape, library
) -> None:
    """The actionable messages were written to be read. Do not swallow them."""
    from soc_copilot.splunk_client import AUTH_FAILURE_MESSAGE, SplunkAuthError

    class Failing:
        def run_search(self, spl, earliest="0", latest=""):
            raise SplunkAuthError(AUTH_FAILURE_MESSAGE)

    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "unanswerable", "reason": "the token was rejected"},
        {"action": "unanswerable", "reason": "the token was rejected"},
    )
    engine = Engine(Failing(), schema, library, backend, shape)
    httpd = serve(engine, port=0, open_browser=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        raw = _post(httpd, "/ask", {"question": "q"}).read().decode()
    finally:
        httpd.shutdown()
        httpd.server_close()

    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    # The 401 becomes a step observation, exactly as it does in the CLI loop.
    assert any(
        "Settings > Tokens" in json.dumps(e) for e in events
    ), "the actionable auth message did not reach the browser"


# --------------------------------------------------------------------------
# Wire format
# --------------------------------------------------------------------------


def test_step_events_carry_progress_but_not_rows(schema, shape) -> None:
    """Rows can be tens of thousands and are attacker-influenced. The count is
    what shows progress; the anchored subset is what the answer needs."""
    from soc_copilot.agent import SearchTool, Step

    rows = [{"Computer": "DESKTOP-01"} for _ in range(3)]
    tool = SearchTool(ScriptedClient(rows), schema, shape, question="q")
    result = tool.call("index=logforge | table Computer")
    event = step_event(Step(n=1, action="search", purpose="look", result=result))

    assert event["rows"] == 3
    assert not isinstance(event["rows"], list)
    assert "DESKTOP-01" not in json.dumps(event)


def test_error_events_are_plain_text_for_the_page() -> None:
    assert error_event("token expired") == {"type": "error", "message": "token expired"}


def test_result_events_wrap_the_shared_payload(schema, shape, library) -> None:
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "done", "evidence": "step 1"},
    )
    result = investigate(
        "q", schema, library, client=ScriptedClient([{"ProcessGuid": GUID}]),
        backend=backend, shape=shape,
    )

    event = result_event(result)

    assert event["type"] == "result"
    assert event["investigation"] == to_payload(result)
