"""A local web skin over the investigate loop. It changes how you talk to the
tool, not what the tool does.

This module adds no capability. It calls :func:`soc_copilot.agent.investigate`
with the same schema, the same library, the same backend and the same guardrails
the CLI uses, and renders what comes back with
:func:`soc_copilot.views.to_payload`. Every guarantee — read-only enforcement,
literal anchoring, the untrusted-data envelope, the alignment advisory — is made
before this module sees a result, and none of it can be relaxed from here.

Three things are load-bearing about the design.

**It is bound to the loopback interface and nowhere else.** This process holds a
Splunk token and can read evidence. Serving it on 0.0.0.0 would put an
unauthenticated query interface for that evidence on every network the machine is
attached to. The bind address is :data:`HOST` and there is no flag to change it —
if you want this reachable from elsewhere, that is a decision that deserves an
authenticating proxy and a conversation, not a command-line switch. Requests
whose ``Host`` header is not a loopback name are refused, which is what stops a
hostile page in the analyst's browser from reaching this server by DNS rebinding.

That check alone is not enough, because a hostile page does not have to rebind:
it can post straight at ``127.0.0.1``, and the ``Host`` header the browser then
sends is a loopback name and passes. What it cannot do is read the reply — but
an investigation it fires blind still runs searches and still spends the
machine's model time. So a request is also refused when it carries an ``Origin``
that is not this server, and when it does not declare ``application/json``.
The second condition is the load-bearing one: a JSON content type is not a CORS
"simple request", so the browser must ask permission with a preflight first, and
this server answers no preflight at all. Together they mean a cross-site page
cannot reach :meth:`Handler.do_POST` even to be ignored.

**The secrets stay on this side.** The browser sends a question string and
receives an answer plus the evidence behind it. It never receives the token, the
backend configuration, or the environment. It cannot ask for SPL to be run: the
only input is a question, and the loop decides what to search.

**It streams, because the honest wait is minutes.** A 14B local model spends
90-120 seconds per turn, and a two-hop investigation runs to several minutes.
A request/response page would look hung for the entire time, and a user who
cannot tell "working" from "broken" reasonably assumes broken. The loop already
exposes an ``on_step`` callback for exactly this, so each step is flushed to the
browser as it completes and the page shows what is happening while it happens.
"""

from __future__ import annotations

import json
import logging
import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final
from urllib.parse import urlparse

from soc_copilot.agent import MAX_STEPS, AgentError, Investigation, Step, investigate
from soc_copilot.generator import GenerationError
from soc_copilot.library import SplLibrary
from soc_copilot.llm.base import LLMBackend, LLMError
from soc_copilot.payload_shape import PayloadShape
from soc_copilot.schema import Schema
from soc_copilot.splunk_client import SplunkError
from soc_copilot.views import to_payload

log = logging.getLogger(__name__)

#: Loopback only. Deliberately not configurable — see the module docstring.
HOST: Final[str] = "127.0.0.1"
DEFAULT_PORT: Final[int] = 8765

#: Host header values a request may legitimately carry. Anything else is either
#: a misconfiguration or a browser being pointed here by a page that should not
#: be able to reach it.
_ALLOWED_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

#: Origins a request may legitimately come from: this page, and nothing else.
#: A request with no ``Origin`` at all is fine — that is curl, or the page's own
#: same-origin fetch on browsers that omit it. A request with a *foreign* one is
#: a cross-site page, and is refused.
_ALLOWED_ORIGIN_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

#: The only request body this server accepts. Enforced rather than assumed,
#: because it is what forces a cross-origin caller through a CORS preflight.
_REQUIRED_CONTENT_TYPE: Final[str] = "application/json"

#: A question longer than this is not a question.
MAX_QUESTION_CHARS: Final[int] = 2000

#: Hard cap on a request body, so a declared ``Content-Length`` cannot be used
#: to make this process allocate arbitrary memory. Generous next to
#: :data:`MAX_QUESTION_CHARS`, which is the limit that actually matters.
MAX_BODY_BYTES: Final[int] = 64 * 1024


class Engine:
    """Everything an investigation needs, discovered once and reused.

    Schema discovery and the payload probe cost several Splunk searches and tens
    of seconds. Doing that per question would add that delay to every message
    for no benefit — the index shape does not change between two questions typed
    a minute apart. The CLI pays it once per invocation; the server pays it once
    per process, at startup, before the port opens.
    """

    def __init__(
        self,
        client: Any,
        schema: Schema,
        library: SplLibrary,
        backend: LLMBackend,
        shape: PayloadShape | None = None,
        max_steps: int = MAX_STEPS,
    ) -> None:
        self.client = client
        self.schema = schema
        self.library = library
        self.backend = backend
        self.shape = shape
        self.max_steps = max_steps
        #: One investigation at a time. A local model saturates the machine, and
        #: two concurrent runs would make both slower and neither clearer.
        self._lock = threading.Lock()

    def describe(self) -> dict[str, Any]:
        """Non-secret facts about this session, safe to show in the page."""
        return {
            "index": self.schema.index,
            "fields": len(self.schema.fields),
            "nested": len(self.shape.nested_names) if self.shape else 0,
            "backend": self.backend.name,
            "model": self.backend.config.model,
            "local": self.backend.config.is_local,
            "max_steps": self.max_steps,
        }

    def ask(self, question: str, on_step: Callable[[Step], None]) -> Investigation:
        """Run one investigation. Identical call to the one the CLI makes."""
        with self._lock:
            return investigate(
                question,
                self.schema,
                self.library,
                client=self.client,
                backend=self.backend,
                shape=self.shape,
                max_steps=self.max_steps,
                on_step=on_step,
            )


# --------------------------------------------------------------------------
# Wire format
# --------------------------------------------------------------------------


def step_event(step: Step) -> dict[str, Any]:
    """One transcript step, as the page shows it while the loop is still going.

    Rows are deliberately not streamed. They can be tens of thousands, they are
    attacker-influenced, and the page has no use for them until the answer
    exists — at which point the anchored subset is what matters. Sending the
    count is enough to show progress honestly.
    """
    result = step.result
    return {
        "type": "step",
        "n": step.n,
        "action": step.action,
        "purpose": step.purpose,
        "note": step.note,
        "spl": result.spl if result else "",
        "earliest": result.time_range.earliest if result else "",
        "latest": result.time_range.latest if result else "",
        "executed": bool(result and result.executed),
        "rows": result.row_count if result else 0,
        "error": result.error if result else "",
        "hint": result.hint if result else "",
    }


def result_event(result: Investigation) -> dict[str, Any]:
    """The finished investigation, straight from the shared view payload.

    Built by :func:`soc_copilot.views.to_payload` rather than assembled here, so
    the browser sees exactly what the ``--view json`` CLI path sees. A second
    hand-rolled serialiser would be a second place for a guardrail to be dropped
    by accident.
    """
    payload = to_payload(result)
    return {"type": "result", "investigation": payload}


def error_event(message: str) -> dict[str, Any]:
    return {"type": "error", "message": message}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    """Two routes: the page, and the question stream."""

    server_version = "soc-copilot"
    sys_version = ""
    #: Set by :func:`serve`.
    engine: Engine | None = None

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("web: " + fmt, *args)

    # -- guards ----------------------------------------------------------

    def _host_is_local(self) -> bool:
        host = (self.headers.get("Host") or "").strip()
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        return name.lower() in _ALLOWED_HOSTS or host.lower() in _ALLOWED_HOSTS

    def _refuse_remote(self) -> bool:
        """Reject anything not addressed to loopback by name.

        The socket is already bound to 127.0.0.1, so a remote machine cannot
        connect. This closes the other door: a page in the analyst's own browser
        resolving an attacker-controlled name to 127.0.0.1 and posting questions
        to this server from a context that is not this page.
        """
        if self._host_is_local():
            return False
        self._send_json(403, {"error": "This server answers loopback requests only."})
        return True

    def _origin_is_local(self) -> bool:
        """True when ``Origin`` is absent or names this machine.

        Absent is allowed on purpose: a same-origin ``fetch`` need not send one,
        and neither does curl. Present-and-foreign is the case worth refusing.
        """
        origin = (self.headers.get("Origin") or "").strip()
        if not origin or origin.lower() == "null":
            return not origin
        parsed = urlparse(origin)
        if parsed.scheme.lower() not in _ALLOWED_ORIGIN_SCHEMES:
            return False
        return (parsed.hostname or "").lower() in _ALLOWED_HOSTS

    def _refuse_cross_site(self) -> bool:
        """Reject a POST that a page on another origin could have sent.

        Two conditions, and the content type is the one that does the work. A
        cross-origin ``fetch`` declaring ``application/json`` is not a CORS
        simple request, so the browser sends a preflight first; this server
        implements no ``OPTIONS`` handler and returns no ``Access-Control-*``
        header, so that preflight fails and the real request is never sent. What
        a page *can* send without asking is ``text/plain`` — which this refuses.
        """
        if not self._origin_is_local():
            self._send_json(403, {"error": "Cross-site requests are refused."})
            return True
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip()
        if content_type.lower() != _REQUIRED_CONTENT_TYPE:
            self._send_json(
                415, {"error": f"Content-Type must be {_REQUIRED_CONTENT_TYPE}."}
            )
            return True
        return False

    # -- plumbing --------------------------------------------------------

    def _send_json(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._send_hardening_headers()
        self.end_headers()
        self.wfile.write(raw)

    def _send_hardening_headers(self) -> None:
        # No external anything: the page is self-contained, so the policy that
        # describes it is also the policy that catches a mistake later.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; form-action 'none'; base-uri 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:
        if self._refuse_remote():
            return
        path = self.path.split("?", 1)[0]
        if path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_hardening_headers()
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/session":
            engine = type(self).engine
            self._send_json(200, engine.describe() if engine else {})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self._refuse_remote() or self._refuse_cross_site():
            return
        if self.path.split("?", 1)[0] != "/ask":
            self._send_json(404, {"error": "not found"})
            return

        engine = type(self).engine
        if engine is None:  # pragma: no cover - serve() always sets it
            self._send_json(503, {"error": "engine not ready"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(400, {"error": "Malformed Content-Length."})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "That request body is too large."})
            return

        try:
            payload = json.loads(self.rfile.read(max(length, 0)) or b"{}")
            question = str(payload.get("question", "")).strip()
        except (ValueError, TypeError, AttributeError):
            self._send_json(400, {"error": "expected JSON with a 'question' field"})
            return

        if not question:
            self._send_json(400, {"error": "The question is empty."})
            return
        if len(question) > MAX_QUESTION_CHARS:
            self._send_json(400, {"error": "That question is too long."})
            return

        self._stream_investigation(engine, question)

    # -- the stream ------------------------------------------------------

    def _stream_investigation(self, engine: Engine, question: str) -> None:
        """Newline-delimited JSON, flushed per event.

        Chosen over Server-Sent Events because the question arrives by POST and
        EventSource cannot POST. Chosen over one big response because the wait is
        minutes long and silence is indistinguishable from a hang.
        """
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self._send_hardening_headers()
        self.end_headers()

        def emit(event: dict[str, Any]) -> None:
            self.wfile.write((json.dumps(event) + "\n").encode("utf-8"))
            self.wfile.flush()

        log.info("web: investigating %r", question)
        try:
            emit({"type": "started", "question": question})
            result = engine.ask(question, on_step=lambda s: emit(step_event(s)))
            emit(result_event(result))
        except (AgentError, GenerationError, LLMError, SplunkError) as exc:
            # These carry analyst-facing text by design — the expired-token
            # message, the "no backend configured" message, the slow-local-model
            # message. Passing them through is the whole point of having written
            # them; replacing them with "something went wrong" would undo it.
            log.warning("web: investigation failed: %s", exc)
            emit(error_event(str(exc)))
        except BrokenPipeError:  # pragma: no cover - user closed the tab
            log.info("web: client disconnected mid-investigation")
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("web: unexpected failure")
            emit(error_event(f"Unexpected server error: {exc}"))


def serve(
    engine: Engine,
    port: int = DEFAULT_PORT,
    *,
    open_browser: bool = True,
) -> ThreadingHTTPServer:
    """Start the server on loopback and return it.

    Threading so a long investigation does not block the page from loading, and
    so a second tab gets a considered "one at a time" wait rather than a dead
    socket.
    """
    Handler.engine = engine
    httpd = ThreadingHTTPServer((HOST, port), Handler)
    httpd.daemon_threads = True

    url = f"http://{HOST}:{port}/"
    log.info("web: listening on %s (loopback only)", url)
    if open_browser:  # pragma: no cover - side effect
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    return httpd


# --------------------------------------------------------------------------
# The page — one file, no build step, no network
# --------------------------------------------------------------------------

PAGE: Final[str] = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Copilot</title>
<style>
  :root {
    --ink: #16181d; --muted: #6b7280; --line: #e6e8ec;
    --bg: #ffffff; --panel: #fafbfc; --accent: #1f6feb; --warn: #b45309;
    --bad: #b42318; --ok: #027a48;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    background: var(--bg); color: var(--ink); display: flex; flex-direction: column;
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
          Helvetica, Arial, sans-serif;
  }
  header {
    border-bottom: 1px solid var(--line); padding: 14px 22px;
    display: flex; align-items: baseline; gap: 12px; flex: 0 0 auto;
  }
  header h1 { font-size: 15px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
  header .meta { font-size: 12px; color: var(--muted); }
  main { flex: 1 1 auto; overflow-y: auto; }
  .thread { max-width: 780px; margin: 0 auto; padding: 26px 22px 8px; }
  .msg { margin-bottom: 26px; }
  .msg.user .bubble {
    background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
    padding: 10px 14px; display: inline-block; max-width: 100%;
    white-space: pre-wrap; word-break: break-word;
  }
  .msg.user { text-align: right; }
  .who { font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
         color: var(--muted); margin-bottom: 6px; }
  .answer { white-space: pre-wrap; word-break: break-word; }
  .answer.none { color: var(--muted); }
  .steps { margin: 2px 0 12px; }
  .step { display: flex; gap: 9px; align-items: baseline; color: var(--muted);
          font-size: 13px; padding: 3px 0; }
  .step .dot { width: 6px; height: 6px; border-radius: 50%; background: #cbd5e1;
               flex: 0 0 auto; transform: translateY(-1px); }
  .step.done .dot { background: var(--ok); }
  .step.refused .dot { background: var(--warn); }
  .thinking { display: flex; align-items: center; gap: 9px; color: var(--muted);
              font-size: 13px; padding: 4px 0; }
  .pulse { width: 7px; height: 7px; border-radius: 50%; background: var(--accent);
           animation: pulse 1.15s ease-in-out infinite; }
  @keyframes pulse { 0%,100% { opacity: .25; } 50% { opacity: 1; } }
  .flag { border-left: 3px solid var(--warn); background: #fffbeb; padding: 9px 12px;
          margin: 12px 0; font-size: 13px; border-radius: 0 6px 6px 0; }
  .flag.bad { border-left-color: var(--bad); background: #fef3f2; }
  .flag b { font-weight: 600; }
  details { margin-top: 12px; border-top: 1px solid var(--line); padding-top: 10px; }
  summary { cursor: pointer; font-size: 12.5px; color: var(--muted);
            list-style: none; user-select: none; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: "▸ "; }
  details[open] summary::before { content: "▾ "; }
  summary:hover { color: var(--ink); }
  .ev { margin: 14px 0 4px; }
  .ev h4 { font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
           color: var(--muted); margin: 0 0 6px; font-weight: 600; }
  pre.spl { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
            padding: 10px 12px; overflow-x: auto; font-size: 12.5px; margin: 0 0 6px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .range { font-size: 12px; color: var(--muted); margin-bottom: 12px; }
  table.rows { border-collapse: collapse; width: 100%; font-size: 12.5px;
               font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  table.rows th { text-align: left; font-weight: 600; color: var(--muted);
                  border-bottom: 1px solid var(--line); padding: 5px 9px 5px 0;
                  font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
  table.rows td { padding: 4px 9px 4px 0; border-bottom: 1px solid #f2f4f7;
                  vertical-align: top; word-break: break-all; }
  .scroll { overflow-x: auto; }
  .guards { font-size: 12.5px; color: var(--muted); }
  .guards div { padding: 2px 0; }
  footer { flex: 0 0 auto; border-top: 1px solid var(--line); background: var(--bg); }
  .composer { max-width: 780px; margin: 0 auto; padding: 14px 22px 18px;
              display: flex; gap: 10px; align-items: flex-end; }
  textarea {
    flex: 1 1 auto; resize: none; font: inherit; color: inherit; padding: 10px 13px;
    border: 1px solid var(--line); border-radius: 10px; background: var(--bg);
    max-height: 160px; min-height: 42px;
  }
  textarea:focus { outline: none; border-color: #c3c8d0; }
  textarea:disabled { background: var(--panel); color: var(--muted); }
  button {
    font: inherit; font-weight: 500; padding: 10px 17px; border-radius: 10px;
    border: 1px solid var(--ink); background: var(--ink); color: #fff; cursor: pointer;
    flex: 0 0 auto;
  }
  button:disabled { background: var(--line); border-color: var(--line);
                    color: var(--muted); cursor: default; }
  .hint { max-width: 780px; margin: 0 auto; padding: 0 22px 12px;
          font-size: 11.5px; color: var(--muted); }
</style>
</head>
<body>
<header>
  <h1>SOC Copilot</h1>
  <span class="meta" id="meta">connecting…</span>
</header>

<main id="main"><div class="thread" id="thread"></div></main>

<footer>
  <div class="composer">
    <textarea id="q" rows="1" placeholder="Ask a question about the indexed data…"
              autocomplete="off" spellcheck="false"></textarea>
    <button id="send">Ask</button>
  </div>
  <div class="hint" id="hint">
    Runs locally on 127.0.0.1. Searches are read-only; every value in an answer is
    checked against the rows Splunk returned.
  </div>
</footer>

<script>
(function () {
  "use strict";
  var thread = document.getElementById("thread");
  var main = document.getElementById("main");
  var box = document.getElementById("q");
  var send = document.getElementById("send");
  var busy = false;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function atBottom() {
    return main.scrollHeight - main.scrollTop - main.clientHeight < 120;
  }
  function scroll(force) {
    if (force || atBottom()) main.scrollTop = main.scrollHeight;
  }

  fetch("/session").then(function (r) { return r.json(); }).then(function (s) {
    if (!s || !s.index) return;
    document.getElementById("meta").textContent =
      "index=" + s.index + " · " + s.backend + " " + s.model +
      (s.local ? " · local, nothing leaves this machine" : " · hosted backend");
  }).catch(function () {
    document.getElementById("meta").textContent = "";
  });

  function describeStep(s) {
    if (s.action === "search" && s.executed) {
      return "Step " + s.n + ": searched — " + s.rows.toLocaleString() + " row" +
             (s.rows === 1 ? "" : "s") + (s.purpose ? " · " + s.purpose : "");
    }
    if (s.action === "search") return "Step " + s.n + ": query refused before it ran";
    if (s.action === "refused") return "Step " + s.n + ": not run";
    if (s.action === "answer") return "Step " + s.n + ": writing the answer";
    if (s.action === "unanswerable") return "Step " + s.n + ": reporting it cannot be answered";
    if (s.action === "malformed") return "Step " + s.n + ": unusable reply, retrying";
    return "Step " + s.n + ": " + s.action;
  }

  function stepClass(s) {
    if (s.action === "search" && s.executed) return "step done";
    if (s.action === "search" || s.action === "refused") return "step refused";
    return "step";
  }

  function evidence(inv) {
    var d = el("details");
    var n = (inv.searches || []).length;
    d.appendChild(el("summary", null,
      "Show query & evidence" + (n ? " (" + n + " search" + (n === 1 ? "" : "es") + ")" : "")));

    (inv.searches || []).forEach(function (s) {
      var w = el("div", "ev");
      w.appendChild(el("h4", null, "Step " + s.step + " · " +
        s.row_count.toLocaleString() + " row" + (s.row_count === 1 ? "" : "s")));
      w.appendChild(el("pre", "spl", s.spl));
      w.appendChild(el("div", "range",
        "earliest=" + JSON.stringify(s.earliest) + "  latest=" + JSON.stringify(s.latest)));
      d.appendChild(w);
    });

    var rows = inv.anchored_rows || [];
    if (rows.length) {
      var w2 = el("div", "ev");
      w2.appendChild(el("h4", null, "Anchored rows — where the answer's values came from"));
      var cols = [];
      rows.forEach(function (r) {
        Object.keys(r.fields).forEach(function (k) {
          if (cols.indexOf(k) === -1) cols.push(k);
        });
      });
      var wrap = el("div", "scroll");
      var t = el("table", "rows");
      var tr = el("tr");
      tr.appendChild(el("th", null, "source"));
      cols.forEach(function (c) { tr.appendChild(el("th", null, c)); });
      t.appendChild(tr);
      rows.forEach(function (r) {
        var row = el("tr");
        row.appendChild(el("td", null, r.source + " · row " + r.row));
        cols.forEach(function (c) { row.appendChild(el("td", null, r.fields[c] || "")); });
        t.appendChild(row);
      });
      wrap.appendChild(t);
      w2.appendChild(wrap);
      d.appendChild(w2);
    }

    var g = inv.guardrails || {};
    var gd = el("div", "ev");
    gd.appendChild(el("h4", null, "Guardrails"));
    var list = el("div", "guards");
    var anchoring = (g.anchoring || {});
    list.appendChild(el("div", null, "read-only: enforced before dispatch" +
      ((g.read_only && g.read_only.refused && g.read_only.refused.length)
        ? " · " + g.read_only.refused.length + " quer" +
          (g.read_only.refused.length === 1 ? "y" : "ies") + " refused" : "")));
    list.appendChild(el("div", null, "literal anchoring: " +
      (anchoring.no_literals ? "no checkable literal in the answer"
        : (anchoring.ok
           ? (anchoring.literals || []).length +
             " literal(s), all traced to returned rows"
           : (anchoring.unverified || []).length + " literal(s) traced to NO returned row"))));
    list.appendChild(el("div", null, "untrusted input: field values sealed" +
      (((g.untrusted_input || {}).signals || []).length
        ? " · " + g.untrusted_input.signals.length + " injection signal(s)" : "")));
    list.appendChild(el("div", null, "backend: " + (inv.backend || {}).name +
      " (" + (inv.backend || {}).model + ")"));
    list.appendChild(el("div", null, "stop reason: " + inv.stop_reason));
    gd.appendChild(list);
    d.appendChild(gd);
    return d;
  }

  function renderResult(node, inv) {
    node.innerHTML = "";
    var ans = inv.answer || {};
    var text = ans.text || "";
    if (text) {
      node.appendChild(el("div", "answer", text));
    } else {
      var none = el("div", "answer none",
        ans.unsupported_reason || "No answer was produced.");
      node.appendChild(none);
    }

    if (ans.fully_anchored === false) {
      var f = el("div", "flag bad");
      f.appendChild(el("b", null, "Unsupported values. "));
      f.appendChild(document.createTextNode(
        "Marked [UNVERIFIED] above: they appear in no row Splunk returned this " +
        "session. Treat them as unsupported."));
      node.appendChild(f);
    }

    var al = (inv.guardrails || {}).alignment || {};
    if (al.ok === false && (al.misaligned || []).length) {
      var w = el("div", "flag");
      w.appendChild(el("b", null, "May not answer what was asked. "));
      w.appendChild(document.createTextNode(al.misaligned[0].warning || ""));
      node.appendChild(w);
    }

    var sig = ((inv.guardrails || {}).untrusted_input || {}).signals || [];
    if (sig.length) {
      var s = el("div", "flag");
      s.appendChild(el("b", null, "Instruction-shaped text in the data. "));
      s.appendChild(document.createTextNode(
        sig.length + " field value(s) contain text aimed at an automated reader. " +
        "They were passed as sealed data and changed nothing here."));
      node.appendChild(s);
    }

    node.appendChild(evidence(inv));
    scroll(false);
  }

  function ask(question) {
    if (busy || !question) return;
    busy = true;
    send.disabled = true;
    box.disabled = true;

    var um = el("div", "msg user");
    um.appendChild(el("div", "bubble", question));
    thread.appendChild(um);

    var am = el("div", "msg assistant");
    am.appendChild(el("div", "who", "SOC Copilot"));
    var steps = el("div", "steps");
    var body = el("div");
    var think = el("div", "thinking");
    think.appendChild(el("span", "pulse"));
    var label = el("span", null, "thinking…");
    think.appendChild(label);
    am.appendChild(steps);
    am.appendChild(think);
    am.appendChild(body);
    thread.appendChild(am);
    scroll(true);

    var t0 = Date.now();
    var tick = setInterval(function () {
      var s = Math.round((Date.now() - t0) / 1000);
      label.textContent = "thinking… " + (s < 60 ? s + "s"
        : Math.floor(s / 60) + "m " + (s % 60) + "s");
    }, 1000);

    function finish() {
      clearInterval(tick);
      think.remove();
      busy = false;
      send.disabled = false;
      box.disabled = false;
      box.focus();
    }

    fetch("/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: question })
    }).then(function (r) {
      if (!r.ok) {
        return r.json().then(function (e) { throw new Error(e.error || "request failed"); });
      }
      var reader = r.body.getReader();
      var dec = new TextDecoder();
      var buf = "";
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) { finish(); return; }
          buf += dec.decode(chunk.value, { stream: true });
          var lines = buf.split("\\n");
          buf = lines.pop();
          lines.forEach(function (line) {
            if (!line.trim()) return;
            var ev;
            try { ev = JSON.parse(line); } catch (e) { return; }
            if (ev.type === "step") {
              var s = el("div", stepClass(ev), describeStep(ev));
              s.insertBefore(el("span", "dot"), s.firstChild);
              steps.appendChild(s);
              scroll(false);
            } else if (ev.type === "result") {
              renderResult(body, ev.investigation);
            } else if (ev.type === "error") {
              var e2 = el("div", "flag bad");
              e2.appendChild(el("b", null, "Could not complete. "));
              e2.appendChild(el("div", "answer", ev.message));
              body.appendChild(e2);
              scroll(false);
            }
          });
          return pump();
        });
      }
      return pump();
    }).catch(function (err) {
      var e = el("div", "flag bad");
      e.appendChild(el("b", null, "Could not complete. "));
      e.appendChild(document.createTextNode(String(err.message || err)));
      body.appendChild(e);
      finish();
      scroll(false);
    });
  }

  function submit() {
    var q = box.value.trim();
    if (!q) return;
    box.value = "";
    box.style.height = "auto";
    ask(q);
  }

  send.addEventListener("click", submit);
  box.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
  });
  box.addEventListener("input", function () {
    box.style.height = "auto";
    box.style.height = Math.min(box.scrollHeight, 160) + "px";
  });
  box.focus();
})();
</script>
</body>
</html>
"""
