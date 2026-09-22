"""Command line entry point for SOC Copilot.

Stage 1 — deterministic Splunk layer, no LLM anywhere:

    python -m soc_copilot verify           # end-to-end proof against live Splunk
    python -m soc_copilot schema           # indexes, sourcetypes, full field list
    python -m soc_copilot shape            # discovered nested payload structure
    python -m soc_copilot search "<spl>"   # run one read-only search

Stage 2 — natural language to SPL:

    python -m soc_copilot generate "question" ["question" ...]
    python -m soc_copilot generate --dry-run "question"    # prompt only, no LLM

``generate`` never executes the SPL it produces. It prints the query and the
chosen time range for review.

Stage 3 — the tool-using loop (question -> SPL -> rows -> answer or pivot):

    python -m soc_copilot investigate "question" ["question" ...]
    python -m soc_copilot investigate --max-steps 8 "question"

``investigate`` DOES run searches, read-only, and prints every one of them with
its time range as it goes. The answer is printed last, followed by a
deterministic check that each literal in it came from a row Splunk returned.

Stage 4 — the guardrails, and three renderings of the same result:

    python -m soc_copilot investigate --view human "question"   # default
    python -m soc_copilot investigate --view spl   "question"   # just the query
    python -m soc_copilot investigate --view json  "question"   # stable schema

The view chooses only how the answer is said. What the answer is allowed to say
is settled before any of them runs, by :mod:`soc_copilot.guardrails`.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable, Sequence
from typing import Any, Final

from soc_copilot.agent import (
    MAX_STEPS,
    AgentError,
    Investigation,
    Step,
    investigate,
)
from soc_copilot.config import ConfigError, SplunkConfig, load_config
from soc_copilot.generator import GeneratedSPL, GenerationError, generate_spl
from soc_copilot.library import LibraryError, SplLibrary, load_library
from soc_copilot.llm.base import LLMError, build_backend
from soc_copilot.payload_shape import PayloadShape, probe_payload_shape
from soc_copilot.schema import (
    DEFAULT_INDEX,
    Schema,
    SchemaError,
    discover_schema,
)
from soc_copilot.splunk_client import (
    ALL_TIME_EARLIEST,
    ALL_TIME_LATEST,
    SplunkClient,
    SplunkError,
)
from soc_copilot.views import VIEW_HUMAN, VIEW_JSON, VIEWS, render, to_payload
from soc_copilot.web import DEFAULT_PORT, HOST, Engine, serve

#: The known-good query used to prove the layer works end to end.
VERIFY_SPL = "index={index} | stats count by Computer, EventId"


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _rule(title: str = "", width: int = 78) -> str:
    if not title:
        return "-" * width
    return f"-- {title} " + "-" * max(0, width - len(title) - 4)


def _cell(value: Any, limit: int = 48) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", " ").replace("\t", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_table(
    rows: Sequence[dict[str, Any]],
    columns: Sequence[str] | None = None,
    *,
    limit: int | None = None,
) -> str:
    """Render result rows as a fixed-width table. Values are shown verbatim."""
    if not rows:
        return "(no rows)"

    if columns is None:
        seen: dict[str, None] = {}
        for row in rows:
            for key in row:
                seen.setdefault(key, None)
        columns = list(seen)

    shown = rows[:limit] if limit is not None else rows
    body = [[_cell(row.get(col, "")) for col in columns] for row in shown]
    widths = [
        max(len(col), *(len(r[i]) for r in body)) if body else len(col)
        for i, col in enumerate(columns)
    ]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    out = [line(columns), "  ".join("-" * w for w in widths)]
    out.extend(line(cells) for cells in body)
    if limit is not None and len(rows) > limit:
        out.append(f"... {len(rows) - limit} more row(s) not shown")
    return "\n".join(out)


def print_schema(schema: Schema) -> None:
    """Print discovered indexes, sourcetypes and the full field list."""
    print()
    print(_rule("INDEXES"))
    print(
        render_table(
            [
                {
                    "index": i.name,
                    "events": f"{i.event_count:,}",
                    "earliest": i.earliest,
                    "latest": i.latest,
                    "disabled": "yes" if i.disabled else "no",
                }
                for i in schema.indexes
            ]
        )
    )

    print()
    print(_rule(f"SOURCETYPES in index={schema.index}"))
    print(
        render_table(
            [
                {
                    "sourcetype": s.name,
                    "events": f"{s.event_count:,}",
                    "earliest": s.earliest,
                    "latest": s.latest,
                }
                for s in schema.sourcetypes
            ]
        )
    )

    print()
    print(_rule(f"FIELDS in index={schema.index} ({len(schema.fields)} total)"))
    print(
        render_table(
            [
                {
                    "field": f.name,
                    # A field can be known to exist without fieldsummary having
                    # measured it; report that as unknown, not as zero.
                    "events": f"{f.event_count:,}" if f.counts_known else "?",
                    "distinct": (
                        f"{f.distinct_count:,}" + ("" if f.is_exact else "~")
                        if f.counts_known
                        else "?"
                    ),
                }
                for f in schema.fields
            ]
        )
    )
    print()
    print("Field names (authoritative — generate SPL against exactly these):")
    print("  " + ", ".join(schema.field_names))


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_verify(client: SplunkClient, args: argparse.Namespace) -> int:
    """Prove the deterministic layer works: real rows, then the real schema."""
    spl = VERIFY_SPL.format(index=args.index)

    print(_rule("VERIFICATION SEARCH"))
    print(f"SPL      : {spl}")
    print(f"earliest : {args.earliest!r}  (epoch 0 = no lower bound)")
    print(f"latest   : {args.latest!r}  (empty = no upper bound)")
    print("Time range is explicit and all-time; the lab data is from ~Nov 2024.")
    print()

    rows = client.run_search(spl, earliest=args.earliest, latest=args.latest)
    if not rows:
        print(
            f"No rows returned for index={args.index}. Nothing was fabricated: this "
            "means the index is empty or the token cannot read it.",
            file=sys.stderr,
        )
        return 1

    print(render_table(rows, ["Computer", "EventId", "count"], limit=args.limit))
    print()

    total_events = sum(_to_int(r.get("count")) for r in rows)
    computers = sorted({str(r.get("Computer", "")) for r in rows if r.get("Computer")})
    event_ids = {str(r.get("EventId", "")) for r in rows if r.get("EventId")}

    print(_rule("TOTALS (summed from the rows above — not from any prior knowledge)"))
    print(f"Computer x EventId combinations : {len(rows):,}")
    print(f"Total events                    : {total_events:,}")
    print(f"Distinct hosts ({len(computers)})              : {', '.join(computers)}")
    print(f"Distinct EventIds               : {len(event_ids):,}")

    schema = discover_schema(
        client,
        args.index,
        include_internal_indexes=args.include_internal,
        earliest=args.earliest,
        latest=args.latest,
    )
    print_schema(schema)

    print()
    print(_rule("RESULT"))
    print("Stage 1 verified: config, authenticated REST client, blocking search and")
    print("schema discovery all work against the live instance. No LLM was involved.")
    return 0


def cmd_schema(client: SplunkClient, args: argparse.Namespace) -> int:
    schema = discover_schema(
        client,
        args.index,
        include_internal_indexes=args.include_internal,
        sample_size=args.sample_size,
        earliest=args.earliest,
        latest=args.latest,
    )
    print_schema(schema)
    return 0


def cmd_search(client: SplunkClient, args: argparse.Namespace) -> int:
    rows = client.run_search(args.spl, earliest=args.earliest, latest=args.latest)
    print(render_table(rows, limit=args.limit))
    print()
    print(f"{len(rows):,} row(s).")
    return 0 if rows else 1


# --------------------------------------------------------------------------
# Stage 2
# --------------------------------------------------------------------------


def print_shape(shape: PayloadShape) -> None:
    """Print the discovered nested payload structure. No LLM involved."""
    print()
    print(_rule(f"PAYLOAD SHAPE in index={shape.index}"))
    if not shape.is_nested:
        print(shape.note or "No structured payload field was found; the index is flat.")
        return

    print(f"container field   : {shape.container}")
    print(f"encoding          : {shape.encoding}")
    print(f"layout            : {shape.layout}")
    if shape.name_path:
        print(f"names array       : '{shape.name_path}'")
        print(f"values array      : '{shape.text_path}'")
    print(f"sampled events    : {shape.sampled_events:,}")
    print(f"stratified by     : {', '.join(shape.stratified_by) or '(none)'}")
    print(f"event types seen  : {len(shape.event_types):,}")
    print(f"nested names      : {len(shape.nested_names):,}")
    for family in shape.split_families:
        print(f"positional split  : {', '.join(family.members)}")

    print()
    print("Extraction pattern that works on this instance:")
    if shape.layout == "name-value-array":
        print(f"    | spath input={shape.container}")
        print(f"    | eval <Name> = mvindex('{shape.text_path}',")
        print(f"                            mvfind('{shape.name_path}', \"^<Name>$\"))")
    else:
        print(f"    | spath input={shape.container}")

    print()
    print(f"Nested names ({len(shape.nested_names)}) — NOT columns, extract before use:")
    print("  " + ", ".join(shape.nested_names))


def print_generated(result: GeneratedSPL, *, show_prompt: bool = False) -> None:
    """Render one generated query for human review."""
    print()
    print(_rule("QUESTION"))
    print(result.question)

    print()
    print(_rule("GENERATED SPL"))
    if not result.answerable:
        print("(no query — the model reported this as unanswerable from indexed data)")
        print()
        print("Reason:", result.unsupported_reason or "(none given)")
    else:
        print(result.spl)

    print()
    print(_rule("TIME RANGE"))
    print(f"earliest : {result.time_range.earliest!r}")
    print(f"latest   : {result.time_range.latest!r}")
    print(f"meaning  : {result.time_range.describe()}")
    if result.time_range.rationale:
        print(f"why      : {result.time_range.rationale}")

    if result.rationale:
        print()
        print(_rule("RATIONALE"))
        print(result.rationale)

    print()
    print(_rule("VALIDATION (deterministic — against the discovered schema)"))
    print(result.validation.render())
    print()
    print(f"  extracts from payload : {'yes' if result.validation.uses_extraction else 'no'}")
    if result.validation.referenced:
        print(f"  fields referenced     : {', '.join(result.validation.referenced)}")
    if result.validation.defined:
        print(f"  fields created        : {', '.join(result.validation.defined)}")

    print()
    print(_rule("DOES THIS ANSWER THE QUESTION? (advisory, never blocking)"))
    if result.alignment.ok:
        print(result.alignment.render())
    else:
        print(result.alignment.render())
        print()
        print("  Reviewing this is the reason the SPL is printed and not run.")

    print()
    print(_rule("PROVENANCE"))
    print(f"backend      : {result.backend} ({result.model})")
    print(f"grounded on  : {', '.join(result.grounded_on) or '(nothing)'}")
    print("NOT executed. Review the SPL above before running it.")

    if show_prompt:
        print()
        print(_rule("SYSTEM PROMPT"))
        print(result.system_prompt)
        print()
        print(_rule("USER PROMPT"))
        print(result.user_prompt)


def _generated_to_dict(result: GeneratedSPL) -> dict[str, Any]:
    return {
        "question": result.question,
        "spl": result.spl,
        "earliest": result.time_range.earliest,
        "latest": result.time_range.latest,
        "time_rationale": result.time_range.rationale,
        "rationale": result.rationale,
        "answerable": result.answerable,
        "unsupported_reason": result.unsupported_reason,
        "backend": result.backend,
        "model": result.model,
        "grounded_on": list(result.grounded_on),
        "alignment": {
            "ok": result.alignment.ok,
            "advisory": True,
            "question_subjects": list(result.alignment.subjects),
            "question_terms": list(result.alignment.subject_terms),
            "grouped_by": list(result.alignment.grouped_by),
            "output_fields": list(result.alignment.output),
            "warning": result.alignment.warning,
        },
        "validation": {
            "ok": result.validation.ok,
            "errors": list(result.validation.errors),
            "warnings": list(result.validation.warnings),
            "referenced": list(result.validation.referenced),
            "defined": list(result.validation.defined),
            "unextracted_nested": list(result.validation.unextracted_nested),
            "uses_extraction": result.validation.uses_extraction,
        },
        "executed": False,
    }


def _discover(client: SplunkClient, args: argparse.Namespace) -> tuple[Schema, PayloadShape | None]:
    """Stage 1 discovery, plus the payload probe unless it was turned off."""
    schema = discover_schema(
        client,
        args.index,
        include_internal_indexes=args.include_internal,
        earliest=args.earliest,
        latest=args.latest,
    )
    shape = None
    if not getattr(args, "no_probe", False):
        shape = probe_payload_shape(
            client, schema, earliest=args.earliest, latest=args.latest
        )
    return schema, shape


def cmd_shape(client: SplunkClient, args: argparse.Namespace) -> int:
    _schema, shape = _discover(client, args)
    if shape is None:  # --no-probe makes this command pointless
        print("Nothing to show: --no-probe disables payload discovery.", file=sys.stderr)
        return 2
    print_shape(shape)
    return 0


def cmd_generate(client: SplunkClient, args: argparse.Namespace) -> int:
    """Translate questions to SPL. Discovery runs once for all of them."""
    library: SplLibrary = load_library(args.library).with_index(args.index)
    print(f"SPL library: {library.name} ({len(library)} detections) from {library.source}")

    schema, shape = _discover(client, args)
    print(
        f"Discovered {len(schema.fields)} flat field(s)"
        + (
            f" and {len(shape.nested_names)} nested name(s) inside '{shape.container}'."
            if shape is not None and shape.is_nested
            else " (no nested payload found)."
        )
    )

    if args.dry_run:
        return _dry_run(args, schema, shape, library)

    backend = build_backend()
    print(f"LLM backend: {backend.config.describe()}")
    if backend.config.is_local:
        print("Inference is local — the question and schema stay on this machine.")

    results: list[GeneratedSPL] = []
    failures = 0
    for question in args.questions:
        try:
            result = generate_spl(question, schema, library, backend=backend, shape=shape)
        except (GenerationError, LLMError) as exc:
            print(f"\nCould not generate SPL for {question!r}:\n{exc}\n", file=sys.stderr)
            failures += 1
            continue
        results.append(result)
        if not args.json:
            print_generated(result, show_prompt=args.show_prompt)
        if not result.ok:
            failures += 1

    if args.json:
        print(json.dumps([_generated_to_dict(r) for r in results], indent=2))

    return 1 if failures else 0


def _dry_run(
    args: argparse.Namespace,
    schema: Schema,
    shape: PayloadShape | None,
    library: SplLibrary,
) -> int:
    """Show what *would* be sent, without contacting any LLM."""
    from soc_copilot.generator import build_system_prompt, build_user_prompt

    for question in args.questions:
        selected = library.select(question)
        user_prompt = build_user_prompt(question, schema, selected, shape)
        print()
        print(_rule(f"DRY RUN — {question}"))
        print(f"grounded on: {', '.join(d.id for d in selected)}")
        print(f"prompt size: {len(user_prompt):,} chars")
        if args.show_prompt:
            print()
            print(_rule("SYSTEM PROMPT"))
            print(build_system_prompt())
            print()
            print(_rule("USER PROMPT"))
            print(user_prompt)
    print()
    print("No LLM was contacted (--dry-run).")
    return 0


# --------------------------------------------------------------------------
# Stage 3 — the tool-using loop
# --------------------------------------------------------------------------


#: Steps whose raw backend reply is always shown, because these are the ones
#: where the loop is saying "I could not use what came back" — and that claim is
#: unfalsifiable without the bytes. Two separate misdiagnoses, one of them a real
#: code bug reported as a model limitation, cost several multi-minute runs each
#: to settle. Both would have been one glance at this. See F6 in NOTES.md.
_SHOW_RAW_ON: Final[frozenset[str]] = frozenset({"malformed", "refused"})


def print_step(step: Step) -> None:
    """Print one loop step as it happens.

    Every query the system runs is printed here, with its time range, before its
    rows are shown — so the analyst reviewing the transcript sees exactly what
    was asked of Splunk, in order, with nothing executed off the record.
    """
    print()
    if step.action == "search" and step.result is not None:
        print(_rule(f"STEP {step.n} — SEARCH"))
        if step.purpose:
            print(f"purpose  : {step.purpose}")
        print("SPL      :")
        for line in step.result.spl.splitlines():
            print(f"    {line}")
        print(
            f"earliest : {step.result.time_range.earliest!r}    "
            f"latest: {step.result.time_range.latest!r}    "
            f"({step.result.time_range.describe()})"
        )
        if step.result.error:
            print("status   : NOT RUN")
            print(step.result.error)
            return
        print(f"status   : ran, {step.result.row_count:,} row(s) returned")
        if step.result.validation.warnings:
            print(step.result.validation.render())
        print()
        print(render_table(list(step.result.rows), limit=10))
        return

    if step.action == "refused":
        print(_rule(f"STEP {step.n} — NOT RUN"))
        if step.result is not None:
            print("SPL      :")
            for line in step.result.spl.splitlines():
                print(f"    {line}")
            print(step.result.error)
        if step.note:
            print(step.note)
        return

    if step.action == "answer":
        print(_rule(f"STEP {step.n} — ANSWER"))
        if step.purpose:
            print(f"evidence : {step.purpose}")
        return

    if step.action == "unanswerable":
        print(_rule(f"STEP {step.n} — REPORTED UNANSWERABLE"))
        return

    print(_rule(f"STEP {step.n} — UNUSABLE RESPONSE"))
    print(step.note)
    _print_raw_reply(step)


def _print_raw_reply(step: Step) -> None:
    """Show what the backend actually sent.

    "The reply was unusable" is a statement about the code's ability to read it
    as much as about the model's ability to write it, and the two are
    indistinguishable from the outside. Printing the bytes makes the difference
    visible at the moment it matters instead of days later.
    """
    raw = (step.raw_response or "").strip()
    if not raw:
        print("raw reply: (empty — the backend returned nothing at all)")
        return
    print("raw reply from the backend:")
    for line in raw.splitlines():
        print(f"    {line}")


def print_investigation(
    result: Investigation,
    *,
    view: str = VIEW_HUMAN,
    show_prompt: bool = False,
) -> None:
    """Print the conclusion. The transcript has already streamed above it.

    Rendering is delegated to :mod:`soc_copilot.views`, so the CLI has no say in
    what an answer is allowed to claim — it picks a view and prints it.
    """
    print(render(result, view))
    if show_prompt and view == VIEW_HUMAN:
        print()
        print(_rule("SYSTEM PROMPT"))
        print(result.system_prompt)


def cmd_investigate(client: SplunkClient, args: argparse.Namespace) -> int:
    """Answer questions by running searches until the rows support an answer."""
    view = _resolve_view(args)
    # Setup chatter belongs on stdout only in the human view. The spl and json
    # views are piped into a search bar or a parser, and a preamble mixed into
    # either is output the caller cannot use.
    note = _noter(view)

    library: SplLibrary = load_library(args.library).with_index(args.index)
    note(f"SPL library: {library.name} ({len(library)} detections) from {library.source}")

    schema, shape = _discover(client, args)
    note(
        f"Discovered {len(schema.fields)} flat field(s)"
        + (
            f" and {len(shape.nested_names)} nested name(s) inside '{shape.container}'."
            if shape is not None and shape.is_nested
            else " (no nested payload found)."
        )
    )

    backend = build_backend()
    note(f"LLM backend: {backend.config.describe()}")
    if backend.config.is_local:
        note("Inference is local — the question and schema stay on this machine.")
    note(
        f"Search budget: {args.max_steps} search(es). Every query is validated "
        "against the discovered schema, checked against the read-only allowlist, "
        "and only then run."
    )

    results: list[Investigation] = []
    failures = 0
    for question in args.questions:
        if view == VIEW_HUMAN:
            # Heads the live transcript. The report below it opens with its own
            # QUESTION section, because the report has to stand alone once it is
            # saved or pasted somewhere the transcript did not follow it.
            print()
            print(_rule("INVESTIGATING"))
            print(question)
        try:
            result = investigate(
                question,
                schema,
                library,
                client=client,
                backend=backend,
                shape=shape,
                max_steps=args.max_steps,
                on_step=print_step if _streams_transcript(args) else None,
            )
        except (AgentError, GenerationError, LLMError) as exc:
            print(f"\nCould not investigate {question!r}:\n{exc}\n", file=sys.stderr)
            failures += 1
            continue
        results.append(result)
        if view != VIEW_JSON:
            print_investigation(result, view=view, show_prompt=args.show_prompt)
        if not result.ok:
            failures += 1

    if view == VIEW_JSON:
        # One document for the whole invocation, so a caller parsing stdout gets
        # valid JSON whether it asked one question or five.
        print(json.dumps([to_payload(r) for r in results], indent=2, default=str))

    return 1 if failures else 0


def _noter(view: str) -> Callable[[str], None]:
    """A ``print`` that keeps non-human views free of anything but their payload."""
    if view == VIEW_HUMAN:
        return print
    return lambda message: print(message, file=sys.stderr)


def cmd_serve(client: SplunkClient, args: argparse.Namespace) -> int:
    """Serve the local web UI. A skin over `investigate`, not a second engine.

    Discovery and backend construction happen here, once, before the port opens:
    the index shape does not change between two questions typed a minute apart,
    and paying for it per message would add tens of seconds to every answer.
    """
    library: SplLibrary = load_library(args.library).with_index(args.index)
    print(f"SPL library: {library.name} ({len(library)} detections) from {library.source}")

    schema, shape = _discover(client, args)
    print(
        f"Discovered {len(schema.fields)} flat field(s)"
        + (
            f" and {len(shape.nested_names)} nested name(s) inside '{shape.container}'."
            if shape is not None and shape.is_nested
            else " (no nested payload found)."
        )
    )

    backend = build_backend()
    print(f"LLM backend: {backend.config.describe()}")
    if backend.config.is_local:
        print("Inference is local — the question and schema stay on this machine.")

    engine = Engine(client, schema, library, backend, shape, max_steps=args.max_steps)
    httpd = serve(engine, port=args.port, open_browser=not args.no_browser)

    print()
    print(_rule("SERVING"))
    print(f"  http://{HOST}:{args.port}/")
    print(f"  Bound to {HOST} only — not reachable from any other machine.")
    print("  The Splunk token and the model stay on this side; the browser sends")
    print("  a question and receives the answer plus the rows behind it.")
    print("  Ctrl-C to stop.")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print("Stopping.")
    finally:
        httpd.server_close()
    return 0


def _resolve_view(args: argparse.Namespace) -> str:
    """The chosen view. ``--json`` is kept as the older spelling of ``--view json``."""
    if getattr(args, "json", False) and args.view == VIEW_HUMAN:
        return VIEW_JSON
    return args.view


def _streams_transcript(args: argparse.Namespace) -> bool:
    """Whether to print each step as it happens.

    Only the human view does. The other two are consumed — piped into a search
    bar or into a parser — and a transcript interleaved with them would be
    output the caller did not ask for and cannot use.
    """
    return _resolve_view(args) == VIEW_HUMAN


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_copilot",
        description="SOC Copilot — Stage 1 deterministic Splunk layer (no LLM).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    parser.add_argument(
        "--index", default=DEFAULT_INDEX, help=f"Index to inspect (default: {DEFAULT_INDEX})."
    )
    parser.add_argument(
        "--earliest",
        default=ALL_TIME_EARLIEST,
        help="Splunk earliest_time. Default '0' (epoch 0, no lower bound).",
    )
    parser.add_argument(
        "--latest",
        default=ALL_TIME_LATEST,
        help="Splunk latest_time. Default '' (no upper bound).",
    )
    parser.add_argument(
        "--include-internal",
        action="store_true",
        help="Include Splunk's internal (_*) indexes when listing.",
    )
    parser.add_argument(
        "--limit", type=int, default=25, help="Rows to print (default: 25)."
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("verify", help="Run the known-good search, then print the schema.")
    sub.add_parser("schema", help="Print indexes, sourcetypes and the full field list.")
    sub.add_parser("shape", help="Print the discovered nested payload structure.")

    search = sub.add_parser("search", help="Run one read-only SPL search.")
    search.add_argument("spl", help="The SPL to run, e.g. 'index=logforge | head 5'.")

    generate = sub.add_parser(
        "generate",
        help="Translate questions into SPL. Does NOT run the result.",
    )
    generate.add_argument(
        "questions", nargs="+", help="One or more plain-language questions."
    )
    generate.add_argument(
        "--dry-run",
        action="store_true",
        help="Build the prompt but contact no LLM. Exercises discovery only.",
    )
    generate.add_argument(
        "--show-prompt", action="store_true", help="Print the full prompts sent."
    )
    generate.add_argument(
        "--json", action="store_true", help="Emit results as JSON instead of a report."
    )
    generate.add_argument(
        "--library", default=None, help="Path to an alternative SPL library TOML."
    )

    investigate = sub.add_parser(
        "investigate",
        help="Answer a question by running searches until the rows support one.",
    )
    investigate.add_argument(
        "questions", nargs="+", help="One or more plain-language questions."
    )
    investigate.add_argument(
        "--max-steps",
        type=int,
        default=MAX_STEPS,
        help=f"Searches the loop may run per question (default: {MAX_STEPS}).",
    )
    investigate.add_argument(
        "--show-prompt", action="store_true", help="Print the system prompt used."
    )
    investigate.add_argument(
        "--view",
        choices=VIEWS,
        default=VIEW_HUMAN,
        help=(
            "How to render the result. 'human' (default): the answer, the SPL "
            "behind it and the rows behind that. 'spl': the queries alone, ready "
            "to paste into Splunk. 'json': a stable schema for tooling. The view "
            "changes only the rendering — the guardrails rule on the answer "
            "first, identically, in all three."
        ),
    )
    investigate.add_argument(
        "--json",
        action="store_true",
        help="Deprecated spelling of --view json.",
    )
    investigate.add_argument(
        "--library", default=None, help="Path to an alternative SPL library TOML."
    )

    serve_cmd = sub.add_parser(
        "serve",
        help="Serve the local web UI on 127.0.0.1 (loopback only).",
    )
    serve_cmd.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Port to listen on (default: {DEFAULT_PORT}). The host is always "
             f"{HOST} and cannot be changed.",
    )
    serve_cmd.add_argument(
        "--no-browser", action="store_true", help="Do not open a browser window."
    )
    serve_cmd.add_argument(
        "--max-steps", type=int, default=MAX_STEPS,
        help=f"Searches the loop may run per question (default: {MAX_STEPS}).",
    )
    serve_cmd.add_argument(
        "--library", default=None, help="Path to an alternative SPL library TOML."
    )

    for command in (generate, investigate, serve_cmd, sub.choices["shape"]):
        command.add_argument(
            "--no-probe",
            action="store_true",
            help="Skip payload-shape discovery (nested fields become invisible).",
        )

    parser.set_defaults(
        port=DEFAULT_PORT,
        no_browser=False,
        view=VIEW_HUMAN,
        sample_size=0,
        max_steps=MAX_STEPS,
        no_probe=False,
        dry_run=False,
        show_prompt=False,
        json=False,
        library=None,
        questions=[],
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    handlers = {
        "verify": cmd_verify,
        "schema": cmd_schema,
        "search": cmd_search,
        "shape": cmd_shape,
        "generate": cmd_generate,
        "investigate": cmd_investigate,
        "serve": cmd_serve,
    }
    handler = handlers.get(args.command or "verify")
    if handler is None:  # pragma: no cover - argparse rejects unknown commands
        parser.print_help()
        return 2

    try:
        config: SplunkConfig = load_config()
    except ConfigError as exc:
        print(f"\nConfiguration error:\n\n{exc}\n", file=sys.stderr)
        return 2

    note = _noter(_resolve_view(args))
    note(f"Splunk connection: {config.describe()}")
    if not config.verify_tls:
        note(
            "TLS verification is RELAXED because the host is loopback "
            "(local self-signed management cert). Remote hosts are always verified."
        )

    try:
        with SplunkClient(config) as client:
            return handler(client, args)
    except (SplunkError, SchemaError, LibraryError, AgentError) as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 1
    except LLMError as exc:
        # Includes "no backend configured". Actionable, never a stack trace, and
        # never a silently guessed query.
        print(f"\n{exc}\n", file=sys.stderr)
        return 2


def _to_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
