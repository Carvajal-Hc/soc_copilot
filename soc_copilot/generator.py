"""Stage 2: turn a natural-language question into SPL. Single-shot, no loop.

The design goal is "correct and grounded", not clever. Splunk's own assistant
already does cloud NL->SPL; there is nothing to win by out-engineering the
translator. What this module does instead is refuse to let the model operate on
anything it has not been shown:

1. **Ground in the live schema.** The field list comes from Stage 1 discovery of
   the real index — never a hardcoded list, never the model's recollection of
   what a Sysmon CSV usually looks like.
2. **Ground in the real payload shape.** Whether a name is a flat column or
   lives inside a payload is discovered by sampling (:mod:`payload_shape`) and
   stated explicitly in the prompt, along with the extraction pattern that works
   on *this* instance.
3. **Ground in known-good SPL.** The curated library supplies the shapes; the
   model adapts one rather than improvising.
4. **Verify deterministically.** Whatever comes back is checked against the
   schema by :mod:`validation` before it is shown. Generation is not trusted.

This module never runs the query. It returns SPL plus the chosen time range for
a human to review.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Final

from soc_copilot.library import Detection, SplLibrary
from soc_copilot.llm.base import LLMBackend
from soc_copilot.payload_shape import PayloadShape
from soc_copilot.schema import Schema
from soc_copilot.semantics import AlignmentReport, check_alignment
from soc_copilot.splunk_client import ALL_TIME_EARLIEST, ALL_TIME_LATEST
from soc_copilot.validation import ValidationReport, validate_spl

log = logging.getLogger(__name__)

#: How many event types and nested names to put in the prompt. The lab index has
#: ~720 event types and ~800 nested names; sending all of them would drown the
#: question and blow the context of a small local model.
MAX_EVENT_TYPES: Final[int] = 12
MAX_NESTED_NAMES: Final[int] = 300
MAX_LIBRARY_ENTRIES: Final[int] = 4

_WORD_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9_]+")


class GenerationError(RuntimeError):
    """The model's response could not be turned into a query."""


@dataclass(frozen=True)
class TimeRange:
    """The time window chosen for a generated query."""

    earliest: str = ALL_TIME_EARLIEST
    latest: str = ALL_TIME_LATEST
    rationale: str = ""

    def describe(self) -> str:
        low = self.earliest or "(none)"
        high = self.latest or "(none)"
        if self.earliest == ALL_TIME_EARLIEST and not self.latest:
            return "all time (epoch 0 -> no upper bound)"
        return f"{low} -> {high}"


@dataclass(frozen=True)
class GeneratedSPL:
    """One generated query, with everything needed to review it."""

    question: str
    spl: str
    time_range: TimeRange
    validation: ValidationReport
    rationale: str = ""
    #: False when the model judged the question unanswerable from indexed data.
    answerable: bool = True
    unsupported_reason: str = ""
    backend: str = ""
    model: str = ""
    #: Ids of the library detections used to ground this generation.
    grounded_on: tuple[str, ...] = ()
    #: Whether the query's output lines up with what the question asked about.
    #: A warning only — see :mod:`soc_copilot.semantics`. It never blocks, and
    #: it is deliberately excluded from :attr:`ok`, because "this may answer a
    #: different question" is a judgement for the analyst, not a verdict.
    alignment: AlignmentReport = field(default_factory=AlignmentReport)
    #: The exact prompts sent, for audit and debugging.
    system_prompt: str = field(default="", repr=False)
    user_prompt: str = field(default="", repr=False)
    raw_response: str = field(default="", repr=False)

    @property
    def ok(self) -> bool:
        return self.answerable and self.validation.ok


# --------------------------------------------------------------------------
# The interface CLAUDE.md specifies
# --------------------------------------------------------------------------


def generate_spl(
    question: str,
    schema: Schema,
    library: SplLibrary,
    *,
    backend: LLMBackend,
    shape: PayloadShape | None = None,
) -> GeneratedSPL:
    """Translate ``question`` into SPL grounded in ``schema`` and ``library``.

    Args:
        question: The analyst's question, in plain language.
        schema: Discovered at runtime from the live index (Stage 1). The only
            authority on what fields exist.
        library: Curated known-good detections to adapt from.
        backend: Any :class:`~soc_copilot.llm.base.LLMBackend`. This function
            does not know or care which one.
        shape: Discovered payload structure. Without it, nested fields cannot be
            distinguished from flat ones and the query is generated (and
            validated) as if the index were flat — a warning is attached.

    Returns:
        A :class:`GeneratedSPL`. The query is **not** executed.

    Raises:
        GenerationError: the response was not usable.
        LLMError: the backend failed. Propagated unchanged so the caller can
            report the backend's own actionable message.
    """
    if not question or not question.strip():
        raise GenerationError("The question is empty; there is nothing to translate.")

    selected = library.select(question, limit=MAX_LIBRARY_ENTRIES)
    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(question, schema, selected, shape)

    log.info(
        "Generating SPL via %s (%s), grounded on: %s",
        backend.name,
        backend.config.model,
        ", ".join(d.id for d in selected) or "(nothing)",
    )

    raw = backend.complete(system=system_prompt, user=user_prompt)
    parsed = parse_response(raw)

    time_range = TimeRange(
        earliest=str(parsed.get("earliest", ALL_TIME_EARLIEST)),
        latest=str(parsed.get("latest", ALL_TIME_LATEST)),
        rationale=str(parsed.get("time_rationale", "")),
    )
    spl = str(parsed.get("spl", "")).strip()
    answerable = bool(parsed.get("answerable", True))

    report = validate_spl(
        spl,
        schema,
        shape,
        earliest=time_range.earliest,
        latest=time_range.latest,
    )

    if shape is None:
        report = ValidationReport(
            ok=report.ok,
            errors=report.errors,
            warnings=(
                *report.warnings,
                "Payload structure was not probed, so nested fields could not be "
                "distinguished from flat ones. A query that filters a nested field "
                "directly would not have been caught.",
            ),
            referenced=report.referenced,
            defined=report.defined,
            unextracted_nested=report.unextracted_nested,
            uses_extraction=report.uses_extraction,
            read_only=report.read_only,
        )

    return GeneratedSPL(
        question=question.strip(),
        spl=spl,
        alignment=check_alignment(question, spl, schema, shape),
        time_range=time_range,
        validation=report,
        rationale=str(parsed.get("rationale", "")),
        answerable=answerable,
        unsupported_reason=str(parsed.get("unsupported_reason", "")),
        backend=backend.name,
        model=backend.config.model,
        grounded_on=tuple(d.id for d in selected),
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        raw_response=raw,
    )


# --------------------------------------------------------------------------
# Prompt construction
# --------------------------------------------------------------------------


SYSTEM_PROMPT: Final[str] = """\
You translate a SOC analyst's plain-language question into a single Splunk SPL \
search. You are one deterministic step in a larger system, not a chat assistant.

RULES — these are not style preferences.

1. GROUNDING. Use ONLY the field names listed under DISCOVERED SCHEMA and NESTED
   PAYLOAD FIELDS below. That list was read from the live index moments ago and
   is the only authority on what exists. If a field you expect is not listed, it
   does not exist here — do not use it, and do not substitute a name you have
   seen in other Splunk deployments.

2. NEVER INVENT A LITERAL. Do not put a hostname, username, hash, IP, SID,
   filename, GUID or event id into the query unless the analyst supplied it in
   the question, or it appears in the material below. You do not know the
   contents of this index; the query is how it gets discovered. If the analyst
   asks about "the malicious binary", write a query that would surface
   candidates — do not guess its name.

3. FLAT vs NESTED. This is the single most common way to produce a query that
   looks right and silently returns nothing. Fields listed as flat are real
   columns: filter and group by them directly. Fields listed as nested live
   INSIDE the payload field and are NOT columns — referencing one directly
   matches zero events. Extract it first, using the pattern shown below, then
   filter or group on the extracted field. Always narrow on flat fields in the
   base search before extracting, so the extraction runs over as few events as
   possible.

4. READ-ONLY. Never emit delete, collect, outputlookup, outputcsv, sendemail or
   any other command that writes or exfiltrates. Searching only.

5. TIME RANGE. Choose it explicitly and state it. The data may be historical, so
   never default to a relative window like "last 24 hours" — that silently
   returns nothing against an old index. Use the index's actual time bounds
   shown below. When the question implies no particular window, use the full
   range: earliest "0", latest "".

6. HONESTY ABOUT SCOPE. This tool answers only what the indexed data supports.
   If the question needs raw-artifact work (parsing $MFT internals, carving
   bytes, reading UTF-16 strings out of a file) or asks for something the
   discovered schema simply cannot express, set "answerable" to false and
   explain why in "unsupported_reason". Do not produce a query that pretends to
   answer it. "Not in this index" is a correct and useful answer.

OUTPUT. Reply with a single JSON object and nothing else — no prose before or
after, no markdown fence. Keys:

{
  "answerable":         true or false,
  "spl":                "the SPL search, or \\"\\" when answerable is false",
  "earliest":           "Splunk earliest_time, e.g. \\"0\\"",
  "latest":             "Splunk latest_time, \\"\\" for no upper bound",
  "time_rationale":     "one sentence on why that window",
  "rationale":          "two or three sentences: what the query does, and for \
any nested field, that you extracted it rather than filtering it flat",
  "unsupported_reason": "when answerable is false, what the analyst should do \
instead; otherwise \\"\\""
}\
"""


def build_system_prompt() -> str:
    return SYSTEM_PROMPT


def build_user_prompt(
    question: str,
    schema: Schema,
    detections: tuple[Detection, ...],
    shape: PayloadShape | None,
) -> str:
    """Assemble the grounded prompt for one question."""
    sections = [
        f"# ANALYST QUESTION\n\n{question.strip()}\n",
        build_grounding(question, schema, detections, shape),
        _render_task(schema, shape),
    ]
    return "\n".join(section for section in sections if section)


def build_grounding(
    question: str,
    schema: Schema,
    detections: tuple[Detection, ...],
    shape: PayloadShape | None,
) -> str:
    """The grounding material — discovered schema, payload shape, library.

    Everything the model is allowed to treat as true about this index, and
    nothing else. Stage 3's tool-using loop shows the same material, so the
    two stages cannot drift into grounding the model differently.
    """
    sections = [
        _render_schema(schema),
        _render_shape(shape, question),
        _render_library(detections),
    ]
    return "\n".join(section for section in sections if section)


def _render_schema(schema: Schema) -> str:
    index_info = next((i for i in schema.indexes if i.name == schema.index), None)
    bounds = ""
    if index_info and index_info.earliest:
        bounds = (
            f"Events span {index_info.earliest} to {index_info.latest} "
            f"({index_info.event_count:,} events).\n"
            "Note the date range — a relative time window may fall entirely "
            "outside it.\n"
        )

    sourcetypes = ", ".join(
        f"{s.name} ({s.event_count:,} events)" for s in schema.sourcetypes
    ) or "(none discovered)"

    flat = ", ".join(schema.field_names)

    return (
        f"# DISCOVERED SCHEMA (read from the live index — authoritative)\n\n"
        f"index: {schema.index}\n"
        f"{bounds}"
        f"sourcetypes: {sourcetypes}\n\n"
        f"FLAT FIELDS — real top-level columns, filter and group by these "
        f"directly ({len(schema.fields)}):\n{flat}\n"
    )


def _render_shape(shape: PayloadShape | None, question: str) -> str:
    if shape is None:
        return (
            "# NESTED PAYLOAD FIELDS\n\n"
            "Payload structure was not probed. Treat every field above as flat.\n"
        )
    if not shape.is_nested:
        note = shape.note or "Sampling found no structured payload field."
        return f"# NESTED PAYLOAD FIELDS\n\n{note}\nThis index is flat.\n"

    lines = [
        "# NESTED PAYLOAD FIELDS (discovered by sampling real events)",
        "",
        f"The field '{shape.container}' holds {shape.encoding.upper()} content. "
        f"Its layout is: {shape.layout}.",
        "",
    ]

    if shape.layout == "name-value-array":
        lines += [
            "IMPORTANT — how this payload actually behaves on this instance:",
            "",
            f"  `spath input={shape.container}` does NOT create one field per name.",
            "  It creates TWO PARALLEL MULTIVALUE ARRAYS:",
            f"      '{shape.name_path}'   (the names)",
            f"      '{shape.text_path}'   (the matching values)",
            "",
            "  So neither of these works — both return nothing:",
            f"      | spath input={shape.container} path={shape.name_path.split('{')[0]}.Image",
            f'      | spath input={shape.container} path=...{{@Name="Image"}}.#text   '
            "(predicate form unsupported here — verified)",
            "",
            "  THE PATTERN THAT WORKS. Pair the arrays by position: mvfind() gives",
            "  the index of the name, mvindex() reads the value at that index.",
            "  Anchor the regex with ^...$ or 'ProcessId' also matches",
            "  'ParentProcessId'. One eval per field you need:",
            "",
            f"      | spath input={shape.container}",
            f"      | eval Image = mvindex('{shape.text_path}',",
            f"                             mvfind('{shape.name_path}', \"^Image$\"))",
            "",
        ]
    else:
        lines += [
            f"  Extract with: | spath input={shape.container}",
            "  Nested values then become fields at their dotted paths.",
            "",
        ]

    if shape.split_families:
        for family in shape.split_families:
            lines += [
                f"POSITIONAL SPLIT FIELDS: {', '.join(family.members)} are flat "
                f"columns, but their meaning is positional and CHANGES BY EVENT "
                f"TYPE, and they are often truncated. Use them only for a cheap "
                f"pre-filter or an eyeball. Never report a value from them as a "
                f"named field, and never group by them across event types — "
                f"extract from '{shape.container}' instead.",
                "",
            ]

    relevant = _relevant_event_types(shape, question)
    if relevant:
        lines.append(
            f"NESTED FIELDS BY EVENT TYPE (keyed by "
            f"{' + '.join(shape.stratified_by)}) — the event types most relevant "
            f"to this question, out of {len(shape.event_types)} discovered:"
        )
        lines.append("")
        for event_type in relevant:
            lines.append(f"  {event_type.describe()}")
        lines.append("")

    names = shape.nested_names
    shown = names[:MAX_NESTED_NAMES]
    truncated = (
        f" (showing {len(shown)} of {len(names)}; ask about a specific event type "
        "for the rest)"
        if len(names) > len(shown)
        else ""
    )
    lines.append(
        f"ALL NESTED NAMES seen anywhere in '{shape.container}'{truncated}. "
        "These are NOT columns — extract before use:"
    )
    lines.append(", ".join(shown))
    lines.append("")
    return "\n".join(lines)


def _render_library(detections: tuple[Detection, ...]) -> str:
    if not detections:
        return ""
    return (
        "# CURATED SPL LIBRARY (known-good detections — adapt these)\n\n"
        "These are verified working queries. Adapt the closest one's PATTERN to "
        "the question. Their concrete field names are illustrative only — the "
        "DISCOVERED SCHEMA above overrides them.\n\n"
        + "\n".join(d.render() for d in detections)
    )


def _render_task(schema: Schema, shape: PayloadShape | None) -> str:
    reminder = ""
    if shape is not None and shape.is_nested:
        reminder = (
            f"Before you answer, check every field name in your query: is it in "
            f"the FLAT FIELDS list, or is it a nested name that needs extracting "
            f"from '{shape.container}' first?\n"
        )
    return (
        f"# TASK\n\n"
        f"Write one SPL search against index={schema.index} that answers the "
        f"analyst's question.\n{reminder}"
        f"\nThe library entries above are REFERENCE MATERIAL. Their labels — id, "
        f"maps to, pattern, asked as, technique this teaches, canonical SPL — "
        f"describe those examples. They are NOT the keys of your reply, and you "
        f"must not copy them.\n"
        f"\nReply with EXACTLY this JSON object and nothing else. Use these key "
        f"names verbatim:\n"
        "{\n"
        '  "answerable": true,\n'
        '  "spl": "<your SPL search>",\n'
        '  "earliest": "0",\n'
        '  "latest": "",\n'
        '  "time_rationale": "<one sentence>",\n'
        '  "rationale": "<two or three sentences>",\n'
        '  "unsupported_reason": ""\n'
        "}"
    )


def _relevant_event_types(shape: PayloadShape, question: str) -> list[Any]:
    """Rank discovered event types by overlap with the question's wording."""
    terms = {w for w in _WORD_RE.findall(question.lower()) if len(w) > 2}
    if not terms:
        return list(shape.event_types[:MAX_EVENT_TYPES])

    def score(event_type: Any) -> int:
        haystack = " ".join([*event_type.key, event_type.label, *event_type.nested_names])
        bag = set(_WORD_RE.findall(haystack.lower()))
        # A nested name matching the question is the strongest possible signal
        # that this event type is the one being asked about.
        direct = sum(2 for name in event_type.nested_names if name.lower() in terms)
        return direct + len(terms & bag)

    ranked = sorted(shape.event_types, key=lambda e: (-score(e), e.key))
    return [e for e in ranked[:MAX_EVENT_TYPES] if score(e) > 0]


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def parse_response(raw: str, *, require_spl: bool = True) -> dict[str, Any]:
    """Extract the JSON object from a model response.

    Tolerates a markdown fence or a stray sentence around the object, because
    small local models add them; anything less recoverable is an error rather
    than a guess.

    Args:
        require_spl: Stage 2 asks for exactly one thing — a query — so a reply
            claiming the question is answerable but carrying no SPL is a
            malformed reply. Stage 3's loop speaks a wider protocol in which
            ``answer`` and ``unanswerable`` legitimately carry no SPL at all, so
            it passes ``False`` and checks the action itself.
    """
    text = (raw or "").strip()
    if not text:
        raise GenerationError("The backend returned an empty response.")

    fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()

    try:
        parsed = json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise GenerationError(
                "The backend did not return a JSON object. SOC Copilot will not "
                f"guess SPL from free text. Response began: {text[:200]!r}"
            ) from None
        try:
            parsed = json.loads(text[start : end + 1])
        except ValueError as exc:
            raise GenerationError(
                f"The backend's response was not valid JSON: {exc}. "
                f"Response began: {text[:200]!r}"
            ) from exc

    if not isinstance(parsed, dict):
        raise GenerationError(
            f"Expected a JSON object from the backend, got {type(parsed).__name__}."
        )

    if require_spl and parsed.get("answerable", True) and not str(parsed.get("spl", "")).strip():
        raise GenerationError(
            "The backend reported the question as answerable but returned no SPL."
        )
    return parsed
