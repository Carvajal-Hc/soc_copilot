"""Three renderings of one investigation: human, spl, json.

The engine is the same in every case. :func:`~soc_copilot.agent.investigate`
runs, the Stage 4 guardrails rule on what came back, and only then does anything
here choose how to say it. Nothing in this module decides what is true, and
nothing here can promote a claim the guardrails refused — the views read
:class:`~soc_copilot.guardrails.AnchoringReport` and print
:attr:`~soc_copilot.guardrails.AnchoringReport.redacted`, so an unanchored
literal is marked as unsupported in all three or it appears in none.

Who each view is for:

``human``
    An analyst reading the result. The plain-language answer, the SPL that
    produced it, and the rows the answer's values actually came from — the three
    things needed to agree or disagree with it. Any guardrail that fired says so
    here, in words.

``spl``
    The query, and nothing else. Pasteable straight into Splunk's search bar so
    the analyst can run it themselves and see the raw events. When nothing ran,
    it emits an SPL comment rather than empty output, so the paste still lands
    somewhere legible.

``json``
    Tooling: a case-management system, a notebook, a diff between two runs. The
    shape is versioned (:data:`SCHEMA_VERSION`) and the keys are stable. Every
    guardrail outcome is machine-readable, so a caller can refuse to ingest an
    investigation whose answer did not anchor without re-deriving that itself.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Final

from soc_copilot.agent import Investigation, Step
from soc_copilot.guardrails import describe_policy

__all__ = [
    "SCHEMA_VERSION",
    "VIEWS",
    "VIEW_HUMAN",
    "VIEW_JSON",
    "VIEW_SPL",
    "render",
    "render_human",
    "render_json",
    "render_spl",
    "to_payload",
]

VIEW_HUMAN: Final[str] = "human"
VIEW_SPL: Final[str] = "spl"
VIEW_JSON: Final[str] = "json"
VIEWS: Final[tuple[str, ...]] = (VIEW_HUMAN, VIEW_SPL, VIEW_JSON)

#: Bumped when a key in :func:`to_payload` changes meaning or disappears.
#: Additive keys do not bump it; consumers must tolerate keys they do not know.
SCHEMA_VERSION: Final[str] = "1.0"

_WIDTH: Final[int] = 78
#: Cells longer than this are elided in the human view. The full value is always
#: present in the json view, so nothing is lost — only shortened for reading.
_MAX_CELL: Final[int] = 200


def render(result: Investigation, view: str = VIEW_HUMAN) -> str:
    """Render ``result`` in the named view.

    Raises:
        ValueError: ``view`` is not one of :data:`VIEWS`.
    """
    if view == VIEW_HUMAN:
        return render_human(result)
    if view == VIEW_SPL:
        return render_spl(result)
    if view == VIEW_JSON:
        return render_json(result)
    raise ValueError(f"Unknown view {view!r}. Expected one of: {', '.join(VIEWS)}.")


# --------------------------------------------------------------------------
# human
# --------------------------------------------------------------------------


def render_human(result: Investigation) -> str:
    """The analyst's view: the answer, the SPL behind it, and the rows behind that."""
    out: list[str] = []
    out += _section("QUESTION", [result.question])
    out += _section("ANSWER", _answer_lines(result))

    if result.grounding.unverified:
        out += _section("UNSUPPORTED CLAIMS — NOT SHOWN AS FACT", _unsupported_lines(result))

    if result.misaligned:
        out += _section(
            "DOES THIS ANSWER THE QUESTION? — advisory", _alignment_lines(result)
        )

    out += _section("SPL USED", _spl_lines(result))
    out += _section(
        "ANCHORED ROWS — where the answer's values came from",
        _evidence_lines(result),
    )
    out += _section("UNTRUSTED INPUT", _untrusted_lines(result))
    out += _section("GUARDRAILS", _guardrail_lines(result))
    out += _section("PROVENANCE", _provenance_lines(result))
    return "\n".join(out)


def _answer_lines(result: Investigation) -> list[str]:
    if result.answer:
        # The redacted text, never the raw draft: an unanchored literal is
        # rewritten into an explicit marker so that no reading of this view
        # presents it as something Splunk returned.
        lines = [result.grounding.redacted or result.answer]
        if result.grounding.unverified:
            lines += [
                "",
                f"This answer is NOT fully supported: {len(result.grounding.unverified)} "
                "value(s) in it appear in no row Splunk returned. They are marked "
                "[UNVERIFIED: ...] above and listed below.",
            ]
        return lines

    return [
        "(no answer)",
        "",
        result.unsupported_reason or "(no reason given)",
        "",
        "Nothing has been inferred beyond the transcript. \"Not found\" here means "
        "\"not in what was ingested\" — not that it does not exist.",
    ]


def _unsupported_lines(result: Investigation) -> list[str]:
    lines = []
    for lit in result.grounding.literals:
        if not lit.anchored:
            lines.append(
                f"  {lit.value}  ({lit.kind}) — in no row returned this session, "
                "and not in the question. Treat as unsupported."
            )
    lines.append("")
    lines.append(
        "A literal the model produced that Splunk never returned is a "
        "fabrication, whatever else is right about the answer."
    )
    return lines


def _alignment_lines(result: Investigation) -> list[str]:
    """Show the mismatch and let the analyst rule on it.

    Printed above the SPL rather than buried in the guardrail summary, because
    the whole failure mode is that the answer *reads* fine — an analyst who has
    already accepted the prose will not go looking for a footnote.
    """
    lines: list[str] = []
    for step in result.misaligned:
        assert step.result is not None
        if lines:
            lines.append("")
        lines.append(f"step {step.n}:")
        for line in step.result.alignment.warning.splitlines():
            lines.append(f"  {line.strip()}")
    lines.append("")
    lines.append(
        "This is a heuristic, and it is advisory. It compares the noun the "
        "question enumerates against the fields the query outputs; it does not "
        "understand either. Nothing was blocked or rewritten."
    )
    return lines


def _spl_lines(result: Investigation) -> list[str]:
    searches = result.searches
    if not searches:
        return ["(no search was executed)"]

    lines: list[str] = []
    for step in searches:
        assert step.result is not None  # `searches` filters on it
        if lines:
            lines.append("")
        lines.append(f"step {step.n} — {step.result.row_count:,} row(s) returned")
        if step.purpose:
            lines.append(f"  purpose : {step.purpose}")
        for line in step.result.spl.splitlines():
            lines.append(f"  {line}")
        lines.append(
            f"  earliest={step.result.time_range.earliest!r} "
            f"latest={step.result.time_range.latest!r} "
            f"({step.result.time_range.describe()})"
        )
    return lines


def _evidence_lines(result: Investigation) -> list[str]:
    if result.grounding.no_literals:
        return [
            "(the answer states no checkable literal, so there is no row to anchor "
            "it to — read the SPL above and judge the claim on the searches)"
        ]
    if not result.grounding.anchored_rows:
        return ["(no returned row supplied a value used in the answer)"]

    lines: list[str] = []
    for source, number, row in result.grounding.anchored_rows:
        if lines:
            lines.append("")
        lines.append(f"{source}, row {number}")
        width = max((len(str(k)) for k in row), default=0)
        for name, value in row.items():
            lines.append(f"    {str(name).ljust(width)} = {_cell(value)}")
    return lines


def _untrusted_lines(result: Investigation) -> list[str]:
    lines = [
        "Every field value shown to the model was sealed in a per-session "
        "envelope and marked as data. Field values are attacker-controlled; the "
        "model is instructed, in the system message they cannot reach, to read "
        "them and never obey them.",
    ]
    if not result.injection_signals:
        lines += ["", "No instruction-shaped text was found in the returned rows."]
        return lines

    lines += [
        "",
        f"{len(result.injection_signals)} field value(s) contain text that reads as "
        "an instruction to an automated reviewer. They were passed as sealed data "
        "and changed nothing about this answer. Someone put them there:",
        "",
    ]
    for signal in result.injection_signals:
        lines.append(f"  [{signal.kind}] {signal.describe()}")
    return lines


def _guardrail_lines(result: Investigation) -> list[str]:
    lines = [describe_policy(), ""]

    refused = [
        step
        for step in result.steps
        if step.result is not None and step.result.error and not step.result.executed
    ]
    lines.append(f"queries executed  : {len(result.searches)}")
    lines.append(f"queries refused   : {len(refused)}")
    for step in refused:
        assert step.result is not None
        first = step.result.error.strip().splitlines()[0]
        lines.append(f"  step {step.n}: {first}")

    anchoring = result.grounding
    if anchoring.no_literals:
        verdict = "no checkable literal in the answer"
    elif anchoring.ok:
        verdict = f"{len(anchoring.verified)} literal(s), all traced to returned rows"
    else:
        verdict = (
            f"{len(anchoring.unverified)} of "
            f"{len(anchoring.literals)} literal(s) traced to NO returned row"
        )
    lines.append(f"literal anchoring : {verdict}")
    lines.append(
        "question alignment: "
        + (
            f"{len(result.misaligned)} "
            + ("query" if len(result.misaligned) == 1 else "queries")
            + " may answer a different question"
            if result.misaligned
            else "output lines up with the question's subject"
        )
    )
    lines.append(f"injection signals : {len(result.injection_signals)}")
    lines.append(f"stop reason       : {result.stop_reason}")
    lines.append(
        f"overall           : {'PASS' if result.ok else 'NOT CLEAN — read the sections above'}"
    )
    return lines


def _provenance_lines(result: Investigation) -> list[str]:
    return [
        f"backend      : {result.backend} ({result.model})",
        f"grounded on  : {', '.join(result.grounded_on) or '(nothing)'}",
        f"pattern used : {result.pattern_used or '(could not attribute)'}"
        + "   (inferred from the SPL, not reported by the model)",
        f"rows seen    : {result.rows_seen:,}",
        "Every literal shown above as fact came from a row Splunk returned in "
        "this session. Nothing was supplied from the model's own knowledge.",
    ]


def _section(title: str, body: Sequence[str]) -> list[str]:
    rule = f"-- {title} " + "-" * max(0, _WIDTH - len(title) - 4)
    return ["", rule, *body]


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", " ").replace("\t", " ").strip()
    return text if len(text) <= _MAX_CELL else text[: _MAX_CELL - 1] + "…"


# --------------------------------------------------------------------------
# spl
# --------------------------------------------------------------------------


def render_spl(result: Investigation) -> str:
    """Just the queries, ready to paste into Splunk.

    Each executed search is emitted with its time range as an SPL comment, since
    the range is not part of the query text and pasting without it is how an
    all-time search silently becomes a last-24-hours one.
    """
    searches = result.searches
    if not searches:
        reason = (
            result.unsupported_reason or "no search was executed"
        ).replace("\n", " ").strip()
        return f"``` {reason} ```"

    blocks: list[str] = []
    for step in searches:
        assert step.result is not None
        time_range = (
            f"``` step {step.n}: earliest={step.result.time_range.earliest!r} "
            f"latest={step.result.time_range.latest!r} — "
            f"{step.result.row_count:,} row(s) ```"
        )
        blocks.append(f"{time_range}\n{step.result.spl.strip()}")
    return "\n\n".join(blocks)


# --------------------------------------------------------------------------
# json
# --------------------------------------------------------------------------


def render_json(result: Investigation, *, indent: int = 2) -> str:
    """The stable machine-readable rendering."""
    return json.dumps(to_payload(result), indent=indent, default=str)


def to_payload(result: Investigation) -> dict[str, Any]:
    """One investigation as a plain dict, in the :data:`SCHEMA_VERSION` schema.

    ``answer.text`` is the anchored answer and is what a consumer should display.
    ``answer.draft`` is what the model actually wrote, kept so that a reviewer can
    see what was refused; a consumer that shows ``draft`` to a user is defeating
    the guardrail, and that is why the field is named the way it is.
    """
    anchoring = result.grounding
    return {
        "schema_version": SCHEMA_VERSION,
        "question": result.question,
        "answer": {
            "text": anchoring.redacted or result.answer,
            "draft": result.answer,
            "answerable": result.answerable,
            "unsupported_reason": result.unsupported_reason,
            "fully_anchored": anchoring.ok,
        },
        "ok": result.ok,
        "stop_reason": result.stop_reason,
        "backend": {
            "name": result.backend,
            "model": result.model,
            "grounded_on": list(result.grounded_on),
            "pattern_used": result.pattern_used,
        },
        "guardrails": {
            "read_only": {
                "enforced": True,
                "policy": describe_policy(),
                "refused": [
                    {
                        "step": step.n,
                        "spl": step.result.spl,
                        "reason": step.result.error,
                    }
                    for step in result.steps
                    if step.result is not None
                    and step.result.error
                    and not step.result.executed
                ],
            },
            "anchoring": {
                "ok": anchoring.ok,
                "no_literals": anchoring.no_literals,
                "literals": [
                    {
                        "value": lit.value,
                        "kind": lit.kind,
                        "anchored": lit.anchored,
                        "from_question": lit.from_question,
                        "anchors": [
                            {"source": a.source, "row": a.row, "field": a.field}
                            for a in lit.anchors
                        ],
                    }
                    for lit in anchoring.literals
                ],
                "unverified": list(anchoring.unverified),
            },
            "alignment": {
                "ok": not result.misaligned,
                "advisory": True,
                "misaligned": [
                    {
                        "step": step.n,
                        "question_subjects": list(step.result.alignment.subjects),
                        "question_terms": list(step.result.alignment.subject_terms),
                        "grouped_by": list(step.result.alignment.grouped_by),
                        "output_fields": list(step.result.alignment.output),
                        "warning": step.result.alignment.warning,
                    }
                    for step in result.misaligned
                    if step.result is not None
                ],
            },
            "untrusted_input": {
                "field_values_sealed": True,
                "signals": [
                    {
                        "source": s.source,
                        "row": s.row,
                        "field": s.field,
                        "kind": s.kind,
                        "excerpt": s.excerpt,
                    }
                    for s in result.injection_signals
                ],
            },
        },
        "searches": [_search_payload(step) for step in result.searches],
        "anchored_rows": [
            {"source": source, "row": number, "fields": dict(row)}
            for source, number, row in anchoring.anchored_rows
        ],
        "steps": [_step_payload(step) for step in result.steps],
        "rows_seen": result.rows_seen,
    }


def _search_payload(step: Step) -> dict[str, Any]:
    assert step.result is not None
    verdict = step.result.validation.read_only
    return {
        "step": step.n,
        "purpose": step.purpose,
        "spl": step.result.spl,
        "earliest": step.result.time_range.earliest,
        "latest": step.result.time_range.latest,
        "row_count": step.result.row_count,
        "commands": list(verdict.commands) if verdict is not None else [],
        "rows": [dict(row) for row in step.result.rows],
    }


def _step_payload(step: Step) -> dict[str, Any]:
    result = step.result
    return {
        "n": step.n,
        "action": step.action,
        "purpose": step.purpose,
        "note": step.note,
        "spl": result.spl if result else "",
        "earliest": result.time_range.earliest if result else "",
        "latest": result.time_range.latest if result else "",
        "executed": bool(result and result.executed),
        "row_count": result.row_count if result else 0,
        "error": result.error if result else "",
        # Why a result was empty, when the loop can name a reason. Omitted from
        # the payload until now, which made the instrumentation invisible in the
        # one view built for reading a run back afterwards.
        "hint": result.hint if result else "",
        "validation": _validation_payload(step),
    }


def _validation_payload(step: Step) -> dict[str, Any] | None:
    if step.result is None:
        return None
    report = step.result.validation
    return {
        "ok": report.ok,
        "errors": list(report.errors),
        "warnings": list(report.warnings),
        "referenced": list(report.referenced),
        "defined": list(report.defined),
        "unextracted_nested": list(report.unextracted_nested),
        "uses_extraction": report.uses_extraction,
        "read_only": (
            {
                "allowed": report.read_only.allowed,
                "reason": report.read_only.reason,
                "commands": list(report.read_only.commands),
            }
            if report.read_only is not None
            else None
        ),
    }
