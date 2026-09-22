"""Deterministic checks on generated SPL, before a human ever sees it.

An LLM that writes ``| stats count by ProcessGuid`` against an index where
ProcessGuid lives inside a payload produces a query that is syntactically fine,
runs without error, and silently returns nothing. That failure is invisible at
review time and catastrophic in triage — "no results" reads as "no evidence".

So generation is not trusted. Every generated query is checked here against the
schema discovered at runtime:

* it must be read-only;
* it must target the index we discovered;
* every field it references must exist — flat, nested-and-extracted, or created
  by the query itself;
* a field that is known to live *inside* the payload may not be referenced as
  though it were flat. That is the specific, high-confidence check this module
  exists for, and it is a hard error.

The field-reference scan is a best-effort static parse of SPL, not a full
grammar. It is deliberately tuned to under-report: a name it cannot classify is
reported as a warning, while the nested-without-extraction case — which it can
identify precisely — is an error.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Final

from soc_copilot.guardrails import ReadOnlyVerdict, read_only_verdict
from soc_copilot.payload_shape import PayloadShape
from soc_copilot.schema import Schema

log = logging.getLogger(__name__)

#: Left-hand names in ``name=value`` that are command *options*, not fields.
_COMMAND_OPTIONS: Final[frozenset[str]] = frozenset(
    """allnum as charset count countfield default delim desc earliest end exact
    field fillnull format header input limit match max maxvals mode offset
    otherstr output outfield overwrite partial path percentfield sep showcount
    sortby span start top type usetime useother nullstr latest""".split()
)

#: Aggregation functions whose single argument is a field name.
_AGG_FUNCTIONS: Final[str] = (
    r"count|dc|distinct_count|values|list|sum|sumsq|avg|mean|min|max|first|last"
    r"|median|mode|range|stdev|stdevp|var|varp|earliest|latest|estdc|perc\d+"
)

#: Commands whose arguments are a bare list of field names.
_FIELD_LIST_COMMANDS: Final[str] = r"table|fields|dedup|sort|rename|untable|contingency"

_BY_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:by|BY|over|OVER|GROUPBY|groupby)\s+([^|\]]+)"
)
_COMPARE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w.'\"])([A-Za-z_][A-Za-z0-9_.]*)\s*(?:=|!=|<=|>=|<|>)(?!=)"
)
_AGG_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?:{_AGG_FUNCTIONS})\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)", re.IGNORECASE
)
_FIELD_LIST_RE: Final[re.Pattern[str]] = re.compile(
    rf"\|\s*(?:{_FIELD_LIST_COMMANDS})\b([^|\]]*)", re.IGNORECASE
)
_QUOTED_FIELD_RE: Final[re.Pattern[str]] = re.compile(r"'([^']+)'")

#: Names the query creates for itself.
_AS_RE: Final[re.Pattern[str]] = re.compile(
    r"\bas\s+\"?([A-Za-z_][A-Za-z0-9_.]*)\"?", re.IGNORECASE
)
_EVAL_RE: Final[re.Pattern[str]] = re.compile(
    r"\beval\s+([A-Za-z_][A-Za-z0-9_.]*)\s*=|,\s*([A-Za-z_][A-Za-z0-9_.]*)\s*="
)
_REX_CAPTURE_RE: Final[re.Pattern[str]] = re.compile(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>")
_OUTPUT_RE: Final[re.Pattern[str]] = re.compile(
    r"\boutput\s*=\s*\"?([A-Za-z_][A-Za-z0-9_.]*)\"?", re.IGNORECASE
)
_RENAME_RE: Final[re.Pattern[str]] = re.compile(
    r"\brename\s+([A-Za-z_][A-Za-z0-9_.]*)", re.IGNORECASE
)

_INDEX_RE: Final[re.Pattern[str]] = re.compile(
    r"\bindex\s*=\s*\"?([A-Za-z0-9_*-]+)\"?", re.IGNORECASE
)

#: Template text left unsubstituted in a filter. Two shapes only, both chosen
#: because real values in this data never take them: angle brackets, and
#: SCREAMING-KEBAB tokens of three or more alphabetic segments. A real hostname
#: like WIN-1U80VJFJPGD has two segments and a numeric one, so it is untouched.
#:
#: This is a hard error rather than a warning because a query carrying a
#: placeholder cannot match anything, and a zero-row result is the most
#: dangerous outcome this system has: it reads as "no such evidence" when it
#: means "the filter was never filled in". A 14B model did exactly this, then
#: reported that no PowerShell process creation existed — of six that did.
_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(
    # Not a rex named-capture group: '(?<Image>...)' is valid SPL, and
    # flagging it would refuse every query that extracts with a named group.
    r"(?<!\(\?)(?<!\(\?P)<[A-Za-z][^<>]{2,40}>"
    r"|\b[A-Z]{2,}(?:-[A-Z0-9]{1,}){2,}\b"
)

#: Any of these means the query is doing extraction rather than flat filtering.
_EXTRACTION_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(spath|rex|mvindex|mvfind|mvexpand|mvzip|extract|kvform|xmlkv|json_extract)\b",
    re.IGNORECASE,
)


def spl_uses_extraction(spl: str) -> bool:
    """True when ``spl`` pulls values out of a structured field.

    The single source of truth for "is this query nested?", used both to report
    on generated SPL and to classify curated library entries. Deriving it from
    the query text rather than from a label means an entry cannot claim to teach
    extraction while demonstrating a flat filter, or vice versa.
    """
    return bool(_EXTRACTION_RE.search(spl or ""))

#: SPL keywords, operators and literals that are never field names.
_SPL_KEYWORDS: Final[frozenset[str]] = frozenset(
    """and or not in like by over where search index eval stats table fields
    sort head tail dedup rename top rare timechart chart bin bucket fillnull
    lookup transaction eventstats streamstats spath rex regex replace mvexpand
    mvzip mvindex mvfind makemv nomv convert strftime strptime tostring tonumber
    if case match null true false now relative_time coalesce len substr split
    lower upper trim ltrim rtrim urldecode md5 sha1 sha256 isnull isnotnull
    count dc values list sum avg min max first last earliest latest distinct_count
    limit usenull useother span cont format append appendcols join set union
    return map fillnull addtotals addinfo untable xyseries reverse abs ceil floor
    round exact printf tostring typeof mvcount mvjoin mvsort mvdedup nullif
    validate multisearch inputlookup outputlookup where sortby asc desc""".split()
)

#: Splunk supplies these on every event regardless of what fieldsummary reports.
_ALWAYS_VALID_FIELDS: Final[frozenset[str]] = frozenset(
    {"_time", "_raw", "_indextime", "_cd", "_bkt", "_serial", "_si", "_sourcetype",
     "_subsecond", "host", "source", "sourcetype", "index", "splunk_server", "linecount"}
)

#: Splunk time modifiers: epoch, relative ("-7d@d", "now"), or a literal
#: MM/DD/YYYY:HH:MM:SS timestamp. Empty means "no bound".
_TIME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:\d+(?:\.\d+)?|now|-?\d+[smhdwmonqy]+(?:@[a-z0-9+\-]+)?|@[a-z0-9+\-]+"
    r"|\d{1,2}/\d{1,2}/\d{4}(?::\d{1,2}:\d{1,2}:\d{1,2})?"
    r"|\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?)?)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ValidationReport:
    """The outcome of checking one generated query."""

    #: True when nothing blocking was found. Warnings do not clear this flag.
    ok: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    #: Field names the query reads.
    referenced: tuple[str, ...] = ()
    #: Field names the query creates (eval, as, rex capture, spath output).
    defined: tuple[str, ...] = ()
    #: Nested names referenced without being extracted first — the silent-empty
    #: bug this module exists to catch.
    unextracted_nested: tuple[str, ...] = ()
    #: True when the query extracts from the payload at all.
    uses_extraction: bool = False
    #: The read-only ruling, kept whole so the views can show which commands the
    #: query actually contains rather than only whether it passed.
    read_only: ReadOnlyVerdict | None = None

    def render(self) -> str:
        lines = []
        for message in self.errors:
            lines.append(f"  [ERROR]   {message}")
        for message in self.warnings:
            lines.append(f"  [warning] {message}")
        if not lines:
            lines.append("  All checks passed.")
        return "\n".join(lines)


def validate_spl(
    spl: str,
    schema: Schema,
    shape: PayloadShape | None = None,
    *,
    earliest: str | None = None,
    latest: str | None = None,
) -> ValidationReport:
    """Check ``spl`` against the discovered schema and payload shape."""
    errors: list[str] = []
    warnings: list[str] = []

    text = (spl or "").strip()
    if not text:
        return ValidationReport(ok=False, errors=("No SPL was generated.",))

    # -- read-only ---------------------------------------------------------
    # Stage 4's hard guardrail. It runs first because nothing else about a
    # query matters if the query is not allowed to run at all.
    verdict = read_only_verdict(text)
    if not verdict.allowed:
        errors.append(verdict.reason)

    # -- index targeting ---------------------------------------------------
    indexes = {m.lower() for m in _INDEX_RE.findall(text)}
    if not indexes:
        warnings.append(
            f"The query does not name an index. It will run against the token's "
            f"default indexes, not necessarily {schema.index!r}."
        )
    else:
        wrong = indexes - {schema.index.lower()}
        if wrong:
            errors.append(
                f"The query targets index {', '.join(sorted(wrong))} but the "
                f"discovered schema describes {schema.index!r}. Field names are "
                "only known to be correct for that index."
            )

    # -- time range --------------------------------------------------------
    for label, value in (("earliest", earliest), ("latest", latest)):
        if value is None or value == "":
            continue
        if not _TIME_RE.match(value.strip()):
            errors.append(
                f"{label}={value!r} is not a Splunk time modifier (expected an "
                "epoch, a relative modifier such as '-7d@d', or MM/DD/YYYY:HH:MM:SS)."
            )

    # -- fields ------------------------------------------------------------
    defined = _defined_fields(text, shape)
    referenced = _referenced_fields(text)
    uses_extraction = spl_uses_extraction(text)

    flat = {f.name for f in schema.fields} | _ALWAYS_VALID_FIELDS
    flat_lower = {name.lower() for name in flat}
    nested = set(shape.nested_names) if shape else set()
    nested_lower = {name.lower() for name in nested}

    unextracted: list[str] = []
    unknown: list[str] = []

    for name in referenced:
        lowered = name.lower()
        if lowered in flat_lower or name in defined or lowered in {d.lower() for d in defined}:
            continue
        if lowered in nested_lower:
            # Known to exist, but only inside the container. Referencing it flat
            # is the silent-empty-result bug.
            unextracted.append(name)
        else:
            unknown.append(name)

    contradiction = _contradictory_selector(text, schema)
    if contradiction:
        errors.append(contradiction)

    placeholder = _PLACEHOLDER_RE.search(text)
    if placeholder is not None:
        errors.append(
            f"{placeholder.group(0)!r} looks like unsubstituted template text, not a "
            f"real value. A filter containing it matches nothing, and the empty "
            f"result would read as 'no such evidence' when it means 'the filter was "
            f"never filled in'. Replace it with a value from the question, or from a "
            f"row an earlier search returned."
        )

    if unextracted and shape is not None:
        errors.append(_nested_field_error(sorted(set(unextracted)), shape, schema))

    if unknown:
        warnings.append(
            f"Not found in the discovered schema and not created by the query: "
            f"{', '.join(sorted(set(unknown)))}. Either the name is wrong, or the "
            "static check misread the SPL — confirm before running."
        )

    return ValidationReport(
        ok=not errors,
        errors=tuple(errors),
        warnings=tuple(warnings),
        referenced=tuple(sorted(set(referenced))),
        defined=tuple(sorted(defined)),
        unextracted_nested=tuple(sorted(set(unextracted))),
        uses_extraction=uses_extraction,
        read_only=verdict,
    )


# --------------------------------------------------------------------------
# Field-reference scanning
# --------------------------------------------------------------------------


#: A literal ``EventId=4624`` / ``Channel="Security"`` pinned in the query. Only
#: single, unambiguous values count: a wildcard, an OR or an IN is the author
#: deliberately casting wide, and narrowing it for them would be the wrong kind
#: of help.
_EVENT_ID_PIN_RE: Final[re.Pattern[str]] = re.compile(
    r'\bEventId\s*=\s*"?(\d{1,6})"?', re.IGNORECASE
)
_CHANNEL_PIN_RE: Final[re.Pattern[str]] = re.compile(
    r'\bChannel\s*=\s*"([^"*]+)"', re.IGNORECASE
)


def _contradictory_selector(text: str, schema: Schema) -> str:
    """Report an event id paired with a channel it never appears on.

    Both halves are real: the field names exist, the event id exists, the
    channel exists. Only the combination does not, so every check that looks at
    names individually passes and the query returns zero — which reads as "no
    such activity" rather than "that pairing cannot occur".

    Measured: a 14B asked for a logon took ``EventId=4624`` from the right
    library entry and ``Channel="Microsoft-Windows-Sysmon/Operational"`` from
    the entries around it, three runs out of three, and concluded there were no
    logons. The pairing is checked against what Stage 1 measured on this index,
    never a built-in list, so a dataset with different channels is judged by its
    own contents.
    """
    if not schema.event_channels:
        return ""

    ids = _EVENT_ID_PIN_RE.findall(text)
    channels = _CHANNEL_PIN_RE.findall(text)
    if len(ids) != 1 or len(channels) != 1:
        return ""

    event_id, channel = ids[0], channels[0].strip()
    seen = schema.channels_for(event_id)
    if not seen or channel in seen:
        return ""

    listed = ", ".join(sorted(seen))
    return (
        f'EventId={event_id} never appears on Channel="{channel}" in this index. '
        f"Both halves are real, but the combination occurs nowhere, so this query "
        f"is guaranteed to return zero rows — and an empty result would read as "
        f'"no such activity" rather than "wrong channel". EventId={event_id} was '
        f"observed only on: {listed}. Fix the Channel, or drop it and filter on "
        f"EventId alone."
    )


def _nested_field_error(
    names: list[str],
    shape: PayloadShape,
    schema: Schema,
) -> str:
    """Explain the nested-vs-flat mistake by showing the whole corrected query.

    An earlier version of this message showed only the ``eval`` fragment. Against
    a live 7B that was not enough: told twice that ``Image`` is nested, it kept
    writing ``index=logforge EventId=1 Image="powershell.exe"`` — it had learned
    that an extraction exists without learning that the *filter has to move* to
    the other side of it. A fragment says what to add; it does not say what to
    stop doing. So the message now shows a complete, runnable query and names the
    ordering rule explicitly.
    """
    first = names[0]
    extraction = "\n".join(
        f"    | eval {name} = mvindex('{shape.text_path}', "
        f"mvfind('{shape.name_path}', \"^{name}$\"))"
        for name in names
    )
    return (
        f"{', '.join(names)} live inside the '{shape.container}' field, not as "
        f"top-level column(s). Referencing them directly matches nothing and "
        f"returns zero rows silently.\n"
        f"    Extract first, THEN filter on the extracted name. The filter must "
        f"come after the eval — a nested name in the base search, before "
        f"'{shape.container}' has been opened, matches nothing:\n\n"
        f"    index={schema.index} EventId=<id>\n"
        f"    | spath input={shape.container}\n"
        f"{extraction}\n"
        f'    | search {first}="<value>"\n'
        f"    | table {', '.join(names)}\n\n"
        f'    NOT: index={schema.index} {first}="<value>"   <- matches nothing.'
    )


def _defined_fields(spl: str, shape: PayloadShape | None) -> set[str]:
    """Names the query creates, which are therefore legitimate downstream."""
    defined: set[str] = set()

    for match in _AS_RE.finditer(spl):
        defined.add(match.group(1))
    for match in _EVAL_RE.finditer(spl):
        defined.add(match.group(1) or match.group(2))
    for match in _REX_CAPTURE_RE.finditer(spl):
        defined.add(match.group(1))
    for match in _OUTPUT_RE.finditer(spl):
        defined.add(match.group(1))
    for match in _RENAME_RE.finditer(spl):
        defined.add(match.group(1))

    # `spath input=<container>` publishes the container's internal paths as
    # fields, so those become referenceable too.
    if shape is not None and shape.container and re.search(r"\bspath\b", spl, re.IGNORECASE):
        defined.update({shape.name_path, shape.text_path} - {""})
        defined.update(name for name in shape.nested_names if "." in name)

    defined.discard("")
    return defined


def _referenced_fields(spl: str) -> list[str]:
    """Best-effort list of field names the query reads."""
    found: list[str] = []

    def keep(name: str) -> None:
        cleaned = name.strip().strip('"').strip("'")
        if not cleaned or cleaned in found:
            return
        if cleaned.lower() in _SPL_KEYWORDS or cleaned.lower() in _COMMAND_OPTIONS:
            return
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", cleaned):
            return
        found.append(cleaned)

    for match in _BY_RE.finditer(spl):
        for part in match.group(1).split(","):
            # A `by` clause ends at the next command word; take the leading name.
            token = part.strip().split()[0] if part.strip() else ""
            keep(token)

    for match in _COMPARE_RE.finditer(spl):
        keep(match.group(1))

    for match in _AGG_RE.finditer(spl):
        keep(match.group(1))

    for match in _FIELD_LIST_RE.finditer(spl):
        for part in match.group(1).split(","):
            for token in part.split():
                if token.lower() in ("as", "asc", "desc") or token.startswith(("-", "+")):
                    continue
                keep(token)

    for match in _QUOTED_FIELD_RE.finditer(spl):
        # Single quotes denote a field name in SPL (double quotes are strings).
        keep(match.group(1))

    return found
