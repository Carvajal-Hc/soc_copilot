"""Does the query answer the question that was asked?

Every other check in this project is about safety or well-formedness. This one
is about *intent*, and it exists because of F1 in NOTES.md: a local model, asked
what each process connected to on the network, produced SPL that was read-only,
used real discovered field names, extracted the nested payload correctly, ran
cleanly and returned real rows — and grouped by ``DestinationIp``. It answered
"which destinations were contacted?" when the question was "which process was
doing the contacting?". Nothing in the pipeline had a reason to complain.

The check here is deliberately modest, and it is worth being precise about what
it is and is not:

* It is a **detection**, not a fix. It never rewrites a query and never blocks
  one. It surfaces a warning beside the answer naming the question's subject and
  what the SPL actually grouped by, and the analyst decides.
* It is **conservative by construction**. It only speaks when the question
  contains an explicit subject marker ("each *process*", "which *hosts*", "per
  *user*") and the query's output carries no field of that kind. An unrecognised
  question shape produces silence, not a guess.
* It is **not a semantic model**. It does not understand the question. It
  compares two small extractions — the noun the question is enumerating, and the
  fields that survive to the query's output — and reports when they do not line
  up.

A check that fires on everything is noise an analyst learns to skip, which is
worse than no check at all. So the bar for speaking is high, and the tests hold
it to both directions: it must flag the Q3 shape, and it must stay silent on the
correct query for the same question.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from soc_copilot.guardrails import split_pipeline
from soc_copilot.payload_shape import PayloadShape
from soc_copilot.schema import Schema

__all__ = [
    "CONCEPTS",
    "AlignmentReport",
    "check_alignment",
    "classify_field",
    "output_fields",
    "question_subjects",
]


# --------------------------------------------------------------------------
# The vocabulary
# --------------------------------------------------------------------------

#: Entity kinds a triage question is usually *about*, each with the field-name
#: fragments that represent it and the question words that name it.
#:
#: The field fragments are matched against whatever names the query actually
#: uses; nothing here asserts that a field exists. Schema truth stays where it
#: belongs, in Stage 1 discovery and :mod:`soc_copilot.validation`.
#:
#: Classification is deliberately multi-label. ``DestinationHostname`` is both a
#: network destination and a host, and counting it as both means a question
#: about hosts will not be flagged against it. Every ambiguity is resolved
#: toward silence.
CONCEPTS: Final[Mapping[str, Mapping[str, tuple[str, ...]]]] = {
    "process": {
        "fields": (
            "processguid", "processid", "image", "parentimage", "parentprocessguid",
            "parentprocessid", "newprocessname", "parentcommandline", "commandline",
            "originalfilename", "parentimagepath", "callertrace",
        ),
        "nouns": (
            "process", "processes", "executable", "executables", "binary",
            "binaries", "program", "programs", "parent process", "child process",
        ),
    },
    "host": {
        "fields": (
            "computer", "hostname", "host", "workstation", "machinename",
            "computername", "dvc",
        ),
        "nouns": (
            "host", "hosts", "computer", "computers", "machine", "machines",
            "endpoint", "endpoints", "workstation", "workstations", "device",
            "devices", "system", "systems",
        ),
    },
    "user": {
        "fields": (
            "user", "username", "userid", "accountname", "subjectusername",
            "targetusername", "logonid", "accountdomain", "sid", "securityid",
        ),
        "nouns": (
            "user", "users", "account", "accounts", "logon", "logons",
            "identity", "identities",
        ),
    },
    "network_destination": {
        "fields": (
            "destinationip", "destinationhostname", "destinationport",
            "destinationportname", "destinationisipv6", "queryname", "queryresults",
            "remotehost", "remoteaddress", "url", "uri",
        ),
        "nouns": (
            "destination", "destinations", "ip", "ips", "address", "addresses",
            "domain", "domains", "server", "servers", "remote host", "endpoint ip",
        ),
    },
    "network_source": {
        "fields": ("sourceip", "sourceport", "sourcehostname", "sourceisipv6"),
        "nouns": ("source ip", "source address", "source port"),
    },
    "file": {
        "fields": (
            "targetfilename", "filename", "sourcefile", "filepath", "imageloaded",
            "pipename",
        ),
        "nouns": (
            "file", "files", "filename", "filenames", "document", "documents",
            "path", "paths", "dll", "dlls",
        ),
    },
    "registry": {
        "fields": ("targetobject", "registrykey", "registryvalue", "newname"),
        "nouns": ("registry", "registry key", "registry keys", "run key"),
    },
    "event": {
        "fields": (
            "eventid", "eventtype", "channel", "mapdescription", "provider",
            "eventrecordid", "task", "opcode", "level", "keywords",
        ),
        "nouns": (
            "event", "events", "event id", "event ids", "event type",
            "event types", "channel", "channels", "log", "logs",
        ),
    },
}

#: Words that mark the noun after them as the thing being enumerated — the
#: question's subject rather than something merely mentioned. This is the whole
#: reason the check can tell Q3's subject ("each **process**") from the network
#: destination the same sentence also names.
_SUBJECT_MARKERS: Final[tuple[str, ...]] = (
    "each", "per", "every", "which", "what", "whose", "by",
    "top", "list", "show me", "group by", "grouped by", "for each", "how many",
)

_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:" + "|".join(re.escape(m) for m in _SUBJECT_MARKERS) + r")\b",
    re.IGNORECASE,
)

#: How far past a marker to look for the noun it introduces. A question says
#: "which .evtx source files ..." as readily as "which files ...", and a pattern
#: that demanded the noun sit immediately after the marker missed the first
#: form entirely — reporting the query as misaligned when it was correct.
_SUBJECT_WINDOW: Final[int] = 45

#: Commands that rebuild the result set from scratch: whatever they do not name,
#: the rows no longer carry.
_RESHAPING: Final[frozenset[str]] = frozenset(
    {"stats", "chart", "timechart", "top", "rare", "sistats", "sichart",
     "sitimechart", "sitop", "sirare", "eventstats", "tstats", "mstats",
     "contingency", "xyseries", "untable", "transpose"}
)
#: Commands that narrow an existing result set to a named list of fields.
_PROJECTING: Final[frozenset[str]] = frozenset({"table", "fields"})
#: Commands that introduce a name without discarding anything.
_CREATING: Final[frozenset[str]] = frozenset({"eval", "rex", "rename", "spath", "extract"})

_BY_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:by|over)\s+([^|\]]+)", re.IGNORECASE)
_AGG_ARG_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[a-z_0-9]+\s*\(\s*'?([A-Za-z_][A-Za-z0-9_.{}#@]*)'?\s*\)", re.IGNORECASE
)
_AS_RE: Final[re.Pattern[str]] = re.compile(
    r"\bas\s+\"?'?([A-Za-z_][A-Za-z0-9_.]*)\"?'?", re.IGNORECASE
)
_EVAL_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|,)\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=", re.MULTILINE
)
_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_.{}#@]*$")

#: Never treated as an entity the analyst asked about.
_NOT_FIELDS: Final[frozenset[str]] = frozenset(
    {"count", "limit", "span", "as", "by", "over", "output", "input", "sort",
     "asc", "desc", "usenull", "useother", "where", "percent", "total"}
)


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AlignmentReport:
    """Whether the query's output lines up with what the question asked about."""

    #: False only when the check is confident enough to speak. True covers both
    #: "they line up" and "no opinion", which are deliberately not distinguished
    #: to callers deciding whether to warn.
    ok: bool = True
    #: Concept names the question appears to be enumerating, e.g. ``("process",)``.
    subjects: tuple[str, ...] = ()
    #: The words in the question that identified them, quoted back verbatim so
    #: the analyst can see what was read rather than trusting a label.
    subject_terms: tuple[str, ...] = ()
    #: Fields the query's output actually carries.
    output: tuple[str, ...] = ()
    #: The subset of those that are grouping keys — the pivot, in Q3's terms.
    grouped_by: tuple[str, ...] = ()
    #: Concepts those output fields represent.
    output_concepts: tuple[str, ...] = ()
    #: True when no field of the subject's kind exists anywhere in the schema,
    #: which changes the advice from "regroup it" to "this index cannot answer it".
    subject_absent_from_schema: bool = False
    #: Why the check stayed silent, when it did. For debugging, not for display.
    quiet_reason: str = ""

    @property
    def warning(self) -> str:
        """The analyst-facing warning, or empty when there is nothing to say."""
        if self.ok:
            return ""
        subject = ", ".join(self.subject_terms) or ", ".join(self.subjects)
        grouped = ", ".join(self.grouped_by or self.output) or "(nothing)"
        lines = [
            f"This query may not answer what was asked. The question is about "
            f"{subject!r}, but the results are grouped by {grouped} and carry no "
            f"field identifying a {'/'.join(self.subjects)}.",
        ]
        if self.subject_absent_from_schema:
            lines.append(
                f"    No field representing a {'/'.join(self.subjects)} was found in "
                "the discovered schema at all, so this index may simply not hold it."
            )
        else:
            lines.append(
                "    Check whether the grouping key is the entity you asked about. "
                "Both readings can be valid questions over the same events."
            )
        lines.append(
            "    Not blocked and not corrected — this is a judgement call, and it "
            "is yours."
        )
        return "\n".join(lines)

    def render(self) -> str:
        if self.ok:
            return "  [ok]      query output lines up with the question's subject."
        return "\n".join(f"  [warning] {line.strip()}" for line in self.warning.splitlines())


# --------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------


def check_alignment(
    question: str,
    spl: str,
    schema: Schema | None = None,
    shape: PayloadShape | None = None,
) -> AlignmentReport:
    """Compare what ``question`` enumerates against what ``spl`` outputs.

    Returns a report whose ``ok`` is False only when the check is confident: the
    question named a subject explicitly, the query reshapes its output, and no
    output field represents that subject. Every other path returns ``ok=True``
    with a ``quiet_reason``, because a semantic warning that fires on ambiguity
    is a semantic warning nobody reads.
    """
    subjects = question_subjects(question)
    if not subjects:
        return AlignmentReport(quiet_reason="no explicit subject in the question")

    concepts = tuple(sorted({c for c, _ in subjects}))
    terms = tuple(dict.fromkeys(term for _, term in subjects))

    surviving, grouped = output_fields(spl)
    if surviving is None:
        # No reshaping command: the rows are whole events and still carry every
        # field. There is nothing missing from the output to complain about.
        return AlignmentReport(
            subjects=concepts,
            subject_terms=terms,
            quiet_reason="query does not reshape its output; full events are returned",
        )

    out_concepts: set[str] = set()
    for name in surviving:
        out_concepts.update(classify_field(name))

    # "how many events" asks for a count of events, and a count is what a count
    # aggregation produces. No field name will ever carry that concept, so
    # without this an ordinary volume question reads as misaligned.
    if "event" in concepts and _counts_events(spl):
        out_concepts.add("event")

    # Any one satisfied subject is enough. A question naming several entities
    # ("which source files, and how many events") is answered by a query that
    # groups by one of them, and demanding all of them would flag correct work.
    if out_concepts & set(concepts):
        return AlignmentReport(
            subjects=concepts,
            subject_terms=terms,
            output=surviving,
            grouped_by=grouped,
            output_concepts=tuple(sorted(out_concepts)),
        )

    return AlignmentReport(
        ok=False,
        subjects=concepts,
        subject_terms=terms,
        output=surviving,
        grouped_by=grouped,
        output_concepts=tuple(sorted(out_concepts)),
        subject_absent_from_schema=_absent_from_schema(concepts, schema, shape),
    )


def question_subjects(question: str) -> tuple[tuple[str, str], ...]:
    """The concepts a question explicitly enumerates, with the words that said so.

    Only nouns carrying a subject marker count. "what did each **process**
    connect to on the network" yields ``process`` and not ``network``, which is
    the distinction the whole check rests on — both words are in the sentence,
    but only one is the thing being asked about.
    """
    text = (question or "").lower()
    found: list[tuple[str, str]] = []

    for match in _MARKER_RE.finditer(text):
        window = text[match.end() : match.end() + _SUBJECT_WINDOW]
        for concept, spec in CONCEPTS.items():
            for noun in spec["nouns"]:
                if re.search(rf"\b{re.escape(noun)}\b", window):
                    pair = (concept, noun)
                    if pair not in found:
                        found.append(pair)
                    break
    return tuple(found)


def output_fields(spl: str) -> tuple[tuple[str, ...] | None, tuple[str, ...]]:
    """Fields that survive to the query's output, and which of them group it.

    Walking the pipeline in order is the point. ``| eval Image = ... | stats
    count by DestinationIp`` mentions ``Image``, but ``stats`` rebuilds the
    result set around its own keys and the field is gone by the time anything is
    returned. A check that scanned the whole query for the word "Image" would
    call Q3 correct.

    Returns ``(None, ())`` when no command reshapes the output, meaning whole
    events are returned and every field is still present.
    """
    surviving: set[str] | None = None
    grouped: tuple[str, ...] = ()

    for stage in split_pipeline(spl or ""):
        command = stage.command
        if command in _RESHAPING:
            keys = _by_fields(stage.text)
            produced = _agg_fields(stage.text) | _as_names(stage.text)
            if command in ("top", "rare"):
                keys = keys or _bare_field_list(stage.text, command)
            surviving = set(keys) | produced
            grouped = tuple(keys)
        elif command in _PROJECTING:
            named = _bare_field_list(stage.text, command)
            if named:
                surviving = set(named)
        elif command in _CREATING and surviving is not None:
            surviving |= _eval_names(stage.text) | _as_names(stage.text)

    if surviving is None:
        return None, ()
    return tuple(sorted(surviving)), grouped


_COUNTING_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:count|dc|distinct_count|estdc)\s*\("
    r"|\bstats\b[^|]*\bcount\b"
    r"|\|\s*(?:top|rare)\b",
    re.IGNORECASE,
)


def _counts_events(spl: str) -> bool:
    """True when the query produces an event count rather than event fields."""
    return bool(_COUNTING_RE.search(spl or ""))


def classify_field(name: str) -> set[str]:
    """Concepts a field name represents. Multi-label, and permissive by design."""
    lowered = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    if not lowered:
        return set()
    return {
        concept
        for concept, spec in CONCEPTS.items()
        if any(fragment in lowered for fragment in spec["fields"])
    }


def _absent_from_schema(
    concepts: Sequence[str],
    schema: Schema | None,
    shape: PayloadShape | None,
) -> bool:
    """True when the discovered schema holds no field of any named concept."""
    if schema is None:
        return False
    names = list(schema.field_names)
    if shape is not None:
        names += list(shape.nested_names)
    wanted = set(concepts)
    return not any(classify_field(name) & wanted for name in names)


# --------------------------------------------------------------------------
# Small extractors
# --------------------------------------------------------------------------


def _by_fields(text: str) -> list[str]:
    names: list[str] = []
    for match in _BY_RE.finditer(text):
        for part in match.group(1).split(","):
            token = part.strip().strip("'\"")
            token = token.split()[0] if token.split() else ""
            _keep(token, names)
    return names


def _agg_fields(text: str) -> set[str]:
    found: set[str] = set()
    for match in _AGG_ARG_RE.finditer(text):
        _keep(match.group(1), found)
    return found


def _as_names(text: str) -> set[str]:
    found: set[str] = set()
    for match in _AS_RE.finditer(text):
        _keep(match.group(1), found)
    return found


def _eval_names(text: str) -> set[str]:
    """Names an ``eval`` / ``rename`` stage introduces.

    The command word is stripped first: in ``eval Image="n/a"`` the new name
    follows the keyword rather than a comma or a line start, and a pattern
    anchored only on those misses the first assignment of every stage.
    """
    body = re.sub(r"^\s*(?:eval|rename|spath|rex|extract)\b", ",", text, count=1,
                  flags=re.IGNORECASE)
    found: set[str] = set()
    for match in _EVAL_NAME_RE.finditer(body):
        _keep(match.group(1), found)
    return found


def _bare_field_list(text: str, command: str) -> list[str]:
    """Field names after ``table`` / ``fields`` / ``top`` / ``rare``."""
    body = re.sub(rf"^\s*{command}\b", "", text, count=1, flags=re.IGNORECASE)
    body = re.sub(r"\b(?:limit|countfield|percentfield|showcount|showperc|useother)"
                  r"\s*=\s*\S+", " ", body, flags=re.IGNORECASE)
    body = _BY_RE.sub(" ", body)
    names: list[str] = []
    for part in body.split(","):
        for token in part.split():
            if token.lower() in ("as",) or token.startswith(("-", "+")):
                continue
            _keep(token.strip("'\""), names)
    return names


def _keep(token: str, into: list[str] | set[str]) -> None:
    cleaned = (token or "").strip().strip("'\"")
    if not cleaned or cleaned.lower() in _NOT_FIELDS:
        return
    if not _NAME_RE.match(cleaned):
        return
    if isinstance(into, list):
        if cleaned not in into:
            into.append(cleaned)
    else:
        into.add(cleaned)
