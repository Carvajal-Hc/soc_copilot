"""Discover the *shape* of nested data inside an index, at runtime.

Stage 1 answers "what fields exist?". That is not enough to write correct SPL,
because Windows/Sysmon-style exports keep the interesting values (ProcessGuid,
Image, CommandLine, hashes, target paths) *inside* a structured payload field
rather than as top-level columns. A query like ``... | stats count by ProcessGuid``
then returns nothing at all — the field is real, but it is not flat.

This module samples real events and reports:

* which discovered field (if any) holds structured content, and in what encoding;
* how that content is laid out — a flat object, or a name/value array;
* which nested names actually occur, and under which event types;
* which flat fields form a positional "split" family (``PayloadDataN``).

Everything here is deterministic and derived from sampled rows. No LLM, and no
field name is assumed: a firewall CSV, a Sysmon CSV and an EVTX export all take
the same code path and produce different answers.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Final
from xml.etree import ElementTree

from soc_copilot.schema import Schema, validate_index_name
from soc_copilot.splunk_client import (
    ALL_TIME_EARLIEST,
    ALL_TIME_LATEST,
    SplunkClient,
)

log = logging.getLogger(__name__)

#: Fields Splunk adds to every event in every index. They describe the *ingest*,
#: not the dataset, so they are never payload containers and never useful for
#: stratifying a sample. Excluding them is dataset-independent.
SPLUNK_METADATA_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "eventtype",
        "host",
        "index",
        "linecount",
        "punct",
        "source",
        "sourcetype",
        "splunk_server",
        "splunk_server_group",
        "tag",
        "timeendpos",
        "timestartpos",
    }
)

#: ``date_*`` is another Splunk-added family (date_hour, date_wday, …).
_SPLUNK_METADATA_PREFIXES: Final[tuple[str, ...]] = ("date_", "tag::")

#: Only plain field names can be interpolated into a ``| table`` safely.
_SAFE_FIELD_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

#: A nested name we would be willing to use as an SPL field name.
_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: ``PayloadData1``, ``PayloadData2``… — a positional family.
_NUMERIC_SUFFIX_RE: Final[re.Pattern[str]] = re.compile(r"^(?P<base>.+?)(?P<n>\d+)$")

#: How many distinct values a field may have and still be useful for spreading a
#: sample across event types. Above this it is closer to an identifier than a
#: category.
_MAX_STRATIFY_CARDINALITY: Final[int] = 600

#: At or below this many distinct values a field reads as a true category
#: (Channel, Provider, Level) rather than a type code with many members.
_CATEGORY_CARDINALITY: Final[int] = 200

#: Fraction of a candidate name-key's observed values that must be plain
#: identifiers before it is accepted as the key holding nested field *names*.
_NAME_KEY_IDENTIFIER_RATIO: Final[float] = 0.7


@dataclass(frozen=True)
class EventTypeShape:
    """The nested names observed for one combination of categorical values.

    ``key`` is ordered the same way as :attr:`PayloadShape.stratified_by`, e.g.
    ``("Microsoft-Windows-Sysmon/Operational", "1")``.
    """

    key: tuple[str, ...]
    nested_names: tuple[str, ...]
    #: A human-readable label for this event type when the data supplies one.
    label: str = ""

    def describe(self) -> str:
        head = " / ".join(k for k in self.key if k)
        if self.label:
            head = f"{head} ({self.label})"
        return f"{head}: {', '.join(self.nested_names)}"


@dataclass(frozen=True)
class SplitFieldFamily:
    """Flat fields that share a base name and differ only by a trailing number.

    EvtxECmd's ``PayloadData1..N`` are the canonical example. Their meaning is
    *positional and varies by event type* — ``PayloadData1`` is not the same
    thing for a Sysmon process-create as for a Security logon — so they are a
    convenience for eyeballing, never a substitute for extracting from the
    container.
    """

    base: str
    members: tuple[str, ...]


@dataclass(frozen=True)
class PayloadShape:
    """What sampling found out about nested data in one index."""

    index: str
    #: The flat field holding structured content, or ``None`` if there is none.
    container: str | None = None
    #: ``"json"``, ``"xml"`` or ``"none"``.
    encoding: str = "none"
    #: ``"name-value-array"``, ``"object"`` or ``"none"``.
    layout: str = "none"
    #: For a name/value array: the spath paths of the parallel arrays.
    name_path: str = ""
    text_path: str = ""
    #: Every nested name seen anywhere in the sample.
    nested_names: tuple[str, ...] = ()
    #: Categorical fields used to spread the sample, in order.
    stratified_by: tuple[str, ...] = ()
    #: Per-event-type nested names.
    event_types: tuple[EventTypeShape, ...] = ()
    split_families: tuple[SplitFieldFamily, ...] = ()
    sampled_events: int = 0
    #: Set when the sample was taken but no container was found, explaining why.
    note: str = ""

    @property
    def is_nested(self) -> bool:
        return self.container is not None and bool(self.nested_names)

    @property
    def split_field_names(self) -> tuple[str, ...]:
        return tuple(m for fam in self.split_families for m in fam.members)

    def names_for(self, *values: str) -> tuple[str, ...]:
        """Nested names for event types whose key contains all of ``values``."""
        wanted = {v for v in values if v}
        out: list[str] = []
        for et in self.event_types:
            if wanted.issubset(set(et.key)):
                out.extend(n for n in et.nested_names if n not in out)
        return tuple(out)


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------


def probe_payload_shape(
    client: SplunkClient,
    schema: Schema,
    *,
    sample_size: int = 800,
    min_container_ratio: float = 0.5,
    earliest: str = ALL_TIME_EARLIEST,
    latest: str = ALL_TIME_LATEST,
) -> PayloadShape:
    """Sample ``schema.index`` and describe any nested payload it contains.

    Args:
        sample_size: Upper bound on events pulled. The sample is spread across
            event types (see :func:`choose_stratify_fields`) so that rare event
            types still contribute their nested names.
        min_container_ratio: Fraction of a field's non-empty sampled values that
            must parse as structured content before it is called a container.

    Returns:
        A :class:`PayloadShape`. ``is_nested`` is False when the data really is
        flat — that is a valid answer, not a failure.
    """
    index = validate_index_name(schema.index)
    candidates = candidate_container_fields(schema)

    if not candidates:
        return PayloadShape(
            index=index,
            note="No candidate fields to sample; the schema has no non-metadata fields.",
        )

    cardinality = measure_cardinality(
        client, index, candidates, earliest=earliest, latest=latest
    )
    stratify = choose_stratify_fields(schema, cardinality)

    columns = list(dict.fromkeys([*stratify, *candidates]))
    spl = f"index={index}"
    if stratify:
        spl += " | dedup " + ", ".join(stratify)
    spl += f" | head {int(sample_size)} | table " + ", ".join(columns)

    rows = client.run_search(spl, earliest=earliest, latest=latest)
    log.info("Payload probe sampled %d event(s) from index=%s", len(rows), index)

    return analyze_rows(
        rows,
        index=index,
        candidates=candidates,
        stratify=tuple(stratify),
        split_families=detect_split_families(schema),
        min_container_ratio=min_container_ratio,
    )


def candidate_container_fields(schema: Schema) -> list[str]:
    """Discovered fields that could plausibly hold structured content.

    Only Splunk's own metadata fields and unsafe names are excluded. Whether a
    field *is* a container is decided by parsing its values, not by its name.
    """
    out: list[str] = []
    for f in schema.fields:
        name = f.name
        if f.is_internal or name in SPLUNK_METADATA_FIELDS:
            continue
        if name.startswith(_SPLUNK_METADATA_PREFIXES):
            continue
        if not _SAFE_FIELD_RE.match(name):
            continue
        if f.counts_known and f.event_count == 0:
            continue
        out.append(name)
    return out


def measure_cardinality(
    client: SplunkClient,
    index: str,
    fields: list[str],
    *,
    earliest: str = ALL_TIME_EARLIEST,
    latest: str = ALL_TIME_LATEST,
) -> dict[str, int]:
    """Count distinct values per field, exactly, in one search.

    ``fieldsummary`` reports an *estimate* capped at 500 (``is_exact=0``), which
    makes a 60,000-value identifier look identical to a 500-value category. Any
    choice that depends on "is this a category or an identifier?" must measure
    rather than trust that estimate.
    """
    safe = [f for f in fields if _SAFE_FIELD_RE.match(f)]
    if not safe:
        return {}
    aggs = ", ".join(f"dc({name}) as {name}" for name in safe)
    rows = client.run_search(
        f"index={index} | stats {aggs}", earliest=earliest, latest=latest
    )
    if not rows:
        return {}

    counts: dict[str, int] = {}
    for name, value in rows[0].items():
        try:
            counts[name] = int(float(value))
        except (TypeError, ValueError):
            continue
    return counts


def choose_stratify_fields(
    schema: Schema,
    cardinality: dict[str, int] | None = None,
    limit: int = 2,
) -> list[str]:
    """Pick categorical fields to spread a sample across event types.

    Chooses the most discriminating fields that are still categories rather than
    identifiers: highest distinct count at or below
    :data:`_MAX_STRATIFY_CARDINALITY`. Derived from the discovered schema, so a
    firewall CSV strata on its own fields, not on ``Channel``/``EventId``.

    Args:
        cardinality: Measured distinct counts from :func:`measure_cardinality`.
            Strongly preferred; without it this falls back to ``fieldsummary``'s
            estimates and will only consider fields whose counts are exact,
            because an inexact count cannot distinguish a category from an
            identifier.
    """
    usable: list[tuple[int, str]] = []
    for f in schema.fields:
        if (
            f.is_internal
            or f.name in SPLUNK_METADATA_FIELDS
            or f.name.startswith(_SPLUNK_METADATA_PREFIXES)
            or not _SAFE_FIELD_RE.match(f.name)
        ):
            continue

        if cardinality is not None:
            count = cardinality.get(f.name)
            if count is None:
                continue
        elif f.counts_known and f.is_exact:
            count = f.distinct_count
        else:
            continue

        if 1 < count <= _MAX_STRATIFY_CARDINALITY:
            usable.append((count, f.name))

    # Cardinality alone cannot tell a category from an identifier: on the lab
    # index EventId (530 values, a category) and ProcessId (511 values, an
    # identifier) are indistinguishable by count. Draw one field from each band
    # instead — the widest "type-like" field, then the widest true category —
    # which yields a pair that partitions event types rather than two near-
    # identifiers. Both bounds are relative to the data, not to any dataset.
    wide = sorted(
        (p for p in usable if p[0] > _CATEGORY_CARDINALITY),
        key=lambda p: (-p[0], p[1]),
    )
    tight = sorted(
        (p for p in usable if p[0] <= _CATEGORY_CARDINALITY),
        key=lambda p: (-p[0], p[1]),
    )

    chosen: list[str] = []
    for band in (wide, tight):
        if band and len(chosen) < limit:
            chosen.append(band[0][1])
    # Backfill from whichever band still has entries.
    for _, name in [*wide, *tight]:
        if len(chosen) >= limit:
            break
        if name not in chosen:
            chosen.append(name)
    return chosen


def detect_split_families(schema: Schema) -> tuple[SplitFieldFamily, ...]:
    """Group discovered fields that differ only by a trailing number."""
    groups: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for f in schema.fields:
        if f.is_internal:
            continue
        match = _NUMERIC_SUFFIX_RE.match(f.name)
        if match:
            groups[match.group("base")].append((int(match.group("n")), f.name))

    families = [
        SplitFieldFamily(base=base, members=tuple(n for _, n in sorted(members)))
        for base, members in groups.items()
        if len(members) > 1
    ]
    families.sort(key=lambda fam: fam.base)
    return tuple(families)


# --------------------------------------------------------------------------
# Analysis (pure — unit-testable without Splunk)
# --------------------------------------------------------------------------


def analyze_rows(
    rows: list[dict[str, Any]],
    *,
    index: str,
    candidates: list[str],
    stratify: tuple[str, ...],
    split_families: tuple[SplitFieldFamily, ...] = (),
    min_container_ratio: float = 0.5,
) -> PayloadShape:
    """Decide the payload shape from sampled rows. Pure function, no I/O."""
    if not rows:
        return PayloadShape(
            index=index,
            stratified_by=stratify,
            split_families=split_families,
            note="The sample returned no events, so nested structure is unknown.",
        )

    container, encoding = _pick_container(rows, candidates, min_container_ratio)
    if container is None:
        return PayloadShape(
            index=index,
            stratified_by=stratify,
            split_families=split_families,
            sampled_events=len(rows),
            note=(
                f"No field in the {len(rows)}-event sample held parseable "
                "structured content; treat this index as flat."
            ),
        )

    parsed_rows = [(row, _parse(row.get(container), encoding)) for row in rows]
    parsed_rows = [(row, doc) for row, doc in parsed_rows if doc is not None]

    # Which of the array's two keys holds the *names* cannot be decided from a
    # single event: with short values both keys can look like identifiers. Decide
    # it once, from the whole sample (see _resolve_name_key).
    root_path, name_key, text_key = _resolve_name_key(doc for _, doc in parsed_rows)
    layout = "name-value-array" if name_key else "none"

    per_type: dict[tuple[str, ...], list[str]] = {}
    labels: dict[tuple[str, ...], str] = {}
    all_names: list[str] = []

    for row, parsed in parsed_rows:
        names = _names_from_array(parsed, root_path, name_key) if name_key else []
        if not names:
            # Either there is no name/value array at all, or this event type
            # simply uses a different payload schema. Both are real; fall back to
            # reading its object keys so its names are still discovered.
            names, object_layout = _names_from_object(parsed)
            if names and layout == "none":
                layout = object_layout
        if not names:
            continue

        key = tuple(str(row.get(f, "") or "") for f in stratify)
        bucket = per_type.setdefault(key, [])
        for name in names:
            if name not in bucket:
                bucket.append(name)
            if name not in all_names:
                all_names.append(name)
        label = _label_for(row, stratify)
        if label and key not in labels:
            labels[key] = label

    event_types = tuple(
        EventTypeShape(key=key, nested_names=tuple(names), label=labels.get(key, ""))
        for key, names in sorted(per_type.items())
    )

    name_path = f"{root_path}{{}}.{name_key}" if layout == "name-value-array" else ""
    text_path = f"{root_path}{{}}.{text_key}" if layout == "name-value-array" else ""

    return PayloadShape(
        index=index,
        container=container,
        encoding=encoding,
        layout=layout,
        name_path=name_path,
        text_path=text_path,
        nested_names=tuple(sorted(all_names)),
        stratified_by=stratify,
        event_types=event_types,
        split_families=split_families,
        sampled_events=len(rows),
    )


def _pick_container(
    rows: list[dict[str, Any]], candidates: list[str], min_ratio: float
) -> tuple[str | None, str]:
    """Return the field whose values most consistently parse as structure."""
    best: tuple[float, int, str, str] | None = None

    for name in candidates:
        values = [row.get(name) for row in rows]
        values = [v for v in values if isinstance(v, str) and v.strip()]
        if not values:
            continue

        json_hits = sum(1 for v in values if _parse(v, "json") is not None)
        xml_hits = sum(1 for v in values if _parse(v, "xml") is not None)
        hits, encoding = (
            (json_hits, "json") if json_hits >= xml_hits else (xml_hits, "xml")
        )
        ratio = hits / len(values)
        if ratio < min_ratio:
            continue
        # Prefer the field that parses most consistently, then the one seen in
        # the most events — the richest container rather than a small one.
        score = (ratio, hits, name, encoding)
        if best is None or score[:2] > best[:2]:
            best = score

    if best is None:
        return None, "none"
    return best[2], best[3]


#: The longest payload worth attempting to parse. Windows event payloads run to
#: a few kilobytes; a megabyte-long one is not a payload this probe needs to
#: understand, and parsing it costs time and memory an attacker chose.
MAX_PAYLOAD_CHARS: Final[int] = 512 * 1024

#: A document type declaration is where XML entity-expansion attacks live. It is
#: matched case-insensitively and with arbitrary whitespace, because the point is
#: to catch the thing however it is written, not to parse it.
_DOCTYPE_RE: Final[re.Pattern[str]] = re.compile(r"<!\s*DOCTYPE", re.IGNORECASE)


def _parse(value: Any, encoding: str) -> Any | None:
    """Parse ``value`` as ``encoding``; return ``None`` if it is not that shape.

    This function is where attacker-controlled bytes meet a parser, so it is
    deliberately narrow about what it will attempt.

    A payload carrying a ``<!DOCTYPE`` is refused before the parser sees it.
    Windows event XML has no document type declaration, so a payload that has
    one is not evidence this probe needs to read — it is the construct that
    every XML entity-expansion attack ("billion laughs", quadratic blowup) is
    built out of. Modern expat caps amplification on its own, but that cap is a
    property of whichever libexpat happens to be linked into the running Python,
    and this system is meant to fail closed on its own terms rather than inherit
    a guarantee from a dependency's patch level. Refusing the declaration
    outright costs one regex and does not depend on anything.

    Oversized values are refused for the same reason: see
    :data:`MAX_PAYLOAD_CHARS`.
    """
    if not isinstance(value, str):
        return None
    if len(value) > MAX_PAYLOAD_CHARS:
        log.debug("Payload of %d chars exceeds the parse limit; skipped", len(value))
        return None
    text = value.strip()
    if not text:
        return None
    if encoding == "json":
        if text[0] not in "{[":
            return None
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, (dict, list)) else None
    if encoding == "xml":
        if not text.startswith("<"):
            return None
        if _DOCTYPE_RE.search(text):
            log.warning(
                "Refusing to parse a payload containing a DOCTYPE declaration. "
                "Event XML has no DTD, and this is the construct XML "
                "entity-expansion attacks are built from."
            )
            return None
        try:
            # No external entity is ever resolved: ElementTree installs no
            # external-entity handler, so a DTD could only ever have expanded
            # internal entities — and the check above means there is no DTD.
            # S314 is suppressed rather than answered with `defusedxml` on
            # purpose. A dependency is a poor fit for the air-gapped goal, and
            # the attack it defends against needs the DOCTYPE this function has
            # already refused. See MAX_PAYLOAD_CHARS and _DOCTYPE_RE above, and
            # TestTheXmlParserRefusesHostilePayloads for the tests that pin it.
            return ElementTree.fromstring(text)  # noqa: S314
        except ElementTree.ParseError:
            return None
    return None


def _resolve_name_key(docs: Any) -> tuple[str, str, str]:
    """Decide, across the whole sample, which array key holds the names.

    Returns ``(root_path, name_key, text_key)``; ``name_key`` is empty when the
    payload is not a name/value array.

    A single event is not enough to tell the two keys apart — in
    ``{"@Name": "Image", "#text": "a"}`` both values are identifier-shaped. Two
    properties separate them reliably once the whole sample is considered:

    * the name key holds an identifier in *every* event, whereas values
      eventually contain a path, an IP or a space;
    * names repeat across events while values vary, so the name key has far
      fewer distinct values.
    """
    seen: dict[str, int] = defaultdict(int)
    values: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for doc in docs:
        located = _locate_array(doc, prefix="")
        if located is None:
            continue
        path, dicts = located
        seen[path] += 1
        for item in dicts:
            for key, value in item.items():
                values[path][key].add(str(value))

    if not seen:
        return "", "", ""

    # Take the array path most events actually use. Taking the first one seen
    # would let a single unusual event (a different payload schema that happens
    # to sort first) define the shape for the whole index.
    root_path = max(seen, key=lambda p: (seen[p], -len(p)))
    keys = tuple(sorted(values[root_path]))
    if len(keys) != 2:
        return "", "", ""

    # A *ratio*, not "all": real name sets contain a few labels with spaces
    # ("Member Name", "Thread ID") while value sets are overwhelmingly paths,
    # sentences and numbers. On the lab index the split is 97% vs 9%.
    ratios: dict[str, float] = {}
    for key in keys:
        observed = values[root_path][key]
        if not observed:
            continue
        identifiers = sum(1 for v in observed if _IDENTIFIER_RE.match(v))
        ratios[key] = identifiers / len(observed)

    qualifying = [k for k, ratio in ratios.items() if ratio >= _NAME_KEY_IDENTIFIER_RATIO]
    if not qualifying:
        return "", "", ""

    # Most identifier-like wins; ties break toward fewer distinct values,
    # because names recur across events while values do not.
    name_key = max(qualifying, key=lambda k: (ratios[k], -len(values[root_path][k]), k))
    text_key = next(k for k in keys if k != name_key)
    return root_path, name_key, text_key


def _locate_array(node: Any, prefix: str, depth: int = 0) -> tuple[str, list[dict]] | None:
    """Find a list of uniform two-key dicts and return its dotted path.

    Structural detection only — this is the EvtxECmd/Windows-EVTX shape
    (``{"EventData": {"Data": [{"@Name": "Image", "#text": "..."}]}}``), but
    nothing here is specific to those key names.
    """
    if depth > 6:
        return None

    if isinstance(node, list):
        dicts = [item for item in node if isinstance(item, dict)]
        # One pair is enough: plenty of event types carry a single nested field,
        # and excluding them would lose their names entirely.
        if (
            dicts
            and all(len(d) == 2 for d in dicts)
            and len({tuple(sorted(d)) for d in dicts}) == 1
        ):
            return prefix, dicts
        return None

    if isinstance(node, dict):
        for key, value in node.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            found = _locate_array(value, child_prefix, depth + 1)
            if found is not None:
                return found
    return None


def _names_from_array(parsed: Any, root_path: str, name_key: str) -> list[str]:
    """Nested names of one event, given the resolved array location and key."""
    located = _locate_array(parsed, prefix="")
    if located is None or located[0] != root_path:
        return []
    seen: list[str] = []
    for item in located[1]:
        value = str(item.get(name_key, ""))
        if value and value not in seen:
            seen.append(value)
    return seen


def _names_from_object(parsed: Any) -> tuple[list[str], str]:
    """Nested names of an event whose payload is a plain object or XML."""
    if isinstance(parsed, ElementTree.Element):
        names = [
            child.get("Name") or child.tag
            for child in parsed.iter()
            if child is not parsed
        ]
        return [n for n in names if _IDENTIFIER_RE.match(n or "")], "object"
    if isinstance(parsed, dict):
        return _flat_keys(parsed), "object"
    return [], "none"


def _flat_keys(node: dict, prefix: str = "", depth: int = 0) -> list[str]:
    """Dotted paths of the scalar leaves of a plain JSON object."""
    if depth > 4:
        return []
    out: list[str] = []
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out.extend(_flat_keys(value, path, depth + 1))
        else:
            out.append(path)
    return out


def _label_for(row: dict[str, Any], stratify: tuple[str, ...]) -> str:
    """A short human label for an event type, if the row carries one.

    Prefers a short descriptive string field that is not already part of the
    stratification key — e.g. EvtxECmd's ``MapDescription`` ("Process creation").
    Chosen by shape, not by name.
    """
    best = ""
    for key, value in row.items():
        if key in stratify or not isinstance(value, str):
            continue
        text = value.strip()
        if not (3 <= len(text) <= 60) or " " not in text or text.startswith(("{", "<")):
            continue
        # Prose, not a timestamp or an id: mostly letters. Without this a
        # TimeCreated value ("2025-08-11 06:46:52.20") reads as a valid label.
        letters = sum(1 for ch in text if ch.isalpha())
        if letters < 0.6 * len(text):
            continue
        if not best or len(text) < len(best):
            best = text
    return best
