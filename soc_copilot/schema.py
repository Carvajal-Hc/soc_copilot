"""Schema discovery: read the *real* index, sourcetype and field names.

Later stages must generate SPL against fields that actually exist. Nothing here
invents a name — every value returned comes from the live Splunk instance,
either from the REST catalogue endpoints or from a search over the index.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Final

from soc_copilot.splunk_client import (
    ALL_TIME_EARLIEST,
    ALL_TIME_LATEST,
    SplunkClient,
    SplunkSearchError,
)

log = logging.getLogger(__name__)

DEFAULT_INDEX: Final[str] = "logforge"

#: Splunk index names are letters, digits, underscores and hyphens. Validating
#: before interpolation keeps a hostile or fat-fingered name out of the SPL.
_INDEX_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")

#: Splunk's own bookkeeping indexes; noise when listing what an analyst can query.
_INTERNAL_INDEX_PREFIXES: Final[tuple[str, ...]] = ("_",)

#: The ``fieldsummary`` columns :func:`list_fields` reads. Naming them in a
#: ``| table`` drops the heavy ``values`` column without using ``maxvals``, which
#: suppressed every row on this instance.
_FIELDSUMMARY_COLUMNS: Final[str] = "field, count, distinct_count, is_exact"

#: ``fieldsummary`` does not report Splunk's internal fields, but ``_time`` is
#: present on every event in every index — it is how Splunk stores the event
#: timestamp. Later stages need it to filter or pivot by time, so the discovered
#: schema states it explicitly instead of implying it does not exist.
ALWAYS_PRESENT_FIELDS: Final[tuple[str, ...]] = ("_time",)


class SchemaError(RuntimeError):
    """A schema-discovery request could not be satisfied."""


def validate_index_name(index: str) -> str:
    """Return ``index`` if it is a safe Splunk index name, else raise."""
    name = index.strip()
    if not _INDEX_NAME_RE.match(name):
        raise SchemaError(
            f"{index!r} is not a valid Splunk index name (expected letters, "
            "digits, underscores or hyphens)."
        )
    return name


@dataclass(frozen=True)
class IndexInfo:
    """One entry from ``/services/data/indexes``."""

    name: str
    event_count: int
    earliest: str
    latest: str
    disabled: bool
    is_internal: bool


@dataclass(frozen=True)
class SourcetypeInfo:
    """A sourcetype actually present in an index, with its event count."""

    name: str
    event_count: int
    earliest: str = ""
    latest: str = ""


@dataclass(frozen=True)
class FieldInfo:
    """A field Splunk really extracts from the index's events."""

    name: str
    #: Events in which the field appears.
    event_count: int
    #: Distinct values observed (0 when Splunk did not compute it).
    distinct_count: int
    #: True when ``distinct_count`` is exact rather than estimated.
    is_exact: bool
    #: False when the counts above are unknown rather than measured — the field
    #: is known to exist, but ``fieldsummary`` did not report statistics for it.
    counts_known: bool = True

    @property
    def is_internal(self) -> bool:
        return self.name.startswith("_")


@dataclass(frozen=True)
class Schema:
    """Everything Stage 1 discovered about the live instance."""

    index: str
    indexes: list[IndexInfo] = field(default_factory=list)
    sourcetypes: list[SourcetypeInfo] = field(default_factory=list)
    fields: list[FieldInfo] = field(default_factory=list)
    #: Which channels each event id was actually observed on, measured from the
    #: live index. Empty when the data has no such pair of fields.
    #:
    #: An event id and a channel are two halves of one selector, and a query can
    #: pair them in a combination that exists in neither. That query is valid
    #: SPL against real fields and returns zero — the silent-empty failure this
    #: project keeps meeting from new directions. Knowing which pairings occur
    #: is the only way to tell a contradiction from a genuine absence, and it
    #: has to be discovered rather than assumed: the answer differs per dataset.
    event_channels: dict[str, frozenset[str]] = field(default_factory=dict)

    @property
    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]

    def channels_for(self, event_id: str) -> frozenset[str]:
        """Channels this event id was seen on. Empty means "never observed"."""
        return self.event_channels.get(str(event_id).strip(), frozenset())

    @property
    def sourcetype_names(self) -> list[str]:
        return [s.name for s in self.sourcetypes]

    @property
    def total_events(self) -> int:
        return sum(s.event_count for s in self.sourcetypes)


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def list_indexes(client: SplunkClient, *, include_internal: bool = False) -> list[IndexInfo]:
    """List indexes from the REST catalogue, newest data first is not implied."""
    entries = client.rest_entries("/services/data/indexes")
    indexes: list[IndexInfo] = []

    for entry in entries:
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        internal = name.startswith(_INTERNAL_INDEX_PREFIXES)
        if internal and not include_internal:
            continue
        content = entry.get("content") or {}
        indexes.append(
            IndexInfo(
                name=name,
                event_count=_as_int(content.get("totalEventCount")),
                earliest=str(content.get("minTime") or ""),
                latest=str(content.get("maxTime") or ""),
                disabled=bool(content.get("disabled")),
                is_internal=internal,
            )
        )

    indexes.sort(key=lambda i: i.name)
    return indexes


def list_sourcetypes(
    client: SplunkClient,
    index: str = DEFAULT_INDEX,
    *,
    earliest: str = ALL_TIME_EARLIEST,
    latest: str = ALL_TIME_LATEST,
) -> list[SourcetypeInfo]:
    """List the sourcetypes present in ``index``.

    Uses ``| metadata`` (cheap, reads the index's own catalogue) and falls back
    to a ``stats count by sourcetype`` if metadata comes back empty.
    """
    name = validate_index_name(index)

    rows = client.run_search(
        f"| metadata type=sourcetypes index={name}", earliest=earliest, latest=latest
    )
    sourcetypes = [
        SourcetypeInfo(
            name=str(row.get("sourcetype", "")),
            event_count=_as_int(row.get("totalCount")),
            earliest=_epoch_to_text(row.get("firstTime")),
            latest=_epoch_to_text(row.get("lastTime")),
        )
        for row in rows
        if row.get("sourcetype")
    ]

    if not sourcetypes:
        log.debug("metadata returned nothing for index=%s; falling back to stats", name)
        rows = client.run_search(
            f"index={name} | stats count by sourcetype", earliest=earliest, latest=latest
        )
        sourcetypes = [
            SourcetypeInfo(
                name=str(row.get("sourcetype", "")),
                event_count=_as_int(row.get("count")),
            )
            for row in rows
            if row.get("sourcetype")
        ]

    sourcetypes.sort(key=lambda s: s.name)
    return sourcetypes


def list_fields(
    client: SplunkClient,
    index: str = DEFAULT_INDEX,
    *,
    sourcetype: str | None = None,
    sample_size: int = 0,
    include_internal: bool = True,
    earliest: str = ALL_TIME_EARLIEST,
    latest: str = ALL_TIME_LATEST,
) -> list[FieldInfo]:
    """Enumerate the field names Splunk extracts from ``index``.

    ``fieldsummary`` is authoritative here: it reports the fields present on the
    events themselves, so no field name is ever guessed.

    The trailing ``| table`` is deliberate. ``fieldsummary maxvals=0`` returned
    zero rows against this instance, suppressing the field list entirely; a plain
    ``fieldsummary`` returns all 49 fields. The ``table`` keeps the columns this
    function actually reads and drops ``values``, which is the bulky column
    ``maxvals`` was there to trim.

    Args:
        sourcetype: Restrict to one sourcetype.
        sample_size: ``0`` (default) examines every matching event. A positive
            value inserts ``| head N`` — faster, but only a sample.
        include_internal: Keep Splunk's underscore fields (``_time``, ``_raw``).
    """
    name = validate_index_name(index)

    parts = [f"index={name}"]
    if sourcetype:
        parts.append(f'sourcetype="{_escape_quotes(sourcetype)}"')
    spl = " ".join(parts)
    if sample_size > 0:
        spl += f" | head {int(sample_size)}"
    spl += f" | fieldsummary | table {_FIELDSUMMARY_COLUMNS}"

    rows = client.run_search(spl, earliest=earliest, latest=latest)

    fields: list[FieldInfo] = []
    for row in rows:
        field_name = str(row.get("field", "")).strip()
        if not field_name:
            continue
        if not include_internal and field_name.startswith("_"):
            continue
        fields.append(
            FieldInfo(
                name=field_name,
                event_count=_as_int(row.get("count")),
                distinct_count=_as_int(row.get("distinct_count")),
                is_exact=_as_int(row.get("is_exact")) == 1,
            )
        )

    if include_internal:
        known = {f.name for f in fields}
        for always in ALWAYS_PRESENT_FIELDS:
            if always in known:
                continue
            # Known to exist, but fieldsummary measured nothing for it. Say the
            # counts are unknown rather than reporting a fabricated zero.
            log.debug("%s absent from fieldsummary; adding it explicitly", always)
            fields.append(
                FieldInfo(
                    name=always,
                    event_count=0,
                    distinct_count=0,
                    is_exact=False,
                    counts_known=False,
                )
            )

    fields.sort(key=lambda f: (f.name.startswith("_"), f.name.lower()))
    return fields


#: Fields that together select an event type. Discovered as a pair so a query
#: cannot silently combine a valid half of each into a combination that occurs
#: nowhere. Named generically because the names differ by dataset; both must
#: exist in the discovered field list before the pairing is measured at all.
EVENT_ID_FIELD: Final[str] = "EventId"
CHANNEL_FIELD: Final[str] = "Channel"


def list_event_channels(
    client: SplunkClient,
    index: str,
    *,
    earliest: str = ALL_TIME_EARLIEST,
    latest: str = ALL_TIME_LATEST,
) -> dict[str, frozenset[str]]:
    """Measure which channels each event id actually appears on.

    One cheap aggregation over the whole index. The result is the difference
    between "this combination returned nothing because the data does not have
    it" and "this combination returned nothing because it cannot exist" — and
    only the second is worth refusing before dispatch.

    Returns an empty mapping when either field is absent, which is the honest
    outcome for a dataset that does not carry this pair. Nothing downstream
    should assume Windows event logs.
    """
    spl = (
        f"index={index} {EVENT_ID_FIELD}=* {CHANNEL_FIELD}=* "
        f"| stats count by {EVENT_ID_FIELD}, {CHANNEL_FIELD}"
    )
    try:
        rows = client.run_search(spl, earliest=earliest, latest=latest)
    except SplunkSearchError:
        # Not fatal: without this the loop simply loses one check.
        log.warning("event id/channel pairing probe failed for index=%s", index)
        return {}

    pairs: dict[str, set[str]] = {}
    for row in rows:
        event_id = str(row.get(EVENT_ID_FIELD, "")).strip()
        channel = str(row.get(CHANNEL_FIELD, "")).strip()
        if event_id and channel:
            pairs.setdefault(event_id, set()).add(channel)

    log.info(
        "Discovered %d event id(s) across %d channel(s) in index=%s",
        len(pairs),
        len({c for cs in pairs.values() for c in cs}),
        index,
    )
    return {k: frozenset(v) for k, v in pairs.items()}


def discover_schema(
    client: SplunkClient,
    index: str = DEFAULT_INDEX,
    *,
    include_internal_indexes: bool = False,
    sample_size: int = 0,
    earliest: str = ALL_TIME_EARLIEST,
    latest: str = ALL_TIME_LATEST,
) -> Schema:
    """Discover indexes, plus the sourcetypes and fields of ``index``."""
    validate_index_name(index)

    indexes = list_indexes(client, include_internal=include_internal_indexes)
    if index not in {i.name for i in indexes}:
        known = ", ".join(i.name for i in indexes) or "(none visible)"
        raise SchemaError(
            f"Index {index!r} was not found on {client.config.base_url}. "
            f"Indexes visible to this token: {known}."
        )

    sourcetypes = list_sourcetypes(client, index, earliest=earliest, latest=latest)
    try:
        fields = list_fields(
            client, index, sample_size=sample_size, earliest=earliest, latest=latest
        )
    except SplunkSearchError:
        log.exception("fieldsummary failed for index=%s", index)
        raise

    names = {f.name for f in fields}
    event_channels = (
        list_event_channels(client, index, earliest=earliest, latest=latest)
        if {EVENT_ID_FIELD, CHANNEL_FIELD} <= names
        else {}
    )

    return Schema(
        index=index,
        indexes=indexes,
        sourcetypes=sourcetypes,
        fields=fields,
        event_channels=event_channels,
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _as_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _escape_quotes(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _epoch_to_text(value: Any) -> str:
    """Render a Splunk epoch timestamp as UTC text; pass anything else through."""
    from datetime import UTC, datetime

    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return str(value or "")
    if seconds <= 0:
        return ""
    return datetime.fromtimestamp(seconds, tz=UTC).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
