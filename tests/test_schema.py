from __future__ import annotations

from typing import Any

import pytest

from soc_copilot.schema import (
    SchemaError,
    discover_schema,
    list_fields,
    list_indexes,
    list_sourcetypes,
    validate_index_name,
)

INDEX_ENTRIES = [
    {
        "name": "logforge",
        "content": {
            "totalEventCount": "60000",
            "minTime": "2024-11-01T00:00:00.000+00:00",
            "maxTime": "2024-11-30T23:59:59.000+00:00",
            "disabled": False,
        },
    },
    {"name": "main", "content": {"totalEventCount": "0", "disabled": False}},
    {"name": "_internal", "content": {"totalEventCount": "12345", "disabled": False}},
]

METADATA_ROWS = [
    {
        "sourcetype": "csv",
        "totalCount": "60000",
        "firstTime": "1730419200",
        "lastTime": "1733011199",
    },
]

FIELDSUMMARY_ROWS = [
    {"field": "Computer", "count": "60000", "distinct_count": "2", "is_exact": "1"},
    {"field": "EventId", "count": "60000", "distinct_count": "480", "is_exact": "1"},
    {"field": "_time", "count": "60000", "distinct_count": "59000", "is_exact": "0"},
    {"field": "Channel", "count": "60000", "distinct_count": "12", "is_exact": "1"},
    {"field": "", "count": "0", "distinct_count": "0", "is_exact": "1"},
]

#: What the live lab instance actually returns: no underscore fields at all.
FIELDSUMMARY_WITHOUT_TIME = [
    row for row in FIELDSUMMARY_ROWS if not row["field"].startswith("_")
]


class StubClient:
    """Stands in for SplunkClient; returns canned rows keyed by SPL substring."""

    def __init__(
        self,
        *,
        entries: list[dict[str, Any]] | None = None,
        searches: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.entries = INDEX_ENTRIES if entries is None else entries
        self.searches = searches or {}
        self.spl_seen: list[tuple[str, str, str]] = []

        class _Config:
            base_url = "https://localhost:8089"

        self.config = _Config()

    def rest_entries(self, path: str, params: dict | None = None) -> list[dict]:
        assert path == "/services/data/indexes"
        return self.entries

    def run_search(self, spl: str, earliest: str = "0", latest: str = "") -> list[dict]:
        self.spl_seen.append((spl, earliest, latest))
        for needle, rows in self.searches.items():
            if needle in spl:
                return rows
        return []


# --------------------------------------------------------------------------
# Index name validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["logforge", "main", "_internal", "my-index_2"])
def test_valid_index_names(name: str) -> None:
    assert validate_index_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["logforge | delete", "log forge", "", "logforge;drop", "*", "-leading-hyphen"],
)
def test_invalid_index_names_are_rejected(name: str) -> None:
    with pytest.raises(SchemaError):
        validate_index_name(name)


def test_index_name_is_validated_before_reaching_spl() -> None:
    client = StubClient()
    with pytest.raises(SchemaError):
        list_sourcetypes(client, "logforge | delete")
    assert client.spl_seen == []


# --------------------------------------------------------------------------
# Indexes
# --------------------------------------------------------------------------


def test_list_indexes_hides_internal_by_default() -> None:
    indexes = list_indexes(StubClient())
    assert [i.name for i in indexes] == ["logforge", "main"]

    logforge = indexes[0]
    assert logforge.event_count == 60000
    assert logforge.earliest.startswith("2024-11-01")
    assert logforge.disabled is False


def test_list_indexes_can_include_internal() -> None:
    indexes = list_indexes(StubClient(), include_internal=True)
    assert [i.name for i in indexes] == ["_internal", "logforge", "main"]
    assert next(i for i in indexes if i.name == "_internal").is_internal is True


# --------------------------------------------------------------------------
# Sourcetypes
# --------------------------------------------------------------------------


def test_list_sourcetypes_uses_metadata() -> None:
    client = StubClient(searches={"metadata type=sourcetypes": METADATA_ROWS})
    sourcetypes = list_sourcetypes(client, "logforge")

    assert [s.name for s in sourcetypes] == ["csv"]
    assert sourcetypes[0].event_count == 60000
    assert sourcetypes[0].earliest.startswith("2024-11-01")
    assert client.spl_seen[0][0] == "| metadata type=sourcetypes index=logforge"


def test_list_sourcetypes_falls_back_to_stats() -> None:
    client = StubClient(
        searches={"stats count by sourcetype": [{"sourcetype": "csv", "count": "60000"}]}
    )
    sourcetypes = list_sourcetypes(client, "logforge")

    assert [s.name for s in sourcetypes] == ["csv"]
    assert sourcetypes[0].event_count == 60000
    assert len(client.spl_seen) == 2  # metadata returned nothing, then the fallback


def test_list_sourcetypes_passes_the_time_range_through() -> None:
    client = StubClient(searches={"metadata": METADATA_ROWS})
    list_sourcetypes(client, "logforge", earliest="0", latest="")
    assert client.spl_seen[0][1:] == ("0", "")


# --------------------------------------------------------------------------
# Fields
# --------------------------------------------------------------------------


def test_list_fields_reads_real_names_from_fieldsummary() -> None:
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_ROWS})
    fields = list_fields(client, "logforge")

    # Blank names dropped; internal fields sorted last; real names preserved.
    assert [f.name for f in fields] == ["Channel", "Computer", "EventId", "_time"]
    assert client.spl_seen[0][0] == (
        "index=logforge | fieldsummary | table field, count, distinct_count, is_exact"
    )

    computer = next(f for f in fields if f.name == "Computer")
    assert computer.event_count == 60000
    assert computer.distinct_count == 2
    assert computer.is_exact is True
    assert computer.is_internal is False
    assert next(f for f in fields if f.name == "_time").is_internal is True
    assert next(f for f in fields if f.name == "_time").is_exact is False


def test_time_is_added_when_fieldsummary_omits_it() -> None:
    """fieldsummary does not report internal fields, but _time is on every event."""
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_WITHOUT_TIME})
    fields = list_fields(client, "logforge")

    names = [f.name for f in fields]
    assert "_time" in names
    assert names == ["Channel", "Computer", "EventId", "_time"]

    time_field = next(f for f in fields if f.name == "_time")
    assert time_field.is_internal is True
    # Its existence is known; its statistics are not. Do not fabricate them.
    assert time_field.counts_known is False
    assert time_field.event_count == 0


def test_time_is_not_duplicated_when_fieldsummary_does_report_it() -> None:
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_ROWS})
    fields = list_fields(client, "logforge")

    assert [f.name for f in fields].count("_time") == 1
    # Real measurements win over the synthesised entry.
    time_field = next(f for f in fields if f.name == "_time")
    assert time_field.counts_known is True
    assert time_field.event_count == 60000


def test_measured_fields_report_their_counts_as_known() -> None:
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_WITHOUT_TIME})
    fields = list_fields(client, "logforge")
    assert all(f.counts_known for f in fields if f.name != "_time")


def test_discovered_schema_always_exposes_time() -> None:
    client = StubClient(
        searches={
            "metadata type=sourcetypes": METADATA_ROWS,
            "fieldsummary": FIELDSUMMARY_WITHOUT_TIME,
        }
    )
    schema = discover_schema(client, "logforge")
    assert "_time" in schema.field_names


def test_list_fields_can_drop_internal_fields() -> None:
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_ROWS})
    fields = list_fields(client, "logforge", include_internal=False)
    assert all(not f.name.startswith("_") for f in fields)


def test_list_fields_scans_every_event_by_default() -> None:
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_ROWS})
    list_fields(client, "logforge")
    assert "head" not in client.spl_seen[0][0]


def test_list_fields_sample_size_adds_head() -> None:
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_ROWS})
    list_fields(client, "logforge", sample_size=5000)
    assert client.spl_seen[0][0] == (
        "index=logforge | head 5000 | fieldsummary "
        "| table field, count, distinct_count, is_exact"
    )


def test_list_fields_quotes_the_sourcetype() -> None:
    client = StubClient(searches={"fieldsummary": FIELDSUMMARY_ROWS})
    list_fields(client, "logforge", sourcetype='csv"evil')
    assert client.spl_seen[0][0] == (
        'index=logforge sourcetype="csv\\"evil" | fieldsummary '
        "| table field, count, distinct_count, is_exact"
    )


# --------------------------------------------------------------------------
# Whole schema
# --------------------------------------------------------------------------


def test_discover_schema_collects_everything() -> None:
    client = StubClient(
        searches={
            "metadata type=sourcetypes": METADATA_ROWS,
            "fieldsummary": FIELDSUMMARY_ROWS,
        }
    )
    schema = discover_schema(client, "logforge")

    assert schema.index == "logforge"
    assert [i.name for i in schema.indexes] == ["logforge", "main"]
    assert schema.sourcetype_names == ["csv"]
    assert schema.field_names == ["Channel", "Computer", "EventId", "_time"]
    assert schema.total_events == 60000


def test_discover_schema_reports_a_missing_index_honestly() -> None:
    client = StubClient()
    with pytest.raises(SchemaError) as excinfo:
        discover_schema(client, "nosuchindex")
    message = str(excinfo.value)
    assert "nosuchindex" in message
    assert "logforge" in message  # tells the analyst what *does* exist
