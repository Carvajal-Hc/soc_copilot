"""Payload-shape discovery. The analysis half is pure, so no Splunk is needed."""

from __future__ import annotations

import json

from soc_copilot.payload_shape import (
    MAX_PAYLOAD_CHARS,
    SplitFieldFamily,
    _parse,
    analyze_rows,
    candidate_container_fields,
    choose_stratify_fields,
    detect_split_families,
)
from soc_copilot.schema import FieldInfo, Schema


def _evtx_payload(pairs: list[tuple[str, str]]) -> str:
    """The EvtxECmd/Windows shape: a name/value array, not a flat object."""
    return json.dumps(
        {"EventData": {"Data": [{"@Name": n, "#text": v} for n, v in pairs]}}
    )


def _rows(count: int = 3) -> list[dict[str, str]]:
    return [
        {
            "EventId": "1",
            "Provider": "Microsoft-Windows-Sysmon",
            "MapDescription": "Process creation",
            "Computer": "user",
            "Payload": _evtx_payload(
                [
                    ("ProcessGuid", f"guid-{i}"),
                    ("Image", r"C:\Windows\System32\cmd.exe"),
                    ("CommandLine", "cmd.exe /c whoami"),
                ]
            ),
        }
        for i in range(count)
    ]


def _schema(*fields: tuple[str, int, bool]) -> Schema:
    return Schema(
        index="testidx",
        fields=[
            FieldInfo(name=n, event_count=100, distinct_count=d, is_exact=exact)
            for n, d, exact in fields
        ],
    )


class TestContainerDetection:
    def test_finds_the_json_container_and_its_layout(self):
        shape = analyze_rows(
            _rows(),
            index="testidx",
            candidates=["Payload", "Computer", "MapDescription"],
            stratify=("EventId", "Provider"),
        )

        assert shape.container == "Payload"
        assert shape.encoding == "json"
        assert shape.layout == "name-value-array"
        assert shape.is_nested

    def test_reports_the_parallel_array_paths_spath_actually_produces(self):
        # This is the crux: spath on a name/value array yields two arrays, not
        # one field per name. Generated SPL depends on these exact paths.
        shape = analyze_rows(
            _rows(),
            index="testidx",
            candidates=["Payload"],
            stratify=("EventId",),
        )

        assert shape.name_path == "EventData.Data{}.@Name"
        assert shape.text_path == "EventData.Data{}.#text"

    def test_collects_nested_names_that_are_not_columns(self):
        shape = analyze_rows(
            _rows(), index="testidx", candidates=["Payload"], stratify=("EventId",)
        )

        assert set(shape.nested_names) == {"ProcessGuid", "Image", "CommandLine"}

    def test_flat_index_is_reported_as_flat_not_as_a_failure(self):
        rows = [{"src_ip": "10.0.0.1", "action": "allow"} for _ in range(5)]

        shape = analyze_rows(
            rows, index="fw", candidates=["src_ip", "action"], stratify=("action",)
        )

        assert shape.container is None
        assert not shape.is_nested
        assert "flat" in shape.note.lower()

    def test_detects_a_plain_json_object_payload(self):
        rows = [
            {
                "EventID": "4688",
                "raw": json.dumps({"process": {"name": "cmd.exe", "pid": 42}}),
            }
        ] * 3

        shape = analyze_rows(
            rows, index="x", candidates=["raw"], stratify=("EventID",)
        )

        assert shape.container == "raw"
        assert shape.layout == "object"
        assert "process.name" in shape.nested_names

    def test_ignores_a_field_that_only_sometimes_parses(self):
        rows = [{"maybe": json.dumps({"a": 1})}] + [{"maybe": "not json"}] * 9

        shape = analyze_rows(
            rows, index="x", candidates=["maybe"], stratify=(), min_container_ratio=0.5
        )

        assert shape.container is None

    def test_empty_sample_says_unknown_rather_than_flat(self):
        shape = analyze_rows([], index="x", candidates=["Payload"], stratify=())

        assert not shape.is_nested
        assert "unknown" in shape.note.lower()


class TestPerEventTypeNames:
    def test_nested_names_are_recorded_per_event_type(self):
        rows = [
            {"EventId": "1", "Payload": _evtx_payload([("Image", "a"), ("User", "b")])},
            {"EventId": "3", "Payload": _evtx_payload([("DestinationIp", "1.2.3.4")])},
        ]

        shape = analyze_rows(
            rows, index="x", candidates=["Payload"], stratify=("EventId",)
        )

        assert shape.names_for("1") == ("Image", "User")
        assert shape.names_for("3") == ("DestinationIp",)

    def test_label_prefers_prose_over_a_timestamp(self):
        rows = [
            {
                "EventId": "1",
                "TimeCreated": "2025-08-11 06:46:52.2049890",
                "MapDescription": "Process creation",
                "Payload": _evtx_payload([("Image", "a")]),
            }
        ]

        shape = analyze_rows(
            rows, index="x", candidates=["Payload"], stratify=("EventId",)
        )

        assert shape.event_types[0].label == "Process creation"


class TestSplitFamilies:
    def test_groups_numbered_siblings(self):
        schema = _schema(
            ("PayloadData1", 10, True),
            ("PayloadData2", 10, True),
            ("PayloadData3", 10, True),
            ("Computer", 4, True),
        )

        families = detect_split_families(schema)

        assert families == (
            SplitFieldFamily(
                base="PayloadData",
                members=("PayloadData1", "PayloadData2", "PayloadData3"),
            ),
        )

    def test_a_lone_numbered_field_is_not_a_family(self):
        assert detect_split_families(_schema(("Message1", 5, True))) == ()


class TestStratification:
    def test_prefers_a_category_over_an_identifier_of_similar_size(self):
        # Measured cardinality: EventId is a type code (530), ProcessId is an
        # identifier that happens to have a similar count (511), Provider is a
        # true category (137). Picking EventId+ProcessId would give a useless
        # near-unique key, so the bands must pick EventId+Provider.
        schema = _schema(
            ("EventId", 0, False), ("ProcessId", 0, False), ("Provider", 0, False)
        )
        measured = {"EventId": 530, "ProcessId": 511, "Provider": 137}

        assert choose_stratify_fields(schema, measured) == ["EventId", "Provider"]

    def test_ignores_fields_above_the_cardinality_ceiling(self):
        schema = _schema(("EventRecordId", 0, False), ("Channel", 0, False))
        measured = {"EventRecordId": 24387, "Channel": 92}

        assert choose_stratify_fields(schema, measured) == ["Channel"]

    def test_without_measurement_only_exact_counts_are_trusted(self):
        # fieldsummary estimates cap at 500, so an inexact 500 could be an
        # identifier with 60,000 values. Refuse to guess from it.
        schema = _schema(("EventId", 500, False), ("Channel", 92, True))

        assert choose_stratify_fields(schema) == ["Channel"]


class TestCandidateFields:
    def test_excludes_splunk_metadata_but_keeps_dataset_fields(self):
        schema = _schema(
            ("Payload", 40371, False),
            ("punct", 500, False),
            ("date_hour", 12, True),
            ("sourcetype", 1, True),
            ("Computer", 4, True),
        )

        candidates = candidate_container_fields(schema)

        assert "Payload" in candidates
        assert "Computer" in candidates
        assert "punct" not in candidates
        assert "date_hour" not in candidates
        assert "sourcetype" not in candidates

    def test_excludes_names_that_cannot_be_put_in_a_table_command(self):
        schema = _schema(("tag::eventtype", 3, True), ("Channel", 92, True))

        assert candidate_container_fields(schema) == ["Channel"]


class TestTheXmlParserRefusesHostilePayloads:
    """A payload field holds whatever the attacker put in the event.

    This is the one place in the system where attacker-controlled bytes are
    handed to a parser, so the refusals are pinned here rather than trusted to
    whichever libexpat happens to be linked into the running Python.
    """

    def test_a_doctype_declaration_is_refused_before_parsing(self):
        """Event XML has no DTD, so a payload that has one is not evidence.

        It is also the construct every XML entity-expansion attack is built
        out of, which is why it is refused rather than parsed carefully.
        """
        bomb = (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE lolz [\n"
            ' <!ENTITY lol "lol">\n'
            ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
            "]>\n"
            "<lolz>&lol1;</lolz>"
        )

        assert _parse(bomb, "xml") is None

    def test_the_doctype_check_is_not_defeated_by_spacing_or_case(self):
        for text in ("<!doctype a []><a/>", "<!  DOCTYPE a []><a/>", "<!\tDoCtYpE a []><a/>"):
            assert _parse(text, "xml") is None, text

    def test_an_oversized_payload_is_not_parsed(self):
        """A length the attacker chose must not size an allocation here."""
        oversized = "x" * (MAX_PAYLOAD_CHARS + 1)

        assert _parse("<a>" + oversized + "</a>", "xml") is None
        assert _parse('{"k":"' + oversized + '"}', "json") is None

    def test_ordinary_event_xml_still_parses(self):
        """The guards have to refuse attacks, not evidence."""
        parsed = _parse(
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>1</EventID></System></Event>",
            "xml",
        )

        assert parsed is not None
        assert parsed.tag.endswith("Event")
