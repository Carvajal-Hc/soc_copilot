"""Validation of generated SPL.

The most important test in this file is
``TestNestedFieldsMustBeExtracted::test_flat_filter_on_a_nested_field_is_an_error``
— that query runs cleanly and returns zero rows, which in triage reads as "no
evidence". Catching it statically is the point of the module.
"""

from __future__ import annotations

import pytest

from soc_copilot.payload_shape import EventTypeShape, PayloadShape, SplitFieldFamily
from soc_copilot.schema import FieldInfo, Schema
from soc_copilot.validation import validate_spl

FLAT_FIELDS = ("Channel", "EventId", "Computer", "Payload", "PayloadData1", "UserName")
NESTED_NAMES = ("ProcessGuid", "Image", "CommandLine", "Hashes", "DestinationIp")


@pytest.fixture
def schema() -> Schema:
    return Schema(
        index="logforge",
        fields=[
            FieldInfo(name=n, event_count=100, distinct_count=5, is_exact=True)
            for n in FLAT_FIELDS
        ],
    )


@pytest.fixture
def shape() -> PayloadShape:
    return PayloadShape(
        index="logforge",
        container="Payload",
        encoding="json",
        layout="name-value-array",
        name_path="EventData.Data{}.@Name",
        text_path="EventData.Data{}.#text",
        nested_names=NESTED_NAMES,
        stratified_by=("EventId",),
        event_types=(EventTypeShape(key=("1",), nested_names=NESTED_NAMES),),
        split_families=(SplitFieldFamily(base="PayloadData", members=("PayloadData1",)),),
        sampled_events=100,
    )


class TestNestedFieldsMustBeExtracted:
    def test_flat_filter_on_a_nested_field_is_an_error(self, schema, shape):
        # Valid SPL. Runs fine. Returns nothing, because ProcessGuid is not a
        # column — it is a name inside Payload.
        spl = "index=logforge EventId=1 | stats count by ProcessGuid"

        report = validate_spl(spl, schema, shape)

        assert not report.ok
        assert report.unextracted_nested == ("ProcessGuid",)
        assert "ProcessGuid" in report.errors[0]
        assert "Payload" in report.errors[0]

    def test_the_error_shows_the_extraction_that_would_fix_it(self, schema, shape):
        report = validate_spl("index=logforge | stats count by Image", schema, shape)

        message = report.errors[0]
        assert "spath input=Payload" in message
        assert "mvfind" in message and "mvindex" in message
        assert "EventData.Data{}.@Name" in message

    def test_extracting_first_then_grouping_passes(self, schema, shape):
        spl = (
            "index=logforge Channel=\"Microsoft-Windows-Sysmon/Operational\" EventId=1\n"
            "| spath input=Payload\n"
            "| eval ProcessGuid = mvindex('EventData.Data{}.#text', "
            "mvfind('EventData.Data{}.@Name', \"^ProcessGuid$\"))\n"
            "| stats count by ProcessGuid"
        )

        report = validate_spl(spl, schema, shape)

        assert report.ok, report.errors
        assert report.unextracted_nested == ()
        assert report.uses_extraction

    def test_rex_extraction_also_counts_as_extraction(self, schema, shape):
        spl = (
            'index=logforge | rex field=Payload "\\"@Name\\":\\"Image\\",'
            '\\"#text\\":\\"(?<Image>[^\\"]*)\\"" | stats count by Image'
        )

        report = validate_spl(spl, schema, shape)

        assert report.ok, report.errors
        assert "Image" in report.defined

    def test_a_nested_field_filtered_in_the_base_search_is_caught(self, schema, shape):
        # The base search only ever sees flat fields, so this matches nothing.
        report = validate_spl(
            'index=logforge CommandLine="*powershell*"', schema, shape
        )

        assert not report.ok
        assert "CommandLine" in report.unextracted_nested


class TestFlatFields:
    def test_a_plain_flat_query_passes(self, schema, shape):
        report = validate_spl(
            "index=logforge Channel=Security | stats count by Computer, EventId",
            schema,
            shape,
        )

        assert report.ok, report.errors
        assert not report.uses_extraction

    def test_split_fields_are_flat_and_allowed(self, schema, shape):
        report = validate_spl(
            "index=logforge EventId=1 | table _time, PayloadData1", schema, shape
        )

        assert report.ok, report.errors

    def test_an_invented_field_is_flagged(self, schema, shape):
        report = validate_spl(
            "index=logforge | stats count by SourceNetworkAddress", schema, shape
        )

        assert report.warnings
        assert "SourceNetworkAddress" in report.warnings[0]

    def test_underscore_time_is_always_valid(self, schema, shape):
        report = validate_spl(
            "index=logforge | timechart span=1h count by Computer", schema, shape
        )

        assert report.ok, report.errors


class TestSafety:
    def test_mutating_commands_are_rejected(self, schema, shape):
        report = validate_spl(
            "index=logforge | stats count by Computer | outputlookup out.csv",
            schema,
            shape,
        )

        assert not report.ok
        assert "read-only" in report.errors[0].lower()

    def test_delete_is_rejected(self, schema, shape):
        report = validate_spl("index=logforge | delete", schema, shape)

        assert not report.ok

    def test_targeting_a_different_index_is_an_error(self, schema, shape):
        report = validate_spl("index=windows | stats count", schema, shape)

        assert not report.ok
        assert "windows" in report.errors[0]

    def test_missing_index_is_a_warning_not_a_failure(self, schema, shape):
        report = validate_spl("| stats count by Computer", schema, shape)

        assert report.ok
        assert any("does not name an index" in w for w in report.warnings)

    def test_empty_spl_fails(self, schema, shape):
        assert not validate_spl("   ", schema, shape).ok


class TestTimeRange:
    @pytest.mark.parametrize("value", ["0", "-7d@d", "now", "1699999999", "@d", "-24h"])
    def test_accepts_real_splunk_modifiers(self, schema, shape, value):
        report = validate_spl(
            "index=logforge | stats count", schema, shape, earliest=value
        )

        assert report.ok, report.errors

    def test_rejects_prose_as_a_time_modifier(self, schema, shape):
        report = validate_spl(
            "index=logforge | stats count",
            schema,
            shape,
            earliest="last november",
        )

        assert not report.ok
        assert "time modifier" in report.errors[0]

    def test_empty_latest_means_no_upper_bound(self, schema, shape):
        report = validate_spl(
            "index=logforge | stats count", schema, shape, earliest="0", latest=""
        )

        assert report.ok, report.errors


class TestWithoutShape:
    def test_nested_misuse_cannot_be_detected_without_a_probe(self, schema):
        # Documents the limitation honestly: with no shape, this passes.
        report = validate_spl("index=logforge | stats count by ProcessGuid", schema, None)

        assert report.unextracted_nested == ()
        assert any("ProcessGuid" in w for w in report.warnings)


# --------------------------------------------------------------------------
# Unsubstituted template text
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spl",
    [
        r'index=logforge EventId=1 | search Image="*\THE-IMAGE-THE-QUESTION-NAMES"',
        'index=logforge | search ProcessGuid="PASTE-THE-GUID-STEP-1-RETURNED"',
        "index=logforge | search ProcessGuid=<value>",
        "index=logforge | search TargetFilename=<the file from step 1>",
    ],
)
def test_a_pasted_placeholder_is_refused(spl: str, schema, shape) -> None:
    """Observed live: a 14b pasted a library placeholder into a filter, got zero
    rows, and reported that no PowerShell process creation existed — of six that
    did. Zero rows is the most dangerous result this system produces, because it
    reads as "no such evidence" when it means "the filter was never filled in".
    """
    report = validate_spl(spl, schema, shape)

    assert not report.ok
    assert any("template text" in e for e in report.errors)
    assert any("never filled in" in e for e in report.errors)


@pytest.mark.parametrize(
    "spl",
    [
        'index=logforge | search Computer="WIN-1U80VJFJPGD"',
        r'index=logforge | search Image="*\powershell.exe"',
        'index=logforge | search ProcessGuid="a5ea900f-97f3-6899-6801-000000000800"',
        "index=logforge EventId=4624 | stats count by Computer",
        'index=logforge | search MapDescription="A process changed a file creation time"',
    ],
)
def test_real_values_that_look_shouty_are_not_placeholders(spl: str, schema, shape) -> None:
    """A real hostname is SCREAMING-KEBAB too. False positives here would block
    legitimate queries against exactly the kind of host an analyst hunts."""
    report = validate_spl(spl, schema, shape)

    assert not any("template text" in e for e in report.errors), report.errors


# --------------------------------------------------------------------------
# An event id paired with a channel it never appears on
# --------------------------------------------------------------------------


@pytest.fixture
def paired_schema():
    """A schema carrying measured event-id/channel pairings, as Stage 1 builds."""
    from soc_copilot.schema import FieldInfo, Schema

    return Schema(
        index="logforge",
        indexes=[],
        fields=[
            FieldInfo(name=n, event_count=1, distinct_count=1, is_exact=True)
            for n in ("EventId", "Channel", "Computer", "Payload", "_time")
        ],
        event_channels={
            "4624": frozenset({"Security"}),
            "1": frozenset({"Microsoft-Windows-Sysmon/Operational"}),
        },
    )


def test_an_event_id_on_the_wrong_channel_is_refused(paired_schema) -> None:
    """Measured: a 14B took EventId=4624 from the right library entry and the
    Sysmon Channel from the entries around it, three runs of three, and reported
    that there were no logons. Both halves are real; the pairing occurs nowhere.
    """
    report = validate_spl(
        'index=logforge Channel="Microsoft-Windows-Sysmon/Operational" EventId=4624',
        paired_schema,
    )

    assert not report.ok
    error = next(e for e in report.errors if "never appears on" in e)
    assert "EventId=4624" in error
    assert "observed only on: Security" in error


@pytest.mark.parametrize(
    ("spl", "why"),
    [
        ('index=logforge Channel="Security" EventId=4624', "the real pairing"),
        (
            'index=logforge Channel="Microsoft-Windows-Sysmon/Operational" EventId=1',
            "the other real pairing",
        ),
        ("index=logforge EventId=4624 | head 5", "no channel pinned at all"),
        ('index=logforge Channel="Security" EventId=9999', "event id never observed"),
        ('index=logforge Channel="*" EventId=4624', "a wildcard is casting wide on purpose"),
        (
            'index=logforge (EventId=1 OR EventId=4624) Channel="Security"',
            "more than one id — the author is deliberately broad",
        ),
    ],
)
def test_legitimate_selectors_are_not_refused(paired_schema, spl, why) -> None:
    report = validate_spl(spl, paired_schema)

    assert not any("never appears on" in e for e in report.errors), why


def test_the_check_is_silent_when_nothing_was_discovered(schema) -> None:
    """A dataset with no such pairing must not be judged by another one's.

    The base schema fixture carries no event_channels, which is what Stage 1
    produces for data that has no Channel field at all.
    """
    report = validate_spl(
        'index=logforge Channel="anything" EventId=4624', schema
    )

    assert not any("never appears on" in e for e in report.errors)


def test_the_pairings_come_from_the_live_index_not_a_builtin_list() -> None:
    """The rule is measured per dataset, so a different index gets a different
    verdict for the identical query."""
    from soc_copilot.schema import FieldInfo, Schema

    def build(pairs):
        return Schema(
            index="logforge", indexes=[],
            fields=[FieldInfo(name=n, event_count=1, distinct_count=1, is_exact=True)
                    for n in ("EventId", "Channel")],
            event_channels=pairs,
        )

    spl = 'index=logforge Channel="Operations" EventId=4624'
    strict = validate_spl(spl, build({"4624": frozenset({"Security"})}))
    lenient = validate_spl(spl, build({"4624": frozenset({"Security", "Operations"})}))

    assert any("never appears on" in e for e in strict.errors)
    assert not any("never appears on" in e for e in lenient.errors)
