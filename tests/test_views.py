"""Stage 4: three renderings, one engine.

The point of the views is that they are renderings and nothing more. What an
answer is allowed to claim is settled by the guardrails before any of them runs,
so the tests that matter most here are the ones asserting a view cannot promote
a claim the guardrails refused — in particular that no view prints an unanchored
literal as though Splunk had returned it.
"""

from __future__ import annotations

import json

import pytest

from soc_copilot.agent import investigate
from soc_copilot.views import (
    SCHEMA_VERSION,
    VIEWS,
    render,
    render_human,
    render_json,
    render_spl,
    to_payload,
)
from tests.conftest import ScriptedBackend, ScriptedClient

GUID = "{a1b2c3d4-1111-2222-3333-444455556666}"
CMD_PATH = "C:\\Windows\\System32\\cmd.exe"


def _extract(name: str) -> str:
    return (
        f"| eval {name} = mvindex('EventData.Data{{}}.#text', "
        f"mvfind('EventData.Data{{}}.@Name', \"^{name}$\"))"
    )


FIND_SPL = (
    "index=logforge EventId=1 | spath input=Payload "
    + _extract("ProcessGuid")
    + " "
    + _extract("Image")
    + " | table ProcessGuid, Image"
)


@pytest.fixture
def answered(schema, shape, library):
    """A clean run: one search, one grounded answer."""
    backend = ScriptedBackend(
        {
            "action": "search",
            "purpose": "find the process creation",
            "spl": FIND_SPL,
            "earliest": "0",
            "latest": "",
        },
        {
            "action": "answer",
            "answer": f"The process {GUID} ran {CMD_PATH} on DESKTOP-01.",
            "evidence": "step 1",
        },
    )
    client = ScriptedClient(
        [{"ProcessGuid": GUID, "Image": CMD_PATH, "Computer": "DESKTOP-01"}]
    )
    return investigate(
        "what ran on DESKTOP-01",
        schema,
        library,
        client=client,
        backend=backend,
        shape=shape,
    )


@pytest.fixture
def fabricated(schema, shape, library):
    """A run whose answer names a binary that appears in no returned row."""
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL, "earliest": "0", "latest": ""},
        {
            "action": "answer",
            "answer": "The process dropped C:\\Users\\victim\\backdoor.exe.",
            "evidence": "step 1",
        },
    )
    client = ScriptedClient([{"ProcessGuid": GUID, "Image": CMD_PATH}])
    return investigate(
        "what was dropped",
        schema,
        library,
        client=client,
        backend=backend,
        shape=shape,
    )


# --------------------------------------------------------------------------
# human
# --------------------------------------------------------------------------


def test_the_human_view_shows_the_answer_the_spl_and_the_rows(answered) -> None:
    """The three things an analyst needs to agree or disagree with a conclusion."""
    out = render_human(answered)

    assert CMD_PATH in out
    assert "spath input=Payload" in out       # the SPL that produced it
    assert "step 1, row 1" in out             # the row it came from
    assert "ProcessGuid" in out


def test_the_human_view_states_the_time_range_with_the_query(answered) -> None:
    """SPL without its window is a different search, and silently so."""
    out = render_human(answered)

    assert "earliest='0'" in out
    assert "all time" in out


def test_the_human_view_marks_an_unanchored_literal_instead_of_asserting_it(
    fabricated,
) -> None:
    out = render_human(fabricated)

    assert "[UNVERIFIED: C:\\Users\\victim\\backdoor.exe]" in out
    assert "UNSUPPORTED CLAIMS" in out
    assert "NOT fully supported" in out


def test_the_human_view_never_prints_the_unredacted_draft(fabricated) -> None:
    """The whole point: the fabricated value must not read as a finding."""
    out = render_human(fabricated)

    assert "dropped C:\\Users\\victim\\backdoor.exe" not in out


def test_the_human_view_reports_the_guardrails_that_ran(answered) -> None:
    out = render_human(answered)

    assert "Read-only policy" in out
    assert "literal anchoring" in out
    assert "queries executed  : 1" in out
    assert "overall           : PASS" in out


def test_the_human_view_says_when_nothing_could_be_answered(
    schema, shape, library
) -> None:
    backend = ScriptedBackend(
        {"action": "unanswerable", "reason": "$MFT internals are not indexed."},
        # Insisted on after the loop challenged a give-up with no searches.
        {"action": "unanswerable", "reason": "$MFT internals are not indexed."},
    )
    result = investigate(
        "what is inside the MFT record",
        schema,
        library,
        client=ScriptedClient([]),
        backend=backend,
        shape=shape,
    )

    out = render_human(result)

    assert "$MFT internals are not indexed." in out
    assert "not in what was ingested" in out
    assert "(no search was executed)" in out


# --------------------------------------------------------------------------
# spl
# --------------------------------------------------------------------------


def test_the_spl_view_is_the_query_and_its_window(answered) -> None:
    out = render_spl(answered)

    assert out.strip().splitlines()[1].startswith("index=logforge")
    assert "earliest='0'" in out
    # No prose, no report furniture — this is meant to be pasted.
    assert "ANSWER" not in out
    assert "GUARDRAILS" not in out


def test_the_spl_view_stays_pasteable_when_nothing_ran(schema, shape, library) -> None:
    """Empty output would vanish into a search bar; an SPL comment does not."""
    backend = ScriptedBackend(
        {"action": "unanswerable", "reason": "not indexed"},
        {"action": "unanswerable", "reason": "not indexed"},
    )
    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    out = render_spl(result)

    assert out.startswith("```") and out.endswith("```")
    assert "not indexed" in out


def test_the_spl_view_emits_every_executed_query(schema, shape, library) -> None:
    pivot = (
        "index=logforge EventId=1 | spath input=Payload "
        + _extract("ParentProcessGuid")
        + f' | search ParentProcessGuid="{GUID}" | table Computer'
    )
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "search", "spl": pivot},
        {"action": "answer", "answer": "Two searches ran.", "evidence": "steps 1-2"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}], [{"Computer": "DESKTOP-01"}])
    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    out = render_spl(result)

    assert "step 1" in out and "step 2" in out
    assert "ParentProcessGuid" in out


# --------------------------------------------------------------------------
# json
# --------------------------------------------------------------------------


def test_the_json_view_is_valid_json_with_a_versioned_schema(answered) -> None:
    payload = json.loads(render_json(answered))

    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["question"] == "what ran on DESKTOP-01"
    assert payload["ok"] is True


def test_the_json_view_reports_every_guardrail_outcome(answered) -> None:
    guardrails = to_payload(answered)["guardrails"]

    assert guardrails["read_only"]["enforced"] is True
    assert guardrails["read_only"]["refused"] == []
    assert guardrails["anchoring"]["ok"] is True
    assert guardrails["untrusted_input"]["field_values_sealed"] is True


def test_the_json_answer_text_is_the_anchored_one_not_the_draft(fabricated) -> None:
    """A consumer reading ``text`` cannot accidentally publish a fabrication."""
    answer = to_payload(fabricated)["answer"]

    assert "[UNVERIFIED:" in answer["text"]
    assert answer["fully_anchored"] is False
    assert "backdoor.exe" in answer["draft"]  # kept, but named as a draft


def test_the_json_view_carries_the_provenance_of_each_literal(answered) -> None:
    literals = to_payload(answered)["guardrails"]["anchoring"]["literals"]
    by_value = {lit["value"]: lit for lit in literals}

    anchors = by_value[GUID]["anchors"]
    assert anchors[0] == {"source": "step 1", "row": 1, "field": "ProcessGuid"}


def test_the_json_view_carries_the_rows_behind_the_answer(answered) -> None:
    payload = to_payload(answered)

    assert payload["anchored_rows"][0]["fields"]["Computer"] == "DESKTOP-01"
    assert payload["searches"][0]["row_count"] == 1
    assert "spath" in payload["searches"][0]["commands"]


def test_a_refused_query_is_recorded_in_the_json_view(schema, shape, library) -> None:
    backend = ScriptedBackend(
        {"action": "search", "spl": "index=logforge | delete"},
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "One search ran.", "evidence": "step 2"},
    )
    result = investigate(
        "q",
        schema,
        library,
        client=ScriptedClient([{"ProcessGuid": GUID}]),
        backend=backend,
        shape=shape,
    )

    refused = to_payload(result)["guardrails"]["read_only"]["refused"]

    assert len(refused) == 1
    assert refused[0]["step"] == 1
    assert "delete" in refused[0]["reason"]


# --------------------------------------------------------------------------
# all three
# --------------------------------------------------------------------------


FABRICATED = "C:\\Users\\victim\\backdoor.exe"


@pytest.mark.parametrize("view", VIEWS)
def test_no_view_presents_an_unanchored_literal_as_fact(fabricated, view) -> None:
    """The invariant the views exist under, asserted for every one of them.

    The value is not deleted — deleting it would leave a fluent sentence that
    reads as verified, and would hide from the analyst what the model tried to
    say. It is marked. So the assertion is that every place the value survives
    is a place that says it is unsupported.
    """
    out = render(fabricated, view)

    unmarked = out.replace(f"[UNVERIFIED: {FABRICATED}]", "")
    if "UNSUPPORTED CLAIMS" in unmarked:  # the human view lists them again
        head, _, tail = unmarked.partition("-- UNSUPPORTED CLAIMS")
        unmarked = head + tail.partition("-- SPL USED")[2]
    assert FABRICATED not in unmarked


def test_the_json_view_marks_rather_than_hides_the_fabrication(fabricated) -> None:
    payload = to_payload(fabricated)

    assert f"[UNVERIFIED: {FABRICATED}]" in payload["answer"]["text"]
    assert payload["answer"]["fully_anchored"] is False
    assert FABRICATED in payload["guardrails"]["anchoring"]["unverified"]
    assert payload["ok"] is False


@pytest.mark.parametrize("view", VIEWS)
def test_every_view_renders_without_an_answer(schema, shape, library, view) -> None:
    backend = ScriptedBackend(
        {"action": "unanswerable", "reason": "not indexed"},
        {"action": "unanswerable", "reason": "not indexed"},
    )
    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    assert render(result, view).strip()


def test_an_unknown_view_is_refused_by_name() -> None:
    with pytest.raises(ValueError, match="Unknown view"):
        render(None, "yaml")  # type: ignore[arg-type]
