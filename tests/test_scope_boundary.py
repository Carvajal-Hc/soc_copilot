"""The edge of what the tool can answer, and what happens at it.

CLAUDE.md draws a scope boundary: the tool answers what is answerable from data
ingested into Splunk, and raw-artifact work — content resident inside ``$MFT``,
UTF-16 strings, byte-level carving — belongs to the human analyst. "Not found"
must mean "not in what was ingested", never "does not exist", and never a
plausible value invented to fill the gap.

Two different mechanisms keep that promise, and conflating them would overstate
the guarantee:

1. **The model declining honestly.** Desirable, and the usual outcome, but it is
   model behaviour. It is not a guarantee, and it varies by backend.
2. **Literal anchoring.** Deterministic, always runs, and does not care what the
   model intended. This is the guarantee.

The tests below cover the second, because the second is the one that has to hold
when the first fails. A run where the model refuses honestly never exercises
anchoring at all — so a demonstration built only on the happy path would prove
nothing about the backstop.
"""

from __future__ import annotations

import pytest

from soc_copilot.agent import STOP_UNANSWERABLE, investigate
from soc_copilot.guardrails import EvidenceSource, anchor_literals
from soc_copilot.views import render_human, to_payload
from tests.conftest import ScriptedBackend, ScriptedClient

#: The question that crosses the line. The file-create event for this path IS
#: indexed (Sysmon EID 11 records that a file was written); the file's CONTENT
#: is not, and no amount of searching will produce it.
QUESTION = (
    "The file C:\\Users\\Public\\README.txt was written to disk. "
    "What text does it contain?"
)

#: What a model with no guardrail would produce: fluent, specific, and invented.
#: Every concrete value in it is the kind an analyst would act on.
FABRICATED = (
    "The ransom note reads: 'Your files have been encrypted. Your personal ID is "
    "d41d8cd98f00b204e9800998ecf8427e. To recover them, run "
    "C:\\Users\\Public\\decrypt_tool.exe and contact us. Do not restart, or "
    "10.20.30.40 will delete your key.'"
)

#: The one search that legitimately ran: the file-create event exists, and its
#: row proves the file was written without saying anything about its contents.
FILE_CREATE_ROW = {
    "_time": "2025-08-11T07:31:00.485-07:00",
    "Computer": "user",
    "ProcessGuid": "a5ea900f-97f3-6899-6801-000000000800",
    "TargetFilename": "C:\\Users\\Public\\README.txt",
}

FIND_SPL = (
    "index=logforge EventId=11 | spath input=Payload "
    "| eval TargetFilename = mvindex('EventData.Data{}.#text', "
    "mvfind('EventData.Data{}.@Name', \"^TargetFilename$\")) "
    '| search TargetFilename="*README.txt" | table _time, Computer, TargetFilename'
)


# --------------------------------------------------------------------------
# The guarantee: anchoring catches the fabrication regardless of intent
# --------------------------------------------------------------------------


def test_a_fabricated_file_content_answer_is_caught_by_anchoring() -> None:
    """The model invents a ransom note. Every literal in it came from nowhere.

    This is the failure the architecture exists to prevent, in its most
    dangerous form: the answer is fluent, specific, internally consistent, and
    an analyst could act on it. Nothing about how it reads distinguishes it from
    a real finding. Only checking it against the returned rows does.
    """
    report = anchor_literals(
        FABRICATED,
        [EvidenceSource(label="step 1", spl=FIND_SPL, rows=(FILE_CREATE_ROW,))],
        question=QUESTION,
    )

    assert not report.ok
    # The hash, the invented binary and the IP are all unsupported.
    assert "d41d8cd98f00b204e9800998ecf8427e" in report.unverified
    assert "C:\\Users\\Public\\decrypt_tool.exe" in report.unverified
    assert "10.20.30.40" in report.unverified


def test_the_one_real_value_still_anchors_while_the_invented_ones_do_not() -> None:
    """Anchoring is not a blanket rejection — it separates the two kinds.

    The README.txt path is real: it came out of a returned row. The rest did
    not. An analyst reading the marked-up answer can see exactly which half of
    the claim survived contact with the data.
    """
    answer = (
        "C:\\Users\\Public\\README.txt was created, and it contains the ID "
        "d41d8cd98f00b204e9800998ecf8427e."
    )

    report = anchor_literals(
        answer,
        [EvidenceSource(label="step 1", spl=FIND_SPL, rows=(FILE_CREATE_ROW,))],
    )

    assert "C:\\Users\\Public\\README.txt" in report.verified
    assert "d41d8cd98f00b204e9800998ecf8427e" in report.unverified
    assert not report.ok


def test_the_fabricated_content_is_rewritten_out_of_every_view() -> None:
    """A caught fabrication must not survive into anything a human reads."""
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL, "earliest": "0", "latest": ""},
        {"action": "answer", "answer": FABRICATED, "evidence": "step 1"},
    )

    from soc_copilot.payload_shape import PayloadShape
    from soc_copilot.schema import FieldInfo, Schema

    schema = Schema(
        index="logforge",
        indexes=[],
        fields=[
            FieldInfo(name=n, event_count=1, distinct_count=1, is_exact=True)
            for n in ("EventId", "Channel", "Computer", "Payload", "_time")
        ],
    )
    shape = PayloadShape(
        index="logforge",
        container="Payload",
        encoding="json",
        layout="name-value-array",
        name_path="EventData.Data{}.@Name",
        text_path="EventData.Data{}.#text",
        nested_names=("TargetFilename", "ProcessGuid"),
        stratified_by=("EventId",),
        event_types=(),
        sampled_events=1,
    )

    from soc_copilot.library import load_library

    result = investigate(
        QUESTION,
        schema,
        load_library().with_index("logforge"),
        client=ScriptedClient([FILE_CREATE_ROW]),
        backend=backend,
        shape=shape,
    )

    assert not result.ok  # concluded, but the conclusion is not supported
    human = render_human(result)
    payload = to_payload(result)

    for invented in (
        "d41d8cd98f00b204e9800998ecf8427e",
        "C:\\Users\\Public\\decrypt_tool.exe",
        "10.20.30.40",
    ):
        assert f"[UNVERIFIED: {invented}]" in human
        assert invented not in payload["answer"]["text"].replace(
            f"[UNVERIFIED: {invented}]", ""
        )
    assert payload["answer"]["fully_anchored"] is False
    assert "UNSUPPORTED CLAIMS" in human


# --------------------------------------------------------------------------
# The desirable outcome: declining honestly, and being taken at its word
# --------------------------------------------------------------------------


def test_an_honest_out_of_scope_refusal_is_accepted_after_looking(
    schema, shape, library
) -> None:
    """The model searches, finds the event but not the content, and says so.

    Note the ordering the loop enforces: it must run a search first. "Not in
    what was ingested" is a claim about the index, and the loop will not accept
    it from a model that never queried the index.
    """
    reason = (
        "The file-create event for C:\\Users\\Public\\README.txt is indexed, but "
        "file CONTENT is not — Sysmon records that a file was written, never what "
        "was written into it. Recovering the note's text is raw-artifact work on "
        "the disk image and is out of scope for this tool."
    )
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL, "earliest": "0", "latest": ""},
        {"action": "unanswerable", "reason": reason},
    )

    result = investigate(
        QUESTION,
        schema,
        library,
        client=ScriptedClient([FILE_CREATE_ROW]),
        backend=backend,
        shape=shape,
    )

    assert result.stop_reason == STOP_UNANSWERABLE
    assert result.ok  # an honest "cannot" is a correct outcome, not a failure
    assert "out of scope" in result.unsupported_reason
    assert "not in what was ingested" in render_human(result)


def test_not_found_is_never_rendered_as_does_not_exist(
    schema, shape, library
) -> None:
    """The wording matters: absence of evidence is not evidence of absence.

    An analyst who reads "no ransom note exists" and moves on has been actively
    misled. The view is required to say what the tool actually knows.
    """
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL, "earliest": "0", "latest": ""},
        {"action": "unanswerable", "reason": "content is not indexed"},
    )

    result = investigate(
        QUESTION,
        schema,
        library,
        client=ScriptedClient([]),  # zero rows
        backend=backend,
        shape=shape,
    )

    human = render_human(result)

    assert "not in what was ingested" in human
    assert "does not exist" not in human.lower().replace(
        "not that it does not exist", ""
    )


@pytest.mark.parametrize(
    "invented",
    [
        "the note says 'pay 1 BTC to recover', per the file at C:\\evil\\note.txt",
        "the ID inside it is 5d41402abc4b2a76b9719d911017c592",
        "it instructs the victim to contact 192.0.2.99",
    ],
)
def test_any_shape_of_invented_artifact_detail_is_flagged(invented: str) -> None:
    """The scope boundary is not one question; it is a class of them."""
    report = anchor_literals(
        invented,
        [EvidenceSource(label="step 1", spl=FIND_SPL, rows=(FILE_CREATE_ROW,))],
    )

    assert not report.ok


# --------------------------------------------------------------------------
# Declining is not enough — it has to say why
# --------------------------------------------------------------------------


def test_an_unanswerable_with_no_reason_is_sent_back(schema, shape, library) -> None:
    """Observed live: the 14b declined this exact question and said nothing.

    Refusing correctly is half the requirement. CLAUDE.md asks the tool to say
    *plainly* when it cannot answer, and "(no reason given)" leaves the analyst
    unable to tell whether the data is missing, the question is out of scope, or
    the model gave up — three findings with three different next actions.
    """
    good = (
        "Sysmon records that a file was written, never its contents. "
        "Recovering the text is raw-artifact work and is out of scope."
    )
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL, "earliest": "0", "latest": ""},
        {"action": "unanswerable", "reason": ""},
        {"action": "unanswerable", "reason": good},
    )

    result = investigate(
        QUESTION,
        schema,
        library,
        client=ScriptedClient([FILE_CREATE_ROW]),
        backend=backend,
        shape=shape,
    )

    assert result.steps[1].action == "malformed"
    assert "gave no reason" in result.steps[1].note
    assert result.unsupported_reason == good
    assert result.ok


def test_a_persistently_silent_refusal_is_not_reported_as_a_data_finding(
    schema, shape, library
) -> None:
    """"No answer was produced" and "the data has no answer" are different claims.

    If the loop never learns why, it must not quietly present the stronger one.
    """
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        *[{"action": "unanswerable", "reason": ""} for _ in range(3)],
    )

    result = investigate(
        QUESTION,
        schema,
        library,
        client=ScriptedClient([FILE_CREATE_ROW]),
        backend=backend,
        shape=shape,
    )

    assert not result.ok
    assert "not as 'the data has no answer'" in result.unsupported_reason
