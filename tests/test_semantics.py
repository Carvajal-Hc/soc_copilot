"""The semantic-output check: does the query answer the question that was asked?

This is the F1 follow-up. Q3 asked what each *process* connected to on the
network, and a local model produced SPL that grouped by ``DestinationIp`` —
read-only, real field names, correct nested extraction, real rows returned, and
answering a different question. Every other check in the project had nothing to
say about it.

The tests are held to both directions, on the same discipline as the injection
suite: a check that never fires is as useless as one that always does. So the Q3
shape must be flagged, the *correct* query for the identical question must not
be, and a battery of real questions from this project's own history must stay
silent. A semantic warning that cries wolf is one an analyst learns to skip,
which is worse than no warning at all.
"""

from __future__ import annotations

import pytest

from soc_copilot.semantics import (
    check_alignment,
    classify_field,
    output_fields,
    question_subjects,
)

Q3 = "what did each process connect to on the network?"


def _extract(name: str) -> str:
    return (
        f"| eval {name} = mvindex('EventData.Data{{}}.#text', "
        f"mvfind('EventData.Data{{}}.@Name', \"^{name}$\"))"
    )


#: The query F1 recorded: extracts Image, then rolls up by destination anyway.
Q3_WRONG = (
    "index=logforge EventId=3 | spath input=Payload "
    + _extract("Image")
    + " "
    + _extract("DestinationIp")
    + " | stats count by DestinationIp | sort 0 - count"
)

#: The query that answers the question actually asked.
Q3_RIGHT = (
    "index=logforge EventId=3 | spath input=Payload "
    + _extract("Image")
    + " "
    + _extract("DestinationIp")
    + " | stats values(DestinationIp) as destinations, count by Image"
)


# --------------------------------------------------------------------------
# Q3 itself — the case this exists for
# --------------------------------------------------------------------------


def test_q3_grouping_by_destination_is_flagged() -> None:
    report = check_alignment(Q3, Q3_WRONG)

    assert not report.ok
    assert report.subjects == ("process",)
    assert report.grouped_by == ("DestinationIp",)


def test_q3_flagged_warning_names_both_sides_of_the_mismatch() -> None:
    """The analyst has to see what was asked *and* what the query did.

    "This might be wrong" is not actionable; "you asked about processes, this
    groups by DestinationIp" is a one-second judgement.
    """
    warning = check_alignment(Q3, Q3_WRONG).warning

    assert "process" in warning
    assert "DestinationIp" in warning
    assert "may not answer what was asked" in warning


def test_the_correct_query_for_the_same_question_is_not_flagged() -> None:
    """The control. Without this, a check that always fires would look identical."""
    report = check_alignment(Q3, Q3_RIGHT)

    assert report.ok
    assert report.grouped_by == ("Image",)


def test_extracting_the_field_but_dropping_it_does_not_count_as_answering() -> None:
    """The subtlety that makes Q3 hard, and the reason the pipeline is walked.

    ``Q3_WRONG`` contains the string "Image" — it evals it. A check that scanned
    the query text for a process field would call it aligned. But ``stats count
    by DestinationIp`` rebuilds the result set and Image is gone before any row
    is returned.
    """
    surviving, grouped = output_fields(Q3_WRONG)

    assert "Image" not in surviving
    assert surviving == ("DestinationIp",)
    assert grouped == ("DestinationIp",)


def test_a_warning_is_advisory_and_says_so() -> None:
    """It must not read as a verdict — the analyst decides, the tool surfaces."""
    warning = check_alignment(Q3, Q3_WRONG).warning

    assert "Not blocked and not corrected" in warning
    assert "yours" in warning


# --------------------------------------------------------------------------
# Silence on real questions — the expensive half to get right
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("question", "spl"),
    [
        (
            "which hosts recorded Sysmon process-creation events, and how many each?",
            "index=logforge EventId=1 | stats count by Computer | sort 0 - count",
        ),
        (
            "which .evtx source files were these events ingested from, "
            "and how many events came from each?",
            "index=logforge EventId=11 | stats count by Computer, SourceFile",
        ),
        (
            "which files did that same process write to disk?",
            "index=logforge EventId=11 | spath input=Payload "
            + _extract("TargetFilename")
            + ' | search ProcessGuid="a5ea" | table _time, Computer, TargetFilename',
        ),
        (
            "what kinds of events are in the index?",
            "index=logforge | stats count by Channel, EventId",
        ),
        (
            "how many events per host?",
            "index=logforge | stats count by Computer",
        ),
        (
            "how many events are there in total?",
            "index=logforge | stats count",
        ),
        (
            "show me the raw events for event id 4624",
            "index=logforge EventId=4624 | head 20",
        ),
        (
            "which users logged on, and to which machines?",
            "index=logforge EventId=4624 | stats count by TargetUserName, Computer",
        ),
        (
            "top 10 destination ips contacted",
            "index=logforge EventId=3 | spath input=Payload "
            + _extract("DestinationIp")
            + " | top limit=10 DestinationIp",
        ),
    ],
)
def test_real_questions_with_matching_queries_stay_silent(question, spl) -> None:
    """Every one of these is a question actually asked of this tool."""
    report = check_alignment(question, spl)

    assert report.ok, f"false positive: {report.warning}"


def test_a_question_with_no_explicit_subject_produces_silence() -> None:
    """No opinion is a valid output, and the report says which it is."""
    report = check_alignment(
        "is there anything suspicious going on here?",
        "index=logforge | stats count by DestinationIp",
    )

    assert report.ok
    assert "no explicit subject" in report.quiet_reason


def test_a_query_returning_whole_events_is_never_flagged() -> None:
    """Raw events still carry every field, so nothing is missing from the output."""
    report = check_alignment(
        "what did each process connect to?",
        "index=logforge EventId=3 | head 20",
    )

    assert report.ok
    assert "does not reshape" in report.quiet_reason


# --------------------------------------------------------------------------
# The pieces
# --------------------------------------------------------------------------


def test_the_subject_is_the_noun_the_question_enumerates() -> None:
    """Q3 names both a process and a network. Only one is the subject."""
    concepts = {concept for concept, _ in question_subjects(Q3)}

    assert "process" in concepts
    assert "network_destination" not in concepts


@pytest.mark.parametrize(
    ("field", "concept"),
    [
        ("Image", "process"),
        ("ProcessGuid", "process"),
        ("ParentImage", "process"),
        ("Computer", "host"),
        ("TargetUserName", "user"),
        ("DestinationIp", "network_destination"),
        ("TargetFilename", "file"),
        ("EventId", "event"),
    ],
)
def test_fields_classify_to_the_entity_they_represent(field, concept) -> None:
    assert concept in classify_field(field)


def test_an_ambiguous_field_carries_every_concept_it_could_mean() -> None:
    """DestinationHostname is a destination and a host. Ambiguity favours silence.

    Counting it as both means a question about hosts is not flagged against it,
    which is the safe direction for a check whose false positives cost more than
    its false negatives.
    """
    concepts = classify_field("DestinationHostname")

    assert "network_destination" in concepts
    assert "host" in concepts


def test_a_projection_after_a_rollup_is_what_survives() -> None:
    surviving, _ = output_fields(
        "index=logforge | stats count by Image, DestinationIp | table Image"
    )

    assert surviving == ("Image",)


def test_a_field_created_after_the_rollup_still_counts() -> None:
    """An eval *after* stats adds to the output rather than being discarded."""
    surviving, _ = output_fields(
        "index=logforge | stats count by DestinationIp | eval Image=\"n/a\""
    )

    assert "Image" in surviving
