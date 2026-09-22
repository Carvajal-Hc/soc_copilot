"""Stage 3: the tool-using loop.

A scripted backend plays the model and a scripted client plays Splunk, so these
tests assert on the half that is ours: that the tool refuses what it should,
that the loop pivots on a value it was actually shown, that it always stops, and
that a literal in the answer which came from no row is caught.

No test here touches a real Splunk instance or a real model.
"""

from __future__ import annotations

import json

import pytest

from soc_copilot.agent import (
    MAX_MALFORMED,
    STOP_ANSWERED,
    STOP_BUDGET,
    STOP_MALFORMED,
    STOP_STUCK,
    STOP_UNANSWERABLE,
    AgentError,
    SearchTool,
    check_grounding,
    investigate,
    render_rows_for_model,
)
from soc_copilot.splunk_client import SplunkSearchError
from tests.conftest import ScriptedBackend, ScriptedClient

GUID = "{a1b2c3d4-1111-2222-3333-444455556666}"


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
PIVOT_SPL = (
    f'index=logforge EventId=1 | spath input=Payload {_extract("ParentProcessGuid")} '
    f'{_extract("Image")} | search ParentProcessGuid="{GUID}" | table Image'
)


# --------------------------------------------------------------------------
# The tool
# --------------------------------------------------------------------------


def test_tool_runs_a_valid_search_and_returns_rows(schema, shape):
    client = ScriptedClient([{"Image": "C:\\Windows\\System32\\cmd.exe"}])
    tool = SearchTool(client, schema, shape)

    result = tool.call("index=logforge EventId=1 | stats count by Computer")

    assert result.ok
    assert result.row_count == 1
    assert client.calls[0]["earliest"] == "0"
    assert client.calls[0]["latest"] == ""


def test_tool_refuses_a_mutating_search_without_dispatching(schema, shape):
    client = ScriptedClient([{"x": 1}])
    tool = SearchTool(client, schema, shape)

    result = tool.call("index=logforge | delete")

    assert not result.ok
    assert not result.executed
    assert client.calls == []
    assert "read-only" in result.error


def test_tool_refuses_a_nested_field_referenced_as_flat(schema, shape):
    """The Stage 2 guardrail still applies to every query the loop writes."""
    client = ScriptedClient([{"x": 1}])
    tool = SearchTool(client, schema, shape)

    result = tool.call("index=logforge | stats count by ProcessGuid")

    assert not result.executed
    assert client.calls == []
    assert "ProcessGuid" in result.error
    assert "Payload" in result.error


def test_tool_turns_a_splunk_failure_into_an_observation(schema, shape):
    client = ScriptedClient(SplunkSearchError("Splunk could not run that search"))
    tool = SearchTool(client, schema, shape)

    result = tool.call("index=logforge | stats count by Computer")

    assert not result.ok
    assert "could not run" in result.error


# --------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------


def test_loop_pivots_on_an_identifier_from_the_first_result(schema, shape, library):
    """find an event -> pivot on its ProcessGuid -> answer. The core flow."""
    backend = ScriptedBackend(
        {"action": "search", "purpose": "find the process", "spl": FIND_SPL,
         "earliest": "0", "latest": ""},
        {"action": "search", "purpose": "children of that process", "spl": PIVOT_SPL,
         "earliest": "0", "latest": ""},
        {"action": "answer",
         "answer": f"powershell.exe was spawned by the process with ProcessGuid {GUID}.",
         "evidence": "step 2"},
    )
    client = ScriptedClient(
        [{"ProcessGuid": GUID, "Image": "C:\\Windows\\System32\\cmd.exe"}],
        [{"Image": "C:\\Windows\\System32\\powershell.exe"}],
    )

    result = investigate(
        "what did the cmd.exe process spawn",
        schema,
        library,
        client=client,
        backend=backend,
        shape=shape,
    )

    assert result.stop_reason == STOP_ANSWERED
    assert len(result.searches) == 2
    # The pivot filtered on the GUID the first search returned, not on a category.
    assert GUID in client.calls[1]["spl"]
    assert result.ok
    assert result.grounding.ok


def test_rows_from_a_step_are_shown_to_the_model_on_the_next_turn(
    schema, shape, library
):
    backend = ScriptedBackend(
        {"action": "search", "purpose": "find", "spl": FIND_SPL},
        {"action": "answer", "answer": "Done.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID, "Image": "cmd.exe"}])

    investigate("q", schema, library, client=client, backend=backend, shape=shape)

    second_prompt = backend.prompts[1]
    assert GUID in second_prompt
    assert "1 row(s)" in second_prompt


def test_loop_stops_when_the_model_answers(schema, shape, library):
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "One process ran.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert result.answer == "One process ran."
    assert len(client.calls) == 1
    assert backend.replies == []  # it did not ask for another turn


def test_loop_stops_at_the_step_budget_without_inventing_an_answer(
    schema, shape, library
):
    search = {
        "action": "search",
        "purpose": "again",
        "spl": "index=logforge | stats count by Computer",
    }
    # More search actions than the budget allows, and it never answers.
    backend = ScriptedBackend(
        {**search, "spl": "index=logforge EventId=1 | stats count by Computer"},
        {**search, "spl": "index=logforge EventId=3 | stats count by Computer"},
        {**search, "spl": "index=logforge EventId=11 | stats count by Computer"},
    )
    client = ScriptedClient([{"count": "1"}], [{"count": "2"}], [{"count": "3"}])

    result = investigate(
        "q",
        schema,
        library,
        client=client,
        backend=backend,
        shape=shape,
        max_steps=2,
    )

    assert result.stop_reason == STOP_BUDGET
    assert len(client.calls) == 2  # the third was never dispatched
    assert result.answer == ""
    assert "budget" in result.unsupported_reason


def test_loop_refuses_to_re_run_an_identical_search(schema, shape, library):
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "search", "spl": FIND_SPL},  # same query, reformatted below
        {"action": "answer", "answer": "Nothing further.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert len(client.calls) == 1
    refused = [s for s in result.steps if s.action == "refused"]
    assert refused and "same search" in refused[0].result.error


def test_a_rejected_query_is_fed_back_so_the_loop_can_correct_it(
    schema, shape, library
):
    backend = ScriptedBackend(
        {"action": "search", "spl": "index=logforge | stats count by ProcessGuid"},
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "Corrected.", "evidence": "step 2"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert len(client.calls) == 1  # the bad query never reached Splunk
    assert "NOT RUN" in backend.prompts[1]
    assert result.stop_reason == STOP_ANSWERED


def test_unanswerable_is_a_valid_conclusion(schema, shape, library):
    backend = ScriptedBackend(
        {"action": "unanswerable",
         "reason": "$MFT internals are not indexed; that is raw-artifact work."},
        # The loop challenges a give-up that ran no searches; it insists, which
        # is its right. The transcript records that it was asked twice.
        {"action": "unanswerable",
         "reason": "$MFT internals are not indexed; that is raw-artifact work."},
    )
    client = ScriptedClient()

    result = investigate(
        "what is resident in the $MFT",
        schema,
        library,
        client=client,
        backend=backend,
        shape=shape,
    )

    assert result.stop_reason == STOP_UNANSWERABLE
    assert not result.answerable
    assert result.ok  # an honest "not in this data" is a correct outcome
    assert client.calls == []


def test_persistent_garbage_from_the_backend_stops_the_loop(schema, shape, library):
    backend = ScriptedBackend("not json", "still not json", "nope")
    client = ScriptedClient()

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_MALFORMED
    assert result.answer == ""
    assert client.calls == []


def test_empty_question_is_refused(schema, shape, library):
    with pytest.raises(AgentError):
        investigate(
            "   ",
            schema,
            library,
            client=ScriptedClient(),
            backend=ScriptedBackend(),
            shape=shape,
        )


# --------------------------------------------------------------------------
# Grounding
# --------------------------------------------------------------------------


def test_grounding_accepts_a_literal_that_came_from_a_row(schema, shape):
    tool = SearchTool(ScriptedClient([{"Image": "C:\\Windows\\System32\\cmd.exe"}]), schema, shape)
    tool.call("index=logforge | stats count by Computer")

    report = check_grounding("The binary was C:\\Windows\\System32\\cmd.exe.", tool.calls)

    assert report.ok
    assert report.verified


def test_grounding_flags_a_literal_that_came_from_nowhere(schema, shape):
    """The failure this architecture exists to prevent: an invented value."""
    tool = SearchTool(ScriptedClient([{"Image": "C:\\Windows\\System32\\cmd.exe"}]), schema, shape)
    tool.call("index=logforge | stats count by Computer")

    report = check_grounding("The binary was C:\\Users\\victim\\evil.exe.", tool.calls)

    assert not report.ok
    assert any("evil.exe" in value for value in report.unverified)


def test_grounding_matches_a_path_escaped_inside_a_json_payload(schema, shape):
    tool = SearchTool(
        ScriptedClient([{"Payload": '{"Image":"C:\\\\Windows\\\\System32\\\\cmd.exe"}'}]),
        schema,
        shape,
    )
    tool.call("index=logforge | table Payload")

    report = check_grounding("It ran C:\\Windows\\System32\\cmd.exe.", tool.calls)

    assert report.ok


def test_grounding_accepts_a_value_the_analyst_supplied(schema, shape):
    tool = SearchTool(ScriptedClient([]), schema, shape)
    tool.call("index=logforge | stats count by Computer")

    report = check_grounding(
        "No events reference 10.0.0.5.", tool.calls, question="did anything talk to 10.0.0.5"
    )

    assert report.ok


def test_grounding_is_quiet_when_there_is_nothing_to_check(schema, shape):
    report = check_grounding("Three processes ran on one host.", ())

    assert report.ok
    assert report.no_literals


def test_ungrounded_answer_makes_the_investigation_not_ok(schema, shape, library):
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "It was C:\\evil\\backdoor.exe.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_ANSWERED
    assert not result.ok  # concluded, but the conclusion is not supported
    assert not result.grounding.ok


# --------------------------------------------------------------------------
# Row rendering
# --------------------------------------------------------------------------


def test_zero_rows_are_described_as_found_nothing_not_as_nonexistent():
    rendered = render_rows_for_model([])

    assert "NOT that nothing exists" in rendered


def test_row_truncation_is_announced():
    rows = [{"n": str(i)} for i in range(100)]

    rendered = render_rows_for_model(rows, limit=5)

    assert "95 further row(s) NOT shown" in rendered
    assert "5 of 100" in rendered


# --------------------------------------------------------------------------
# Auth failure — legible, never a traceback
# --------------------------------------------------------------------------


def test_a_401_mid_loop_becomes_an_actionable_observation(schema, shape, library):
    """Stage 1's message has to survive the trip up through Stage 3.

    A token can expire between the schema probe and the third search. When it
    does, the analyst must be told to regenerate it — not handed a stack trace,
    and not handed an answer built on the two searches that happened to run
    before it expired.
    """
    from soc_copilot.splunk_client import AUTH_FAILURE_MESSAGE, SplunkAuthError

    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "unanswerable", "reason": "the token was rejected"},
        # The search was attempted but never ran, so the loop challenges the
        # give-up. With a dead token, insisting is the correct reply.
        {"action": "unanswerable", "reason": "the token was rejected"},
    )
    client = ScriptedClient(SplunkAuthError(AUTH_FAILURE_MESSAGE))

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    step = result.steps[0]
    assert step.result is not None and not step.result.executed
    assert "Settings > Tokens" in step.result.error
    assert "SPLUNK_TOKEN" in step.result.error
    assert "Traceback" not in step.result.error
    # And nothing was concluded from a search that never ran.
    assert result.searches == ()


def test_the_expired_token_message_reaches_the_model_so_it_stops_guessing(
    schema, shape, library
):
    from soc_copilot.splunk_client import AUTH_FAILURE_MESSAGE, SplunkAuthError

    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "unanswerable", "reason": "the token was rejected"},
        # The search was attempted but never ran, so the loop challenges the
        # give-up. With a dead token, insisting is the correct reply.
        {"action": "unanswerable", "reason": "the token was rejected"},
    )
    client = ScriptedClient(SplunkAuthError(AUTH_FAILURE_MESSAGE))

    investigate("q", schema, library, client=client, backend=backend, shape=shape)

    assert "HTTP 401" in backend.prompts[1]


# --------------------------------------------------------------------------
# Termination — the loop must stop even when nothing it writes will run
# --------------------------------------------------------------------------


class StubbornBackend:
    """A model that emits the same unrunnable query forever.

    Modelled directly on an observed live failure: a 7B local model repeated one
    invalid query until it was killed. Because the query is refused it never
    reaches Splunk, so it never spends the search budget — which is exactly the
    hole this class exists to sit in.
    """

    name = "stubborn"

    def __init__(self, spl: str) -> None:
        from soc_copilot.llm.base import LLMConfig

        self.config = LLMConfig(backend="stubborn", model="stubborn-model")
        self.spl = spl
        self.turns = 0

    def complete(self, *, system: str, user: str) -> str:
        self.turns += 1
        if self.turns > 100:
            raise AssertionError("the loop did not terminate")
        return json.dumps(
            {"action": "search", "purpose": "try again", "spl": self.spl,
             "earliest": "0", "latest": ""}
        )


def test_a_repeatedly_rejected_query_does_not_loop_forever(schema, shape, library):
    """The search budget cannot stop this on its own, so something else must."""
    backend = StubbornBackend("index=logforge | stats count by ProcessGuid")

    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend,
        shape=shape, max_steps=6,
    )

    assert result.stop_reason == STOP_STUCK
    assert backend.turns < 20
    assert result.searches == ()


def test_a_repeated_mutating_query_does_not_loop_forever(schema, shape, library):
    backend = StubbornBackend("index=logforge | delete")

    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_STUCK


def test_the_no_progress_stop_does_not_imply_anything_about_the_data(
    schema, shape, library
):
    """"The loop gave up" and "the data has no answer" are different claims."""
    backend = StubbornBackend("index=logforge | stats count by ProcessGuid")

    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    assert "NOT a statement about the data" in result.unsupported_reason
    assert not result.answerable


def test_resubmitting_a_rejected_query_is_refused_with_the_original_reason(
    schema, shape, library
):
    """Feeding back "same as before" alone would not tell it what to change."""
    backend = ScriptedBackend(
        {"action": "search", "spl": "index=logforge | stats count by ProcessGuid"},
        {"action": "search", "spl": "index=logforge | stats count by ProcessGuid"},
        {"action": "unanswerable", "reason": "gave up"},
        {"action": "unanswerable", "reason": "gave up"},
    )

    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    second = result.steps[1]
    assert second.result is not None
    assert "already submitted this exact query" in second.result.error
    assert "Payload" in second.result.error  # the original refusal, repeated


def test_the_counters_reset_once_a_query_runs(schema, shape, library):
    """A loop that corrected itself has made progress and must not be penalised."""
    backend = ScriptedBackend(
        {"action": "search", "spl": "index=logforge | stats count by ProcessGuid"},
        {"action": "search", "spl": "index=logforge | stats count by Image"},
        {"action": "search", "spl": FIND_SPL},
        {"action": "search", "spl": PIVOT_SPL},
        {"action": "answer", "answer": "Recovered after two rejections.", "evidence": "step 4"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}], [{"Image": "cmd.exe"}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_ANSWERED
    assert len(result.searches) == 2


# --------------------------------------------------------------------------
# Wrapper tags must not survive from the model's reply into a query
# --------------------------------------------------------------------------


def test_wrapper_tags_in_the_models_reply_are_stripped(schema, shape, library):
    """Observed live: shown the envelope syntax, a 7B reproduced it in its output.

    It emitted a time range of "<u:4d8796b7>earliest_time</u:4d8796b7>", which the
    validator then rejected as not a Splunk time modifier. The tags belong to this
    program and are never meaningful in a reply, so they are removed in code.
    """
    backend = ScriptedBackend(
        {
            "action": "search",
            "spl": "<u:4d8796b7>" + FIND_SPL + "</u:4d8796b7>",
            "earliest": "<u:4d8796b7>0</u:4d8796b7>",
            "latest": "",
        },
        {"action": "answer", "answer": "It ran.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert len(result.searches) == 1
    assert "<u:" not in client.calls[0]["spl"]
    assert client.calls[0]["earliest"] == "0"


def test_wrapper_tags_are_stripped_from_the_answer_too(schema, shape, library):
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "The process was <u:abcd1234>cmd.exe</u:abcd1234>.",
         "evidence": "step 1"},
    )
    client = ScriptedClient([{"Image": "cmd.exe"}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert result.answer == "The process was cmd.exe."
    assert result.grounding.ok


# --------------------------------------------------------------------------
# The protocol should not lose a turn to a naming collision
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "alias", ["run_search", "RUN_SEARCH", "runSearch", "query", "tool_call"]
)
def test_the_tools_own_name_is_accepted_as_the_search_action(
    schema, shape, library, alias
):
    """Observed live on two different local models, on their very first turn.

    The prompt names the tool ``run_search`` and the protocol names the action
    ``search``. Models write the name they were shown. Refusing that costs a turn
    and teaches nothing; the SPL still goes through every guardrail either way.
    """
    backend = ScriptedBackend(
        {"action": alias, "spl": FIND_SPL, "earliest": "0", "latest": ""},
        {"action": "answer", "answer": "It ran.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert len(result.searches) == 1
    assert result.stop_reason == STOP_ANSWERED


def test_an_unknown_action_carrying_spl_is_still_read_as_a_search(
    schema, shape, library
):
    backend = ScriptedBackend(
        {"action": "do_the_thing", "spl": FIND_SPL},
        {"action": "answer", "answer": "It ran.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert len(result.searches) == 1


def test_a_reply_with_no_usable_key_is_still_malformed(schema, shape, library):
    """Tolerance has a floor: with nothing to go on, do not guess."""
    backend = ScriptedBackend(
        {"action": "mystery", "notes": "hmm"},
        {"action": "mystery", "notes": "hmm"},
        {"action": "mystery", "notes": "hmm"},
    )

    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_MALFORMED


def test_the_tool_description_warns_about_the_collision(schema, shape):
    described = SearchTool(ScriptedClient([]), schema, shape).describe()

    assert '"search"' in described
    assert "not an action" in described


# --------------------------------------------------------------------------
# Giving up before looking is challenged once
# --------------------------------------------------------------------------


def test_unanswerable_before_any_search_is_challenged(schema, shape, library):
    """"The data cannot answer this" is a claim about an index nobody queried.

    CLAUDE.md is explicit that "not found" means "not in what was ingested",
    which is only knowable after looking. A 14b model declared a question
    unanswerable on turn two having run nothing; that is a guess wearing the
    costume of honesty.
    """
    backend = ScriptedBackend(
        {"action": "unanswerable", "reason": "probably not indexed"},
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "It was there after all.", "evidence": "step 3"},
    )
    client = ScriptedClient([{"ProcessGuid": GUID}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    challenge = result.steps[0]
    assert challenge.action == "refused"
    assert "without running a single search" in challenge.note
    assert result.stop_reason == STOP_ANSWERED
    assert len(result.searches) == 1


def test_the_challenge_happens_only_once(schema, shape, library):
    """If it looks and still says no, that is its answer — do not badger it."""
    backend = ScriptedBackend(
        {"action": "unanswerable", "reason": "$MFT is not indexed"},
        {"action": "unanswerable", "reason": "$MFT is not indexed"},
    )

    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_UNANSWERABLE
    assert result.unsupported_reason == "$MFT is not indexed"


def test_unanswerable_after_a_search_is_accepted_immediately(schema, shape, library):
    """A model that looked, found nothing, and said so is behaving correctly."""
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "unanswerable", "reason": "zero rows; not in what was ingested"},
    )
    client = ScriptedClient([])  # the search runs and returns nothing

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_UNANSWERABLE
    assert [s.action for s in result.steps] == ["search", "unanswerable"]


# --------------------------------------------------------------------------
# An empty answer is a failure, not a conclusion
# --------------------------------------------------------------------------


def test_an_answer_action_with_no_answer_text_is_not_a_conclusion(
    schema, shape, library
):
    """Observed live: a 14b ran two good searches, then answered with nothing.

    The run stopped as ANSWERED with an empty string, and the report printed
    "overall: PASS" directly above the words "(no answer)". Reporting success
    while delivering nothing is the failure mode this project exists to avoid.
    """
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "", "evidence": "step 1"},
        {"action": "answer", "answer": "   ", "evidence": "step 1"},
        {"action": "answer", "answer": "It ran cmd.exe.", "evidence": "step 1"},
    )
    client = ScriptedClient([{"Image": "cmd.exe"}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    # It was asked again rather than accepted, and eventually said something.
    assert result.answer == "It ran cmd.exe."
    assert result.stop_reason == STOP_ANSWERED
    assert [s.action for s in result.steps[1:3]] == ["malformed", "malformed"]


def test_an_empty_answer_repeated_ends_as_unusable_not_as_answered(
    schema, shape, library
):
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        *[{"action": "answer", "answer": ""} for _ in range(MAX_MALFORMED)],
    )
    client = ScriptedClient([{"Image": "cmd.exe"}])

    result = investigate(
        "q", schema, library, client=client, backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_MALFORMED
    assert not result.ok
    assert "without ever stating one" in result.unsupported_reason


def test_an_empty_answer_can_never_report_itself_as_a_pass(schema, shape, library):
    """Belt and braces: ok is False for an empty answer whatever the stop reason."""
    from soc_copilot.agent import Investigation

    empty = Investigation(question="q", steps=(), answer="   ", stop_reason=STOP_ANSWERED)
    silent = Investigation(
        question="q", steps=(), answerable=False, unsupported_reason="",
        stop_reason=STOP_UNANSWERABLE,
    )

    assert not empty.ok
    assert not silent.ok


# --------------------------------------------------------------------------
# A confident zero is the most dangerous result this system produces
# --------------------------------------------------------------------------


def test_zero_rows_from_an_exact_name_filter_gets_a_specific_hint():
    """Measured: prefetch stores GKAPE.EXE, the analyst asks about kape.exe.

    ExecutableName="kape.exe" is valid SPL against a real field and returns
    nothing. Without a hint the honest-looking conclusion is "it never ran" — of
    a program that ran twice.
    """
    from soc_copilot.agent import _empty_result_hint

    hint = _empty_result_hint(
        'index=logforge source="*logforge_pf.csv" ExecutableName="kape.exe"'
    )

    assert "EXACT match" in hint
    assert "retry on the stem" in hint
    assert "Only if THAT returns nothing is absence supported" in hint


@pytest.mark.parametrize(
    "spl",
    [
        'index=logforge source="*logforge_pf.csv" ExecutableName="*KAPE*"',
        "index=logforge EventId=1 | stats count by Computer",
        "index=logforge | stats count",
        'index=logforge source="*logforge_mft.csv" | stats count by FileName',
    ],
)
def test_an_ordinary_empty_result_gets_no_spurious_hint(spl: str):
    """A wildcard search that found nothing has already done the right thing."""
    from soc_copilot.agent import _empty_result_hint

    assert _empty_result_hint(spl) == ""


def test_the_hint_reaches_the_model_on_the_next_turn(schema, shape, library):
    """A hint the loop keeps to itself changes nothing."""
    backend = ScriptedBackend(
        {"action": "search", "spl": 'index=logforge Computer="nosuchhost"'},
        {"action": "unanswerable", "reason": "checked"},
        {"action": "unanswerable", "reason": "checked"},
    )

    investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    assert "EXACT match" in backend.prompts[1]


def test_a_search_that_returned_rows_carries_no_hint(schema, shape):
    tool = SearchTool(
        ScriptedClient([{"Computer": "DESKTOP-01"}]), schema, shape, question="q"
    )

    result = tool.call('index=logforge Computer="DESKTOP-01" | table Computer')

    assert result.hint == ""


# --------------------------------------------------------------------------
# The answer arrives under whatever key the model chose
# --------------------------------------------------------------------------


def test_answer_text_is_read_from_the_key_the_model_actually_used(
    schema, shape, library
):
    """Captured verbatim from a live 14b, twice in one run.

    It replied {"action": "answer", "text": "..."} with correct, complete prose.
    The loop read only "answer", found nothing, discarded the reply as malformed
    and ended the investigation as unusable — while holding the right answer. The
    action name and the payload key are the same class of collision: the model
    picked a reasonable synonym and the parser was literal about the label.
    """
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {
            "action": "answer",
            "text": "The user's last successful login was on 2025-08-11 06:46:52.",
        },
    )
    client = ScriptedClient([{"TargetUserName": "user"}])

    result = investigate(
        "when did the user last log in",
        schema, library, client=client, backend=backend, shape=shape,
    )

    assert result.stop_reason == STOP_ANSWERED
    assert result.answer.startswith("The user's last successful login")
    assert result.ok


@pytest.mark.parametrize(
    "key", ["answer", "text", "response", "summary", "message", "final_answer"]
)
def test_every_tolerated_answer_key_is_accepted(schema, shape, library, key):
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", key: "It happened at 06:46:52."},
    )

    result = investigate(
        "q", schema, library,
        client=ScriptedClient([{"TargetUserName": "user"}]),
        backend=backend, shape=shape,
    )

    assert result.answer == "It happened at 06:46:52."


def test_a_reply_carrying_row_fields_instead_of_prose_is_still_refused(
    schema, shape, library
):
    """Also captured from the same run, and this one deserved refusing.

    {"action": "answer", "last_logon": "...", "TargetUserName": "user"} hands back
    data, not an answer. Tolerating the label must not become tolerating any
    string in the object, or the analyst gets a field dump presented as prose.
    """
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "last_logon": "2025-08-11 06:46:52",
         "TargetUserName": "user"},
        {"action": "answer", "text": "The user last logged in at 06:46:52."},
    )

    result = investigate(
        "q", schema, library,
        client=ScriptedClient([{"TargetUserName": "user"}]),
        backend=backend, shape=shape,
    )

    assert result.steps[1].action == "malformed"
    assert result.answer == "The user last logged in at 06:46:52."


def test_an_unanswerable_reason_is_read_from_a_synonym_key(schema, shape, library):
    """Same tolerance for the other conclusion, before it costs a run too."""
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"action": "unanswerable", "explanation": "file content is not indexed"},
    )

    result = investigate(
        "q", schema, library, client=ScriptedClient([]), backend=backend, shape=shape
    )

    assert result.stop_reason == STOP_UNANSWERABLE
    assert result.unsupported_reason == "file content is not indexed"


def test_a_reply_with_no_action_but_answer_text_still_routes(schema, shape, library):
    """Key tolerance has to reach the action inference too, or a reply that omits
    'action' and uses 'text' is unroutable for exactly the same reason."""
    backend = ScriptedBackend(
        {"action": "search", "spl": FIND_SPL},
        {"text": "The user last logged in at 06:46:52."},
    )

    result = investigate(
        "q", schema, library,
        client=ScriptedClient([{"TargetUserName": "user"}]),
        backend=backend, shape=shape,
    )

    assert result.stop_reason == STOP_ANSWERED
    assert result.answer == "The user last logged in at 06:46:52."


# --------------------------------------------------------------------------
# Which retrieved pattern the model actually used
# --------------------------------------------------------------------------


def test_the_pattern_the_model_adapted_is_recorded(schema, shape, library):
    """Retrieval and selection are different steps, and only one was recorded.

    A logon question retrieved the right entry at rank 1 and the model adapted
    the one at rank 2. Retrieval order was blameless and got blamed, because
    nothing on the run said which entry the SPL actually came from.
    """
    entry = next(d for d in library.detections if d.id == "prefetch-last-execution")
    backend = ScriptedBackend(
        {"action": "search", "spl": entry.spl.replace(
            'ExecutableName="*NAME-FROM-THE-QUESTION*"', 'ExecutableName="*chrome*"')},
        {"action": "answer", "answer": "It ran.", "evidence": "step 1"},
    )

    result = investigate(
        "when was chrome last executed?",
        schema, library, client=ScriptedClient([{"ExecutableName": "CHROME.EXE"}]),
        backend=backend, shape=shape,
    )

    assert result.pattern_used == "prefetch-last-execution"


def test_attribution_says_nothing_rather_than_guessing(library):
    """A weak overlap is a shared `index=`, not evidence of which entry was used."""
    from soc_copilot.library import attribute_spl

    selected = library.select("when did the user last log in", limit=4)
    entry_id, score = attribute_spl("index=logforge | stats count by Computer", selected)

    assert entry_id == ""
    assert score < 0.15


def test_attribution_distinguishes_the_two_entries_that_were_confused(library):
    """The logon and execution entries must not attribute to each other.

    The candidate set is built by hand rather than retrieved: retrieval now
    keeps these two apart by design, so asking it for both would test the
    separation instead of the attribution.
    """
    from soc_copilot.library import attribute_spl

    by_id = {d.id: d for d in library.detections}
    selected = [
        by_id["successful-interactive-logon-4624"],
        by_id["prefetch-last-execution"],
        by_id["mft-files-created-in-path"],
    ]

    logon, _ = attribute_spl(by_id["successful-interactive-logon-4624"].spl, selected)
    prefetch, _ = attribute_spl(by_id["prefetch-last-execution"].spl, selected)

    assert logon == "successful-interactive-logon-4624"
    assert prefetch == "prefetch-last-execution"


def test_an_unusable_step_keeps_the_raw_reply_for_the_transcript(
    schema, shape, library
):
    """"Unusable" is a claim about the code as much as the model. Keep the bytes."""
    backend = ScriptedBackend(
        "not json at all",
        {"action": "search", "spl": FIND_SPL},
        {"action": "answer", "answer": "done", "evidence": "step 2"},
    )

    result = investigate(
        "q", schema, library, client=ScriptedClient([{"ProcessGuid": GUID}]),
        backend=backend, shape=shape,
    )

    malformed = result.steps[0]
    assert malformed.action == "malformed"
    assert malformed.raw_response == "not json at all"
