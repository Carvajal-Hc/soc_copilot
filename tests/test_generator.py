"""Generation: prompt grounding, response parsing, and the validation gate.

A fake backend stands in for the LLM, so these tests assert on what the system
*sends* and what it *does with what comes back* — the two halves that are ours.
"""

from __future__ import annotations

import json

import pytest

from soc_copilot.generator import (
    GenerationError,
    build_user_prompt,
    generate_spl,
    parse_response,
)
from soc_copilot.library import load_library
from soc_copilot.llm.base import LLMConfig
from soc_copilot.payload_shape import EventTypeShape, PayloadShape, SplitFieldFamily
from soc_copilot.schema import FieldInfo, IndexInfo, Schema


class FakeBackend:
    """Records the prompts it was given and replays a scripted reply."""

    name = "fake"

    def __init__(self, reply: str | dict):
        self.config = LLMConfig(backend="fake", model="fake-model")
        self.reply = json.dumps(reply) if isinstance(reply, dict) else reply
        self.system = ""
        self.user = ""

    def complete(self, *, system: str, user: str) -> str:
        self.system, self.user = system, user
        return self.reply


@pytest.fixture
def schema() -> Schema:
    return Schema(
        index="logforge",
        indexes=[
            IndexInfo(
                name="logforge",
                event_count=60132,
                earliest="2024-11-06T14:49:02-0700",
                latest="2025-08-11T07:50:30-0700",
                disabled=False,
                is_internal=False,
            )
        ],
        fields=[
            FieldInfo(name=n, event_count=100, distinct_count=5, is_exact=True)
            for n in ("Channel", "EventId", "Computer", "Payload", "PayloadData1")
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
        nested_names=("ProcessGuid", "Image", "CommandLine", "DestinationIp"),
        stratified_by=("EventId",),
        event_types=(
            EventTypeShape(
                key=("1",),
                nested_names=("ProcessGuid", "Image", "CommandLine"),
                label="Process creation",
            ),
        ),
        split_families=(
            SplitFieldFamily(base="PayloadData", members=("PayloadData1",)),
        ),
        sampled_events=725,
    )


@pytest.fixture
def library():
    return load_library().with_index("logforge")


GOOD_REPLY = {
    "answerable": True,
    "spl": (
        "index=logforge EventId=1\n"
        "| spath input=Payload\n"
        "| eval ProcessGuid = mvindex('EventData.Data{}.#text', "
        "mvfind('EventData.Data{}.@Name', \"^ProcessGuid$\"))\n"
        "| stats count by ProcessGuid"
    ),
    "earliest": "0",
    "latest": "",
    "time_rationale": "Data is historical; use the full range.",
    "rationale": "Extracts ProcessGuid from the payload before grouping.",
    "unsupported_reason": "",
}


class TestPromptGrounding:
    def test_prompt_contains_the_discovered_flat_fields(self, schema, library, shape):
        prompt = build_user_prompt("q", schema, library.select("q"), shape)

        for name in schema.field_names:
            assert name in prompt

    def test_prompt_states_the_real_extraction_paths(self, schema, library, shape):
        prompt = build_user_prompt("command lines", schema, library.select("x"), shape)

        assert "EventData.Data{}.@Name" in prompt
        assert "EventData.Data{}.#text" in prompt
        assert "mvfind" in prompt and "mvindex" in prompt

    def test_prompt_warns_that_the_predicate_form_does_not_work(
        self, schema, library, shape
    ):
        prompt = build_user_prompt("q", schema, library.select("q"), shape)

        assert "predicate form unsupported here" in prompt

    def test_prompt_separates_nested_names_from_flat_columns(
        self, schema, library, shape
    ):
        prompt = build_user_prompt("q", schema, library.select("q"), shape)

        assert "NOT columns" in prompt
        assert "ProcessGuid" in prompt

    def test_prompt_warns_about_positional_split_fields(self, schema, library, shape):
        prompt = build_user_prompt("q", schema, library.select("q"), shape)

        assert "POSITIONAL SPLIT FIELDS" in prompt
        assert "CHANGES BY EVENT TYPE" in prompt

    def test_prompt_carries_the_index_time_bounds(self, schema, library, shape):
        prompt = build_user_prompt("q", schema, library.select("q"), shape)

        assert "2024-11-06T14:49:02-0700" in prompt

    def test_prompt_includes_library_entries(self, schema, library, shape):
        selected = library.select("pivot by processguid")

        prompt = build_user_prompt("pivot by processguid", schema, selected, shape)

        assert "CURATED SPL LIBRARY" in prompt
        assert selected[0].title in prompt

    def test_prompt_says_the_schema_overrides_the_library(self, schema, library, shape):
        prompt = build_user_prompt("q", schema, library.select("q"), shape)

        assert "DISCOVERED SCHEMA above overrides them" in prompt

    def test_a_flat_index_is_described_as_flat(self, schema, library):
        flat = PayloadShape(index="logforge", note="Sampling found no payload.")

        prompt = build_user_prompt("q", schema, library.select("q"), flat)

        assert "This index is flat." in prompt


class TestGeneration:
    def test_returns_the_spl_and_the_time_range_without_running_it(
        self, schema, library, shape
    ):
        result = generate_spl(
            "pivot by processguid",
            schema,
            library,
            backend=FakeBackend(GOOD_REPLY),
            shape=shape,
        )

        assert result.ok
        assert "mvfind" in result.spl
        assert result.time_range.earliest == "0"
        assert result.time_range.latest == ""
        assert result.backend == "fake"

    def test_records_which_library_entries_grounded_it(self, schema, library, shape):
        result = generate_spl(
            "pivot by processguid",
            schema,
            library,
            backend=FakeBackend(GOOD_REPLY),
            shape=shape,
        )

        assert result.grounded_on

    def test_a_nested_field_used_flat_is_caught_after_generation(
        self, schema, library, shape
    ):
        # The model produced plausible-looking SPL that would return nothing.
        reply = {**GOOD_REPLY, "spl": "index=logforge | stats count by ProcessGuid"}

        result = generate_spl(
            "pivot by processguid",
            schema,
            library,
            backend=FakeBackend(reply),
            shape=shape,
        )

        assert not result.ok
        assert result.validation.unextracted_nested == ("ProcessGuid",)

    def test_a_mutating_query_is_caught_after_generation(self, schema, library, shape):
        reply = {**GOOD_REPLY, "spl": "index=logforge | delete"}

        result = generate_spl(
            "delete everything", schema, library, backend=FakeBackend(reply), shape=shape
        )

        assert not result.ok

    def test_unanswerable_questions_are_reported_not_faked(self, schema, library, shape):
        reply = {
            "answerable": False,
            "spl": "",
            "earliest": "0",
            "latest": "",
            "rationale": "",
            "unsupported_reason": "$MFT record contents are not in the index.",
        }

        result = generate_spl(
            "what is in the $MFT record for evil.exe",
            schema,
            library,
            backend=FakeBackend(reply),
            shape=shape,
        )

        assert not result.answerable
        assert "$MFT" in result.unsupported_reason
        assert result.spl == ""

    def test_generating_without_a_shape_warns_that_nesting_was_unchecked(
        self, schema, library
    ):
        result = generate_spl(
            "q", schema, library, backend=FakeBackend(GOOD_REPLY), shape=None
        )

        assert any("not probed" in w for w in result.validation.warnings)

    def test_an_empty_question_is_refused(self, schema, library, shape):
        with pytest.raises(GenerationError, match="empty"):
            generate_spl("   ", schema, library, backend=FakeBackend(GOOD_REPLY))

    def test_the_prompts_are_kept_for_audit(self, schema, library, shape):
        result = generate_spl(
            "q", schema, library, backend=FakeBackend(GOOD_REPLY), shape=shape
        )

        assert result.system_prompt and result.user_prompt
        assert result.raw_response


class TestResponseParsing:
    def test_plain_json(self):
        assert parse_response('{"spl": "index=x", "answerable": true}')["spl"] == "index=x"

    def test_json_inside_a_markdown_fence(self):
        raw = 'Here you go:\n```json\n{"spl": "index=x", "answerable": true}\n```'

        assert parse_response(raw)["spl"] == "index=x"

    def test_json_with_surrounding_chatter(self):
        raw = 'Sure! {"spl": "index=x", "answerable": true} Hope that helps.'

        assert parse_response(raw)["spl"] == "index=x"

    def test_free_text_is_an_error_rather_than_a_guess(self):
        with pytest.raises(GenerationError, match="will not guess SPL"):
            parse_response("Just run: index=logforge | stats count")

    def test_an_empty_response_is_an_error(self):
        with pytest.raises(GenerationError, match="empty"):
            parse_response("   ")

    def test_answerable_with_no_spl_is_an_error(self):
        with pytest.raises(GenerationError, match="no SPL"):
            parse_response('{"answerable": true, "spl": ""}')

    def test_unanswerable_with_no_spl_is_fine(self):
        parsed = parse_response('{"answerable": false, "spl": "", "reason": "x"}')

        assert parsed["answerable"] is False
