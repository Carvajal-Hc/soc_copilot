"""The curated SPL library: loading, validation and retrieval."""

from __future__ import annotations

import pytest

from soc_copilot.library import (
    PATTERN_EXTRACT,
    PATTERN_FLAT,
    LibraryError,
    load_library,
)

MINIMAL = '''
version = 1
name = "test"

[[detection]]
id = "flat-one"
title = "Failed logons by account"
attack = "Credential Access / T1110"
pattern = "flat-filter"
question_examples = ["failed logons", "brute force"]
teaches = "Flat fields filter directly."
spl = "index={index} EventId=4625 | stats count by UserName"

[[detection]]
id = "nested-one"
title = "Extract the command line from the payload"
attack = "Execution / T1059"
pattern = "payload-extract"
question_examples = ["command lines", "what commands ran"]
teaches = "Use spath then mvfind/mvindex."
spl = "index={index} | spath input=Payload"
'''


def _write(tmp_path, text: str):
    path = tmp_path / "lib.toml"
    path.write_text(text, encoding="utf-8")
    return path


class TestLoading:
    def test_loads_the_shipped_starter_library(self):
        library = load_library()

        assert len(library) > 0
        assert {d.pattern for d in library.detections} >= {PATTERN_FLAT, PATTERN_EXTRACT}

    def test_every_shipped_entry_is_complete(self):
        for detection in load_library().detections:
            assert detection.id and detection.title and detection.teaches
            assert detection.spl.strip()

    def test_index_placeholder_is_substituted(self, tmp_path):
        library = load_library(_write(tmp_path, MINIMAL)).with_index("logforge")

        assert "index=logforge" in library.by_id("flat-one").spl
        assert "{index}" not in library.by_id("flat-one").spl

    def test_missing_file_fails_closed(self, tmp_path):
        with pytest.raises(LibraryError, match="not found"):
            load_library(tmp_path / "nope.toml")

    def test_unparseable_file_fails_closed(self, tmp_path):
        with pytest.raises(LibraryError, match="parse"):
            load_library(_write(tmp_path, "this is not [ valid toml"))

    def test_no_entries_fails_closed(self, tmp_path):
        with pytest.raises(LibraryError, match="no \\[\\[detection\\]\\]"):
            load_library(_write(tmp_path, 'version = 1\nname = "empty"\n'))

    def test_entry_missing_a_required_key_fails_closed(self, tmp_path):
        broken = MINIMAL.replace('teaches = "Flat fields filter directly."', "")

        with pytest.raises(LibraryError, match="teaches"):
            load_library(_write(tmp_path, broken))

    def test_unknown_pattern_fails_closed(self, tmp_path):
        broken = MINIMAL.replace('pattern = "flat-filter"', 'pattern = "improvise"')

        with pytest.raises(LibraryError, match="improvise"):
            load_library(_write(tmp_path, broken))

    def test_duplicate_ids_fail_closed(self, tmp_path):
        with pytest.raises(LibraryError, match="duplicate"):
            load_library(_write(tmp_path, MINIMAL.replace("nested-one", "flat-one")))


class TestNestedFlagComesFromTheSpl:
    """``is_nested_pattern`` reads the query, not the ``pattern`` label.

    Labels are curator-supplied prose and drift: a methodology entry gets filed
    under its method while its SPL extracts a nested field first. Retrieval's
    flat/nested contrast depends on this flag, so it must track the query.
    """

    LABEL_DRIFT = '''
version = 1
name = "drift"

[[detection]]
id = "labelled-flat-but-extracts"
title = "Least-frequent-occurrence over a nested value"
attack = "Hunting / methodology"
pattern = "flat-filter"
question_examples = ["rarest command lines"]
teaches = "Filed as methodology, but it must extract before stacking."
spl = """
index={index} EventId=1
| spath input=Payload
| eval CommandLine = mvindex('EventData.Data{}.#text', mvfind('EventData.Data{}.@Name', "^CommandLine$"))
| stats count by CommandLine
| sort count
"""

[[detection]]
id = "labelled-extract-but-flat"
title = "Outlier by a flat grouping field"
attack = "Anomaly detection / methodology"
pattern = "payload-extract"
question_examples = ["which host is anomalous"]
teaches = "Filed under extraction, but groups a top-level column."
spl = """
index={index}
| stats count as N by Computer
| eventstats avg(N) as avg_n stdev(N) as sd_n
| where N > avg_n + (2 * sd_n)
"""
'''

    def test_spl_that_extracts_is_nested_despite_a_flat_label(self, tmp_path):
        library = load_library(_write(tmp_path, self.LABEL_DRIFT))

        detection = library.by_id("labelled-flat-but-extracts")

        assert detection.pattern == PATTERN_FLAT
        assert detection.is_nested_pattern

    def test_spl_that_does_not_extract_is_flat_despite_a_nested_label(self, tmp_path):
        library = load_library(_write(tmp_path, self.LABEL_DRIFT))

        detection = library.by_id("labelled-extract-but-flat")

        assert detection.pattern == PATTERN_EXTRACT
        assert not detection.is_nested_pattern

    def test_contrast_follows_the_spl_not_the_labels(self, tmp_path):
        # Both entries are labelled the wrong way round. Judging by label would
        # conclude there is no flat example present and no nested one either.
        library = load_library(_write(tmp_path, self.LABEL_DRIFT))

        selected = library.select("rarest command lines", limit=2)

        assert any(d.is_nested_pattern for d in selected)
        assert any(not d.is_nested_pattern for d in selected)

    @pytest.mark.parametrize(
        "spl, nested",
        [
            ("index=x | spath input=Payload | stats count", True),
            ("index=x | rex field=Payload \"(?<A>.)\" | stats count", True),
            ("index=x | eval a = mvindex(b, mvfind(c, \"^d$\"))", True),
            ("index=x | eval p = mvzip(a, b) | mvexpand p", True),
            ("index=x | stats count by Computer", False),
            ("index=x | eventstats avg(N) as m | where N > m", False),
            ("index=x | table _time, Computer | sort - _time", False),
        ],
    )
    def test_recognises_the_extraction_commands(self, tmp_path, spl, nested):
        from soc_copilot.validation import spl_uses_extraction

        assert spl_uses_extraction(spl) is nested

    def test_the_shipped_library_agrees_with_its_own_labels(self):
        # Not required, but a mismatch is worth surfacing to the curator: an
        # entry labelled payload-extract whose SPL never extracts is a bug in
        # the entry, even though nothing downstream now depends on the label.
        mismatched = [
            d.id
            for d in load_library().detections
            if (d.pattern in (PATTERN_EXTRACT, "pivot")) is not d.is_nested_pattern
        ]

        assert not mismatched, f"label/SPL mismatch in: {', '.join(mismatched)}"


class TestRetrieval:
    def test_matches_on_example_wording(self, tmp_path):
        library = load_library(_write(tmp_path, MINIMAL))

        best = library.select("show me failed logons", limit=1, require_contrast=False)

        assert best[0].id == "flat-one"

    def test_plurals_still_match(self, tmp_path):
        library = load_library(_write(tmp_path, MINIMAL))

        best = library.select("what command lines ran", limit=1, require_contrast=False)

        assert best[0].id == "nested-one"

    def test_always_shows_both_a_flat_and_a_nested_example(self):
        # A question worded only like the flat examples must still show the
        # extraction pattern, or the model will filter nested fields flat.
        selected = load_library().select("how many events per channel", limit=4)

        patterns = {d.pattern for d in selected}
        assert PATTERN_FLAT in patterns
        assert any(d.is_nested_pattern for d in selected)

    def test_contrast_can_be_disabled(self, tmp_path):
        library = load_library(_write(tmp_path, MINIMAL))

        selected = library.select("failed logons", limit=1, require_contrast=False)

        assert len(selected) == 1

    def test_respects_the_limit(self):
        assert len(load_library().select("processes", limit=2)) == 2

    def test_an_unrelated_question_still_returns_grounding(self):
        # Better to adapt from something than to improvise from zero.
        assert load_library().select("xyzzy plugh", limit=3)

    def test_rendered_entry_carries_the_technique_and_the_spl(self):
        detection = load_library().detections[0]

        rendered = detection.render()

        assert detection.title in rendered
        assert detection.spl.strip() in rendered
        assert "pattern:" in rendered


# --------------------------------------------------------------------------
# Declared mismatches — separating questions that share vocabulary
# --------------------------------------------------------------------------


def test_an_entry_is_not_offered_for_a_question_it_declares_it_is_not_for():
    """"When did X run" and "when did the user log in" share the word "last".

    Measured before this existed: a 14B chose the prefetch execution entry for
    "when was the user's last successful login" three times out of three, and
    said so in prose in both entries made no difference. Models follow the
    examples they are shown, not the commentary around them — so the separation
    had to move to a layer the model never sees.
    """
    library = load_library().with_index("logforge")

    chosen = [d.id for d in library.select(
        "when was the user's last successful login to the system?", limit=4)]

    assert chosen[0] == "successful-interactive-logon-4624"
    assert "prefetch-last-execution" not in chosen


def test_the_converse_holds_for_execution_questions():
    library = load_library().with_index("logforge")

    chosen = [d.id for d in library.select("when was kape.exe last executed?", limit=4)]

    assert chosen[0] == "prefetch-last-execution"
    assert "successful-interactive-logon-4624" not in chosen


def test_a_declared_mismatch_outweighs_strong_keyword_overlap():
    """The demotion must beat a good positive score, or it is only a tiebreak."""
    from soc_copilot.library import Detection, SplLibrary

    rival = Detection(
        id="rival", title="last run time for a program", attack="Execution",
        pattern="flat-filter", teaches="last run", spl="index=x | stats count",
        question_examples=("when was the last successful login to the system",),
        not_for=("login",),
    )
    plain = Detection(
        id="plain", title="something else", attack="Other", pattern="flat-filter",
        teaches="unrelated", spl="index=x | head 1",
        question_examples=("unrelated question",),
    )
    library = SplLibrary(version=1, name="t", description="", source=None,
                         detections=(rival, plain))

    chosen = [d.id for d in library.select(
        "when was the last successful login to the system", limit=2,
        require_contrast=False)]

    assert chosen[0] == "plain"


def test_not_for_is_optional_and_absent_entries_are_unaffected():
    library = load_library().with_index("logforge")
    without = [d for d in library.detections if not d.not_for]

    assert without, "expected most entries to declare no mismatch"
    assert library.select("how many processes were created", limit=2)


def test_a_malformed_not_for_is_refused_at_load(tmp_path):
    """Fail closed on a broken library rather than silently ignoring the field."""
    from soc_copilot.library import LibraryError

    bad = tmp_path / "bad.toml"
    bad.write_text(
        'version = 1\nname = "t"\ndescription = "d"\n\n'
        '[[detection]]\nid = "x"\ntitle = "t"\nattack = "a"\npattern = "flat-filter"\n'
        'teaches = "t"\nspl = "index=x"\nnot_for = "login"\n',
        encoding="utf-8",
    )

    with pytest.raises(LibraryError, match="not_for"):
        load_library(bad)
