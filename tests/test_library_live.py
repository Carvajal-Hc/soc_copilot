"""Every library entry, run against a real Splunk. Opt-in: ``pytest -m live``.

This is the only test in the suite that touches a live system, and it exists
because the other 482 cannot see the thing that actually breaks first.

The offline suite proves the *machinery* is right: that a mutating command is
refused, that a literal is anchored, that a 401 surfaces legibly. None of it can
tell you that `lsass-dump-eid10` still returns rows, because none of it ever asks
Splunk anything. A library entry rots in ways no unit test observes — Splunk
stops supporting a predicate form, a re-ingest renames a source, an entry is
edited and its `spath` no longer lines up with the payload. Each of those is a
query that still parses, still passes every guardrail, and quietly returns
nothing. On the local backend, "returns nothing" is the input the model turns
into "that did not happen", which is the worst failure this project has (F6).

So this suite is a canary for drift, in two layers:

* **Every entry must still run clean.** A query that errors is a broken entry,
  full stop, and that is a hard failure.
* **Entries expected to return rows must still return rows.** The counts below
  were measured on 2026-09-22 against the reference ingest (283,821 events).
  They are asserted as "> 0", not as exact numbers: this has to survive a
  re-ingest of the same evidence without being re-baselined, and an exact count
  would fail for a reason that is not a defect.

Three queries are expected to return zero and say why, because a zero has to be
explained to be trusted (see `EXPECTED_EMPTY`).

It skips — never fails — when Splunk is unreachable or the index is missing, so
a contributor without the dataset is not blocked, and CI stays hermetic.
"""

from __future__ import annotations

import re

import pytest

from soc_copilot.config import ConfigError, load_config
from soc_copilot.library import load_library
from soc_copilot.splunk_client import SplunkClient, SplunkError

pytestmark = pytest.mark.live

INDEX = "logforge"

#: Fenced blocks are prose for the model, not SPL. An entry may hold more than
#: one query separated by them (the two-step pivot holds two).
FENCE = re.compile(r"```[^`]*```")

#: Deliberately synthetic values the loop substitutes at run time — from the
#: question, or from a row the previous step returned. Run literally they cannot
#: match, so their zero is by construction rather than evidence of anything.
PLACEHOLDERS = (
    "NAME-FROM-THE-QUESTION",
    "PASTE-THE-GUID-STEP-1-RETURNED",
    "THE-IMAGE-THE-QUESTION-NAMES",
)

#: Queries that legitimately return nothing, and the reason each one does. A
#: zero is only acceptable here if it is explained; anything else returning zero
#: is drift and fails.
EXPECTED_EMPTY: dict[str, str] = {
    "payload-extract-then-filter": (
        "No encoded PowerShell in this capture. Verified 2026-09-22: all 812 "
        "EID 1 events have CommandLine populated and none match the -enc "
        "filter. The PowerShell present uses IEX + DownloadString instead."
    ),
    "two-step-pivot-processguid [q2]": (
        "Holds PASTE-THE-GUID-STEP-1-RETURNED. Step 2's filter is a value that "
        "only exists once step 1 has run, which is the entry's whole point."
    ),
    "prefetch-last-execution": (
        "Holds *NAME-FROM-THE-QUESTION*, substituted from the question at run "
        "time."
    ),
}


def queries_of(spl: str) -> list[str]:
    return [part.strip() for part in FENCE.split(spl) if part.strip()]


def labelled_queries() -> list[tuple[str, str]]:
    """Every runnable query in the library, with a stable label."""
    out: list[tuple[str, str]] = []
    for detection in load_library().with_index(INDEX).detections:
        parts = queries_of(detection.spl)
        for n, query in enumerate(parts, 1):
            label = detection.id if len(parts) == 1 else f"{detection.id} [q{n}]"
            out.append((label, query))
    return out


CASES = labelled_queries()


@pytest.fixture(scope="module")
def client():
    """A real client, or a skip that says which prerequisite is missing."""
    try:
        config = load_config()
    except ConfigError as exc:
        pytest.skip(f"No Splunk configuration: {exc}")

    splunk = SplunkClient(config)
    try:
        rows = splunk.run_search(f"index={INDEX} | stats count")
    except SplunkError as exc:
        splunk.close()
        pytest.skip(f"Splunk not usable at {config.base_url}: {exc}")

    count = int(rows[0].get("count", 0)) if rows else 0
    if count == 0:
        splunk.close()
        pytest.skip(
            f"index={INDEX} is empty or absent. See 'The dataset this demo runs "
            "on' in SETUP.md for how to build it."
        )

    yield splunk
    splunk.close()


def test_the_library_is_not_empty() -> None:
    """A library that failed to load would make every case below vacuously pass."""
    assert len(CASES) >= 20


@pytest.mark.parametrize("label,query", CASES, ids=[c[0] for c in CASES])
def test_entry_runs_clean_against_live_splunk(client, label: str, query: str) -> None:
    """Hard requirement: the SPL still executes. An error is a broken entry."""
    try:
        client.run_search(query)
    except SplunkError as exc:
        pytest.fail(f"{label} no longer runs:\n{exc}\n\nSPL:\n{query}")


@pytest.mark.parametrize("label,query", CASES, ids=[c[0] for c in CASES])
def test_entry_still_returns_the_evidence_it_claims(client, label: str, query: str) -> None:
    """Drift check: an entry that used to find rows must still find rows."""
    rows = client.run_search(query)

    if label in EXPECTED_EMPTY:
        # Stated as an equality so the reverse drift is caught too: if this ever
        # starts returning rows, the documented reason has gone stale.
        assert len(rows) == 0, (
            f"{label} is documented as legitimately empty, but returned "
            f"{len(rows)} row(s). The reason on record is no longer true:\n"
            f"  {EXPECTED_EMPTY[label]}"
        )
        return

    held = [p for p in PLACEHOLDERS if p in query]
    assert not held, (
        f"{label} contains the placeholder {held[0]!r} but is not listed in "
        "EXPECTED_EMPTY. Either it is newly templated, or the list is stale."
    )
    assert len(rows) > 0, (
        f"{label} returned 0 rows. It is not a documented empty, so this is "
        "either library drift (the query no longer matches the data) or index "
        "drift (the events it looks for are gone). Diagnose before editing the "
        "SPL: strip the narrowing filter and list the field's real values.\n\n"
        f"SPL:\n{query}"
    )
