"""The curated SPL library: known-good detections that ground generation.

The generator does not invent SPL from zero. It retrieves the entries closest to
the analyst's question and adapts their *pattern* to the schema discovered at
runtime. That is the difference between "correct and grounded" and "clever".

Entries live in a versioned TOML file (:data:`DEFAULT_LIBRARY_PATH`), parsed with
the standard library's ``tomllib`` — no extra dependency. Selection is plain
keyword scoring: deterministic, debuggable, and no second LLM call.
"""

from __future__ import annotations

import logging
import re
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from soc_copilot.validation import spl_uses_extraction

log = logging.getLogger(__name__)

DEFAULT_LIBRARY_PATH: Final[Path] = Path(__file__).with_name("spl_library.toml")

#: Patterns an entry may teach. Retrieval guarantees the prompt shows both the
#: flat and the nested shape, so the model always sees the contrast.
PATTERN_FLAT: Final[str] = "flat-filter"
PATTERN_EXTRACT: Final[str] = "payload-extract"
PATTERN_PIVOT: Final[str] = "pivot"

#: Words too common to carry signal when matching a question to an entry.
_STOPWORDS: Final[frozenset[str]] = frozenset(
    """a an and are as at be by did do does for from has have how in into is it its
    me my of on or show that the their there these this to was were what when where
    which who why with me give list find get all any""".split()
)

_WORD_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9_]+")


class LibraryError(RuntimeError):
    """The SPL library could not be loaded or is structurally invalid."""


@dataclass(frozen=True)
class Detection:
    """One known-good detection: an attack, and the canonical SPL for it."""

    id: str
    title: str
    attack: str
    pattern: str
    teaches: str
    spl: str
    question_examples: tuple[str, ...] = ()
    #: Question words this entry is explicitly NOT for. A prefetch entry answers
    #: "when did X run" and must not be offered for "when did the user log in":
    #: both contain "last", the overlap scores well, and the model then adapts
    #: the wrong artifact into a confident answer about the wrong thing.
    #:
    #: This exists because saying it in prose did not work. The same distinction
    #: was written into both entries' ``teaches`` blocks in capitals, and a 14B
    #: picked the wrong entry in three runs out of three anyway. Models follow
    #: the examples they are shown, not the commentary around them (F5), so the
    #: separation had to move somewhere the model never sees: retrieval.
    not_for: tuple[str, ...] = ()

    @property
    def is_nested_pattern(self) -> bool:
        """Whether this entry actually demonstrates payload extraction.

        Read from the SPL itself, not from the ``pattern`` label. The label is
        curator-supplied prose and can drift from what the query does — a
        methodology entry such as least-frequent-occurrence is filed under its
        method while its SPL extracts a nested field first. Retrieval relies on
        this flag to guarantee the model always sees both shapes, so it has to
        reflect the query, not the filing.
        """
        return spl_uses_extraction(self.spl)

    def render(self) -> str:
        """The entry as it appears in a prompt."""
        examples = "; ".join(self.question_examples)
        return (
            f"### {self.title}\n"
            f"id: {self.id}   |   maps to: {self.attack}   |   pattern: {self.pattern}\n"
            f"asked as: {examples}\n"
            f"technique this teaches:\n{self.teaches.strip()}\n"
            f"canonical SPL:\n{self.spl.strip()}\n"
        )


@dataclass(frozen=True)
class SplLibrary:
    """A loaded, validated collection of :class:`Detection` entries."""

    version: int
    name: str
    description: str
    detections: tuple[Detection, ...]
    source: Path | None = None

    def __len__(self) -> int:
        return len(self.detections)

    def by_id(self, detection_id: str) -> Detection | None:
        return next((d for d in self.detections if d.id == detection_id), None)

    def with_index(self, index: str) -> SplLibrary:
        """Substitute ``{index}`` in every entry's SPL with the real index."""
        return SplLibrary(
            version=self.version,
            name=self.name,
            description=self.description,
            source=self.source,
            detections=tuple(
                Detection(**{**d.__dict__, "spl": d.spl.replace("{index}", index)})
                for d in self.detections
            ),
        )

    def select(
        self,
        question: str,
        *,
        limit: int = 4,
        require_contrast: bool = True,
    ) -> tuple[Detection, ...]:
        """Return the entries most relevant to ``question``, best first.

        Scoring is keyword overlap against each entry's title, attack mapping,
        example questions and technique notes.

        Args:
            require_contrast: Guarantee that the result contains at least one
                entry that extracts from a payload and one that does not — as
                judged by :attr:`Detection.is_nested_pattern`, i.e. by what the
                SPL does, not by its label. Without this a question whose wording
                happens to match only flat examples would never show the model
                the extraction pattern — and the model would then filter a nested
                field as if it were flat, which is exactly the failure this
                library exists to prevent.
        """
        if limit <= 0 or not self.detections:
            return ()

        terms = _terms(question)
        scored = sorted(
            self.detections,
            key=lambda d: (-self._score(d, terms), d.id),
        )
        chosen = list(scored[:limit])

        if require_contrast and limit >= 2:
            chosen = self._ensure_contrast(chosen, scored, limit)
        return tuple(chosen)

    def _ensure_contrast(
        self,
        chosen: list[Detection],
        ranked: list[Detection],
        limit: int,
    ) -> list[Detection]:
        for wanted in (lambda d: d.is_nested_pattern, lambda d: not d.is_nested_pattern):
            if any(wanted(d) for d in chosen):
                continue
            replacement = next((d for d in ranked if wanted(d)), None)
            if replacement is None:
                continue
            # Drop the weakest entry of the over-represented kind.
            for i in range(len(chosen) - 1, -1, -1):
                if not wanted(chosen[i]):
                    chosen.pop(i)
                    break
            chosen.insert(min(len(chosen), limit - 1), replacement)
        return chosen[:limit]

    @staticmethod
    def _score(detection: Detection, terms: set[str]) -> int:
        if not terms:
            return 0
        # Example questions are the strongest signal: they are literally how an
        # analyst phrases the request. Technique notes are the weakest.
        weighted = (
            (_terms(" ".join(detection.question_examples)), 3),
            (_terms(detection.title), 2),
            (_terms(detection.attack), 2),
            (_terms(detection.teaches), 1),
        )
        score = sum(len(terms & bag) * weight for bag, weight in weighted)

        # A declared mismatch is not a weak signal to be outvoted — it is the
        # entry saying "this is a different question". Demote hard enough that
        # it cannot surface while any genuinely relevant entry exists.
        if _terms(" ".join(detection.not_for)) & terms:
            score -= _NOT_FOR_PENALTY
        return score

    def render(self, detections: tuple[Detection, ...] | None = None) -> str:
        entries = self.detections if detections is None else detections
        return "\n".join(d.render() for d in entries)


#: Weight of a declared mismatch. Larger than any achievable positive score, so
#: "not for this question" beats "shares several words with this question".
_NOT_FOR_PENALTY: Final[int] = 1000


def _terms(text: str) -> set[str]:
    """Lowercase content words, with a crude plural fold so 'logons' hits 'logon'."""
    words = _WORD_RE.findall(text.lower())
    out: set[str] = set()
    for word in words:
        if len(word) < 3 or word in _STOPWORDS:
            continue
        out.add(word)
        if word.endswith("es") and len(word) > 4:
            out.add(word[:-2])
        elif word.endswith("s") and len(word) > 3:
            out.add(word[:-1])
    return out


def load_library(path: str | Path | None = None) -> SplLibrary:
    """Load and validate the curated SPL library.

    Raises:
        LibraryError: if the file is missing, unparseable, or an entry is
            missing a required key. Failing closed here is deliberate: a silently
            half-loaded library would degrade generation invisibly.
    """
    library_path = Path(path) if path is not None else DEFAULT_LIBRARY_PATH
    if not library_path.is_file():
        raise LibraryError(
            f"SPL library not found at {library_path}. It grounds every generated "
            "query, so generation cannot proceed without it."
        )

    try:
        raw: dict[str, Any] = tomllib.loads(library_path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise LibraryError(f"Could not parse SPL library {library_path}: {exc}") from exc

    entries = raw.get("detection")
    if not isinstance(entries, list) or not entries:
        raise LibraryError(
            f"{library_path} defines no [[detection]] entries; nothing to ground on."
        )

    detections: list[Detection] = []
    seen: set[str] = set()
    for position, entry in enumerate(entries, start=1):
        detections.append(_build_detection(entry, position, library_path, seen))

    log.debug("Loaded %d detection(s) from %s", len(detections), library_path)
    return SplLibrary(
        version=int(raw.get("version", 1)),
        name=str(raw.get("name", library_path.stem)),
        description=str(raw.get("description", "")),
        detections=tuple(detections),
        source=library_path,
    )


def _build_detection(
    entry: Any, position: int, path: Path, seen: set[str]
) -> Detection:
    if not isinstance(entry, dict):
        raise LibraryError(f"{path}: [[detection]] #{position} is not a table.")

    def required(key: str) -> str:
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            raise LibraryError(
                f"{path}: [[detection]] #{position} is missing a non-empty {key!r}."
            )
        return value.strip()

    detection_id = required("id")
    if detection_id in seen:
        raise LibraryError(f"{path}: duplicate detection id {detection_id!r}.")
    seen.add(detection_id)

    pattern = required("pattern")
    known = (PATTERN_FLAT, PATTERN_EXTRACT, PATTERN_PIVOT)
    if pattern not in known:
        raise LibraryError(
            f"{path}: detection {detection_id!r} has pattern {pattern!r}; "
            f"expected one of {', '.join(known)}."
        )

    not_for = entry.get("not_for", [])
    if not isinstance(not_for, list):
        raise LibraryError(
            f"{path}: detection {detection_id!r} has a non-list not_for."
        )

    examples = entry.get("question_examples", [])
    if not isinstance(examples, list) or not all(isinstance(e, str) for e in examples):
        raise LibraryError(
            f"{path}: detection {detection_id!r} has a non-list question_examples."
        )

    return Detection(
        id=detection_id,
        title=required("title"),
        attack=entry.get("attack", "").strip() or "unspecified",
        pattern=pattern,
        teaches=required("teaches"),
        spl=required("spl"),
        question_examples=tuple(e.strip() for e in examples if e.strip()),
        not_for=tuple(n.strip() for n in not_for if str(n).strip()),
    )


#: Below this share of an entry's distinctive tokens, a match is coincidence.
MIN_ATTRIBUTION_SCORE: Final[float] = 0.15


def attribute_spl(
    spl: str,
    detections: Sequence[Detection],
) -> tuple[str, float]:
    """Which retrieved entry does this generated SPL most resemble?

    Retrieval and *selection* are different steps, and conflating them cost a
    misdiagnosis: a logon question retrieved the right entry at rank 1 and the
    model adapted the one at rank 2 anyway. Retrieval order was blameless and
    got blamed, because nothing recorded which entry was actually used.

    This is an inference, not a record — the model never says which example it
    followed. It scores the produced query against each candidate on the
    distinctive tokens they share (event ids, field names, source scoping), so
    "the SPL that came back looks like `prefetch-last-execution`" is at least
    attributable at a glance instead of reconstructed days later.

    Returns:
        The best-matching entry id and its overlap score, or ``("", 0.0)`` when
        nothing was retrieved or the SPL shares no distinctive token with any of
        it — an honest "cannot tell" rather than a confident wrong id.
    """
    produced = _terms(spl or "")
    if not produced or not detections:
        return "", 0.0

    best_id, best_score = "", 0.0
    for detection in detections:
        candidate = _terms(detection.spl)
        # Tokens common to every entry (index, the extraction boilerplate) say
        # nothing about which one was followed; only what distinguishes them does.
        shared = {
            other
            for other in detections
            if other.id != detection.id
        }
        common: set[str] = set()
        for other in shared:
            common |= _terms(other.spl)
        distinctive = candidate - common
        if not distinctive:
            continue
        score = len(produced & distinctive) / len(distinctive)
        if score > best_score:
            best_id, best_score = detection.id, score

    # Below the floor the overlap is incidental — a shared `index=` and a stray
    # field name. Naming an entry on that evidence would be the same overconfident
    # attribution this function exists to replace.
    if best_score < MIN_ATTRIBUTION_SCORE:
        return "", round(best_score, 3)
    return best_id, round(best_score, 3)
