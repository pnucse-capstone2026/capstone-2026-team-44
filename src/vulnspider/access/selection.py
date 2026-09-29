"""Deterministic within-category selection for AccessScoringResult.

Mirrors ``selection/top_k.py``'s invariants (validated factories only,
deterministic tie-breaking by candidate id, unrankable accounting) for the
BAC candidate pool. Kept as its own selector -- see
``selection/combined.py`` for how this is merged with the injection
``SelectionOutcome`` into one true cross-category Top-K.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite

from vulnspider.access.scoring import ACCESS_MAX_RANK_SCORE, ACCESS_SCORER_VERSION
from vulnspider.domain import AccessScoringResult


class AccessSelectionError(ValueError):
    """Raised when access scoring results cannot be selected deterministically."""


@dataclass(frozen=True, slots=True, init=False)
class RankedAccessScoringResult:
    scoring_result: AccessScoringResult
    raw_rank_score: float
    raw_rank_score_max: float
    selection_priority: float

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "RankedAccessScoringResult must be created with from_scoring_result()"
        )

    @classmethod
    def from_scoring_result(
        cls,
        scoring_result: AccessScoringResult,
    ) -> RankedAccessScoringResult:
        raw_score, maximum, priority = _authoritative_rank_values(scoring_result)
        instance = object.__new__(cls)
        object.__setattr__(instance, "scoring_result", scoring_result)
        object.__setattr__(instance, "raw_rank_score", raw_score)
        object.__setattr__(instance, "raw_rank_score_max", maximum)
        object.__setattr__(instance, "selection_priority", priority)
        return instance

    def validate(self) -> None:
        raw_score, maximum, priority = _authoritative_rank_values(self.scoring_result)
        if self.raw_rank_score != raw_score:
            raise AccessSelectionError("ranked raw score does not match its AccessScoringResult")
        if self.raw_rank_score_max != maximum:
            raise AccessSelectionError(
                "ranked maximum does not match its exact scorer policy"
            )
        if self.selection_priority != priority:
            raise AccessSelectionError(
                "selection priority does not match raw score / scorer maximum"
            )


@dataclass(frozen=True, slots=True, init=False)
class AccessSelectionSummary:
    total_scoring_results: int
    rankable_results: int
    unrankable_results: int
    selected_results: int
    top_k_requested: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("AccessSelectionSummary is produced only by select_top_k_access()")

    @classmethod
    def _from_counts(
        cls,
        *,
        total_scoring_results: int,
        rankable_results: int,
        unrankable_results: int,
        selected_results: int,
        top_k_requested: int,
    ) -> AccessSelectionSummary:
        instance = object.__new__(cls)
        object.__setattr__(instance, "total_scoring_results", total_scoring_results)
        object.__setattr__(instance, "rankable_results", rankable_results)
        object.__setattr__(instance, "unrankable_results", unrankable_results)
        object.__setattr__(instance, "selected_results", selected_results)
        object.__setattr__(instance, "top_k_requested", top_k_requested)
        instance.validate()
        return instance

    def validate(self) -> None:
        counts = {
            "total_scoring_results": self.total_scoring_results,
            "rankable_results": self.rankable_results,
            "unrankable_results": self.unrankable_results,
            "selected_results": self.selected_results,
            "top_k_requested": self.top_k_requested,
        }
        for name, value in counts.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise AccessSelectionError(f"{name} must be an integer")
        for name, value in counts.items():
            if name != "top_k_requested" and value < 0:
                raise AccessSelectionError(f"{name} must be non-negative")
        if self.top_k_requested <= 0:
            raise AccessSelectionError("top-k must be a positive integer")
        if self.total_scoring_results != self.rankable_results + self.unrankable_results:
            raise AccessSelectionError(
                "total results must equal rankable plus unrankable results"
            )
        if self.selected_results > self.rankable_results:
            raise AccessSelectionError("selected results cannot exceed rankable results")
        if self.selected_results > self.top_k_requested:
            raise AccessSelectionError("selected results cannot exceed requested top-k")


@dataclass(frozen=True, slots=True, init=False)
class AccessSelectionOutcome:
    summary: AccessSelectionSummary
    selected: tuple[RankedAccessScoringResult, ...]
    unrankable: tuple[AccessScoringResult, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("AccessSelectionOutcome is produced only by select_top_k_access()")

    @classmethod
    def _from_selection(
        cls,
        *,
        summary: AccessSelectionSummary,
        selected: tuple[RankedAccessScoringResult, ...],
        unrankable: tuple[AccessScoringResult, ...],
    ) -> AccessSelectionOutcome:
        instance = object.__new__(cls)
        object.__setattr__(instance, "summary", summary)
        object.__setattr__(instance, "selected", tuple(selected))
        object.__setattr__(instance, "unrankable", tuple(unrankable))
        instance.validate()
        return instance

    def validate(self) -> None:
        if not isinstance(self.summary, AccessSelectionSummary):
            raise AccessSelectionError("summary must be an AccessSelectionSummary")
        self.summary.validate()
        for item in self.selected:
            if not isinstance(item, RankedAccessScoringResult):
                raise AccessSelectionError(
                    "selected must contain RankedAccessScoringResult objects"
                )
            item.validate()
        for result in self.unrankable:
            if not isinstance(result, AccessScoringResult):
                raise AccessSelectionError(
                    "unrankable must contain AccessScoringResult objects"
                )
            if any(item.observed for item in result.evidence):
                raise AccessSelectionError(
                    "unrankable results must have no observed scoring term"
                )
        if self.summary.selected_results != len(self.selected):
            raise AccessSelectionError(
                "summary selected count must match selected outcome contents"
            )
        if self.summary.unrankable_results != len(self.unrankable):
            raise AccessSelectionError("summary unrankable count must match outcome contents")
        candidate_ids = tuple(item.scoring_result.candidate.id or "" for item in self.selected)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise AccessSelectionError("selected candidates must be unique")
        if self.selected != tuple(sorted(self.selected, key=_selection_sort_key)):
            raise AccessSelectionError("selected results must use deterministic ordering")


def select_top_k_access(
    scoring_results: Sequence[AccessScoringResult],
    *,
    k: int,
) -> AccessSelectionOutcome:
    """Select unique access candidates by normalized priority and stable identity."""

    if isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        raise AccessSelectionError("top-k must be a positive integer")

    results = tuple(scoring_results)
    rankable: list[RankedAccessScoringResult] = []
    unrankable: list[AccessScoringResult] = []
    for result in results:
        if not isinstance(result, AccessScoringResult):
            raise AccessSelectionError(
                "scoring_results must contain AccessScoringResult objects"
            )
        if not any(item.observed for item in result.evidence):
            unrankable.append(result)
            continue
        rankable.append(RankedAccessScoringResult.from_scoring_result(result))

    ordered = sorted(rankable, key=_selection_sort_key)
    unique: list[RankedAccessScoringResult] = []
    seen_candidate_ids: set[str] = set()
    for item in ordered:
        candidate_id = item.scoring_result.candidate.id or ""
        if candidate_id in seen_candidate_ids:
            continue
        seen_candidate_ids.add(candidate_id)
        unique.append(item)

    selected = tuple(unique[:k])
    summary = AccessSelectionSummary._from_counts(
        total_scoring_results=len(results),
        rankable_results=len(rankable),
        unrankable_results=len(unrankable),
        selected_results=len(selected),
        top_k_requested=k,
    )
    return AccessSelectionOutcome._from_selection(
        summary=summary,
        selected=selected,
        unrankable=tuple(
            sorted(
                unrankable,
                key=lambda item: (
                    item.candidate.id or "",
                    item.access_probe_plan_id,
                ),
            )
        ),
    )


def _authoritative_rank_values(result: AccessScoringResult) -> tuple[float, float, float]:
    if not isinstance(result, AccessScoringResult):
        raise AccessSelectionError("scoring_result must be an AccessScoringResult")
    if not any(item.observed for item in result.evidence):
        raise AccessSelectionError("ranked result must have an observed scoring term")
    raw_score = result.candidate.rank_score
    if raw_score is None or isinstance(raw_score, bool):
        raise AccessSelectionError("rankable candidate must have a numeric rank_score")
    raw_score = float(raw_score)
    if not isfinite(raw_score):
        raise AccessSelectionError("rank_score must be finite")

    if result.candidate.scorer_version != ACCESS_SCORER_VERSION:
        raise AccessSelectionError("candidate does not identify a supported scorer policy")
    maximum = ACCESS_MAX_RANK_SCORE
    if raw_score < 0.0 or raw_score > maximum:
        raise AccessSelectionError("rank_score must be within its exact scorer range")
    priority = raw_score / maximum
    if not isfinite(priority):
        raise AccessSelectionError("selection priority must be finite")
    return raw_score, maximum, priority


def _selection_sort_key(item: RankedAccessScoringResult) -> tuple[float, str, str]:
    result = item.scoring_result
    return (
        -item.selection_priority,
        result.candidate.id or "",
        result.access_probe_plan_id,
    )
