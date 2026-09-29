"""Deterministic cross-type selection for validated scoring results."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite

from vulnspider.domain import VulnerabilityType
from vulnspider.scoring import (
    SQLI_MAX_RANK_SCORE,
    SQLI_SCORER_VERSION,
    XSS_MAX_RANK_SCORE,
    XSS_SCORER_VERSION,
    ScoringResult,
)


class SelectionError(ValueError):
    """Raised when scoring results cannot be selected deterministically."""


@dataclass(frozen=True, slots=True, init=False)
class RankedScoringResult:
    """A scoring result plus its cross-type selection key."""

    scoring_result: ScoringResult
    raw_rank_score: float
    raw_rank_score_max: float
    selection_priority: float

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "RankedScoringResult must be created with from_scoring_result()"
        )

    @classmethod
    def from_scoring_result(
        cls,
        scoring_result: ScoringResult,
    ) -> RankedScoringResult:
        raw_score, maximum, priority = _authoritative_rank_values(scoring_result)
        instance = object.__new__(cls)
        object.__setattr__(instance, "scoring_result", scoring_result)
        object.__setattr__(instance, "raw_rank_score", raw_score)
        object.__setattr__(instance, "raw_rank_score_max", maximum)
        object.__setattr__(instance, "selection_priority", priority)
        return instance

    def validate(self) -> None:
        raw_score, maximum, priority = _authoritative_rank_values(
            self.scoring_result
        )
        if self.raw_rank_score != raw_score:
            raise SelectionError(
                "ranked raw score does not match its ScoringResult"
            )
        if self.raw_rank_score_max != maximum:
            raise SelectionError(
                "ranked maximum does not match its exact scorer policy"
            )
        if self.selection_priority != priority:
            raise SelectionError(
                "selection priority does not match raw score / scorer maximum"
            )


@dataclass(frozen=True, slots=True, init=False)
class SelectionSummary:
    total_scoring_results: int
    rankable_results: int
    unrankable_results: int
    selected_results: int
    top_k_requested: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("SelectionSummary is produced only by select_top_k()")

    @classmethod
    def _from_counts(
        cls,
        *,
        total_scoring_results: int,
        rankable_results: int,
        unrankable_results: int,
        selected_results: int,
        top_k_requested: int,
    ) -> SelectionSummary:
        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "total_scoring_results",
            total_scoring_results,
        )
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
                raise SelectionError(f"{name} must be an integer")
        for name, value in counts.items():
            if name != "top_k_requested" and value < 0:
                raise SelectionError(f"{name} must be non-negative")
        if self.top_k_requested <= 0:
            raise SelectionError("top-k must be a positive integer")
        if (
            self.total_scoring_results
            != self.rankable_results + self.unrankable_results
        ):
            raise SelectionError(
                "total results must equal rankable plus unrankable results"
            )
        if self.selected_results > self.rankable_results:
            raise SelectionError("selected results cannot exceed rankable results")
        if self.selected_results > self.top_k_requested:
            raise SelectionError("selected results cannot exceed requested top-k")


@dataclass(frozen=True, slots=True, init=False)
class SelectionOutcome:
    """Selected unique candidates and retained unrankable accounting."""

    summary: SelectionSummary
    selected: tuple[RankedScoringResult, ...]
    unrankable: tuple[ScoringResult, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("SelectionOutcome is produced only by select_top_k()")

    @classmethod
    def _from_selection(
        cls,
        *,
        summary: SelectionSummary,
        selected: tuple[RankedScoringResult, ...],
        unrankable: tuple[ScoringResult, ...],
    ) -> SelectionOutcome:
        instance = object.__new__(cls)
        object.__setattr__(instance, "summary", summary)
        object.__setattr__(instance, "selected", tuple(selected))
        object.__setattr__(instance, "unrankable", tuple(unrankable))
        instance.validate()
        return instance

    def validate(self) -> None:
        if not isinstance(self.summary, SelectionSummary):
            raise SelectionError("summary must be a SelectionSummary")
        self.summary.validate()
        for item in self.selected:
            if not isinstance(item, RankedScoringResult):
                raise SelectionError(
                    "selected must contain RankedScoringResult objects"
                )
            item.validate()
        for result in self.unrankable:
            if not isinstance(result, ScoringResult):
                raise SelectionError(
                    "unrankable must contain ScoringResult objects"
                )
            if any(item.observed for item in result.evidence):
                raise SelectionError(
                    "unrankable results must have no observed scoring term"
                )
        if self.summary.selected_results != len(self.selected):
            raise SelectionError(
                "summary selected count must match selected outcome contents"
            )
        if self.summary.unrankable_results != len(self.unrankable):
            raise SelectionError(
                "summary unrankable count must match outcome contents"
            )
        candidate_ids = tuple(
            item.scoring_result.candidate.id or "" for item in self.selected
        )
        if len(candidate_ids) != len(set(candidate_ids)):
            raise SelectionError("selected candidates must be unique")
        if self.selected != tuple(sorted(self.selected, key=_selection_sort_key)):
            raise SelectionError("selected results must use deterministic ordering")


def select_top_k(
    scoring_results: Sequence[ScoringResult],
    *,
    k: int,
) -> SelectionOutcome:
    """Select unique candidates by normalized priority and stable identity."""

    if isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        raise SelectionError("top-k must be a positive integer")

    results = tuple(scoring_results)
    rankable: list[RankedScoringResult] = []
    unrankable: list[ScoringResult] = []
    for result in results:
        if not isinstance(result, ScoringResult):
            raise SelectionError("scoring_results must contain ScoringResult objects")
        if not any(item.observed for item in result.evidence):
            unrankable.append(result)
            continue
        rankable.append(_rank_result(result))

    ordered = sorted(rankable, key=_selection_sort_key)
    unique: list[RankedScoringResult] = []
    seen_candidate_ids: set[str] = set()
    for item in ordered:
        candidate_id = item.scoring_result.candidate.id or ""
        if candidate_id in seen_candidate_ids:
            continue
        seen_candidate_ids.add(candidate_id)
        unique.append(item)

    selected = tuple(unique[:k])
    summary = SelectionSummary._from_counts(
        total_scoring_results=len(results),
        rankable_results=len(rankable),
        unrankable_results=len(unrankable),
        selected_results=len(selected),
        top_k_requested=k,
    )
    return SelectionOutcome._from_selection(
        summary=summary,
        selected=selected,
        unrankable=tuple(
            sorted(
                unrankable,
                key=lambda item: (
                    item.candidate.id or "",
                    item.feature_vector_id,
                ),
            )
        ),
    )


def _rank_result(result: ScoringResult) -> RankedScoringResult:
    return RankedScoringResult.from_scoring_result(result)


def _authoritative_rank_values(
    result: ScoringResult,
) -> tuple[float, float, float]:
    if not isinstance(result, ScoringResult):
        raise SelectionError("scoring_result must be a ScoringResult")
    if not any(item.observed for item in result.evidence):
        raise SelectionError("ranked result must have an observed scoring term")
    raw_score = result.candidate.rank_score
    if raw_score is None or isinstance(raw_score, bool):
        raise SelectionError("rankable candidate must have a numeric RankScore")
    raw_score = float(raw_score)
    if not isfinite(raw_score):
        raise SelectionError("RankScore must be finite")

    maximum = _maximum_score_for(result)
    if raw_score < 0.0 or raw_score > maximum:
        raise SelectionError("RankScore must be within its exact scorer range")
    priority = raw_score / maximum
    if not isfinite(priority):
        raise SelectionError("selection priority must be finite")
    return raw_score, maximum, priority


def _maximum_score_for(result: ScoringResult) -> float:
    candidate = result.candidate
    policy = (candidate.vulnerability_type, candidate.scorer_version)
    if policy == (VulnerabilityType.SQLI, SQLI_SCORER_VERSION):
        return SQLI_MAX_RANK_SCORE
    if policy == (VulnerabilityType.REFLECTED_XSS, XSS_SCORER_VERSION):
        return XSS_MAX_RANK_SCORE
    raise SelectionError("candidate does not identify a supported scorer policy")


def _selection_sort_key(item: RankedScoringResult) -> tuple[float, str, str]:
    result = item.scoring_result
    return (
        -item.selection_priority,
        result.candidate.id or "",
        result.feature_vector_id,
    )
