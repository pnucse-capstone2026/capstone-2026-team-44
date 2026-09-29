"""Cross-category Top-K merge: injection candidates plus Broken Access
Control candidates.

Uses the same ``selection_priority`` cross-type comparison ADR-010
established for SQLi vs Reflected XSS (``raw_rank_score / exact_scorer_
maximum``), extended to a third, structurally different candidate kind
(ADR-014's ``AccessCandidate``).

This module does not change ``select_top_k()`` or ``select_top_k_access()``;
it only merges their already-computed, already-validated outputs. Given both
category selections were computed at the same ``k``, merging each category's
own top-``k`` and re-trimming to ``k`` yields the exact global top-``k``: any
item inside the true global top-``k`` must already rank inside its own
category's top-``k``, because removing items belonging to other categories
can only raise (numerically lower) an item's rank within its own category.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from vulnspider.access.selection import AccessSelectionOutcome, RankedAccessScoringResult
from vulnspider.selection.top_k import RankedScoringResult, SelectionOutcome

CandidateOrigin = Literal["injection", "access"]


class CombinedSelectionError(ValueError):
    """Raised when injection and access selections cannot be merged."""


@dataclass(frozen=True, slots=True)
class CombinedRankedEntry:
    """One selected candidate from either category, tagged by origin."""

    origin: CandidateOrigin
    selection_priority: float
    candidate_id: str
    injection_result: RankedScoringResult | None = None
    access_result: RankedAccessScoringResult | None = None

    def __post_init__(self) -> None:
        if self.origin == "injection":
            if self.injection_result is None or self.access_result is not None:
                raise CombinedSelectionError(
                    "injection entries must carry exactly an injection_result"
                )
        elif self.origin == "access":
            if self.access_result is None or self.injection_result is not None:
                raise CombinedSelectionError(
                    "access entries must carry exactly an access_result"
                )
        else:
            raise CombinedSelectionError(f"unsupported combined entry origin: {self.origin}")


@dataclass(frozen=True, slots=True, init=False)
class CombinedSelectionSummary:
    total_scoring_results: int
    rankable_results: int
    unrankable_results: int
    selected_results: int
    top_k_requested: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "CombinedSelectionSummary is produced only by select_combined_top_k()"
        )

    @classmethod
    def _from_counts(
        cls,
        *,
        total_scoring_results: int,
        rankable_results: int,
        unrankable_results: int,
        selected_results: int,
        top_k_requested: int,
    ) -> CombinedSelectionSummary:
        instance = object.__new__(cls)
        object.__setattr__(instance, "total_scoring_results", total_scoring_results)
        object.__setattr__(instance, "rankable_results", rankable_results)
        object.__setattr__(instance, "unrankable_results", unrankable_results)
        object.__setattr__(instance, "selected_results", selected_results)
        object.__setattr__(instance, "top_k_requested", top_k_requested)
        instance.validate()
        return instance

    def validate(self) -> None:
        if self.top_k_requested <= 0:
            raise CombinedSelectionError("top-k must be a positive integer")
        if self.total_scoring_results != self.rankable_results + self.unrankable_results:
            raise CombinedSelectionError(
                "total results must equal rankable plus unrankable results"
            )
        if self.selected_results > self.rankable_results:
            raise CombinedSelectionError("selected results cannot exceed rankable results")
        if self.selected_results > self.top_k_requested:
            raise CombinedSelectionError("selected results cannot exceed requested top-k")


@dataclass(frozen=True, slots=True, init=False)
class CombinedSelectionOutcome:
    summary: CombinedSelectionSummary
    selected: tuple[CombinedRankedEntry, ...]
    injection_unrankable: tuple[object, ...]
    access_unrankable: tuple[object, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "CombinedSelectionOutcome is produced only by select_combined_top_k()"
        )

    @classmethod
    def _from_selection(
        cls,
        *,
        summary: CombinedSelectionSummary,
        selected: tuple[CombinedRankedEntry, ...],
        injection_unrankable: tuple[object, ...],
        access_unrankable: tuple[object, ...],
    ) -> CombinedSelectionOutcome:
        instance = object.__new__(cls)
        object.__setattr__(instance, "summary", summary)
        object.__setattr__(instance, "selected", tuple(selected))
        object.__setattr__(instance, "injection_unrankable", tuple(injection_unrankable))
        object.__setattr__(instance, "access_unrankable", tuple(access_unrankable))
        instance.validate()
        return instance

    def validate(self) -> None:
        if self.summary.selected_results != len(self.selected):
            raise CombinedSelectionError(
                "summary selected count must match selected outcome contents"
            )
        candidate_ids = tuple(item.candidate_id for item in self.selected)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise CombinedSelectionError("selected candidates must be unique")
        if self.selected != tuple(sorted(self.selected, key=_combined_sort_key)):
            raise CombinedSelectionError("selected results must use deterministic ordering")


def select_combined_top_k(
    injection_outcome: SelectionOutcome,
    access_outcome: AccessSelectionOutcome,
    *,
    k: int,
) -> CombinedSelectionOutcome:
    if isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        raise CombinedSelectionError("top-k must be a positive integer")
    if not isinstance(injection_outcome, SelectionOutcome):
        raise CombinedSelectionError("injection_outcome must be a SelectionOutcome")
    if not isinstance(access_outcome, AccessSelectionOutcome):
        raise CombinedSelectionError("access_outcome must be an AccessSelectionOutcome")
    injection_outcome.validate()
    access_outcome.validate()
    if injection_outcome.summary.top_k_requested != k:
        raise CombinedSelectionError(
            "injection_outcome must have been selected with the same k"
        )
    if access_outcome.summary.top_k_requested != k:
        raise CombinedSelectionError("access_outcome must have been selected with the same k")

    entries = [
        CombinedRankedEntry(
            origin="injection",
            selection_priority=item.selection_priority,
            candidate_id=item.scoring_result.candidate.id or "",
            injection_result=item,
        )
        for item in injection_outcome.selected
    ] + [
        CombinedRankedEntry(
            origin="access",
            selection_priority=item.selection_priority,
            candidate_id=item.scoring_result.candidate.id or "",
            access_result=item,
        )
        for item in access_outcome.selected
    ]
    ordered = tuple(sorted(entries, key=_combined_sort_key))
    selected = ordered[:k]

    summary = CombinedSelectionSummary._from_counts(
        total_scoring_results=(
            injection_outcome.summary.total_scoring_results
            + access_outcome.summary.total_scoring_results
        ),
        rankable_results=(
            injection_outcome.summary.rankable_results
            + access_outcome.summary.rankable_results
        ),
        unrankable_results=(
            injection_outcome.summary.unrankable_results
            + access_outcome.summary.unrankable_results
        ),
        selected_results=len(selected),
        top_k_requested=k,
    )
    return CombinedSelectionOutcome._from_selection(
        summary=summary,
        selected=selected,
        injection_unrankable=injection_outcome.unrankable,
        access_unrankable=access_outcome.unrankable,
    )


def _combined_sort_key(entry: CombinedRankedEntry) -> tuple[float, str]:
    return (-entry.selection_priority, entry.candidate_id)
