"""Deterministic candidate selection package."""

from vulnspider.selection.combined import (
    CombinedRankedEntry,
    CombinedSelectionError,
    CombinedSelectionOutcome,
    CombinedSelectionSummary,
    select_combined_top_k,
)
from vulnspider.selection.handoff import (
    HANDOFF_CONTRACT_VERSION,
    MutationHandoff,
    MutationHandoffError,
    RankedCandidateContext,
    build_mutation_handoff,
)
from vulnspider.selection.top_k import (
    RankedScoringResult,
    SelectionError,
    SelectionOutcome,
    SelectionSummary,
    select_top_k,
)

__all__ = [
    "HANDOFF_CONTRACT_VERSION",
    "CombinedRankedEntry",
    "CombinedSelectionError",
    "CombinedSelectionOutcome",
    "CombinedSelectionSummary",
    "MutationHandoff",
    "MutationHandoffError",
    "RankedCandidateContext",
    "RankedScoringResult",
    "SelectionError",
    "SelectionOutcome",
    "SelectionSummary",
    "build_mutation_handoff",
    "select_combined_top_k",
    "select_top_k",
]
