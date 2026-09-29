"""Validated downstream handoff derived from canonical crawl and analysis artifacts."""

from vulnspider.handoff.contracts import (
    INTERFACE_CONTRACT_VERSION,
    CandidateCategory,
    CandidateEvidence,
    CandidateProvenance,
    HandoffContractError,
    HandoffVulnerabilityType,
    InjectionMutationContext,
    NormalizedCandidate,
    build_candidate_handoff,
    normalize_selected_candidates,
)

__all__ = [
    "INTERFACE_CONTRACT_VERSION",
    "CandidateCategory",
    "CandidateEvidence",
    "CandidateProvenance",
    "HandoffContractError",
    "HandoffVulnerabilityType",
    "InjectionMutationContext",
    "NormalizedCandidate",
    "build_candidate_handoff",
    "normalize_selected_candidates",
]
