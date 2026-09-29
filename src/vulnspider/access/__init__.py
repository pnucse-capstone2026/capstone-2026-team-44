"""Broken Access Control (BAC) scoring and within-family selection.

A small parallel pipeline to ``features`` / ``scoring`` / ``selection``, but
built around :class:`vulnspider.domain.access.AccessCandidate`
(subject_context x resource_reference) instead of the injection
``InputPoint x VulnerabilityType`` model. See ADR-014 for why these stay
separate pipelines.

This package carries the reused BAC scorer, its features, and its
within-family selector -- what ``selection.combined`` needs to merge access
candidates into the global Top-K -- plus the BAC observation pipeline
(``planner``/``executor``) that re-sends the credential-stripped or
identifier-substituted request and captures the differential.
"""

from vulnspider.access.executor import (
    AccessProbeExecutionResult,
    AccessRequestExecutionError,
    execute_access_plan,
)
from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
    ACCESS_FEATURE_SCHEMA_VERSION,
    ACCESS_UNAUTHORIZED_SUCCESS,
    extract_access_features,
)
from vulnspider.access.planner import (
    AccessProbePlanner,
    plan_credential_strip,
    plan_identifier_substitution,
)
from vulnspider.access.scoring import (
    ACCESS_MAX_RANK_SCORE,
    ACCESS_SCORER_VERSION,
    ACCESS_TERMS,
    AccessScorer,
    AccessScoringError,
    AccessScoringTerm,
    score_access_plan,
)
from vulnspider.access.selection import (
    AccessSelectionError,
    AccessSelectionOutcome,
    AccessSelectionSummary,
    RankedAccessScoringResult,
    select_top_k_access,
)

__all__ = [
    "ACCESS_BODY_SIZE_SIMILARITY_RATIO",
    "ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION",
    "ACCESS_FEATURE_SCHEMA_VERSION",
    "ACCESS_MAX_RANK_SCORE",
    "ACCESS_SCORER_VERSION",
    "ACCESS_TERMS",
    "ACCESS_UNAUTHORIZED_SUCCESS",
    "AccessProbeExecutionResult",
    "AccessProbePlanner",
    "AccessRequestExecutionError",
    "AccessScorer",
    "AccessScoringError",
    "AccessScoringTerm",
    "AccessSelectionError",
    "AccessSelectionOutcome",
    "AccessSelectionSummary",
    "RankedAccessScoringResult",
    "execute_access_plan",
    "extract_access_features",
    "plan_credential_strip",
    "plan_identifier_substitution",
    "score_access_plan",
    "select_top_k_access",
]
