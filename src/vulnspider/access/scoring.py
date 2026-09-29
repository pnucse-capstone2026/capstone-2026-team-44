"""Deterministic scoring for Broken Access Control (BAC) access probes.

Structurally parallel to ``scoring.engine`` (same weighted-sum, same
observed-vs-missing evidence discipline) but intentionally does not import
from it: BAC evidence is not vulnerability-type-tagged injection evidence
(ADR-014), and keeping the two scorers independent protects each one's
weight tuning from accidentally leaking into the other.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from urllib.parse import urlsplit

from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_UNAUTHORIZED_SUCCESS,
)
from vulnspider.domain import (
    AccessCandidate,
    AccessCheckKind,
    AccessProbePlan,
    AccessScoreEvidence,
    AccessScoringResult,
    FeatureObservation,
)

ACCESS_SCORER_VERSION = "access-control-weighted-v1"


class AccessScoringError(ValueError):
    """Raised when an access probe cannot be scored without fabrication."""


@dataclass(frozen=True, slots=True)
class AccessScoringTerm:
    feature_name: str
    weight: float
    reason: str


ACCESS_TERMS: tuple[AccessScoringTerm, ...] = (
    AccessScoringTerm(
        ACCESS_UNAUTHORIZED_SUCCESS,
        55.0,
        "Comparison request was not denied (2xx) despite missing credentials "
        "or referencing a different identifier -- the primary Broken Access "
        "Control signal.",
    ),
    AccessScoringTerm(
        ACCESS_BODY_SIZE_SIMILARITY_RATIO,
        20.0,
        "Comparison response body is similarly sized to the reference "
        "response, suggesting it received substantive content rather than a "
        "rejection/error page.",
    ),
)

ACCESS_MAX_RANK_SCORE = sum(term.weight for term in ACCESS_TERMS)


@dataclass(frozen=True, slots=True)
class AccessScorer:
    """Score one executed AccessProbePlan's extracted features."""

    def score(
        self,
        access_probe_plan: AccessProbePlan,
        features: Mapping[str, FeatureObservation],
    ) -> AccessScoringResult:
        return score_access_plan(access_probe_plan, features)


def score_access_plan(
    access_probe_plan: AccessProbePlan,
    features: Mapping[str, FeatureObservation],
) -> AccessScoringResult:
    if not isinstance(access_probe_plan, AccessProbePlan):
        raise AccessScoringError("access_probe_plan must be an AccessProbePlan")

    resource_reference, resource_owner_context = _resource_description(
        access_probe_plan
    )
    identity_candidate = AccessCandidate(
        endpoint_id=access_probe_plan.endpoint_id,
        check_kind=access_probe_plan.check_kind,
        subject_context=access_probe_plan.comparison_subject,
        resource_reference=resource_reference,
        resource_owner_context=resource_owner_context,
        access_probe_plan_id=access_probe_plan.id or "",
        input_point_id=access_probe_plan.input_point_id,
    )
    evidence = tuple(
        _score_term(
            features,
            candidate_id=identity_candidate.id or "",
            access_probe_plan_id=access_probe_plan.id or "",
            check_kind=access_probe_plan.check_kind,
            term=term,
        )
        for term in ACCESS_TERMS
    )
    rank_score = sum(
        item.contribution for item in evidence if item.contribution is not None
    )
    candidate = AccessCandidate(
        endpoint_id=access_probe_plan.endpoint_id,
        check_kind=access_probe_plan.check_kind,
        subject_context=access_probe_plan.comparison_subject,
        resource_reference=resource_reference,
        resource_owner_context=resource_owner_context,
        access_probe_plan_id=access_probe_plan.id or "",
        input_point_id=access_probe_plan.input_point_id,
        rank_score=rank_score,
        scorer_version=ACCESS_SCORER_VERSION,
    )
    return AccessScoringResult.from_objects(access_probe_plan, candidate, evidence)


def _resource_description(access_probe_plan: AccessProbePlan) -> tuple[str, str]:
    method = access_probe_plan.reference_request.method.value
    path = urlsplit(access_probe_plan.reference_request.url).path or "/"
    location = f"{method} {path}"
    if access_probe_plan.check_kind == AccessCheckKind.CREDENTIAL_STRIP:
        return (
            location,
            "credentials observed during discovery (session cookie or "
            "Authorization header)",
        )
    return (
        f"{access_probe_plan.changed_aspect} on {location}",
        f"baseline value observed during discovery for "
        f"{access_probe_plan.changed_aspect}",
    )


def _score_term(
    features: Mapping[str, FeatureObservation],
    *,
    candidate_id: str,
    access_probe_plan_id: str,
    check_kind: AccessCheckKind,
    term: AccessScoringTerm,
) -> AccessScoreEvidence:
    observation = features.get(term.feature_name)
    if observation is None:
        return _missing_evidence(
            candidate_id=candidate_id,
            access_probe_plan_id=access_probe_plan_id,
            check_kind=check_kind,
            term=term,
            reason="Feature is absent from this observation; no numeric contribution.",
        )
    if not isinstance(observation, FeatureObservation):
        raise AccessScoringError(f"{term.feature_name} must be a FeatureObservation")
    if observation.name != term.feature_name:
        raise AccessScoringError(
            f"feature key {term.feature_name!r} does not match observation name "
            f"{observation.name!r}"
        )
    if not observation.observed:
        missing_reason = observation.details.get("reason")
        reason_context = (
            f" ({missing_reason})" if isinstance(missing_reason, str) else ""
        )
        return _missing_evidence(
            candidate_id=candidate_id,
            access_probe_plan_id=access_probe_plan_id,
            check_kind=check_kind,
            term=term,
            reason=(
                f"Feature is unavailable{reason_context} from {observation.source}; "
                "no numeric contribution."
            ),
        )

    value = observation.value
    if value is None or not isinstance(value, bool | int | float):
        raise AccessScoringError(f"observed feature {term.feature_name} must be numeric")
    numeric_value = float(value)
    if not isfinite(numeric_value):
        raise AccessScoringError(f"observed feature {term.feature_name} must be finite")
    if not 0.0 <= numeric_value <= 1.0:
        raise AccessScoringError(
            f"observed feature {term.feature_name} must be between 0.0 and 1.0"
        )
    contribution = numeric_value * term.weight
    return AccessScoreEvidence(
        candidate_id=candidate_id,
        access_probe_plan_id=access_probe_plan_id,
        feature_name=term.feature_name,
        feature_value=numeric_value,
        weight=term.weight,
        contribution=contribution,
        reason=term.reason,
        observed=True,
        check_kind=check_kind,
    )


def _missing_evidence(
    *,
    candidate_id: str,
    access_probe_plan_id: str,
    check_kind: AccessCheckKind,
    term: AccessScoringTerm,
    reason: str,
) -> AccessScoreEvidence:
    return AccessScoreEvidence(
        candidate_id=candidate_id,
        access_probe_plan_id=access_probe_plan_id,
        feature_name=term.feature_name,
        feature_value=None,
        weight=term.weight,
        contribution=None,
        reason=reason,
        observed=False,
        check_kind=check_kind,
    )
