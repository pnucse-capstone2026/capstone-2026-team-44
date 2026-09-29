"""Deterministic candidate generation and type-specific v0.1 scoring."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite

from vulnspider.domain import (
    FeatureObservation,
    FeatureVector,
    ScoreEvidence,
    VulnerabilityCandidate,
    VulnerabilityType,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)

SQLI_SCORER_VERSION = "sqli-weighted-v1"
XSS_SCORER_VERSION = "reflected-xss-weighted-v1"


@dataclass(frozen=True, slots=True)
class ScoringTerm:
    feature_name: str
    weight: float
    reason: str


SQLI_TERMS: tuple[ScoringTerm, ...] = (
    ScoringTerm(
        STATUS_CODE_CHANGED,
        20.0,
        "Observed status-code change raises SQLi verification priority.",
    ),
    ScoringTerm(
        RESPONSE_LENGTH_DIFF_RATIO,
        20.0,
        "Observed response-length difference raises SQLi verification priority.",
    ),
    ScoringTerm(
        SQL_ERROR_PATTERN,
        35.0,
        "Observed new SQL error pattern raises SQLi verification priority.",
    ),
)

XSS_TERMS: tuple[ScoringTerm, ...] = (
    ScoringTerm(
        MARKER_REFLECTED,
        35.0,
        "Observed new marker reflection raises Reflected XSS verification priority.",
    ),
    ScoringTerm(
        RESPONSE_LENGTH_DIFF_RATIO,
        10.0,
        "Observed response-length difference raises Reflected XSS verification priority.",
    ),
)

SQLI_MAX_RANK_SCORE = sum(term.weight for term in SQLI_TERMS)
XSS_MAX_RANK_SCORE = sum(term.weight for term in XSS_TERMS)


class ScoringError(ValueError):
    """Raised when a FeatureVector cannot be scored without fabrication."""


@dataclass(frozen=True, slots=True, init=False)
class ScoringResult:
    """One candidate score and its evidence from one exact FeatureVector."""

    feature_vector_id: str
    candidate: VulnerabilityCandidate
    evidence: tuple[ScoreEvidence, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ScoringResult must be created with from_objects()")

    @classmethod
    def from_objects(
        cls,
        feature_vector: FeatureVector,
        candidate: VulnerabilityCandidate,
        evidence: tuple[ScoreEvidence, ...],
    ) -> ScoringResult:
        if not isinstance(feature_vector, FeatureVector):
            raise TypeError("feature_vector must be a FeatureVector")
        if not isinstance(candidate, VulnerabilityCandidate):
            raise TypeError("candidate must be a VulnerabilityCandidate")
        if candidate.input_point_id != feature_vector.input_point_id:
            raise ScoringError(
                "ScoringResult candidate and FeatureVector ownership mismatch"
            )

        feature_vector_id = feature_vector.id or ""
        candidate_id = candidate.id or ""
        evidence_items = tuple(evidence)
        for item in evidence_items:
            if not isinstance(item, ScoreEvidence):
                raise TypeError("evidence must contain only ScoreEvidence")
            if item.candidate_id != candidate_id:
                raise ScoringError("ScoreEvidence candidate ownership mismatch")
            if item.feature_vector_id != feature_vector_id:
                raise ScoringError("ScoreEvidence FeatureVector ownership mismatch")
            if item.vulnerability_type != candidate.vulnerability_type:
                raise ScoringError("ScoreEvidence vulnerability type mismatch")

        instance = object.__new__(cls)
        object.__setattr__(instance, "feature_vector_id", feature_vector_id)
        object.__setattr__(instance, "candidate", candidate)
        object.__setattr__(instance, "evidence", evidence_items)
        return instance


@dataclass(frozen=True, slots=True)
class SQLiScorer:
    """Score only the currently available SQLi-relevant features."""

    def score(self, feature_vector: FeatureVector) -> ScoringResult:
        return _score_feature_vector(
            feature_vector,
            vulnerability_type=VulnerabilityType.SQLI,
            scorer_version=SQLI_SCORER_VERSION,
            terms=SQLI_TERMS,
        )


@dataclass(frozen=True, slots=True)
class XSSScorer:
    """Score only the currently available Reflected XSS features."""

    def score(self, feature_vector: FeatureVector) -> ScoringResult:
        return _score_feature_vector(
            feature_vector,
            vulnerability_type=VulnerabilityType.REFLECTED_XSS,
            scorer_version=XSS_SCORER_VERSION,
            terms=XSS_TERMS,
        )


@dataclass(frozen=True, slots=True)
class CandidateGenerator:
    """Generate both v0.1 candidate interpretations for one FeatureVector."""

    def generate(self, feature_vector: FeatureVector) -> tuple[ScoringResult, ...]:
        return (
            SQLiScorer().score(feature_vector),
            XSSScorer().score(feature_vector),
        )


def generate_candidates(feature_vector: FeatureVector) -> tuple[ScoringResult, ...]:
    """Generate and score SQLi and Reflected XSS candidates deterministically."""

    return CandidateGenerator().generate(feature_vector)


def _score_feature_vector(
    feature_vector: FeatureVector,
    *,
    vulnerability_type: VulnerabilityType,
    scorer_version: str,
    terms: tuple[ScoringTerm, ...],
) -> ScoringResult:
    if not isinstance(feature_vector, FeatureVector):
        raise ScoringError("feature_vector must be a FeatureVector")
    if not feature_vector.input_point_id:
        raise ScoringError("FeatureVector.input_point_id must not be empty")

    identity_candidate = VulnerabilityCandidate(
        input_point_id=feature_vector.input_point_id,
        vulnerability_type=vulnerability_type,
    )
    evidence = tuple(
        _score_term(
            feature_vector,
            candidate_id=identity_candidate.id or "",
            vulnerability_type=vulnerability_type,
            term=term,
        )
        for term in terms
    )
    rank_score = sum(
        item.contribution
        for item in evidence
        if item.contribution is not None
    )
    candidate = VulnerabilityCandidate(
        input_point_id=feature_vector.input_point_id,
        vulnerability_type=vulnerability_type,
        rank_score=rank_score,
        scorer_version=scorer_version,
    )
    return ScoringResult.from_objects(feature_vector, candidate, evidence)


def _score_term(
    feature_vector: FeatureVector,
    *,
    candidate_id: str,
    vulnerability_type: VulnerabilityType,
    term: ScoringTerm,
) -> ScoreEvidence:
    observation = feature_vector.features.get(term.feature_name)
    if observation is None:
        return _missing_evidence(
            feature_vector,
            candidate_id=candidate_id,
            vulnerability_type=vulnerability_type,
            term=term,
            reason="Feature is absent from this FeatureVector; no numeric contribution.",
        )
    if not isinstance(observation, FeatureObservation):
        raise ScoringError(f"{term.feature_name} must be a FeatureObservation")
    if observation.name != term.feature_name:
        raise ScoringError(
            f"feature key {term.feature_name!r} does not match observation name "
            f"{observation.name!r}"
        )
    if not observation.observed:
        missing_reason = observation.details.get("reason")
        reason_context = (
            f" ({missing_reason})" if isinstance(missing_reason, str) else ""
        )
        return _missing_evidence(
            feature_vector,
            candidate_id=candidate_id,
            vulnerability_type=vulnerability_type,
            term=term,
            reason=(
                f"Feature is unavailable{reason_context} from {observation.source}; "
                "no numeric contribution."
            ),
        )

    value = observation.value
    if value is None or not isinstance(value, bool | int | float):
        raise ScoringError(f"observed feature {term.feature_name} must be numeric")
    numeric_value = float(value)
    if not isfinite(numeric_value):
        raise ScoringError(f"observed feature {term.feature_name} must be finite")
    if not 0.0 <= numeric_value <= 1.0:
        raise ScoringError(
            f"observed feature {term.feature_name} must be between 0.0 and 1.0"
        )
    contribution = numeric_value * term.weight
    return ScoreEvidence(
        candidate_id=candidate_id,
        feature_name=term.feature_name,
        feature_value=numeric_value,
        weight=term.weight,
        contribution=contribution,
        reason=term.reason,
        observed=True,
        vulnerability_type=vulnerability_type,
        feature_vector_id=feature_vector.id,
    )


def _missing_evidence(
    feature_vector: FeatureVector,
    *,
    candidate_id: str,
    vulnerability_type: VulnerabilityType,
    term: ScoringTerm,
    reason: str,
) -> ScoreEvidence:
    return ScoreEvidence(
        candidate_id=candidate_id,
        feature_name=term.feature_name,
        feature_value=None,
        weight=term.weight,
        contribution=None,
        reason=reason,
        observed=False,
        vulnerability_type=vulnerability_type,
        feature_vector_id=feature_vector.id,
    )
