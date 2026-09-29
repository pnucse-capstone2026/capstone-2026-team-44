"""The VerificationResult record (docs/TEAM_INTERFACES_V0_2.md §3).

One record per proposal: it binds the source candidate, the provider and
proposal, the deterministic validator decision, the bounded execution trace (if
any), the baseline-vs-verification feature delta, and the rule-derived
confidence into one auditable object. A rejected proposal carries a decision and
reasons but no execution and no evidence -- the contract's "no execution exists
for a rejected/unvalidated payload" invariant, enforced in ``__post_init__``.

Nothing here recomputes a score or confidence: the producer (`focused.py`)
passes the authoritative pieces in, and this object only checks their ownership
and serializes them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from vulnspider.domain import VulnerabilityType, stable_fingerprint
from vulnspider.verification.confidence import (
    CONFIDENCE_RULE_VERSION,
    VerificationConfidence,
    VerificationOutcome,
)
from vulnspider.verification.delta import FeatureVectorDelta
from vulnspider.verification.proposal import MutationFamily, PayloadProposal
from vulnspider.verification.validator import (
    VALIDATOR_POLICY_VERSION,
    ValidatorResult,
)

VERIFICATION_CONTRACT_VERSION = "0.1"


class VerificationResultError(ValueError):
    """Raised when a verification result cannot be assembled honestly."""


class ResultStatus(StrEnum):
    """Superset of the confidence outcomes plus the pre-execution reject state."""

    REJECTED = "REJECTED"
    NOT_EXECUTED = "NOT_EXECUTED"
    UNCHANGED = "UNCHANGED"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    INCONCLUSIVE_ERROR = "INCONCLUSIVE_ERROR"


@dataclass(frozen=True, slots=True)
class ExecutionRefs:
    """The bounded request/response provenance of one executed verification."""

    probe_plan_id: str
    baseline_response_id: str
    probe_response_id: str
    verification_feature_vector_id: str
    baseline_execution_error: str | None = None
    probe_execution_error: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "probe_plan_id",
            "baseline_response_id",
            "probe_response_id",
            "verification_feature_vector_id",
        ):
            if not getattr(self, name):
                raise VerificationResultError(f"{name} must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_plan_id": self.probe_plan_id,
            "baseline_response_id": self.baseline_response_id,
            "probe_response_id": self.probe_response_id,
            "verification_feature_vector_id": self.verification_feature_vector_id,
            "baseline_execution_error": self.baseline_execution_error,
            "probe_execution_error": self.probe_execution_error,
        }


@dataclass(frozen=True, slots=True, init=False)
class VerificationResult:
    contract_version: str
    verification_result_id: str
    candidate_id: str
    selection_rank: int | None
    vulnerability_type: VulnerabilityType
    provider: str
    proposal_id: str
    proposer_version: str
    mutation_family: MutationFamily
    mutated_value: str
    based_on_value: str | None
    rationale: str
    validator_policy_version: str
    validator_decision: str
    validator_rejection_reasons: tuple[str, ...]
    validated_payload_id: str | None
    baseline_feature_vector_id: str
    execution_refs: ExecutionRefs | None
    feature_delta: FeatureVectorDelta | None
    confidence_rule_version: str
    verification_confidence: VerificationConfidence
    outcome_status: ResultStatus
    warnings: tuple[str, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise VerificationResultError(
            "VerificationResult must be created with from_objects()"
        )

    @classmethod
    def from_objects(
        cls,
        *,
        proposal: PayloadProposal,
        validator_result: ValidatorResult,
        confidence: VerificationConfidence,
        baseline_feature_vector_id: str,
        selection_rank: int | None,
        execution_refs: ExecutionRefs | None = None,
        feature_delta: FeatureVectorDelta | None = None,
    ) -> VerificationResult:
        if not isinstance(proposal, PayloadProposal):
            raise VerificationResultError("proposal must be a PayloadProposal")
        if not isinstance(validator_result, ValidatorResult):
            raise VerificationResultError("validator_result must be a ValidatorResult")
        if not isinstance(confidence, VerificationConfidence):
            raise VerificationResultError(
                "confidence must be a VerificationConfidence"
            )
        if validator_result.proposal_id != proposal.id:
            raise VerificationResultError(
                "validator result does not target this proposal"
            )
        if validator_result.candidate_id != proposal.candidate_id:
            raise VerificationResultError(
                "validator result does not target this candidate"
            )
        if not baseline_feature_vector_id:
            raise VerificationResultError("baseline_feature_vector_id must not be empty")

        accepted = validator_result.accepted
        if not accepted:
            if execution_refs is not None or feature_delta is not None:
                raise VerificationResultError(
                    "a rejected proposal must have no execution or feature delta"
                )
            outcome_status = ResultStatus.REJECTED
        else:
            outcome_status = ResultStatus(confidence.outcome.value)
            if execution_refs is not None and not isinstance(
                execution_refs, ExecutionRefs
            ):
                raise VerificationResultError("execution_refs must be ExecutionRefs")
            if feature_delta is not None and not isinstance(
                feature_delta, FeatureVectorDelta
            ):
                raise VerificationResultError(
                    "feature_delta must be a FeatureVectorDelta"
                )
            if execution_refs is None and confidence.outcome != VerificationOutcome.NOT_EXECUTED:
                raise VerificationResultError(
                    "an accepted-but-unexecuted result must carry NOT_EXECUTED"
                )

        validated_payload = validator_result.validated_payload
        validated_payload_id = (
            validated_payload.id if validated_payload is not None else None
        )
        verification_result_id = _result_id(
            proposal_id=proposal.id,
            validator_policy_version=validator_result.validator_policy_version,
            confidence_rule_version=confidence.rule_version,
            outcome_status=outcome_status.value,
            verification_feature_vector_id=(
                execution_refs.verification_feature_vector_id
                if execution_refs is not None
                else ""
            ),
        )

        instance = object.__new__(cls)
        object.__setattr__(instance, "contract_version", VERIFICATION_CONTRACT_VERSION)
        object.__setattr__(
            instance, "verification_result_id", verification_result_id
        )
        object.__setattr__(instance, "candidate_id", proposal.candidate_id)
        object.__setattr__(instance, "selection_rank", selection_rank)
        object.__setattr__(
            instance, "vulnerability_type", proposal.vulnerability_type
        )
        object.__setattr__(instance, "provider", proposal.provider)
        object.__setattr__(instance, "proposal_id", proposal.id)
        object.__setattr__(instance, "proposer_version", proposal.proposer_version)
        object.__setattr__(instance, "mutation_family", proposal.family)
        object.__setattr__(instance, "mutated_value", proposal.mutated_value)
        object.__setattr__(instance, "based_on_value", proposal.based_on_value)
        object.__setattr__(instance, "rationale", proposal.rationale)
        object.__setattr__(
            instance,
            "validator_policy_version",
            validator_result.validator_policy_version,
        )
        object.__setattr__(
            instance, "validator_decision", validator_result.decision.value
        )
        object.__setattr__(
            instance,
            "validator_rejection_reasons",
            tuple(reason.value for reason in validator_result.rejection_reasons),
        )
        object.__setattr__(instance, "validated_payload_id", validated_payload_id)
        object.__setattr__(
            instance, "baseline_feature_vector_id", baseline_feature_vector_id
        )
        object.__setattr__(instance, "execution_refs", execution_refs)
        object.__setattr__(instance, "feature_delta", feature_delta)
        object.__setattr__(
            instance, "confidence_rule_version", confidence.rule_version
        )
        object.__setattr__(instance, "verification_confidence", confidence)
        object.__setattr__(instance, "outcome_status", outcome_status)
        object.__setattr__(instance, "warnings", tuple(confidence.warnings))
        return instance

    @property
    def executed(self) -> bool:
        return self.execution_refs is not None

    @property
    def confidence(self) -> float:
        return self.verification_confidence.confidence

    def to_dict(self) -> dict[str, Any]:
        confidence = self.verification_confidence
        return {
            "contract_version": self.contract_version,
            "verification_result_id": self.verification_result_id,
            "candidate_id": self.candidate_id,
            "selection_rank": self.selection_rank,
            "vulnerability_type": self.vulnerability_type.value,
            "provider": self.provider,
            "proposal_id": self.proposal_id,
            "proposer_version": self.proposer_version,
            "mutation_family": self.mutation_family.value,
            "mutated_value": self.mutated_value,
            "based_on_value": self.based_on_value,
            "rationale": self.rationale,
            "validator": {
                "policy_version": self.validator_policy_version,
                "decision": self.validator_decision,
                "rejection_reasons": list(self.validator_rejection_reasons),
                "validated_payload_id": self.validated_payload_id,
            },
            "baseline_feature_vector_id": self.baseline_feature_vector_id,
            "execution": (
                None if self.execution_refs is None else self.execution_refs.to_dict()
            ),
            "feature_delta": _delta_to_dict(self.feature_delta),
            "confidence": {
                "rule_version": confidence.rule_version,
                "scale": confidence.scale,
                "outcome": confidence.outcome.value,
                "signal": confidence.signal.value,
                "model_version": confidence.model_version,
                "prior_probability": confidence.prior_probability,
                "verification_confidence": confidence.confidence,
                "confidence_delta": confidence.confidence_delta,
                "evidence": [
                    {
                        "feature_name": item.feature_name,
                        "baseline_value": item.baseline_value,
                        "verification_value": item.verification_value,
                        "direction": item.direction,
                        "reason": item.reason,
                    }
                    for item in confidence.evidence
                ],
            },
            "outcome_status": self.outcome_status.value,
            "warnings": list(self.warnings),
        }


def _delta_to_dict(delta: FeatureVectorDelta | None) -> dict[str, Any] | None:
    if delta is None:
        return None
    return {
        "input_point_id": delta.input_point_id,
        "verification_feature_vector_id": delta.verification_feature_vector_id,
        "material_delta_threshold": delta.material_delta_threshold,
        "max_abs_delta": delta.max_abs_delta,
        "changed": delta.changed,
        "observability_flips": list(delta.observability_flips),
        "features": [
            {
                "feature_name": item.feature_name,
                "baseline_value": item.baseline_value,
                "baseline_observed": item.baseline_observed,
                "verification_value": item.verification_value,
                "verification_observed": item.verification_observed,
                "delta": item.delta,
                "abs_delta": item.abs_delta,
                "observability_flip": item.observability_flip,
            }
            for item in delta.deltas
        ],
    }


def _result_id(
    *,
    proposal_id: str,
    validator_policy_version: str,
    confidence_rule_version: str,
    outcome_status: str,
    verification_feature_vector_id: str,
) -> str:
    fingerprint = stable_fingerprint(
        "verification-result",
        proposal_id,
        validator_policy_version,
        confidence_rule_version,
        outcome_status,
        verification_feature_vector_id,
    )
    return f"vres_{fingerprint[:16]}"


# Re-exported so consumers can reference the policy versions without importing
# three modules.
POLICY_VERSIONS = {
    "contract_version": VERIFICATION_CONTRACT_VERSION,
    "validator_policy_version": VALIDATOR_POLICY_VERSION,
    "confidence_rule_version": CONFIDENCE_RULE_VERSION,
}
