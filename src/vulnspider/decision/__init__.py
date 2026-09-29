"""Decision layer over the authoritative candidate selection.

The scoring and selection layers answer "which candidates exist and in what
order". This package answers the ranking question a verification run faces: given
each candidate's calibrated probability, which Top-K should be reported, and --
optionally -- which smallest set holds a calibrated recall guarantee.

It consumes the selection layer's published contract and recomputes none of it
(ADR-017, ADR-021).
"""

from vulnspider.decision.candidate import (
    DEFAULT_FAMILY_PRIORITY,
    FAMILY_PRIORITY,
    DecisionCandidate,
    DecisionCandidateError,
    decision_candidate_from_context,
)
from vulnspider.decision.conformal import (
    CONFORMAL_METHOD_VERSION,
    ConformalCalibrationGroup,
    ConformalCalibrationItem,
    ConformalError,
    ConformalThreshold,
    calibrate_conformal_threshold,
    minimum_groups_for_target,
    select_by_threshold,
)
from vulnspider.decision.policy import (
    DECISION_POLICY_VERSION,
    DecisionOutcome,
    DecisionPolicyRunError,
    run_decision_layer,
)

__all__ = [
    "CONFORMAL_METHOD_VERSION",
    "DECISION_POLICY_VERSION",
    "DEFAULT_FAMILY_PRIORITY",
    "FAMILY_PRIORITY",
    "ConformalCalibrationGroup",
    "ConformalCalibrationItem",
    "ConformalError",
    "ConformalThreshold",
    "DecisionCandidate",
    "DecisionCandidateError",
    "DecisionOutcome",
    "DecisionPolicyRunError",
    "calibrate_conformal_threshold",
    "decision_candidate_from_context",
    "minimum_groups_for_target",
    "run_decision_layer",
    "select_by_threshold",
]
