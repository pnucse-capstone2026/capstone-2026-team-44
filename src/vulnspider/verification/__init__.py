"""LLM-assisted focused verification and rule-based confidence update.

The last v0.2 pipeline stage. It takes the ranked ``AnalysisResult`` and, for
each top candidate, proposes same-family variant payloads, gates them through a
mandatory deterministic validator, re-probes the loopback target, differences
the new feature vector against the baseline one, and updates the confidence by a
reviewed rule set -- producing the ``VerificationResult`` contract
(`docs/TEAM_INTERFACES_V0_2.md` §3).

An LLM never sets the final number and never bypasses the validator
(`docs/PROTOTYPE_V0_2.md` §4.3-4.4).
"""

from vulnspider.verification.calibration import (
    DEFAULT_MAX_ABS_LLR,
    VERIFICATION_MODEL_VERSION,
    VerificationCalibrationError,
    VerificationConfidenceModel,
    VerificationSignal,
    VerificationTrainingSample,
    fit_verification_model,
)
from vulnspider.verification.confidence import (
    CONFIDENCE_RULE_VERSION,
    CONFIDENCE_SCALE,
    OUTCOME_FOR_SIGNAL,
    ConfidenceError,
    VerificationConfidence,
    VerificationEvidenceItem,
    VerificationOutcome,
    update_confidence,
)
from vulnspider.verification.delta import (
    DEFAULT_MATERIAL_DELTA,
    FeatureDelta,
    FeatureDeltaError,
    FeatureVectorDelta,
    compute_feature_delta,
)
from vulnspider.verification.focused import (
    CandidateVerification,
    FocusedVerificationError,
    VerificationConfig,
    VerificationRun,
    VerificationTarget,
    VerificationSelection,
    build_targets,
    verify_analysis,
    verify_target,
)
from vulnspider.verification.llm_proposal import (
    LLM_MODEL_PATH_ENV,
    LLM_PROPOSER_VERSION,
    PROVIDER_LOCAL_LLM,
    LLMProposerError,
    LocalLLMMutationProposer,
)
from vulnspider.verification.planner import (
    VerificationPlanningError,
    plan_verification_probe,
    probe_family_for_mutation,
)
from vulnspider.verification.proposal import (
    DETERMINISTIC_PROPOSER_VERSION,
    PROVIDER_DETERMINISTIC,
    DeterministicMutationProposer,
    FAMILIES_FOR_TYPE,
    MutationFamily,
    MutationProposalError,
    MutationSubject,
    PayloadProposal,
    PayloadProposer,
    verification_identifier,
)
from vulnspider.verification.result import (
    VERIFICATION_CONTRACT_VERSION,
    ExecutionRefs,
    ResultStatus,
    VerificationResult,
    VerificationResultError,
)
from vulnspider.verification.validator import (
    MAX_PAYLOAD_LENGTH,
    VALIDATOR_POLICY_VERSION,
    PayloadValidator,
    ValidatedPayload,
    ValidatorDecision,
    ValidatorError,
    ValidatorRejectionReason,
    ValidatorResult,
)

__all__ = [
    "CONFIDENCE_RULE_VERSION",
    "CONFIDENCE_SCALE",
    "DEFAULT_MATERIAL_DELTA",
    "DEFAULT_MAX_ABS_LLR",
    "DETERMINISTIC_PROPOSER_VERSION",
    "FAMILIES_FOR_TYPE",
    "LLM_MODEL_PATH_ENV",
    "LLM_PROPOSER_VERSION",
    "MAX_PAYLOAD_LENGTH",
    "OUTCOME_FOR_SIGNAL",
    "PROVIDER_DETERMINISTIC",
    "PROVIDER_LOCAL_LLM",
    "VALIDATOR_POLICY_VERSION",
    "VERIFICATION_CONTRACT_VERSION",
    "VERIFICATION_MODEL_VERSION",
    "CandidateVerification",
    "ConfidenceError",
    "DeterministicMutationProposer",
    "LLMProposerError",
    "LocalLLMMutationProposer",
    "VerificationCalibrationError",
    "VerificationConfidenceModel",
    "VerificationSignal",
    "VerificationTrainingSample",
    "fit_verification_model",
    "ExecutionRefs",
    "FeatureDelta",
    "FeatureDeltaError",
    "FeatureVectorDelta",
    "FocusedVerificationError",
    "MutationFamily",
    "MutationProposalError",
    "MutationSubject",
    "PayloadProposal",
    "PayloadProposer",
    "PayloadValidator",
    "ResultStatus",
    "ValidatedPayload",
    "ValidatorDecision",
    "ValidatorError",
    "ValidatorRejectionReason",
    "ValidatorResult",
    "VerificationConfig",
    "VerificationConfidence",
    "VerificationEvidenceItem",
    "VerificationOutcome",
    "VerificationPlanningError",
    "VerificationResult",
    "VerificationResultError",
    "VerificationRun",
    "VerificationTarget",
    "VerificationSelection",
    "build_targets",
    "compute_feature_delta",
    "plan_verification_probe",
    "probe_family_for_mutation",
    "update_confidence",
    "verification_identifier",
    "verify_analysis",
    "verify_target",
]
