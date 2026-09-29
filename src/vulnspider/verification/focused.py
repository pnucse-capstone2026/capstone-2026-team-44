"""Focused verification orchestrator: the confidence-update pipeline stage.

This is the last pipeline stage. It consumes the already-ranked
``AnalysisResult`` (crawl -> observe -> feature -> score -> Top-K) and, for each
top candidate, runs the loop the user described:

1. ask the proposer for same-family variant payloads (``proposal.py``),
2. gate every one through the deterministic validator (``validator.py``),
3. re-send each accepted payload against the loopback target and re-probe
   (``planner.py`` + the v0.1 executor + the v0.1 feature extractor),
4. difference the re-probed feature vector against the baseline one
   (``delta.py``), and
5. update the confidence by the reviewed rule set (``confidence.py``),

emitting one :class:`~vulnspider.verification.result.VerificationResult` per
proposal and one :class:`CandidateVerification` summary per candidate.

The orchestrator owns everything a proposer must not touch: the transport, the
loopback guard, the calibrated prior, and the provenance. It never lets a
rejected payload execute, and it never sends a request off the loopback.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

from vulnspider.domain import (
    FeatureVector,
    InputPoint,
    RequestInstance,
    VulnerabilityType,
    normalize_parameter_name,
)
from vulnspider.features import extract_minimal_features
from vulnspider.observation import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    execute_probe_plan,
)
from vulnspider.observation.executor import RequestTransport
from vulnspider.scoring.calibration import (
    CalibratedScorer,
    CalibrationError,
    heuristic_prior_for_family,
)
from vulnspider.scope.loopback import (
    LoopbackSafetyError,
    require_loopback_http_url,
)
from vulnspider.verification.calibration import (
    VerificationConfidenceModel,
    VerificationSignal,
)
from vulnspider.verification.confidence import OUTCOME_FOR_SIGNAL, update_confidence
from vulnspider.verification.delta import (
    DEFAULT_MATERIAL_DELTA,
    compute_feature_delta,
)
from vulnspider.verification.planner import (
    VerificationPlanningError,
    plan_verification_probe,
)
from vulnspider.verification.proposal import (
    DeterministicMutationProposer,
    MutationSubject,
    PayloadProposal,
    PayloadProposer,
)
from vulnspider.verification.result import (
    VERIFICATION_CONTRACT_VERSION,
    ExecutionRefs,
    ResultStatus,
    VerificationResult,
)
from vulnspider.verification.validator import PayloadValidator, ValidatorResult

DEFAULT_MAX_CANDIDATES = 10

# Aggregation priority when a candidate's payloads land on different signals:
# the strongest evidence wins. Support (newly revealed first) outranks a
# weakening, which outranks an inconclusive error, an unchanged, and finally a
# not-executed/rejected result.
_SIGNAL_PRIORITY: dict[VerificationSignal, int] = {
    VerificationSignal.SUPPORT_NEW: 0,
    VerificationSignal.SUPPORT_REPRODUCED: 1,
    VerificationSignal.WEAKEN: 2,
    VerificationSignal.INCONCLUSIVE: 3,
    VerificationSignal.UNCHANGED: 4,
    VerificationSignal.NOT_EXECUTED: 5,
}


class FocusedVerificationError(ValueError):
    """Raised when focused verification cannot run against an analysis."""


@dataclass(frozen=True, slots=True)
class VerificationConfig:
    """Bounds and injected collaborators for one verification run."""

    proposer: PayloadProposer = field(default_factory=DeterministicMutationProposer)
    validator: PayloadValidator = field(default_factory=PayloadValidator)
    transport: RequestTransport | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    material_delta_threshold: float = DEFAULT_MATERIAL_DELTA
    max_candidates: int = DEFAULT_MAX_CANDIDATES
    confidence_model: VerificationConfidenceModel = field(
        default_factory=VerificationConfidenceModel.default
    )
    # Optional per-candidate progress hook: called ``(index, total, target)``
    # just before each candidate is verified, so a caller (the CLI) can report
    # progress during a long run (e.g. the LLM proposer). Purely observational --
    # it never changes what is verified.
    progress: Callable[[int, int, "VerificationTarget"], None] | None = None
    # Optional diagnostic sink used only for timing/proposer diagnostics. It does
    # not influence selection, payload validation, execution, or confidence.
    diagnostics: Callable[[str], None] | None = None


@dataclass(frozen=True, slots=True)
class VerificationSelection:
    """One candidate the caller wants verified, and the prior to update.

    ``build_targets`` defaults to the v0.1 heuristic Top-K held on
    ``AnalysisResult.selection``. That is the right set when the goal is to
    collect verification training data over the historical ordering, but it is
    the *wrong* set for a scan report: the decision layer ranks by calibrated
    probability, and once a fitted model or a calibration-only term (the XSS
    encoding penalty, ADR-031) pulls the two orderings apart, the verified
    candidates can miss the reported Top-K entirely. Passing an explicit
    selection keeps verification pointed at exactly the candidates the report
    ranks, with exactly the priors the report shows.
    """

    candidate_id: str
    input_point_id: str
    feature_vector_id: str
    vulnerability_type: VulnerabilityType
    prior_probability: float


@dataclass(frozen=True, slots=True)
class VerificationTarget:
    """One selected candidate resolved to everything verification needs."""

    candidate_id: str
    selection_rank: int
    vulnerability_type: VulnerabilityType
    input_point: InputPoint
    baseline_request: RequestInstance
    baseline_feature_vector: FeatureVector
    prior_probability: float


@dataclass(frozen=True, slots=True)
class CandidateVerification:
    """The aggregate verdict for one candidate across its payloads."""

    candidate_id: str
    input_point_id: str
    vulnerability_type: VulnerabilityType
    selection_rank: int
    prior_probability: float
    final_outcome: ResultStatus
    final_signal: VerificationSignal
    final_confidence: float
    results: tuple[VerificationResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "input_point_id": self.input_point_id,
            "vulnerability_type": self.vulnerability_type.value,
            "selection_rank": self.selection_rank,
            "prior_probability": self.prior_probability,
            "final_outcome": self.final_outcome.value,
            "final_signal": self.final_signal.value,
            "final_confidence": self.final_confidence,
            "confidence_delta": self.final_confidence - self.prior_probability,
            "results": [result.to_dict() for result in self.results],
        }


@dataclass(frozen=True, slots=True)
class VerificationRun:
    """The full verification stage output for one analysis."""

    contract_version: str
    candidates: tuple[CandidateVerification, ...]
    warnings: tuple[str, ...]

    @property
    def results(self) -> tuple[VerificationResult, ...]:
        return tuple(
            result
            for candidate in self.candidates
            for result in candidate.results
        )

    def counts(self) -> dict[str, int]:
        results = self.results
        return {
            "candidates_verified": len(self.candidates),
            "proposals": len(results),
            "accepted": sum(
                r.outcome_status != ResultStatus.REJECTED for r in results
            ),
            "rejected": sum(
                r.outcome_status == ResultStatus.REJECTED for r in results
            ),
            "executed": sum(r.executed for r in results),
            "supported": sum(
                r.outcome_status == ResultStatus.SUPPORTED for r in results
            ),
            "weakened": sum(
                r.outcome_status == ResultStatus.WEAKENED for r in results
            ),
            "inconclusive_error": sum(
                r.outcome_status == ResultStatus.INCONCLUSIVE_ERROR for r in results
            ),
            "unchanged": sum(
                r.outcome_status == ResultStatus.UNCHANGED for r in results
            ),
        }

    def to_dict(self, *, target_url: str | None = None) -> dict[str, Any]:
        return {
            "report_version": "verification-report-v1",
            "contract_version": self.contract_version,
            "target": target_url,
            "counts": self.counts(),
            "warnings": list(self.warnings),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


@dataclass
class _CandidateTiming:
    validation_seconds: float = 0.0
    planning_seconds: float = 0.0
    execution_seconds: float = 0.0
    postprocess_seconds: float = 0.0
    accepted: int = 0
    rejected: int = 0
    not_planned: int = 0
    rejection_reasons: dict[str, int] = field(default_factory=dict)


def _diagnostic(config: VerificationConfig, message: str) -> None:
    if config.diagnostics is not None:
        config.diagnostics(message)


def verify_analysis(
    analysis: Any,
    *,
    config: VerificationConfig | None = None,
    selection: Sequence[VerificationSelection] | None = None,
) -> VerificationRun:
    """Run focused verification over the Top-K of one analysis result.

    ``selection`` names the candidates to verify, in report order. Without it
    the v0.1 heuristic Top-K on ``analysis.selection`` is used, which is what
    the verification corpus builder wants; a scan wants the decision layer's
    Top-K instead (see :class:`VerificationSelection`).
    """

    config = config or VerificationConfig()
    targets, warnings = build_targets(
        analysis,
        max_candidates=config.max_candidates,
        selection=selection,
    )
    total = len(targets)
    verified: list[CandidateVerification] = []
    for index, target in enumerate(targets, start=1):
        if config.progress is not None:
            config.progress(index, total, target)
        verified.append(verify_target(target, config=config))
    return VerificationRun(
        contract_version=VERIFICATION_CONTRACT_VERSION,
        candidates=tuple(verified),
        warnings=tuple(warnings),
    )


def verify_target(
    target: VerificationTarget,
    *,
    config: VerificationConfig | None = None,
) -> CandidateVerification:
    """Propose, validate, re-probe, and update confidence for one candidate."""

    config = config or VerificationConfig()
    if not isinstance(target, VerificationTarget):
        raise FocusedVerificationError("target must be a VerificationTarget")

    subject = MutationSubject(
        candidate_id=target.candidate_id,
        input_point_id=target.input_point.id or "",
        vulnerability_type=target.vulnerability_type,
        parameter_name=target.input_point.name,
        parameter_location=target.input_point.location,
        baseline_value=_target_baseline_value(target),
    )
    candidate_started = perf_counter()

    proposal_started = perf_counter()
    proposals = config.proposer.propose(subject)
    proposal_seconds = perf_counter() - proposal_started
    _diagnostic(
        config,
        f"      [TIMING] proposer {proposal_seconds:.2f}s "
        f"-- proposals={len(proposals)}",
    )
    proposer_diagnostics = getattr(config.proposer, "diagnostics", ())
    for diagnostic in proposer_diagnostics:
        _diagnostic(config, f"      [LLM] {diagnostic}")
    proposer_warnings = getattr(config.proposer, "warnings", ())
    for warning in proposer_warnings:
        _diagnostic(config, f"      [LLM] {warning}")

    timing = _CandidateTiming()
    results = tuple(
        _verify_proposal(target, proposal, config=config, timing=timing)
        for proposal in proposals
    )
    final_signal, final_outcome, final_confidence = _aggregate(target, results)

    _diagnostic(
        config,
        f"      [TIMING] validator {timing.validation_seconds:.2f}s "
        f"-- accepted={timing.accepted}/rejected={timing.rejected}",
    )
    for reason, count in sorted(timing.rejection_reasons.items()):
        _diagnostic(config, f"          - {reason}: {count}")
    _diagnostic(
        config,
        f"      [TIMING] HTTP re-probe {timing.execution_seconds:.2f}s "
        f"-- accepted_payloads={timing.accepted - timing.not_planned}",
    )
    other_seconds = timing.planning_seconds + timing.postprocess_seconds
    _diagnostic(config, f"      [TIMING] planning/postprocess {other_seconds:.2f}s")
    _diagnostic(
        config,
        f"      [TIMING] candidate internal total "
        f"{perf_counter() - candidate_started:.2f}s",
    )
    return CandidateVerification(
        candidate_id=target.candidate_id,
        input_point_id=target.input_point.id or "",
        vulnerability_type=target.vulnerability_type,
        selection_rank=target.selection_rank,
        prior_probability=target.prior_probability,
        final_outcome=final_outcome,
        final_signal=final_signal,
        final_confidence=final_confidence,
        results=results,
    )


def _verify_proposal(
    target: VerificationTarget,
    proposal: PayloadProposal,
    *,
    config: VerificationConfig,
    timing: _CandidateTiming | None = None,
) -> VerificationResult:
    validation_started = perf_counter()
    validator_result = config.validator.validate(proposal)
    if timing is not None:
        timing.validation_seconds += perf_counter() - validation_started
    if not validator_result.accepted:
        if timing is not None:
            timing.rejected += 1
            for reason in validator_result.rejection_reasons:
                reason_name = getattr(reason, "value", str(reason))
                timing.rejection_reasons[reason_name] = (
                    timing.rejection_reasons.get(reason_name, 0) + 1
                )
        return _rejected_result(target, proposal, validator_result, config=config)

    if timing is not None:
        timing.accepted += 1

    payload = validator_result.validated_payload
    assert payload is not None  # validator guarantees this for accepted results
    planning_started = perf_counter()
    try:
        probe_plan = plan_verification_probe(
            input_point=target.input_point,
            baseline_request=target.baseline_request,
            injected_value=payload.mutated_value,
            probe_marker=payload.reflection_marker,
            mutation_family=payload.family,
        )
    except VerificationPlanningError:
        if timing is not None:
            timing.planning_seconds += perf_counter() - planning_started
            timing.not_planned += 1
        return _not_executed_result(target, proposal, validator_result, config=config)
    if timing is not None:
        timing.planning_seconds += perf_counter() - planning_started

    _require_loopback(probe_plan.baseline_request.url)
    _require_loopback(probe_plan.probe_request.url)

    execution_started = perf_counter()
    execution = execute_probe_plan(
        probe_plan,
        transport=config.transport,
        timeout_seconds=config.timeout_seconds,
        max_body_bytes=config.max_body_bytes,
    )
    if timing is not None:
        timing.execution_seconds += perf_counter() - execution_started

    postprocess_started = perf_counter()
    verification_vector = extract_minimal_features(
        target.input_point,
        probe_plan,
        execution.response_pair,
        execution.baseline_response,
        execution.probe_response,
    )
    execution_ok = not (
        execution.baseline_response.execution_error
        or execution.probe_response.execution_error
    )
    delta = compute_feature_delta(
        target.baseline_feature_vector,
        verification_vector,
        material_delta_threshold=config.material_delta_threshold,
        execution_ok=execution_ok,
    )
    confidence = update_confidence(
        vulnerability_type=target.vulnerability_type,
        prior_probability=target.prior_probability,
        delta=delta,
        executed=True,
        model=config.confidence_model,
        probe_status_code=execution.probe_response.status_code,
        baseline_status_code=execution.baseline_response.status_code,
    )
    execution_refs = ExecutionRefs(
        probe_plan_id=probe_plan.id or "",
        baseline_response_id=execution.baseline_response.id or "",
        probe_response_id=execution.probe_response.id or "",
        verification_feature_vector_id=verification_vector.id or "",
        baseline_execution_error=execution.baseline_response.execution_error,
        probe_execution_error=execution.probe_response.execution_error,
    )
    if timing is not None:
        timing.postprocess_seconds += perf_counter() - postprocess_started
    return VerificationResult.from_objects(
        proposal=proposal,
        validator_result=validator_result,
        confidence=confidence,
        baseline_feature_vector_id=target.baseline_feature_vector.id or "",
        selection_rank=target.selection_rank,
        execution_refs=execution_refs,
        feature_delta=delta,
    )


def _rejected_result(
    target: VerificationTarget,
    proposal: PayloadProposal,
    validator_result: ValidatorResult,
    *,
    config: VerificationConfig,
) -> VerificationResult:
    confidence = update_confidence(
        vulnerability_type=target.vulnerability_type,
        prior_probability=target.prior_probability,
        delta=None,
        executed=False,
        model=config.confidence_model,
    )
    return VerificationResult.from_objects(
        proposal=proposal,
        validator_result=validator_result,
        confidence=confidence,
        baseline_feature_vector_id=target.baseline_feature_vector.id or "",
        selection_rank=target.selection_rank,
    )


def _not_executed_result(
    target: VerificationTarget,
    proposal: PayloadProposal,
    validator_result: ValidatorResult,
    *,
    config: VerificationConfig,
) -> VerificationResult:
    # Accepted, but the payload could not be planned into a probe (e.g. a
    # non-request-bindable location). No request was sent, so the prior is kept.
    confidence = update_confidence(
        vulnerability_type=target.vulnerability_type,
        prior_probability=target.prior_probability,
        delta=None,
        executed=False,
        model=config.confidence_model,
    )
    return VerificationResult.from_objects(
        proposal=proposal,
        validator_result=validator_result,
        confidence=confidence,
        baseline_feature_vector_id=target.baseline_feature_vector.id or "",
        selection_rank=target.selection_rank,
    )


def _aggregate(
    target: VerificationTarget,
    results: tuple[VerificationResult, ...],
) -> tuple[VerificationSignal, ResultStatus, float]:
    """Reduce a candidate's per-payload results to one signal, outcome, score.

    The strongest signal wins (``_SIGNAL_PRIORITY``): newly revealed support
    over reproduced support over a weakening over an inconclusive error over no
    change. The chosen payload's confidence is the candidate's final confidence
    -- and because every payload shares one prior and one model, that equals the
    model applied to the winning signal.
    """

    if not results:
        return (
            VerificationSignal.NOT_EXECUTED,
            ResultStatus.NOT_EXECUTED,
            target.prior_probability,
        )
    best = min(
        results,
        key=lambda r: (
            _SIGNAL_PRIORITY[r.verification_confidence.signal],
            r.verification_result_id,
        ),
    )
    final_signal = best.verification_confidence.signal
    if all(r.outcome_status == ResultStatus.REJECTED for r in results):
        return final_signal, ResultStatus.REJECTED, target.prior_probability
    final_outcome = ResultStatus(OUTCOME_FOR_SIGNAL[final_signal].value)
    return final_signal, final_outcome, best.confidence


def build_targets(
    analysis: Any,
    *,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    selection: Sequence[VerificationSelection] | None = None,
) -> tuple[tuple[VerificationTarget, ...], list[str]]:
    """Resolve the candidates to verify into verification targets.

    With ``selection`` the caller owns both the set and the priors. Without it
    the v0.1 heuristic Top-K on ``analysis.selection`` is resolved instead, and
    the prior comes from the zero-corpus heuristic scorer.
    """

    input_points = {point.id or "": point for point in analysis.input_points}
    vectors = {vector.id or "": vector for vector in analysis.feature_vectors}
    baseline_requests = _baseline_requests(analysis)
    scorer_cache: dict[str, CalibratedScorer] = {}

    entries: list[tuple[str, str, str, VulnerabilityType, float | None]] = []
    if selection is None:
        outcome = getattr(analysis, "selection", None)
        if outcome is None:
            raise FocusedVerificationError("analysis has no selection outcome")
        for ranked in outcome.selected:
            candidate = ranked.scoring_result.candidate
            entries.append(
                (
                    candidate.id or "",
                    candidate.input_point_id,
                    ranked.scoring_result.feature_vector_id,
                    candidate.vulnerability_type,
                    None,
                )
            )
    else:
        entries.extend(
            (
                chosen.candidate_id,
                chosen.input_point_id,
                chosen.feature_vector_id,
                chosen.vulnerability_type,
                chosen.prior_probability,
            )
            for chosen in selection
        )

    targets: list[VerificationTarget] = []
    warnings: list[str] = []
    for rank, entry in enumerate(entries, start=1):
        if 0 < max_candidates < rank:
            break
        candidate_id, input_point_id, feature_vector_id, family, prior = entry
        vector = vectors.get(feature_vector_id)
        input_point = input_points.get(input_point_id)
        baseline_request = baseline_requests.get(input_point_id)
        if input_point is None or vector is None or baseline_request is None:
            warnings.append(
                f"candidate {candidate_id} rank {rank} skipped: "
                "missing input point, feature vector, or baseline request"
            )
            continue
        if input_point.location.value not in {"QUERY", "FORM"}:
            warnings.append(
                f"candidate {candidate_id} rank {rank} skipped: "
                f"location {input_point.location.value} is not verification-bindable"
            )
            continue
        if prior is None:
            prior = _prior_probability(family, vector, scorer_cache)
        if prior is None:
            warnings.append(
                f"candidate {candidate_id} rank {rank} skipped: "
                f"no calibrated prior for family {family.value}"
            )
            continue
        targets.append(
            VerificationTarget(
                candidate_id=candidate_id,
                selection_rank=rank,
                vulnerability_type=family,
                input_point=input_point,
                baseline_request=baseline_request,
                baseline_feature_vector=vector,
                prior_probability=prior,
            )
        )
    return tuple(targets), warnings


def _baseline_requests(analysis: Any) -> dict[str, RequestInstance]:
    """Pick one deterministic baseline request per InputPoint.

    An InputPoint can own several probe runs; the first by stable ProbePlan id
    is chosen, matching how the decision report picks a representative run.
    """

    chosen: dict[str, tuple[str, RequestInstance]] = {}
    for observation in analysis.probe_observations:
        input_point_id = observation.input_point_id
        probe_plan_id = observation.probe_plan.id or ""
        current = chosen.get(input_point_id)
        if current is None or probe_plan_id < current[0]:
            chosen[input_point_id] = (
                probe_plan_id,
                observation.probe_plan.baseline_request,
            )
    return {key: request for key, (_id, request) in chosen.items()}


def _prior_probability(
    vulnerability_type: VulnerabilityType,
    vector: FeatureVector,
    scorer_cache: dict[str, CalibratedScorer],
) -> float | None:
    family = VulnerabilityType(vulnerability_type).value
    scorer = scorer_cache.get(family)
    if scorer is None:
        try:
            scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(family))
        except CalibrationError:
            return None
        scorer_cache[family] = scorer
    return scorer.probability(vector.features).probability


def _target_baseline_value(target: VerificationTarget) -> str | None:
    input_point = target.input_point
    if input_point.baseline_value is not None:
        return input_point.baseline_value
    pairs = (
        target.baseline_request.query
        if input_point.location.value == "QUERY"
        else target.baseline_request.form
    )
    matches = [
        value
        for name, value in pairs
        if normalize_parameter_name(name) == input_point.name
    ]
    if input_point.occurrence_index is not None:
        if input_point.occurrence_index < len(matches):
            return matches[input_point.occurrence_index]
        return None
    return matches[0] if len(matches) == 1 else None


def _require_loopback(url: str) -> None:
    try:
        require_loopback_http_url(url)
    except LoopbackSafetyError as exc:
        raise FocusedVerificationError(
            "verification permits only localhost or loopback IP targets"
        ) from exc
