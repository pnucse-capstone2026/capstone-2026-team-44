"""Interface Contract v1 handoff over the two canonical JSON artifacts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from math import isclose, isfinite
from typing import Any

from vulnspider.discovery.contracts import (
    CONTRACT_VERSION as DISCOVERY_CONTRACT_VERSION,
    DiscoveryContractError,
    discovery_snapshot_id_for,
)
from vulnspider.domain import (
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    normalize_parameter_name,
)
from vulnspider.reporting.json_report import REPORT_SCHEMA_VERSION
from vulnspider.scoring import ScoringResult, generate_candidates
from vulnspider.sensitive import (
    contains_credential_material as _contains_credential_material,
)
from vulnspider.sensitive import credential_field_name as _credential_field_name
from vulnspider.selection import (
    RankedScoringResult,
    SelectionError,
    SelectionOutcome,
    select_top_k,
)


INTERFACE_CONTRACT_VERSION = "1.0"
class HandoffContractError(ValueError):
    """Raised when canonical artifacts cannot produce a safe handoff."""


class CandidateCategory(StrEnum):
    INJECTION = "INJECTION"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"


class HandoffVulnerabilityType(StrEnum):
    SQLI = "SQLI"
    REFLECTED_XSS = "REFLECTED_XSS"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    feature_name: str
    feature_value: float | None
    observed: bool
    weight: float
    contribution: float | None
    reason: str

    def __post_init__(self) -> None:
        _string(self.feature_name, "evidence feature_name")
        _string(self.reason, "evidence reason")
        if type(self.observed) is not bool:
            raise HandoffContractError("evidence observed must be a boolean")
        object.__setattr__(self, "weight", _number(self.weight, "evidence weight"))
        if self.observed:
            if self.feature_value is None or self.contribution is None:
                raise HandoffContractError(
                    "observed evidence requires feature_value and contribution"
                )
            object.__setattr__(
                self,
                "feature_value",
                _number(self.feature_value, "evidence feature_value"),
            )
            object.__setattr__(
                self,
                "contribution",
                _number(self.contribution, "evidence contribution"),
            )
        elif self.feature_value is not None or self.contribution is not None:
            raise HandoffContractError(
                "unobserved evidence must not fabricate numeric zero or contribution"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "feature_value": self.feature_value,
            "observed": self.observed,
            "weight": self.weight,
            "contribution": self.contribution,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class CandidateProvenance:
    discovery_run_id: str
    discovery_snapshot_id: str
    discovery_provenance_ids: tuple[str, ...]
    request_template_id: str | None = None
    request_context_id: str | None = None
    probe_plan_id: str | None = None
    response_pair_ids: tuple[str, ...] = ()
    baseline_request_id: str | None = None
    probe_request_id: str | None = None
    baseline_response_id: str | None = None
    probe_response_id: str | None = None

    def __post_init__(self) -> None:
        _string(self.discovery_run_id, "discovery_run_id")
        _string(self.discovery_snapshot_id, "discovery_snapshot_id")
        object.__setattr__(
            self,
            "discovery_provenance_ids",
            _canonical_ids(
                self.discovery_provenance_ids,
                "discovery_provenance_ids",
            ),
        )
        object.__setattr__(
            self,
            "response_pair_ids",
            _canonical_ids(self.response_pair_ids, "response_pair_ids"),
        )
        for name in (
            "request_template_id",
            "request_context_id",
            "probe_plan_id",
            "baseline_request_id",
            "probe_request_id",
            "baseline_response_id",
            "probe_response_id",
        ):
            value = getattr(self, name)
            if value is not None:
                _string(value, name)

    def validate_injection(self) -> None:
        required = (
            self.discovery_provenance_ids,
            self.request_template_id,
            self.request_context_id,
            self.probe_plan_id,
            self.response_pair_ids,
            self.baseline_request_id,
            self.probe_request_id,
            self.baseline_response_id,
            self.probe_response_id,
        )
        if not all(required):
            raise HandoffContractError("Injection provenance is incomplete")

    def to_dict(self) -> dict[str, Any]:
        return {
            "discovery_run_id": self.discovery_run_id,
            "discovery_snapshot_id": self.discovery_snapshot_id,
            "discovery_provenance_ids": list(self.discovery_provenance_ids),
            "request_template_id": self.request_template_id,
            "request_context_id": self.request_context_id,
            "probe_plan_id": self.probe_plan_id,
            "response_pair_ids": list(self.response_pair_ids),
            "baseline_request_id": self.baseline_request_id,
            "probe_request_id": self.probe_request_id,
            "baseline_response_id": self.baseline_response_id,
            "probe_response_id": self.probe_response_id,
        }


@dataclass(frozen=True, slots=True)
class InjectionMutationContext:
    request_template_id: str
    request_context_id: str
    method: HttpMethod
    url: str
    parameter_name: str
    parameter_location: InputLocation
    parameter_occurrence: int | None
    original_value: str | None
    auth_context_id: str | None = None

    def __post_init__(self) -> None:
        _string(self.request_template_id, "request_template_id")
        _string(self.request_context_id, "request_context_id")
        _string(self.url, "mutation context URL")
        _string(self.parameter_name, "parameter_name")
        try:
            method = HttpMethod(self.method)
            location = InputLocation(self.parameter_location)
        except ValueError as exc:
            raise HandoffContractError(
                "mutation context must use canonical method and location"
            ) from exc
        if self.parameter_occurrence is not None and (
            type(self.parameter_occurrence) is not int
            or self.parameter_occurrence < 0
        ):
            raise HandoffContractError("parameter_occurrence is invalid")
        if self.original_value is not None and type(self.original_value) is not str:
            raise HandoffContractError("original_value must be a string or null")
        if self.auth_context_id is not None:
            _string(self.auth_context_id, "auth_context_id")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "parameter_location", location)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_template_id": self.request_template_id,
            "request_context_id": self.request_context_id,
            "method": self.method.value,
            "url": self.url,
            "parameter_name": self.parameter_name,
            "parameter_location": self.parameter_location.value,
            "parameter_occurrence": self.parameter_occurrence,
            "original_value": self.original_value,
            "auth_context_id": self.auth_context_id,
        }


@dataclass(frozen=True, slots=True)
class NormalizedCandidate:
    candidate_id: str
    category: CandidateCategory
    vulnerability_type: HandoffVulnerabilityType
    rank: int
    raw_rank_score: float
    raw_rank_score_max: float
    selection_priority: float
    input_point_id: str | None
    endpoint_id: str | None
    scorer_version: str
    feature_vector_id: str | None
    evidence: tuple[CandidateEvidence, ...]
    provenance: CandidateProvenance
    injection_context: InjectionMutationContext | None = None

    def __post_init__(self) -> None:
        _string(self.candidate_id, "candidate_id")
        _string(self.scorer_version, "scorer_version")
        try:
            category = CandidateCategory(self.category)
            vulnerability = HandoffVulnerabilityType(self.vulnerability_type)
        except ValueError as exc:
            raise HandoffContractError("candidate category or type is invalid") from exc
        if type(self.rank) is not int or self.rank <= 0:
            raise HandoffContractError("rank must be a positive post-selection value")
        raw_score = _number(self.raw_rank_score, "raw_rank_score")
        maximum = _number(self.raw_rank_score_max, "raw_rank_score_max")
        priority = _number(self.selection_priority, "selection_priority")
        if maximum <= 0 or not 0 <= raw_score <= maximum:
            raise HandoffContractError("raw rank score is outside its scorer range")
        if not isclose(priority, raw_score / maximum, rel_tol=0.0, abs_tol=1e-12):
            raise HandoffContractError(
                "selection_priority must be normalized from the scorer range"
            )
        if self.input_point_id is None and self.endpoint_id is None:
            raise HandoffContractError("candidate requires input_point_id or endpoint_id")
        for value, label in (
            (self.input_point_id, "input_point_id"),
            (self.endpoint_id, "endpoint_id"),
            (self.feature_vector_id, "feature_vector_id"),
        ):
            if value is not None:
                _string(value, label)
        evidence = tuple(self.evidence)
        names = [item.feature_name for item in evidence]
        if (
            not evidence
            or any(type(item) is not CandidateEvidence for item in evidence)
            or names != sorted(set(names))
        ):
            raise HandoffContractError("candidate evidence is not canonical")
        if not any(item.observed for item in evidence):
            raise HandoffContractError("selected candidate has no observed evidence")
        if type(self.provenance) is not CandidateProvenance:
            raise HandoffContractError("candidate provenance is invalid")
        if category == CandidateCategory.INJECTION:
            if vulnerability not in {
                HandoffVulnerabilityType.SQLI,
                HandoffVulnerabilityType.REFLECTED_XSS,
            }:
                raise HandoffContractError("Injection candidate type is invalid")
            if (
                self.input_point_id is None
                or self.endpoint_id is None
                or self.feature_vector_id is None
                or type(self.injection_context) is not InjectionMutationContext
            ):
                raise HandoffContractError("Injection candidate context is incomplete")
            self.provenance.validate_injection()
        elif (
            vulnerability != HandoffVulnerabilityType.BROKEN_ACCESS_CONTROL
            or self.injection_context is not None
        ):
            raise HandoffContractError("BAC discriminator or context is invalid")
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "vulnerability_type", vulnerability)
        object.__setattr__(self, "raw_rank_score", raw_score)
        object.__setattr__(self, "raw_rank_score_max", maximum)
        object.__setattr__(self, "selection_priority", priority)
        object.__setattr__(self, "evidence", evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "category": self.category.value,
            "vulnerability_type": self.vulnerability_type.value,
            "rank": self.rank,
            "raw_rank_score": self.raw_rank_score,
            "raw_rank_score_max": self.raw_rank_score_max,
            "selection_priority": self.selection_priority,
            "input_point_id": self.input_point_id,
            "endpoint_id": self.endpoint_id,
            "scorer_version": self.scorer_version,
            "feature_vector_id": self.feature_vector_id,
            "evidence": [item.to_dict() for item in self.evidence],
            "provenance": self.provenance.to_dict(),
            "injection_context": (
                None
                if self.injection_context is None
                else self.injection_context.to_dict()
            ),
        }


def normalize_selected_candidates(
    crawl_artifact: Mapping[str, Any],
    analysis_artifact: Mapping[str, Any],
) -> tuple[NormalizedCandidate, ...]:
    """Resolve selected Injection candidates against exact artifact identities."""

    crawl = _mapping(crawl_artifact, "crawl artifact")
    analysis = _mapping(analysis_artifact, "analysis artifact")
    if crawl.get("report_kind") != "crawl":
        raise HandoffContractError("crawl artifact report_kind must be crawl")
    if analysis.get("report_kind") != "analysis":
        raise HandoffContractError("analysis artifact report_kind must be analysis")
    if crawl.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise HandoffContractError("crawl artifact schema_version is unsupported")
    if analysis.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise HandoffContractError("analysis artifact schema_version is unsupported")
    crawl_payload = _mapping(_required(crawl, "crawl", "crawl artifact"), "crawl")
    discovery = _mapping(
        _required(crawl_payload, "discovery", "crawl"),
        "crawl discovery",
    )
    if "context_registry" in discovery:
        raise HandoffContractError("context_registry is not a canonical artifact")
    if discovery.get("contract_version") != DISCOVERY_CONTRACT_VERSION:
        raise HandoffContractError("discovery contract_version is unsupported")
    discovery_snapshot_id = _validate_discovery_snapshot(discovery)
    endpoints = _index(discovery, "endpoints", "Endpoint")
    inputs = _index(discovery, "input_points", "InputPoint")
    templates = _index(discovery, "request_templates", "RequestTemplate")
    contexts = _index(
        discovery,
        "input_point_request_contexts",
        "InputPointRequestContext",
    )
    features = _index(analysis, "feature_vectors", "FeatureVector")
    feature_vectors = _feature_vectors(features)
    authoritative_results = _authoritative_scoring(feature_vectors)
    selection = _validate_authoritative_analysis(analysis, authoritative_results)
    discovery_run_id = _required_string(
        discovery,
        "discovery_run_id",
        "crawl discovery",
    )
    _validate_crawl_reference(
        analysis,
        discovery_run_id,
        discovery_snapshot_id,
        set(inputs),
    )
    _reject_credentials(discovery, analysis, templates, inputs)

    candidates = _records(analysis, "candidates", "analysis candidates")
    if len(candidates) != len(selection.selected):
        raise HandoffContractError("analysis selected candidate count is inconsistent")
    normalized: list[NormalizedCandidate] = []
    seen: set[str] = set()
    for expected_rank, (raw_candidate, authoritative) in enumerate(
        zip(candidates, selection.selected, strict=True),
        start=1,
    ):
        candidate = _mapping(raw_candidate, "candidate")
        if _required_int(candidate, "rank", "candidate") != expected_rank:
            raise HandoffContractError("candidate ranks are not deterministic")
        candidate_id = _required_string(candidate, "candidate_id", "candidate")
        if candidate_id in seen:
            raise HandoffContractError("candidate_id is duplicated")
        seen.add(candidate_id)
        expected_candidate_id = authoritative.scoring_result.candidate.id or ""
        if candidate_id != expected_candidate_id:
            raise HandoffContractError(
                "candidate order does not match authoritative selection"
            )
        normalized.append(
            _normalize_injection(
                candidate,
                authoritative=authoritative,
                analysis=analysis,
                discovery=discovery,
                discovery_run_id=discovery_run_id,
                discovery_snapshot_id=discovery_snapshot_id,
                endpoints=endpoints,
                inputs=inputs,
                templates=templates,
                contexts=contexts,
                features=features,
            )
        )
    return tuple(normalized)


def build_candidate_handoff(
    crawl_artifact: Mapping[str, Any],
    analysis_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Build deterministic derived data without writing a third artifact."""

    candidates = normalize_selected_candidates(crawl_artifact, analysis_artifact)
    return {
        "contract_version": INTERFACE_CONTRACT_VERSION,
        "source_artifacts": [
            "vulnspider-crawl.json",
            "vulnspider-analysis.json",
        ],
        "candidates": [candidate.to_dict() for candidate in candidates],
    }


def _normalize_injection(
    candidate: Mapping[str, Any],
    *,
    authoritative: RankedScoringResult,
    analysis: Mapping[str, Any],
    discovery: Mapping[str, Any],
    discovery_run_id: str,
    discovery_snapshot_id: str,
    endpoints: Mapping[str, Mapping[str, Any]],
    inputs: Mapping[str, Mapping[str, Any]],
    templates: Mapping[str, Mapping[str, Any]],
    contexts: Mapping[str, Mapping[str, Any]],
    features: Mapping[str, Mapping[str, Any]],
) -> NormalizedCandidate:
    candidate_id = _required_string(candidate, "candidate_id", "candidate")
    expected_scoring = authoritative.scoring_result
    if candidate_id != (expected_scoring.candidate.id or ""):
        raise HandoffContractError("candidate identity is not authoritative")
    vulnerability = _vulnerability(candidate.get("vulnerability_type"))
    if vulnerability not in {
        HandoffVulnerabilityType.SQLI,
        HandoffVulnerabilityType.REFLECTED_XSS,
    }:
        raise HandoffContractError("analysis artifact supports Injection only")
    input_id = _required_string(candidate, "input_point_id", "candidate")
    input_point = _resolve(inputs, input_id, "candidate input_point_id")
    endpoint_id = _required_string(input_point, "endpoint_id", "InputPoint")
    _resolve(endpoints, endpoint_id, "InputPoint endpoint_id")
    feature_id = _required_string(candidate, "feature_vector_id", "candidate")
    feature = _resolve(features, feature_id, "candidate feature_vector_id")
    if feature.get("input_point_id") != input_id:
        raise HandoffContractError("FeatureVector ownership mismatch")

    scoring = _one(
        analysis,
        "scoring_results",
        "ScoringResult",
        lambda item: item.get("candidate_id") == candidate_id,
    )
    _validate_scoring_record(scoring, expected_scoring)
    _validate_selected_candidate(candidate, authoritative)
    evidence = _evidence(candidate, candidate_id, feature_id, vulnerability)
    expected_evidence = _authoritative_evidence(expected_scoring)
    if not _evidence_equal(evidence, expected_evidence):
        raise HandoffContractError("candidate evidence is not authoritative")

    observation = _one(
        analysis,
        "probe_observations",
        "probe observation",
        lambda item: item.get("input_point_id") == input_id
        and item.get("feature_vector_id") == feature_id,
    )
    plan = _mapping(_required(observation, "probe_plan", "observation"), "ProbePlan")
    plan_id = _required_string(plan, "id", "ProbePlan")
    if plan.get("input_point_id") != input_id:
        raise HandoffContractError("ProbePlan InputPoint ownership mismatch")
    template_id = _required_string(plan, "request_template_id", "ProbePlan")
    context_id = _required_string(plan, "request_context_id", "ProbePlan")
    template = _resolve(templates, template_id, "ProbePlan request_template_id")
    context = _resolve(contexts, context_id, "ProbePlan request_context_id")
    if template.get("endpoint_id") != endpoint_id:
        raise HandoffContractError("RequestTemplate Endpoint ownership mismatch")
    if (
        context.get("input_point_id") != input_id
        or context.get("request_template_id") != template_id
    ):
        raise HandoffContractError("request context ownership mismatch")
    _require_ready(discovery, input_id, context_id)

    pair_ids = _ids(observation.get("response_pair_ids"), "response_pair_ids")
    if pair_ids != _ids(feature.get("probe_run_ids"), "FeatureVector probe_run_ids"):
        raise HandoffContractError("ResponsePair ownership mismatch")
    baseline_request = _mapping(
        _required(plan, "baseline_request", "ProbePlan"),
        "baseline request",
    )
    probe_request = _mapping(
        _required(plan, "probe_request", "ProbePlan"),
        "probe request",
    )
    baseline_response = _mapping(
        _required(observation, "baseline_response", "observation"),
        "baseline response",
    )
    probe_response = _mapping(
        _required(observation, "probe_response", "observation"),
        "probe response",
    )
    baseline_request_id = _required_string(baseline_request, "id", "baseline request")
    probe_request_id = _required_string(probe_request, "id", "probe request")
    _response_owner(
        baseline_response,
        role="baseline",
        plan_id=plan_id,
        request_id=baseline_request_id,
    )
    _response_owner(
        probe_response,
        role="probe",
        plan_id=plan_id,
        request_id=probe_request_id,
    )
    provenance_ids = _provenance_ids(
        discovery,
        discovery_run_id,
        {input_id, endpoint_id, template_id, context_id},
    )
    return NormalizedCandidate(
        candidate_id=candidate_id,
        category=CandidateCategory.INJECTION,
        vulnerability_type=vulnerability,
        rank=_required_int(candidate, "rank", "candidate"),
        raw_rank_score=authoritative.raw_rank_score,
        raw_rank_score_max=authoritative.raw_rank_score_max,
        selection_priority=authoritative.selection_priority,
        input_point_id=input_id,
        endpoint_id=endpoint_id,
        scorer_version=_required_string(candidate, "scorer_version", "candidate"),
        feature_vector_id=feature_id,
        evidence=evidence,
        provenance=CandidateProvenance(
            discovery_run_id=discovery_run_id,
            discovery_snapshot_id=discovery_snapshot_id,
            discovery_provenance_ids=provenance_ids,
            request_template_id=template_id,
            request_context_id=context_id,
            probe_plan_id=plan_id,
            response_pair_ids=pair_ids,
            baseline_request_id=baseline_request_id,
            probe_request_id=probe_request_id,
            baseline_response_id=_required_string(
                baseline_response,
                "id",
                "baseline response",
            ),
            probe_response_id=_required_string(
                probe_response,
                "id",
                "probe response",
            ),
        ),
        injection_context=_mutation_context(input_point, template, context_id),
    )


def _feature_vectors(
    records: Mapping[str, Mapping[str, Any]],
) -> dict[str, FeatureVector]:
    result: dict[str, FeatureVector] = {}
    for feature_id, record in records.items():
        observations: dict[str, FeatureObservation] = {}
        for raw in _records(record, "features", "FeatureVector features"):
            item = _mapping(raw, "FeatureObservation")
            name = _required_string(item, "name", "FeatureObservation")
            if name in observations:
                raise HandoffContractError("duplicate FeatureObservation name")
            observed = _required(item, "observed", "FeatureObservation")
            if type(observed) is not bool:
                raise HandoffContractError(
                    "FeatureObservation observed must be a boolean"
                )
            missing_reason = item.get("missing_reason")
            if missing_reason is not None and type(missing_reason) is not str:
                raise HandoffContractError(
                    "FeatureObservation missing_reason must be a string or null"
                )
            try:
                observations[name] = FeatureObservation(
                    name=name,
                    value=_required(item, "value", "FeatureObservation"),
                    observed=observed,
                    source=_required_string(item, "source", "FeatureObservation"),
                    extractor_version=_required_string(
                        item,
                        "extractor_version",
                        "FeatureObservation",
                    ),
                    details=(
                        {}
                        if missing_reason is None
                        else {"reason": missing_reason}
                    ),
                )
            except (TypeError, ValueError) as exc:
                raise HandoffContractError(
                    "FeatureObservation cannot be reconstructed"
                ) from exc
        probe_run_ids = _ids(record.get("probe_run_ids"), "FeatureVector probe_run_ids")
        if probe_run_ids != tuple(sorted(set(probe_run_ids))):
            raise HandoffContractError("FeatureVector probe_run_ids are not canonical")
        try:
            result[feature_id] = FeatureVector(
                input_point_id=_required_string(
                    record,
                    "input_point_id",
                    "FeatureVector",
                ),
                probe_run_ids=probe_run_ids,
                features=observations,
                feature_schema_version=_required_string(
                    record,
                    "feature_schema_version",
                    "FeatureVector",
                ),
                id=feature_id,
            )
        except (TypeError, ValueError) as exc:
            raise HandoffContractError("FeatureVector cannot be reconstructed") from exc
    return result


def _authoritative_scoring(
    feature_vectors: Mapping[str, FeatureVector],
) -> tuple[ScoringResult, ...]:
    result: list[ScoringResult] = []
    seen: set[str] = set()
    try:
        for vector in sorted(feature_vectors.values(), key=lambda item: item.id or ""):
            for scoring in generate_candidates(vector):
                candidate_id = scoring.candidate.id or ""
                if not candidate_id or candidate_id in seen:
                    raise HandoffContractError(
                        "authoritative scoring produced duplicate candidate identity"
                    )
                seen.add(candidate_id)
                result.append(scoring)
    except HandoffContractError:
        raise
    except (TypeError, ValueError) as exc:
        raise HandoffContractError(
            "FeatureVectors cannot be scored authoritatively"
        ) from exc
    return tuple(result)


def _validate_authoritative_analysis(
    analysis: Mapping[str, Any],
    authoritative_results: tuple[ScoringResult, ...],
) -> SelectionOutcome:
    summary = _mapping(
        _required(analysis, "summary", "analysis artifact"),
        "analysis summary",
    )
    top_k = _required_int(summary, "top_k_requested", "analysis summary")
    try:
        selection = select_top_k(authoritative_results, k=top_k)
    except (SelectionError, TypeError, ValueError) as exc:
        raise HandoffContractError("analysis cannot be selected authoritatively") from exc

    expected_summary = selection.summary
    for key in (
        "total_scoring_results",
        "rankable_results",
        "unrankable_results",
        "selected_results",
        "top_k_requested",
    ):
        if _required_int(summary, key, "analysis summary") != getattr(
            expected_summary,
            key,
        ):
            raise HandoffContractError(f"analysis summary {key} is inconsistent")

    policy = _mapping(
        _required(analysis, "ranking_policy", "analysis artifact"),
        "ranking policy",
    )
    if (
        policy.get("selection_key") != "rank_score / exact_scorer_maximum"
        or policy.get("tie_breaker") != "candidate_id ascending"
    ):
        raise HandoffContractError("analysis ranking_policy is unsupported")

    expected_by_id = {
        item.candidate.id or "": item for item in authoritative_results
    }
    records = _records(analysis, "scoring_results", "ScoringResult")
    if len(records) != len(expected_by_id):
        raise HandoffContractError("analysis ScoringResult count is inconsistent")
    seen: set[str] = set()
    for raw in records:
        record = _mapping(raw, "ScoringResult")
        candidate_id = _required_string(record, "candidate_id", "ScoringResult")
        if candidate_id in seen:
            raise HandoffContractError("duplicate ScoringResult candidate_id")
        seen.add(candidate_id)
        expected = expected_by_id.get(candidate_id)
        if expected is None:
            raise HandoffContractError("ScoringResult candidate is NOT_RESOLVED")
        _validate_scoring_record(record, expected)
    return selection


def _validate_scoring_record(
    record: Mapping[str, Any],
    expected: ScoringResult,
) -> None:
    candidate = expected.candidate
    expected_values = {
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": expected.feature_vector_id,
        "vulnerability_type": candidate.vulnerability_type.value,
        "scorer_version": candidate.scorer_version,
    }
    for key, value in expected_values.items():
        if record.get(key) != value:
            raise HandoffContractError(f"ScoringResult {key} is not authoritative")
    expected_score = candidate.rank_score
    if expected_score is None or not _numbers_equal(
        _number(record.get("rank_score"), "ScoringResult rank_score"),
        float(expected_score),
    ):
        raise HandoffContractError("ScoringResult rank_score is not authoritative")
    vulnerability = _vulnerability(candidate.vulnerability_type.value)
    actual_evidence = _evidence(
        record,
        candidate.id or "",
        expected.feature_vector_id,
        vulnerability,
    )
    expected_evidence = _authoritative_evidence(expected)
    if not _evidence_equal(actual_evidence, expected_evidence):
        raise HandoffContractError("ScoringResult evidence is not authoritative")
    contribution_sum = sum(
        item.contribution or 0.0 for item in actual_evidence
    )
    if not _numbers_equal(contribution_sum, float(expected_score)):
        raise HandoffContractError(
            "ScoringResult evidence contribution sum does not match rank_score"
        )


def _validate_selected_candidate(
    record: Mapping[str, Any],
    expected: RankedScoringResult,
) -> None:
    scoring = expected.scoring_result
    candidate = scoring.candidate
    expected_values = {
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": scoring.feature_vector_id,
        "vulnerability_type": candidate.vulnerability_type.value,
        "scorer_version": candidate.scorer_version,
    }
    for key, value in expected_values.items():
        if record.get(key) != value:
            raise HandoffContractError(f"selected candidate {key} is not authoritative")
    for key, actual, authoritative in (
        ("raw_rank_score", record.get("raw_rank_score"), expected.raw_rank_score),
        (
            "raw_rank_score_max",
            record.get("raw_rank_score_max"),
            expected.raw_rank_score_max,
        ),
        (
            "selection_priority",
            record.get("selection_priority"),
            expected.selection_priority,
        ),
    ):
        if not _numbers_equal(_number(actual, key), authoritative):
            raise HandoffContractError(f"selected candidate {key} is not authoritative")


def _authoritative_evidence(
    scoring: ScoringResult,
) -> tuple[CandidateEvidence, ...]:
    return tuple(
        CandidateEvidence(
            feature_name=item.feature_name,
            feature_value=item.feature_value,
            observed=item.observed,
            weight=item.weight,
            contribution=item.contribution,
            reason=item.reason,
        )
        for item in sorted(scoring.evidence, key=lambda item: item.feature_name)
    )


def _evidence_equal(
    actual: tuple[CandidateEvidence, ...],
    expected: tuple[CandidateEvidence, ...],
) -> bool:
    if len(actual) != len(expected):
        return False
    return all(
        left.feature_name == right.feature_name
        and left.observed is right.observed
        and left.reason == right.reason
        and _optional_numbers_equal(left.feature_value, right.feature_value)
        and _numbers_equal(left.weight, right.weight)
        and _optional_numbers_equal(left.contribution, right.contribution)
        for left, right in zip(actual, expected, strict=True)
    )


def _evidence(
    owner: Mapping[str, Any],
    candidate_id: str,
    feature_id: str,
    vulnerability: HandoffVulnerabilityType,
) -> tuple[CandidateEvidence, ...]:
    result: list[CandidateEvidence] = []
    for raw in _records(owner, "evidence", "candidate evidence"):
        item = _mapping(raw, "evidence")
        if (
            item.get("candidate_id") != candidate_id
            or item.get("feature_vector_id") != feature_id
            or item.get("vulnerability_type") != vulnerability.value
        ):
            raise HandoffContractError("evidence ownership mismatch")
        observed = item.get("observed")
        if type(observed) is not bool:
            raise HandoffContractError("evidence observed must be a boolean")
        result.append(
            CandidateEvidence(
                feature_name=_required_string(item, "feature_name", "evidence"),
                feature_value=_optional_number(item.get("feature_value")),
                observed=observed,
                weight=_number(item.get("weight"), "evidence weight"),
                contribution=_optional_number(item.get("contribution")),
                reason=_required_string(item, "reason", "evidence"),
            )
        )
    return tuple(result)


def _mutation_context(
    input_point: Mapping[str, Any],
    template: Mapping[str, Any],
    context_id: str,
) -> InjectionMutationContext:
    if _sensitive_input(input_point):
        raise HandoffContractError("credential InputPoint cannot enter handoff")
    name = _required_string(input_point, "name", "InputPoint")
    try:
        location = InputLocation(
            _required_string(input_point, "location", "InputPoint")
        )
        method = HttpMethod(_required_string(template, "method", "RequestTemplate"))
    except ValueError as exc:
        raise HandoffContractError("method or parameter location is invalid") from exc
    if location == InputLocation.QUERY:
        pairs = _pairs(template.get("query"), "query")
    elif location == InputLocation.FORM:
        pairs = _pairs(template.get("form"), "form")
    else:
        raise HandoffContractError("parameter location cannot be reconstructed safely")
    occurrence = input_point.get("occurrence_index")
    if occurrence is not None and (type(occurrence) is not int or occurrence < 0):
        raise HandoffContractError("InputPoint occurrence_index is invalid")
    values = [
        value
        for pair_name, value in pairs
        if normalize_parameter_name(pair_name) == name
    ]
    if occurrence is None:
        if len(values) != 1:
            raise HandoffContractError("InputPoint occurrence is ambiguous")
        original_value = values[0]
    elif occurrence >= len(values):
        raise HandoffContractError("InputPoint occurrence is NOT_RESOLVED")
    else:
        original_value = values[occurrence]
    if _contains_credential_material(original_value, field_name=name):
        raise HandoffContractError(
            "credential material cannot enter mutation context"
        )
    baseline = input_point.get("baseline_value")
    if baseline is not None and baseline != original_value:
        raise HandoffContractError("InputPoint baseline value is inconsistent")
    return InjectionMutationContext(
        request_template_id=_required_string(template, "id", "RequestTemplate"),
        request_context_id=context_id,
        method=method,
        url=_required_string(template, "url", "RequestTemplate"),
        parameter_name=name,
        parameter_location=location,
        parameter_occurrence=occurrence,
        original_value=original_value,
        auth_context_id=_optional_string(input_point.get("auth_context_id")),
    )


def _validate_crawl_reference(
    analysis: Mapping[str, Any],
    discovery_run_id: str,
    discovery_snapshot_id: str,
    input_ids: set[str],
) -> None:
    reference = _mapping(
        _required(analysis, "crawl_reference", "analysis artifact"),
        "crawl reference",
    )
    if reference.get("discovery_run_id") != discovery_run_id:
        raise HandoffContractError("analysis references a different discovery run")
    if reference.get("discovery_snapshot_id") != discovery_snapshot_id:
        raise HandoffContractError("analysis references a different discovery snapshot")
    referenced_input_ids = _ids(
        reference.get("input_point_ids"),
        "crawl input_point_ids",
    )
    if referenced_input_ids != tuple(sorted(input_ids)):
        raise HandoffContractError("analysis does not exactly reference crawl InputPoints")


def _validate_discovery_snapshot(discovery: Mapping[str, Any]) -> str:
    claimed = _required_string(
        discovery,
        "discovery_snapshot_id",
        "crawl discovery",
    )
    try:
        expected = discovery_snapshot_id_for(discovery)
    except DiscoveryContractError as exc:
        raise HandoffContractError("discovery snapshot cannot be calculated") from exc
    if claimed != expected:
        raise HandoffContractError("discovery snapshot does not match canonical content")
    return claimed


def _require_ready(
    discovery: Mapping[str, Any],
    input_id: str,
    context_id: str,
) -> None:
    readiness = _one(
        discovery,
        "probe_readiness",
        "ProbeReadiness",
        lambda item: item.get("input_point_id") == input_id
        and item.get("request_context_id") == context_id,
    )
    if readiness.get("status") != "READY":
        raise HandoffContractError("request context is not probe READY")


def _response_owner(
    response: Mapping[str, Any],
    *,
    role: str,
    plan_id: str,
    request_id: str,
) -> None:
    if (
        response.get("probe_plan_id") != plan_id
        or response.get("request_role") != role
        or response.get("request_id") != request_id
    ):
        raise HandoffContractError(f"{role} response provenance mismatch")


def _provenance_ids(
    discovery: Mapping[str, Any],
    discovery_run_id: str,
    subject_ids: set[str],
) -> tuple[str, ...]:
    covered: set[str] = set()
    result: list[str] = []
    for raw in _records(discovery, "crawl_provenance", "crawl provenance"):
        item = _mapping(raw, "DiscoveryProvenance")
        subject_id = item.get("subject_id")
        if subject_id not in subject_ids:
            continue
        if item.get("discovery_run_id") != discovery_run_id:
            raise HandoffContractError("discovery provenance run mismatch")
        covered.add(str(subject_id))
        result.append(_required_string(item, "id", "DiscoveryProvenance"))
    if covered != subject_ids:
        raise HandoffContractError("candidate discovery provenance is incomplete")
    return _canonical_ids(result, "discovery provenance IDs")


def _reject_credentials(
    discovery: Mapping[str, Any],
    analysis: Mapping[str, Any],
    templates: Mapping[str, Mapping[str, Any]],
    inputs: Mapping[str, Mapping[str, Any]],
) -> None:
    if "context_registry" in discovery:
        raise HandoffContractError("context_registry is not canonical")
    if _contains_credential_material(discovery) or _contains_credential_material(
        analysis
    ):
        raise HandoffContractError("canonical artifact contains raw credentials")
    for template in templates.values():
        _mapping(template.get("cookies"), "RequestTemplate cookies")
        _mapping(template.get("headers"), "RequestTemplate headers")
    for input_point in inputs.values():
        if _sensitive_input(input_point) and (
            input_point.get("baseline_value") is not None
            or input_point.get("baseline_values")
        ):
            raise HandoffContractError("canonical artifact contains a credential value")


def _sensitive_input(input_point: Mapping[str, Any]) -> bool:
    if str(input_point.get("type_hint", "")).lower() == "password":
        return True
    return _credential_field_name(input_point.get("name"))


def _one(
    owner: Mapping[str, Any],
    key: str,
    label: str,
    predicate: Any,
) -> Mapping[str, Any]:
    matches = [
        item
        for raw in _records(owner, key, label)
        if predicate(item := _mapping(raw, label))
    ]
    if len(matches) != 1:
        raise HandoffContractError(f"{label} is not uniquely resolved")
    return matches[0]


def _index(
    owner: Mapping[str, Any],
    key: str,
    label: str,
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for raw in _records(owner, key, label):
        item = _mapping(raw, label)
        item_id = _required_string(item, "id", label)
        if item_id in result:
            raise HandoffContractError(f"duplicate {label} id")
        result[item_id] = item
    return result


def _resolve(
    index: Mapping[str, Mapping[str, Any]],
    item_id: str,
    label: str,
) -> Mapping[str, Any]:
    try:
        return index[item_id]
    except KeyError as exc:
        raise HandoffContractError(f"{label} is NOT_RESOLVED") from exc


def _records(
    owner: Mapping[str, Any],
    key: str,
    label: str,
) -> tuple[object, ...]:
    value = _required(owner, key, label)
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise HandoffContractError(f"{label} must be a sequence")
    return tuple(value)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HandoffContractError(f"{label} must be a mapping")
    return value


def _required(owner: Mapping[str, Any], key: str, label: str) -> object:
    if key not in owner:
        raise HandoffContractError(f"{label} is missing required {key}")
    return owner[key]


def _required_string(owner: Mapping[str, Any], key: str, label: str) -> str:
    value = _required(owner, key, label)
    _string(value, f"{label} {key}")
    return value


def _required_int(owner: Mapping[str, Any], key: str, label: str) -> int:
    value = _required(owner, key, label)
    if type(value) is not int:
        raise HandoffContractError(f"{label} {key} must be an integer")
    return value


def _string(value: object, label: str) -> None:
    if type(value) is not str or not value:
        raise HandoffContractError(f"{label} must be a non-empty string")


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    _string(value, "optional identifier")
    return value


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise HandoffContractError(f"{label} must be numeric")
    result = float(value)
    if not isfinite(result):
        raise HandoffContractError(f"{label} must be finite")
    return result


def _numbers_equal(left: float, right: float) -> bool:
    return isclose(left, right, rel_tol=0.0, abs_tol=1e-12)


def _optional_numbers_equal(
    left: float | None,
    right: float | None,
) -> bool:
    if left is None or right is None:
        return left is right
    return _numbers_equal(left, right)


def _optional_number(value: object) -> float | None:
    return None if value is None else _number(value, "optional evidence value")


def _ids(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise HandoffContractError(f"{label} must be a sequence")
    result = tuple(value)
    if any(type(item) is not str or not item for item in result):
        raise HandoffContractError(f"{label} contains an invalid ID")
    return result


def _canonical_ids(value: Sequence[str], label: str) -> tuple[str, ...]:
    result = _ids(value, label)
    canonical = tuple(sorted(set(result)))
    if len(canonical) != len(result):
        raise HandoffContractError(f"{label} contains duplicate IDs")
    return canonical


def _pairs(value: object, label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise HandoffContractError(f"RequestTemplate {label} is invalid")
    result: list[tuple[str, str]] = []
    for pair in value:
        if (
            not isinstance(pair, Sequence)
            or isinstance(pair, str | bytes)
            or len(pair) != 2
            or type(pair[0]) is not str
            or type(pair[1]) is not str
        ):
            raise HandoffContractError(f"RequestTemplate {label} pair is invalid")
        result.append((pair[0], pair[1]))
    return tuple(result)


def _vulnerability(value: object) -> HandoffVulnerabilityType:
    if type(value) is not str:
        raise HandoffContractError("vulnerability_type must be a string")
    try:
        return HandoffVulnerabilityType(value)
    except ValueError as exc:
        raise HandoffContractError("vulnerability_type is invalid") from exc
