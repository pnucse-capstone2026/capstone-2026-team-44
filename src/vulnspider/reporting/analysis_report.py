"""Authoritative analysis evidence reporting for the public simple CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnspider.discovery import discovery_snapshot_id_for
from vulnspider.domain import FeatureVector, ResponseSnapshot
from vulnspider.observation import RequestExecutionError, pair_probe_responses
from vulnspider.pipeline import AnalysisResult, ProbeObservation
from vulnspider.reporting.json_report import (
    ReportingError,
    build_json_report,
    render_json_document,
    score_evidence_record,
    write_json_document,
)
from vulnspider.scoring import ScoringResult
from vulnspider.selection import SelectionError, select_top_k


def build_analysis_report(analysis: AnalysisResult) -> dict[str, Any]:
    """Extend the existing Top-K report with retained probe provenance."""

    if type(analysis) is not AnalysisResult:
        raise ReportingError("analysis must be an AnalysisResult")
    discovery = analysis.discovery_result
    if discovery is None:
        raise ReportingError("simple analysis report requires native discovery")
    try:
        discovery.validate()
    except (TypeError, ValueError) as exc:
        raise ReportingError("analysis discovery failed revalidation") from exc

    input_point_ids = {item.id or "" for item in discovery.input_points}
    feature_vectors = _validated_feature_vectors(
        analysis.feature_vectors,
        input_point_ids=input_point_ids,
    )
    observations = _validated_probe_observations(
        analysis.probe_observations,
        input_point_ids=input_point_ids,
        feature_vectors=feature_vectors,
    )
    if {item.feature_vector_id for item in observations} != set(feature_vectors):
        raise ReportingError(
            "FeatureVectors and probe observations must have exact ownership"
        )
    scoring_results = _validated_scoring_results(
        analysis.scoring_results,
        input_point_ids=input_point_ids,
        feature_vectors=feature_vectors,
    )
    if {item.feature_vector_id for item in scoring_results} != set(feature_vectors):
        raise ReportingError(
            "FeatureVectors and scoring results must have exact ownership"
        )
    _validate_selection(analysis, scoring_results)
    discovery_snapshot_id = discovery_snapshot_id_for(discovery.to_dict())

    report = build_json_report(analysis.selection, warnings=analysis.warnings)
    report.update(
        {
            "report_kind": "analysis",
            "crawl_reference": {
                "discovery_run_id": discovery.discovery_run_id,
                "discovery_snapshot_id": discovery_snapshot_id,
                "collector_kind": discovery.discovery_metadata.collector_kind.value,
                "input_point_ids": sorted(input_point_ids),
            },
            "ready_context_ids": sorted(
                context.id for _point, _template, context in discovery.ready_contexts()
            ),
            "executed_input_point_ids": sorted(
                {item.input_point_id for item in observations}
            ),
            "probe_observations": [
                _probe_observation_record(item, feature_vectors)
                for item in observations
            ],
            "feature_vectors": [
                _feature_vector_record(item)
                for item in sorted(feature_vectors.values(), key=lambda value: value.id)
            ],
            "scoring_results": [
                _scoring_result_record(item) for item in scoring_results
            ],
        }
    )
    return report


def render_analysis_report(analysis: AnalysisResult) -> str:
    return render_json_document(build_analysis_report(analysis))


def write_analysis_report(
    analysis: AnalysisResult,
    destination: str | Path,
) -> None:
    write_json_document(render_analysis_report(analysis), destination)


def _validated_feature_vectors(
    values: tuple[FeatureVector, ...],
    *,
    input_point_ids: set[str],
) -> dict[str, FeatureVector]:
    result: dict[str, FeatureVector] = {}
    for item in values:
        if type(item) is not FeatureVector or not item.id:
            raise ReportingError("analysis contains an invalid FeatureVector")
        if item.input_point_id not in input_point_ids:
            raise ReportingError("FeatureVector references missing crawl InputPoint")
        if item.id in result:
            raise ReportingError("analysis contains duplicate FeatureVector ids")
        result[item.id] = item
    return result


def _validated_probe_observations(
    values: tuple[ProbeObservation, ...],
    *,
    input_point_ids: set[str],
    feature_vectors: dict[str, FeatureVector],
) -> tuple[ProbeObservation, ...]:
    result: list[ProbeObservation] = []
    seen_plans: set[str] = set()
    seen_response_pairs: set[str] = set()
    owned_response_pairs: dict[str, set[str]] = {}
    for item in values:
        if type(item) is not ProbeObservation:
            raise ReportingError("analysis contains an invalid ProbeObservation")
        vector = feature_vectors.get(item.feature_vector_id)
        if vector is None or vector.input_point_id != item.input_point_id:
            raise ReportingError("probe observation FeatureVector ownership mismatch")
        if item.input_point_id not in input_point_ids:
            raise ReportingError("probe observation references missing crawl InputPoint")
        plan_id = item.probe_plan.id or ""
        if not plan_id or plan_id in seen_plans:
            raise ReportingError("probe observations require unique ProbePlan ids")
        if item.probe_plan.input_point_id != item.input_point_id:
            raise ReportingError("ProbePlan InputPoint ownership mismatch")
        try:
            response_pair = pair_probe_responses(
                item.probe_plan,
                item.baseline_response,
                item.probe_response,
            )
        except RequestExecutionError as exc:
            raise ReportingError(
                "probe observation response pairing failed revalidation"
            ) from exc
        pair_id = response_pair.id or ""
        if pair_id not in vector.probe_run_ids:
            raise ReportingError("FeatureVector ResponsePair ownership mismatch")
        if pair_id in seen_response_pairs:
            raise ReportingError("probe observations require unique ResponsePair ids")
        seen_plans.add(plan_id)
        seen_response_pairs.add(pair_id)
        owned_response_pairs.setdefault(item.feature_vector_id, set()).add(pair_id)
        result.append(item)
    for vector_id, pair_ids in owned_response_pairs.items():
        if set(feature_vectors[vector_id].probe_run_ids) != pair_ids:
            raise ReportingError("FeatureVector ResponsePair ownership mismatch")
    return tuple(sorted(result, key=lambda value: value.probe_plan.id or ""))


def _validated_scoring_results(
    values: tuple[ScoringResult, ...],
    *,
    input_point_ids: set[str],
    feature_vectors: dict[str, FeatureVector],
) -> tuple[ScoringResult, ...]:
    result: list[ScoringResult] = []
    for item in values:
        if type(item) is not ScoringResult:
            raise ReportingError("analysis contains an invalid ScoringResult")
        vector = feature_vectors.get(item.feature_vector_id)
        if vector is None:
            raise ReportingError("ScoringResult references missing FeatureVector")
        if item.candidate.input_point_id not in input_point_ids:
            raise ReportingError("ScoringResult references missing crawl InputPoint")
        if item.candidate.input_point_id != vector.input_point_id:
            raise ReportingError("ScoringResult FeatureVector ownership mismatch")
        result.append(item)
    return tuple(
        sorted(
            result,
            key=lambda value: (
                value.candidate.input_point_id,
                value.candidate.vulnerability_type.value,
                value.candidate.id or "",
            ),
        )
    )


def _validate_selection(
    analysis: AnalysisResult,
    scoring_results: tuple[ScoringResult, ...],
) -> None:
    try:
        expected = select_top_k(
            scoring_results,
            k=analysis.selection.summary.top_k_requested,
        )
    except (SelectionError, TypeError, ValueError) as exc:
        raise ReportingError("analysis scoring results cannot be selected") from exc
    if analysis.selection != expected:
        raise ReportingError(
            "analysis selection does not match retained scoring results"
        )


def _probe_observation_record(
    observation: ProbeObservation,
    feature_vectors: dict[str, FeatureVector],
) -> dict[str, Any]:
    plan = observation.probe_plan
    vector = feature_vectors[observation.feature_vector_id]
    return {
        "input_point_id": observation.input_point_id,
        "feature_vector_id": observation.feature_vector_id,
        "response_pair_ids": list(vector.probe_run_ids),
        "probe_plan": {
            "id": plan.id,
            "input_point_id": plan.input_point_id,
            "probe_family": plan.probe_family.value,
            "request_template_id": plan.request_template_id,
            "request_context_id": plan.request_context_id,
            "changed_fields": list(plan.changed_fields),
            "marker_strategy": plan.marker_strategy,
            "baseline_request": {
                "id": plan.baseline_request.id,
                "method": plan.baseline_request.method.value,
            },
            "probe_request": {
                "id": plan.probe_request.id,
                "method": plan.probe_request.method.value,
            },
        },
        "baseline_response": _response_record(observation.baseline_response),
        "probe_response": _response_record(observation.probe_response),
    }


def _response_record(response: ResponseSnapshot) -> dict[str, Any]:
    return {
        "id": response.id,
        "request_id": response.request_id,
        "probe_plan_id": response.probe_plan_id,
        "request_role": response.request_role,
        "status_code": response.status_code,
        "elapsed_ms": response.elapsed_ms,
        "body_bytes_hash": response.body_bytes_hash,
        "body_length_bytes": response.body_length_bytes,
        "encoding": response.encoding,
        "execution_error": _safe_execution_error(response.execution_error),
    }


def _safe_execution_error(value: str | None) -> str | None:
    if value is None:
        return None
    if value in {"timeout", "body-capture-limit-reached"}:
        return value
    if value.startswith("transport-error:"):
        return "transport-error"
    return "execution-error"


def _feature_vector_record(vector: FeatureVector) -> dict[str, Any]:
    return {
        "id": vector.id,
        "input_point_id": vector.input_point_id,
        "probe_run_ids": list(vector.probe_run_ids),
        "feature_schema_version": vector.feature_schema_version,
        "features": [
            {
                "name": observation.name,
                "value": observation.value,
                "observed": observation.observed,
                "source": observation.source,
                "extractor_version": observation.extractor_version,
                "missing_reason": (
                    observation.details.get("reason")
                    if isinstance(observation.details.get("reason"), str)
                    else None
                ),
            }
            for _name, observation in sorted(vector.features.items())
        ],
    }


def _scoring_result_record(result: ScoringResult) -> dict[str, Any]:
    candidate = result.candidate
    return {
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "vulnerability_type": candidate.vulnerability_type.value,
        "rank_score": candidate.rank_score,
        "scorer_version": candidate.scorer_version,
        "evidence": [
            score_evidence_record(item)
            for item in sorted(result.evidence, key=lambda value: value.feature_name)
        ],
    }
