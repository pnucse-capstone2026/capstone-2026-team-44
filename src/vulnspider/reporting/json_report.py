"""Stable JSON reporting for deterministic v0.1 Top-K outcomes."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
import tempfile
from typing import Any

from vulnspider.domain import ScoreEvidence
from vulnspider.selection import (
    RankedScoringResult,
    SelectionError,
    SelectionOutcome,
)

REPORT_SCHEMA_VERSION = "0.1"


class ReportingError(ValueError):
    """Raised when a selection outcome cannot be emitted as strict JSON."""


def build_json_report(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    if not isinstance(outcome, SelectionOutcome):
        raise ReportingError("outcome must be a SelectionOutcome")
    try:
        outcome.validate()
    except SelectionError as exc:
        raise ReportingError("selection outcome is internally inconsistent") from exc
    summary = outcome.summary
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "ranking_policy": {
            "selection_key": "rank_score / exact_scorer_maximum",
            "tie_breaker": "candidate_id ascending",
        },
        "summary": {
            "total_scoring_results": summary.total_scoring_results,
            "rankable_results": summary.rankable_results,
            "unrankable_results": summary.unrankable_results,
            "selected_results": summary.selected_results,
            "top_k_requested": summary.top_k_requested,
        },
        "warnings": sorted(dict.fromkeys(str(item) for item in warnings)),
        "candidates": [
            _candidate_record(item, rank=rank)
            for rank, item in enumerate(outcome.selected, start=1)
        ],
    }


def render_json_report(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
) -> str:
    report = build_json_report(outcome, warnings=warnings)
    return render_json_document(report)


def render_json_document(report: Mapping[str, Any]) -> str:
    """Render an already-built report using the strict shared JSON policy."""

    if not isinstance(report, Mapping):
        raise ReportingError("report must be a mapping")
    try:
        return (
            json.dumps(
                report,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    except (TypeError, ValueError) as exc:
        raise ReportingError("report contains a non-finite or unsupported value") from exc


def write_json_report(
    outcome: SelectionOutcome,
    destination: str | Path,
    *,
    warnings: Sequence[str] = (),
) -> None:
    rendered = render_json_report(outcome, warnings=warnings)
    write_json_document(rendered, destination)


def write_json_document(rendered: str, destination: str | Path) -> None:
    """Atomically publish one fully rendered JSON document."""

    if type(rendered) is not str:
        raise ReportingError("rendered report must be a string")
    destination_path = Path(destination)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination_path.parent,
        prefix=f".{destination_path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="",
        ) as temporary_file:
            temporary_file.write(rendered)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, destination_path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    finally:
        temporary_path.unlink(missing_ok=True)


def _candidate_record(
    item: RankedScoringResult,
    *,
    rank: int,
) -> dict[str, Any]:
    result = item.scoring_result
    candidate = result.candidate
    return {
        "rank": rank,
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "vulnerability_type": candidate.vulnerability_type.value,
        "scorer_version": candidate.scorer_version,
        "raw_rank_score": item.raw_rank_score,
        "raw_rank_score_max": item.raw_rank_score_max,
        "selection_priority": item.selection_priority,
        "evidence": [
            score_evidence_record(evidence)
            for evidence in sorted(
                result.evidence,
                key=lambda evidence: evidence.feature_name,
            )
        ],
    }


def score_evidence_record(evidence: ScoreEvidence) -> dict[str, Any]:
    """Serialize existing authoritative score evidence consistently."""

    return {
        "candidate_id": evidence.candidate_id,
        "feature_vector_id": evidence.feature_vector_id,
        "vulnerability_type": (
            None
            if evidence.vulnerability_type is None
            else evidence.vulnerability_type.value
        ),
        "feature_name": evidence.feature_name,
        "feature_value": evidence.feature_value,
        "observed": evidence.observed,
        "weight": evidence.weight,
        "contribution": evidence.contribution,
        "reason": evidence.reason,
    }
