from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    AccessContext,
    NormalizedCandidate,
    RequestContext,
    VulnerabilityType,
)


def load_json(
    path: str | Path,
) -> dict[str, Any]:
    """
    UTF-8 BOM이 포함된 JSON도 읽을 수 있도록 utf-8-sig 사용.
    """

    return json.loads(
        Path(path).read_text(
            encoding="utf-8-sig"
        )
    )


def resolve_vulnerability_type(
    raw_candidate: dict[str, Any],
) -> VulnerabilityType:
    """
    후보마다 다른 유형 표현을 하나로 정규화한다.
    """

    vulnerability_type = raw_candidate.get(
        "vulnerability_type"
    )

    if vulnerability_type == "SQLI":
        return VulnerabilityType.SQLI

    if vulnerability_type == "REFLECTED_XSS":
        return VulnerabilityType.REFLECTED_XSS

    if (
        raw_candidate.get("category")
        == "BROKEN_ACCESS_CONTROL"
    ):
        return VulnerabilityType.BROKEN_ACCESS_CONTROL

    raise ValueError(
        "Unsupported candidate type: "
        f"{raw_candidate}"
    )


def normalize_evidence(
    raw_candidate: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    result.json evidence를 필요한 필드만 남겨 정리한다.
    """

    normalized: list[dict[str, Any]] = []

    for item in raw_candidate.get(
        "evidence",
        [],
    ):
        normalized.append(
            {
                "feature_name": item.get(
                    "feature_name"
                ),
                "feature_value": item.get(
                    "feature_value"
                ),
                "contribution": item.get(
                    "contribution"
                ),
                "weight": item.get(
                    "weight"
                ),
                "reason": item.get(
                    "reason"
                ),
                "observed": item.get(
                    "observed"
                ),
            }
        )

    return normalized


def normalize_candidate(
    raw_candidate: dict[str, Any],
    registry: dict[str, Any],
) -> NormalizedCandidate:
    """
    result.json 후보와 context_registry.json 문맥을 결합한다.
    """

    vulnerability_type = resolve_vulnerability_type(
        raw_candidate
    )

    input_point_id = raw_candidate.get(
        "input_point_id"
    )

    endpoint_id = raw_candidate.get(
        "endpoint_id"
    )

    request_context = None
    access_context = None

    if input_point_id:
        raw_request_context = (
            registry
            .get("input_points", {})
            .get(input_point_id)
        )

        if raw_request_context:
            request_context = RequestContext.model_validate(
                raw_request_context
            )

    if endpoint_id:
        raw_access_context = (
            registry
            .get("endpoints", {})
            .get(endpoint_id)
        )

        if raw_access_context:
            access_context = AccessContext.model_validate(
                raw_access_context
            )

    metadata = {
        "category": raw_candidate.get(
            "category"
        ),
        "check_kind": raw_candidate.get(
            "check_kind"
        ),
        "resource_reference": raw_candidate.get(
            "resource_reference"
        ),
        "resource_owner_context": raw_candidate.get(
            "resource_owner_context"
        ),
        "subject_context": raw_candidate.get(
            "subject_context"
        ),
        "scorer_version": raw_candidate.get(
            "scorer_version"
        ),
        "raw_rank_score_max": raw_candidate.get(
            "raw_rank_score_max"
        ),
    }

    return NormalizedCandidate(
        candidate_id=raw_candidate[
            "candidate_id"
        ],
        vulnerability_type=vulnerability_type,
        rank=raw_candidate.get(
            "rank",
            999999,
        ),
        raw_rank_score=raw_candidate.get(
            "raw_rank_score",
            0.0,
        ),
        selection_priority=raw_candidate.get(
            "selection_priority",
            0.0,
        ),
        input_point_id=input_point_id,
        endpoint_id=endpoint_id,
        evidence=normalize_evidence(
            raw_candidate
        ),
        request_context=request_context,
        access_context=access_context,
        metadata=metadata,
    )


def load_top_candidates(
    result_path: str | Path,
    registry_path: str | Path,
    top_k: int,
) -> list[NormalizedCandidate]:
    """
    rank 기준으로 상위 N개 후보를 읽는다.
    """

    result = load_json(
        result_path
    )

    registry = load_json(
        registry_path
    )

    raw_candidates = sorted(
        result.get(
            "candidates",
            [],
        ),
        key=lambda item: (
            item.get(
                "rank",
                999999,
            ),
            item.get(
                "candidate_id",
                "",
            ),
        ),
    )

    selected = raw_candidates[
        :top_k
    ]

    return [
        normalize_candidate(
            item,
            registry,
        )
        for item in selected
    ]
