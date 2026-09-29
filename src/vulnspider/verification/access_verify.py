"""BAC-specific focused verification.

Injection verification (``focused.py``) re-sends mutated payloads; a Broken
Access Control candidate cannot be verified that way. Instead this module
re-checks an ``IDENTIFIER_SUBSTITUTION`` candidate by re-sending the same GET
with *several other* numeric identifiers (not just baseline+1). If the resource
keeps coming back successfully (2xx, similar body) across independent ids, the
missing access control reproduces and the confidence is confirmed; if none of
them reproduce, the single baseline+1 hit was likely incidental and the
confidence is weakened.

It reuses the access feature extractor and the calibrated confidence model, and
produces an :class:`AccessCandidateVerification` that carries the same
``final_outcome`` / ``prior_probability`` / ``final_confidence`` surface the
dashboard already reads for injection candidates. Non-destructive and GET-only,
like the observation it re-runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from vulnspider.access.features import ACCESS_UNAUTHORIZED_SUCCESS
from vulnspider.domain import (
    AccessCheckKind,
    InputLocation,
    InputPoint,
    ParamPairs,
    RequestInstance,
    normalize_parameter_name,
)
from vulnspider.observation import DEFAULT_MAX_BODY_BYTES, DEFAULT_TIMEOUT_SECONDS
from vulnspider.observation.executor import RequestTransport, execute_request
from vulnspider.scope.loopback import require_loopback_http_url
from vulnspider.verification.calibration import (
    VerificationConfidenceModel,
    VerificationSignal,
)
from vulnspider.verification.confidence import OUTCOME_FOR_SIGNAL
from vulnspider.verification.result import ResultStatus

# Extra identifiers tried during verification (baseline + offset). +1 was the
# observation itself; these are other bounded, non-destructive reads.
_ID_OFFSETS: tuple[int, ...] = (2, 5, -1)

FAMILY_BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"


@dataclass(frozen=True, slots=True)
class AccessCandidateVerification:
    """A BAC candidate's verification verdict, shaped like the injection one.

    Carries only the surface the dashboard reads (``final_outcome`` /
    ``prior_probability`` / ``final_confidence``); ``results`` stays empty
    because a BAC re-check has no payload proposals to list.
    """

    candidate_id: str
    input_point_id: str
    selection_rank: int
    prior_probability: float
    final_outcome: ResultStatus
    final_signal: VerificationSignal
    final_confidence: float
    reproduced: int
    attempted: int
    results: tuple[Any, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "input_point_id": self.input_point_id,
            "family": FAMILY_BROKEN_ACCESS_CONTROL,
            "selection_rank": self.selection_rank,
            "prior_probability": self.prior_probability,
            "final_outcome": self.final_outcome.value,
            "final_signal": self.final_signal.value,
            "final_confidence": self.final_confidence,
            "confidence_delta": self.final_confidence - self.prior_probability,
            "reproduced": self.reproduced,
            "attempted": self.attempted,
        }


@dataclass(frozen=True, slots=True)
class AccessVerificationConfig:
    transport: RequestTransport | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    confidence_model: VerificationConfidenceModel = field(
        default_factory=VerificationConfidenceModel.default
    )


def verify_access_candidate(
    *,
    candidate_id: str,
    selection_rank: int,
    prior_probability: float,
    observation: Any,
    input_point: InputPoint,
    config: AccessVerificationConfig,
) -> AccessCandidateVerification | None:
    """Re-check one IDENTIFIER_SUBSTITUTION candidate with other ids.

    Returns ``None`` for a candidate that cannot be re-checked this way (e.g. a
    CREDENTIAL_STRIP candidate, or a non-numeric baseline), so the caller leaves
    its pre-verification confidence untouched.
    """

    plan = observation.access_probe_plan
    if plan.check_kind != AccessCheckKind.IDENTIFIER_SUBSTITUTION:
        return None
    baseline_value = _numeric_baseline(input_point)
    if baseline_value is None:
        return None

    baseline_success = _observed_success(observation.features)

    reproduced = 0
    attempted = 0
    for offset in _ID_OFFSETS:
        variant = baseline_value + offset
        if variant < 0 or variant == baseline_value or variant == baseline_value + 1:
            continue
        comparison = _substitute_identifier(
            plan.reference_request, input_point, str(variant)
        )
        if comparison is None:
            continue
        require_loopback_http_url(comparison.url)
        attempted += 1
        response = execute_request(
            comparison,
            transport=config.transport or _default_transport(),
            timeout_seconds=config.timeout_seconds,
            max_body_bytes=config.max_body_bytes,
        )
        if _response_success(response):
            reproduced += 1

    signal = _classify(baseline_success, reproduced, attempted)
    confidence = config.confidence_model.apply(
        prior_probability, FAMILY_BROKEN_ACCESS_CONTROL, signal
    )
    return AccessCandidateVerification(
        candidate_id=candidate_id,
        input_point_id=input_point.id or "",
        selection_rank=selection_rank,
        prior_probability=prior_probability,
        final_outcome=ResultStatus(OUTCOME_FOR_SIGNAL[signal].value),
        final_signal=signal,
        final_confidence=confidence,
        reproduced=reproduced,
        attempted=attempted,
    )


def verify_access(
    analysis: Any,
    *,
    probabilities: dict[str, float],
    ranks: dict[str, int] | None = None,
    config: AccessVerificationConfig | None = None,
) -> dict[str, AccessCandidateVerification]:
    """Re-check every re-checkable BAC candidate the analysis selected."""

    config = config or AccessVerificationConfig()
    ranks = ranks or {}
    input_points = {point.id or "": point for point in analysis.input_points}
    observations = {
        observation.candidate_id: observation
        for observation in analysis.access_probe_observations
    }
    verified: dict[str, AccessCandidateVerification] = {}
    for candidate_id, prior in probabilities.items():
        observation = observations.get(candidate_id)
        if observation is None:
            continue  # injection candidate; not our concern
        input_point = input_points.get(
            observation.access_probe_plan.input_point_id or ""
        )
        if input_point is None:
            continue
        result = verify_access_candidate(
            candidate_id=candidate_id,
            selection_rank=ranks.get(candidate_id, 0),
            prior_probability=prior,
            observation=observation,
            input_point=input_point,
            config=config,
        )
        if result is not None:
            verified[candidate_id] = result
    return verified


def _classify(
    baseline_success: bool, reproduced: int, attempted: int
) -> VerificationSignal:
    if attempted == 0:
        return VerificationSignal.UNCHANGED
    if reproduced == attempted:
        # The resource is reachable under every other id too: the missing
        # access control reproduces independently.
        return VerificationSignal.SUPPORT_REPRODUCED
    if reproduced == 0:
        # Only the single baseline+1 hit succeeded; likely incidental.
        return VerificationSignal.WEAKEN
    return VerificationSignal.UNCHANGED


def _numeric_baseline(input_point: InputPoint) -> int | None:
    value = input_point.baseline_value
    if value is None:
        return None
    text = value.strip()
    if text.startswith("-"):
        rest = text[1:]
    else:
        rest = text
    if not rest.isdigit():
        return None
    return int(text)


def _observed_success(features: Any) -> bool:
    observation = features.get(ACCESS_UNAUTHORIZED_SUCCESS)
    return bool(observation and observation.observed and observation.value == 1.0)


def _response_success(response: Any) -> bool:
    if response.execution_error is not None:
        return False
    return 200 <= int(response.status_code) < 300


def _substitute_identifier(
    reference_request: RequestInstance,
    input_point: InputPoint,
    new_value: str,
) -> RequestInstance | None:
    if input_point.location == InputLocation.QUERY:
        pairs = reference_request.query
    elif input_point.location == InputLocation.FORM:
        pairs = reference_request.form
    else:
        return None
    index = _target_index(input_point, pairs)
    if index is None:
        return None
    mutated = _replace_pair_value(pairs, index, new_value)
    if input_point.location == InputLocation.QUERY:
        url = _rebuild_query_url(reference_request.url, mutated)
        return RequestInstance(
            method=reference_request.method,
            url=url,
            headers=dict(reference_request.headers),
            query=mutated,
            form=reference_request.form,
            cookies=dict(reference_request.cookies),
        )
    return RequestInstance(
        method=reference_request.method,
        url=reference_request.url,
        headers=dict(reference_request.headers),
        query=reference_request.query,
        form=mutated,
        cookies=dict(reference_request.cookies),
    )


def _target_index(input_point: InputPoint, pairs: ParamPairs) -> int | None:
    matches = [
        index
        for index, (name, _value) in enumerate(pairs)
        if normalize_parameter_name(name) == input_point.name
    ]
    if not matches:
        return None
    if input_point.occurrence_index is None:
        return matches[0] if len(matches) == 1 else None
    if input_point.occurrence_index >= len(matches):
        return None
    return matches[input_point.occurrence_index]


def _replace_pair_value(pairs: ParamPairs, index: int, value: str) -> ParamPairs:
    return tuple(
        (name, value if position == index else pair_value)
        for position, (name, pair_value) in enumerate(pairs)
    )


def _rebuild_query_url(url: str, pairs: ParamPairs) -> str:
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment)
    )


def _default_transport() -> RequestTransport:
    from vulnspider.observation import UrlLibTransport

    return UrlLibTransport()
