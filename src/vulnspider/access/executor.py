"""Request execution for planned Broken Access Control (BAC) probes.

Reuses the exact same tested transport boundary and ``ResponseSnapshot``
construction (``vulnspider.observation.executor.execute_request``) as the
injection pipeline -- 4xx/5xx and transport failures are observations here
too, never discarded exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass

from vulnspider.domain import (
    ACCESS_REQUEST_ROLE_COMPARISON,
    ACCESS_REQUEST_ROLE_REFERENCE,
    AccessProbePlan,
    ResponseSnapshot,
)
from vulnspider.observation.executor import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    RequestTransport,
    execute_request,
)


class AccessRequestExecutionError(RuntimeError):
    """Raised when an AccessProbePlan cannot be executed validly."""


@dataclass(frozen=True, slots=True)
class AccessProbeExecutionResult:
    access_probe_plan_id: str
    reference_response: ResponseSnapshot
    comparison_response: ResponseSnapshot


def execute_access_plan(
    access_probe_plan: AccessProbePlan,
    *,
    transport: RequestTransport,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> AccessProbeExecutionResult:
    if not isinstance(access_probe_plan, AccessProbePlan):
        raise AccessRequestExecutionError(
            "access_probe_plan must be an AccessProbePlan"
        )
    plan_id = access_probe_plan.id or ""
    reference_response = execute_request(
        access_probe_plan.reference_request,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        probe_plan_id=plan_id,
        request_role=ACCESS_REQUEST_ROLE_REFERENCE,
    )
    comparison_response = execute_request(
        access_probe_plan.comparison_request,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        probe_plan_id=plan_id,
        request_role=ACCESS_REQUEST_ROLE_COMPARISON,
    )
    return AccessProbeExecutionResult(
        access_probe_plan_id=plan_id,
        reference_response=reference_response,
        comparison_response=comparison_response,
    )
