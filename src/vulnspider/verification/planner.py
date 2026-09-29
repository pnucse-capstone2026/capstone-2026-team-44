"""Plan a verification probe that injects one validated payload.

The baseline light probe (``observation.planner``) injects a neutral marker to
measure a candidate. Focused verification instead injects an *approved* variant
payload and re-extracts the same feature set, so the two feature vectors are
directly comparable.

This planner works from the already-executed baseline ``RequestInstance`` the
original ``ProbePlan`` retained, not from a ``RequestTemplate``: the
``AnalysisResult`` keeps the former, and building from it keeps this module
decoupled from discovery. It changes exactly one parameter value (the ADR-004
one-at-a-time invariant) and rebuilds both the baseline and probe URLs from the
same canonical pairs, so within the verification pair every non-target byte is
identical and any response difference is attributable to the payload alone.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit

from vulnspider.domain import (
    InputLocation,
    InputPoint,
    ParamPairs,
    ProbeFamily,
    ProbePlan,
    RequestInstance,
    normalize_parameter_name,
)
from vulnspider.verification.proposal import MutationFamily

# Map a mutation family to the probe family recorded on the ProbePlan. This is
# provenance only; it does not change how the payload is sent.
_PROBE_FAMILY_FOR_MUTATION: dict[MutationFamily, ProbeFamily] = {
    MutationFamily.HTML_SENTINEL: ProbeFamily.REFLECTION_MARKER,
    MutationFamily.SQL_META: ProbeFamily.GENERIC_PERTURBATION,
    MutationFamily.BOUNDARY: ProbeFamily.TYPE_PERTURBATION,
}


class VerificationPlanningError(ValueError):
    """Raised when a validated payload cannot be planned into a probe."""


def probe_family_for_mutation(family: MutationFamily) -> ProbeFamily:
    return _PROBE_FAMILY_FOR_MUTATION[MutationFamily(family)]


def plan_verification_probe(
    *,
    input_point: InputPoint,
    baseline_request: RequestInstance,
    injected_value: str,
    probe_marker: str | None,
    mutation_family: MutationFamily,
) -> ProbePlan:
    """Build a baseline/probe pair that injects ``injected_value`` at the target."""

    if not isinstance(input_point, InputPoint):
        raise VerificationPlanningError("input_point must be an InputPoint")
    if not isinstance(baseline_request, RequestInstance):
        raise VerificationPlanningError("baseline_request must be a RequestInstance")
    if not isinstance(injected_value, str):
        raise VerificationPlanningError("injected_value must be a string")

    location = input_point.location
    if location == InputLocation.QUERY:
        pairs = baseline_request.query
    elif location == InputLocation.FORM:
        pairs = baseline_request.form
    else:
        raise VerificationPlanningError(
            f"location {location.value} cannot be verification-probed"
        )

    pair_index = _target_pair_index(input_point, pairs)
    mutated_pairs = _replace_pair_value(pairs, pair_index, injected_value)

    if location == InputLocation.QUERY:
        baseline_query = pairs
        probe_query = mutated_pairs
        baseline_form = baseline_request.form
        probe_form = baseline_request.form
        baseline_url = _rebuild_query_url(baseline_request.url, baseline_query)
        probe_url = _rebuild_query_url(baseline_request.url, probe_query)
    else:
        baseline_query = baseline_request.query
        probe_query = baseline_request.query
        baseline_form = pairs
        probe_form = mutated_pairs
        baseline_url = baseline_request.url
        probe_url = baseline_request.url

    baseline_instance = RequestInstance(
        method=baseline_request.method,
        url=baseline_url,
        headers=dict(baseline_request.headers),
        query=baseline_query,
        form=baseline_form,
        cookies=dict(baseline_request.cookies),
    )
    probe_instance = RequestInstance(
        method=baseline_request.method,
        url=probe_url,
        headers=dict(baseline_request.headers),
        query=probe_query,
        form=probe_form,
        cookies=dict(baseline_request.cookies),
    )
    return ProbePlan(
        input_point_id=input_point.id or "",
        probe_family=probe_family_for_mutation(mutation_family),
        baseline_request=baseline_instance,
        probe_request=probe_instance,
        changed_fields=(_changed_field(input_point),),
        probe_marker=probe_marker,
        marker_strategy=None,
    )


def _target_pair_index(input_point: InputPoint, pairs: ParamPairs) -> int:
    matches = [
        index
        for index, (name, _value) in enumerate(pairs)
        if normalize_parameter_name(name) == input_point.name
    ]
    if not matches:
        raise VerificationPlanningError(
            "InputPoint target is missing from the baseline request"
        )
    if input_point.occurrence_index is None:
        if len(matches) != 1:
            raise VerificationPlanningError(
                "repeated target requires an occurrence-level InputPoint"
            )
        return matches[0]
    if input_point.occurrence_index >= len(matches):
        raise VerificationPlanningError("InputPoint occurrence_index is out of range")
    return matches[input_point.occurrence_index]


def _replace_pair_value(pairs: ParamPairs, pair_index: int, value: str) -> ParamPairs:
    return tuple(
        (name, value if index == pair_index else pair_value)
        for index, (name, pair_value) in enumerate(pairs)
    )


def _rebuild_query_url(url: str, pairs: ParamPairs) -> str:
    parts = urlsplit(url)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(pairs),
            parts.fragment,
        )
    )


def _changed_field(input_point: InputPoint) -> str:
    location = input_point.location.value.lower()
    if input_point.occurrence_index is None:
        return f"{location}.{input_point.name}"
    return f"{location}.{input_point.name}[{input_point.occurrence_index}]"
