"""Deterministic baseline and one-at-a-time probe request planning."""

from __future__ import annotations

import json
import math

from dataclasses import dataclass, field
from threading import Lock
from urllib.parse import (
    parse_qsl,
    quote,
    unquote_plus,
    urlencode,
    urlsplit,
    urlunsplit,
)

from vulnspider.domain import (
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ParamPairs,
    ProbeFamily,
    ProbePlan,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
    normalize_parameter_name,
    stable_fingerprint,
    validate_input_point_request_context,
)
from vulnspider.sensitive import credential_field_name

# The neutral strategy sends only the alphanumeric identifier token. The
# sentinel strategy appends four HTML-significant characters so the extractor can
# observe whether a reflection is entity-encoded (safe) or raw (dangerous) --
# the distinction the alphanumeric marker alone cannot make (ADR-031). The
# neutral strategy is retained so an old corpus reproduces byte-for-byte.
NEUTRAL_MARKER_STRATEGY = "neutral-reflection-marker-v1"
SENTINEL_MARKER_STRATEGY = "sentinel-reflection-marker-v1"
DEFAULT_MARKER_STRATEGY = SENTINEL_MARKER_STRATEGY
NUMERIC_ADJACENT_MARKER_STRATEGY = "numeric-adjacent-v1"
MARKER_PREFIX = "VULNSPIDER_"
MARKER_TOKEN_LENGTH = 16

# `<`, `>`, `"`, `'` bracketed by an alphanumeric `Z` delimiter. The delimiter
# survives entity-encoding, so the extractor can find the sentinel region even
# when its characters became `&lt;` etc. This is a reflection-context probe, not
# a script and not destructive: it does not carry an executable payload, it does
# not change server state, and ADR-004 (one-at-a-time) is preserved.
SENTINEL_CHARS = "<>\"'"
PROBE_SENTINEL = f"Z{SENTINEL_CHARS}Z"

RAW_QUERY_ALIGNMENT_FAILED = "raw-query-alignment-failed"
DEFAULT_POST_PROBE_PLAN_BUDGET = 4
POST_PROBE_PLAN_BUDGET_EXHAUSTED = "POST_PROBE_PLAN_BUDGET_EXHAUSTED"
POST_PROBE_PLAN_BUDGET_REQUIRED = "POST_PROBE_PLAN_BUDGET_REQUIRED"
POST_PROBE_SCALAR_TYPE_UNSUPPORTED = "POST_PROBE_SCALAR_TYPE_UNSUPPORTED"
POST_PROBE_NUMERIC_VALUE_NONFINITE = "POST_PROBE_NUMERIC_VALUE_NONFINITE"


class ProbePlanningError(ValueError):
    """Raised when a request context cannot safely produce a probe plan."""


@dataclass(frozen=True, slots=True)
class PostProbePlanningBudget:
    """Per-planner cap reserved before selective POST requests are built."""

    max_plans: int = DEFAULT_POST_PROBE_PLAN_BUDGET
    _planned_count: int = field(
        default=0,
        init=False,
        compare=False,
        repr=False,
    )
    _lock: Lock = field(
        default_factory=Lock,
        init=False,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self.max_plans) is not int or self.max_plans < 0:
            raise ValueError("POST probe plan budget must be a non-negative integer")

    @property
    def planned_count(self) -> int:
        with self._lock:
            return self._planned_count

    def try_reserve(self) -> bool:
        with self._lock:
            if self._planned_count >= self.max_plans:
                return False
            object.__setattr__(self, "_planned_count", self._planned_count + 1)
            return True


@dataclass(frozen=True, slots=True)
class ProbePlanner:
    probe_family: ProbeFamily = ProbeFamily.REFLECTION_MARKER
    marker_strategy: str = DEFAULT_MARKER_STRATEGY
    post_probe_budget: PostProbePlanningBudget = field(
        default_factory=PostProbePlanningBudget,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self.post_probe_budget) is not PostProbePlanningBudget:
            raise TypeError(
                "post_probe_budget must be a PostProbePlanningBudget"
            )

    def plan(
        self,
        input_point: InputPoint,
        request_template: RequestTemplate,
        request_context: InputPointRequestContext,
    ) -> ProbePlan:
        return plan_probe_request(
            input_point=input_point,
            request_template=request_template,
            request_context=request_context,
            probe_family=self.probe_family,
            marker_strategy=self.marker_strategy,
            post_probe_budget=self.post_probe_budget,
        )


def plan_probe_request(
    *,
    input_point: InputPoint,
    request_template: RequestTemplate,
    request_context: InputPointRequestContext,
    probe_family: ProbeFamily = ProbeFamily.REFLECTION_MARKER,
    marker_strategy: str = DEFAULT_MARKER_STRATEGY,
    post_probe_budget: PostProbePlanningBudget | None = None,
) -> ProbePlan:
    """Create baseline and probe requests for one selected validated context."""

    _validate_planning_inputs(input_point, request_template, request_context)
    _reject_non_probe_ready(input_point, request_template)

    target_pairs = _pairs_for_location(input_point.location, request_template)
    pair_index, baseline_value = _target_pair_index(input_point, target_pairs)
    selective_post_probe = _is_selective_post_probe(input_point, request_template)
    decoded_post_json_value: object = None
    marker_baseline_value = baseline_value
    if (
        selective_post_probe
        and input_point.location in {InputLocation.JSON, InputLocation.JSON_BODY}
    ):
        decoded_post_json_value = _decode_post_json_value(baseline_value)
        if type(decoded_post_json_value) is str:
            marker_baseline_value = decoded_post_json_value
    marker = deterministic_probe_marker(
        input_point=input_point,
        request_template=request_template,
        request_context=request_context,
        probe_family=probe_family,
        marker_strategy=marker_strategy,
        baseline_value=marker_baseline_value,
    )
    probe_marker: str | None = marker
    effective_marker_strategy = marker_strategy
    probe_query = request_template.execution_query
    probe_form = request_template.form
    probe_json_body = request_template.execution_json_body

    if input_point.location == InputLocation.QUERY:
        probe_query = _replace_pair_value(
            request_template.execution_query,
            pair_index,
            marker,
        )
    elif input_point.location == InputLocation.FORM:
        probe_form = _replace_pair_value(
            request_template.form,
            pair_index,
            marker,
        )
    elif input_point.location in {InputLocation.JSON, InputLocation.JSON_BODY}:
        if selective_post_probe:
            (
                encoded_marker,
                probe_marker,
                effective_marker_strategy,
            ) = _type_aware_post_json_probe_value(
                value=decoded_post_json_value,
                string_marker=marker,
                string_marker_strategy=marker_strategy,
            )
        else:
            # RequestTemplate.json_body stores each member value as canonical
            # JSON text, so a string marker must itself be JSON encoded.
            encoded_marker = json.dumps(
                marker,
                ensure_ascii=True,
                separators=(",", ":"),
            )
        probe_json_body = _replace_pair_value(
            request_template.execution_json_body,
            pair_index,
            encoded_marker,
        )
    else:
        raise ProbePlanningError(
            f"location {input_point.location.value} cannot be probed by planner"
        )

    if selective_post_probe:
        _validate_selective_post_preflight(
            input_point=input_point,
            request_template=request_template,
            probe_query=probe_query,
            probe_form=probe_form,
            probe_json_body=probe_json_body,
        )
        budget = post_probe_budget
        if budget is None:
            raise ProbePlanningError(POST_PROBE_PLAN_BUDGET_REQUIRED)
        if type(budget) is not PostProbePlanningBudget:
            raise TypeError(
                "post_probe_budget must be a PostProbePlanningBudget"
            )
        if not budget.try_reserve():
            raise ProbePlanningError(POST_PROBE_PLAN_BUDGET_EXHAUSTED)

    baseline_request = _request_instance_from_template(request_template)
    probe_request = RequestInstance(
        method=request_template.method,
        url=_probe_url(
            request_template,
            probe_query,
            changed_query_index=(
                pair_index if input_point.location == InputLocation.QUERY else None
            ),
            marker=marker,
        ),
        headers=request_template.headers,
        query=probe_query,
        form=probe_form,
        json_body=probe_json_body,
        cookies=request_template.cookies,
    )
    return ProbePlan(
        input_point_id=input_point.id or "",
        probe_family=probe_family,
        baseline_request=baseline_request,
        probe_request=probe_request,
        changed_fields=(_changed_field(input_point),),
        request_template_id=request_template.id,
        request_context_id=request_context.id,
        probe_marker=probe_marker,
        marker_strategy=effective_marker_strategy,
    )


def deterministic_probe_marker(
    *,
    input_point: InputPoint,
    request_template: RequestTemplate,
    request_context: InputPointRequestContext,
    probe_family: ProbeFamily = ProbeFamily.REFLECTION_MARKER,
    marker_strategy: str = DEFAULT_MARKER_STRATEGY,
    baseline_value: str | None = None,
) -> str:
    """Return a bounded neutral marker reproducible from planning inputs."""

    family = ProbeFamily(probe_family)
    for nonce in range(10):
        fingerprint = stable_fingerprint(
            "probe-marker",
            marker_strategy,
            family.value,
            input_point.id,
            request_template.id,
            request_context.id,
            input_point.location.value,
            input_point.name,
            input_point.occurrence_index,
            nonce,
        )
        identifier = f"{MARKER_PREFIX}{fingerprint[:MARKER_TOKEN_LENGTH].upper()}"
        candidate = (
            identifier + PROBE_SENTINEL
            if marker_strategy == SENTINEL_MARKER_STRATEGY
            else identifier
        )
        if identifier == baseline_value or candidate == baseline_value:
            continue
        return candidate
    raise ProbePlanningError("could not generate a marker distinct from baseline")


def marker_identifier(marker: str) -> str:
    """Return the alphanumeric identifier token, stripped of any sentinel.

    The identifier never contains ``Z`` (it is ``VULNSPIDER_`` plus uppercase
    hex), and the sentinel is introduced by a ``Z`` delimiter, so splitting on
    the first ``Z`` recovers the identifier for both marker strategies -- a
    neutral marker has no ``Z`` and is returned unchanged.
    """

    return marker.split("Z", 1)[0]


def _decode_post_json_value(encoded_value: str) -> object:
    try:
        return json.loads(encoded_value)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProbePlanningError("POST replay JSON scalar is invalid") from exc


def _type_aware_post_json_probe_value(
    *,
    value: object,
    string_marker: str,
    string_marker_strategy: str,
) -> tuple[str, str | None, str]:
    """Return one bounded scalar mutation without changing its JSON type."""

    if type(value) is str:
        return (
            json.dumps(
                string_marker,
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            string_marker,
            string_marker_strategy,
        )
    if type(value) is int:
        return (
            json.dumps(value + 1, separators=(",", ":")),
            None,
            NUMERIC_ADJACENT_MARKER_STRATEGY,
        )
    if type(value) is float:
        if not math.isfinite(value):
            raise ProbePlanningError(POST_PROBE_NUMERIC_VALUE_NONFINITE)
        probe_value = math.nextafter(value, math.inf)
        if not math.isfinite(probe_value):
            probe_value = math.nextafter(value, -math.inf)
        if not math.isfinite(probe_value) or probe_value == value:
            raise ProbePlanningError(POST_PROBE_NUMERIC_VALUE_NONFINITE)
        return (
            json.dumps(
                probe_value,
                allow_nan=False,
                separators=(",", ":"),
            ),
            None,
            NUMERIC_ADJACENT_MARKER_STRATEGY,
        )
    raise ProbePlanningError(POST_PROBE_SCALAR_TYPE_UNSUPPORTED)


def _validate_planning_inputs(
    input_point: InputPoint,
    request_template: RequestTemplate,
    request_context: InputPointRequestContext,
) -> None:
    if not isinstance(input_point, InputPoint):
        raise ProbePlanningError("input_point must be an InputPoint")
    if not isinstance(request_template, RequestTemplate):
        raise ProbePlanningError("request_template must be a RequestTemplate")
    if not isinstance(request_context, InputPointRequestContext):
        raise ProbePlanningError(
            "request_context must be an InputPointRequestContext"
        )
    if request_context.input_point_id != input_point.id:
        raise ProbePlanningError("request context does not target this InputPoint")
    if request_context.request_template_id != request_template.id:
        raise ProbePlanningError(
            "request context does not target this RequestTemplate"
        )
    if request_context.role != "baseline":
        raise ProbePlanningError("request context role must be baseline")
    try:
        validate_input_point_request_context(input_point, request_template)
    except ValueError as exc:
        raise ProbePlanningError(str(exc)) from exc


def _reject_non_probe_ready(
    input_point: InputPoint,
    request_template: RequestTemplate,
) -> None:
    reasons: list[str] = []
    if request_template.completeness != RequestContextCompleteness.COMPLETE:
        reasons.append(f"completeness={request_template.completeness.value}")

    metadata = request_template.metadata
    if _is_selective_post_probe(input_point, request_template):
        if metadata.get("context_kind") != "json_body":
            reasons.append("POST_REPLAY_CONTEXT_NOT_JSON_BODY")
        if input_point.location not in {
            InputLocation.JSON,
            InputLocation.JSON_BODY,
        }:
            reasons.append("POST_REPLAY_CONTEXT_NOT_JSON_BODY")
        if metadata.get("post_replay_disposition") != "SAFE_FOR_PROBE":
            reasons.append("POST_REPLAY_POLICY_NOT_SAFE")
        if request_template.ephemeral_material is None:
            reasons.append("POST_REPLAY_MATERIAL_MISSING")
    structured_reasons = metadata.get("non_probe_ready_reasons")
    if isinstance(structured_reasons, tuple | list):
        reasons.extend(str(reason) for reason in structured_reasons)
    elif structured_reasons:
        reasons.append(str(structured_reasons))

    reconstruction_status = metadata.get("reconstruction_status")
    if reconstruction_status in {"ambiguous", "partial"}:
        reasons.append(f"reconstruction_status={reconstruction_status}")

    form_boundary_status = metadata.get("form_boundary_status")
    if form_boundary_status == "unavailable":
        reasons.append("form_boundary_status=unavailable")

    for key in ("form_method_provenance", "form_action_provenance"):
        provenance = metadata.get(key)
        if isinstance(provenance, str) and provenance != "explicit":
            reasons.append(f"{key}={provenance}")

    if reasons:
        unique_reasons = tuple(dict.fromkeys(reasons))
        raise ProbePlanningError(
            "request context is not probe-ready: " + ", ".join(unique_reasons)
        )


def _is_selective_post_probe(
    input_point: InputPoint,
    request_template: RequestTemplate,
) -> bool:
    return (
        request_template.method == HttpMethod.POST
        and (
            input_point.location in {InputLocation.JSON, InputLocation.JSON_BODY}
            or request_template.metadata.get("context_kind") == "json_body"
            or bool(request_template.json_body)
        )
    )


def _validate_selective_post_preflight(
    *,
    input_point: InputPoint,
    request_template: RequestTemplate,
    probe_query: ParamPairs,
    probe_form: ParamPairs,
    probe_json_body: ParamPairs,
) -> None:
    material = request_template.ephemeral_material
    if material is None:
        raise ProbePlanningError("POST_REPLAY_MATERIAL_MISSING")

    structural_url = urlsplit(request_template.url)
    execution_url = urlsplit(material.url)
    structural_owner = (
        structural_url.scheme.lower(),
        structural_url.netloc.lower(),
        structural_url.path or "/",
    )
    execution_owner = (
        execution_url.scheme.lower(),
        execution_url.netloc.lower(),
        execution_url.path or "/",
    )
    if execution_owner != structural_owner or execution_url.fragment:
        raise ProbePlanningError("POST replay material owner mismatch")
    if (
        tuple(parse_qsl(execution_url.query, keep_blank_values=True))
        != material.query
    ):
        raise ProbePlanningError("POST replay URL/query material mismatch")
    if request_template.execution_url != material.url:
        raise ProbePlanningError("POST replay URL material mismatch")
    if request_template.execution_query != material.query:
        raise ProbePlanningError("POST replay query material mismatch")
    if request_template.execution_json_body != material.json_body:
        raise ProbePlanningError("POST replay JSON material mismatch")
    if probe_query != material.query or probe_form != request_template.form:
        raise ProbePlanningError("POST probe changed non-target request data")

    baseline_names = tuple(name for name, _value in material.json_body)
    probe_names = tuple(name for name, _value in probe_json_body)
    structural_names = tuple(
        name for name, _value in request_template.json_body
    )
    if tuple(sorted(baseline_names)) != tuple(sorted(structural_names)):
        raise ProbePlanningError(
            "POST replay material does not match structural members"
        )
    if probe_names != baseline_names:
        raise ProbePlanningError("POST probe changed JSON member set")
    if any(credential_field_name(name) for name in baseline_names):
        raise ProbePlanningError("POST probe targets sensitive JSON structure")

    changed_members = [
        name
        for (name, baseline_value), (probe_name, probe_value) in zip(
            material.json_body,
            probe_json_body,
            strict=True,
        )
        if name != probe_name or baseline_value != probe_value
    ]
    if changed_members != [input_point.name]:
        raise ProbePlanningError(
            "POST probe must change exactly its target JSON member"
        )


def _pairs_for_location(
    location: InputLocation,
    request_template: RequestTemplate,
) -> ParamPairs:
    if location == InputLocation.QUERY:
        return request_template.execution_query
    if location == InputLocation.FORM:
        return request_template.form
    if location in {InputLocation.JSON, InputLocation.JSON_BODY}:
        return request_template.execution_json_body
    raise ProbePlanningError(f"unsupported InputPoint location: {location.value}")


def _target_pair_index(
    input_point: InputPoint,
    pairs: ParamPairs,
) -> tuple[int, str]:
    matches = [
        (index, value)
        for index, (name, value) in enumerate(pairs)
        if normalize_parameter_name(name) == input_point.name
    ]
    if not matches:
        raise ProbePlanningError("InputPoint target is missing from RequestTemplate")

    if input_point.occurrence_index is None:
        if len(matches) != 1:
            raise ProbePlanningError(
                "repeated target requires an occurrence-level InputPoint"
            )
        return matches[0]

    if input_point.occurrence_index >= len(matches):
        raise ProbePlanningError("InputPoint occurrence_index is out of range")
    return matches[input_point.occurrence_index]


def _replace_pair_value(pairs: ParamPairs, pair_index: int, value: str) -> ParamPairs:
    return tuple(
        (name, value if index == pair_index else pair_value)
        for index, (name, pair_value) in enumerate(pairs)
    )


def _request_instance_from_template(request_template: RequestTemplate) -> RequestInstance:
    return RequestInstance(
        method=request_template.method,
        url=request_template.execution_url,
        headers=request_template.headers,
        query=request_template.execution_query,
        form=request_template.form,
        json_body=request_template.execution_json_body,
        cookies=request_template.cookies,
    )


def _probe_url(
    request_template: RequestTemplate,
    probe_query: ParamPairs,
    *,
    changed_query_index: int | None = None,
    marker: str | None = None,
) -> str:
    if request_template.execution_query == probe_query:
        return request_template.execution_url
    parts = urlsplit(request_template.execution_url)
    if changed_query_index is not None and marker is not None:
        raw_query = _replace_raw_query_value(
            raw_query=parts.query,
            original_query=request_template.execution_query,
            changed_query_index=changed_query_index,
            marker=marker,
        )
        if raw_query is not None:
            return urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    raw_query,
                    parts.fragment,
                )
            )
        if _url_has_raw_query(request_template.url):
            raise ProbePlanningError(RAW_QUERY_ALIGNMENT_FAILED)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(probe_query),
            parts.fragment,
        )
    )


def _replace_raw_query_value(
    *,
    raw_query: str,
    original_query: ParamPairs,
    changed_query_index: int,
    marker: str,
) -> str | None:
    raw_tokens = raw_query.split("&") if raw_query else []
    if len(raw_tokens) != len(original_query):
        return None

    decoded_pairs: list[tuple[str, str]] = []
    for token in raw_tokens:
        raw_name, raw_value = _split_raw_query_token(token)
        decoded_pairs.append((unquote_plus(raw_name), unquote_plus(raw_value)))
    if tuple(decoded_pairs) != original_query:
        return None

    mutated_tokens = list(raw_tokens)
    raw_name, _raw_value = _split_raw_query_token(mutated_tokens[changed_query_index])
    mutated_tokens[changed_query_index] = f"{raw_name}={quote(marker, safe='')}"
    return "&".join(mutated_tokens)


def _split_raw_query_token(token: str) -> tuple[str, str]:
    if "=" not in token:
        return token, ""
    raw_name, raw_value = token.split("=", 1)
    return raw_name, raw_value


def _url_has_raw_query(url: str) -> bool:
    return "?" in url.split("#", 1)[0]


def _changed_field(input_point: InputPoint) -> str:
    location = input_point.location.value.lower()
    if input_point.occurrence_index is None:
        return f"{location}.{input_point.name}"
    return f"{location}.{input_point.name}[{input_point.occurrence_index}]"
