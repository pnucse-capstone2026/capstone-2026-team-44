"""Typed domain objects for VulnSpider prototype v0.1."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from math import isfinite
from types import MappingProxyType
from typing import Any, TypeAlias
from urllib.parse import parse_qsl, urlsplit

JsonScalar: TypeAlias = float | bool | str | None
ParamPairs: TypeAlias = tuple[tuple[str, str], ...]
ParamInput: TypeAlias = Mapping[str, str] | Sequence[tuple[str, str]]


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


class InputLocation(StrEnum):
    QUERY = "QUERY"
    FORM = "FORM"
    JSON = "JSON"
    JSON_BODY = "JSON_BODY"
    PATH = "PATH"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    MULTIPART = "MULTIPART"


class ProbeFamily(StrEnum):
    REFLECTION_MARKER = "REFLECTION_MARKER"
    TYPE_PERTURBATION = "TYPE_PERTURBATION"
    GENERIC_PERTURBATION = "GENERIC_PERTURBATION"


class VulnerabilityType(StrEnum):
    SQLI = "SQLI"
    REFLECTED_XSS = "REFLECTED_XSS"


class RequestContextCompleteness(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


def _normalize_text(value: str | None) -> str:
    return (value or "").strip().lower()


def normalize_parameter_name(value: str | None) -> str:
    """Return the canonical InputPoint/request-parameter comparison name."""

    return _normalize_text(value)


def canonical_path(path: str) -> str:
    parsed = urlsplit(path)
    normalized = parsed.path or "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def _stable_value(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {
            str(key): _stable_value(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_stable_value(item) for item in value]
    if isinstance(value, float) and not isfinite(value):
        raise TypeError("non-finite floats are not stable JSON values")
    if value is None or isinstance(value, bool | int | float | str):
        return value
    raise TypeError(f"unsupported value for stable identity: {type(value).__name__}")


def _freeze_json_value(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise TypeError("feature details must not contain non-finite floats")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError("feature details mapping keys must be strings")
            frozen[key] = _freeze_json_value(value[key])
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return tuple(_freeze_json_value(item) for item in value)
    raise TypeError(
        f"feature details must be JSON-like, got {type(value).__name__}"
    )


def _freeze_json_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    frozen = _freeze_json_value(value)
    if not isinstance(frozen, Mapping):
        raise TypeError("feature details must be a mapping")
    return frozen


def _freeze_string_mapping(
    value: Mapping[str, str],
    *,
    label: str,
) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    frozen: dict[str, str] = {}
    for key, item in value.items():
        if type(key) is not str or type(item) is not str:
            raise TypeError(f"{label} keys and values must be strings")
        frozen[key] = item
    return MappingProxyType(frozen)


def stable_fingerprint(*parts: object) -> str:
    serialized = json.dumps(
        [_stable_value(part) for part in parts],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


def canonical_param_pairs(value: ParamInput | None) -> ParamPairs:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        return tuple(
            (str(key), str(param_value))
            for key, param_value in sorted(
                value.items(),
                key=lambda item: (str(item[0]), str(item[1])),
            )
        )
    if isinstance(value, str):
        raise ValueError("parameter pairs must not be a string")
    pairs: list[tuple[str, str]] = []
    for item in value:
        if len(item) != 2:
            raise ValueError("parameter pair must contain exactly two values")
        name, param_value = item
        pairs.append((str(name), str(param_value)))
    return tuple(pairs)


def canonical_value_tuple(values: Sequence[str] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    return tuple(str(value) for value in values)


@dataclass(frozen=True, slots=True)
class Endpoint:
    method: HttpMethod
    scheme: str
    host: str
    path: str
    content_type: str | None = None
    discovered_by: str = "unknown"
    id: str | None = None
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        method = HttpMethod(self.method)
        normalized_scheme = _normalize_text(self.scheme)
        normalized_host = _normalize_text(self.host)
        normalized_path = canonical_path(self.path)
        fingerprint = endpoint_fingerprint(
            method=method,
            scheme=normalized_scheme,
            host=normalized_host,
            path=normalized_path,
        )
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "scheme", normalized_scheme)
        object.__setattr__(self, "host", normalized_host)
        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "id", self.id or f"ep_{fingerprint[:16]}")


def endpoint_fingerprint(
    *,
    method: HttpMethod,
    scheme: str,
    host: str,
    path: str,
) -> str:
    return stable_fingerprint(
        "endpoint",
        HttpMethod(method).value,
        _normalize_text(scheme),
        _normalize_text(host),
        canonical_path(path),
    )


@dataclass(frozen=True, slots=True)
class InputPoint:
    endpoint_id: str
    endpoint_fingerprint: str
    location: InputLocation
    name: str
    occurrence_index: int | None = None
    baseline_value: str | None = None
    baseline_values: tuple[str, ...] = field(default_factory=tuple)
    type_hint: str | None = None
    source_page: str | None = None
    auth_context_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: str | None = None
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        location = InputLocation(self.location)
        normalized_name = normalize_parameter_name(self.name)
        if not normalized_name:
            raise ValueError("InputPoint.name must not be empty")
        if not self.endpoint_id:
            raise ValueError("InputPoint.endpoint_id must not be empty")
        if not self.endpoint_fingerprint:
            raise ValueError("InputPoint.endpoint_fingerprint must not be empty")
        occurrence_index = self.occurrence_index
        if occurrence_index is not None:
            occurrence_index = int(occurrence_index)
            if occurrence_index < 0:
                raise ValueError("InputPoint.occurrence_index must be non-negative")
        baseline_value = None if self.baseline_value is None else str(self.baseline_value)
        baseline_values = canonical_value_tuple(self.baseline_values)
        if not baseline_values and baseline_value is not None:
            baseline_values = (baseline_value,)
        if len(baseline_values) == 1 and baseline_value is None:
            baseline_value = baseline_values[0]
        if len(baseline_values) > 1 and baseline_value is not None:
            raise ValueError("multi-value InputPoint must not use baseline_value")
        fingerprint = input_point_fingerprint(
            endpoint_fingerprint=self.endpoint_fingerprint,
            location=location,
            name=normalized_name,
            auth_context_id=self.auth_context_id,
            occurrence_index=occurrence_index,
        )
        object.__setattr__(self, "location", location)
        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "occurrence_index", occurrence_index)
        object.__setattr__(self, "baseline_value", baseline_value)
        object.__setattr__(self, "baseline_values", baseline_values)
        object.__setattr__(self, "metadata", _freeze_json_mapping(self.metadata))
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "id", self.id or f"inp_{fingerprint[:16]}")


def input_point_fingerprint(
    *,
    endpoint_fingerprint: str,
    location: InputLocation,
    name: str,
    auth_context_id: str | None = None,
    occurrence_index: int | None = None,
) -> str:
    parts: list[object] = [
        "input-point",
        endpoint_fingerprint,
        InputLocation(location).value,
        normalize_parameter_name(name),
        _normalize_text(auth_context_id),
    ]
    if occurrence_index is not None:
        parts.extend(("occurrence", int(occurrence_index)))
    return stable_fingerprint(*parts)


@dataclass(frozen=True, slots=True, repr=False)
class EphemeralRequestMaterial:
    """Exact replay-only values excluded from canonical identity and artifacts."""

    url: str
    query: ParamInput = field(default_factory=tuple)
    json_body: ParamInput = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self.url) is not str or not self.url:
            raise ValueError("ephemeral request URL must not be empty")
        object.__setattr__(self, "query", canonical_param_pairs(self.query))
        object.__setattr__(self, "json_body", canonical_param_pairs(self.json_body))


@dataclass(frozen=True, slots=True)
class RequestTemplate:
    endpoint_id: str
    endpoint_fingerprint: str
    method: HttpMethod
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    query: ParamInput = field(default_factory=tuple)
    form: ParamInput = field(default_factory=tuple)
    cookies: Mapping[str, str] = field(default_factory=dict, repr=False)
    completeness: RequestContextCompleteness = RequestContextCompleteness.UNKNOWN
    context_key: str | None = None
    provenance: ParamInput = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: str | None = None
    json_body: ParamInput = field(default_factory=tuple)
    ephemeral_material: EphemeralRequestMaterial | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        method = HttpMethod(self.method)
        headers = _freeze_string_mapping(self.headers, label="request headers")
        query = canonical_param_pairs(self.query)
        form = canonical_param_pairs(self.form)
        json_body = canonical_param_pairs(self.json_body)
        cookies = _freeze_string_mapping(self.cookies, label="request cookies")
        completeness = RequestContextCompleteness(self.completeness)
        provenance = canonical_param_pairs(self.provenance)
        metadata = _freeze_json_mapping(self.metadata)
        ephemeral_material = self.ephemeral_material
        if ephemeral_material is not None and type(ephemeral_material) is not (
            EphemeralRequestMaterial
        ):
            raise TypeError(
                "RequestTemplate.ephemeral_material must be replay-only material"
            )
        if ephemeral_material is not None:
            if method != HttpMethod.POST:
                raise ValueError("ephemeral request material requires POST")
            structural_url = urlsplit(self.url)
            replay_url = urlsplit(ephemeral_material.url)
            structural_owner = (
                structural_url.scheme.lower(),
                structural_url.netloc.lower(),
                structural_url.path or "/",
            )
            replay_owner = (
                replay_url.scheme.lower(),
                replay_url.netloc.lower(),
                replay_url.path or "/",
            )
            if replay_owner != structural_owner or replay_url.fragment:
                raise ValueError(
                    "ephemeral request material escaped its structural URL owner"
                )
            replay_url_query = canonical_param_pairs(
                parse_qsl(replay_url.query, keep_blank_values=True)
            )
            if replay_url_query != ephemeral_material.query:
                raise ValueError(
                    "ephemeral request URL and query material do not align"
                )
            structural_query_names = tuple(
                sorted(normalize_parameter_name(name) for name, _ in query)
            )
            replay_query_names = tuple(
                sorted(
                    normalize_parameter_name(name)
                    for name, _ in ephemeral_material.query
                )
            )
            if replay_query_names != structural_query_names:
                raise ValueError(
                    "ephemeral request query does not match structural names"
                )
            structural_json_names = tuple(
                sorted(normalize_parameter_name(name) for name, _ in json_body)
            )
            replay_json_names = tuple(
                sorted(
                    normalize_parameter_name(name)
                    for name, _ in ephemeral_material.json_body
                )
            )
            if replay_json_names != structural_json_names:
                raise ValueError(
                    "ephemeral request JSON body does not match structural names"
                )
        fingerprint = stable_fingerprint(
            "request-template",
            self.endpoint_id,
            self.endpoint_fingerprint,
            method.value,
            self.url,
            tuple(sorted(headers.items())),
            query,
            form,
            json_body,
            tuple(sorted(cookies.items())),
            completeness.value,
            self.context_key,
            provenance,
        )
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "headers", headers)
        object.__setattr__(self, "query", query)
        object.__setattr__(self, "form", form)
        object.__setattr__(self, "json_body", json_body)
        object.__setattr__(self, "cookies", cookies)
        object.__setattr__(self, "completeness", completeness)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "ephemeral_material", ephemeral_material)
        object.__setattr__(self, "fingerprint", fingerprint)
        if not self.id:
            object.__setattr__(self, "id", f"rt_{fingerprint[:16]}")

    @property
    def execution_url(self) -> str:
        material = self.ephemeral_material
        return self.url if material is None else material.url

    @property
    def execution_query(self) -> ParamPairs:
        material = self.ephemeral_material
        return self.query if material is None else material.query

    @property
    def execution_json_body(self) -> ParamPairs:
        material = self.ephemeral_material
        return self.json_body if material is None else material.json_body


@dataclass(frozen=True, slots=True)
class RequestInstance:
    method: HttpMethod
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    query: ParamInput = field(default_factory=tuple)
    form: ParamInput = field(default_factory=tuple)
    cookies: dict[str, str] = field(default_factory=dict)
    id: str | None = None
    json_body: ParamInput = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", HttpMethod(self.method))
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "query", canonical_param_pairs(self.query))
        object.__setattr__(self, "form", canonical_param_pairs(self.form))
        object.__setattr__(self, "json_body", canonical_param_pairs(self.json_body))
        object.__setattr__(self, "cookies", dict(self.cookies))
        if not self.id:
            fingerprint = stable_fingerprint(
                "request-instance",
                self.method.value,
                self.url,
                tuple(sorted(self.headers.items())),
                self.query,
                self.form,
                self.json_body,
                tuple(sorted(self.cookies.items())),
            )
            object.__setattr__(self, "id", f"req_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True, init=False)
class InputPointRequestContext:
    input_point_id: str
    request_template_id: str
    role: str
    id: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "InputPointRequestContext must be created with from_objects()"
        )

    @classmethod
    def from_objects(
        cls,
        input_point: InputPoint,
        request_template: RequestTemplate,
        *,
        role: str = "baseline",
    ) -> InputPointRequestContext:
        if not isinstance(input_point, InputPoint):
            raise TypeError("input_point must be an InputPoint")
        if not isinstance(request_template, RequestTemplate):
            raise TypeError("request_template must be a RequestTemplate")
        validate_input_point_request_context(input_point, request_template)
        input_point_id = input_point.id or ""
        request_template_id = request_template.id or ""
        if not input_point_id:
            raise ValueError("input_point_id must not be empty")
        if not request_template_id:
            raise ValueError("request_template_id must not be empty")
        normalized_role = _normalize_text(role) or "baseline"
        fingerprint = stable_fingerprint(
            "input-point-request-context",
            input_point_id,
            request_template_id,
            normalized_role,
        )
        instance = object.__new__(cls)
        object.__setattr__(instance, "input_point_id", input_point_id)
        object.__setattr__(instance, "request_template_id", request_template_id)
        object.__setattr__(instance, "role", normalized_role)
        object.__setattr__(instance, "id", f"ipctx_{fingerprint[:16]}")
        return instance


def validate_input_point_request_context(
    input_point: InputPoint,
    request_template: RequestTemplate,
) -> None:
    if input_point.endpoint_id != request_template.endpoint_id:
        raise ValueError("InputPoint and RequestTemplate endpoint_id must match")

    if input_point.location == InputLocation.QUERY:
        pairs = request_template.query
    elif input_point.location == InputLocation.FORM:
        pairs = request_template.form
    elif input_point.location in {InputLocation.JSON, InputLocation.JSON_BODY}:
        pairs = request_template.json_body
    else:
        raise ValueError(
            f"InputPoint location {input_point.location.value} is not request-bindable"
        )

    matches = [
        value
        for name, value in pairs
        if normalize_parameter_name(name) == input_point.name
    ]
    if not matches:
        raise ValueError("InputPoint target is missing from RequestTemplate")

    if input_point.occurrence_index is None:
        if len(matches) != 1:
            raise ValueError(
                "repeated target requires an occurrence-level InputPoint"
            )
        if (
            input_point.baseline_value is not None
            and input_point.baseline_value != matches[0]
        ):
            raise ValueError(
                "InputPoint baseline_value does not match RequestTemplate target"
            )
        return

    if input_point.occurrence_index >= len(matches):
        raise ValueError("InputPoint occurrence_index is out of range")
    matched_value = matches[input_point.occurrence_index]
    if (
        input_point.baseline_value is not None
        and input_point.baseline_value != matched_value
    ):
        raise ValueError(
            "InputPoint baseline_value does not match RequestTemplate occurrence"
        )


@dataclass(frozen=True, slots=True)
class ProbePlan:
    input_point_id: str
    probe_family: ProbeFamily
    baseline_request: RequestInstance
    probe_request: RequestInstance
    changed_fields: tuple[str, ...]
    request_template_id: str | None = None
    request_context_id: str | None = None
    probe_marker: str | None = None
    marker_strategy: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        changed_fields = tuple(self.changed_fields)
        if len(changed_fields) != 1:
            raise ValueError("ProbePlan must change exactly one InputPoint")
        object.__setattr__(self, "probe_family", ProbeFamily(self.probe_family))
        object.__setattr__(self, "changed_fields", changed_fields)
        if not self.id:
            fingerprint = stable_fingerprint(
                "probe-plan",
                self.input_point_id,
                self.probe_family.value,
                self.request_template_id,
                self.request_context_id,
                self.probe_marker,
                self.marker_strategy,
                self.baseline_request.id,
                self.probe_request.id,
                changed_fields[0],
            )
            object.__setattr__(self, "id", f"probe_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ResponseSnapshot:
    request_id: str
    status_code: int
    elapsed_ms: float
    body_bytes_hash: str
    body_length_bytes: int
    headers: dict[str, str] = field(default_factory=dict)
    decoded_text: str | None = None
    encoding: str | None = None
    redirect_location: str | None = None
    execution_error: str | None = None
    probe_plan_id: str | None = None
    request_role: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", dict(self.headers))
        execution_error = None if self.execution_error is None else str(self.execution_error)
        probe_plan_id = None if self.probe_plan_id is None else str(self.probe_plan_id)
        request_role = None if self.request_role is None else str(self.request_role)
        object.__setattr__(self, "execution_error", execution_error)
        object.__setattr__(self, "probe_plan_id", probe_plan_id)
        object.__setattr__(self, "request_role", request_role)
        if not self.id:
            fingerprint = stable_fingerprint(
                "response-snapshot",
                probe_plan_id,
                request_role,
                self.request_id,
                self.status_code,
                self.body_bytes_hash,
                self.body_length_bytes,
                self.redirect_location,
                execution_error,
            )
            object.__setattr__(self, "id", f"resp_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ResponsePair:
    input_point_id: str
    probe_plan_id: str
    baseline_response_id: str
    probe_response_id: str
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            fingerprint = stable_fingerprint(
                "response-pair",
                self.input_point_id,
                self.probe_plan_id,
                self.baseline_response_id,
                self.probe_response_id,
            )
            object.__setattr__(self, "id", f"pair_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class FeatureObservation:
    name: str
    value: JsonScalar
    observed: bool
    source: str
    extractor_version: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.observed and self.value is not None:
            raise ValueError("unobserved features must use value=None")
        object.__setattr__(self, "details", _freeze_json_mapping(self.details))

    @classmethod
    def missing(
        cls,
        name: str,
        *,
        source: str,
        extractor_version: str,
        details: Mapping[str, Any] | None = None,
    ) -> FeatureObservation:
        return cls(
            name=name,
            value=None,
            observed=False,
            source=source,
            extractor_version=extractor_version,
            details=details or {},
        )


@dataclass(frozen=True, slots=True)
class FeatureVector:
    input_point_id: str
    probe_run_ids: tuple[str, ...]
    features: Mapping[str, FeatureObservation]
    feature_schema_version: str = "feature-v0.1"
    id: str | None = None

    def __post_init__(self) -> None:
        probe_run_ids = tuple(sorted(self.probe_run_ids))
        features = MappingProxyType(
            {
                str(name): observation
                for name, observation in sorted(self.features.items())
            }
        )
        feature_items = tuple(
            (
                name,
                observation.name,
                observation.value,
                observation.observed,
                observation.source,
                observation.extractor_version,
                observation.details,
            )
            for name, observation in sorted(features.items())
        )
        object.__setattr__(self, "probe_run_ids", probe_run_ids)
        object.__setattr__(self, "features", features)
        if not self.id:
            fingerprint = stable_fingerprint(
                "feature-vector",
                self.input_point_id,
                self.feature_schema_version,
                probe_run_ids,
                feature_items,
            )
            object.__setattr__(self, "id", f"fv_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class VulnerabilityCandidate:
    input_point_id: str
    vulnerability_type: VulnerabilityType
    rank_score: float | None = None
    scorer_version: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        vulnerability_type = VulnerabilityType(self.vulnerability_type)
        object.__setattr__(self, "vulnerability_type", vulnerability_type)
        if not self.id:
            fingerprint = stable_fingerprint(
                "candidate",
                self.input_point_id,
                vulnerability_type.value,
            )
            object.__setattr__(self, "id", f"cand_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ScoreEvidence:
    candidate_id: str
    feature_name: str
    feature_value: float | None
    weight: float
    contribution: float | None
    reason: str
    observed: bool = True
    vulnerability_type: VulnerabilityType | None = None
    feature_vector_id: str | None = None

    def __post_init__(self) -> None:
        vulnerability_type = (
            None
            if self.vulnerability_type is None
            else VulnerabilityType(self.vulnerability_type)
        )
        object.__setattr__(self, "vulnerability_type", vulnerability_type)
        if self.observed:
            if self.feature_value is None or self.contribution is None:
                raise ValueError(
                    "observed score evidence requires a value and contribution"
                )
        elif self.feature_value is not None or self.contribution is not None:
            raise ValueError(
                "unavailable score evidence must not fabricate a value or contribution"
            )
