"""Versioned run-level contract for canonical discovery output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from vulnspider.domain import (
    Endpoint,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    RequestContextCompleteness,
    RequestTemplate,
    endpoint_fingerprint,
    input_point_fingerprint,
    stable_fingerprint,
    validate_input_point_request_context,
)

CONTRACT_VERSION = "canonical-discovery/1.0"
DISCOVERY_SNAPSHOT_VERSION = "canonical-discovery-snapshot/1.0"


class DiscoveryContractError(ValueError):
    """Raised when a discovery result violates the canonical handoff contract."""


class CollectorKind(StrEnum):
    NATIVE_STATIC = "NATIVE_STATIC"
    NATIVE_DYNAMIC = "NATIVE_DYNAMIC"
    NATIVE_COMBINED = "NATIVE_COMBINED"
    LEGACY_COMPATIBILITY = "LEGACY_COMPATIBILITY"


class DiscoverySafetyInvariant(StrEnum):
    SENSITIVE_FORM_PRE_CANONICAL_ELISION = (
        "SENSITIVE_FORM_PRE_CANONICAL_ELISION"
    )


class ProbeReadyStatus(StrEnum):
    READY = "READY"
    NOT_READY = "NOT_READY"


class NonProbeReadyReason(StrEnum):
    REQUEST_CONTEXT_MISSING = "REQUEST_CONTEXT_MISSING"
    REQUEST_CONTEXT_PARTIAL = "REQUEST_CONTEXT_PARTIAL"
    REQUEST_CONTEXT_UNKNOWN = "REQUEST_CONTEXT_UNKNOWN"
    FORM_BOUNDARY_UNAVAILABLE = "FORM_BOUNDARY_UNAVAILABLE"
    HIDDEN_INPUT_COMPLETENESS_UNKNOWN = "HIDDEN_INPUT_COMPLETENESS_UNKNOWN"
    METHOD_PROVENANCE_UNTRUSTED = "METHOD_PROVENANCE_UNTRUSTED"
    ACTION_PROVENANCE_UNTRUSTED = "ACTION_PROVENANCE_UNTRUSTED"
    RAW_QUERY_UNAVAILABLE = "RAW_QUERY_UNAVAILABLE"
    RAW_QUERY_ALIGNMENT_FAILED = "RAW_QUERY_ALIGNMENT_FAILED"
    UNSUPPORTED_INPUT_LOCATION = "UNSUPPORTED_INPUT_LOCATION"
    REQUEST_NOT_AUTHORIZED = "REQUEST_NOT_AUTHORIZED"
    POST_POLICY_STRUCTURAL_ONLY = "POST_POLICY_STRUCTURAL_ONLY"
    POST_POLICY_BLOCKED_SENSITIVE = "POST_POLICY_BLOCKED_SENSITIVE"
    POST_POLICY_ASSESSMENT_FAILED = "POST_POLICY_ASSESSMENT_FAILED"


class DiscoverySubjectKind(StrEnum):
    ENDPOINT = "ENDPOINT"
    INPUT_POINT = "INPUT_POINT"
    REQUEST_TEMPLATE = "REQUEST_TEMPLATE"
    REQUEST_CONTEXT = "REQUEST_CONTEXT"


JsonValue = str | int | float | bool | None | tuple["JsonValue", ...] | Mapping[str, "JsonValue"]

_BAC_DECISION_KEY_TOKENS = frozenset(
    {
        "confidence",
        "priority",
        "rank",
        "ranking",
        "score",
        "verdict",
    }
)


def _freeze_json(value: Any) -> JsonValue:
    if value is None or type(value) in {str, bool, int}:
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise DiscoveryContractError("contract metadata must use finite numbers")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, JsonValue] = {}
        for key in sorted(value):
            if type(key) is not str:
                raise DiscoveryContractError("contract metadata keys must be strings")
            frozen[key] = _freeze_json(value[key])
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return tuple(_freeze_json(item) for item in value)
    raise DiscoveryContractError(
        f"contract metadata contains unsupported object: {type(value).__name__}"
    )


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, JsonValue]:
    frozen = _freeze_json(value)
    if not isinstance(frozen, Mapping):
        raise DiscoveryContractError("contract details must be a mapping")
    return frozen


def _json_value(value: JsonValue) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_value(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def _validate_frozen_json(value: Any, *, label: str) -> None:
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float:
        if not isfinite(value):
            raise DiscoveryContractError(f"{label} must use finite numbers")
        return
    if type(value) is tuple:
        for item in value:
            _validate_frozen_json(item, label=label)
        return
    if type(value) is MappingProxyType:
        keys = tuple(value)
        if any(type(key) is not str for key in keys):
            raise DiscoveryContractError(f"{label} keys must be strings")
        if keys != tuple(sorted(keys)):
            raise DiscoveryContractError(f"{label} mapping order is not canonical")
        for item in value.values():
            _validate_frozen_json(item, label=label)
        return
    raise DiscoveryContractError(f"{label} must be an immutable JSON snapshot")


def _validate_bac_static_evidence(value: Any) -> None:
    if type(value) is MappingProxyType:
        for key, item in value.items():
            normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
            tokens = {token for token in normalized.split("_") if token}
            finding_decision = (
                "finding" in tokens
                and bool(
                    {"confirmed", "decision", "state", "status"}.intersection(
                        tokens
                    )
                )
            )
            scorer_maximum = (
                "scorer" in tokens
                and bool({"max", "maximum"}.intersection(tokens))
            )
            global_top_k = (
                "global" in tokens
                and "top" in tokens
                and "k" in tokens
            )
            if (
                _BAC_DECISION_KEY_TOKENS.intersection(tokens)
                or finding_decision
                or scorer_maximum
                or global_top_k
            ):
                raise DiscoveryContractError(
                    "BAC static hints must not contain scoring, ranking, "
                    "or decision fields"
                )
            _validate_bac_static_evidence(item)
    elif type(value) is tuple:
        for item in value:
            _validate_bac_static_evidence(item)


@dataclass(frozen=True, slots=True)
class DiscoveryMetadata:
    collector_kind: CollectorKind
    collector_version: str
    configuration_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "collector_kind", CollectorKind(self.collector_kind))
        self.validate()

    def validate(self) -> None:
        if type(self.collector_kind) is not CollectorKind:
            raise DiscoveryContractError("collector_kind must be canonical")
        if type(self.collector_version) is not str or not self.collector_version:
            raise DiscoveryContractError("collector_version must not be empty")
        if (
            type(self.configuration_fingerprint) is not str
            or not self.configuration_fingerprint
        ):
            raise DiscoveryContractError(
                "configuration_fingerprint must not be empty"
            )


@dataclass(frozen=True, slots=True)
class ScopeMetadata:
    target_scope_id: str
    root_url: str
    scope_policy_version: str
    scope_decision_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        try:
            refs = tuple(self.scope_decision_refs)
        except TypeError as exc:
            raise DiscoveryContractError(
                "scope_decision_refs must be an iterable of strings"
            ) from exc
        if any(type(item) is not str for item in refs):
            raise DiscoveryContractError(
                "scope_decision_refs must contain only strings"
            )
        object.__setattr__(self, "scope_decision_refs", tuple(sorted(refs)))
        self.validate()

    def validate(self) -> None:
        if type(self.target_scope_id) is not str or not self.target_scope_id:
            raise DiscoveryContractError("target_scope_id must not be empty")
        if type(self.root_url) is not str:
            raise DiscoveryContractError("root_url must be a string")
        parts = urlsplit(self.root_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise DiscoveryContractError("root_url must be an absolute HTTP(S) URL")
        if (
            type(self.scope_policy_version) is not str
            or not self.scope_policy_version
        ):
            raise DiscoveryContractError("scope_policy_version must not be empty")
        expected_scope_id = scope_id_for_root(
            self.root_url,
            policy_version=self.scope_policy_version,
        )
        if self.target_scope_id != expected_scope_id:
            raise DiscoveryContractError(
                "target_scope_id does not match root URL and scope policy"
            )
        if type(self.scope_decision_refs) is not tuple:
            raise DiscoveryContractError(
                "scope_decision_refs must be an immutable tuple"
            )
        if any(type(item) is not str for item in self.scope_decision_refs):
            raise DiscoveryContractError(
                "scope_decision_refs must contain only strings"
            )
        refs = self.scope_decision_refs
        if any(
            not item
            or item != item.strip()
            or any(character.isspace() for character in item)
            for item in refs
        ):
            raise DiscoveryContractError(
                "scope_decision_refs must be non-empty stable references"
            )
        if refs != tuple(sorted(refs)):
            raise DiscoveryContractError(
                "scope_decision_refs ordering is not canonical"
            )
        if len(refs) != len(set(refs)):
            raise DiscoveryContractError("scope_decision_refs must be unique")


@dataclass(frozen=True, slots=True)
class CrawlStatistics:
    requests_attempted: int = 0
    pages_processed: int = 0
    html_pages: int = 0
    links_discovered: int = 0
    forms_discovered: int = 0
    skipped: int = 0
    redirects_followed: int = 0
    max_depth_reached: int = 0
    request_budget: int = 0
    page_budget: int = 0
    depth_budget: int = 0
    elapsed_ms: float = 0.0
    endpoint_count: int = 0
    input_point_count: int = 0
    request_template_count: int = 0
    request_context_count: int = 0

    def validate(self) -> None:
        integer_values = (
            self.requests_attempted,
            self.pages_processed,
            self.html_pages,
            self.links_discovered,
            self.forms_discovered,
            self.skipped,
            self.redirects_followed,
            self.max_depth_reached,
            self.request_budget,
            self.page_budget,
            self.depth_budget,
            self.endpoint_count,
            self.input_point_count,
            self.request_template_count,
            self.request_context_count,
        )
        if any(type(value) is not int for value in integer_values):
            raise DiscoveryContractError(
                "crawl statistic counters and budgets must be integers"
            )
        if any(value < 0 for value in integer_values):
            raise DiscoveryContractError("crawl statistics must be non-negative")
        if type(self.elapsed_ms) not in {int, float}:
            raise DiscoveryContractError("elapsed_ms must be numeric")
        if not isfinite(self.elapsed_ms) or self.elapsed_ms < 0:
            raise DiscoveryContractError("elapsed_ms must be finite and non-negative")
        if self.request_budget and self.requests_attempted > self.request_budget:
            raise DiscoveryContractError("request budget was exceeded")
        if self.page_budget and self.pages_processed > self.page_budget:
            raise DiscoveryContractError("page budget was exceeded")
        if self.html_pages > self.pages_processed:
            raise DiscoveryContractError("HTML pages must not exceed processed pages")
        if self.max_depth_reached > self.depth_budget:
            raise DiscoveryContractError("depth budget was exceeded")


@dataclass(frozen=True, slots=True)
class DiscoveryProvenance:
    discovery_run_id: str
    subject_kind: DiscoverySubjectKind
    subject_id: str
    collector_kind: CollectorKind
    source_url: str
    collector_observation_key: str
    parent_url: str | None = None
    depth: int = 0
    id: str | None = None

    def __post_init__(self) -> None:
        subject_kind = DiscoverySubjectKind(self.subject_kind)
        collector_kind = CollectorKind(self.collector_kind)
        expected_id = self._expected_id(
            subject_kind=subject_kind,
            collector_kind=collector_kind,
        )
        if self.id is not None and self.id != expected_id:
            raise DiscoveryContractError("provenance id does not match its content")
        object.__setattr__(self, "subject_kind", subject_kind)
        object.__setattr__(self, "collector_kind", collector_kind)
        object.__setattr__(self, "id", expected_id)
        self.validate()

    def _expected_id(
        self,
        *,
        subject_kind: DiscoverySubjectKind | None = None,
        collector_kind: CollectorKind | None = None,
    ) -> str:
        fingerprint = stable_fingerprint(
            "discovery-provenance",
            self.discovery_run_id,
            (subject_kind or DiscoverySubjectKind(self.subject_kind)).value,
            self.subject_id,
            (collector_kind or CollectorKind(self.collector_kind)).value,
            self.source_url,
            self.parent_url,
            self.depth,
            self.collector_observation_key,
        )
        return f"prov_{fingerprint[:16]}"

    def validate_identity(self) -> None:
        if self.id != self._expected_id():
            raise DiscoveryContractError("provenance id does not match its content")

    def validate(self) -> None:
        if type(self.discovery_run_id) is not str or not self.discovery_run_id:
            raise DiscoveryContractError(
                "provenance discovery_run_id must not be empty"
            )
        if type(self.subject_kind) is not DiscoverySubjectKind:
            raise DiscoveryContractError("provenance subject_kind must be canonical")
        if type(self.subject_id) is not str or not self.subject_id:
            raise DiscoveryContractError("provenance subject_id must not be empty")
        if type(self.collector_kind) is not CollectorKind:
            raise DiscoveryContractError("provenance collector_kind must be canonical")
        if type(self.source_url) is not str or not self.source_url:
            raise DiscoveryContractError("provenance source_url must not be empty")
        if self.parent_url is not None and (
            type(self.parent_url) is not str or not self.parent_url
        ):
            raise DiscoveryContractError(
                "provenance parent_url must be a non-empty string"
            )
        if (
            type(self.collector_observation_key) is not str
            or not self.collector_observation_key
        ):
            raise DiscoveryContractError(
                "collector_observation_key must not be empty"
            )
        if type(self.depth) is not int or self.depth < 0:
            raise DiscoveryContractError(
                "provenance depth must be a non-negative integer"
            )
        self.validate_identity()


@dataclass(frozen=True, slots=True)
class ProbeReadiness:
    input_point_id: str
    request_context_id: str | None
    status: ProbeReadyStatus
    reasons: tuple[NonProbeReadyReason, ...] = field(default_factory=tuple)
    id: str | None = None

    def __post_init__(self) -> None:
        status = ProbeReadyStatus(self.status)
        reasons = tuple(
            sorted(
                (NonProbeReadyReason(reason) for reason in self.reasons),
                key=lambda item: item.value,
            )
        )
        if len(reasons) != len(set(reasons)):
            raise DiscoveryContractError("probe readiness reasons must be unique")
        if status == ProbeReadyStatus.READY:
            if self.request_context_id is None:
                raise DiscoveryContractError(
                    "probe-ready result requires a request context"
                )
            if reasons:
                raise DiscoveryContractError(
                    "probe-ready result must not contain reasons"
                )
        elif not reasons:
            raise DiscoveryContractError(
                "non-probe-ready result requires a reason"
            )
        expected_id = self._expected_id(status=status, reasons=reasons)
        if self.id is not None and self.id != expected_id:
            raise DiscoveryContractError("probe readiness id does not match its content")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reasons", reasons)
        object.__setattr__(self, "id", expected_id)
        self.validate()

    def _expected_id(
        self,
        *,
        status: ProbeReadyStatus | None = None,
        reasons: tuple[NonProbeReadyReason, ...] | None = None,
    ) -> str:
        current_status = status or ProbeReadyStatus(self.status)
        current_reasons = reasons
        if current_reasons is None:
            current_reasons = tuple(
                sorted(
                    (NonProbeReadyReason(reason) for reason in self.reasons),
                    key=lambda item: item.value,
                )
            )
        fingerprint = stable_fingerprint(
            "probe-readiness",
            self.input_point_id,
            self.request_context_id,
            current_status.value,
            tuple(reason.value for reason in current_reasons),
        )
        return f"ready_{fingerprint[:16]}"

    def validate_identity(self) -> None:
        if self.id != self._expected_id():
            raise DiscoveryContractError("probe readiness id does not match its content")

    def validate(self) -> None:
        if type(self.input_point_id) is not str or not self.input_point_id:
            raise DiscoveryContractError(
                "probe readiness input_point_id must not be empty"
            )
        if self.request_context_id is not None and (
            type(self.request_context_id) is not str or not self.request_context_id
        ):
            raise DiscoveryContractError(
                "probe readiness request_context_id must be a non-empty string"
            )
        if type(self.status) is not ProbeReadyStatus:
            raise DiscoveryContractError("probe readiness status must be canonical")
        if type(self.reasons) is not tuple or any(
            type(reason) is not NonProbeReadyReason for reason in self.reasons
        ):
            raise DiscoveryContractError(
                "probe readiness reasons must be an immutable canonical tuple"
            )
        ordered = tuple(sorted(self.reasons, key=lambda item: item.value))
        if self.reasons != ordered:
            raise DiscoveryContractError(
                "probe readiness reason ordering is not canonical"
            )
        if len(self.reasons) != len(set(self.reasons)):
            raise DiscoveryContractError("probe readiness reasons must be unique")
        if self.status == ProbeReadyStatus.READY:
            if self.request_context_id is None:
                raise DiscoveryContractError(
                    "probe-ready result requires a request context"
                )
            if self.reasons:
                raise DiscoveryContractError(
                    "probe-ready result must not contain reasons"
                )
        elif not self.reasons:
            raise DiscoveryContractError(
                "non-probe-ready result requires a reason"
            )
        self.validate_identity()


@dataclass(frozen=True, slots=True)
class DiscoveryWarning:
    code: str
    message: str
    subject_id: str | None = None
    provenance_id: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    id: str | None = None

    def __post_init__(self) -> None:
        details = _freeze_mapping(self.details)
        expected_id = self._expected_id(details=details)
        if self.id is not None and self.id != expected_id:
            raise DiscoveryContractError("warning id does not match its content")
        object.__setattr__(self, "details", details)
        object.__setattr__(self, "id", expected_id)
        self.validate()

    def _expected_id(self, *, details: Mapping[str, Any] | None = None) -> str:
        fingerprint = stable_fingerprint(
            "discovery-warning",
            self.code,
            self.subject_id,
            self.provenance_id,
            self.details if details is None else details,
        )
        return f"warn_{fingerprint[:16]}"

    def validate_identity(self) -> None:
        if self.id != self._expected_id():
            raise DiscoveryContractError("warning id does not match its content")

    def validate(self) -> None:
        if type(self.code) is not str or not self.code:
            raise DiscoveryContractError("warning code must not be empty")
        if type(self.message) is not str:
            raise DiscoveryContractError("warning message must be a string")
        if self.subject_id is not None and (
            type(self.subject_id) is not str or not self.subject_id
        ):
            raise DiscoveryContractError(
                "warning subject_id must be a non-empty string"
            )
        if self.provenance_id is not None and (
            type(self.provenance_id) is not str or not self.provenance_id
        ):
            raise DiscoveryContractError(
                "warning provenance_id must be a non-empty string"
            )
        _validate_frozen_json(self.details, label="warning details")
        self.validate_identity()


def _warning_sort_key(
    warning: DiscoveryWarning,
    *,
    collector_kind: CollectorKind,
    provenance_collectors: Mapping[str, CollectorKind],
) -> tuple[object, ...]:
    base_key: tuple[object, ...] = (
        warning.code,
        warning.subject_id or "",
        warning.provenance_id or "",
        warning.id or "",
    )
    if collector_kind != CollectorKind.NATIVE_COMBINED:
        return base_key
    producer: CollectorKind | None = None
    raw_producer = warning.details.get("producer_kind")
    if type(raw_producer) is str:
        try:
            producer = CollectorKind(raw_producer)
        except ValueError:
            producer = None
    if producer is None and warning.provenance_id is not None:
        producer = provenance_collectors.get(warning.provenance_id)
    producer_rank = {
        CollectorKind.NATIVE_STATIC: 0,
        CollectorKind.NATIVE_DYNAMIC: 1,
    }.get(producer, 2)
    return (producer_rank, *base_key)


@dataclass(frozen=True, slots=True)
class BACStaticHint:
    hint_kind: str
    source_subject_kind: DiscoverySubjectKind
    source_subject_id: str
    provenance_id: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    id: str | None = None

    def __post_init__(self) -> None:
        subject_kind = DiscoverySubjectKind(self.source_subject_kind)
        evidence = _freeze_mapping(self.evidence)
        expected_id = self._expected_id(
            subject_kind=subject_kind,
            evidence=evidence,
        )
        if self.id is not None and self.id != expected_id:
            raise DiscoveryContractError("BAC hint id does not match its content")
        object.__setattr__(self, "source_subject_kind", subject_kind)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "id", expected_id)
        self.validate()

    def _expected_id(
        self,
        *,
        subject_kind: DiscoverySubjectKind | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> str:
        fingerprint = stable_fingerprint(
            "bac-static-hint",
            self.hint_kind,
            (subject_kind or DiscoverySubjectKind(self.source_subject_kind)).value,
            self.source_subject_id,
            self.provenance_id,
            self.evidence if evidence is None else evidence,
        )
        return f"bachint_{fingerprint[:16]}"

    def validate_identity(self) -> None:
        if self.id != self._expected_id():
            raise DiscoveryContractError("BAC hint id does not match its content")

    def validate(self) -> None:
        if type(self.hint_kind) is not str or not self.hint_kind:
            raise DiscoveryContractError("BAC hint kind must not be empty")
        if type(self.source_subject_kind) is not DiscoverySubjectKind:
            raise DiscoveryContractError("BAC hint subject kind must be canonical")
        if type(self.source_subject_id) is not str or not self.source_subject_id:
            raise DiscoveryContractError(
                "BAC hint source_subject_id must not be empty"
            )
        if type(self.provenance_id) is not str or not self.provenance_id:
            raise DiscoveryContractError("BAC hint provenance_id must not be empty")
        _validate_frozen_json(self.evidence, label="BAC static evidence")
        _validate_bac_static_evidence(self.evidence)
        self.validate_identity()


def scope_id_for_root(root_url: str, *, policy_version: str) -> str:
    parts = urlsplit(root_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise DiscoveryContractError("root_url must be an absolute HTTP(S) URL")
    fingerprint = stable_fingerprint(
        "target-scope",
        parts.scheme.lower(),
        parts.hostname.lower() if parts.hostname else "",
        parts.port,
        policy_version,
    )
    return f"scope_{fingerprint[:16]}"


def discovery_run_id_for(
    metadata: DiscoveryMetadata,
    scope: ScopeMetadata,
) -> str:
    fingerprint = stable_fingerprint(
        "discovery-run",
        CONTRACT_VERSION,
        metadata.collector_kind.value,
        metadata.collector_version,
        metadata.configuration_fingerprint,
        scope.target_scope_id,
        scope.root_url,
        scope.scope_policy_version,
    )
    return f"discovery_{fingerprint[:16]}"


def discovery_snapshot_id_for(
    discovery_record: Mapping[str, Any],
) -> str:
    """Bind one deterministic canonical discovery serialization by content."""

    if not isinstance(discovery_record, Mapping):
        raise DiscoveryContractError("discovery snapshot input must be a mapping")
    content = {
        str(key): value
        for key, value in discovery_record.items()
        if key != "discovery_snapshot_id"
    }
    crawl_statistics = content.get("crawl_statistics")
    if isinstance(crawl_statistics, Mapping):
        content["crawl_statistics"] = {
            str(key): 0.0 if key == "elapsed_ms" else value
            for key, value in crawl_statistics.items()
        }
    try:
        fingerprint = stable_fingerprint(DISCOVERY_SNAPSHOT_VERSION, content)
    except TypeError as exc:
        raise DiscoveryContractError(
            "discovery snapshot contains unsupported content"
        ) from exc
    return f"dsnap_{fingerprint[:32]}"


@dataclass(frozen=True, slots=True)
class CanonicalDiscoveryResult:
    contract_version: str
    discovery_run_id: str
    discovery_metadata: DiscoveryMetadata
    scope_metadata: ScopeMetadata
    crawl_statistics: CrawlStatistics
    endpoints: tuple[Endpoint, ...]
    input_points: tuple[InputPoint, ...]
    request_templates: tuple[RequestTemplate, ...]
    input_point_request_contexts: tuple[InputPointRequestContext, ...]
    probe_readiness: tuple[ProbeReadiness, ...]
    crawl_provenance: tuple[DiscoveryProvenance, ...]
    bac_static_hints: tuple[BACStaticHint, ...]
    warnings: tuple[DiscoveryWarning, ...]
    safety_invariants: tuple[DiscoverySafetyInvariant, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        discovery_metadata: DiscoveryMetadata,
        scope_metadata: ScopeMetadata,
        crawl_statistics: CrawlStatistics,
        endpoints: Sequence[Endpoint] = (),
        input_points: Sequence[InputPoint] = (),
        request_templates: Sequence[RequestTemplate] = (),
        input_point_request_contexts: Sequence[InputPointRequestContext] = (),
        probe_readiness: Sequence[ProbeReadiness] = (),
        crawl_provenance: Sequence[DiscoveryProvenance] = (),
        bac_static_hints: Sequence[BACStaticHint] = (),
        warnings: Sequence[DiscoveryWarning] = (),
        safety_invariants: Sequence[DiscoverySafetyInvariant] = (),
    ) -> CanonicalDiscoveryResult:
        _require_type(discovery_metadata, DiscoveryMetadata, "discovery_metadata")
        _require_type(scope_metadata, ScopeMetadata, "scope_metadata")
        _require_type(crawl_statistics, CrawlStatistics, "crawl_statistics")
        typed_endpoints = _typed_items(endpoints, Endpoint, "Endpoint")
        typed_input_points = _typed_items(input_points, InputPoint, "InputPoint")
        typed_templates = _typed_items(
            request_templates,
            RequestTemplate,
            "RequestTemplate",
        )
        typed_contexts = _typed_items(
            input_point_request_contexts,
            InputPointRequestContext,
            "InputPointRequestContext",
        )
        typed_readiness = _typed_items(
            probe_readiness,
            ProbeReadiness,
            "ProbeReadiness",
        )
        typed_provenance = _typed_items(
            crawl_provenance,
            DiscoveryProvenance,
            "DiscoveryProvenance",
        )
        typed_hints = _typed_items(
            bac_static_hints,
            BACStaticHint,
            "BACStaticHint",
        )
        typed_warnings = _typed_items(
            warnings,
            DiscoveryWarning,
            "DiscoveryWarning",
        )
        try:
            typed_safety_invariants = tuple(
                DiscoverySafetyInvariant(item)
                for item in safety_invariants
            )
        except (TypeError, ValueError) as exc:
            raise DiscoveryContractError(
                "safety invariants must contain only known canonical values"
            ) from exc
        if len(typed_safety_invariants) != len(set(typed_safety_invariants)):
            raise DiscoveryContractError("safety invariants must be unique")
        typed_safety_invariants = tuple(
            sorted(typed_safety_invariants, key=lambda item: item.value)
        )
        provenance_collectors = {
            item.id or "": item.collector_kind for item in typed_provenance
        }
        result = cls(
            contract_version=CONTRACT_VERSION,
            discovery_run_id=discovery_run_id_for(
                discovery_metadata,
                scope_metadata,
            ),
            discovery_metadata=discovery_metadata,
            scope_metadata=scope_metadata,
            crawl_statistics=crawl_statistics,
            endpoints=tuple(
                sorted(
                    typed_endpoints,
                    key=lambda item: (item.fingerprint, item.id or ""),
                )
            ),
            input_points=tuple(
                sorted(
                    typed_input_points,
                    key=lambda item: (item.fingerprint, item.id or ""),
                )
            ),
            request_templates=tuple(
                sorted(
                    typed_templates,
                    key=lambda item: (item.fingerprint, item.id or ""),
                )
            ),
            input_point_request_contexts=tuple(
                sorted(
                    typed_contexts,
                    key=lambda item: (
                        item.input_point_id,
                        item.request_template_id,
                        item.role,
                        item.id,
                    ),
                )
            ),
            probe_readiness=tuple(
                sorted(
                    typed_readiness,
                    key=lambda item: (
                        item.input_point_id,
                        item.request_context_id or "",
                        item.status.value,
                        tuple(reason.value for reason in item.reasons),
                    ),
                )
            ),
            crawl_provenance=tuple(
                sorted(
                    typed_provenance,
                    key=lambda item: (
                        item.subject_kind.value,
                        item.subject_id,
                        item.collector_observation_key,
                        item.id or "",
                    ),
                )
            ),
            bac_static_hints=tuple(
                sorted(
                    typed_hints,
                    key=lambda item: (
                        item.hint_kind,
                        item.source_subject_kind.value,
                        item.source_subject_id,
                        item.id or "",
                    ),
                )
            ),
            warnings=tuple(
                sorted(
                    typed_warnings,
                    key=lambda item: _warning_sort_key(
                        item,
                        collector_kind=discovery_metadata.collector_kind,
                        provenance_collectors=provenance_collectors,
                    ),
                )
            ),
            safety_invariants=typed_safety_invariants,
        )
        result.validate()
        return result

    def validate(self) -> None:
        self._validate_types()
        self.discovery_metadata.validate()
        self.scope_metadata.validate()
        self.crawl_statistics.validate()
        self._validate_safety_invariants()
        if self.contract_version != CONTRACT_VERSION:
            raise DiscoveryContractError("unsupported discovery contract version")
        expected_run_id = discovery_run_id_for(
            self.discovery_metadata,
            self.scope_metadata,
        )
        if self.discovery_run_id != expected_run_id:
            raise DiscoveryContractError("discovery_run_id does not match metadata")
        self._validate_contract_owned_records()
        self._validate_ordering()
        endpoints = _unique_by_id(self.endpoints, "Endpoint")
        input_points = _unique_by_id(self.input_points, "InputPoint")
        templates = _unique_by_id(self.request_templates, "RequestTemplate")
        contexts = _unique_by_id(
            self.input_point_request_contexts,
            "InputPointRequestContext",
        )
        provenance = _unique_by_id(self.crawl_provenance, "DiscoveryProvenance")
        _unique_by_id(self.probe_readiness, "ProbeReadiness")
        _unique_by_id(self.bac_static_hints, "BACStaticHint")
        _unique_by_id(self.warnings, "DiscoveryWarning")

        self._validate_endpoints()
        self._validate_input_points(endpoints)
        self._validate_templates(endpoints)
        self._validate_contexts(input_points, templates)
        self._validate_readiness(input_points, contexts, templates)
        self._validate_provenance(
            endpoints,
            input_points,
            templates,
            contexts,
        )
        self._validate_hints(endpoints, input_points, templates, contexts, provenance)
        self._validate_warnings(
            endpoints,
            input_points,
            templates,
            contexts,
            provenance,
        )
        self._validate_counts()
        self._validate_metadata_values()

    def _validate_types(self) -> None:
        _require_type(
            self.discovery_metadata,
            DiscoveryMetadata,
            "discovery_metadata",
        )
        _require_type(self.scope_metadata, ScopeMetadata, "scope_metadata")
        _require_type(
            self.crawl_statistics,
            CrawlStatistics,
            "crawl_statistics",
        )
        _typed_items(self.endpoints, Endpoint, "Endpoint")
        _typed_items(self.input_points, InputPoint, "InputPoint")
        _typed_items(
            self.request_templates,
            RequestTemplate,
            "RequestTemplate",
        )
        _typed_items(
            self.input_point_request_contexts,
            InputPointRequestContext,
            "InputPointRequestContext",
        )
        _typed_items(self.probe_readiness, ProbeReadiness, "ProbeReadiness")
        _typed_items(
            self.crawl_provenance,
            DiscoveryProvenance,
            "DiscoveryProvenance",
        )
        _typed_items(self.bac_static_hints, BACStaticHint, "BACStaticHint")
        _typed_items(self.warnings, DiscoveryWarning, "DiscoveryWarning")

    def _validate_safety_invariants(self) -> None:
        if type(self.safety_invariants) is not tuple or any(
            type(item) is not DiscoverySafetyInvariant
            for item in self.safety_invariants
        ):
            raise DiscoveryContractError(
                "safety invariants must be an immutable canonical tuple"
            )
        ordered = tuple(
            sorted(self.safety_invariants, key=lambda item: item.value)
        )
        if self.safety_invariants != ordered:
            raise DiscoveryContractError(
                "safety invariant ordering is not canonical"
            )
        if len(self.safety_invariants) != len(set(self.safety_invariants)):
            raise DiscoveryContractError("safety invariants must be unique")

    def _validate_contract_owned_records(self) -> None:
        for item in self.probe_readiness:
            item.validate()
        for item in self.crawl_provenance:
            item.validate()
        for item in self.bac_static_hints:
            item.validate()
        for item in self.warnings:
            item.validate()

    def _validate_ordering(self) -> None:
        provenance_collectors = {
            item.id or "": item.collector_kind
            for item in self.crawl_provenance
        }
        checks = (
            (
                self.endpoints,
                tuple(
                    sorted(
                        self.endpoints,
                        key=lambda item: (item.fingerprint, item.id or ""),
                    )
                ),
            ),
            (
                self.input_points,
                tuple(
                    sorted(
                        self.input_points,
                        key=lambda item: (item.fingerprint, item.id or ""),
                    )
                ),
            ),
            (
                self.request_templates,
                tuple(
                    sorted(
                        self.request_templates,
                        key=lambda item: (item.fingerprint, item.id or ""),
                    )
                ),
            ),
            (
                self.input_point_request_contexts,
                tuple(
                    sorted(
                        self.input_point_request_contexts,
                        key=lambda item: (
                            item.input_point_id,
                            item.request_template_id,
                            item.role,
                            item.id,
                        ),
                    )
                ),
            ),
            (
                self.probe_readiness,
                tuple(
                    sorted(
                        self.probe_readiness,
                        key=lambda item: (
                            item.input_point_id,
                            item.request_context_id or "",
                            item.status.value,
                            tuple(reason.value for reason in item.reasons),
                        ),
                    )
                ),
            ),
            (
                self.crawl_provenance,
                tuple(
                    sorted(
                        self.crawl_provenance,
                        key=lambda item: (
                            item.subject_kind.value,
                            item.subject_id,
                            item.collector_observation_key,
                            item.id or "",
                        ),
                    )
                ),
            ),
            (
                self.bac_static_hints,
                tuple(
                    sorted(
                        self.bac_static_hints,
                        key=lambda item: (
                            item.hint_kind,
                            item.source_subject_kind.value,
                            item.source_subject_id,
                            item.id or "",
                        ),
                    )
                ),
            ),
            (
                self.warnings,
                tuple(
                    sorted(
                        self.warnings,
                        key=lambda item: _warning_sort_key(
                            item,
                            collector_kind=self.discovery_metadata.collector_kind,
                            provenance_collectors=provenance_collectors,
                        ),
                    )
                ),
            ),
        )
        if any(actual != ordered for actual, ordered in checks):
            raise DiscoveryContractError("discovery result ordering is not canonical")

    def _validate_endpoints(self) -> None:
        fingerprints: set[str] = set()
        for endpoint in self.endpoints:
            expected_fingerprint = endpoint_fingerprint(
                method=endpoint.method,
                scheme=endpoint.scheme,
                host=endpoint.host,
                path=endpoint.path,
            )
            if endpoint.fingerprint != expected_fingerprint:
                raise DiscoveryContractError("Endpoint fingerprint mismatch")
            if endpoint.id != f"ep_{expected_fingerprint[:16]}":
                raise DiscoveryContractError("Endpoint id does not match fingerprint")
            if endpoint.fingerprint in fingerprints:
                raise DiscoveryContractError("duplicate Endpoint stable identity")
            fingerprints.add(endpoint.fingerprint)

    def _validate_input_points(self, endpoints: Mapping[str, Endpoint]) -> None:
        fingerprints: set[str] = set()
        for point in self.input_points:
            endpoint = endpoints.get(point.endpoint_id)
            if endpoint is None:
                raise DiscoveryContractError("InputPoint references missing Endpoint")
            if point.endpoint_fingerprint != endpoint.fingerprint:
                raise DiscoveryContractError("InputPoint endpoint fingerprint mismatch")
            expected_fingerprint = input_point_fingerprint(
                endpoint_fingerprint=point.endpoint_fingerprint,
                location=point.location,
                name=point.name,
                auth_context_id=point.auth_context_id,
                occurrence_index=point.occurrence_index,
            )
            if point.fingerprint != expected_fingerprint:
                raise DiscoveryContractError("InputPoint fingerprint mismatch")
            if point.id != f"inp_{expected_fingerprint[:16]}":
                raise DiscoveryContractError("InputPoint id does not match fingerprint")
            if point.fingerprint in fingerprints:
                raise DiscoveryContractError("duplicate InputPoint stable identity")
            fingerprints.add(point.fingerprint)

    def _validate_templates(self, endpoints: Mapping[str, Endpoint]) -> None:
        fingerprints: set[str] = set()
        for template in self.request_templates:
            endpoint = endpoints.get(template.endpoint_id)
            if endpoint is None:
                raise DiscoveryContractError(
                    "RequestTemplate references missing Endpoint"
                )
            if template.endpoint_fingerprint != endpoint.fingerprint:
                raise DiscoveryContractError(
                    "RequestTemplate endpoint fingerprint mismatch"
                )
            parts = urlsplit(template.url)
            template_endpoint_fingerprint = endpoint_fingerprint(
                method=template.method,
                scheme=parts.scheme,
                host=parts.netloc,
                path=parts.path or "/",
            )
            if template_endpoint_fingerprint != endpoint.fingerprint:
                raise DiscoveryContractError(
                    "RequestTemplate URL/method ownership mismatch"
                )
            if template.id != f"rt_{template.fingerprint[:16]}":
                raise DiscoveryContractError(
                    "RequestTemplate id does not match fingerprint"
                )
            expected_fingerprint = stable_fingerprint(
                "request-template",
                template.endpoint_id,
                template.endpoint_fingerprint,
                template.method.value,
                template.url,
                tuple(sorted(template.headers.items())),
                template.query,
                template.form,
                template.json_body,
                tuple(sorted(template.cookies.items())),
                template.completeness.value,
                template.context_key,
                template.provenance,
            )
            if template.fingerprint != expected_fingerprint:
                raise DiscoveryContractError(
                    "RequestTemplate fingerprint does not match content"
                )
            if template.fingerprint in fingerprints:
                raise DiscoveryContractError(
                    "duplicate RequestTemplate stable identity"
                )
            fingerprints.add(template.fingerprint)

    def _validate_contexts(
        self,
        input_points: Mapping[str, InputPoint],
        templates: Mapping[str, RequestTemplate],
    ) -> None:
        for context in self.input_point_request_contexts:
            point = input_points.get(context.input_point_id)
            template = templates.get(context.request_template_id)
            if point is None or template is None:
                raise DiscoveryContractError(
                    "InputPointRequestContext references missing child"
                )
            expected_id = "ipctx_" + stable_fingerprint(
                "input-point-request-context",
                context.input_point_id,
                context.request_template_id,
                context.role,
            )[:16]
            if context.id != expected_id:
                raise DiscoveryContractError(
                    "InputPointRequestContext id does not match ownership"
                )
            try:
                validate_input_point_request_context(point, template)
            except ValueError as exc:
                raise DiscoveryContractError(
                    f"InputPointRequestContext ownership mismatch: {exc}"
                ) from exc

    def _validate_readiness(
        self,
        input_points: Mapping[str, InputPoint],
        contexts: Mapping[str, InputPointRequestContext],
        templates: Mapping[str, RequestTemplate],
    ) -> None:
        readiness_keys: set[tuple[str, str | None]] = set()
        for readiness in self.probe_readiness:
            if readiness.input_point_id not in input_points:
                raise DiscoveryContractError(
                    "ProbeReadiness references missing InputPoint"
                )
            key = (readiness.input_point_id, readiness.request_context_id)
            if key in readiness_keys:
                raise DiscoveryContractError("duplicate ProbeReadiness ownership")
            readiness_keys.add(key)
            if readiness.status == ProbeReadyStatus.READY:
                if readiness.request_context_id is None:
                    raise DiscoveryContractError(
                        "probe-ready result requires a request context"
                    )
                if readiness.reasons:
                    raise DiscoveryContractError(
                        "probe-ready result must not contain reasons"
                    )
                context = contexts.get(readiness.request_context_id)
                if context is None:
                    raise DiscoveryContractError(
                        "ProbeReadiness references missing request context"
                    )
                if context.input_point_id != readiness.input_point_id:
                    raise DiscoveryContractError(
                        "ProbeReadiness ownership does not match request context"
                    )
                template = templates[context.request_template_id]
                if template.completeness != RequestContextCompleteness.COMPLETE:
                    raise DiscoveryContractError(
                        "probe-ready result requires a complete request context"
                    )
                point = input_points[readiness.input_point_id]
                if point.location not in {
                    InputLocation.QUERY,
                    InputLocation.FORM,
                    InputLocation.JSON,
                    InputLocation.JSON_BODY,
                }:
                    raise DiscoveryContractError(
                        "unsupported InputPoint cannot be probe-ready"
                    )
                self._validate_ready_template(point, template)
            else:
                if not readiness.reasons:
                    raise DiscoveryContractError(
                        "non-probe-ready result requires a reason"
                    )
                if (
                    readiness.request_context_id is not None
                    and readiness.request_context_id not in contexts
                ):
                    raise DiscoveryContractError(
                        "ProbeReadiness references missing request context"
                    )
                if readiness.request_context_id is not None:
                    context = contexts[readiness.request_context_id]
                    if context.input_point_id != readiness.input_point_id:
                        raise DiscoveryContractError(
                            "ProbeReadiness ownership does not match request context"
                        )
        for context in contexts.values():
            key = (context.input_point_id, context.id)
            if key not in readiness_keys:
                raise DiscoveryContractError(
                    "request context is missing ProbeReadiness"
                )
        context_input_ids = {context.input_point_id for context in contexts.values()}
        for point in input_points.values():
            if point.id not in context_input_ids and (
                point.id,
                None,
            ) not in readiness_keys:
                raise DiscoveryContractError(
                    "InputPoint without context requires non-probe-ready status"
                )

    def _validate_ready_template(
        self,
        point: InputPoint,
        template: RequestTemplate,
    ) -> None:
        provenance_pairs = template.provenance
        provenance = dict(provenance_pairs)
        if len(provenance) != len(provenance_pairs):
            raise DiscoveryContractError(
                "probe-ready template provenance keys must be unique"
            )
        if point.location == InputLocation.QUERY:
            if provenance.get("query") != "raw-url":
                raise DiscoveryContractError(
                    "probe-ready query requires trusted raw query provenance"
                )
            raw_query = urlsplit(template.url).query
            if template.query and not raw_query:
                raise DiscoveryContractError(
                    "probe-ready query requires authoritative raw query"
                )
            decoded = tuple(parse_qsl(raw_query, keep_blank_values=True))
            if decoded != template.query:
                raise DiscoveryContractError(
                    "probe-ready raw query does not align with request template"
                )
            return
        if point.location in {InputLocation.JSON, InputLocation.JSON_BODY}:
            if template.method.value != "POST":
                raise DiscoveryContractError(
                    "probe-ready JSON body requires POST request template"
                )
            if provenance.get("json_body") != "browser-request-body":
                raise DiscoveryContractError(
                    "probe-ready JSON body requires trusted browser body provenance"
                )
            if template.metadata.get("content_type") != "application/json":
                raise DiscoveryContractError(
                    "probe-ready JSON body requires application/json content type"
                )
            if not template.json_body:
                raise DiscoveryContractError(
                    "probe-ready JSON body requires structural member bindings"
                )
            if (
                template.metadata.get("post_replay_disposition")
                != "SAFE_FOR_PROBE"
            ):
                raise DiscoveryContractError(
                    "probe-ready JSON body requires safe POST replay policy"
                )
            if template.ephemeral_material is None:
                raise DiscoveryContractError(
                    "probe-ready JSON body requires ephemeral replay material"
                )
            return
        if provenance.get("form_method") not in {"explicit", "html_default_get"}:
            raise DiscoveryContractError(
                "probe-ready form method provenance is not trusted"
            )
        if provenance.get("form_action") not in {
            "explicit",
            "html_default_current_document",
        }:
            raise DiscoveryContractError(
                "probe-ready form action provenance is not trusted"
            )
        if provenance.get("form_boundary") != "stable":
            raise DiscoveryContractError(
                "probe-ready form requires stable boundary provenance"
            )
        if provenance.get("form_controls") != "complete":
            raise DiscoveryContractError(
                "probe-ready form requires complete control provenance"
            )
        if template.metadata.get("form_boundary_status") != "stable":
            raise DiscoveryContractError(
                "probe-ready form requires a stable form boundary"
            )
        if (
            template.metadata.get("hidden_input_policy")
            != "native_all_successful_controls_preserved"
        ):
            raise DiscoveryContractError(
                "probe-ready form requires complete hidden-input evidence"
            )

    def _validate_provenance(
        self,
        endpoints: Mapping[str, Endpoint],
        input_points: Mapping[str, InputPoint],
        templates: Mapping[str, RequestTemplate],
        contexts: Mapping[str, InputPointRequestContext],
    ) -> None:
        subject_maps: dict[DiscoverySubjectKind, Mapping[str, object]] = {
            DiscoverySubjectKind.ENDPOINT: endpoints,
            DiscoverySubjectKind.INPUT_POINT: input_points,
            DiscoverySubjectKind.REQUEST_TEMPLATE: templates,
            DiscoverySubjectKind.REQUEST_CONTEXT: contexts,
        }
        covered: set[tuple[DiscoverySubjectKind, str]] = set()
        for item in self.crawl_provenance:
            if item.discovery_run_id != self.discovery_run_id:
                raise DiscoveryContractError(
                    "provenance does not belong to this discovery run"
                )
            if (
                self.discovery_metadata.collector_kind
                == CollectorKind.NATIVE_COMBINED
            ):
                if item.collector_kind not in {
                    CollectorKind.NATIVE_STATIC,
                    CollectorKind.NATIVE_DYNAMIC,
                }:
                    raise DiscoveryContractError(
                        "aggregate provenance uses an unsupported collector kind"
                    )
            elif item.collector_kind != self.discovery_metadata.collector_kind:
                raise DiscoveryContractError(
                    "provenance collector kind does not match discovery metadata"
                )
            if item.subject_id not in subject_maps[item.subject_kind]:
                raise DiscoveryContractError(
                    "DiscoveryProvenance references missing subject"
                )
            covered.add((item.subject_kind, item.subject_id))
        for kind, subjects in subject_maps.items():
            for subject_id in subjects:
                if (kind, subject_id) not in covered:
                    raise DiscoveryContractError(
                        f"{kind.value} is missing discovery provenance"
                    )

    def _validate_hints(
        self,
        endpoints: Mapping[str, Endpoint],
        input_points: Mapping[str, InputPoint],
        templates: Mapping[str, RequestTemplate],
        contexts: Mapping[str, InputPointRequestContext],
        provenance: Mapping[str, DiscoveryProvenance],
    ) -> None:
        subject_maps: dict[DiscoverySubjectKind, Mapping[str, object]] = {
            DiscoverySubjectKind.ENDPOINT: endpoints,
            DiscoverySubjectKind.INPUT_POINT: input_points,
            DiscoverySubjectKind.REQUEST_TEMPLATE: templates,
            DiscoverySubjectKind.REQUEST_CONTEXT: contexts,
        }
        for hint in self.bac_static_hints:
            if hint.source_subject_id not in subject_maps[hint.source_subject_kind]:
                raise DiscoveryContractError("BACStaticHint references missing subject")
            if hint.provenance_id not in provenance:
                raise DiscoveryContractError(
                    "BACStaticHint references missing provenance"
                )
            source = provenance[hint.provenance_id]
            if (
                source.subject_kind != hint.source_subject_kind
                or source.subject_id != hint.source_subject_id
            ):
                raise DiscoveryContractError(
                    "BACStaticHint provenance ownership mismatch"
                )

    def _validate_warnings(
        self,
        endpoints: Mapping[str, Endpoint],
        input_points: Mapping[str, InputPoint],
        templates: Mapping[str, RequestTemplate],
        contexts: Mapping[str, InputPointRequestContext],
        provenance: Mapping[str, DiscoveryProvenance],
    ) -> None:
        subject_ids = set(endpoints) | set(input_points) | set(templates) | set(contexts)
        for warning in self.warnings:
            if warning.subject_id is not None and warning.subject_id not in subject_ids:
                raise DiscoveryContractError(
                    "DiscoveryWarning references missing subject"
                )
            if (
                warning.provenance_id is not None
                and warning.provenance_id not in provenance
            ):
                raise DiscoveryContractError(
                    "DiscoveryWarning references missing provenance"
                )
            if (
                self.discovery_metadata.collector_kind
                == CollectorKind.NATIVE_COMBINED
            ):
                producer_kind = warning.details.get("producer_kind")
                if producer_kind not in {
                    CollectorKind.NATIVE_STATIC.value,
                    CollectorKind.NATIVE_DYNAMIC.value,
                }:
                    raise DiscoveryContractError(
                        "aggregate warning requires canonical producer attribution"
                    )
                if warning.provenance_id is not None and (
                    provenance[warning.provenance_id].collector_kind.value
                    != producer_kind
                ):
                    raise DiscoveryContractError(
                        "aggregate warning producer attribution mismatch"
                    )

    def _validate_counts(self) -> None:
        expected = (
            (self.crawl_statistics.endpoint_count, len(self.endpoints), "Endpoint"),
            (
                self.crawl_statistics.input_point_count,
                len(self.input_points),
                "InputPoint",
            ),
            (
                self.crawl_statistics.request_template_count,
                len(self.request_templates),
                "RequestTemplate",
            ),
            (
                self.crawl_statistics.request_context_count,
                len(self.input_point_request_contexts),
                "InputPointRequestContext",
            ),
        )
        for recorded, actual, label in expected:
            if recorded != actual:
                raise DiscoveryContractError(f"{label} count does not match output")

    def _validate_metadata_values(self) -> None:
        for point in self.input_points:
            _freeze_mapping(point.metadata)
        for template in self.request_templates:
            _freeze_mapping(template.metadata)

    def ready_contexts(
        self,
    ) -> tuple[tuple[InputPoint, RequestTemplate, InputPointRequestContext], ...]:
        self.validate()
        points = {item.id or "": item for item in self.input_points}
        templates = {item.id or "": item for item in self.request_templates}
        contexts = {
            item.id: item for item in self.input_point_request_contexts
        }
        ready: list[
            tuple[InputPoint, RequestTemplate, InputPointRequestContext]
        ] = []
        for status in self.probe_readiness:
            if status.status != ProbeReadyStatus.READY:
                continue
            context = contexts[status.request_context_id or ""]
            ready.append(
                (
                    points[status.input_point_id],
                    templates[context.request_template_id],
                    context,
                )
            )
        return tuple(ready)

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        result = {
            "contract_version": self.contract_version,
            "discovery_run_id": self.discovery_run_id,
            "discovery_metadata": {
                "collector_kind": self.discovery_metadata.collector_kind.value,
                "collector_version": self.discovery_metadata.collector_version,
                "configuration_fingerprint": (
                    self.discovery_metadata.configuration_fingerprint
                ),
            },
            "scope_metadata": {
                "target_scope_id": self.scope_metadata.target_scope_id,
                "root_url": self.scope_metadata.root_url,
                "scope_policy_version": self.scope_metadata.scope_policy_version,
                "scope_decision_refs": list(
                    self.scope_metadata.scope_decision_refs
                ),
            },
            "crawl_statistics": {
                name: getattr(self.crawl_statistics, name)
                for name in self.crawl_statistics.__dataclass_fields__
            },
            "endpoints": [
                {
                    "id": item.id,
                    "fingerprint": item.fingerprint,
                    "method": item.method.value,
                    "scheme": item.scheme,
                    "host": item.host,
                    "path": item.path,
                    "content_type": item.content_type,
                    "discovered_by": item.discovered_by,
                }
                for item in self.endpoints
            ],
            "input_points": [
                {
                    "id": item.id,
                    "fingerprint": item.fingerprint,
                    "endpoint_id": item.endpoint_id,
                    "endpoint_fingerprint": item.endpoint_fingerprint,
                    "location": item.location.value,
                    "name": item.name,
                    "occurrence_index": item.occurrence_index,
                    "baseline_value": item.baseline_value,
                    "baseline_values": list(item.baseline_values),
                    "type_hint": item.type_hint,
                    "source_page": item.source_page,
                    "auth_context_id": item.auth_context_id,
                    "metadata": _json_value(_freeze_mapping(item.metadata)),
                }
                for item in self.input_points
            ],
            "request_templates": [
                {
                    "id": item.id,
                    "fingerprint": item.fingerprint,
                    "endpoint_id": item.endpoint_id,
                    "endpoint_fingerprint": item.endpoint_fingerprint,
                    "method": item.method.value,
                    "url": item.url,
                    "headers": dict(sorted(item.headers.items())),
                    "query": [list(pair) for pair in item.query],
                    "form": [list(pair) for pair in item.form],
                    "json_body": [list(pair) for pair in item.json_body],
                    "cookies": {
                        name: "<redacted>" for name in sorted(item.cookies)
                    },
                    "completeness": item.completeness.value,
                    "context_key": item.context_key,
                    "provenance": [list(pair) for pair in item.provenance],
                    "metadata": _json_value(_freeze_mapping(item.metadata)),
                }
                for item in self.request_templates
            ],
            "input_point_request_contexts": [
                {
                    "id": item.id,
                    "input_point_id": item.input_point_id,
                    "request_template_id": item.request_template_id,
                    "role": item.role,
                }
                for item in self.input_point_request_contexts
            ],
            "probe_readiness": [
                {
                    "id": item.id,
                    "input_point_id": item.input_point_id,
                    "request_context_id": item.request_context_id,
                    "status": item.status.value,
                    "reasons": [reason.value for reason in item.reasons],
                }
                for item in self.probe_readiness
            ],
            "crawl_provenance": [
                {
                    "id": item.id,
                    "discovery_run_id": item.discovery_run_id,
                    "subject_kind": item.subject_kind.value,
                    "subject_id": item.subject_id,
                    "collector_kind": item.collector_kind.value,
                    "source_url": item.source_url,
                    "parent_url": item.parent_url,
                    "depth": item.depth,
                    "collector_observation_key": item.collector_observation_key,
                }
                for item in self.crawl_provenance
            ],
            "bac_static_hints": [
                {
                    "id": item.id,
                    "hint_kind": item.hint_kind,
                    "source_subject_kind": item.source_subject_kind.value,
                    "source_subject_id": item.source_subject_id,
                    "provenance_id": item.provenance_id,
                    "evidence": _json_value(item.evidence),
                }
                for item in self.bac_static_hints
            ],
            "warnings": [
                {
                    "id": item.id,
                    "code": item.code,
                    "message": item.message,
                    "subject_id": item.subject_id,
                    "provenance_id": item.provenance_id,
                    "details": _json_value(item.details),
                }
                for item in self.warnings
            ],
        }
        if self.safety_invariants:
            result["safety_invariants"] = [
                item.value for item in self.safety_invariants
            ]
        result["discovery_snapshot_id"] = discovery_snapshot_id_for(result)
        return result


def _unique_by_id(items: Sequence[Any], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in items:
        item_id = getattr(item, "id", None)
        if not isinstance(item_id, str) or not item_id:
            raise DiscoveryContractError(f"{label} id must not be empty")
        if item_id in result:
            raise DiscoveryContractError(f"duplicate {label} id")
        result[item_id] = item
    return result


def _require_type(value: object, expected: type[Any], label: str) -> None:
    if type(value) is not expected:
        raise DiscoveryContractError(
            f"{label} must use canonical {expected.__name__} objects"
        )


def _typed_items(
    items: Sequence[Any],
    expected: type[Any],
    label: str,
) -> tuple[Any, ...]:
    result = tuple(items)
    for item in result:
        _require_type(item, expected, label)
    return result
