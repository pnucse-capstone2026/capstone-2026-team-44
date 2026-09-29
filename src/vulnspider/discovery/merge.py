"""Transport-free deterministic merge for canonical discovery producers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from vulnspider.discovery.contracts import (
    BACStaticHint,
    CanonicalDiscoveryResult,
    CollectorKind,
    CrawlStatistics,
    DiscoveryContractError,
    DiscoveryMetadata,
    DiscoveryProvenance,
    DiscoverySafetyInvariant,
    DiscoveryWarning,
    ProbeReadiness,
    ProbeReadyStatus,
    ScopeMetadata,
    discovery_run_id_for,
)
from vulnspider.domain import (
    Endpoint,
    InputPoint,
    InputPointRequestContext,
    RequestTemplate,
    stable_fingerprint,
)


DISCOVERY_MERGE_POLICY_VERSION = "static-first/1"
_REQUIRED_SAFETY_INVARIANT = (
    DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION
)
_UNION_METADATA_KEYS = frozenset(
    {
        "control_indices",
        "origin_kinds",
        "pair_indices",
    }
)


class DynamicIntegrityError(DiscoveryContractError):
    """Raised when validated producer results cannot form a valid aggregate."""


@dataclass(frozen=True, slots=True)
class DiscoveryMergePolicy:
    """Versioned fixed Static-first canonical merge policy."""

    version: str = DISCOVERY_MERGE_POLICY_VERSION

    def __post_init__(self) -> None:
        if type(self.version) is not str:
            raise TypeError("merge policy version must be a string")
        if self.version != DISCOVERY_MERGE_POLICY_VERSION:
            raise ValueError("unsupported discovery merge policy version")

    @property
    def producer_order(self) -> tuple[CollectorKind, CollectorKind]:
        return (
            CollectorKind.NATIVE_STATIC,
            CollectorKind.NATIVE_DYNAMIC,
        )


def merge_discovery_results(
    static_result: CanonicalDiscoveryResult,
    dynamic_result: CanonicalDiscoveryResult,
    policy: DiscoveryMergePolicy,
) -> CanonicalDiscoveryResult:
    """Validate and merge one Static and one Dynamic canonical result."""

    if type(policy) is not DiscoveryMergePolicy:
        raise TypeError("policy must be a DiscoveryMergePolicy")
    _validate_component(
        static_result,
        expected_collector=CollectorKind.NATIVE_STATIC,
        label="Static",
    )
    _validate_component(
        dynamic_result,
        expected_collector=CollectorKind.NATIVE_DYNAMIC,
        label="Dynamic",
    )
    if static_result.scope_metadata != dynamic_result.scope_metadata:
        _validate_compatible_scopes(
            static_result.scope_metadata,
            dynamic_result.scope_metadata,
        )
    aggregate_scope = _merge_scope_metadata(
        static_result.scope_metadata,
        dynamic_result.scope_metadata,
    )

    aggregate_metadata = DiscoveryMetadata(
        collector_kind=CollectorKind.NATIVE_COMBINED,
        collector_version=policy.version,
        configuration_fingerprint=stable_fingerprint(
            "canonical-discovery-merge",
            policy.version,
            static_result.discovery_run_id,
            dynamic_result.discovery_run_id,
        ),
    )
    aggregate_run_id = discovery_run_id_for(
        aggregate_metadata,
        aggregate_scope,
    )

    endpoints = _merge_endpoints(
        static_result.endpoints,
        dynamic_result.endpoints,
    )
    input_points, point_conflicts = _merge_input_points(
        static_result.input_points,
        dynamic_result.input_points,
    )
    request_templates, template_conflicts = _merge_request_templates(
        static_result.request_templates,
        dynamic_result.request_templates,
    )
    contexts = _merge_contexts(
        static_result.input_point_request_contexts,
        dynamic_result.input_point_request_contexts,
    )
    readiness = _merge_readiness(
        static_result.probe_readiness,
        dynamic_result.probe_readiness,
    )
    provenance, provenance_ids = _rebuild_provenance(
        static_result,
        dynamic_result,
        aggregate_run_id=aggregate_run_id,
    )
    hints = _rebuild_static_hints(
        static_result,
        dynamic_result,
        provenance_ids=provenance_ids,
    )
    warnings = (
        *_rebuild_warnings(
            static_result,
            provenance_ids=provenance_ids,
        ),
        *_rebuild_warnings(
            dynamic_result,
            provenance_ids=provenance_ids,
        ),
        *point_conflicts,
        *template_conflicts,
    )
    statistics = _merge_statistics(
        static_result.crawl_statistics,
        dynamic_result.crawl_statistics,
        endpoint_count=len(endpoints),
        input_point_count=len(input_points),
        request_template_count=len(request_templates),
        request_context_count=len(contexts),
    )

    aggregate = CanonicalDiscoveryResult.create(
        discovery_metadata=aggregate_metadata,
        scope_metadata=aggregate_scope,
        crawl_statistics=statistics,
        endpoints=endpoints,
        input_points=input_points,
        request_templates=request_templates,
        input_point_request_contexts=contexts,
        probe_readiness=readiness,
        crawl_provenance=provenance,
        bac_static_hints=hints,
        warnings=warnings,
        safety_invariants=(_REQUIRED_SAFETY_INVARIANT,),
    )
    aggregate.validate()
    return aggregate


def _validate_compatible_scopes(
    static_scope: ScopeMetadata,
    dynamic_scope: ScopeMetadata,
) -> None:
    if (
        static_scope.target_scope_id != dynamic_scope.target_scope_id
        or static_scope.root_url != dynamic_scope.root_url
        or static_scope.scope_policy_version != dynamic_scope.scope_policy_version
    ):
        raise DynamicIntegrityError(
            "Static and Dynamic components must use identical scope metadata "
            "except for producer decision references"
        )


def _merge_scope_metadata(
    static_scope: ScopeMetadata,
    dynamic_scope: ScopeMetadata,
) -> ScopeMetadata:
    _validate_compatible_scopes(static_scope, dynamic_scope)
    return ScopeMetadata(
        target_scope_id=static_scope.target_scope_id,
        root_url=static_scope.root_url,
        scope_policy_version=static_scope.scope_policy_version,
        scope_decision_refs=tuple(
            sorted(
                {
                    *static_scope.scope_decision_refs,
                    *dynamic_scope.scope_decision_refs,
                }
            )
        ),
    )


def _validate_component(
    result: CanonicalDiscoveryResult,
    *,
    expected_collector: CollectorKind,
    label: str,
) -> None:
    if type(result) is not CanonicalDiscoveryResult:
        raise TypeError(f"{label} result must be a CanonicalDiscoveryResult")
    result.validate()
    if result.discovery_metadata.collector_kind != expected_collector:
        raise DynamicIntegrityError(
            f"{label} component uses the wrong collector kind"
        )
    if _REQUIRED_SAFETY_INVARIANT not in result.safety_invariants:
        raise DynamicIntegrityError(
            f"{label}: missing {_REQUIRED_SAFETY_INVARIANT.value}"
        )
    for point in result.input_points:
        if (point.type_hint or "").strip().lower() == "password":
            raise DynamicIntegrityError(
                f"{label} component contains a structurally sensitive InputPoint"
            )
    for warning in result.warnings:
        producer_kind = warning.details.get("producer_kind")
        if (
            producer_kind is not None
            and producer_kind != expected_collector.value
        ):
            raise DynamicIntegrityError(
                f"{label} warning producer attribution mismatch"
            )
        if warning.code != "SENSITIVE_FORM_ELIDED":
            continue
        if (
            warning.subject_id is not None
            or warning.provenance_id is not None
            or warning.details.get("producer_kind") != expected_collector.value
        ):
            raise DynamicIntegrityError(
                f"{label} sensitive-form warning has invalid producer ownership"
            )


def _merge_endpoints(
    static_items: Sequence[Endpoint],
    dynamic_items: Sequence[Endpoint],
) -> tuple[Endpoint, ...]:
    by_fingerprint: dict[str, Endpoint] = {}
    id_fingerprints: dict[str, str] = {}
    for item in (*static_items, *dynamic_items):
        item_id = item.id or ""
        previous_fingerprint = id_fingerprints.setdefault(
            item_id,
            item.fingerprint,
        )
        if previous_fingerprint != item.fingerprint:
            raise DynamicIntegrityError("Endpoint identity collision during merge")
        by_fingerprint.setdefault(item.fingerprint, item)
    return tuple(by_fingerprint.values())


def _merge_input_points(
    static_items: Sequence[InputPoint],
    dynamic_items: Sequence[InputPoint],
) -> tuple[tuple[InputPoint, ...], tuple[DiscoveryWarning, ...]]:
    by_fingerprint: dict[str, InputPoint] = {
        item.fingerprint: item for item in static_items
    }
    id_fingerprints = {
        item.id or "": item.fingerprint for item in static_items
    }
    warnings: list[DiscoveryWarning] = []
    for item in dynamic_items:
        item_id = item.id or ""
        previous_fingerprint = id_fingerprints.setdefault(
            item_id,
            item.fingerprint,
        )
        if previous_fingerprint != item.fingerprint:
            raise DynamicIntegrityError("InputPoint identity collision during merge")
        current = by_fingerprint.get(item.fingerprint)
        if current is None:
            by_fingerprint[item.fingerprint] = item
            continue
        merged, conflict_fields = _merge_input_point(current, item)
        by_fingerprint[item.fingerprint] = merged
        if conflict_fields:
            warnings.append(
                _metadata_conflict_warning(
                    subject_id=merged.id or "",
                    fields=conflict_fields,
                )
            )
    return tuple(by_fingerprint.values()), tuple(warnings)


def _merge_input_point(
    static_item: InputPoint,
    dynamic_item: InputPoint,
) -> tuple[InputPoint, tuple[str, ...]]:
    values = tuple(
        sorted(
            set(static_item.baseline_values).union(
                dynamic_item.baseline_values
            )
        )
    )
    baseline_value = values[0] if len(values) == 1 else None
    metadata, metadata_conflicts = _merge_metadata(
        static_item.metadata,
        dynamic_item.metadata,
    )
    conflict_fields = set(metadata_conflicts)
    if static_item.type_hint != dynamic_item.type_hint:
        conflict_fields.add("type_hint")
    if static_item.source_page != dynamic_item.source_page:
        conflict_fields.add("source_page")
    merged = InputPoint(
        endpoint_id=static_item.endpoint_id,
        endpoint_fingerprint=static_item.endpoint_fingerprint,
        location=static_item.location,
        name=static_item.name,
        occurrence_index=static_item.occurrence_index,
        baseline_value=baseline_value,
        baseline_values=values,
        type_hint=static_item.type_hint,
        source_page=static_item.source_page,
        auth_context_id=static_item.auth_context_id,
        metadata=metadata,
        id=static_item.id,
    )
    return merged, tuple(sorted(conflict_fields))


def _merge_request_templates(
    static_items: Sequence[RequestTemplate],
    dynamic_items: Sequence[RequestTemplate],
) -> tuple[tuple[RequestTemplate, ...], tuple[DiscoveryWarning, ...]]:
    by_fingerprint: dict[str, RequestTemplate] = {
        item.fingerprint: item for item in static_items
    }
    id_fingerprints = {
        item.id or "": item.fingerprint for item in static_items
    }
    warnings: list[DiscoveryWarning] = []
    for item in dynamic_items:
        item_id = item.id or ""
        previous_fingerprint = id_fingerprints.setdefault(
            item_id,
            item.fingerprint,
        )
        if previous_fingerprint != item.fingerprint:
            raise DynamicIntegrityError(
                "RequestTemplate identity collision during merge"
            )
        current = by_fingerprint.get(item.fingerprint)
        if current is None:
            by_fingerprint[item.fingerprint] = item
            continue
        metadata, conflict_fields = _merge_metadata(
            current.metadata,
            item.metadata,
        )
        ephemeral_material = (
            current.ephemeral_material
            if current.ephemeral_material is not None
            else item.ephemeral_material
        )
        if (
            metadata != current.metadata
            or ephemeral_material is not current.ephemeral_material
        ):
            current = RequestTemplate(
                endpoint_id=current.endpoint_id,
                endpoint_fingerprint=current.endpoint_fingerprint,
                method=current.method,
                url=current.url,
                headers=current.headers,
                query=current.query,
                form=current.form,
                json_body=current.json_body,
                cookies=current.cookies,
                completeness=current.completeness,
                context_key=current.context_key,
                provenance=current.provenance,
                metadata=metadata,
                id=current.id,
                ephemeral_material=ephemeral_material,
            )
            by_fingerprint[item.fingerprint] = current
        if conflict_fields:
            warnings.append(
                _metadata_conflict_warning(
                    subject_id=current.id or "",
                    fields=conflict_fields,
                )
            )
    return tuple(by_fingerprint.values()), tuple(warnings)


def _merge_contexts(
    static_items: Sequence[InputPointRequestContext],
    dynamic_items: Sequence[InputPointRequestContext],
) -> tuple[InputPointRequestContext, ...]:
    by_id: dict[str, InputPointRequestContext] = {}
    for item in (*static_items, *dynamic_items):
        current = by_id.get(item.id)
        if current is not None and current != item:
            raise DynamicIntegrityError(
                "InputPointRequestContext identity collision during merge"
            )
        by_id.setdefault(item.id, item)
    return tuple(by_id.values())


def _merge_readiness(
    static_items: Sequence[ProbeReadiness],
    dynamic_items: Sequence[ProbeReadiness],
) -> tuple[ProbeReadiness, ...]:
    by_owner: dict[tuple[str, str | None], ProbeReadiness] = {}
    for item in (*static_items, *dynamic_items):
        key = (item.input_point_id, item.request_context_id)
        current = by_owner.get(key)
        if current is None or current == item:
            by_owner.setdefault(key, item)
            continue
        if ProbeReadyStatus.READY in {current.status, item.status}:
            by_owner[key] = (
                current
                if current.status == ProbeReadyStatus.READY
                else item
            )
            continue
        by_owner[key] = ProbeReadiness(
            input_point_id=item.input_point_id,
            request_context_id=item.request_context_id,
            status=ProbeReadyStatus.NOT_READY,
            reasons=tuple(set(current.reasons).union(item.reasons)),
        )
    return tuple(by_owner.values())


def _rebuild_provenance(
    static_result: CanonicalDiscoveryResult,
    dynamic_result: CanonicalDiscoveryResult,
    *,
    aggregate_run_id: str,
) -> tuple[tuple[DiscoveryProvenance, ...], dict[str, str]]:
    rebuilt: list[DiscoveryProvenance] = []
    id_mapping: dict[str, str] = {}
    for component in (static_result, dynamic_result):
        for item in component.crawl_provenance:
            new_item = DiscoveryProvenance(
                discovery_run_id=aggregate_run_id,
                subject_kind=item.subject_kind,
                subject_id=item.subject_id,
                collector_kind=item.collector_kind,
                source_url=item.source_url,
                collector_observation_key=item.collector_observation_key,
                parent_url=item.parent_url,
                depth=item.depth,
            )
            rebuilt.append(new_item)
            id_mapping[item.id or ""] = new_item.id or ""
    return tuple(rebuilt), id_mapping


def _rebuild_static_hints(
    static_result: CanonicalDiscoveryResult,
    dynamic_result: CanonicalDiscoveryResult,
    *,
    provenance_ids: Mapping[str, str],
) -> tuple[BACStaticHint, ...]:
    if dynamic_result.bac_static_hints:
        raise DynamicIntegrityError(
            "Dynamic component must not contain BAC static hints"
        )
    return tuple(
        BACStaticHint(
            hint_kind=item.hint_kind,
            source_subject_kind=item.source_subject_kind,
            source_subject_id=item.source_subject_id,
            provenance_id=provenance_ids[item.provenance_id],
            evidence=item.evidence,
        )
        for item in static_result.bac_static_hints
    )


def _rebuild_warnings(
    result: CanonicalDiscoveryResult,
    *,
    provenance_ids: Mapping[str, str],
) -> tuple[DiscoveryWarning, ...]:
    producer_kind = result.discovery_metadata.collector_kind
    rebuilt: list[DiscoveryWarning] = []
    for item in result.warnings:
        details = dict(item.details)
        details["producer_kind"] = producer_kind.value
        rebuilt.append(
            DiscoveryWarning(
                code=item.code,
                message=item.message,
                subject_id=item.subject_id,
                provenance_id=(
                    provenance_ids[item.provenance_id]
                    if item.provenance_id is not None
                    else None
                ),
                details=details,
            )
        )
    return tuple(rebuilt)


def _merge_statistics(
    static: CrawlStatistics,
    dynamic: CrawlStatistics,
    *,
    endpoint_count: int,
    input_point_count: int,
    request_template_count: int,
    request_context_count: int,
) -> CrawlStatistics:
    return CrawlStatistics(
        requests_attempted=static.requests_attempted + dynamic.requests_attempted,
        pages_processed=static.pages_processed + dynamic.pages_processed,
        html_pages=static.html_pages + dynamic.html_pages,
        links_discovered=static.links_discovered + dynamic.links_discovered,
        forms_discovered=static.forms_discovered + dynamic.forms_discovered,
        skipped=static.skipped + dynamic.skipped,
        redirects_followed=static.redirects_followed + dynamic.redirects_followed,
        max_depth_reached=max(
            static.max_depth_reached,
            dynamic.max_depth_reached,
        ),
        request_budget=static.request_budget + dynamic.request_budget,
        page_budget=static.page_budget + dynamic.page_budget,
        depth_budget=max(static.depth_budget, dynamic.depth_budget),
        elapsed_ms=static.elapsed_ms + dynamic.elapsed_ms,
        endpoint_count=endpoint_count,
        input_point_count=input_point_count,
        request_template_count=request_template_count,
        request_context_count=request_context_count,
    )


def _merge_metadata(
    static: Mapping[str, Any],
    dynamic: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    merged = dict(static)
    conflicts: set[str] = set()
    static_tokens = _raw_query_tokens(static)
    dynamic_tokens = _raw_query_tokens(dynamic)
    for key, value in dynamic.items():
        if key in {"raw_query_token", "raw_query_tokens"}:
            continue
        if key not in merged:
            merged[key] = value
            continue
        if merged[key] == value:
            continue
        if key in _UNION_METADATA_KEYS:
            union = _sorted_metadata_union(merged[key], value)
            if union is not None:
                merged[key] = union
                continue
        conflicts.add(key)
    if static_tokens or dynamic_tokens:
        merged.pop("raw_query_token", None)
        merged.pop("raw_query_tokens", None)
        tokens = tuple(sorted(set(static_tokens).union(dynamic_tokens)))
        if len(tokens) == 1:
            merged["raw_query_token"] = tokens[0]
        elif tokens:
            merged["raw_query_tokens"] = tokens
    return merged, tuple(sorted(conflicts))


def _raw_query_tokens(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    tokens: list[str] = []
    single = metadata.get("raw_query_token")
    if type(single) is str:
        tokens.append(single)
    multiple = metadata.get("raw_query_tokens")
    if type(multiple) is tuple and all(type(item) is str for item in multiple):
        tokens.extend(multiple)
    return tuple(tokens)


def _sorted_metadata_union(
    first: Any,
    second: Any,
) -> tuple[str, ...] | tuple[int, ...] | None:
    if type(first) is not tuple or type(second) is not tuple:
        return None
    values = (*first, *second)
    if all(type(item) is str for item in values):
        return tuple(sorted(set(values)))
    if all(type(item) is int for item in values):
        return tuple(sorted(set(values)))
    return None


def _metadata_conflict_warning(
    *,
    subject_id: str,
    fields: Sequence[str],
) -> DiscoveryWarning:
    return DiscoveryWarning(
        code="DISCOVERY_METADATA_CONFLICT",
        message="Static-first discovery metadata was retained",
        subject_id=subject_id,
        details={
            "fields": tuple(sorted(fields)),
            "producer_kind": CollectorKind.NATIVE_STATIC.value,
            "producer_order": (
                CollectorKind.NATIVE_STATIC.value,
                CollectorKind.NATIVE_DYNAMIC.value,
            ),
        },
    )
