"""Adapter for legacy WHSPIDER crawl records.

The adapter is intentionally pure: it does not import or execute the legacy
crawler, perform network I/O, or depend on the old SQLite schema at runtime.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit

from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ParamPairs,
    RequestContextCompleteness,
    RequestTemplate,
)


@dataclass(frozen=True, slots=True)
class LegacyCrawlRecord:
    link: str
    parent: str | None = None
    depth: int | None = None
    host: str | None = None
    query_params: str | Mapping[str, Any] | None = None
    input_fields: str | Sequence[Mapping[str, Any]] | None = None
    collected_time: str | None = None
    source: str = "legacy_static"

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> LegacyCrawlRecord:
        return cls(
            link=str(raw.get("link") or raw.get("url") or ""),
            parent=_optional_str(raw.get("parent")),
            depth=_optional_int(raw.get("depth")),
            host=_optional_str(raw.get("host")),
            query_params=raw.get("query_params"),
            input_fields=raw.get("input_fields"),
            collected_time=_optional_str(raw.get("collected_time")),
            source=str(raw.get("source") or "legacy_static"),
        )


@dataclass(frozen=True, slots=True)
class LegacyAdapterResult:
    endpoints: tuple[Endpoint, ...]
    input_points: tuple[InputPoint, ...]
    request_templates: tuple[RequestTemplate, ...]
    input_point_request_contexts: tuple[InputPointRequestContext, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class _FormFieldContext:
    method: HttpMethod
    form_url: str
    action_value: str
    method_provenance: str
    action_provenance: str
    boundary_key: str | None
    boundary_status: str
    field_name: str | None
    field_type: str | None
    field_value: str
    ambiguous_field_key: str | None


class LegacyCrawlerAdapter:
    def convert(
        self,
        records: Sequence[LegacyCrawlRecord | Mapping[str, Any]],
    ) -> LegacyAdapterResult:
        endpoints: dict[str, Endpoint] = {}
        input_points: dict[str, InputPoint] = {}
        request_templates: dict[str, RequestTemplate] = {}
        input_point_request_contexts: dict[str, InputPointRequestContext] = {}
        input_to_template_ids: dict[str, set[str]] = {}
        input_baseline_values: dict[str, set[str | None]] = {}
        warnings: list[str] = []

        normalized_records = [
            record
            if isinstance(record, LegacyCrawlRecord)
            else LegacyCrawlRecord.from_mapping(record)
            for record in records
        ]

        for record in sorted(normalized_records, key=_record_sort_key):
            if not record.link:
                warnings.append("legacy record skipped: missing link")
                continue
            page_parts = urlsplit(record.link)
            if not page_parts.scheme or not page_parts.netloc:
                warnings.append(f"legacy record skipped: invalid link: {record.link}")
                continue

            query_pairs = _parse_query_pairs(record, warnings)
            if query_pairs:
                endpoint = _endpoint_from_url(record.link, HttpMethod.GET)
                endpoints.setdefault(endpoint.fingerprint, endpoint)
                request_template = _query_request_template(
                    endpoint,
                    record.link,
                    query_pairs,
                    record,
                )
                request_templates.setdefault(request_template.id or "", request_template)
                name_counts = Counter(pair_name for pair_name, _ in query_pairs)
                seen_names: dict[str, int] = {}
                for pair_index, (name, value) in enumerate(query_pairs):
                    occurrence_index = None
                    if name_counts[name] > 1:
                        occurrence_index = seen_names.get(name, 0)
                    seen_names[name] = seen_names.get(name, 0) + 1
                    context_input_point = InputPoint(
                        endpoint_id=endpoint.id or "",
                        endpoint_fingerprint=endpoint.fingerprint,
                        location=InputLocation.QUERY,
                        name=name,
                        occurrence_index=occurrence_index,
                        baseline_value=value,
                        source_page=record.link,
                        metadata={
                            "legacy_source": record.source,
                            "legacy_parent": record.parent,
                            "legacy_depth": record.depth,
                            "pair_index": pair_index,
                            "repeated_parameter": name_counts[name] > 1,
                            "occurrence_index": occurrence_index,
                        },
                    )
                    input_points.setdefault(
                        context_input_point.fingerprint,
                        context_input_point,
                    )
                    _remember_input_baseline(
                        input_baseline_values,
                        context_input_point,
                        value,
                    )
                    _bind_input_to_template(
                        input_point=context_input_point,
                        request_template=request_template,
                        bindings=input_point_request_contexts,
                        input_to_template_ids=input_to_template_ids,
                    )

            fields = _parse_input_fields(record, warnings)
            field_contexts = tuple(
                (field, _form_context(field, record, warnings)) for field in fields
            )
            for field, context in field_contexts:
                name = _optional_str(field.get("name"))
                if not name:
                    warnings.append(
                        f"legacy form field skipped on {record.link}: missing name"
                    )
                    continue
                endpoint = _endpoint_from_url(context.form_url, context.method)
                endpoints.setdefault(endpoint.fingerprint, endpoint)
                form_values = _form_values_for_context(field_contexts, context)
                request_template = _form_request_template(
                    endpoint,
                    context,
                    form_values,
                    record,
                )
                request_templates.setdefault(request_template.id or "", request_template)
                if context.boundary_status == "unavailable":
                    _append_unique(
                        warnings,
                        (
                            f"legacy form context on {record.link} is ambiguous: "
                            "form-boundary-unavailable"
                        ),
                    )
                _append_unique(
                    warnings,
                    (
                        f"legacy form context on {record.link} is partial: "
                        "hidden inputs may have been omitted"
                    ),
                )

                type_hint = _optional_str(field.get("type"))
                hidden = (type_hint or "").strip().lower() == "hidden"
                form_value = _form_field_value(field)
                occurrence_index = _form_occurrence_index(
                    field_contexts,
                    context,
                    name,
                    field,
                )
                context_input_point = InputPoint(
                    endpoint_id=endpoint.id or "",
                    endpoint_fingerprint=endpoint.fingerprint,
                    location=InputLocation.FORM,
                    name=name,
                    occurrence_index=occurrence_index,
                    baseline_value=form_value,
                    type_hint=type_hint,
                    source_page=record.link,
                    metadata={
                        "legacy_source": record.source,
                        "legacy_parent": record.parent,
                        "legacy_depth": record.depth,
                        "form_action": context.action_value,
                        "form_action_provenance": context.action_provenance,
                        "form_method": context.method.value,
                        "form_method_provenance": context.method_provenance,
                        "form_boundary_status": context.boundary_status,
                        "form_boundary_key": context.boundary_key,
                        "occurrence_index": occurrence_index,
                        "hidden": hidden,
                        "visibility": "hidden" if hidden else "visible",
                        "request_context_completeness": (
                            RequestContextCompleteness.PARTIAL.value
                        ),
                        "non_probe_ready_reasons": _form_non_probe_ready_reasons(
                            context
                        ),
                    },
                )
                input_points.setdefault(
                    context_input_point.fingerprint,
                    context_input_point,
                )
                _remember_input_baseline(
                    input_baseline_values,
                    context_input_point,
                    form_value,
                )
                _bind_input_to_template(
                    input_point=context_input_point,
                    request_template=request_template,
                    bindings=input_point_request_contexts,
                    input_to_template_ids=input_to_template_ids,
                )

        for input_point_id, template_ids in sorted(input_to_template_ids.items()):
            if len(template_ids) > 1:
                warnings.append(
                    f"input point {input_point_id} has "
                    f"{len(template_ids)} request context variants; "
                    "no canonical baseline selected"
                )

        input_points = _finalize_input_points(input_points, input_baseline_values)

        return LegacyAdapterResult(
            endpoints=tuple(sorted(endpoints.values(), key=lambda item: item.fingerprint)),
            input_points=tuple(
                sorted(input_points.values(), key=lambda item: item.fingerprint)
            ),
            request_templates=tuple(
                sorted(
                    request_templates.values(),
                    key=lambda item: item.id or "",
                )
            ),
            input_point_request_contexts=tuple(
                sorted(
                    input_point_request_contexts.values(),
                    key=lambda item: item.id or "",
                )
            ),
            warnings=tuple(warnings),
        )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_sort_key(record: LegacyCrawlRecord) -> tuple[str, str, str]:
    return (record.link, record.collected_time or "", record.source)


def _append_unique(warnings: list[str], message: str) -> None:
    if message not in warnings:
        warnings.append(message)


def _bind_input_to_template(
    *,
    input_point: InputPoint,
    request_template: RequestTemplate,
    bindings: dict[str, InputPointRequestContext],
    input_to_template_ids: dict[str, set[str]],
) -> None:
    binding = InputPointRequestContext.from_objects(input_point, request_template)
    bindings.setdefault(binding.id or "", binding)
    input_to_template_ids.setdefault(input_point.id or "", set()).add(
        request_template.id or ""
    )


def _remember_input_baseline(
    values_by_fingerprint: dict[str, set[str | None]],
    input_point: InputPoint,
    value: str | None,
) -> None:
    values_by_fingerprint.setdefault(input_point.fingerprint, set()).add(value)


def _finalize_input_points(
    input_points: dict[str, InputPoint],
    values_by_fingerprint: dict[str, set[str | None]],
) -> dict[str, InputPoint]:
    finalized: dict[str, InputPoint] = {}
    for fingerprint, input_point in input_points.items():
        observed_values = values_by_fingerprint.get(fingerprint, set())
        metadata = dict(input_point.metadata)
        if len(observed_values) == 1:
            value = next(iter(observed_values))
            metadata["baseline_value_state"] = (
                "single" if value is not None else "unknown"
            )
            finalized[fingerprint] = replace(
                input_point,
                baseline_value=value,
                baseline_values=(value,) if value is not None else (),
                metadata=metadata,
            )
        elif observed_values:
            metadata["baseline_value_state"] = "multiple_contexts_conflicting"
            finalized[fingerprint] = replace(
                input_point,
                baseline_value=None,
                baseline_values=(),
                metadata=metadata,
            )
        else:
            metadata["baseline_value_state"] = "unknown"
            finalized[fingerprint] = replace(
                input_point,
                baseline_value=None,
                baseline_values=(),
                metadata=metadata,
            )
    return finalized


def _parse_json_object(raw: Any, *, label: str, link: str, warnings: list[str]) -> Any:
    if raw is None or raw == "":
        return {} if label == "query_params" else []
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            warnings.append(f"{label} on {link} is not valid JSON")
            return {} if label == "query_params" else []
    return raw


def _parse_query_pairs(
    record: LegacyCrawlRecord,
    warnings: list[str],
) -> ParamPairs:
    url_pairs = tuple(parse_qsl(urlsplit(record.link).query, keep_blank_values=True))
    parsed = _parse_json_object(
        record.query_params,
        label="query_params",
        link=record.link,
        warnings=warnings,
    )
    metadata_pairs: list[tuple[str, str]] = []
    if isinstance(parsed, Mapping):
        for key, value in parsed.items():
            name = str(key)
            if isinstance(value, list):
                metadata_pairs.extend((name, str(item)) for item in value)
            else:
                metadata_pairs.append((name, str(value)))
    elif parsed:
        warnings.append(f"query_params on {record.link} is not an object")

    if url_pairs:
        if metadata_pairs and Counter(url_pairs) != Counter(metadata_pairs):
            warnings.append(
                f"query_params on {record.link} conflicts with URL query; "
                "using authoritative URL order"
            )
        return url_pairs
    return tuple(metadata_pairs)


def _parse_input_fields(
    record: LegacyCrawlRecord,
    warnings: list[str],
) -> tuple[Mapping[str, Any], ...]:
    parsed = _parse_json_object(
        record.input_fields,
        label="input_fields",
        link=record.link,
        warnings=warnings,
    )
    if parsed in ({}, None):
        return ()
    if not isinstance(parsed, Sequence) or isinstance(parsed, str):
        warnings.append(f"input_fields on {record.link} is not a list")
        return ()
    fields: list[Mapping[str, Any]] = []
    for item in parsed:
        if isinstance(item, Mapping):
            fields.append(item)
        else:
            warnings.append(f"input_fields on {record.link} contains non-object item")
    return tuple(fields)


def _form_context(
    field: Mapping[str, Any],
    record: LegacyCrawlRecord,
    warnings: list[str],
) -> _FormFieldContext:
    raw_method = _optional_str(field.get("form_method"))
    if raw_method:
        method_provenance = "explicit"
        raw = raw_method.strip().upper()
    else:
        method_provenance = "unknown_assumed_get"
        raw = "GET"
        warnings.append(
            f"form field {field.get('name')!r} on {record.link}: "
            "missing form_method; assumed GET"
        )
    try:
        method = HttpMethod(raw)
    except ValueError:
        method_provenance = "invalid_assumed_get"
        warnings.append(
            f"form field {field.get('name')!r} on {record.link}: "
            f"unsupported method {raw!r}; defaulted to GET"
        )
        method = HttpMethod.GET

    raw_action = _optional_str(field.get("form_action"))
    if raw_action:
        action_provenance = "explicit"
        action_value = raw_action
    else:
        action_provenance = "unknown_assumed_current_page"
        action_value = record.link
        warnings.append(
            f"form field {field.get('name')!r} on {record.link}: "
            "missing form_action; assumed current page"
        )
    boundary_key = _stable_form_boundary_key(field)
    field_name = _optional_str(field.get("name"))
    field_type = _optional_str(field.get("type"))
    field_value = _form_field_value(field)
    ambiguous_field_key = None
    if boundary_key is None:
        ambiguous_field_key = _ambiguous_form_field_key(
            name=field_name,
            field_type=field_type,
            value=field_value,
        )
    return _FormFieldContext(
        method=method,
        form_url=urljoin(record.link, action_value),
        action_value=action_value,
        method_provenance=method_provenance,
        action_provenance=action_provenance,
        boundary_key=boundary_key,
        boundary_status="stable" if boundary_key is not None else "unavailable",
        field_name=field_name,
        field_type=field_type,
        field_value=field_value,
        ambiguous_field_key=ambiguous_field_key,
    )


def _stable_form_boundary_key(field: Mapping[str, Any]) -> str | None:
    for key in (
        "form_instance_id",
        "form_boundary_id",
        "form_id",
        "form_key",
        "form_index",
    ):
        value = _optional_str(field.get(key))
        if value is not None:
            return f"{key}:{value}"
    return None


def _ambiguous_form_field_key(
    *,
    name: str | None,
    field_type: str | None,
    value: str,
) -> str:
    return json.dumps(
        {
            "name": _normalize_form_identity_part(name),
            "type": _normalize_form_identity_part(field_type),
            "value": value,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _normalize_form_identity_part(value: str | None) -> str:
    return (value or "").strip().lower()


def _endpoint_from_url(url: str, method: HttpMethod) -> Endpoint:
    parts = urlsplit(url)
    return Endpoint(
        method=method,
        scheme=parts.scheme,
        host=parts.netloc,
        path=parts.path or "/",
        discovered_by="legacy_whspider",
    )


def _query_request_template(
    endpoint: Endpoint,
    url: str,
    query_pairs: ParamPairs,
    record: LegacyCrawlRecord,
) -> RequestTemplate:
    return RequestTemplate(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        method=HttpMethod.GET,
        url=url,
        query=query_pairs,
        completeness=RequestContextCompleteness.COMPLETE,
        context_key=f"legacy-query:{url}",
        metadata={
            "legacy_source": record.source,
            "legacy_parent": record.parent,
            "legacy_depth": record.depth,
            "context_kind": "query",
            "repeated_parameters": _repeated_names(query_pairs),
        },
    )


def _repeated_names(pairs: ParamPairs) -> tuple[str, ...]:
    counts: dict[str, int] = {}
    for name, _ in pairs:
        counts[name] = counts.get(name, 0) + 1
    return tuple(sorted(name for name, count in counts.items() if count > 1))


def _form_group_key(context: _FormFieldContext) -> tuple[object, ...]:
    boundary_key = context.boundary_key
    if boundary_key is None:
        boundary_key = "form-boundary-unavailable"
    return (
        context.method.value,
        context.form_url,
        context.method_provenance,
        context.action_provenance,
        boundary_key,
        context.ambiguous_field_key,
    )


def _form_field_value(field: Mapping[str, Any]) -> str:
    value = field.get("value")
    return "" if value is None else str(value)


def _form_values_for_context(
    field_contexts: Sequence[tuple[Mapping[str, Any], _FormFieldContext]],
    target_context: _FormFieldContext,
) -> ParamPairs:
    if target_context.boundary_status != "stable":
        if target_context.field_name is None:
            return ()
        return ((target_context.field_name, target_context.field_value),)

    values: list[tuple[str, str]] = []
    target_key = _form_group_key(target_context)
    for field, context in field_contexts:
        if _form_group_key(context) != target_key:
            continue
        name = _optional_str(field.get("name"))
        if name:
            values.append((name, _form_field_value(field)))
    return tuple(values)


def _form_occurrence_index(
    field_contexts: Sequence[tuple[Mapping[str, Any], _FormFieldContext]],
    target_context: _FormFieldContext,
    target_name: str,
    target_field: Mapping[str, Any],
) -> int | None:
    if target_context.boundary_status != "stable":
        return None
    target_key = _form_group_key(target_context)
    matching_fields = [
        field
        for field, context in field_contexts
        if _form_group_key(context) == target_key
        and _optional_str(field.get("name")) == target_name
    ]
    if len(matching_fields) <= 1:
        return None
    for index, field in enumerate(matching_fields):
        if field is target_field:
            return index
    return None


def _form_non_probe_ready_reasons(
    context: _FormFieldContext,
) -> tuple[str, ...]:
    reasons = ["legacy-hidden-inputs-may-be-omitted"]
    if context.boundary_status == "unavailable":
        reasons.append("form-boundary-unavailable")
    return tuple(reasons)


def _form_request_template(
    endpoint: Endpoint,
    context: _FormFieldContext,
    form_values: ParamPairs,
    record: LegacyCrawlRecord,
) -> RequestTemplate:
    context_key = (
        f"legacy-form:{record.link}:{context.method.value}:{context.form_url}:"
        f"method-provenance={context.method_provenance}:"
        f"action-provenance={context.action_provenance}:"
        f"boundary={context.boundary_key or 'unavailable'}:"
        f"field={context.ambiguous_field_key if context.boundary_key is None else 'group'}"
    )
    return RequestTemplate(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        method=endpoint.method,
        url=context.form_url,
        form=form_values,
        completeness=RequestContextCompleteness.PARTIAL,
        context_key=context_key,
        provenance=(
            ("form_method", context.method_provenance),
            ("form_action", context.action_provenance),
            ("form_boundary", context.boundary_status),
        ),
        metadata={
            "legacy_source": record.source,
            "legacy_parent": record.parent,
            "legacy_depth": record.depth,
            "context_kind": "form",
            "source_page": record.link,
            "form_method_provenance": context.method_provenance,
            "form_action_provenance": context.action_provenance,
            "hidden_input_policy": "legacy_collector_may_omit_hidden_inputs",
            "form_boundary_status": context.boundary_status,
            "form_boundary_key": context.boundary_key,
            "form_grouping_policy": (
                "stable_form_boundary"
                if context.boundary_status == "stable"
                else "single_legacy_field_record"
            ),
            "reconstruction_status": (
                "partial"
                if context.boundary_status == "stable"
                else "ambiguous"
            ),
            "non_probe_ready_reasons": _form_non_probe_ready_reasons(context),
            "repeated_form_controls": _repeated_names(form_values),
        },
    )
