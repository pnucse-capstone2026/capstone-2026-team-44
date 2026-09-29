from __future__ import annotations

from dataclasses import replace
import json
import unittest

from vulnspider.discovery import (
    CanonicalDiscoveryResult,
    CollectorKind,
    CrawlStatistics,
    DiscoveryContractError,
    DiscoveryMergePolicy,
    DiscoveryMetadata,
    DiscoveryProvenance,
    DiscoverySafetyInvariant,
    DiscoverySubjectKind,
    DiscoveryWarning,
    DynamicIntegrityError,
    ProbeReadiness,
    ProbeReadyStatus,
    SensitiveFormElisionPolicy,
    ScopeMetadata,
    discovery_run_id_for,
    extract_static_html,
    merge_discovery_results,
    scope_id_for_root,
)
from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    RequestContextCompleteness,
    RequestTemplate,
    stable_fingerprint,
)


ROOT_URL = "http://127.0.0.1:8080/"
SCOPE = ScopeMetadata(
    target_scope_id=scope_id_for_root(
        ROOT_URL,
        policy_version="same-origin-v1",
    ),
    root_url=ROOT_URL,
    scope_policy_version="same-origin-v1",
)
POLICY = DiscoveryMergePolicy()
SAFETY_INVARIANT = (
    DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION
)
SENSITIVE_FORM_POLICY = SensitiveFormElisionPolicy()
COLLISION_HTML = """
<a href="/search?q=safe">safe</a>
<form method="get" action="/search">
  <input type="password" name="q" value="PW_SENTINEL">
</form>
"""
ALT_SCOPE = ScopeMetadata(
    target_scope_id=scope_id_for_root(
        ROOT_URL,
        policy_version="same-origin-v2",
    ),
    root_url=ROOT_URL,
    scope_policy_version="same-origin-v2",
)


def sensitive_warning(
    collector_kind: CollectorKind,
    *,
    occurrence_index: int = 0,
) -> DiscoveryWarning:
    return DiscoveryWarning(
        code="SENSITIVE_FORM_ELIDED",
        message="sensitive form was elided before canonical construction",
        details={
            "depth": 0,
            "form_occurrence_index": occurrence_index,
            "producer_kind": collector_kind.value,
        },
    )


def build_component(
    collector_kind: CollectorKind,
    *,
    path: str | None = "/search",
    name: str = "q",
    value: str = "safe",
    type_hint: str = "query",
    warnings: tuple[DiscoveryWarning, ...] = (),
    statistics: CrawlStatistics | None = None,
    scope: ScopeMetadata = SCOPE,
    safety_invariants: tuple[DiscoverySafetyInvariant, ...] = (
        SAFETY_INVARIANT,
    ),
) -> CanonicalDiscoveryResult:
    metadata = DiscoveryMetadata(
        collector_kind=collector_kind,
        collector_version=f"{collector_kind.value.lower()}-v1",
        configuration_fingerprint=stable_fingerprint(
            "merge-test-component",
            collector_kind.value,
            path,
            name,
            value,
        ),
    )
    run_id = discovery_run_id_for(metadata, scope)
    if path is None:
        records: tuple[
            tuple[Endpoint, ...],
            tuple[InputPoint, ...],
            tuple[RequestTemplate, ...],
            tuple[InputPointRequestContext, ...],
            tuple[ProbeReadiness, ...],
            tuple[DiscoveryProvenance, ...],
        ] = ((), (), (), (), (), ())
    else:
        endpoint = Endpoint(
            HttpMethod.GET,
            "http",
            "127.0.0.1:8080",
            path,
            discovered_by=collector_kind.value.lower(),
        )
        raw_token = f"{name}={value}"
        url = f"{ROOT_URL.rstrip('/')}{path}?{raw_token}"
        point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name=name,
            baseline_value=value,
            type_hint=type_hint,
            source_page=url,
            metadata={
                (
                    "native_static"
                    if collector_kind == CollectorKind.NATIVE_STATIC
                    else "native_dynamic"
                ): True,
                "origin_kinds": ("query",),
                "pair_indices": (0,),
                "control_indices": (),
                "raw_query_token": raw_token,
            },
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url=url,
            query=((name, value),),
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="native-query",
            provenance=(("query", "raw-url"),),
            metadata={
                "context_kind": "query",
                (
                    "native_static"
                    if collector_kind == CollectorKind.NATIVE_STATIC
                    else "native_dynamic"
                ): True,
            },
        )
        context = InputPointRequestContext.from_objects(point, template)
        readiness = ProbeReadiness(
            input_point_id=point.id or "",
            request_context_id=context.id,
            status=ProbeReadyStatus.READY,
        )
        provenance = tuple(
            DiscoveryProvenance(
                discovery_run_id=run_id,
                subject_kind=subject_kind,
                subject_id=item.id or "",
                collector_kind=collector_kind,
                source_url=url,
                collector_observation_key=(
                    f"{collector_kind.value}:{subject_kind.value}:{item.id}"
                ),
            )
            for subject_kind, item in (
                (DiscoverySubjectKind.ENDPOINT, endpoint),
                (DiscoverySubjectKind.INPUT_POINT, point),
                (DiscoverySubjectKind.REQUEST_TEMPLATE, template),
                (DiscoverySubjectKind.REQUEST_CONTEXT, context),
            )
        )
        records = (
            (endpoint,),
            (point,),
            (template,),
            (context,),
            (readiness,),
            provenance,
        )
    (
        endpoints,
        input_points,
        templates,
        contexts,
        readiness_items,
        provenance_items,
    ) = records
    base_statistics = statistics or CrawlStatistics(
        request_budget=5,
        page_budget=5,
        depth_budget=2,
    )
    canonical_statistics = replace(
        base_statistics,
        endpoint_count=len(endpoints),
        input_point_count=len(input_points),
        request_template_count=len(templates),
        request_context_count=len(contexts),
    )
    return CanonicalDiscoveryResult.create(
        discovery_metadata=metadata,
        scope_metadata=scope,
        crawl_statistics=canonical_statistics,
        endpoints=endpoints,
        input_points=input_points,
        request_templates=templates,
        input_point_request_contexts=contexts,
        probe_readiness=readiness_items,
        crawl_provenance=provenance_items,
        warnings=warnings,
        safety_invariants=safety_invariants,
    )


def build_multi_component(
    collector_kind: CollectorKind,
    specs: tuple[tuple[str, str, str], ...],
    *,
    warnings: tuple[DiscoveryWarning, ...],
) -> CanonicalDiscoveryResult:
    metadata = DiscoveryMetadata(
        collector_kind=collector_kind,
        collector_version=f"{collector_kind.value.lower()}-v1",
        configuration_fingerprint=stable_fingerprint(
            "merge-test-multi-component",
            collector_kind.value,
            tuple(sorted(specs)),
        ),
    )
    run_id = discovery_run_id_for(metadata, SCOPE)
    endpoints: list[Endpoint] = []
    points: list[InputPoint] = []
    templates: list[RequestTemplate] = []
    contexts: list[InputPointRequestContext] = []
    readiness_items: list[ProbeReadiness] = []
    provenance_items: list[DiscoveryProvenance] = []
    for path, name, value in specs:
        endpoint = Endpoint(
            HttpMethod.GET,
            "http",
            "127.0.0.1:8080",
            path,
            discovered_by=collector_kind.value.lower(),
        )
        raw_token = f"{name}={value}"
        url = f"{ROOT_URL.rstrip('/')}{path}?{raw_token}"
        point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name=name,
            baseline_value=value,
            type_hint="query",
            source_page=url,
            metadata={
                "origin_kinds": ("query",),
                "pair_indices": (0,),
                "raw_query_token": raw_token,
            },
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url=url,
            query=((name, value),),
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="native-query",
            provenance=(("query", "raw-url"),),
            metadata={"context_kind": "query"},
        )
        context = InputPointRequestContext.from_objects(point, template)
        readiness = ProbeReadiness(
            input_point_id=point.id or "",
            request_context_id=context.id,
            status=ProbeReadyStatus.READY,
        )
        endpoints.append(endpoint)
        points.append(point)
        templates.append(template)
        contexts.append(context)
        readiness_items.append(readiness)
        for subject_kind, item in (
            (DiscoverySubjectKind.ENDPOINT, endpoint),
            (DiscoverySubjectKind.INPUT_POINT, point),
            (DiscoverySubjectKind.REQUEST_TEMPLATE, template),
            (DiscoverySubjectKind.REQUEST_CONTEXT, context),
        ):
            provenance_items.append(
                DiscoveryProvenance(
                    discovery_run_id=run_id,
                    subject_kind=subject_kind,
                    subject_id=item.id or "",
                    collector_kind=collector_kind,
                    source_url=url,
                    collector_observation_key=(
                        f"{collector_kind.value}:"
                        f"{subject_kind.value}:{item.id}"
                    ),
                )
            )
    return CanonicalDiscoveryResult.create(
        discovery_metadata=metadata,
        scope_metadata=SCOPE,
        crawl_statistics=CrawlStatistics(
            request_budget=10,
            page_budget=10,
            depth_budget=2,
            endpoint_count=len(endpoints),
            input_point_count=len(points),
            request_template_count=len(templates),
            request_context_count=len(contexts),
        ),
        endpoints=tuple(endpoints),
        input_points=tuple(points),
        request_templates=tuple(templates),
        input_point_request_contexts=tuple(contexts),
        probe_readiness=tuple(readiness_items),
        crawl_provenance=tuple(provenance_items),
        warnings=warnings,
        safety_invariants=(SAFETY_INVARIANT,),
    )


class DiscoveryMergeTests(unittest.TestCase):
    def test_static_result_plus_empty_dynamic_result_is_valid(self) -> None:
        static = build_component(CollectorKind.NATIVE_STATIC)
        static_snapshot = build_component(CollectorKind.NATIVE_STATIC)
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
        )
        dynamic_snapshot = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
        )
        static_serialized = static.to_dict()
        dynamic_serialized = dynamic.to_dict()

        first = merge_discovery_results(static, dynamic, POLICY)
        second = merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(
            first.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_COMBINED,
        )
        self.assertEqual(first.safety_invariants, (SAFETY_INVARIANT,))
        self.assertEqual(first.endpoints, static.endpoints)
        self.assertEqual(first.input_points, static.input_points)
        self.assertEqual(first, second)
        self.assertEqual(static, static_snapshot)
        self.assertEqual(dynamic, dynamic_snapshot)
        self.assertEqual(static.to_dict(), static_serialized)
        self.assertEqual(dynamic.to_dict(), dynamic_serialized)
        first.validate()

    def test_empty_static_result_plus_dynamic_result_is_valid(self) -> None:
        static = build_component(CollectorKind.NATIVE_STATIC, path=None)
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path="/dynamic",
        )

        aggregate = merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(
            [item.path for item in aggregate.endpoints],
            ["/dynamic"],
        )
        aggregate.validate()

    def test_independent_discoveries_preserve_references_and_readiness(self) -> None:
        static = build_component(
            CollectorKind.NATIVE_STATIC,
            path="/static",
            name="left",
        )
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path="/dynamic",
            name="right",
        )

        aggregate = merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(
            {item.path for item in aggregate.endpoints},
            {"/dynamic", "/static"},
        )
        self.assertEqual(
            {item.name for item in aggregate.input_points},
            {"left", "right"},
        )
        self.assertEqual(len(aggregate.ready_contexts()), 2)
        aggregate.validate()

    def test_exact_duplicate_discovery_uses_static_first_identity(self) -> None:
        static = build_component(CollectorKind.NATIVE_STATIC)
        dynamic = build_component(CollectorKind.NATIVE_DYNAMIC)

        aggregate = merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(len(aggregate.endpoints), 1)
        self.assertEqual(len(aggregate.input_points), 1)
        self.assertEqual(len(aggregate.request_templates), 1)
        self.assertEqual(len(aggregate.input_point_request_contexts), 1)
        self.assertEqual(
            aggregate.endpoints[0].discovered_by,
            CollectorKind.NATIVE_STATIC.value.lower(),
        )
        point_producers = {
            item.collector_kind
            for item in aggregate.crawl_provenance
            if (
                item.subject_kind == DiscoverySubjectKind.INPUT_POINT
                and item.subject_id == aggregate.input_points[0].id
            )
        }
        self.assertEqual(
            point_producers,
            {
                CollectorKind.NATIVE_STATIC,
                CollectorKind.NATIVE_DYNAMIC,
            },
        )
        aggregate.validate()

    def test_same_endpoint_with_distinct_inputs_preserves_both(self) -> None:
        static = build_component(
            CollectorKind.NATIVE_STATIC,
            path="/shared",
            name="q",
        )
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path="/shared",
            name="page",
            value="1",
        )

        aggregate = merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(len(aggregate.endpoints), 1)
        self.assertEqual(
            {item.name for item in aggregate.input_points},
            {"page", "q"},
        )
        self.assertEqual(len(aggregate.input_point_request_contexts), 2)
        self.assertEqual(len(aggregate.ready_contexts()), 2)
        aggregate.validate()

    def test_duplicate_point_unions_values_and_reports_safe_conflict(self) -> None:
        static = build_component(
            CollectorKind.NATIVE_STATIC,
            value="a",
            type_hint="query",
        )
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            value="b",
            type_hint="text",
        )

        aggregate = merge_discovery_results(static, dynamic, POLICY)

        point = aggregate.input_points[0]
        self.assertEqual(point.baseline_values, ("a", "b"))
        self.assertIsNone(point.baseline_value)
        self.assertEqual(point.type_hint, "query")
        self.assertEqual(
            point.metadata["raw_query_tokens"],
            ("q=a", "q=b"),
        )
        conflicts = [
            item
            for item in aggregate.warnings
            if item.code == "DISCOVERY_METADATA_CONFLICT"
        ]
        self.assertEqual(len(conflicts), 1)
        self.assertIn("type_hint", conflicts[0].details["fields"])
        conflict_text = json.dumps(
            dict(conflicts[0].details),
            sort_keys=True,
        )
        self.assertNotIn("q=a", conflict_text)
        self.assertNotIn("q=b", conflict_text)
        aggregate.validate()

    def test_invalid_components_are_hard_failures(self) -> None:
        invalid_components = (
            (
                "missing template",
                lambda item: replace(item, request_templates=()),
            ),
            (
                "missing InputPoint",
                lambda item: replace(item, input_points=()),
            ),
            (
                "invalid statistics",
                lambda item: replace(
                    item,
                    crawl_statistics=replace(
                        item.crawl_statistics,
                        endpoint_count=99,
                    ),
                ),
            ),
        )
        for label, forge in invalid_components:
            with self.subTest(case=label):
                static = build_component(CollectorKind.NATIVE_STATIC)
                dynamic = forge(build_component(CollectorKind.NATIVE_DYNAMIC))
                with self.assertRaises(DiscoveryContractError):
                    merge_discovery_results(static, dynamic, POLICY)

        static = build_component(CollectorKind.NATIVE_STATIC)
        dynamic = build_component(CollectorKind.NATIVE_DYNAMIC)
        provenance = dynamic.crawl_provenance[0]
        object.__setattr__(
            provenance,
            "collector_kind",
            CollectorKind.NATIVE_STATIC,
        )
        object.__setattr__(provenance, "id", provenance._expected_id())
        with self.assertRaises(DiscoveryContractError):
            merge_discovery_results(static, dynamic, POLICY)

    def test_aggregate_rejects_unreviewed_provenance_kind(self) -> None:
        aggregate = merge_discovery_results(
            build_component(CollectorKind.NATIVE_STATIC),
            build_component(CollectorKind.NATIVE_DYNAMIC),
            POLICY,
        )
        provenance = aggregate.crawl_provenance[0]
        object.__setattr__(
            provenance,
            "collector_kind",
            CollectorKind.LEGACY_COMPATIBILITY,
        )
        object.__setattr__(provenance, "id", provenance._expected_id())

        with self.assertRaisesRegex(
            DiscoveryContractError,
            "unsupported collector",
        ):
            aggregate.validate()

    def test_warning_cardinality_is_producer_local_and_static_first(self) -> None:
        cases = (
            (
                "static only",
                (sensitive_warning(CollectorKind.NATIVE_STATIC),),
                (),
                (CollectorKind.NATIVE_STATIC.value,),
            ),
            (
                "dynamic only",
                (),
                (sensitive_warning(CollectorKind.NATIVE_DYNAMIC),),
                (CollectorKind.NATIVE_DYNAMIC.value,),
            ),
            (
                "both",
                (sensitive_warning(CollectorKind.NATIVE_STATIC),),
                (sensitive_warning(CollectorKind.NATIVE_DYNAMIC),),
                (
                    CollectorKind.NATIVE_STATIC.value,
                    CollectorKind.NATIVE_DYNAMIC.value,
                ),
            ),
        )
        for label, static_warnings, dynamic_warnings, expected in cases:
            with self.subTest(case=label):
                aggregate = merge_discovery_results(
                    build_component(
                        CollectorKind.NATIVE_STATIC,
                        warnings=static_warnings,
                    ),
                    build_component(
                        CollectorKind.NATIVE_DYNAMIC,
                        warnings=dynamic_warnings,
                    ),
                    POLICY,
                )
                sensitive = [
                    item
                    for item in aggregate.warnings
                    if item.code == "SENSITIVE_FORM_ELIDED"
                ]
                self.assertEqual(
                    tuple(
                        item.details["producer_kind"]
                        for item in sensitive
                    ),
                    expected,
                )

    def test_subject_free_warnings_are_attributed_and_static_first(self) -> None:
        static_warning = DiscoveryWarning(
            code="ZZZ_STATIC",
            message="static warning",
        )
        dynamic_warning = DiscoveryWarning(
            code="AAA_DYNAMIC",
            message="dynamic warning",
        )

        aggregate = merge_discovery_results(
            build_component(
                CollectorKind.NATIVE_STATIC,
                warnings=(static_warning,),
            ),
            build_component(
                CollectorKind.NATIVE_DYNAMIC,
                warnings=(dynamic_warning,),
            ),
            POLICY,
        )

        self.assertEqual(
            [item.code for item in aggregate.warnings],
            ["ZZZ_STATIC", "AAA_DYNAMIC"],
        )
        self.assertEqual(
            [
                item.details["producer_kind"]
                for item in aggregate.warnings
            ],
            [
                CollectorKind.NATIVE_STATIC.value,
                CollectorKind.NATIVE_DYNAMIC.value,
            ],
        )

    def test_identical_cross_producer_warnings_remain_distinct(self) -> None:
        warning = DiscoveryWarning(
            code="SAME_WARNING",
            message="same warning",
        )
        first = merge_discovery_results(
            build_component(
                CollectorKind.NATIVE_STATIC,
                warnings=(warning,),
            ),
            build_component(
                CollectorKind.NATIVE_DYNAMIC,
                warnings=(warning,),
            ),
            POLICY,
        )
        second = merge_discovery_results(
            build_component(
                CollectorKind.NATIVE_STATIC,
                warnings=(warning,),
            ),
            build_component(
                CollectorKind.NATIVE_DYNAMIC,
                warnings=(warning,),
            ),
            POLICY,
        )

        self.assertEqual(len(first.warnings), 2)
        self.assertEqual(len({item.id for item in first.warnings}), 2)
        self.assertEqual(
            [
                item.details["producer_kind"]
                for item in first.warnings
            ],
            [
                CollectorKind.NATIVE_STATIC.value,
                CollectorKind.NATIVE_DYNAMIC.value,
            ],
        )
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_conflicting_warning_producer_detail_fails_immutably(self) -> None:
        conflicting_warning = DiscoveryWarning(
            code="CONFLICTING_PRODUCER",
            message="safe warning",
            details={
                "producer_kind": CollectorKind.NATIVE_DYNAMIC.value,
            },
        )
        static = build_component(
            CollectorKind.NATIVE_STATIC,
            warnings=(conflicting_warning,),
        )
        static_snapshot = build_component(
            CollectorKind.NATIVE_STATIC,
            warnings=(conflicting_warning,),
        )
        dynamic = build_component(CollectorKind.NATIVE_DYNAMIC)
        dynamic_snapshot = build_component(CollectorKind.NATIVE_DYNAMIC)

        with self.assertRaisesRegex(
            DynamicIntegrityError,
            "Static warning producer attribution mismatch",
        ):
            merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(static, static_snapshot)
        self.assertEqual(dynamic, dynamic_snapshot)
        self.assertEqual(static.to_dict(), static_snapshot.to_dict())
        self.assertEqual(dynamic.to_dict(), dynamic_snapshot.to_dict())

    def test_unmarked_default_static_collision_fails_without_leak(self) -> None:
        secret = "PW_SENTINEL"
        static = extract_static_html(
            COLLISION_HTML,
            ROOT_URL,
        ).discovery
        static_snapshot = extract_static_html(
            COLLISION_HTML,
            ROOT_URL,
        ).discovery
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
        )
        dynamic_snapshot = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
        )
        q_point = next(
            item for item in static.input_points if item.name == "q"
        )

        self.assertEqual(static.safety_invariants, ())
        self.assertIsNone(q_point.type_hint)
        self.assertIn(secret, q_point.baseline_values)
        with self.assertRaises(DynamicIntegrityError) as caught:
            merge_discovery_results(static, dynamic, POLICY)

        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, repr(caught.exception))
        self.assertEqual(
            str(caught.exception),
            "Static: missing SENSITIVE_FORM_PRE_CANONICAL_ELISION",
        )
        self.assertEqual(static, static_snapshot)
        self.assertEqual(dynamic, dynamic_snapshot)
        self.assertEqual(static.to_dict(), static_snapshot.to_dict())
        self.assertEqual(dynamic.to_dict(), dynamic_snapshot.to_dict())

    def test_missing_dynamic_safety_marker_fails_before_merge(self) -> None:
        static = extract_static_html(
            COLLISION_HTML,
            ROOT_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        ).discovery
        static_snapshot = extract_static_html(
            COLLISION_HTML,
            ROOT_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        ).discovery
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
            safety_invariants=(),
        )
        dynamic_snapshot = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
            safety_invariants=(),
        )

        with self.assertRaises(DynamicIntegrityError) as caught:
            merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(
            str(caught.exception),
            "Dynamic: missing SENSITIVE_FORM_PRE_CANONICAL_ELISION",
        )
        self.assertEqual(static, static_snapshot)
        self.assertEqual(dynamic, dynamic_snapshot)
        self.assertEqual(static.to_dict(), static_snapshot.to_dict())
        self.assertEqual(dynamic.to_dict(), dynamic_snapshot.to_dict())

    def test_scope_integrity_failure_keeps_inputs_unchanged(self) -> None:
        static = build_component(CollectorKind.NATIVE_STATIC)
        static_snapshot = build_component(CollectorKind.NATIVE_STATIC)
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            scope=ALT_SCOPE,
        )
        dynamic_snapshot = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            scope=ALT_SCOPE,
        )

        with self.assertRaisesRegex(
            DynamicIntegrityError,
            "identical scope metadata",
        ):
            merge_discovery_results(static, dynamic, POLICY)

        self.assertEqual(static, static_snapshot)
        self.assertEqual(dynamic, dynamic_snapshot)
        self.assertEqual(static.to_dict(), static_snapshot.to_dict())
        self.assertEqual(dynamic.to_dict(), dynamic_snapshot.to_dict())

    def test_compatible_producer_scope_references_are_preserved(self) -> None:
        static_scope = replace(
            SCOPE,
            scope_decision_refs=("scope-decision:origin:static",),
        )
        dynamic_scope = replace(
            SCOPE,
            scope_decision_refs=("scope-decision:dynamic-authority:dynamic",),
        )

        aggregate = merge_discovery_results(
            build_component(CollectorKind.NATIVE_STATIC, scope=static_scope),
            build_component(CollectorKind.NATIVE_DYNAMIC, scope=dynamic_scope),
            POLICY,
        )

        self.assertEqual(
            aggregate.scope_metadata.scope_decision_refs,
            (
                "scope-decision:dynamic-authority:dynamic",
                "scope-decision:origin:static",
            ),
        )
        aggregate.validate()

    def test_multi_item_input_permutations_produce_equal_aggregates(self) -> None:
        static_specs = (
            ("/static-b", "b", "2"),
            ("/static-a", "a", "1"),
        )
        dynamic_specs = (
            ("/dynamic-b", "d", "4"),
            ("/dynamic-a", "c", "3"),
        )
        static_warnings = (
            DiscoveryWarning(code="ZZ_STATIC", message="static z"),
            DiscoveryWarning(code="AA_STATIC", message="static a"),
        )
        dynamic_warnings = (
            DiscoveryWarning(code="ZZ_DYNAMIC", message="dynamic z"),
            DiscoveryWarning(code="AA_DYNAMIC", message="dynamic a"),
        )
        static_first = build_multi_component(
            CollectorKind.NATIVE_STATIC,
            static_specs,
            warnings=static_warnings,
        )
        static_second = build_multi_component(
            CollectorKind.NATIVE_STATIC,
            tuple(reversed(static_specs)),
            warnings=tuple(reversed(static_warnings)),
        )
        dynamic_first = build_multi_component(
            CollectorKind.NATIVE_DYNAMIC,
            dynamic_specs,
            warnings=dynamic_warnings,
        )
        dynamic_second = build_multi_component(
            CollectorKind.NATIVE_DYNAMIC,
            tuple(reversed(dynamic_specs)),
            warnings=tuple(reversed(dynamic_warnings)),
        )

        first = merge_discovery_results(
            static_first,
            dynamic_first,
            POLICY,
        )
        second = merge_discovery_results(
            static_second,
            dynamic_second,
            POLICY,
        )

        self.assertEqual(static_first, static_second)
        self.assertEqual(dynamic_first, dynamic_second)
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.ready_contexts(), second.ready_contexts())
        self.assertEqual(first.crawl_statistics, second.crawl_statistics)
        self.assertEqual(
            [
                item.details["producer_kind"]
                for item in first.warnings
            ],
            [
                CollectorKind.NATIVE_STATIC.value,
                CollectorKind.NATIVE_STATIC.value,
                CollectorKind.NATIVE_DYNAMIC.value,
                CollectorKind.NATIVE_DYNAMIC.value,
            ],
        )
        self.assertEqual(first.warnings, second.warnings)

    def test_sensitive_collision_merge_keeps_only_safe_query(self) -> None:
        secret = "PW_SENTINEL"
        static = extract_static_html(
            COLLISION_HTML,
            ROOT_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )
        static_component = static.discovery
        static_snapshot = extract_static_html(
            COLLISION_HTML,
            ROOT_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        ).discovery
        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
        )
        dynamic_snapshot = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            path=None,
        )

        first = merge_discovery_results(static_component, dynamic, POLICY)
        second = merge_discovery_results(
            static_snapshot,
            dynamic_snapshot,
            POLICY,
        )

        q_points = [item for item in first.input_points if item.name == "q"]
        self.assertEqual(len(q_points), 1)
        self.assertEqual(q_points[0].baseline_values, ("safe",))
        self.assertEqual(q_points[0].metadata["raw_query_token"], "q=safe")
        form_templates = [
            item
            for item in first.request_templates
            if item.metadata.get("context_kind") == "form"
        ]
        self.assertEqual(form_templates, [])
        self.assertEqual(len(first.input_point_request_contexts), 1)
        self.assertEqual(
            static_component.safety_invariants,
            (SAFETY_INVARIANT,),
        )
        self.assertEqual(first.safety_invariants, (SAFETY_INVARIANT,))
        sensitive = [
            item
            for item in first.warnings
            if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(sensitive), 1)
        self.assertEqual(
            [
                item.details["producer_kind"]
                for item in sensitive
            ],
            [
                CollectorKind.NATIVE_STATIC.value,
            ],
        )
        serialized = json.dumps(first.to_dict(), sort_keys=True)
        self.assertNotIn(secret, serialized)
        self.assertNotIn(secret, repr(first))
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(static_component, static_snapshot)
        self.assertEqual(dynamic, dynamic_snapshot)
        self.assertEqual(
            static_component.to_dict(),
            static_snapshot.to_dict(),
        )
        self.assertEqual(dynamic.to_dict(), dynamic_snapshot.to_dict())
        first.validate()

    def test_statistics_follow_every_aggregate_formula(self) -> None:
        static_statistics = CrawlStatistics(
            requests_attempted=1,
            pages_processed=2,
            html_pages=2,
            links_discovered=3,
            forms_discovered=4,
            skipped=5,
            redirects_followed=1,
            max_depth_reached=2,
            request_budget=7,
            page_budget=8,
            depth_budget=3,
            elapsed_ms=11.5,
        )
        dynamic_statistics = CrawlStatistics(
            requests_attempted=2,
            pages_processed=3,
            html_pages=2,
            links_discovered=5,
            forms_discovered=6,
            skipped=7,
            redirects_followed=2,
            max_depth_reached=4,
            request_budget=9,
            page_budget=10,
            depth_budget=5,
            elapsed_ms=13.25,
        )
        aggregate = merge_discovery_results(
            build_component(
                CollectorKind.NATIVE_STATIC,
                path="/stats-static",
                statistics=static_statistics,
            ),
            build_component(
                CollectorKind.NATIVE_DYNAMIC,
                path="/stats-dynamic",
                statistics=dynamic_statistics,
            ),
            POLICY,
        )

        statistics = aggregate.crawl_statistics
        expected = {
            "requests_attempted": 3,
            "pages_processed": 5,
            "html_pages": 4,
            "links_discovered": 8,
            "forms_discovered": 10,
            "skipped": 12,
            "redirects_followed": 3,
            "max_depth_reached": 4,
            "request_budget": 16,
            "page_budget": 18,
            "depth_budget": 5,
            "elapsed_ms": 24.75,
            "endpoint_count": 2,
            "input_point_count": 2,
            "request_template_count": 2,
            "request_context_count": 2,
        }
        for field_name, expected_value in expected.items():
            with self.subTest(field=field_name):
                self.assertEqual(
                    getattr(statistics, field_name),
                    expected_value,
                )
        aggregate.validate()

    def test_wrong_component_kind_and_sensitive_point_fail_hard(self) -> None:
        static = build_component(CollectorKind.NATIVE_STATIC)
        dynamic = build_component(CollectorKind.NATIVE_DYNAMIC)
        with self.assertRaises(DynamicIntegrityError):
            merge_discovery_results(dynamic, static, POLICY)

        dynamic = build_component(
            CollectorKind.NATIVE_DYNAMIC,
            type_hint="password",
        )
        with self.assertRaisesRegex(
            DynamicIntegrityError,
            "structurally sensitive",
        ):
            merge_discovery_results(static, dynamic, POLICY)


if __name__ == "__main__":
    unittest.main()
