from __future__ import annotations

import json
import unittest

from vulnspider.discovery import (
    BACStaticHint,
    CanonicalDiscoveryResult,
    CollectorKind,
    CrawlStatistics,
    DiscoveryMetadata,
    DiscoveryProvenance,
    DiscoverySafetyInvariant,
    DiscoverySubjectKind,
    NonProbeReadyReason,
    ProbeReadiness,
    ProbeReadyStatus,
    ScopeMetadata,
    discovery_run_id_for,
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


def build_contract(
    *,
    reverse: bool = False,
    query_provenance: tuple[tuple[str, str], ...] = (("query", "raw-url"),),
    safety_invariants: tuple[DiscoverySafetyInvariant, ...] = (),
) -> CanonicalDiscoveryResult:
    root_url = "http://127.0.0.1:8080/"
    endpoint = Endpoint(
        HttpMethod.GET,
        "http",
        "127.0.0.1:8080",
        "/search",
        discovered_by="native_static",
    )
    first = InputPoint(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        location=InputLocation.QUERY,
        name="tag",
        occurrence_index=0,
        baseline_value="a",
        source_page=f"{root_url}search?tag=a&tag=a",
    )
    second = InputPoint(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        location=InputLocation.QUERY,
        name="tag",
        occurrence_index=1,
        baseline_value="a",
        source_page=f"{root_url}search?tag=a&tag=a",
    )
    template = RequestTemplate(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        method=HttpMethod.GET,
        url=f"{root_url}search?tag=a&tag=a",
        query=(("tag", "a"), ("tag", "a")),
        completeness=RequestContextCompleteness.COMPLETE,
        context_key="native-query",
        provenance=query_provenance,
    )
    first_context = InputPointRequestContext.from_objects(first, template)
    second_context = InputPointRequestContext.from_objects(second, template)
    children = (
        (first, second),
        (first_context, second_context),
    )
    points, contexts = (
        (tuple(reversed(children[0])), tuple(reversed(children[1])))
        if reverse
        else children
    )
    metadata = DiscoveryMetadata(
        collector_kind=CollectorKind.NATIVE_STATIC,
        collector_version="native-static-v1",
        configuration_fingerprint=stable_fingerprint("policy", 1),
    )
    scope = ScopeMetadata(
        target_scope_id=scope_id_for_root(root_url, policy_version="same-origin-v1"),
        root_url=root_url,
        scope_policy_version="same-origin-v1",
    )
    run_id = discovery_run_id_for(metadata, scope)
    provenance: list[DiscoveryProvenance] = []
    for kind, item in (
        (DiscoverySubjectKind.ENDPOINT, endpoint),
        (DiscoverySubjectKind.INPUT_POINT, first),
        (DiscoverySubjectKind.INPUT_POINT, second),
        (DiscoverySubjectKind.REQUEST_TEMPLATE, template),
        (DiscoverySubjectKind.REQUEST_CONTEXT, first_context),
        (DiscoverySubjectKind.REQUEST_CONTEXT, second_context),
    ):
        provenance.append(
            DiscoveryProvenance(
                discovery_run_id=run_id,
                subject_kind=kind,
                subject_id=item.id or "",
                collector_kind=CollectorKind.NATIVE_STATIC,
                source_url=template.url,
                collector_observation_key=f"{kind.value}:{item.id}",
            )
        )
    readiness = (
        ProbeReadiness(
            input_point_id=first.id or "",
            request_context_id=first_context.id,
            status=ProbeReadyStatus.READY,
        ),
        ProbeReadiness(
            input_point_id=second.id or "",
            request_context_id=second_context.id,
            status=ProbeReadyStatus.READY,
        ),
    )
    endpoint_provenance = next(
        item
        for item in provenance
        if item.subject_kind == DiscoverySubjectKind.ENDPOINT
    )
    hint = BACStaticHint(
        hint_kind="RESOURCE_IDENTIFIER",
        source_subject_kind=DiscoverySubjectKind.ENDPOINT,
        source_subject_id=endpoint.id or "",
        provenance_id=endpoint_provenance.id or "",
        evidence={"path": "/search"},
    )
    return CanonicalDiscoveryResult.create(
        discovery_metadata=metadata,
        scope_metadata=scope,
        crawl_statistics=CrawlStatistics(
            endpoint_count=1,
            input_point_count=2,
            request_template_count=1,
            request_context_count=2,
            request_budget=10,
            page_budget=10,
            depth_budget=2,
        ),
        endpoints=(endpoint,),
        input_points=points,
        request_templates=(template,),
        input_point_request_contexts=contexts,
        probe_readiness=tuple(reversed(readiness)) if reverse else readiness,
        crawl_provenance=tuple(reversed(provenance)) if reverse else provenance,
        bac_static_hints=(hint,),
        safety_invariants=safety_invariants,
    )


class CanonicalDiscoveryContractTests(unittest.TestCase):
    def test_aggregate_collector_and_authority_reason_are_canonical(self) -> None:
        self.assertEqual(
            CollectorKind.NATIVE_COMBINED.value,
            "NATIVE_COMBINED",
        )
        self.assertEqual(
            NonProbeReadyReason.REQUEST_NOT_AUTHORIZED.value,
            "REQUEST_NOT_AUTHORIZED",
        )
        self.assertEqual(
            DiscoverySafetyInvariant
            .SENSITIVE_FORM_PRE_CANONICAL_ELISION.value,
            "SENSITIVE_FORM_PRE_CANONICAL_ELISION",
        )

    def test_safety_invariant_is_canonical_and_additive(self) -> None:
        invariant = (
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION
        )
        default_result = build_contract()
        marked_result = build_contract(safety_invariants=(invariant,))

        self.assertEqual(default_result.safety_invariants, ())
        self.assertNotIn("safety_invariants", default_result.to_dict())
        self.assertEqual(marked_result.safety_invariants, (invariant,))
        self.assertEqual(
            marked_result.to_dict()["safety_invariants"],
            [invariant.value],
        )

    def test_duplicate_or_unknown_safety_invariant_is_rejected(self) -> None:
        invariant = (
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION
        )
        with self.assertRaisesRegex(ValueError, "unique"):
            build_contract(safety_invariants=(invariant, invariant))
        with self.assertRaisesRegex(ValueError, "known canonical"):
            build_contract(
                safety_invariants=("UNKNOWN",),  # type: ignore[arg-type]
            )

    def test_valid_contract_reuses_existing_models(self) -> None:
        result = build_contract()
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(len(result.input_points), 2)
        self.assertEqual(len(result.ready_contexts()), 2)
        self.assertTrue(all(isinstance(item, InputPoint) for item in result.input_points))

    def test_factory_canonicalizes_input_order(self) -> None:
        first = build_contract()
        second = build_contract(reverse=True)
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first.to_dict(), sort_keys=True),
            json.dumps(second.to_dict(), sort_keys=True),
        )

    def test_equal_repeated_occurrences_remain_distinct(self) -> None:
        result = build_contract()
        points = sorted(
            result.input_points,
            key=lambda item: item.occurrence_index if item.occurrence_index is not None else -1,
        )
        self.assertEqual(
            [(item.occurrence_index, item.baseline_value) for item in points],
            [(0, "a"), (1, "a")],
        )
        self.assertNotEqual(points[0].id, points[1].id)

    def test_bac_hint_is_not_owned_by_an_input_point(self) -> None:
        hint = build_contract().bac_static_hints[0]
        self.assertEqual(hint.source_subject_kind, DiscoverySubjectKind.ENDPOINT)
        self.assertNotIn("score", hint.evidence)

    def test_contract_metadata_rejects_mutable_legacy_object(self) -> None:
        class MutableLegacyObject:
            pass

        with self.assertRaisesRegex(ValueError, "unsupported object"):
            BACStaticHint(
                hint_kind="RESOURCE_IDENTIFIER",
                source_subject_kind=DiscoverySubjectKind.ENDPOINT,
                source_subject_id="ep",
                provenance_id="prov",
                evidence={"legacy": MutableLegacyObject()},
            )

    def test_request_template_snapshots_mutable_mappings(self) -> None:
        headers = {"X-Test": "one"}
        cookies = {"sid": "abc"}
        metadata = {"nested": {"value": "original"}}
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/",
            headers=headers,
            cookies=cookies,
            metadata=metadata,
        )
        headers["X-Test"] = "changed"
        cookies["sid"] = "changed"
        metadata["nested"]["value"] = "changed"
        self.assertEqual(template.headers["X-Test"], "one")
        self.assertEqual(template.cookies["sid"], "abc")
        self.assertEqual(template.metadata["nested"]["value"], "original")
        with self.assertRaises(TypeError):
            template.headers["New"] = "value"  # type: ignore[index]

    def test_request_template_rejects_non_string_header_and_cookie_values(
        self,
    ) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/")
        with self.assertRaisesRegex(TypeError, "headers.*strings"):
            RequestTemplate(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                method=HttpMethod.GET,
                url="http://127.0.0.1/",
                headers={"X-Values": []},  # type: ignore[dict-item]
            )
        with self.assertRaisesRegex(TypeError, "cookies.*strings"):
            RequestTemplate(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                method=HttpMethod.GET,
                url="http://127.0.0.1/",
                cookies={"sid": {"value": "abc"}},  # type: ignore[dict-item]
            )

    def test_scope_metadata_snapshots_and_orders_valid_references(self) -> None:
        root_url = "http://127.0.0.1:8080/"
        refs = ["scope-decision:root", "scope-decision:redirect"]
        scope = ScopeMetadata(
            target_scope_id=scope_id_for_root(
                root_url,
                policy_version="same-origin-v1",
            ),
            root_url=root_url,
            scope_policy_version="same-origin-v1",
            scope_decision_refs=refs,  # type: ignore[arg-type]
        )
        refs.append("scope-decision:mutated")
        self.assertEqual(
            scope.scope_decision_refs,
            ("scope-decision:redirect", "scope-decision:root"),
        )
        build_contract().validate()


if __name__ == "__main__":
    unittest.main()
