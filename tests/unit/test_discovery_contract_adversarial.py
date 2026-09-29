from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType, SimpleNamespace
import unittest

from tests.unit.test_discovery_contract import build_contract
from vulnspider.discovery import (
    BACStaticHint,
    CanonicalDiscoveryResult,
    CollectorKind,
    CrawlStatistics,
    DiscoveryContractError,
    DiscoveryProvenance,
    DiscoverySubjectKind,
    DiscoveryWarning,
    NonProbeReadyReason,
    ProbeReadiness,
    ProbeReadyStatus,
    ScopeMetadata,
    discovery_run_id_for,
)
from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    RequestContextCompleteness,
    RequestTemplate,
)


def build_form_contract(
    *,
    template_provenance: tuple[tuple[str, str], ...],
    template_metadata: dict[str, str],
) -> CanonicalDiscoveryResult:
    base = build_contract()
    endpoint = Endpoint(
        HttpMethod.POST,
        "http",
        "127.0.0.1:8080",
        "/submit",
        discovered_by="native_static",
    )
    point = InputPoint(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        location=InputLocation.FORM,
        name="token",
        baseline_value="abc",
        type_hint="hidden",
        source_page="http://127.0.0.1:8080/form",
    )
    template = RequestTemplate(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        method=HttpMethod.POST,
        url="http://127.0.0.1:8080/submit",
        form=(("token", "abc"),),
        completeness=RequestContextCompleteness.COMPLETE,
        context_key="native-form",
        provenance=template_provenance,
        metadata=template_metadata,
    )
    context = InputPointRequestContext.from_objects(point, template)
    provenance = tuple(
        DiscoveryProvenance(
            discovery_run_id=base.discovery_run_id,
            subject_kind=kind,
            subject_id=item.id or "",
            collector_kind=CollectorKind.NATIVE_STATIC,
            source_url="http://127.0.0.1:8080/form",
            collector_observation_key=f"{kind.value}:{item.id}",
        )
        for kind, item in (
            (DiscoverySubjectKind.ENDPOINT, endpoint),
            (DiscoverySubjectKind.INPUT_POINT, point),
            (DiscoverySubjectKind.REQUEST_TEMPLATE, template),
            (DiscoverySubjectKind.REQUEST_CONTEXT, context),
        )
    )
    return CanonicalDiscoveryResult.create(
        discovery_metadata=base.discovery_metadata,
        scope_metadata=base.scope_metadata,
        crawl_statistics=CrawlStatistics(
            endpoint_count=1,
            input_point_count=1,
            request_template_count=1,
            request_context_count=1,
            request_budget=10,
            page_budget=10,
            depth_budget=2,
        ),
        endpoints=(endpoint,),
        input_points=(point,),
        request_templates=(template,),
        input_point_request_contexts=(context,),
        probe_readiness=(
            ProbeReadiness(
                input_point_id=point.id or "",
                request_context_id=context.id,
                status=ProbeReadyStatus.READY,
            ),
        ),
        crawl_provenance=provenance,
    )


class CanonicalDiscoveryAdversarialTests(unittest.TestCase):
    def test_rejects_input_template_ownership_mismatch(self) -> None:
        result = build_contract()
        point = result.input_points[0]
        other_endpoint = Endpoint(
            HttpMethod.GET,
            "http",
            "127.0.0.1:8080",
            "/other",
        )
        forged = replace(
            point,
            endpoint_id=other_endpoint.id or "",
            endpoint_fingerprint=other_endpoint.fingerprint,
        )
        with self.assertRaises(DiscoveryContractError):
            CanonicalDiscoveryResult.create(
                discovery_metadata=result.discovery_metadata,
                scope_metadata=result.scope_metadata,
                crawl_statistics=result.crawl_statistics,
                endpoints=result.endpoints,
                input_points=(forged, result.input_points[1]),
                request_templates=result.request_templates,
                input_point_request_contexts=result.input_point_request_contexts,
                probe_readiness=result.probe_readiness,
                crawl_provenance=result.crawl_provenance,
            )

    def test_rejects_endpoint_fingerprint_mismatch(self) -> None:
        result = build_contract()
        endpoint = result.endpoints[0]
        object.__setattr__(endpoint, "fingerprint", "wrong")
        with self.assertRaisesRegex(DiscoveryContractError, "fingerprint"):
            result.validate()

    def test_rejects_missing_child_reference(self) -> None:
        result = build_contract()
        forged_context = object.__new__(type(result.input_point_request_contexts[0]))
        object.__setattr__(forged_context, "input_point_id", "inp_missing")
        object.__setattr__(
            forged_context,
            "request_template_id",
            result.request_templates[0].id,
        )
        object.__setattr__(forged_context, "role", "baseline")
        object.__setattr__(forged_context, "id", "ipctx_missing")
        with self.assertRaisesRegex(DiscoveryContractError, "missing child"):
            CanonicalDiscoveryResult.create(
                discovery_metadata=result.discovery_metadata,
                scope_metadata=result.scope_metadata,
                crawl_statistics=replace(
                    result.crawl_statistics,
                    request_context_count=1,
                ),
                endpoints=result.endpoints,
                input_points=result.input_points,
                request_templates=result.request_templates,
                input_point_request_contexts=(forged_context,),
                probe_readiness=result.probe_readiness,
                crawl_provenance=result.crawl_provenance,
            )

    def test_rejects_ready_without_context(self) -> None:
        with self.assertRaisesRegex(DiscoveryContractError, "requires a request context"):
            ProbeReadiness(
                input_point_id="inp",
                request_context_id=None,
                status=ProbeReadyStatus.READY,
            )

    def test_rejects_not_ready_without_reason(self) -> None:
        result = build_contract()
        forged = ProbeReadiness(
            input_point_id=result.input_points[0].id or "",
            request_context_id=result.input_point_request_contexts[0].id,
            status=ProbeReadyStatus.NOT_READY,
            reasons=(NonProbeReadyReason.REQUEST_CONTEXT_PARTIAL,),
        )
        object.__setattr__(forged, "reasons", ())
        object.__setattr__(forged, "id", forged._expected_id())
        replaced = replace(
            result,
            probe_readiness=(forged, result.probe_readiness[1]),
        )
        with self.assertRaisesRegex(DiscoveryContractError, "requires a reason"):
            replaced.validate()

    def test_rejects_duplicate_stable_identity(self) -> None:
        result = build_contract()
        with self.assertRaisesRegex(DiscoveryContractError, "duplicate InputPoint"):
            CanonicalDiscoveryResult.create(
                discovery_metadata=result.discovery_metadata,
                scope_metadata=result.scope_metadata,
                crawl_statistics=replace(
                    result.crawl_statistics,
                    input_point_count=3,
                ),
                endpoints=result.endpoints,
                input_points=(*result.input_points, result.input_points[0]),
                request_templates=result.request_templates,
                input_point_request_contexts=result.input_point_request_contexts,
                probe_readiness=result.probe_readiness,
                crawl_provenance=result.crawl_provenance,
            )

    def test_rejects_nondeterministic_forged_ordering(self) -> None:
        result = build_contract()
        forged = replace(result, input_points=tuple(reversed(result.input_points)))
        with self.assertRaisesRegex(DiscoveryContractError, "ordering"):
            forged.validate()

    def test_rejects_request_template_content_mutation(self) -> None:
        result = build_contract()
        template = result.request_templates[0]
        object.__setattr__(template, "headers", {"X-Changed": "yes"})
        with self.assertRaisesRegex(DiscoveryContractError, "fingerprint"):
            result.validate()

    def test_rejects_probe_ready_raw_query_mismatch(self) -> None:
        result = build_contract()
        point = result.input_points[0]
        endpoint = result.endpoints[0]
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1:8080/search?tag=a&tag=b",
            query=(("tag", "a"), ("tag", "a")),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        with self.assertRaisesRegex(DiscoveryContractError, "raw query"):
            result._validate_ready_template(point, template)

    def test_rejects_probe_ready_query_without_raw_provenance(self) -> None:
        with self.assertRaisesRegex(DiscoveryContractError, "raw query provenance"):
            build_contract(query_provenance=())

    def test_rejects_probe_ready_untrusted_form_provenance(self) -> None:
        result = build_contract()
        endpoint = Endpoint(
            HttpMethod.POST,
            "http",
            "127.0.0.1:8080",
            "/submit",
        )
        point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.FORM,
            name="q",
            baseline_value="x",
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1:8080/submit",
            form=(("q", "x"),),
            completeness=RequestContextCompleteness.COMPLETE,
            provenance=(
                ("form_method", "unknown_assumed_get"),
                ("form_action", "unknown_assumed_current_page"),
            ),
        )
        with self.assertRaisesRegex(DiscoveryContractError, "not trusted"):
            result._validate_ready_template(point, template)

    def test_rejects_probe_ready_form_without_stable_boundary(self) -> None:
        provenance = (
            ("form_method", "explicit"),
            ("form_action", "explicit"),
            ("form_boundary", "unavailable"),
            ("form_controls", "complete"),
        )
        with self.assertRaisesRegex(DiscoveryContractError, "stable boundary"):
            build_form_contract(
                template_provenance=provenance,
                template_metadata={
                    "form_boundary_status": "stable",
                    "hidden_input_policy": (
                        "native_all_successful_controls_preserved"
                    ),
                },
            )

    def test_rejects_probe_ready_form_without_hidden_input_evidence(self) -> None:
        provenance = (
            ("form_method", "explicit"),
            ("form_action", "explicit"),
            ("form_boundary", "stable"),
            ("form_controls", "complete"),
        )
        with self.assertRaisesRegex(DiscoveryContractError, "hidden-input"):
            build_form_contract(
                template_provenance=provenance,
                template_metadata={
                    "form_boundary_status": "stable",
                    "hidden_input_policy": "unavailable",
                },
            )

    def test_rejects_not_ready_context_ownership_mismatch(self) -> None:
        result = build_contract()
        first_point = result.input_points[0]
        other_context = next(
            item
            for item in result.input_point_request_contexts
            if item.input_point_id != first_point.id
        )
        forged = ProbeReadiness(
            input_point_id=first_point.id or "",
            request_context_id=other_context.id,
            status=ProbeReadyStatus.NOT_READY,
            reasons=(NonProbeReadyReason.REQUEST_CONTEXT_PARTIAL,),
        )
        statuses = tuple(
            forged if item.input_point_id == first_point.id else item
            for item in result.probe_readiness
        )
        with self.assertRaisesRegex(DiscoveryContractError, "ownership"):
            replace(result, probe_readiness=statuses).validate()

    def test_rejects_bac_hint_provenance_ownership_mismatch(self) -> None:
        result = build_contract()
        point = result.input_points[0]
        endpoint_provenance = next(
            item
            for item in result.crawl_provenance
            if item.subject_kind == DiscoverySubjectKind.ENDPOINT
        )
        forged = BACStaticHint(
            hint_kind="RESOURCE_IDENTIFIER",
            source_subject_kind=DiscoverySubjectKind.INPUT_POINT,
            source_subject_id=point.id or "",
            provenance_id=endpoint_provenance.id or "",
            evidence={"name": point.name},
        )
        with self.assertRaisesRegex(DiscoveryContractError, "ownership"):
            replace(result, bac_static_hints=(forged,)).validate()

    def test_rejects_provenance_from_another_run(self) -> None:
        result = build_contract()
        item = result.crawl_provenance[0]
        object.__setattr__(item, "discovery_run_id", "discovery_other")
        object.__setattr__(item, "id", item._expected_id())
        with self.assertRaisesRegex(DiscoveryContractError, "discovery run"):
            result.validate()

    def test_rejects_mixed_provenance_outside_aggregate_result(self) -> None:
        result = build_contract()
        item = result.crawl_provenance[0]
        object.__setattr__(item, "collector_kind", CollectorKind.NATIVE_DYNAMIC)
        object.__setattr__(item, "id", item._expected_id())
        with self.assertRaisesRegex(DiscoveryContractError, "collector kind"):
            result.validate()

    def test_rejects_stale_contract_owned_record_ids(self) -> None:
        mutations = (
            ("provenance", "crawl_provenance", "source_url", "http://changed/"),
            (
                "readiness",
                "probe_readiness",
                "request_context_id",
                "ipctx_changed",
            ),
            ("BAC hint", "bac_static_hints", "hint_kind", "CHANGED"),
        )
        for label, collection_name, field_name, value in mutations:
            with self.subTest(record=label):
                result = build_contract()
                item = getattr(result, collection_name)[0]
                object.__setattr__(item, field_name, value)
                with self.assertRaisesRegex(DiscoveryContractError, "id"):
                    result.validate()

        result = build_contract()
        warning = DiscoveryWarning(code="NOTICE", message="notice", details={"n": 1})
        with_warning = replace(result, warnings=(warning,))
        object.__setattr__(warning, "details", MappingProxyType({"n": 2}))
        with self.assertRaisesRegex(DiscoveryContractError, "id"):
            with_warning.validate()

    def test_rejects_forged_scope_identity(self) -> None:
        result = build_contract()
        with self.assertRaisesRegex(DiscoveryContractError, "target_scope_id"):
            ScopeMetadata(
                target_scope_id="scope_forged",
                root_url=result.scope_metadata.root_url,
                scope_policy_version=result.scope_metadata.scope_policy_version,
            )

    def test_rejects_non_string_scope_decision_reference(self) -> None:
        result = build_contract()
        with self.assertRaisesRegex(DiscoveryContractError, "only strings"):
            ScopeMetadata(
                target_scope_id=result.scope_metadata.target_scope_id,
                root_url=result.scope_metadata.root_url,
                scope_policy_version=result.scope_metadata.scope_policy_version,
                scope_decision_refs=(SimpleNamespace(),),  # type: ignore[arg-type]
            )

    def test_rejects_mutated_scope_refs_with_recomputed_run_id(self) -> None:
        result = build_contract()
        object.__setattr__(
            result.scope_metadata,
            "scope_decision_refs",
            (SimpleNamespace(),),
        )
        object.__setattr__(
            result,
            "discovery_run_id",
            discovery_run_id_for(
                result.discovery_metadata,
                result.scope_metadata,
            ),
        )
        with self.assertRaisesRegex(DiscoveryContractError, "scope_decision_refs"):
            result.validate()

    def test_rejects_empty_or_duplicate_scope_decision_references(self) -> None:
        result = build_contract()
        for refs in (("",), ("scope-decision:root", "scope-decision:root")):
            with self.subTest(refs=refs):
                with self.assertRaises(DiscoveryContractError):
                    ScopeMetadata(
                        target_scope_id=result.scope_metadata.target_scope_id,
                        root_url=result.scope_metadata.root_url,
                        scope_policy_version=(
                            result.scope_metadata.scope_policy_version
                        ),
                        scope_decision_refs=refs,
                    )

    def test_rejects_negative_provenance_depth_with_recomputed_id(self) -> None:
        result = build_contract()
        item = result.crawl_provenance[0]
        object.__setattr__(item, "depth", -1)
        object.__setattr__(item, "id", item._expected_id())
        with self.assertRaisesRegex(DiscoveryContractError, "depth"):
            result.validate()

    def test_rejects_bac_decision_fields_with_recomputed_id(self) -> None:
        forbidden_evidence = (
            {"vulnerability_score": 0.9},
            {"confidence": "HIGH"},
            {"ranking_priority": 1},
            {"finding_status": "CONFIRMED"},
            {"finding_decision": "CONFIRMED"},
            {"finding-decision": "CONFIRMED"},
            {"bac_scorer_maximum": 10},
            {"global_top_k_selected": True},
        )
        for evidence in forbidden_evidence:
            with self.subTest(evidence=evidence):
                result = build_contract()
                hint = result.bac_static_hints[0]
                object.__setattr__(
                    hint,
                    "evidence",
                    MappingProxyType(evidence),
                )
                object.__setattr__(hint, "id", hint._expected_id())
                with self.assertRaisesRegex(
                    DiscoveryContractError,
                    "scoring|ranking|decision",
                ):
                    result.validate()

    def test_rejects_other_mutated_semantics_with_recomputed_ids(self) -> None:
        result = build_contract()
        readiness = result.probe_readiness[0]
        object.__setattr__(readiness, "status", ProbeReadyStatus.NOT_READY)
        object.__setattr__(
            readiness,
            "reasons",
            (
                NonProbeReadyReason.REQUEST_CONTEXT_PARTIAL,
                NonProbeReadyReason.REQUEST_CONTEXT_PARTIAL,
            ),
        )
        object.__setattr__(readiness, "id", readiness._expected_id())
        with self.assertRaisesRegex(DiscoveryContractError, "unique"):
            result.validate()

        result = build_contract()
        warning = DiscoveryWarning(code="NOTICE", message="notice")
        forged = replace(result, warnings=(warning,))
        object.__setattr__(warning, "code", "")
        object.__setattr__(warning, "id", warning._expected_id())
        with self.assertRaisesRegex(DiscoveryContractError, "warning code"):
            forged.validate()

    def test_rejects_non_integer_crawl_statistics(self) -> None:
        for value in (0.5, True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(DiscoveryContractError, "integers"):
                    CrawlStatistics(
                        requests_attempted=value,  # type: ignore[arg-type]
                    ).validate()

    def test_rejects_more_html_pages_than_processed_pages(self) -> None:
        with self.assertRaisesRegex(
            DiscoveryContractError,
            "HTML pages",
        ):
            CrawlStatistics(
                pages_processed=1,
                html_pages=2,
            ).validate()

    def test_rejects_top_level_custom_object(self) -> None:
        result = build_contract()
        fake_endpoint = SimpleNamespace(
            id=result.endpoints[0].id,
            fingerprint=result.endpoints[0].fingerprint,
        )
        with self.assertRaisesRegex(DiscoveryContractError, "canonical Endpoint"):
            CanonicalDiscoveryResult.create(
                discovery_metadata=result.discovery_metadata,
                scope_metadata=result.scope_metadata,
                crawl_statistics=result.crawl_statistics,
                endpoints=(fake_endpoint,),  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
