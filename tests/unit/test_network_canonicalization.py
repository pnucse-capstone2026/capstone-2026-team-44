from __future__ import annotations

import pickle
import unittest

from vulnspider.discovery import (
    BlockedPostJsonCandidate,
    CollectorKind,
    CombinedDiscoveryResult,
    DiscoveryMergePolicy,
    DiscoveryMetadata,
    DynamicCrawlCompletion,
    DynamicCrawlResult,
    DynamicCrawlTerminationReason,
    NetworkDiscoveryCandidate,
    NetworkDiscoveryCollection,
    NetworkDiscoveryDisposition,
    NetworkDiscoveryElisionReason,
    NonProbeReadyReason,
    PostJsonSkipReason,
    ProbeReadyStatus,
    ScopeMetadata,
    canonicalize_network_discovery,
    discovery_snapshot_id_for,
    extract_static_html_with_sensitive_form_elision,
    merge_discovery_results,
    scope_id_for_root,
)
from vulnspider.discovery import dynamic_browser as browser_module
from vulnspider.discovery.post_replay_policy import PostReplayDisposition
from vulnspider.domain import (
    HttpMethod,
    InputLocation,
    validate_input_point_request_context,
)
from vulnspider.observation import ProbePlanner, TransportResponse
from vulnspider.pipeline import analyze_discovery_result
from vulnspider.reporting import build_crawl_report


ROOT = "http://127.0.0.1:8080/"
ORIGIN = ("http", "127.0.0.1", 8080)


def _metadata(kind: CollectorKind) -> DiscoveryMetadata:
    return DiscoveryMetadata(
        collector_kind=kind,
        collector_version=f"test-{kind.value.lower()}/1",
        configuration_fingerprint=f"config-{kind.value.lower()}",
    )


def _scope() -> ScopeMetadata:
    return ScopeMetadata(
        target_scope_id=scope_id_for_root(
            ROOT,
            policy_version="same-origin-v1",
        ),
        root_url=ROOT,
        scope_policy_version="same-origin-v1",
    )


def _candidate(
    url: str,
    *,
    resource_type: str = "fetch",
    credential_header_present: bool = False,
):
    candidate, reason = browser_module._safe_network_discovery_candidate(
        method="GET",
        url=url,
        resource_type=resource_type,
        source_url=ROOT,
        root_origin=ORIGIN,
        credential_header_present=credential_header_present,
    )
    if reason is not None:
        raise AssertionError(reason)
    if candidate is None:
        raise AssertionError("expected a network discovery candidate")
    return candidate


def _canonical(*candidates):
    components = canonicalize_network_discovery(
        NetworkDiscoveryCollection(candidates=tuple(candidates)),
        discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
        scope_metadata=_scope(),
    )
    if len(components) != 1:
        raise AssertionError("expected one source-page component")
    return components[0]


def _post_candidate(
    body: bytes,
    *,
    url: str = "http://127.0.0.1:8080/api/search",
    resource_type: str = "fetch",
    content_type: str = "application/json; charset=UTF-8",
    credential_header_present: bool = False,
) -> BlockedPostJsonCandidate:
    candidate, _replay_material, reason = (
        browser_module._safe_blocked_post_json_candidate(
            method="POST",
            url=url,
            resource_type=resource_type,
            source_url=ROOT,
            root_origin=ORIGIN,
            content_type=content_type,
            credential_header_present=credential_header_present,
            body=body,
        )
    )
    if reason is not None:
        raise AssertionError(reason)
    if candidate is None:
        raise AssertionError("expected a POST JSON candidate")
    return candidate


def _post_capture(
    body: bytes,
    *,
    url: str = "http://127.0.0.1:8080/api/search",
    resource_type: str = "fetch",
    content_type: str = "application/json; charset=UTF-8",
):
    candidate, replay_material, reason = (
        browser_module._safe_blocked_post_json_candidate(
            method="POST",
            url=url,
            resource_type=resource_type,
            source_url=ROOT,
            root_origin=ORIGIN,
            content_type=content_type,
            credential_header_present=False,
            body=body,
        )
    )
    if reason is not None:
        raise AssertionError(reason)
    if candidate is None or replay_material is None:
        raise AssertionError("expected POST structure and replay material")
    return candidate, replay_material


def _canonical_post(*candidates, replay_materials=(), skipped_counts=()):
    components = canonicalize_network_discovery(
        NetworkDiscoveryCollection(
            post_json_candidates=tuple(candidates),
            post_json_replay_materials=tuple(replay_materials),
            post_json_skipped_counts=tuple(skipped_counts),
        ),
        discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
        scope_metadata=_scope(),
    )
    if len(components) != 1:
        raise AssertionError("expected one source-page component")
    return components[0]


class NetworkCanonicalizationTests(unittest.TestCase):
    def test_route_guard_collects_only_authority_allowed_primary_get(self) -> None:
        class Page:
            url = ROOT

        class Frame:
            page = Page()
            parent_frame = None

        class Request:
            frame = Frame()

            def __init__(self, method, url, resource_type, headers=None):
                self.method = method
                self.url = url
                self.resource_type = resource_type
                self._headers = headers or {}

            def all_headers(self):
                return dict(self._headers)

        class Response:
            status = 200
            headers = {}

            def dispose(self):
                return None

        class Route:
            def __init__(self):
                self.fetch_count = 0
                self.fulfill_count = 0
                self.abort_count = 0

            def fetch(self, **_kwargs):
                self.fetch_count += 1
                return Response()

            def fulfill(self, **_kwargs):
                self.fulfill_count += 1

            def abort(self, **_kwargs):
                self.abort_count += 1

        authority = browser_module.DynamicRequestAuthority(
            ROOT,
            allow_passive_same_origin_fetch_xhr=True,
        )
        audit = browser_module._AuditRecorder(event_limit=16)
        network = browser_module._NetworkDiscoveryRecorder(candidate_limit=16)
        guard = browser_module._RouteGuard(
            authority,
            browser_module.DynamicBrowserPolicy(request_decision_budget=16),
            audit,
            lambda: None,
            network_discovery=network,
        )
        guard.set_primary_page(Frame.page)

        allowed = Route()
        guard.handle_http(
            allowed,
            Request(
                "GET",
                "http://127.0.0.1:8080/api/search?q=phone",
                "fetch",
            ),
        )
        guard.handle_http(
            Route(),
            Request("HEAD", "http://127.0.0.1:8080/api/head?q=1", "fetch"),
        )
        guard.handle_http(
            Route(),
            Request("POST", "http://127.0.0.1:8080/api/post?q=1", "fetch"),
        )
        guard.handle_http(
            Route(),
            Request("GET", "http://127.0.0.1:8081/api/off?q=1", "xhr"),
        )
        header_secret = "ROUTE_HEADER_SECRET_SENTINEL"
        guard.handle_http(
            Route(),
            Request(
                "GET",
                "http://127.0.0.1:8080/api/private?page=1",
                "xhr",
                {"Authorization": f"Bearer {header_secret}"},
            ),
        )

        collection = network.snapshot()
        self.assertEqual(allowed.fetch_count, 1)
        self.assertEqual(len(collection.candidates), 2)
        self.assertEqual(
            {item.base_url for item in collection.candidates},
            {
                "http://127.0.0.1:8080/api/search",
                "http://127.0.0.1:8080/api/private",
            },
        )
        private = next(
            item for item in collection.candidates if item.base_url.endswith("/private")
        )
        self.assertEqual(
            private.disposition,
            NetworkDiscoveryDisposition.STRUCTURAL_ELIDED,
        )
        self.assertNotIn(header_secret, repr(collection))
        self.assertNotIn(header_secret.encode(), pickle.dumps(collection, protocol=5))

        blocked_network = browser_module._NetworkDiscoveryRecorder(candidate_limit=4)
        blocked_guard = browser_module._RouteGuard(
            browser_module.DynamicRequestAuthority(ROOT),
            browser_module.DynamicBrowserPolicy(request_decision_budget=4),
            browser_module._AuditRecorder(event_limit=4),
            lambda: None,
            network_discovery=blocked_network,
        )
        blocked_guard.set_primary_page(Frame.page)
        blocked_route = Route()
        blocked_guard.handle_http(
            blocked_route,
            Request(
                "GET",
                "http://127.0.0.1:8080/api/blocked?q=1",
                "fetch",
            ),
        )
        self.assertEqual(blocked_route.abort_count, 1)
        self.assertEqual(blocked_network.snapshot().candidates, ())

    def test_safe_fetch_builds_endpoint_points_template_and_contexts(self) -> None:
        result = _canonical(
            _candidate(
                "http://127.0.0.1:8080/api/search"
                "?keyword=phone&page=1&tag=a&tag=b"
            )
        )

        endpoint = next(item for item in result.endpoints if item.path == "/api/search")
        self.assertEqual(endpoint.discovered_by, "native_dynamic_network")
        points = sorted(
            (item for item in result.input_points if item.endpoint_id == endpoint.id),
            key=lambda item: (
                item.name,
                -1 if item.occurrence_index is None else item.occurrence_index,
            ),
        )
        self.assertEqual(
            [(item.name, item.occurrence_index) for item in points],
            [("keyword", None), ("page", None), ("tag", 0), ("tag", 1)],
        )
        self.assertTrue(
            all("network_fetch" in item.metadata["origin_kinds"] for item in points)
        )
        template = result.request_templates[0]
        self.assertEqual(
            template.query,
            (("keyword", "phone"), ("page", "1"), ("tag", "a"), ("tag", "b")),
        )
        self.assertEqual(template.headers, {})
        self.assertEqual(template.cookies, {})
        contexts = {item.input_point_id: item for item in result.input_point_request_contexts}
        for point in points:
            context = contexts[point.id or ""]
            self.assertEqual(context.request_template_id, template.id)
            validate_input_point_request_context(point, template)
        self.assertTrue(
            all(item.status == ProbeReadyStatus.READY for item in result.probe_readiness)
        )

    def test_safe_xhr_uses_the_same_canonical_contract(self) -> None:
        result = _canonical(
            _candidate(
                "http://127.0.0.1:8080/api/filter?category=book&tag=a&tag=b",
                resource_type="xhr",
            )
        )
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(len(result.input_points), 3)
        self.assertTrue(
            all(
                "network_xhr" in item.metadata["origin_kinds"]
                for item in result.input_points
            )
        )
        self.assertEqual(len(result.ready_contexts()), 3)

    def test_candidate_event_order_and_duplicates_are_deterministic(self) -> None:
        first = _candidate("http://127.0.0.1:8080/api/a?x=1")
        second = _candidate(
            "http://127.0.0.1:8080/api/b?y=2",
            resource_type="xhr",
        )
        forward = canonicalize_network_discovery(
            NetworkDiscoveryCollection(candidates=(first, second)),
            discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
            scope_metadata=_scope(),
        )
        reverse = canonicalize_network_discovery(
            NetworkDiscoveryCollection(candidates=(second, first)),
            discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
            scope_metadata=_scope(),
        )
        self.assertEqual(forward, reverse)
        self.assertEqual(
            discovery_snapshot_id_for(forward[0].to_dict()),
            discovery_snapshot_id_for(reverse[0].to_dict()),
        )
        recorder = browser_module._NetworkDiscoveryRecorder(candidate_limit=4)
        for _ in range(2):
            recorder.record_allowed_get(
                method="GET",
                url="http://127.0.0.1:8080/api/a?x=1",
                resource_type="fetch",
                source_url=ROOT,
                root_origin=ORIGIN,
                credential_header_present=False,
            )
        self.assertEqual(len(recorder.snapshot().candidates), 1)

    def test_query_order_preserves_pairs_but_not_endpoint_or_input_identity(self) -> None:
        first = _canonical(
            _candidate("http://127.0.0.1:8080/api/search?keyword=phone&page=1")
        )
        second = _canonical(
            _candidate("http://127.0.0.1:8080/api/search?page=1&keyword=phone")
        )
        self.assertEqual(first.endpoints[0].id, second.endpoints[0].id)
        self.assertEqual(
            {item.id for item in first.input_points},
            {item.id for item in second.input_points},
        )
        self.assertNotEqual(first.request_templates[0].id, second.request_templates[0].id)
        self.assertEqual(
            second.request_templates[0].query,
            (("page", "1"), ("keyword", "phone")),
        )

    def test_sensitive_query_and_credential_header_are_structural_only(self) -> None:
        query_secret = "QUERY_SECRET_SENTINEL"
        header_secret = "HEADER_SECRET_SENTINEL"
        sensitive = _candidate(
            f"http://127.0.0.1:8080/api/private?token={query_secret}&page=1",
            credential_header_present=True,
        )
        self.assertEqual(
            sensitive.disposition,
            NetworkDiscoveryDisposition.STRUCTURAL_ELIDED,
        )
        self.assertNotIn(query_secret, repr(sensitive))
        self.assertNotIn(header_secret, repr(sensitive))
        self.assertNotIn(query_secret.encode(), pickle.dumps(sensitive, protocol=5))
        self.assertNotIn(header_secret.encode(), pickle.dumps(sensitive, protocol=5))

        result = _canonical(sensitive)
        payload = repr(result.to_dict())
        self.assertNotIn(query_secret, payload)
        self.assertNotIn(header_secret, payload)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(
            [(item.name, item.baseline_value) for item in result.input_points],
            [("page", None), ("token", None)],
        )
        self.assertEqual(result.request_templates, ())
        self.assertEqual(result.input_point_request_contexts, ())
        self.assertTrue(
            all(item.status == ProbeReadyStatus.NOT_READY for item in result.probe_readiness)
        )
        warning = next(
            item for item in result.warnings if item.code == "NETWORK_GET_VALUES_ELIDED"
        )
        self.assertEqual(warning.details["elided_candidate_count"], 1)
        self.assertEqual(warning.details["structural_candidate_count"], 1)
        self.assertEqual(warning.details["audit_only_candidate_count"], 0)

    def test_credential_request_without_query_is_audit_only_with_count(self) -> None:
        result = _canonical(
            _candidate(
                "http://127.0.0.1:8080/api/private",
                credential_header_present=True,
            )
        )
        self.assertEqual(result.endpoints, ())
        self.assertEqual(result.input_points, ())
        self.assertEqual(result.request_templates, ())
        self.assertEqual(result.input_point_request_contexts, ())
        warning = next(
            item for item in result.warnings if item.code == "NETWORK_GET_VALUES_ELIDED"
        )
        self.assertEqual(warning.details["elided_candidate_count"], 1)
        self.assertEqual(warning.details["structural_candidate_count"], 0)
        self.assertEqual(warning.details["audit_only_candidate_count"], 1)

    def test_ineligible_and_invalid_requests_fail_closed(self) -> None:
        cases = (
            {
                "method": "HEAD",
                "url": "http://127.0.0.1:8080/api?q=1",
                "resource_type": "fetch",
            },
            {
                "method": "POST",
                "url": "http://127.0.0.1:8080/api?q=1",
                "resource_type": "xhr",
            },
            {
                "method": "GET",
                "url": "http://127.0.0.1:8081/api?q=1",
                "resource_type": "fetch",
            },
            {
                "method": "GET",
                "url": "http://user:pass@127.0.0.1:8080/api?q=1",
                "resource_type": "fetch",
            },
            {
                "method": "GET",
                "url": "http://127.0.0.1:8080/api?q=%ZZ",
                "resource_type": "fetch",
            },
            {
                "method": "GET",
                "url": "http://127.0.0.1:8080/" + "a" * 8200,
                "resource_type": "fetch",
            },
        )
        for case in cases:
            with self.subTest(case=case):
                candidate, _ = browser_module._safe_network_discovery_candidate(
                    source_url=ROOT,
                    root_origin=ORIGIN,
                    credential_header_present=False,
                    **case,
                )
                self.assertIsNone(candidate)

    def test_dom_and_network_share_identity_and_preserve_both_provenances(self) -> None:
        static = extract_static_html_with_sensitive_form_elision(
            '<a href="/api/search?keyword=phone">search</a>',
            ROOT,
            discovery_metadata=_metadata(CollectorKind.NATIVE_STATIC),
            scope_metadata=_scope(),
            parent_url=None,
            depth=0,
        ).discovery
        dynamic = _canonical(
            _candidate("http://127.0.0.1:8080/api/search?keyword=phone")
        )
        merged = merge_discovery_results(static, dynamic, DiscoveryMergePolicy())
        endpoint = next(item for item in merged.endpoints if item.path == "/api/search")
        points = [item for item in merged.input_points if item.endpoint_id == endpoint.id]
        self.assertEqual(len(points), 1)
        self.assertEqual(len(merged.request_templates), 1)
        self.assertEqual(len(merged.input_point_request_contexts), 1)
        subjects = {
            endpoint.id,
            points[0].id,
            merged.request_templates[0].id,
            merged.input_point_request_contexts[0].id,
        }
        for subject_id in subjects:
            evidence = {
                item.collector_kind
                for item in merged.crawl_provenance
                if item.subject_id == subject_id
            }
            self.assertEqual(
                evidence,
                {CollectorKind.NATIVE_STATIC, CollectorKind.NATIVE_DYNAMIC},
            )
        self.assertEqual(
            set(points[0].metadata["origin_kinds"]),
            {"query", "network_fetch"},
        )

    def test_collection_pickle_round_trip_preserves_canonical_content(self) -> None:
        collection = NetworkDiscoveryCollection(
            candidates=(
                _candidate("http://127.0.0.1:8080/api/search?q=phone"),
            )
        )
        self.assertEqual(pickle.loads(pickle.dumps(collection, protocol=5)), collection)

    def test_candidate_constructor_rejects_forged_unsafe_executable_state(self) -> None:
        common = {
            "resource_type": "fetch",
            "source_url": ROOT,
            "base_url": "http://127.0.0.1:8080/api/search",
            "disposition": NetworkDiscoveryDisposition.SAFE,
        }
        with self.assertRaises(ValueError):
            NetworkDiscoveryCandidate(
                **common,
                query_parameter_names=("token",),
                query_pairs=(("token", "FORGED_QUERY_SECRET"),),
            )
        with self.assertRaises(ValueError):
            NetworkDiscoveryCandidate(
                **common,
                query_parameter_names=("q",),
                query_pairs=(("q", "x" * 2049),),
            )
        with self.assertRaises(ValueError):
            NetworkDiscoveryCandidate(
                **{
                    **common,
                    "base_url": "http://127.0.0.1:8081/api/search",
                },
                query_parameter_names=("q",),
                query_pairs=(("q", "safe"),),
            )
        structural = NetworkDiscoveryCandidate(
            **{
                **common,
                "disposition": NetworkDiscoveryDisposition.STRUCTURAL_ELIDED,
            },
            query_parameter_names=("token",),
            query_pairs=(),
            elision_reasons=(NetworkDiscoveryElisionReason.SENSITIVE_QUERY,),
        )
        self.assertIsNone(structural.canonical_url)

        escaped = NetworkDiscoveryCandidate(
            resource_type="fetch",
            source_url="http://127.0.0.1:8081/",
            base_url="http://127.0.0.1:8081/api/search",
            query_parameter_names=("q",),
            query_pairs=(("q", "safe"),),
            disposition=NetworkDiscoveryDisposition.SAFE,
        )
        with self.assertRaises(ValueError):
            canonicalize_network_discovery(
                NetworkDiscoveryCollection(candidates=(escaped,)),
                discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
                scope_metadata=_scope(),
            )


class PostJsonCanonicalizationTests(unittest.TestCase):
    def test_gate_1c_a_structural_id_ignores_member_values(self) -> None:
        first = _post_candidate(b'{"keyword":"phone","page":1}')
        second = _post_candidate(b'{"page":999,"keyword":"different"}')

        self.assertEqual(first.id, second.id)

    def test_gate_1c_a_structural_id_ignores_json_key_order(self) -> None:
        first = _post_candidate(b'{"keyword":"phone","page":1}')
        reordered = _post_candidate(b'{"page":1,"keyword":"phone"}')

        self.assertEqual(first.id, reordered.id)

    def test_gate_1c_a_structural_id_ignores_query_values(self) -> None:
        first = _post_candidate(
            b'{"keyword":"phone"}',
            url="http://127.0.0.1:8080/api/search?category=book",
        )
        second = _post_candidate(
            b'{"keyword":"phone"}',
            url="http://127.0.0.1:8080/api/search?category=different",
        )

        self.assertEqual(first.id, second.id)

    def test_gate_1c_a_persistent_candidate_repr_is_value_free(self) -> None:
        sentinel = "POST_SECRET_SENTINEL_1C_A"
        candidate = _post_candidate(
            ('{"keyword":"' + sentinel + '","page":1}').encode()
        )

        self.assertNotIn(sentinel, repr(candidate))
        self.assertNotIn(sentinel.encode(), pickle.dumps(candidate, protocol=5))

    def test_gate_1c_a_canonical_artifact_is_value_free_and_keeps_discovery(
        self,
    ) -> None:
        sentinel = "POST_SECRET_SENTINEL_1C_A"
        result = _canonical_post(
            _post_candidate(
                ('{"keyword":"' + sentinel + '","page":1}').encode()
            )
        )
        serialized = repr(result.to_dict())

        self.assertNotIn(sentinel, serialized)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(
            {(item.name, item.location) for item in result.input_points},
            {
                ("keyword", InputLocation.JSON_BODY),
                ("page", InputLocation.JSON_BODY),
            },
        )

    def test_gate_1c_a_input_point_ids_ignore_member_values(self) -> None:
        first = _canonical_post(
            _post_candidate(b'{"keyword":"phone","page":1}')
        )
        second = _canonical_post(
            _post_candidate(b'{"page":999,"keyword":"different"}')
        )

        self.assertEqual(
            {(item.name, item.id) for item in first.input_points},
            {(item.name, item.id) for item in second.input_points},
        )

    def test_gate_1c_a_discovery_snapshot_ignores_transient_values(self) -> None:
        first_candidate, first_material = _post_capture(
            b'{"keyword":"phone","page":1}'
        )
        second_candidate, second_material = _post_capture(
            b'{"page":999,"keyword":"different"}'
        )
        first = _canonical_post(
            first_candidate,
            replay_materials=((first_candidate.id, first_material),),
        )
        second = _canonical_post(
            second_candidate,
            replay_materials=((second_candidate.id, second_material),),
        )

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(
            discovery_snapshot_id_for(first.to_dict()),
            discovery_snapshot_id_for(second.to_dict()),
        )

    def test_gate_1c_a_transient_material_is_explicit_and_not_artifact_data(
        self,
    ) -> None:
        sentinel = "POST_SAFE_BASELINE_SENTINEL_1C_A"
        candidate, replay_material = _post_capture(
            ('{"keyword":"' + sentinel + '","page":1}').encode()
        )
        result = _canonical_post(
            candidate,
            replay_materials=((candidate.id, replay_material),),
        )
        template = result.request_templates[0]

        self.assertNotIn(sentinel, repr(result))
        self.assertNotIn(sentinel, repr(result.to_dict()))
        self.assertNotIn(sentinel, repr(template))
        self.assertEqual(
            template.json_body,
            (("keyword", "null"), ("page", "null")),
        )
        self.assertIn(sentinel, repr(template.execution_json_body))
        worker_payload = pickle.dumps(result, protocol=5)
        self.assertIn(sentinel.encode(), worker_payload)
        restored = pickle.loads(worker_payload)
        self.assertNotIn(sentinel, repr(restored.to_dict()))
        self.assertIn(
            sentinel,
            repr(restored.request_templates[0].execution_json_body),
        )
        self.assertEqual(len(result.ready_contexts()), 2)
        self.assertEqual(len(restored.ready_contexts()), 2)

    def test_gate_1c_a_planner_uses_transient_values_without_persisting_them(
        self,
    ) -> None:
        body_sentinel = "POST_BODY_BASELINE_SENTINEL_1C_A"
        query_sentinel = "POST_QUERY_BASELINE_SENTINEL_1C_A"
        candidate, replay_material = _post_capture(
            ('{"keyword":"' + body_sentinel + '","page":1}').encode(),
            url=(
                "http://127.0.0.1:8080/api/search?category="
                + query_sentinel
            ),
        )
        result = _canonical_post(
            candidate,
            replay_materials=((candidate.id, replay_material),),
        )
        point, template, context = next(
            item for item in result.ready_contexts() if item[0].name == "keyword"
        )
        plan = ProbePlanner().plan(point, template, context)

        self.assertNotIn(query_sentinel, repr(candidate))
        self.assertNotIn(body_sentinel, repr(result.to_dict()))
        self.assertNotIn(query_sentinel, repr(result.to_dict()))
        self.assertIn(query_sentinel, plan.baseline_request.url)
        self.assertIn(
            ("keyword", '"' + body_sentinel + '"'),
            plan.baseline_request.json_body,
        )
        self.assertEqual(plan.baseline_request.query, replay_material.query)
        self.assertEqual(
            dict(plan.probe_request.json_body)["page"],
            "1",
        )
        self.assertNotEqual(
            dict(plan.probe_request.json_body)["keyword"],
            dict(plan.baseline_request.json_body)["keyword"],
        )

    def test_gate_1c_a_pipeline_keeps_current_post_replay_handoff(self) -> None:
        candidate, replay_material = _post_capture(
            b'{"keyword":"phone","page":1}'
        )
        result = _canonical_post(
            candidate,
            replay_materials=((candidate.id, replay_material),),
        )

        class RecordingTransport:
            def __init__(self) -> None:
                self.calls = []

            def send(self, request, *, timeout_seconds):
                self.calls.append(request)
                return TransportResponse(status_code=200, body=b"ok")

        transport = RecordingTransport()
        analysis = analyze_discovery_result(
            result,
            top_k=2,
            transport=transport,
        )

        self.assertEqual(len(transport.calls), 4)
        self.assertTrue(all(item.method == HttpMethod.POST for item in transport.calls))
        self.assertEqual(len(analysis.feature_vectors), 2)

    def test_gate_1c_a_combined_crawl_report_excludes_transient_values(self) -> None:
        from tests.unit.test_combined_discovery import _empty_audit, _static_result

        sentinel = "POST_CRAWL_REPORT_SENTINEL_1C_A"
        candidate, replay_material = _post_capture(
            ('{"keyword":"' + sentinel + '","page":1}').encode()
        )
        dynamic_discovery = _canonical_post(
            candidate,
            replay_materials=((candidate.id, replay_material),),
        )
        static_crawl = _static_result(html="<html></html>")
        dynamic_crawl = DynamicCrawlResult(
            root_url=ROOT,
            visited_urls=(),
            pages=(),
            completion=DynamicCrawlCompletion.COMPLETE,
            termination_reason=DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED,
            navigation_attempts=0,
            route_actions_attempted=0,
            discovery=dynamic_discovery,
            browser_audit=_empty_audit(),
        )
        combined = CombinedDiscoveryResult(
            root_url=ROOT,
            static_crawl=static_crawl,
            dynamic_crawl=dynamic_crawl,
            discovery=merge_discovery_results(
                static_crawl.discovery,
                dynamic_discovery,
                DiscoveryMergePolicy(),
            ),
        )

        report = build_crawl_report(combined)

        self.assertNotIn(sentinel, repr(report))
        self.assertEqual(len(combined.discovery.ready_contexts()), 2)

    def test_blocked_post_json_builds_only_not_ready_structure(self) -> None:
        raw_value = "POST_PHONE_VALUE_SENTINEL"
        candidate = _post_candidate(
            ('{"keyword":"' + raw_value + '","page":1}').encode()
        )
        self.assertEqual(candidate.member_names, ("keyword", "page"))
        self.assertNotIn(raw_value, repr(candidate))
        self.assertNotIn(raw_value.encode(), pickle.dumps(candidate, protocol=5))

        result = _canonical_post(candidate)
        endpoint = result.endpoints[0]
        self.assertEqual(endpoint.method, HttpMethod.POST)
        self.assertEqual(endpoint.path, "/api/search")
        self.assertEqual(
            sorted((item.name, item.location) for item in result.input_points),
            [
                ("keyword", InputLocation.JSON_BODY),
                ("page", InputLocation.JSON_BODY),
            ],
        )
        self.assertTrue(
            all(item.baseline_value is None for item in result.input_points)
        )
        self.assertTrue(
            all(
                "network_fetch" in item.metadata["origin_kinds"]
                for item in result.input_points
            )
        )
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(
            result.request_templates[0].json_body,
            (("keyword", "null"), ("page", "null")),
        )
        self.assertIsNone(result.request_templates[0].ephemeral_material)
        self.assertEqual(len(result.input_point_request_contexts), 2)
        self.assertEqual(result.ready_contexts(), ())
        self.assertTrue(
            all(
                item.status == ProbeReadyStatus.NOT_READY
                and item.request_context_id is not None
                and item.reasons
                == (NonProbeReadyReason.POST_POLICY_STRUCTURAL_ONLY,)
                for item in result.probe_readiness
            )
        )
        self.assertNotIn(raw_value, repr(result.to_dict()))

        class TrapTransport:
            def request(self, *_args, **_kwargs):
                raise AssertionError("structural POST must never execute")

        analysis = analyze_discovery_result(
            result,
            top_k=2,
            transport=TrapTransport(),
        )
        self.assertEqual(analysis.probe_observations, ())
        self.assertEqual(analysis.feature_vectors, ())
        self.assertEqual(analysis.selection.selected, ())

    def test_route_guard_collects_primary_post_then_aborts_without_fetch(self) -> None:
        class Page:
            url = ROOT

        primary_page = Page()

        class Frame:
            parent_frame = None

            def __init__(self, page):
                self.page = page

        class Request:
            def __init__(
                self,
                *,
                url,
                page,
                body,
                content_type="application/json",
                extra_headers=None,
            ):
                self.method = "POST"
                self.url = url
                self.resource_type = "fetch"
                self.frame = Frame(page)
                self.post_data_buffer = body
                self.content_type = content_type
                self.extra_headers = extra_headers or {}

            def all_headers(self):
                return {
                    "Content-Type": self.content_type,
                    **self.extra_headers,
                }

        class Route:
            def __init__(self):
                self.fetch_count = 0
                self.abort_count = 0

            def fetch(self, **_kwargs):
                self.fetch_count += 1
                raise AssertionError("blocked POST reached route.fetch")

            def abort(self, **_kwargs):
                self.abort_count += 1

        recorder = browser_module._NetworkDiscoveryRecorder(candidate_limit=8)
        guard = browser_module._RouteGuard(
            browser_module.DynamicRequestAuthority(
                ROOT,
                allow_passive_same_origin_fetch_xhr=True,
            ),
            browser_module.DynamicBrowserPolicy(request_decision_budget=8),
            browser_module._AuditRecorder(event_limit=8),
            lambda: None,
            network_discovery=recorder,
        )
        guard.set_primary_page(primary_page)
        secret = "ROUTE_POST_VALUE_SENTINEL"
        route = Route()
        guard.handle_http(
            route,
            Request(
                url="http://127.0.0.1:8080/api/search",
                page=primary_page,
                body=(f'{{"keyword":"{secret}","page":1}}').encode(),
            ),
        )
        guard.handle_http(
            Route(),
            Request(
                url="http://127.0.0.1:8081/api/off-scope",
                page=primary_page,
                body=b'{"keyword":"off"}',
            ),
        )
        guard.handle_http(
            Route(),
            Request(
                url="http://127.0.0.1:8080/api/frame",
                page=Page(),
                body=b'{"keyword":"frame"}',
            ),
        )
        guard.handle_http(
            Route(),
            Request(
                url="http://127.0.0.1:8080/api/form-like",
                page=primary_page,
                body=b"keyword=phone",
                content_type="application/x-www-form-urlencoded",
            ),
        )
        header_secret = "Bearer NONSTANDARD_HEADER_SECRET_SENTINEL"
        guard.handle_http(
            Route(),
            Request(
                url="http://127.0.0.1:8080/api/header-secret",
                page=primary_page,
                body=b'{"keyword":"safe"}',
                extra_headers={"X-Trace": header_secret},
            ),
        )
        collection = recorder.snapshot()
        self.assertEqual(route.abort_count, 1)
        self.assertEqual(route.fetch_count, 0)
        self.assertEqual(len(collection.post_json_candidates), 2)
        self.assertEqual(collection.post_json_skipped_counts, ())
        candidates_by_url = {
            item.base_url: item for item in collection.post_json_candidates
        }
        self.assertEqual(
            candidates_by_url[
                "http://127.0.0.1:8080/api/search"
            ].replay_policy.disposition,
            PostReplayDisposition.SAFE_FOR_PROBE,
        )
        self.assertEqual(
            candidates_by_url[
                "http://127.0.0.1:8080/api/header-secret"
            ].replay_policy.disposition,
            PostReplayDisposition.BLOCKED_SENSITIVE,
        )
        self.assertNotIn(secret, repr(collection))
        self.assertNotIn(
            secret.encode(),
            pickle.dumps(collection.post_json_candidates[0], protocol=5),
        )
        self.assertEqual(len(collection.post_json_replay_materials), 1)
        self.assertIn(
            secret,
            repr(collection.post_json_replay_materials[0][1].json_body),
        )
        self.assertNotIn(header_secret, repr(collection))
        self.assertNotIn(
            header_secret.encode(),
            pickle.dumps(collection, protocol=5),
        )

    def test_post_json_rejections_and_sensitive_policy_fail_closed(self) -> None:
        oversized = b'{"field":"' + b"x" * 17000 + b'"}'
        jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
        rejection_cases = (
            (b'{"keyword":', PostJsonSkipReason.JSON_MALFORMED),
            (b'["keyword"]', PostJsonSkipReason.JSON_TOP_LEVEL_NOT_OBJECT),
            (
                b'{"keyword":"one","keyword":"two"}',
                PostJsonSkipReason.JSON_DUPLICATE_KEY,
            ),
            (oversized, PostJsonSkipReason.BODY_TOO_LARGE),
        )
        for body, expected in rejection_cases:
            with self.subTest(expected=expected):
                candidate, replay_material, reason = (
                    browser_module._safe_blocked_post_json_candidate(
                        method="POST",
                        url="http://127.0.0.1:8080/api/search",
                        resource_type="fetch",
                        source_url=ROOT,
                        root_origin=ORIGIN,
                        content_type="application/json",
                        credential_header_present=False,
                        body=body,
                    )
                )
                self.assertIsNone(candidate)
                self.assertIsNone(replay_material)
                self.assertEqual(reason, expected)

        sensitive_bodies = (
            b'{"password":"PASSWORD_VALUE_SENTINEL"}',
            b'{"password":null}',
            b'{"api_key":"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}',
            b'{"token":"POST_TOKEN_VALUE_SENTINEL"}',
            b'{"csrf":"POST_CSRF_VALUE_SENTINEL"}',
            b'{"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAA":null}',
            b'{"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.":null}',
            ('{"note":"' + jwt + '"}').encode(),
        )
        for body in sensitive_bodies:
            with self.subTest(body=body[:32]):
                candidate, replay_material, reason = (
                    browser_module._safe_blocked_post_json_candidate(
                        method="POST",
                        url="http://127.0.0.1:8080/api/search",
                        resource_type="fetch",
                        source_url=ROOT,
                        root_origin=ORIGIN,
                        content_type="application/json",
                        credential_header_present=False,
                        body=body,
                    )
                )
                self.assertIsNotNone(candidate)
                self.assertIsNone(replay_material)
                self.assertIsNone(reason)
                assert candidate is not None
                self.assertEqual(
                    candidate.replay_policy.disposition,
                    PostReplayDisposition.BLOCKED_SENSITIVE,
                )
                serialized = pickle.dumps(candidate, protocol=5)
                for secret in (
                    b"PASSWORD_VALUE_SENTINEL",
                    b"POST_TOKEN_VALUE_SENTINEL",
                    b"POST_CSRF_VALUE_SENTINEL",
                    b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    jwt.lower().encode(),
                ):
                    self.assertNotIn(secret, serialized)

        credential_candidate, credential_material, credential_reason = (
            browser_module._safe_blocked_post_json_candidate(
                method="POST",
                url="http://127.0.0.1:8080/api/search",
                resource_type="xhr",
                source_url=ROOT,
                root_origin=ORIGIN,
                content_type="application/json",
                credential_header_present=True,
                body=b'{"keyword":"phone"}',
            )
        )
        self.assertIsNotNone(credential_candidate)
        self.assertIsNone(credential_material)
        self.assertIsNone(credential_reason)
        assert credential_candidate is not None
        self.assertEqual(
            credential_candidate.replay_policy.disposition,
            PostReplayDisposition.BLOCKED_SENSITIVE,
        )
        query_candidate, query_material, query_reason = (
            browser_module._safe_blocked_post_json_candidate(
                method="POST",
                url=(
                    "http://127.0.0.1:8080/api/search?x-csrf-token="
                    "POST_QUERY_CSRF_SENTINEL"
                ),
                resource_type="fetch",
                source_url=ROOT,
                root_origin=ORIGIN,
                content_type="application/json",
                credential_header_present=False,
                body=b'{"keyword":"phone"}',
            )
        )
        self.assertIsNotNone(query_candidate)
        self.assertIsNone(query_material)
        self.assertIsNone(query_reason)
        assert query_candidate is not None
        self.assertEqual(
            query_candidate.replay_policy.disposition,
            PostReplayDisposition.BLOCKED_SENSITIVE,
        )
        empty_query_candidate, empty_query_material, empty_query_reason = (
            browser_module._safe_blocked_post_json_candidate(
                method="POST",
                url="http://127.0.0.1:8080/api/search?x-csrf-token=",
                resource_type="fetch",
                source_url=ROOT,
                root_origin=ORIGIN,
                content_type="application/json",
                credential_header_present=False,
                body=b'{"keyword":"phone"}',
            )
        )
        self.assertIsNotNone(empty_query_candidate)
        self.assertIsNone(empty_query_material)
        self.assertIsNone(empty_query_reason)
        assert empty_query_candidate is not None
        self.assertEqual(
            empty_query_candidate.replay_policy.disposition,
            PostReplayDisposition.BLOCKED_SENSITIVE,
        )
        collection = NetworkDiscoveryCollection(
            post_json_skipped_counts=(
                (ROOT, PostJsonSkipReason.SENSITIVE_REQUEST_ELIDED, 3),
            )
        )
        serialized = pickle.dumps(collection, protocol=5)
        for secret in (
            b"PASSWORD_VALUE_SENTINEL",
            jwt.encode(),
            b"Authorization",
            b"api_key",
        ):
            self.assertNotIn(secret, serialized)

    def test_post_json_eligibility_and_budgets_are_bounded(self) -> None:
        ineligible = (
            ("GET", "http://127.0.0.1:8080/api", "fetch"),
            ("post", "http://127.0.0.1:8080/api", "fetch"),
            ("PUT", "http://127.0.0.1:8080/api", "fetch"),
            ("POST", "http://127.0.0.1:8081/api", "xhr"),
            ("POST", "http://localhost:8080/api", "fetch"),
            ("POST", "https://127.0.0.1:8080/api", "fetch"),
            ("POST", "http://127.0.0.1.evil.test:8080/api", "xhr"),
            ("POST", "http://user@127.0.0.1:8080/api", "fetch"),
            ("POST", "http://127.0.0.1:8080/api", "script"),
        )
        for method, url, resource_type in ineligible:
            with self.subTest(method=method, url=url, resource_type=resource_type):
                candidate, replay_material, reason = (
                    browser_module._safe_blocked_post_json_candidate(
                        method=method,
                        url=url,
                        resource_type=resource_type,
                        source_url=ROOT,
                        root_origin=ORIGIN,
                        content_type="application/json",
                        credential_header_present=False,
                        body=b'{"keyword":"phone"}',
                    )
                )
                self.assertIsNone(candidate)
                self.assertIsNone(replay_material)
                self.assertIsNone(reason)

        for content_type in ("text/json", "application/problem+json", ""):
            with self.subTest(content_type=content_type):
                candidate, replay_material, reason = (
                    browser_module._safe_blocked_post_json_candidate(
                        method="POST",
                        url="http://127.0.0.1:8080/api",
                        resource_type="fetch",
                        source_url=ROOT,
                        root_origin=ORIGIN,
                        content_type=content_type,
                        credential_header_present=False,
                        body=b'{"keyword":"phone"}',
                    )
                )
                self.assertIsNone(candidate)
                self.assertIsNone(replay_material)
                self.assertEqual(
                    reason,
                    PostJsonSkipReason.CONTENT_TYPE_UNSUPPORTED,
                )

        too_many_body = (
            "{" + ",".join(f'"field_{index}":{index}' for index in range(65)) + "}"
        ).encode()
        candidate, replay_material, reason = (
            browser_module._safe_blocked_post_json_candidate(
                method="POST",
                url="http://127.0.0.1:8080/api",
                resource_type="fetch",
                source_url=ROOT,
                root_origin=ORIGIN,
                content_type="application/json; charset=utf-8",
                credential_header_present=False,
                body=too_many_body,
            )
        )
        self.assertIsNone(candidate)
        self.assertIsNone(replay_material)
        self.assertEqual(reason, PostJsonSkipReason.JSON_MEMBER_LIMIT_EXCEEDED)

        first = _post_candidate(b'{"page":1,"keyword":"phone"}')
        second = _post_candidate(b'{"keyword":"other","page":2}')
        self.assertEqual(first.id, second.id)
        self.assertEqual(first, second)

        recorder = browser_module._NetworkDiscoveryRecorder(candidate_limit=1)
        for path in ("a", "b"):
            recorder.record_blocked_post_json(
                method="POST",
                url=f"http://127.0.0.1:8080/api/{path}",
                resource_type="fetch",
                source_url=ROOT,
                root_origin=ORIGIN,
                content_type="application/json",
                credential_header_present=False,
                headers_available=True,
                body=b'{"keyword":"phone"}',
            )
        snapshot = recorder.snapshot()
        self.assertEqual(len(snapshot.post_json_candidates), 1)
        self.assertEqual(
            snapshot.post_json_skipped_counts,
            ((ROOT, PostJsonSkipReason.CANDIDATE_LIMIT_EXCEEDED, 1),),
        )

        def limited_snapshot(order):
            limited = browser_module._NetworkDiscoveryRecorder(candidate_limit=1)
            for path in order:
                limited.record_blocked_post_json(
                    method="POST",
                    url=f"http://127.0.0.1:8080/api/{path}",
                    resource_type="fetch",
                    source_url=f"http://127.0.0.1:8080/source-{path}",
                    root_origin=ORIGIN,
                    content_type="application/json",
                    credential_header_present=False,
                    headers_available=True,
                    body=b'{"keyword":"phone"}',
                )
            return limited.snapshot()

        self.assertEqual(
            limited_snapshot(("a", "a", "b")),
            limited_snapshot(("b", "a", "a")),
        )
        with self.assertRaises(ValueError):
            NetworkDiscoveryCollection(
                post_json_skipped_counts=(
                    (
                        ROOT + "?token=FORGED_SECRET",
                        PostJsonSkipReason.JSON_MALFORMED,
                        1,
                    ),
                )
            )

    def test_post_json_snapshot_and_pickle_are_deterministic(self) -> None:
        fetch = _post_candidate(b'{"keyword":"phone","page":1}')
        xhr = _post_candidate(
            b'{"category":"book"}',
            url="http://127.0.0.1:8080/api/filter",
            resource_type="xhr",
        )
        forward = NetworkDiscoveryCollection(post_json_candidates=(fetch, xhr))
        reverse = NetworkDiscoveryCollection(post_json_candidates=(xhr, fetch))
        self.assertEqual(forward, reverse)
        self.assertEqual(pickle.loads(pickle.dumps(forward, protocol=5)), forward)
        first = _canonical_post(fetch, xhr)
        second = _canonical_post(xhr, fetch)
        self.assertEqual(first, second)
        self.assertEqual(
            discovery_snapshot_id_for(first.to_dict()),
            discovery_snapshot_id_for(second.to_dict()),
        )

    def test_dom_post_endpoint_merges_with_network_post_provenance(self) -> None:
        static = extract_static_html_with_sensitive_form_elision(
            '<form method="post" action="/api/search">'
            '<input name="keyword" value="phone"></form>',
            ROOT,
            discovery_metadata=_metadata(CollectorKind.NATIVE_STATIC),
            scope_metadata=_scope(),
            parent_url=None,
            depth=0,
        ).discovery
        dynamic = _canonical_post(
            _post_candidate(b'{"keyword":"phone","page":1}')
        )
        merged = merge_discovery_results(static, dynamic, DiscoveryMergePolicy())
        endpoints = [item for item in merged.endpoints if item.path == "/api/search"]
        self.assertEqual(len(endpoints), 1)
        endpoint = endpoints[0]
        self.assertEqual(endpoint.method, HttpMethod.POST)
        points = [item for item in merged.input_points if item.endpoint_id == endpoint.id]
        self.assertEqual(
            {(item.name, item.location) for item in points},
            {
                ("keyword", InputLocation.FORM),
                ("keyword", InputLocation.JSON_BODY),
                ("page", InputLocation.JSON_BODY),
            },
        )
        endpoint_collectors = {
            item.collector_kind
            for item in merged.crawl_provenance
            if item.subject_id == endpoint.id
        }
        self.assertEqual(
            endpoint_collectors,
            {CollectorKind.NATIVE_STATIC, CollectorKind.NATIVE_DYNAMIC},
        )


if __name__ == "__main__":
    unittest.main()
