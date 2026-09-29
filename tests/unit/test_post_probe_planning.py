from __future__ import annotations

from dataclasses import replace
import inspect
import json
import math
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import vulnspider.observation.planner as planner_module
from vulnspider.discovery import (
    CollectorKind,
    DiscoveryMetadata,
    NetworkDiscoveryCollection,
    ScopeMetadata,
    canonicalize_network_discovery,
    scope_id_for_root,
)
from vulnspider.discovery import dynamic_browser as browser_module
from vulnspider.discovery.post_replay_policy import PostReplayDisposition
from vulnspider.domain import (
    EphemeralRequestMaterial,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    REFLECTION_COUNT_NORM,
    SAFE_HTML_ENCODING_DETECTED,
)
from vulnspider.observation import (
    PostProbePlanningBudget,
    ProbePlanner,
    ProbePlanningError,
    TransportResponse,
    plan_probe_request,
)
from vulnspider.pipeline import analyze_discovery_result


ROOT = "http://127.0.0.1:8080/"
ORIGIN = ("http", "127.0.0.1", 8080)
POST_PLAN_CAP = 4


class RecordingTransport:
    def __init__(self) -> None:
        self.calls = []

    def send(self, request, *, timeout_seconds):
        self.calls.append(request)
        return TransportResponse(status_code=200, body=b"ok")


def _capture(body: bytes, *, url: str = ROOT + "api/search"):
    candidate, material, reason = (
        browser_module._safe_blocked_post_json_candidate(
            method="POST",
            url=url,
            resource_type="fetch",
            source_url=ROOT,
            root_origin=ORIGIN,
            content_type="application/json; charset=utf-8",
            credential_header_present=False,
            body=body,
        )
    )
    if candidate is None:
        raise AssertionError(f"expected POST structure, got {reason}")
    return candidate, material


def _canonical(candidate, material):
    materials = () if material is None else ((candidate.id, material),)
    components = canonicalize_network_discovery(
        NetworkDiscoveryCollection(
            post_json_candidates=(candidate,),
            post_json_replay_materials=materials,
        ),
        discovery_metadata=DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_DYNAMIC,
            collector_version="gate-1c-d-1-test/1",
            configuration_fingerprint="gate-1c-d-1",
        ),
        scope_metadata=ScopeMetadata(
            target_scope_id=scope_id_for_root(
                ROOT,
                policy_version="same-origin-v1",
            ),
            root_url=ROOT,
            scope_policy_version="same-origin-v1",
        ),
    )
    if len(components) != 1:
        raise AssertionError("expected one POST discovery component")
    return components[0]


def _safe_result(body: bytes):
    candidate, material = _capture(body)
    if material is None:
        raise AssertionError("expected replay material")
    if candidate.replay_policy.disposition != PostReplayDisposition.SAFE_FOR_PROBE:
        raise AssertionError("expected SAFE_FOR_PROBE")
    return _canonical(candidate, material), material


class PostProbePlanningTests(unittest.TestCase):
    def test_functional_post_entrypoint_requires_one_shared_budget(self) -> None:
        result, _material = _safe_result(
            (
                '{"keyword":"phone",'
                + ",".join(f'"field_{index}":{index}' for index in range(7))
                + "}"
            ).encode()
        )
        point, template, context = result.ready_contexts()[0]

        with self.assertRaisesRegex(ProbePlanningError, "BUDGET_REQUIRED"):
            plan_probe_request(
                input_point=point,
                request_template=template,
                request_context=context,
            )

        budget = PostProbePlanningBudget(max_plans=POST_PLAN_CAP)
        plans = []
        for item in result.ready_contexts():
            point, template, context = item
            try:
                plans.append(
                    plan_probe_request(
                        input_point=point,
                        request_template=template,
                        request_context=context,
                        post_probe_budget=budget,
                    )
                )
            except ProbePlanningError as exc:
                self.assertRegex(str(exc), "BUDGET_EXHAUSTED")
        self.assertEqual(len(plans), POST_PLAN_CAP)

    def test_json_post_context_cannot_be_rebound_as_query_input(self) -> None:
        candidate, material = _capture(
            b'{"keyword":"phone","page":1}',
            url=ROOT + "api/search?category=books",
        )
        if material is None:
            raise AssertionError("expected replay material")
        result = _canonical(candidate, material)
        template = result.request_templates[0]
        stripped = replace(template, ephemeral_material=None)
        point = InputPoint(
            endpoint_id=template.endpoint_id,
            endpoint_fingerprint=template.endpoint_fingerprint,
            location=InputLocation.QUERY,
            name="category",
            baseline_value="",
        )
        context = InputPointRequestContext.from_objects(point, stripped)

        with self.assertRaisesRegex(
            ProbePlanningError,
            "POST_REPLAY_CONTEXT_NOT_JSON_BODY",
        ):
            ProbePlanner().plan(point, stripped, context)

    def test_post_budget_reservation_is_atomic(self) -> None:
        budget = PostProbePlanningBudget(max_plans=1)
        start = threading.Barrier(3)
        source_lines, start_line = inspect.getsourcelines(
            PostProbePlanningBudget.try_reserve
        )
        increment = next(
            start_line + index
            for index, line in enumerate(source_lines)
            if (
                "self.planned_count += 1" in line
                or 'object.__setattr__(self, "_planned_count"' in line
            )
        )
        race = threading.Barrier(2)
        results: list[bool] = []

        def trace(frame, event, _arg):
            if (
                frame.f_code is PostProbePlanningBudget.try_reserve.__code__
                and event == "line"
                and frame.f_lineno == increment
            ):
                try:
                    race.wait(timeout=0.1)
                except threading.BrokenBarrierError:
                    pass
            return trace

        def worker() -> None:
            start.wait()
            results.append(budget.try_reserve())

        threading.settrace(trace)
        threads = [threading.Thread(target=worker) for _index in range(2)]
        try:
            for thread in threads:
                thread.start()
            start.wait()
            for thread in threads:
                thread.join(timeout=2.0)
        finally:
            threading.settrace(None)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(budget.planned_count, 1)

    def test_post_budget_count_and_cap_cannot_be_reset(self) -> None:
        budget = PostProbePlanningBudget(max_plans=1)
        tracked = {budget}

        self.assertTrue(budget.try_reserve())
        self.assertIn(budget, tracked)
        self.assertFalse(budget.try_reserve())
        with self.assertRaises((AttributeError, TypeError)):
            budget.planned_count = 0
        with self.assertRaises((AttributeError, TypeError)):
            budget.max_plans = 2
        self.assertEqual(budget.planned_count, 1)
        self.assertFalse(budget.try_reserve())

    def test_exact_baseline_and_one_top_level_scalar_mutation(self) -> None:
        result, material = _safe_result(
            b'{"keyword":"phone","page":1,"ratio":1.25}'
        )
        ready = {
            point.name: (point, template, context)
            for point, template, context in result.ready_contexts()
        }

        self.assertEqual(set(ready), {"keyword", "page", "ratio"})
        for target_name, (point, template, context) in ready.items():
            with self.subTest(target=target_name):
                plan = ProbePlanner().plan(point, template, context)
                baseline = plan.baseline_request
                probe = plan.probe_request

                self.assertEqual(baseline.json_body, material.json_body)
                self.assertEqual(baseline.method, HttpMethod.POST)
                self.assertEqual(probe.method, baseline.method)
                self.assertEqual(probe.url, baseline.url)
                self.assertEqual(
                    (
                        urlsplit(probe.url).scheme,
                        urlsplit(probe.url).netloc,
                        urlsplit(probe.url).path,
                    ),
                    (
                        urlsplit(material.url).scheme,
                        urlsplit(material.url).netloc,
                        urlsplit(material.url).path,
                    ),
                )
                self.assertEqual(
                    tuple(name for name, _value in probe.json_body),
                    tuple(name for name, _value in baseline.json_body),
                )
                changed = [
                    name
                    for (name, before), (_after_name, after) in zip(
                        baseline.json_body,
                        probe.json_body,
                        strict=True,
                    )
                    if before != after
                ]
                self.assertEqual(changed, [target_name])
                self.assertEqual(
                    plan.changed_fields,
                    (f"json_body.{target_name}",),
                )

    def test_string_scalar_reuses_existing_light_probe_marker(self) -> None:
        result, _material = _safe_result(
            b'{"keyword":"phone","page":1}'
        )
        ready = {
            point.name: (point, template, context)
            for point, template, context in result.ready_contexts()
        }

        point, template, context = ready["keyword"]
        plan = ProbePlanner().plan(point, template, context)
        encoded_probe = dict(plan.probe_request.json_body)["keyword"]

        self.assertIs(type(json.loads(encoded_probe)), str)
        self.assertEqual(json.loads(encoded_probe), plan.probe_marker)
        self.assertEqual(
            plan.marker_strategy,
            planner_module.DEFAULT_MARKER_STRATEGY,
        )

    def test_string_marker_collision_uses_deterministic_fallback(self) -> None:
        first, _material = _safe_result(
            b'{"keyword":"phone","page":1}'
        )
        first_ready = {
            point.name: (point, template, context)
            for point, template, context in first.ready_contexts()
        }
        first_marker = ProbePlanner().plan(*first_ready["keyword"]).probe_marker
        if first_marker is None:
            raise AssertionError("expected string marker")

        collision_body = json.dumps(
            {"keyword": first_marker, "page": 1},
            separators=(",", ":"),
        ).encode()
        collision, _material = _safe_result(collision_body)
        collision_ready = {
            point.name: (point, template, context)
            for point, template, context in collision.ready_contexts()
        }

        plan = ProbePlanner().plan(*collision_ready["keyword"])
        self.assertNotEqual(plan.probe_marker, first_marker)
        self.assertNotEqual(
            dict(plan.baseline_request.json_body)["keyword"],
            dict(plan.probe_request.json_body)["keyword"],
        )

    def test_integer_scalar_uses_minimal_adjacent_integer(self) -> None:
        result, _material = _safe_result(
            b'{"keyword":"phone","page":41}'
        )
        ready = {
            point.name: (point, template, context)
            for point, template, context in result.ready_contexts()
        }

        point, template, context = ready["page"]
        plan = ProbePlanner().plan(point, template, context)
        baseline_value = json.loads(dict(plan.baseline_request.json_body)["page"])
        probe_value = json.loads(dict(plan.probe_request.json_body)["page"])

        self.assertIs(type(baseline_value), int)
        self.assertIs(type(probe_value), int)
        self.assertEqual(probe_value, baseline_value + 1)
        self.assertIsNone(plan.probe_marker)
        self.assertEqual(plan.marker_strategy, "numeric-adjacent-v1")

    def test_float_scalar_uses_closest_finite_numeric_probe(self) -> None:
        result, _material = _safe_result(
            b'{"keyword":"phone","ratio":1.25}'
        )
        ready = {
            point.name: (point, template, context)
            for point, template, context in result.ready_contexts()
        }

        point, template, context = ready["ratio"]
        plan = ProbePlanner().plan(point, template, context)
        baseline_value = json.loads(dict(plan.baseline_request.json_body)["ratio"])
        probe_value = json.loads(dict(plan.probe_request.json_body)["ratio"])

        self.assertIs(type(baseline_value), float)
        self.assertIs(type(probe_value), float)
        self.assertTrue(math.isfinite(probe_value))
        self.assertEqual(probe_value, math.nextafter(baseline_value, math.inf))
        self.assertIsNone(plan.probe_marker)
        self.assertEqual(plan.marker_strategy, "numeric-adjacent-v1")

    def test_largest_finite_float_steps_inward_and_nonfinite_is_rejected(self) -> None:
        result, _material = _safe_result(
            b'{"keyword":"phone","ratio":1.7976931348623157e308}'
        )
        ready = {
            point.name: (point, template, context)
            for point, template, context in result.ready_contexts()
        }
        point, template, context = ready["ratio"]

        plan = ProbePlanner().plan(point, template, context)
        baseline_value = json.loads(dict(plan.baseline_request.json_body)["ratio"])
        probe_value = json.loads(dict(plan.probe_request.json_body)["ratio"])
        self.assertEqual(probe_value, math.nextafter(baseline_value, -math.inf))

        nonfinite, _material = _safe_result(
            b'{"keyword":"phone","ratio":1e309}'
        )
        nonfinite_ready = {
            point.name: (point, template, context)
            for point, template, context in nonfinite.ready_contexts()
        }
        point, template, context = nonfinite_ready["ratio"]
        with self.assertRaisesRegex(
            ProbePlanningError,
            "POST_PROBE_NUMERIC_VALUE_NONFINITE",
        ):
            ProbePlanner().plan(point, template, context)

    def test_boolean_and_null_are_not_active_mutation_targets(self) -> None:
        result, _material = _safe_result(
            b'{"keyword":"phone","enabled":false,"cursor":null}'
        )
        ready = {
            point.name: (point, template, context)
            for point, template, context in result.ready_contexts()
        }

        for target_name in ("enabled", "cursor"):
            with self.subTest(target=target_name):
                point, template, context = ready[target_name]
                with self.assertRaisesRegex(
                    ProbePlanningError,
                    "POST_PROBE_SCALAR_TYPE_UNSUPPORTED",
                ):
                    ProbePlanner().plan(point, template, context)

    def test_unsupported_scalars_do_not_consume_post_budget(self) -> None:
        result, _material = _safe_result(
            b'{"keyword":"phone","enabled":false,"cursor":null,'
            b'"field_0":0,"field_1":1,"field_2":2,"field_3":3}'
        )
        transport = RecordingTransport()

        analysis = analyze_discovery_result(
            result,
            top_k=16,
            transport=transport,
        )

        names_by_id = {point.id: point.name for point in result.input_points}
        planned_names = tuple(
            names_by_id[item.probe_plan.input_point_id]
            for item in analysis.probe_observations
        )
        self.assertEqual(len(planned_names), POST_PLAN_CAP)
        self.assertNotIn("enabled", planned_names)
        self.assertNotIn("cursor", planned_names)
        self.assertEqual(len(transport.calls), POST_PLAN_CAP * 2)

    def test_numeric_probe_leaves_reflection_features_unobserved(self) -> None:
        result, _material = _safe_result(
            b'{"keyword":"phone","page":41}'
        )

        analysis = analyze_discovery_result(
            result,
            top_k=4,
            transport=RecordingTransport(),
        )

        ids_by_name = {point.name: point.id for point in result.input_points}
        page_vector = next(
            vector
            for vector in analysis.feature_vectors
            if vector.input_point_id == ids_by_name["page"]
        )
        for feature_name in (
            MARKER_REFLECTED,
            REFLECTION_COUNT_NORM,
            SAFE_HTML_ENCODING_DETECTED,
        ):
            with self.subTest(feature=feature_name):
                feature = page_vector.features[feature_name]
                self.assertFalse(feature.observed)
                self.assertIsNone(feature.value)

    def test_second_scalar_plans_do_not_mix_values(self) -> None:
        result, _material = _safe_result(b'{"keyword":"phone","page":1}')
        plans = {
            point.name: ProbePlanner().plan(point, template, context)
            for point, template, context in result.ready_contexts()
        }

        keyword_baseline = dict(plans["keyword"].baseline_request.json_body)
        page_baseline = dict(plans["page"].baseline_request.json_body)
        keyword_probe = dict(plans["keyword"].probe_request.json_body)
        page_probe = dict(plans["page"].probe_request.json_body)
        self.assertEqual(keyword_baseline, page_baseline)
        self.assertEqual(keyword_probe["page"], "1")
        self.assertEqual(page_probe["keyword"], '"phone"')
        self.assertNotEqual(keyword_probe["keyword"], keyword_baseline["keyword"])
        self.assertNotEqual(page_probe["page"], page_baseline["page"])

    def test_persistent_null_without_sidecar_never_plans(self) -> None:
        result, _material = _safe_result(b'{"keyword":"phone","page":1}')
        point, template, context = result.ready_contexts()[0]
        stripped = replace(template, ephemeral_material=None)

        self.assertEqual(stripped.json_body, (("keyword", "null"), ("page", "null")))
        with self.assertRaisesRegex(
            ProbePlanningError,
            "POST_REPLAY_MATERIAL_MISSING",
        ):
            ProbePlanner().plan(point, stripped, context)

    def test_owner_mismatch_is_rejected_before_planning(self) -> None:
        result, material = _safe_result(b'{"keyword":"phone","page":1}')
        point, template, context = result.ready_contexts()[0]
        mismatched = EphemeralRequestMaterial(
            url=ROOT + "api/other",
            query=material.query,
            json_body=material.json_body,
        )

        with self.assertRaisesRegex(ValueError, "structural URL owner"):
            replace(template, ephemeral_material=mismatched)
        forged = replace(template)
        object.__setattr__(forged, "ephemeral_material", mismatched)
        with self.assertRaisesRegex(ProbePlanningError, "owner mismatch"):
            ProbePlanner().plan(point, forged, context)

    def test_forged_material_must_match_url_query_and_structural_members(self) -> None:
        result, material = _safe_result(b'{"keyword":"phone","page":1}')
        point, template, context = result.ready_contexts()[0]
        bad_query = EphemeralRequestMaterial(
            url=ROOT + "api/search?category=one",
            query=(("category", "two"),),
            json_body=material.json_body,
        )
        forged_query = replace(template)
        object.__setattr__(forged_query, "ephemeral_material", bad_query)
        with self.assertRaisesRegex(ProbePlanningError, "URL/query"):
            ProbePlanner().plan(point, forged_query, context)

        bad_members = EphemeralRequestMaterial(
            url=material.url,
            query=material.query,
            json_body=(*material.json_body, ("other", "0")),
        )
        forged_members = replace(template)
        object.__setattr__(forged_members, "ephemeral_material", bad_members)
        with self.assertRaisesRegex(ProbePlanningError, "structural member"):
            ProbePlanner().plan(point, forged_members, context)

    def test_structural_sensitive_graphql_and_nested_post_never_execute(self) -> None:
        cases = (
            (ROOT + "api/update-profile", b'{"nickname":"abc"}'),
            (ROOT + "api/search", b'{"password":"secret"}'),
            (ROOT + "graphql", b'{"query":"query Search { items { id } }"}'),
            (ROOT + "api/search", b'{"filter":{"category":"book"}}'),
        )

        for url, body in cases:
            with self.subTest(url=url, body=body):
                candidate, material = _capture(body, url=url)
                result = _canonical(candidate, material)
                transport = RecordingTransport()
                analysis = analyze_discovery_result(
                    result,
                    top_k=2,
                    transport=transport,
                )

                self.assertGreaterEqual(len(result.input_points), 1)
                self.assertEqual(result.ready_contexts(), ())
                self.assertEqual(transport.calls, [])
                self.assertEqual(analysis.probe_observations, ())

    def test_pipeline_caps_post_plans_before_request_creation(self) -> None:
        body = (
            '{"keyword":"phone",'
            + ",".join(f'"field_{index}":{index}' for index in range(7))
            + "}"
        ).encode()
        result, material = _safe_result(body)
        transport = RecordingTransport()

        request_instance = planner_module.RequestInstance
        with patch.object(
            planner_module,
            "RequestInstance",
            wraps=request_instance,
        ) as request_constructor:
            analysis = analyze_discovery_result(
                result,
                top_k=16,
                transport=transport,
            )

        self.assertEqual(len(result.ready_contexts()), 8)
        self.assertEqual(len(analysis.probe_observations), POST_PLAN_CAP)
        self.assertEqual(len(analysis.feature_vectors), POST_PLAN_CAP)
        self.assertEqual(request_constructor.call_count, POST_PLAN_CAP * 2)
        self.assertEqual(len(transport.calls), POST_PLAN_CAP * 2)
        for observation in analysis.probe_observations:
            self.assertEqual(
                observation.probe_plan.baseline_request.json_body,
                material.json_body,
            )
            self.assertEqual(
                observation.baseline_response.probe_plan_id,
                observation.probe_plan.id,
            )
            self.assertEqual(
                observation.probe_response.probe_plan_id,
                observation.probe_plan.id,
            )
            self.assertEqual(observation.baseline_response.request_role, "baseline")
            self.assertEqual(observation.probe_response.request_role, "probe")

    def test_budgeted_plan_order_count_and_identity_are_deterministic(self) -> None:
        body = (
            '{"keyword":"phone",'
            + ",".join(f'"field_{index}":{index}' for index in range(7))
            + "}"
        ).encode()
        result, _material = _safe_result(body)

        first = analyze_discovery_result(
            result,
            top_k=16,
            transport=RecordingTransport(),
        )
        second = analyze_discovery_result(
            result,
            top_k=16,
            transport=RecordingTransport(),
        )

        first_ids = tuple(item.probe_plan.id for item in first.probe_observations)
        second_ids = tuple(item.probe_plan.id for item in second.probe_observations)
        self.assertEqual(len(first_ids), POST_PLAN_CAP)
        self.assertEqual(first_ids, second_ids)

    def test_value_isolation_preserves_structure_and_uses_each_sidecar(self) -> None:
        first, first_material = _safe_result(b'{"keyword":"phone","page":1}')
        second, second_material = _safe_result(
            b'{"keyword":"different","page":999}'
        )

        self.assertEqual(
            tuple((point.name, point.id) for point in first.input_points),
            tuple((point.name, point.id) for point in second.input_points),
        )
        self.assertEqual(first.request_templates[0].id, second.request_templates[0].id)
        first_plans = {
            point.name: ProbePlanner().plan(point, template, context)
            for point, template, context in first.ready_contexts()
        }
        second_plans = {
            point.name: ProbePlanner().plan(point, template, context)
            for point, template, context in second.ready_contexts()
        }
        for name in first_plans:
            with self.subTest(name=name):
                self.assertEqual(
                    first_plans[name].baseline_request.json_body,
                    first_material.json_body,
                )
                self.assertEqual(
                    second_plans[name].baseline_request.json_body,
                    second_material.json_body,
                )
                self.assertEqual(
                    first_plans[name].probe_marker,
                    second_plans[name].probe_marker,
                )


if __name__ == "__main__":
    unittest.main()
