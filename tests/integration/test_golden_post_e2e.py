from __future__ import annotations

from collections import Counter
import json
import unittest

from tests.integration.dynamic_loopback_site import DynamicLoopbackSite
from vulnspider.discovery import (
    DynamicCrawlPolicy,
    DynamicRequestAuthority,
    ProbeReadyStatus,
)
from vulnspider.domain import HttpMethod
from vulnspider.pipeline import analyze_url
from vulnspider.reporting.analysis_report import render_analysis_report
from vulnspider.reporting.crawl_report import render_crawl_report


PASSWORD_SENTINEL = "GOLDEN_POST_PASSWORD_SENTINEL"
USERNAME_SENTINEL = "golden-post-user"
GRAPHQL_SENTINEL = "GoldenAddItem"
STATE_SENTINEL = "golden-sku"


class GoldenPostEndToEndTests(unittest.TestCase):
    def test_real_spa_post_observation_reaches_bounded_analysis(self) -> None:
        with DynamicLoopbackSite() as site:
            analysis = analyze_url(
                site.golden_post_e2e_url,
                top_k=8,
                dynamic_authority=DynamicRequestAuthority(
                    root_url=site.golden_post_e2e_url,
                    allow_passive_same_origin_fetch_xhr=True,
                ),
                dynamic_policy=DynamicCrawlPolicy(
                    max_pages=1,
                    max_depth=0,
                    max_navigation_attempts=1,
                    request_decision_budget=20,
                ),
            )
            primary_requests = site.primary_requests
            post_requests = site.post_requests
            sentinel_requests = site.sentinel_requests

        discovery = analysis.discovery_result
        combined = analysis.combined_result
        self.assertIsNotNone(discovery)
        self.assertIsNotNone(combined)
        assert discovery is not None
        assert combined is not None
        self.assertEqual(sentinel_requests, ())

        post_endpoints = {
            endpoint.path: endpoint
            for endpoint in discovery.endpoints
            if endpoint.method == HttpMethod.POST
        }
        self.assertTrue(
            {"/api/search", "/cart/add", "/login", "/graphql"}
            <= set(post_endpoints)
        )
        points_by_path = {
            path: tuple(
                point
                for point in discovery.input_points
                if point.endpoint_id == endpoint.id
            )
            for path, endpoint in post_endpoints.items()
        }
        self.assertEqual(
            {point.name for point in points_by_path["/api/search"]},
            {"keyword", "page"},
        )
        self.assertEqual(
            {point.name for point in points_by_path["/cart/add"]},
            {"product_id", "quantity"},
        )
        self.assertEqual(
            {point.name for point in points_by_path["/login"]},
            {"username", "password"},
        )
        self.assertEqual(
            {point.name for point in points_by_path["/graphql"]},
            {"query", "operationname"},
        )

        templates_by_path = {
            path: tuple(
                template
                for template in discovery.request_templates
                if template.endpoint_id == endpoint.id
            )
            for path, endpoint in post_endpoints.items()
        }
        for path in ("/api/search", "/cart/add", "/login", "/graphql"):
            self.assertEqual(len(templates_by_path[path]), 1)
        self.assertEqual(
            templates_by_path["/api/search"][0].metadata[
                "post_replay_disposition"
            ],
            "SAFE_FOR_PROBE",
        )
        self.assertEqual(
            templates_by_path["/cart/add"][0].metadata[
                "post_replay_disposition"
            ],
            "STRUCTURAL_ONLY",
        )
        self.assertEqual(
            templates_by_path["/login"][0].metadata[
                "post_replay_disposition"
            ],
            "BLOCKED_SENSITIVE",
        )
        self.assertEqual(
            templates_by_path["/graphql"][0].metadata[
                "post_replay_disposition"
            ],
            "STRUCTURAL_ONLY",
        )

        readiness = {
            item.input_point_id: item for item in discovery.probe_readiness
        }
        self.assertTrue(
            all(
                readiness[point.id or ""].status == ProbeReadyStatus.READY
                for point in points_by_path["/api/search"]
            )
        )
        for path in ("/cart/add", "/login", "/graphql"):
            self.assertTrue(
                all(
                    readiness[point.id or ""].status
                    == ProbeReadyStatus.NOT_READY
                    for point in points_by_path[path]
                )
            )
        self.assertEqual(
            {
                point.name
                for point, _template, _context in discovery.ready_contexts()
                if point.endpoint_id == post_endpoints["/api/search"].id
            },
            {"keyword", "page"},
        )

        search_template = templates_by_path["/api/search"][0]
        self.assertIsNotNone(search_template.ephemeral_material)
        assert search_template.ephemeral_material is not None
        self.assertEqual(
            search_template.ephemeral_material.json_body,
            (("keyword", '"phone"'), ("page", "1")),
        )
        for path in ("/cart/add", "/login", "/graphql"):
            self.assertIsNone(templates_by_path[path][0].ephemeral_material)

        serialized_discovery = json.dumps(discovery.to_dict(), sort_keys=True)
        crawl_text = render_crawl_report(combined)
        analysis_text = render_analysis_report(analysis)
        for raw_value in (
            "phone",
            USERNAME_SENTINEL,
            PASSWORD_SENTINEL,
            GRAPHQL_SENTINEL,
            STATE_SENTINEL,
        ):
            self.assertNotIn(raw_value, serialized_discovery)
            self.assertNotIn(raw_value, crawl_text)
            self.assertNotIn(raw_value, analysis_text)

        post_counts = Counter(request.path for request in post_requests)
        self.assertEqual(post_counts, Counter({"/api/search": 4}))
        self.assertTrue(
            all(
                request.content_type.startswith("application/json")
                for request in post_requests
            )
        )
        self.assertEqual(
            Counter(
                request.path
                for request in primary_requests
                if request.method == "POST"
            ),
            Counter({"/api/search": 4}),
        )
        ordered_bodies = [
            json.loads(
                request.body.decode("utf-8"),
                object_pairs_hook=tuple,
            )
            for request in post_requests
        ]
        self.assertTrue(
            all(
                tuple(name for name, _value in body)
                == ("keyword", "page")
                for body in ordered_bodies
            )
        )
        self.assertEqual(
            ordered_bodies.count((("keyword", "phone"), ("page", 1))),
            2,
        )
        decoded_bodies = [dict(body) for body in ordered_bodies]
        self.assertEqual(
            decoded_bodies.count({"keyword": "phone", "page": 1}),
            2,
        )
        keyword_probes = [
            body
            for body in decoded_bodies
            if body["keyword"] != "phone" and body["page"] == 1
        ]
        page_probes = [
            body
            for body in decoded_bodies
            if body["keyword"] == "phone" and body["page"] != 1
        ]
        self.assertEqual(len(keyword_probes), 1)
        self.assertIs(type(keyword_probes[0]["keyword"]), str)
        self.assertEqual(page_probes, [{"keyword": "phone", "page": 2}])
        self.assertIs(type(page_probes[0]["page"]), int)

        self.assertEqual(len(analysis.probe_observations), 2)
        self.assertLessEqual(len(analysis.probe_observations), 4)
        self.assertEqual(len(analysis.feature_vectors), 2)
        self.assertEqual(len(analysis.scoring_results), 4)
        names_by_id = {point.id: point.name for point in discovery.input_points}
        self.assertEqual(
            {
                names_by_id[observation.input_point_id]
                for observation in analysis.probe_observations
            },
            {"keyword", "page"},
        )
        for observation in analysis.probe_observations:
            plan = observation.probe_plan
            self.assertEqual(
                plan.baseline_request.json_body,
                search_template.ephemeral_material.json_body,
            )
            self.assertEqual(
                observation.baseline_response.probe_plan_id,
                plan.id,
            )
            self.assertEqual(
                observation.probe_response.probe_plan_id,
                plan.id,
            )
            self.assertEqual(
                observation.baseline_response.request_id,
                plan.baseline_request.id,
            )
            self.assertEqual(
                observation.probe_response.request_id,
                plan.probe_request.id,
            )
            self.assertEqual(
                observation.baseline_response.request_role,
                "baseline",
            )
            self.assertEqual(observation.probe_response.request_role, "probe")


if __name__ == "__main__":
    unittest.main()
