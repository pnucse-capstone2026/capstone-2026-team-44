from __future__ import annotations

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import unittest
from unittest.mock import patch

from tests.integration.dynamic_loopback_site import DynamicLoopbackSite
import vulnspider.cli as cli_module
from vulnspider.discovery import (
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    ProbeReadyStatus,
)
from vulnspider.domain import HttpMethod
from vulnspider.pipeline import AnalysisResult


class AdvancedDynamicPassiveCaptureCliTests(unittest.TestCase):
    def test_real_spa_get_surfaces_reach_analysis_only_with_network_provenance(
        self,
    ) -> None:
        stdout = StringIO()
        stderr = StringIO()
        captured: list[AnalysisResult] = []
        real_analyze_url = cli_module.analyze_url

        def capture_analysis(*args: Any, **kwargs: Any) -> AnalysisResult:
            analysis = real_analyze_url(*args, **kwargs)
            captured.append(analysis)
            return analysis

        with TemporaryDirectory(prefix="vulnspider-passive-get-") as workdir:
            output = Path(workdir) / "analysis.json"
            with DynamicLoopbackSite() as site:
                with (
                    patch.object(cli_module, "analyze_url", new=capture_analysis),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    exit_code = cli_module.main(
                        [
                            "analyze",
                            "--url",
                            site.network_canonicalization_url,
                            "--dynamic",
                            "--dynamic-passive-capture",
                            "--dynamic-max-pages",
                            "1",
                            "--dynamic-max-depth",
                            "0",
                            "--dynamic-max-navigation-attempts",
                            "1",
                            "--dynamic-request-decision-budget",
                            "20",
                            "--top-k",
                            "10",
                            "--output",
                            str(output),
                        ]
                    )
                primary_requests = site.primary_requests
                sentinel_requests = site.sentinel_requests
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(captured), 1)
        self.assertNotIn("[ERROR]", stderr.getvalue())
        self.assertGreater(report["selection"]["candidates_scored"], 0)
        self.assertTrue(report["verification_order"])
        self.assertEqual(sentinel_requests, ())
        self.assertFalse(any(item.method == "POST" for item in primary_requests))
        self.assertEqual(
            sum(
                item.method == "HEAD" and item.path == "/api/head"
                for item in primary_requests
            ),
            1,
        )

        analysis = captured[0]
        combined = analysis.combined_result
        discovery = analysis.discovery_result
        self.assertIsNotNone(combined)
        self.assertIsNotNone(discovery)
        assert combined is not None
        assert discovery is not None

        static_paths = {
            endpoint.path for endpoint in combined.static_crawl.discovery.endpoints
        }
        dynamic_endpoints = {
            endpoint.path: endpoint
            for endpoint in combined.dynamic_crawl.discovery.endpoints
        }
        self.assertFalse(
            {"/api/search", "/api/filter", "/api/private"} & static_paths
        )
        self.assertTrue(
            {"/api/search", "/api/filter", "/api/private"}
            <= set(dynamic_endpoints)
        )
        self.assertNotIn("/api/head", dynamic_endpoints)
        self.assertNotIn("/api/post", dynamic_endpoints)
        self.assertNotIn("/api/off-scope", dynamic_endpoints)

        ready_endpoint_ids = {
            dynamic_endpoints["/api/search"].id,
            dynamic_endpoints["/api/filter"].id,
        }
        network_points = tuple(
            point
            for point in discovery.input_points
            if point.endpoint_id in ready_endpoint_ids
        )
        self.assertEqual(
            sorted((point.name, point.occurrence_index) for point in network_points),
            [
                ("category", None),
                ("keyword", None),
                ("page", None),
                ("tag", 0),
                ("tag", 1),
            ],
        )
        self.assertEqual(
            {
                origin
                for point in network_points
                for origin in point.metadata["origin_kinds"]
            },
            {"network_fetch", "network_xhr"},
        )
        self.assertEqual(
            {
                dynamic_endpoints["/api/search"].discovered_by,
                dynamic_endpoints["/api/filter"].discovered_by,
            },
            {"native_dynamic_network"},
        )

        readiness = {
            item.input_point_id: item for item in discovery.probe_readiness
        }
        self.assertTrue(
            all(
                readiness[point.id or ""].status == ProbeReadyStatus.READY
                for point in network_points
            )
        )
        network_point_ids = {point.id for point in network_points}
        observed_input_ids = {
            item.input_point_id for item in analysis.probe_observations
        }
        self.assertTrue(network_point_ids <= observed_input_ids)

        audit = combined.dynamic_crawl.browser_audit
        self.assertIn(
            DynamicNetworkReason.PASSIVE_SAME_ORIGIN_FETCH_XHR,
            {
                event.reason
                for event in audit.events
                if event.decision == DynamicNetworkDecisionKind.ALLOW
            },
        )
        self.assertIn(
            DynamicNetworkReason.NON_GET_METHOD,
            {
                event.reason
                for event in audit.events
                if event.decision == DynamicNetworkDecisionKind.BLOCK
            },
        )
        self.assertIn(
            DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
            {
                event.reason
                for event in audit.events
                if event.decision == DynamicNetworkDecisionKind.BLOCK
            },
        )

    def test_real_spa_post_capture_cannot_bypass_selective_replay_policy(
        self,
    ) -> None:
        stdout = StringIO()
        stderr = StringIO()
        captured: list[AnalysisResult] = []
        real_analyze_url = cli_module.analyze_url

        def capture_analysis(*args: Any, **kwargs: Any) -> AnalysisResult:
            analysis = real_analyze_url(*args, **kwargs)
            captured.append(analysis)
            return analysis

        with TemporaryDirectory(prefix="vulnspider-passive-post-") as workdir:
            output = Path(workdir) / "analysis.json"
            with DynamicLoopbackSite() as site:
                with (
                    patch.object(cli_module, "analyze_url", new=capture_analysis),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    exit_code = cli_module.main(
                        [
                            "analyze",
                            "--url",
                            site.golden_post_e2e_url,
                            "--dynamic",
                            "--dynamic-passive-capture",
                            "--dynamic-max-pages",
                            "1",
                            "--dynamic-max-depth",
                            "0",
                            "--dynamic-max-navigation-attempts",
                            "1",
                            "--dynamic-request-decision-budget",
                            "20",
                            "--top-k",
                            "8",
                            "--output",
                            str(output),
                        ]
                    )
                post_requests = site.post_requests
                sentinel_requests = site.sentinel_requests
            report_text = output.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(captured), 1)
        self.assertNotIn("[ERROR]", stderr.getvalue())
        self.assertEqual(sentinel_requests, ())
        self.assertEqual(
            Counter(item.path for item in post_requests),
            Counter({"/api/search": 4}),
        )

        analysis = captured[0]
        discovery = analysis.discovery_result
        self.assertIsNotNone(discovery)
        assert discovery is not None
        post_endpoints = {
            endpoint.path: endpoint
            for endpoint in discovery.endpoints
            if endpoint.method == HttpMethod.POST
        }
        expected_dispositions = {
            "/api/search": "SAFE_FOR_PROBE",
            "/cart/add": "STRUCTURAL_ONLY",
            "/login": "BLOCKED_SENSITIVE",
            "/graphql": "STRUCTURAL_ONLY",
        }
        self.assertTrue(set(expected_dispositions) <= set(post_endpoints))
        templates_by_path = {
            path: next(
                template
                for template in discovery.request_templates
                if template.endpoint_id == post_endpoints[path].id
            )
            for path in expected_dispositions
        }
        self.assertEqual(
            {
                path: template.metadata["post_replay_disposition"]
                for path, template in templates_by_path.items()
            },
            expected_dispositions,
        )

        readiness = {
            item.input_point_id: item for item in discovery.probe_readiness
        }
        points_by_path = {
            path: tuple(
                point
                for point in discovery.input_points
                if point.endpoint_id == endpoint.id
            )
            for path, endpoint in post_endpoints.items()
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

        safe_ids = {point.id for point in points_by_path["/api/search"]}
        self.assertEqual(
            {item.input_point_id for item in analysis.probe_observations},
            safe_ids,
        )
        for secret in (
            "GOLDEN_POST_PASSWORD_SENTINEL",
            "golden-post-user",
            "GoldenAddItem",
            "golden-sku",
        ):
            self.assertNotIn(secret, report_text)
            self.assertNotIn(secret, stdout.getvalue())
            self.assertNotIn(secret, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
