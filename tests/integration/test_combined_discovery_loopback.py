from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest

from tests.integration.dynamic_loopback_site import DynamicLoopbackSite
from vulnspider.discovery import (
    CollectorKind,
    CrawlPolicy,
    DiscoverySubjectKind,
    DynamicCrawlCompletion,
    DynamicCrawlPolicy,
    DynamicRequestAuthority,
    discover_native_combined,
    preflight_dynamic_browser,
)


class CombinedDiscoveryLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._original_cwd = Path.cwd()
        cls._browser_workdir = tempfile.TemporaryDirectory(
            prefix="vulnspider-combined-discovery-"
        )
        os.chdir(cls._browser_workdir.name)
        try:
            preflight_dynamic_browser()
        except Exception:
            os.chdir(cls._original_cwd)
            cls._browser_workdir.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._original_cwd)
        cls._browser_workdir.cleanup()

    def test_combined_basic(self) -> None:
        with DynamicLoopbackSite() as site:
            result = discover_native_combined(
                site.combined_basic_url,
                authority=DynamicRequestAuthority(site.combined_basic_url),
            )

            combined = result.discovery
            names = [point.name for point in combined.input_points]
            self.assertIn("static_only", names)
            self.assertIn("dynamic_only", names)
            self.assertEqual(names.count("shared"), 1)
            self.assertEqual(
                combined.discovery_metadata.collector_kind,
                CollectorKind.NATIVE_COMBINED,
            )
            shared = next(point for point in combined.input_points if point.name == "shared")
            shared_producers = {
                item.collector_kind
                for item in combined.crawl_provenance
                if item.subject_kind == DiscoverySubjectKind.INPUT_POINT
                and item.subject_id == shared.id
            }
            self.assertEqual(
                shared_producers,
                {CollectorKind.NATIVE_STATIC, CollectorKind.NATIVE_DYNAMIC},
            )
            self.assertEqual(result.completion, DynamicCrawlCompletion.COMPLETE)
            self.assertFalse(result.degraded)
            combined.validate()
            self.assertEqual(site.sentinel_requests, ())
            self.assertTrue(result.dynamic_crawl.browser_audit.cleanup_complete)

    def test_combined_sensitive_elision(self) -> None:
        sentinel = "COMBINED_SECRET_SENTINEL_2c91"
        with DynamicLoopbackSite() as site:
            result = discover_native_combined(
                site.combined_sensitive_url,
                authority=DynamicRequestAuthority(site.combined_sensitive_url),
            )

            combined = result.discovery
            points = [point for point in combined.input_points if point.name == "q"]
            self.assertEqual(len(points), 1)
            self.assertEqual(points[0].baseline_values, ("safe",))
            warnings = [
                warning
                for warning in combined.warnings
                if warning.code == "SENSITIVE_FORM_ELIDED"
            ]
            self.assertEqual(
                [warning.details["producer_kind"] for warning in warnings],
                [CollectorKind.NATIVE_STATIC.value, CollectorKind.NATIVE_DYNAMIC.value],
            )
            serialized = json.dumps(result.to_dict(), sort_keys=True)
            self.assertNotIn(sentinel, serialized)
            self.assertNotIn("password", serialized.lower())
            self.assertFalse(any(item.method == "POST" for item in site.primary_requests))
            self.assertFalse(
                any(sentinel in item.path for item in site.primary_requests)
            )
            self.assertEqual(site.sentinel_requests, ())
            combined.validate()

    def test_combined_multipage(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                site.combined_multipage_url,
                navigation_urls=(
                    site.combined_page_a_url,
                    site.combined_page_b_url,
                ),
            )
            result = discover_native_combined(
                site.combined_multipage_url,
                authority=authority,
                static_policy=CrawlPolicy(max_depth=1),
                dynamic_policy=DynamicCrawlPolicy(max_depth=1, max_pages=3),
            )

            combined = result.discovery
            names = {point.name for point in combined.input_points}
            self.assertTrue(
                {"static_a", "dynamic_a", "shared_page", "dynamic_page"}
                <= names
            )
            point_ids = {
                point.id
                for point in combined.input_points
                if point.name in {
                    "static_a",
                    "dynamic_a",
                    "shared_page",
                    "dynamic_page",
                }
            }
            source_urls = {
                item.source_url
                for item in combined.crawl_provenance
                if item.subject_kind == DiscoverySubjectKind.INPUT_POINT
                and item.subject_id in point_ids
            }
            self.assertEqual(
                source_urls,
                {site.combined_page_a_url, site.combined_page_b_url},
            )
            self.assertEqual(
                [page.page_url for page in result.dynamic_crawl.pages],
                [
                    site.combined_multipage_url,
                    site.combined_page_a_url,
                    site.combined_page_b_url,
                ],
            )
            combined.validate()
            self.assertEqual(site.sentinel_requests, ())
            self.assertFalse(any(item.method == "POST" for item in site.primary_requests))

    def test_combined_deterministic(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(site.combined_basic_url)
            first = discover_native_combined(
                site.combined_basic_url,
                authority=authority,
            )
            second = discover_native_combined(
                site.combined_basic_url,
                authority=authority,
            )

            self.assertEqual(
                self._stable_canonical_json(first.discovery),
                self._stable_canonical_json(second.discovery),
            )
            self.assertEqual(
                tuple(warning.id for warning in first.discovery.warnings),
                tuple(warning.id for warning in second.discovery.warnings),
            )
            self.assertEqual(
                replace(first.discovery.crawl_statistics, elapsed_ms=0.0),
                replace(second.discovery.crawl_statistics, elapsed_ms=0.0),
            )
            self.assertEqual(site.sentinel_requests, ())
            self.assertTrue(first.dynamic_crawl.browser_audit.cleanup_complete)
            self.assertTrue(second.dynamic_crawl.browser_audit.cleanup_complete)

    def test_combined_producer_failure(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                site.navigation_failure_start_url,
                navigation_urls=(
                    site.navigation_not_found_url,
                    site.navigation_server_error_url,
                    site.navigation_good_url,
                    site.navigation_timeout_url,
                ),
            )

            result = discover_native_combined(
                site.navigation_failure_start_url,
                authority=authority,
                static_policy=CrawlPolicy(
                    max_depth=1,
                    timeout_seconds=0.1,
                    max_elapsed_seconds=3.0,
                ),
                dynamic_policy=DynamicCrawlPolicy(
                    max_depth=1,
                    navigation_timeout_seconds=0.1,
                ),
            )

            self.assertTrue(result.degraded)
            self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
            self.assertEqual(result.to_dict()["completion"], "DEGRADED")
            self.assertIn(
                "DYNAMIC_OPERATIONAL_FAILURE",
                {warning.code for warning in result.dynamic_crawl.warnings},
            )
            self.assertTrue(
                any(
                    point.name == "after_failure"
                    for point in result.discovery.input_points
                )
            )
            result.discovery.validate()
            self.assertTrue(result.dynamic_crawl.browser_audit.cleanup_complete)
            self.assertEqual(site.sentinel_requests, ())
            self.assertFalse(any(item.method == "POST" for item in site.primary_requests))

    @staticmethod
    def _stable_canonical_json(discovery) -> str:
        serialized = discovery.to_dict()
        serialized["crawl_statistics"]["elapsed_ms"] = 0.0
        return json.dumps(serialized, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    unittest.main()
