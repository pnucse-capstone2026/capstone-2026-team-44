from __future__ import annotations

from dataclasses import fields
import json
import os
from pathlib import Path
import tempfile
import unittest

from tests.integration.dynamic_loopback_site import DynamicLoopbackSite
from vulnspider.discovery import (
    CollectorKind,
    DynamicCrawlCompletion,
    DynamicCrawler,
    DynamicCrawlPolicy,
    DynamicCrawlTerminationReason,
    DynamicNetworkReason,
    DynamicRequestAuthority,
    preflight_dynamic_browser,
)


class DynamicNavigationLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._original_cwd = Path.cwd()
        cls._browser_workdir = tempfile.TemporaryDirectory(
            prefix="vulnspider-bounded-navigation-"
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

    def test_navigation_basic(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = self._basic_authority(site, include_redirect=True)
            result = DynamicCrawler().crawl(
                site.navigation_start_url,
                DynamicCrawlPolicy(max_depth=2),
                authority,
            )

            self.assertEqual(
                result.visited_urls,
                (
                    site.navigation_start_url,
                    site.navigation_redirect_url,
                    site.navigation_page_a_url,
                    site.navigation_page_b_url,
                    site.navigation_page_c_url,
                ),
            )
            self.assertEqual(
                [item.page_url for item in result.pages],
                [
                    site.navigation_start_url,
                    site.navigation_redirect_target_url,
                    site.navigation_page_a_url,
                    site.navigation_page_b_url,
                    site.navigation_page_c_url,
                ],
            )
            self.assertEqual([item.depth for item in result.pages], [0, 1, 1, 1, 2])
            self.assertEqual(result.completion, DynamicCrawlCompletion.COMPLETE)
            self.assertEqual(
                result.termination_reason,
                DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED,
            )
            self.assertTrue(any(point.name == "from_a" for point in result.discovery.input_points))
            self.assertTrue(any(point.name == "from_c" for point in result.discovery.input_points))
            self.assertEqual(
                result.discovery.discovery_metadata.collector_kind,
                CollectorKind.NATIVE_DYNAMIC,
            )
            self.assertEqual(result.route_actions_attempted, 0)
            self.assertTrue(result.browser_audit.cleanup_complete)
            self.assertEqual(site.sentinel_requests, ())
            self.assertFalse(any(item.method == "POST" for item in site.primary_requests))

    def test_navigation_dedup_cycle(self) -> None:
        with DynamicLoopbackSite() as site:
            result = DynamicCrawler().crawl(
                site.navigation_start_url,
                DynamicCrawlPolicy(max_depth=2),
                self._basic_authority(site, include_duplicate_redirect=True),
            )

            paths = [item.path for item in site.primary_requests]
            self.assertEqual(paths.count("/navigation/start"), 1)
            self.assertEqual(paths.count("/navigation/page-a"), 1)
            self.assertEqual(paths.count("/navigation/page-b"), 1)
            self.assertEqual(paths.count("/navigation/page-c"), 1)
            self.assertEqual(paths.count("/navigation/z-redirect-duplicate"), 1)
            self.assertEqual(len(result.visited_urls), len(set(result.visited_urls)))
            warning_codes = {item.code for item in result.warnings}
            self.assertIn("DYNAMIC_DUPLICATE_URL", warning_codes)
            self.assertIn("DYNAMIC_REDIRECT_DUPLICATE", warning_codes)
            self.assertEqual(site.sentinel_requests, ())
            self.assertTrue(result.browser_audit.cleanup_complete)

    def test_navigation_authority_block(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.navigation_start_url,
                navigation_urls=(site.navigation_cross_redirect_url,),
            )
            result = DynamicCrawler().crawl(
                site.navigation_start_url,
                DynamicCrawlPolicy(),
                authority,
            )

            self.assertEqual(
                result.visited_urls,
                (site.navigation_start_url, site.navigation_cross_redirect_url),
            )
            self.assertEqual([item.page_url for item in result.pages], [site.navigation_start_url])
            self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
            self.assertEqual(site.sentinel_requests, ())
            primary_paths = [item.path for item in site.primary_requests]
            self.assertNotIn("/delete", primary_paths)
            self.assertNotIn("/state-change", primary_paths)
            self.assertTrue(
                any(
                    event.reason == DynamicNetworkReason.REQUEST_NOT_AUTHORIZED
                    and event.path == "/navigation-redirect-target"
                    for event in result.browser_audit.events
                )
            )
            self.assertTrue(result.browser_audit.cleanup_complete)

    def test_navigation_budget(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = self._basic_authority(site)
            page_limited = DynamicCrawler().crawl(
                site.navigation_start_url,
                DynamicCrawlPolicy(max_pages=2, max_depth=2),
                authority,
            )
            self.assertEqual(page_limited.discovery.crawl_statistics.pages_processed, 2)
            self.assertEqual(
                page_limited.termination_reason,
                DynamicCrawlTerminationReason.PAGE_BUDGET_EXHAUSTED,
            )

            depth_limited = DynamicCrawler().crawl(
                site.navigation_start_url,
                DynamicCrawlPolicy(max_depth=0),
                authority,
            )
            self.assertEqual(depth_limited.visited_urls, (site.navigation_start_url,))
            self.assertEqual(
                depth_limited.termination_reason,
                DynamicCrawlTerminationReason.DEPTH_BUDGET_EXHAUSTED,
            )

            attempt_limited = DynamicCrawler().crawl(
                site.navigation_start_url,
                DynamicCrawlPolicy(max_navigation_attempts=2, max_depth=2),
                authority,
            )
            self.assertEqual(attempt_limited.navigation_attempts, 2)
            self.assertEqual(
                attempt_limited.termination_reason,
                DynamicCrawlTerminationReason.NAVIGATION_BUDGET_EXHAUSTED,
            )
            for item in (page_limited, depth_limited, attempt_limited):
                self.assertTrue(item.browser_audit.cleanup_complete)
            self.assertEqual(site.sentinel_requests, ())

    def test_navigation_failure_isolation(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.navigation_failure_start_url,
                navigation_urls=(
                    site.navigation_not_found_url,
                    site.navigation_server_error_url,
                    site.navigation_good_url,
                    site.navigation_timeout_url,
                ),
            )
            result = DynamicCrawler().crawl(
                site.navigation_failure_start_url,
                DynamicCrawlPolicy(
                    max_pages=5,
                    max_depth=1,
                    navigation_timeout_seconds=0.1,
                ),
                authority,
            )

            self.assertEqual(
                [item.page_url for item in result.pages],
                [site.navigation_failure_start_url, site.navigation_good_url],
            )
            self.assertTrue(
                any(point.name == "after_failure" for point in result.discovery.input_points)
            )
            codes = {item.code for item in result.warnings}
            self.assertIn("DYNAMIC_HTTP_ERROR", codes)
            self.assertIn("DYNAMIC_OPERATIONAL_FAILURE", codes)
            self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
            self.assertTrue(result.browser_audit.cleanup_complete)
            self.assertEqual(site.sentinel_requests, ())

    def test_navigation_sensitive_elision(self) -> None:
        sentinel = "NAV_SECRET_SENTINEL_4c2a"
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.navigation_sensitive_url)
            result = DynamicCrawler().crawl(
                site.navigation_sensitive_url,
                DynamicCrawlPolicy(),
                authority,
            )

            warnings = [
                item for item in result.warnings if item.code == "SENSITIVE_FORM_ELIDED"
            ]
            self.assertEqual(len(warnings), 1)
            self.assertEqual(warnings[0].details["form_occurrence_index"], 1)
            serialized = json.dumps(result.to_dict(), sort_keys=True)
            self.assertNotIn(sentinel, serialized)
            self.assertNotIn("password", serialized.lower())
            self.assertTrue(any(point.name == "safe" for point in result.discovery.input_points))
            self.assertFalse(any(item.method == "POST" for item in site.primary_requests))
            self.assertEqual(site.sentinel_requests, ())
            self.assertTrue(result.browser_audit.cleanup_complete)

    def test_navigation_deterministic(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = self._basic_authority(site)
            policy = DynamicCrawlPolicy(max_depth=2)
            first = DynamicCrawler().crawl(site.navigation_start_url, policy, authority)
            second = DynamicCrawler().crawl(site.navigation_start_url, policy, authority)

            self.assertEqual(self._stable_signature(first), self._stable_signature(second))
            self.assertEqual(site.sentinel_requests, ())
            self.assertTrue(first.browser_audit.cleanup_complete)
            self.assertTrue(second.browser_audit.cleanup_complete)

    @staticmethod
    def _basic_authority(
        site: DynamicLoopbackSite,
        *,
        include_redirect: bool = False,
        include_duplicate_redirect: bool = False,
    ) -> DynamicRequestAuthority:
        navigation_urls = [
            site.navigation_page_a_url,
            site.navigation_page_b_url,
            site.navigation_page_c_url,
        ]
        if include_redirect:
            navigation_urls.extend(
                [
                    site.navigation_redirect_url,
                    site.navigation_redirect_target_url,
                ]
            )
        if include_duplicate_redirect:
            navigation_urls.append(site.navigation_duplicate_redirect_url)
        return DynamicRequestAuthority(
            root_url=site.navigation_start_url,
            navigation_urls=tuple(navigation_urls),
        )

    @staticmethod
    def _stable_signature(result) -> tuple[object, ...]:
        stats = result.discovery.crawl_statistics
        stable_stats = tuple(
            getattr(stats, item.name)
            for item in fields(stats)
            if item.name != "elapsed_ms"
        )
        return (
            result.visited_urls,
            tuple(page.to_dict() for page in result.pages),
            tuple(warning.id for warning in result.warnings),
            stable_stats,
            result.completion,
            result.termination_reason,
            result.navigation_attempts,
            result.route_actions_attempted,
        )


if __name__ == "__main__":
    unittest.main()
