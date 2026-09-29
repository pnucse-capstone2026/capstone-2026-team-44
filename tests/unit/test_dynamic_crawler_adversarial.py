from __future__ import annotations

from dataclasses import replace
import subprocess
import unittest
from unittest.mock import Mock, patch

from tests.unit.test_dynamic_crawler import FakeDynamicBrowser, rendered_snapshot
from vulnspider.discovery import (
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicCrawlCompletion,
    DynamicCrawler,
    DynamicCrawlerError,
    DynamicCrawlPolicy,
    DynamicCrawlTerminationReason,
    DynamicRequestAuthority,
    PlaywrightDynamicBrowser,
)


class DynamicCrawlerAdversarialTests(unittest.TestCase):
    def test_policy_rejects_invalid_and_boolean_budget_values(self) -> None:
        cases = (
            {"max_pages": 0},
            {"max_depth": -1},
            {"max_navigation_attempts": True},
            {"max_route_actions": 0},
            {"max_elapsed_seconds": float("inf")},
            {"navigation_timeout_seconds": 0},
            {"max_redirects_per_navigation": 0},
            {"request_decision_budget": 0},
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(DynamicCrawlerError):
                    DynamicCrawlPolicy(**values)

    def test_root_must_match_immutable_authority_before_browser_run(self) -> None:
        root = "http://127.0.0.1/root"
        browser = FakeDynamicBrowser({root: rendered_snapshot(root)})
        crawler = DynamicCrawler(browser=browser, clock=lambda: 0.0)

        with self.assertRaisesRegex(DynamicCrawlerError, "match immutable"):
            crawler.crawl(
                "http://127.0.0.1/other",
                DynamicCrawlPolicy(),
                DynamicRequestAuthority(root_url=root),
            )

        self.assertIsNone(browser.session)

    def test_page_budget_is_exact_and_never_counts_discovery_as_visit(self) -> None:
        root = "http://127.0.0.1/start"
        page_a = "http://127.0.0.1/a"
        page_b = "http://127.0.0.1/b"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/a"></a><a href="/b"></a>',
                ),
                page_a: rendered_snapshot(page_a),
                page_b: rendered_snapshot(page_b),
            }
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(page_a, page_b),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(max_pages=2),
            authority,
        )

        self.assertEqual(result.visited_urls, (root, page_a))
        self.assertEqual(result.discovery.crawl_statistics.pages_processed, 2)
        self.assertEqual(result.navigation_attempts, 2)
        self.assertEqual(
            result.termination_reason,
            DynamicCrawlTerminationReason.PAGE_BUDGET_EXHAUSTED,
        )
        self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
        self.assertNotIn(page_b, browser.session.navigation_calls)

    def test_depth_and_navigation_budgets_are_not_off_by_one(self) -> None:
        root = "http://127.0.0.1/start"
        page_a = "http://127.0.0.1/a"
        page_b = "http://127.0.0.1/b"
        deep = "http://127.0.0.1/deep"
        snapshots = {
            root: rendered_snapshot(
                root,
                '<a href="/a"></a><a href="/b"></a>',
            ),
            page_a: rendered_snapshot(page_a, '<a href="/deep"></a>'),
            page_b: rendered_snapshot(page_b),
            deep: rendered_snapshot(deep),
        }
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(page_a, page_b, deep),
        )

        depth_result = DynamicCrawler(
            browser=FakeDynamicBrowser(snapshots),
            clock=lambda: 0.0,
        ).crawl(
            root,
            DynamicCrawlPolicy(max_depth=1),
            authority,
        )
        self.assertEqual(depth_result.visited_urls, (root, page_a, page_b))
        self.assertNotIn(deep, depth_result.visited_urls)
        self.assertEqual(
            depth_result.termination_reason,
            DynamicCrawlTerminationReason.DEPTH_BUDGET_EXHAUSTED,
        )

        navigation_result = DynamicCrawler(
            browser=FakeDynamicBrowser(snapshots),
            clock=lambda: 0.0,
        ).crawl(
            root,
            DynamicCrawlPolicy(max_navigation_attempts=2),
            authority,
        )
        self.assertEqual(navigation_result.visited_urls, (root, page_a))
        self.assertEqual(navigation_result.navigation_attempts, 2)
        self.assertEqual(
            navigation_result.termination_reason,
            DynamicCrawlTerminationReason.NAVIGATION_BUDGET_EXHAUSTED,
        )

    def test_navigation_timeout_retains_only_prior_validated_pages(self) -> None:
        root = "http://127.0.0.1/start"
        good = "http://127.0.0.1/a-good"
        timeout = "http://127.0.0.1/z-timeout"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/a-good"></a><a href="/z-timeout"></a>',
                ),
                good: rendered_snapshot(good),
                timeout: rendered_snapshot(timeout),
            },
            errors={timeout: DynamicBrowserErrorCode.NAVIGATION_TIMEOUT},
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(good, timeout),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        self.assertEqual([item.page_url for item in result.pages], [root, good])
        self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
        self.assertEqual(
            result.termination_reason,
            DynamicCrawlTerminationReason.OPERATIONAL_FAILURE,
        )
        self.assertTrue(result.browser_audit.cleanup_complete)
        self.assertFalse(any(item.page_url == timeout for item in result.pages))
        result.discovery.validate()

    def test_integrity_failure_survives_managed_browser_cleanup(self) -> None:
        root = "http://127.0.0.1/start"
        unauthorized = "http://127.0.0.1/not-authorized"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(root),
                unauthorized: rendered_snapshot(unauthorized),
            },
            redirects={root: unauthorized},
        )

        with self.assertRaisesRegex(DynamicCrawlerError, "unauthorized final"):
            DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
                root,
                DynamicCrawlPolicy(),
                DynamicRequestAuthority(root_url=root),
            )

    def test_validated_handoff_rejects_topology_and_completion_tampering(self) -> None:
        root = "http://127.0.0.1/start"
        child = "http://127.0.0.1/child"
        result = DynamicCrawler(
            browser=FakeDynamicBrowser(
                {
                    root: rendered_snapshot(root, '<a href="/child"></a>'),
                    child: rendered_snapshot(child),
                }
            ),
            clock=lambda: 0.0,
        ).crawl(
            root,
            DynamicCrawlPolicy(),
            DynamicRequestAuthority(root_url=root, navigation_urls=(child,)),
        )

        with self.assertRaisesRegex(DynamicCrawlerError, "was not visited"):
            replace(result, visited_urls=(root,))
        with self.assertRaisesRegex(DynamicCrawlerError, "non-final termination"):
            replace(
                result,
                termination_reason=DynamicCrawlTerminationReason.PAGE_BUDGET_EXHAUSTED,
            )
        forged_child = replace(
            result.pages[1],
            parent_url="http://127.0.0.1:8080/foreign",
            depth=99,
        )
        with self.assertRaisesRegex(DynamicCrawlerError, "topology escaped origin"):
            replace(result, pages=(result.pages[0], forged_child))

    def test_concrete_browser_hard_deadline_terminates_worker_tree(self) -> None:
        root = "http://127.0.0.1/start"
        process = Mock()
        process.wait.side_effect = subprocess.TimeoutExpired("worker", 0.05)
        with (
            patch(
                "vulnspider.discovery.dynamic_crawler.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "vulnspider.discovery.dynamic_crawler._terminate_worker_tree"
            ) as terminate,
        ):
            with self.assertRaises(DynamicBrowserError) as raised:
                DynamicCrawler(browser=PlaywrightDynamicBrowser()).crawl(
                    root,
                    DynamicCrawlPolicy(max_elapsed_seconds=0.05),
                    DynamicRequestAuthority(root_url=root),
                )

        self.assertEqual(
            raised.exception.code,
            DynamicBrowserErrorCode.OPERATION_TIMEOUT,
        )
        terminate.assert_called_once_with(process)


if __name__ == "__main__":
    unittest.main()
