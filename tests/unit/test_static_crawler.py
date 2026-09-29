from __future__ import annotations

from dataclasses import dataclass, field
import unittest

from vulnspider.discovery import (
    CrawlPolicy,
    ProbeReadyStatus,
    StaticCrawler,
    StaticCrawlerRequest,
    StaticCrawlerResponse,
)
from vulnspider.discovery.static_crawler import StaticCrawlerError
from vulnspider.domain import HttpMethod


ROOT_URL = "http://example.test/"


def html_response(
    html: str,
    *,
    status_code: int = 200,
) -> StaticCrawlerResponse:
    return StaticCrawlerResponse(
        status_code=status_code,
        body=html.encode("utf-8"),
        content_type="text/html",
        encoding="utf-8",
    )


@dataclass
class FakeTransport:
    responses: dict[str, StaticCrawlerResponse | Exception]
    requests: list[StaticCrawlerRequest] = field(default_factory=list)
    timeout_values: list[float] = field(default_factory=list)
    response_limits: list[int] = field(default_factory=list)

    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        self.requests.append(request)
        self.timeout_values.append(timeout_seconds)
        self.response_limits.append(max_response_bytes)
        outcome = self.responses[request.url]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class SessionCookieTests(unittest.TestCase):
    def test_session_cookies_reach_every_request_and_template(self) -> None:
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    '<form method="get" action="/search">'
                    '<input name="q" value="x">'
                    '<input type="submit"></form>'
                ),
                "http://example.test/search?q=x": html_response("<p>ok</p>"),
            }
        )

        result = StaticCrawler(transport=transport, clock=lambda: 0.0).crawl(
            ROOT_URL,
            CrawlPolicy(session_cookies=(("sid", "secret-token"),)),
        )

        # The operator's session rides on every crawl request...
        self.assertTrue(transport.requests)
        self.assertTrue(
            all(
                request.cookies == (("sid", "secret-token"),)
                for request in transport.requests
            )
        )
        # ...and on every discovered request template, so a downstream
        # CREDENTIAL_STRIP check has a credential to remove.
        templates = result.discovery.request_templates
        self.assertTrue(templates)
        self.assertTrue(
            all(t.cookies.get("sid") == "secret-token" for t in templates)
        )

    def test_crawl_report_redacts_the_cookie_value_but_keeps_the_name(self) -> None:
        from vulnspider.reporting.crawl_report import build_crawl_report

        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    '<form method="get" action="/search">'
                    '<input name="q" value="x">'
                    '<input type="submit"></form>'
                ),
                "http://example.test/search?q=x": html_response("<p>ok</p>"),
            }
        )
        result = StaticCrawler(transport=transport, clock=lambda: 0.0).crawl(
            ROOT_URL,
            CrawlPolicy(session_cookies=(("sid", "secret-token"),)),
        )

        report = build_crawl_report(result)

        rendered = repr(report)
        self.assertNotIn("secret-token", rendered)
        self.assertIn("sid", rendered)
        self.assertIn("<redacted>", rendered)

    def test_canonical_artifact_redacts_cookie_but_live_template_keeps_it(
        self,
    ) -> None:
        secret = "BAC_COOKIE_PERSISTENCE_SENTINEL"
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    '<form method="get" action="/search">'
                    '<input name="q" value="x">'
                    '<input type="submit"></form>'
                ),
                "http://example.test/search?q=x": html_response("<p>ok</p>"),
            }
        )
        result = StaticCrawler(transport=transport, clock=lambda: 0.0).crawl(
            ROOT_URL,
            CrawlPolicy(session_cookies=(("sid", secret),)),
        )

        self.assertTrue(
            all(template.cookies.get("sid") == secret for template in result.discovery.request_templates)
        )
        self.assertNotIn(secret, repr(result.discovery))
        serialized = result.discovery.to_dict()
        self.assertNotIn(secret, repr(serialized))
        self.assertTrue(
            all(
                template["cookies"] == {"sid": "<redacted>"}
                for template in serialized["request_templates"]
            )
        )

    def test_no_cookie_is_sent_when_none_are_configured(self) -> None:
        transport = FakeTransport({ROOT_URL: html_response("<p>ok</p>")})
        StaticCrawler(transport=transport, clock=lambda: 0.0).crawl(ROOT_URL)
        self.assertTrue(all(r.cookies == () for r in transport.requests))

    def test_policy_validates_pairs_and_serializes_only_names(self) -> None:
        policy = CrawlPolicy(session_cookies=(("sid", "secret-token"),))
        self.assertEqual(policy.to_dict()["session_cookie_names"], ["sid"])
        # The secret value must never enter the serialized policy.
        self.assertNotIn("secret-token", repr(policy.to_dict()))
        with self.assertRaises(StaticCrawlerError):
            CrawlPolicy(session_cookies=(("sid",),))  # type: ignore[arg-type]


class StaticCrawlerTests(unittest.TestCase):
    def test_authentication_state_change_link_never_reaches_transport(self) -> None:
        profile_url = "http://example.test/account/profile"
        logout_url = "http://example.test/logout.php?confirm=yes"
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    '<a href="/logout.php?confirm=yes">Logout</a>'
                    '<a href="/account/profile">Profile</a>'
                ),
                profile_url: html_response("<p>profile</p>"),
            }
        )

        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)

        self.assertEqual(
            [request.url for request in transport.requests],
            [ROOT_URL, profile_url],
        )
        self.assertNotIn(logout_url, result.visited_urls)
        self.assertNotIn(
            logout_url,
            {template.url for template in result.discovery.request_templates},
        )
        self.assertIn(
            "UNSAFE_NAVIGATION_SUPPRESSED",
            {warning.code for warning in result.discovery.warnings},
        )

    def test_query_driven_logout_never_reaches_transport_or_artifact(self) -> None:
        sentinel = "STATIC_CSRF_SECRET_123"
        unsafe_url = (
            "http://example.test/account?action=logout&csrf=" + sentinel
        )
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    '<a href="/safe?x=1">Safe</a>'
                    f'<a href="{unsafe_url}">Logout</a>'
                ),
                "http://example.test/safe?x=1": html_response("<p>safe</p>"),
            }
        )

        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)

        self.assertNotIn(
            unsafe_url,
            [request.url for request in transport.requests],
        )
        self.assertNotIn(sentinel, repr(result.to_dict()))
        self.assertNotIn(
            unsafe_url,
            {template.url for template in result.discovery.request_templates},
        )

    def test_crawls_same_origin_and_merges_extractor_results(self) -> None:
        page_b_url = "http://example.test/page-b?x=1&x=1"
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    """
                    <a href="/page-b?x=1&x=1#first">b</a>
                    <a href="/page-a">a</a>
                    <a href="/page-a#fragment">a duplicate</a>
                    <a href="https://outside.test/path">outside</a>
                    <form action="/search">
                      <input name="q" value="books">
                    </form>
                    <form method="post" action="/submit">
                      <input name="token" value="one">
                    </form>
                    """
                ),
                "http://example.test/page-a": html_response(
                    '<a href="/shared?q=1">shared</a>'
                ),
                page_b_url: html_response(
                    '<a href="/shared?q=1">shared again</a>'
                ),
                "http://example.test/shared?q=1": html_response("<p>shared</p>"),
            }
        )
        policy = CrawlPolicy(
            max_pages=4,
            max_depth=2,
            max_requests=6,
            timeout_seconds=1.25,
            max_redirects=2,
            delay_seconds=0.0,
            max_elapsed_seconds=5.0,
            max_response_bytes=2048,
        )

        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL, policy)

        self.assertEqual(
            result.visited_urls,
            (
                ROOT_URL,
                "http://example.test/page-a",
                page_b_url,
                "http://example.test/shared?q=1",
            ),
        )
        self.assertEqual(result.processed_urls, result.visited_urls)
        self.assertTrue(
            all(request.method == HttpMethod.GET for request in transport.requests)
        )
        self.assertNotIn(
            "http://example.test/search?q=books",
            result.visited_urls,
        )
        self.assertNotIn("http://example.test/submit", result.visited_urls)
        self.assertEqual(transport.timeout_values, [1.25] * 4)
        self.assertEqual(transport.response_limits, [2048] * 4)

        discovery = result.discovery
        discovery.validate()
        repeated = sorted(
            (
                item
                for item in discovery.input_points
                if item.name == "x"
            ),
            key=lambda item: item.occurrence_index or 0,
        )
        self.assertEqual(
            [item.occurrence_index for item in repeated],
            [0, 1],
        )
        self.assertEqual(
            [item.baseline_value for item in repeated],
            ["1", "1"],
        )
        shared = [
            item
            for item in discovery.input_points
            if item.name == "q" and item.baseline_value == "1"
        ]
        self.assertEqual(len(shared), 1)
        self.assertTrue(
            all(
                item.status == ProbeReadyStatus.READY
                for item in discovery.probe_readiness
            )
        )
        stats = discovery.crawl_statistics
        self.assertEqual(stats.requests_attempted, 4)
        self.assertEqual(stats.pages_processed, 4)
        self.assertEqual(stats.html_pages, 4)
        self.assertEqual(stats.page_budget, 4)
        self.assertEqual(stats.request_budget, 6)
        self.assertGreaterEqual(stats.links_discovered, 6)
        self.assertEqual(stats.forms_discovered, 2)
        self.assertIn(
            "OFF_SCOPE_LINK",
            {item.code for item in discovery.warnings},
        )

    def test_depth_page_and_request_budgets_stop_before_transport(self) -> None:
        root = html_response(
            '<a href="/a">a</a><a href="/b">b</a>'
        )
        responses = {
            ROOT_URL: root,
            "http://example.test/a": html_response('<a href="/deep">deep</a>'),
            "http://example.test/b": html_response("<p>b</p>"),
            "http://example.test/deep": html_response("<p>deep</p>"),
        }
        cases = (
            (
                CrawlPolicy(max_pages=5, max_depth=0, max_requests=5),
                (ROOT_URL,),
                "MAX_DEPTH_REACHED",
            ),
            (
                CrawlPolicy(max_pages=1, max_depth=3, max_requests=5),
                (ROOT_URL,),
                "PAGE_BUDGET_EXHAUSTED",
            ),
            (
                CrawlPolicy(max_pages=5, max_depth=3, max_requests=2),
                (ROOT_URL, "http://example.test/a"),
                "REQUEST_BUDGET_EXHAUSTED",
            ),
        )
        for policy, expected, warning_code in cases:
            with self.subTest(policy=policy):
                transport = FakeTransport(dict(responses))
                result = StaticCrawler(
                    transport=transport,
                    clock=lambda: 0.0,
                ).crawl(ROOT_URL, policy)
                self.assertEqual(result.visited_urls, expected)
                self.assertIn(
                    warning_code,
                    {item.code for item in result.discovery.warnings},
                )
                self.assertLessEqual(
                    result.discovery.crawl_statistics.requests_attempted,
                    policy.max_requests,
                )
                self.assertLessEqual(
                    result.discovery.crawl_statistics.pages_processed,
                    policy.max_pages,
                )

    def test_follows_same_origin_redirect_without_parser_hop(self) -> None:
        final_url = "http://example.test/final"
        transport = FakeTransport(
            {
                ROOT_URL: StaticCrawlerResponse(
                    status_code=302,
                    redirect_location="/final#fragment",
                ),
                final_url: html_response('<a href="/done">done</a>'),
                "http://example.test/done": html_response("<p>done</p>"),
            }
        )

        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(
            ROOT_URL,
            CrawlPolicy(max_pages=2, max_depth=1, max_requests=4),
        )

        self.assertEqual(
            result.visited_urls,
            (ROOT_URL, final_url, "http://example.test/done"),
        )
        self.assertEqual(
            result.processed_urls,
            (final_url, "http://example.test/done"),
        )
        self.assertEqual(
            result.discovery.crawl_statistics.redirects_followed,
            1,
        )

    def test_non_html_is_skipped_and_delay_is_applied_between_requests(
        self,
    ) -> None:
        now = [0.0]
        sleeps: list[float] = []

        def clock() -> float:
            return now[0]

        def sleeper(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        transport = FakeTransport(
            {
                ROOT_URL: html_response('<a href="/data">data</a>'),
                "http://example.test/data": StaticCrawlerResponse(
                    status_code=200,
                    body=b'{"ok":true}',
                    content_type="application/json",
                    encoding="utf-8",
                ),
            }
        )
        result = StaticCrawler(
            transport=transport,
            clock=clock,
            sleeper=sleeper,
        ).crawl(
            ROOT_URL,
            CrawlPolicy(
                max_pages=2,
                max_depth=1,
                max_requests=2,
                delay_seconds=0.25,
                max_elapsed_seconds=2.0,
            ),
        )

        self.assertEqual(sleeps, [0.25])
        self.assertEqual(result.processed_urls, (ROOT_URL,))
        self.assertIn(
            "NON_HTML_RESPONSE",
            {item.code for item in result.discovery.warnings},
        )
        self.assertEqual(result.discovery.crawl_statistics.pages_processed, 1)
        self.assertEqual(result.discovery.crawl_statistics.html_pages, 1)


if __name__ == "__main__":
    unittest.main()
