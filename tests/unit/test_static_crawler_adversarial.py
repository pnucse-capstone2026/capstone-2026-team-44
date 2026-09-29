from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from tests.unit.test_static_crawler import FakeTransport, html_response
from vulnspider.discovery import (
    CrawlPolicy,
    DiscoverySafetyInvariant,
    StaticCrawler,
    StaticCrawlerError,
    StaticCrawlerResponse,
    StaticCrawlerTransportError,
    canonicalize_crawl_url,
    extract_static_html,
    extract_static_html_with_sensitive_form_elision,
)


ROOT_URL = "http://example.test/"


class StaticCrawlerAdversarialTests(unittest.TestCase):
    def test_http_error_safety_invariant_is_bound_to_eliding_extractor(
        self,
    ) -> None:
        response = StaticCrawlerResponse(
            status_code=404,
            body=b"not found",
            content_type="text/html",
        )

        default_result = StaticCrawler(
            transport=FakeTransport({ROOT_URL: response}),
            extractor=extract_static_html,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)
        eliding_result = StaticCrawler(
            transport=FakeTransport({ROOT_URL: response}),
            extractor=extract_static_html_with_sensitive_form_elision,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)

        self.assertEqual(default_result.discovery.safety_invariants, ())
        self.assertEqual(
            eliding_result.discovery.safety_invariants,
            (
                DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
            ),
        )

    def test_cross_origin_link_never_reaches_transport(self) -> None:
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    """
                    <a href="https://outside.test/private">outside</a>
                    <a href="http://sub.example.test/path">subdomain</a>
                    <a href="/inside">inside</a>
                    """
                ),
                "http://example.test/inside": html_response("<p>inside</p>"),
            }
        )
        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)

        self.assertEqual(
            [item.url for item in transport.requests],
            [ROOT_URL, "http://example.test/inside"],
        )
        self.assertEqual(
            {item.code for item in result.discovery.warnings},
            {"OFF_SCOPE_LINK"},
        )

    def test_cross_origin_redirect_is_blocked_before_request(self) -> None:
        transport = FakeTransport(
            {
                ROOT_URL: StaticCrawlerResponse(
                    status_code=302,
                    redirect_location="https://outside.test/redirected",
                )
            }
        )
        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)

        self.assertEqual([item.url for item in transport.requests], [ROOT_URL])
        self.assertIn(
            "OFF_SCOPE_REDIRECT",
            {item.code for item in result.discovery.warnings},
        )

    def test_redirect_loop_and_limit_are_bounded(self) -> None:
        loop_transport = FakeTransport(
            {
                ROOT_URL: StaticCrawlerResponse(
                    status_code=302,
                    redirect_location="/loop",
                ),
                "http://example.test/loop": StaticCrawlerResponse(
                    status_code=302,
                    redirect_location="/",
                ),
            }
        )
        loop_result = StaticCrawler(
            transport=loop_transport,
            clock=lambda: 0.0,
        ).crawl(
            ROOT_URL,
            CrawlPolicy(max_requests=5, max_redirects=4),
        )
        self.assertEqual(
            [item.url for item in loop_transport.requests],
            [ROOT_URL, "http://example.test/loop"],
        )
        self.assertIn(
            "REDIRECT_LOOP",
            {item.code for item in loop_result.discovery.warnings},
        )

        limit_transport = FakeTransport(
            {
                ROOT_URL: StaticCrawlerResponse(
                    status_code=302,
                    redirect_location="/one",
                ),
                "http://example.test/one": StaticCrawlerResponse(
                    status_code=302,
                    redirect_location="/two",
                ),
            }
        )
        limit_result = StaticCrawler(
            transport=limit_transport,
            clock=lambda: 0.0,
        ).crawl(
            ROOT_URL,
            CrawlPolicy(max_requests=5, max_redirects=1),
        )
        self.assertEqual(
            [item.url for item in limit_transport.requests],
            [ROOT_URL, "http://example.test/one"],
        )
        self.assertIn(
            "REDIRECT_LIMIT_REACHED",
            {item.code for item in limit_result.discovery.warnings},
        )

    def test_root_validation_and_url_canonicalization(self) -> None:
        for invalid in (
            "",
            "relative/path",
            "ftp://example.test/",
            "javascript:alert(1)",
            "http://[::1",
            "http://user:secret@example.test/",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(StaticCrawlerError):
                    StaticCrawler(
                        transport=FakeTransport({}),
                        clock=lambda: 0.0,
                    ).crawl(invalid)

        self.assertEqual(
            canonicalize_crawl_url("HTTP://Example.TEST:80#fragment"),
            "http://example.test/",
        )
        self.assertEqual(
            canonicalize_crawl_url("https://EXAMPLE.test:443/a?x=1&x=2"),
            "https://example.test/a?x=1&x=2",
        )
        self.assertNotEqual(
            canonicalize_crawl_url("http://example.test/?a=1&a=2"),
            canonicalize_crawl_url("http://example.test/?a=2&a=1"),
        )
        self.assertNotEqual(
            canonicalize_crawl_url("http://example.test/?a=%2F"),
            canonicalize_crawl_url("http://example.test/?a=/"),
        )

    def test_duplicate_canonical_urls_are_requested_once(self) -> None:
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    """
                    <a href="http://EXAMPLE.test:80">one</a>
                    <a href="/#fragment">two</a>
                    <a href="/">three</a>
                    """
                )
            }
        )
        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)

        self.assertEqual(result.visited_urls, (ROOT_URL,))
        self.assertEqual(len(transport.requests), 1)

    def test_timeout_and_http_error_do_not_abort_later_pages(self) -> None:
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    """
                    <a href="/a-timeout">timeout</a>
                    <a href="/b-missing">missing</a>
                    <a href="/c-ok">ok</a>
                    """
                ),
                "http://example.test/a-timeout": StaticCrawlerTransportError(
                    "timeout"
                ),
                "http://example.test/b-missing": StaticCrawlerResponse(
                    status_code=404,
                    body=b"missing",
                    content_type="text/html",
                ),
                "http://example.test/c-ok": html_response(
                    '<a href="/after">after</a>'
                ),
                "http://example.test/after": html_response("<p>after</p>"),
            }
        )
        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(
            ROOT_URL,
            CrawlPolicy(max_pages=3, max_depth=2, max_requests=5),
        )

        self.assertIn("http://example.test/c-ok", result.processed_urls)
        self.assertIn("http://example.test/after", result.processed_urls)
        codes = {item.code for item in result.discovery.warnings}
        self.assertIn("TRANSPORT_TIMEOUT", codes)
        self.assertIn("HTTP_ERROR", codes)

    def test_elapsed_budget_bounds_transport_timeout_and_response_use(self) -> None:
        now = [0.0]

        class AdvancingTransport(FakeTransport):
            def send(self, request, **kwargs):
                response = super().send(request, **kwargs)
                now[0] += 0.75
                return response

        transport = AdvancingTransport(
            {ROOT_URL: html_response('<a href="/never">never</a>')}
        )
        result = StaticCrawler(
            transport=transport,
            clock=lambda: now[0],
        ).crawl(
            ROOT_URL,
            CrawlPolicy(
                max_elapsed_seconds=0.5,
                timeout_seconds=2.0,
            ),
        )

        self.assertEqual(transport.timeout_values, [0.5])
        self.assertEqual(result.processed_urls, ())
        self.assertIn(
            "ELAPSED_BUDGET_EXHAUSTED",
            {item.code for item in result.discovery.warnings},
        )

    def test_oversized_and_non_html_responses_never_reach_extractor(self) -> None:
        extracted_urls: list[str] = []

        def recording_extractor(
            html: str,
            source_url: str,
            **kwargs: object,
        ):
            extracted_urls.append(source_url)
            return extract_static_html(html, source_url, **kwargs)

        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    '<a href="/large">large</a><a href="/plain">plain</a>'
                ),
                "http://example.test/large": StaticCrawlerResponse(
                    status_code=200,
                    body=b"x" * 32,
                    content_type="text/html",
                    oversized=True,
                ),
                "http://example.test/plain": StaticCrawlerResponse(
                    status_code=200,
                    body=b"<form><input name='bad'></form>",
                    content_type="text/plain",
                ),
            }
        )
        result = StaticCrawler(
            transport=transport,
            extractor=recording_extractor,
            clock=lambda: 0.0,
        ).crawl(
            ROOT_URL,
            CrawlPolicy(max_response_bytes=16, max_requests=3),
        )

        self.assertEqual(extracted_urls, [ROOT_URL])
        codes = {item.code for item in result.discovery.warnings}
        self.assertIn("RESPONSE_BODY_TOO_LARGE", codes)
        self.assertIn("NON_HTML_RESPONSE", codes)
        self.assertNotIn(
            "bad",
            {item.name for item in result.discovery.input_points},
        )

    def test_query_order_and_post_non_submission_are_preserved(self) -> None:
        ordered_url = "http://example.test/ordered?a=2&a=1&a=%2F"
        transport = FakeTransport(
            {
                ROOT_URL: html_response(
                    """
                    <a href="/ordered?a=2&a=1&a=%2F">ordered</a>
                    <form method="post" action="/submit">
                      <input name="password" value="secret">
                    </form>
                    """
                ),
                ordered_url: html_response("<p>ordered</p>"),
            }
        )
        result = StaticCrawler(
            transport=transport,
            clock=lambda: 0.0,
        ).crawl(ROOT_URL)

        self.assertEqual(result.visited_urls, (ROOT_URL, ordered_url))
        template = next(
            item
            for item in result.discovery.request_templates
            if item.url == ordered_url
        )
        self.assertEqual(
            template.query,
            (("a", "2"), ("a", "1"), ("a", "/")),
        )
        self.assertNotIn(
            "http://example.test/submit",
            result.visited_urls,
        )
        self.assertTrue(
            all(item.method.value == "GET" for item in transport.requests)
        )

    def test_input_permutation_produces_same_result(self) -> None:
        first_html = '<a href="/b?q=2">b</a><a href="/a?q=1">a</a>'
        second_html = '<a href="/a?q=1">a</a><a href="/b?q=2">b</a>'

        def crawl(html: str):
            transport = FakeTransport(
                {
                    ROOT_URL: html_response(html),
                    "http://example.test/a?q=1": html_response("<p>a</p>"),
                    "http://example.test/b?q=2": html_response("<p>b</p>"),
                }
            )
            return StaticCrawler(
                transport=transport,
                clock=lambda: 0.0,
            ).crawl(ROOT_URL)

        self.assertEqual(crawl(first_html).to_dict(), crawl(second_html).to_dict())

    def test_identity_is_independent_of_python_hash_seed(self) -> None:
        html = '<a href="/b?q=2">b</a><a href="/a?q=1">a</a>'
        script = "\n".join(
            (
                "import json",
                "from vulnspider.discovery import "
                "StaticCrawler, StaticCrawlerResponse",
                f"root={ROOT_URL!r}",
                f"html={html!r}",
                "class T:",
                "    def send(self, request, **kwargs):",
                "        bodies={",
                "            root: html,",
                "            'http://example.test/a?q=1': '<p>a</p>',",
                "            'http://example.test/b?q=2': '<p>b</p>',",
                "        }",
                "        return StaticCrawlerResponse(",
                "            200, bodies[request.url].encode(),",
                "            content_type='text/html', encoding='utf-8'",
                "        )",
                "result=StaticCrawler(transport=T(), clock=lambda:0.0).crawl(root)",
                "print(json.dumps(result.to_dict(),sort_keys=True,separators=(',',':')))",
            )
        )
        project_root = Path(__file__).resolve().parents[2]
        outputs: list[str] = []
        for seed in ("1", "991"):
            env = os.environ.copy()
            env["PYTHONHASHSEED"] = seed
            env["PYTHONPATH"] = str(project_root / "src")
            completed = subprocess.run(
                [sys.executable, "-B", "-c", script],
                cwd=project_root,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
