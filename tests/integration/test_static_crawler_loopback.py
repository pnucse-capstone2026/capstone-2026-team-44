from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import time
import unittest

from vulnspider.discovery import (
    CrawlPolicy,
    StaticCrawler,
    StaticCrawlerRequest,
    UrlLibStaticCrawlerTransport,
)


class _QuietThreadingHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        return


@contextmanager
def loopback_site():
    primary_log: list[tuple[str, str]] = []
    sentinel_log: list[tuple[str, str]] = []

    class SentinelHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            sentinel_log.append(("GET", self.path))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    sentinel = _QuietThreadingHttpServer(("127.0.0.1", 0), SentinelHandler)
    sentinel_thread = Thread(target=sentinel.serve_forever, daemon=True)
    sentinel_thread.start()
    sentinel_url = f"http://127.0.0.1:{sentinel.server_port}"

    class PrimaryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            primary_log.append(("GET", self.path))
            route = self.path.split("?", 1)[0]
            if route == "/":
                self._html(
                    f"""
                    <a href="/page-a">a</a>
                    <a href="/page-a#fragment">a duplicate</a>
                    <a href="/page-b?x=1&x=1">b</a>
                    <a href="/redirect-local">local redirect</a>
                    <a href="/redirect-external">external redirect</a>
                    <a href="/redirect-loop-a">loop</a>
                    <a href="/non-html">plain</a>
                    <a href="/missing">missing</a>
                    <a href="/slow">slow</a>
                    <a href="/large">large</a>
                    <a href="/zz-after-slow">after slow</a>
                    <a href="{sentinel_url}/external-link">external link</a>
                    <a href="javascript:alert(1)">javascript</a>
                    <a href="http://[::1">malformed</a>
                    <form action="/search">
                      <input name="q" value="books">
                    </form>
                    <form method="post" action="/submit">
                      <input name="token" value="secret">
                    </form>
                    """
                )
                return
            if route == "/page-a":
                self._html("<p>page a</p>")
                return
            if route == "/page-b":
                self._html("<p>page b</p>")
                return
            if route == "/redirect-local":
                self._redirect("/redirect-target#fragment")
                return
            if route == "/redirect-target":
                self._html("<p>redirect target</p>")
                return
            if route == "/redirect-external":
                self._redirect(f"{sentinel_url}/external-redirect")
                return
            if route == "/redirect-loop-a":
                self._redirect("/redirect-loop-b")
                return
            if route == "/redirect-loop-b":
                self._redirect("/redirect-loop-a")
                return
            if route == "/non-html":
                self._send(200, b'{"ok":true}', "application/json")
                return
            if route == "/missing":
                self._send(404, b"missing", "text/plain")
                return
            if route == "/slow":
                time.sleep(0.15)
                self._html("<p>too slow</p>")
                return
            if route == "/large":
                self._send(200, b"x" * 4096, "text/html")
                return
            if route == "/zz-after-slow":
                self._html("<p>after timeout</p>")
                return
            self._send(404, b"unexpected", "text/plain")

        def do_POST(self) -> None:
            primary_log.append(("POST", self.path))
            self._send(405, b"post forbidden", "text/plain")

        def _html(self, text: str) -> None:
            self._send(200, text.encode("utf-8"), "text/html; charset=utf-8")

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    primary = _QuietThreadingHttpServer(("127.0.0.1", 0), PrimaryHandler)
    primary_thread = Thread(target=primary.serve_forever, daemon=True)
    primary_thread.start()
    try:
        yield (
            f"http://127.0.0.1:{primary.server_port}/",
            primary_log,
            sentinel_log,
        )
    finally:
        primary.shutdown()
        primary.server_close()
        primary_thread.join(timeout=1.0)
        sentinel.shutdown()
        sentinel.server_close()
        sentinel_thread.join(timeout=1.0)


class StaticCrawlerLoopbackTests(unittest.TestCase):
    def test_real_transport_enforces_scope_budgets_and_get_only(self) -> None:
        with loopback_site() as (root_url, primary_log, sentinel_log):
            result = StaticCrawler().crawl(
                root_url,
                CrawlPolicy(
                    max_pages=8,
                    max_depth=1,
                    max_requests=20,
                    timeout_seconds=0.05,
                    max_redirects=3,
                    delay_seconds=0.0,
                    max_elapsed_seconds=5.0,
                    max_response_bytes=2048,
                ),
            )

        self.assertEqual(sentinel_log, [])
        self.assertTrue(primary_log)
        self.assertEqual({method for method, _ in primary_log}, {"GET"})
        requested_paths = [path for _, path in primary_log]
        self.assertNotIn("/submit", requested_paths)
        self.assertNotIn("/search?q=books", requested_paths)
        self.assertIn("/redirect-target", requested_paths)
        self.assertIn("/zz-after-slow", requested_paths)
        self.assertNotIn("/external-link", requested_paths)
        self.assertNotIn("/external-redirect", requested_paths)

        codes = {item.code for item in result.discovery.warnings}
        self.assertIn("OFF_SCOPE_LINK", codes)
        self.assertIn("OFF_SCOPE_REDIRECT", codes)
        self.assertIn("REDIRECT_LOOP", codes)
        self.assertIn("NON_HTML_RESPONSE", codes)
        self.assertIn("HTTP_ERROR", codes)
        self.assertIn("TRANSPORT_TIMEOUT", codes)
        self.assertIn("RESPONSE_BODY_TOO_LARGE", codes)
        repeated = sorted(
            (
                item
                for item in result.discovery.input_points
                if item.name == "x"
            ),
            key=lambda item: item.occurrence_index or 0,
        )
        self.assertEqual(
            [item.occurrence_index for item in repeated],
            [0, 1],
        )
        stats = result.discovery.crawl_statistics
        self.assertEqual(stats.requests_attempted, len(primary_log))
        self.assertLessEqual(stats.requests_attempted, stats.request_budget)
        self.assertLessEqual(stats.pages_processed, stats.page_budget)
        result.discovery.validate()

    def test_real_transport_reads_only_limit_plus_sentinel_byte(self) -> None:
        with loopback_site() as (root_url, _, _):
            response = UrlLibStaticCrawlerTransport().send(
                StaticCrawlerRequest(root_url + "large"),
                timeout_seconds=1.0,
                max_response_bytes=32,
            )

        self.assertTrue(response.oversized)
        self.assertEqual(len(response.body), 32)


if __name__ == "__main__":
    unittest.main()
