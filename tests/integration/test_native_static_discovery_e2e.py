from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from urllib.parse import parse_qsl, urlsplit

from vulnspider import cli


def _report_number(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _report_surfaced_candidate_ids(verification_order):
    """Candidate ids the HTML report surfaces: the top type per input point.

    Every input point is scored as several candidates (a SQLi and an XSS
    interpretation of one value); the dashboard collapses them to the highest
    type per input point. Group by ``input_point_ref`` the same way.
    """

    best = {}
    for entry in verification_order:
        ref = entry.get("input_point_ref") or entry["candidate_id"]
        score = entry.get("final_confidence", entry["probability"])
        if ref not in best or score > best[ref][0]:
            best[ref] = (score, entry["candidate_id"])
    return {candidate_id for _score, candidate_id in best.values()}


class _QuietThreadingHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        return


class _ReportStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.tags.append(tag)


@contextmanager
def native_static_site():
    primary_log: list[dict[str, str]] = []
    sentinel_log: list[tuple[str, str]] = []

    class SentinelHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            sentinel_log.append(("GET", self.path))
            self._send()

        def do_POST(self) -> None:
            sentinel_log.append(("POST", self.path))
            self._send()

        def _send(self) -> None:
            body = b"sentinel must not be reached"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    sentinel = _QuietThreadingHttpServer(("127.0.0.1", 0), SentinelHandler)
    sentinel_thread = Thread(target=sentinel.serve_forever, daemon=True)
    sentinel_thread.start()
    sentinel_origin = f"http://127.0.0.1:{sentinel.server_port}"

    class PrimaryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._record("GET")
            route = urlsplit(self.path).path
            if route == "/":
                self._html(
                    f"""
                    <a href="/search?q=hello">search</a>
                    <a href="/search?q=hello">duplicate</a>
                    <a href="/search?q=hello#result">fragment duplicate</a>
                    <a href="/search?q=">blank query</a>
                    <a href="/search?q=hello%20world">encoded query</a>
                    <a href="/items?id=1&id=1">repeated query</a>
                    <a href="/form-get">GET form page</a>
                    <a href="/form-post">POST form page</a>
                    <a href="/redirect-local">local redirect</a>
                    <a href="/redirect-external">external redirect</a>
                    <a href="/non-html">non HTML</a>
                    <a href="/missing">missing</a>
                    <a href="{sentinel_origin}/external-link">external</a>
                    <form>
                      <input name="default_q" value="default">
                    </form>
                    <form method="get" action="relative-search">
                      <input name="relative_q" value="relative">
                    </form>
                    """
                )
                return
            if route == "/form-get":
                self._html(
                    """
                    <form method="get" action="/search">
                      <input type="hidden" name="hidden_flag" value="on">
                      <textarea name="note">hello</textarea>
                      <select name="kind">
                        <option value="first">First</option>
                        <option value="second" selected>Second</option>
                      </select>
                    </form>
                    <a href="/too-deep">depth two</a>
                    """
                )
                return
            if route == "/form-post":
                self._html(
                    """
                    <form method="post" action="/post-sentinel">
                      <input name="post_value" value="not-submitted">
                    </form>
                    """
                )
                return
            if route == "/redirect-local":
                self._redirect("/redirect-target")
                return
            if route == "/redirect-external":
                self._redirect(f"{sentinel_origin}/external-redirect")
                return
            if route == "/non-html":
                self._send(200, b'{"ok":true}', "application/json")
                return
            if route == "/missing":
                self._send(404, b"missing", "text/plain")
                return
            if route in {
                "/search",
                "/items",
                "/relative-search",
                "/redirect-target",
                "/too-deep",
            }:
                self._html(f"<p>request {self.path}</p>")
                return
            self._send(404, b"unexpected", "text/plain")

        def do_POST(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length).decode("utf-8")
            self._record("POST", body=body)
            self._send(500, b"POST form was submitted", "text/plain")

        def _record(self, method: str, *, body: str = "") -> None:
            primary_log.append(
                {
                    "method": method,
                    "path": self.path,
                    "body": body,
                    "user_agent": self.headers.get("User-Agent", ""),
                    "cookie": self.headers.get("Cookie", ""),
                    "authorization": self.headers.get("Authorization", ""),
                }
            )

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


class NativeStaticDiscoveryEndToEndTests(unittest.TestCase):
    def test_cli_url_flow_executes_bounded_get_and_ready_post_with_provenance(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            json_path = directory / "native-report.json"
            html_path = directory / "native-report.html"

            with native_static_site() as (
                root_url,
                primary_log,
                sentinel_log,
            ):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--url",
                        root_url,
                        "--top-k",
                        "20",
                        "--output",
                        str(json_path),
                        "--html-output",
                        str(html_path),
                        "--max-pages",
                        "20",
                        "--max-depth",
                        "1",
                        "--max-requests",
                        "20",
                        "--timeout-seconds",
                        "2",
                        "--max-redirects",
                        "2",
                    ]
                )

            json_text = json_path.read_text(encoding="utf-8")
            html_text = html_path.read_text(encoding="utf-8")
            report = json.loads(json_text)

        self.assertEqual(exit_code, 0)
        self.assertTrue(json_text)
        self.assertTrue(html_text)
        self.assertEqual(sentinel_log, [])
        self.assertTrue(primary_log)
        self.assertEqual(
            {entry["method"] for entry in primary_log},
            {"GET", "POST"},
        )
        self.assertTrue(
            all(not entry["cookie"] for entry in primary_log)
        )
        self.assertTrue(
            all(not entry["authorization"] for entry in primary_log)
        )

        crawler_requests = [
            entry
            for entry in primary_log
            if entry["user_agent"] == "VulnSpider/0.2 static discovery"
        ]
        probe_requests = [
            entry
            for entry in primary_log
            if entry["user_agent"] != "VulnSpider/0.2 static discovery"
        ]
        self.assertEqual(len(crawler_requests), 12)
        self.assertLessEqual(len(crawler_requests), 20)
        self.assertEqual({entry["method"] for entry in crawler_requests}, {"GET"})
        probe_method_paths = Counter(
            (entry["method"], urlsplit(entry["path"]).path)
            for entry in probe_requests
        )
        self.assertEqual(
            Counter(
                {
                    method_path: count
                    for method_path, count in probe_method_paths.items()
                    if method_path[0] == "GET"
                }
            ),
            Counter(
                {
                    ("GET", "/search"): 12,
                    ("GET", "/items"): 4,
                    ("GET", "/relative-search"): 2,
                }
            ),
        )
        self.assertEqual(probe_method_paths[("POST", "/post-sentinel")], 2)
        self.assertEqual(
            sum(
                count
                for (method, _path), count in probe_method_paths.items()
                if method == "POST"
            ),
            2,
        )
        post_bodies = [
            tuple(parse_qsl(entry["body"], keep_blank_values=True))
            for entry in probe_requests
            if entry["method"] == "POST"
        ]
        self.assertIn((("post_value", "not-submitted"),), post_bodies)
        post_probe = next(
            body
            for body in post_bodies
            if body != (("post_value", "not-submitted"),)
        )
        self.assertEqual([name for name, _value in post_probe], ["post_value"])
        self.assertTrue(post_probe[0][1].startswith("VULNSPIDER_"))

        crawler_paths = [entry["path"] for entry in crawler_requests]
        self.assertIn("/search?q=hello", crawler_paths)
        self.assertIn("/search?q=", crawler_paths)
        self.assertIn("/search?q=hello%20world", crawler_paths)
        self.assertIn("/items?id=1&id=1", crawler_paths)
        self.assertIn("/form-get", crawler_paths)
        self.assertIn("/form-post", crawler_paths)
        self.assertIn("/redirect-target", crawler_paths)
        self.assertIn("/non-html", crawler_paths)
        self.assertIn("/missing", crawler_paths)
        self.assertNotIn("/too-deep", crawler_paths)
        self.assertEqual(crawler_paths.count("/search?q=hello"), 1)

        self.assertGreater(report["selection"]["candidates_scored"], 0)
        self.assertGreater(report["selection"]["selected"], 0)
        self.assertEqual(
            report["selection"]["selected"],
            len(report["verification_order"]),
        )
        self.assertTrue(
            all(
                candidate["family"] in {"SQLI", "REFLECTED_XSS"}
                for candidate in report["verification_order"]
            )
        )

        warning_text = "\n".join(report["warnings"])
        for warning_code in (
            "OFF_SCOPE_LINK",
            "OFF_SCOPE_REDIRECT",
            "NON_HTML_RESPONSE",
            "HTTP_ERROR",
            "MAX_DEPTH_REACHED",
        ):
            self.assertIn(warning_code, warning_text)
        self.assertNotIn("executes GET request contexts only", warning_text)
        self.assertIn("form_method_provenance=html_default_get", warning_text)

        parser = _ReportStructureParser()
        parser.feed(html_text)
        for required_tag in ("html", "head", "title", "body", "article"):
            self.assertIn(required_tag, parser.tags)
        # The HTML surfaces one finding per input point (its top type); the
        # collapsed lower-type candidates stay in the JSON but not the HTML.
        for candidate_id in _report_surfaced_candidate_ids(
            report["verification_order"]
        ):
            self.assertIn(candidate_id, html_text)

        # The report joins candidates back to their discovered input points and
        # renders both the retained GET path and the explicit READY POST form.
        self.assertIn("query.", html_text)
        self.assertIn("POST http://", html_text)

        candidate_text = json.dumps(report["verification_order"], sort_keys=True)
        for warning_code in (
            "OFF_SCOPE_LINK",
            "OFF_SCOPE_REDIRECT",
            "NON_HTML_RESPONSE",
            "HTTP_ERROR",
        ):
            self.assertNotIn(warning_code, candidate_text)


if __name__ == "__main__":
    unittest.main()
