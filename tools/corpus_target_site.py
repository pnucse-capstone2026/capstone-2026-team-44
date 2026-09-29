"""Labeled loopback applications used as the corpus source.

Layer 1's weights and Layer 3's guarantee need labeled data. The safety rules
in ``AGENTS.md`` allow exactly one place to get it: authorized localhost and
loopback targets. This module generates a family of small applications whose
ground truth is known because it is authored here -- the same reason DVWA and
WebGoat can serve as labeled corpora.

Every application binds to 127.0.0.1 on an ephemeral port and serves only its
own routes.

Realism, not separability
-------------------------
A corpus where vulnerable and safe candidates are trivially distinguishable
teaches nothing and would make the fitted model look better than it is. The
behaviours below are chosen so the four currently extracted features cannot
cleanly separate them:

* ``SAFE_VALIDATION`` returns a 400 for a non-numeric value with a plain
  validation message. It fires ``status_code_changed`` exactly as an
  error-based injection does, so the heuristic's flat 20 points for that
  feature generate real false positives.
* ``SQLI_BLIND`` never emits a SQL error. Only a modest length difference
  separates it from safe, so ``sql_error_pattern`` cannot find it.
* ``XSS_ESCAPED`` reflects the probe marker into an HTML-escaped context. The
  marker is alphanumeric, so ``marker_reflected`` fires identically to a real
  reflection. **The four implemented features cannot tell it apart from
  ``XSS_RAW``.** That is a true limitation of the current feature set, it is
  what ``safe_html_encoding_detected`` exists to fix, and leaving it in the
  corpus is what makes the fitted XSS probability honest rather than flattering.

``response_length_diff_ratio`` must not be a perfect label lookup
-----------------------------------------------------------------
An earlier version rendered one fixed-length template per behaviour, so every
route sharing a behaviour produced the *identical* length-diff ratio and that
one feature separated the labels perfectly within each family. Real applications
are not like that: a benign search page returns a different-length response for
a different query, and page size varies from route to route regardless of
vulnerability. Two reproducible, per-route sources of variation restore that:

* **Chrome.** Each route carries a static boilerplate block of a reproducible
  random size, served identically on every response. It changes the ratio's
  denominator without creating a baseline/probe difference, so the same
  behaviour lands on different ratios on different routes.
* **Benign dynamic content.** Every response includes a value-dependent number
  of generic result rows. A safe page therefore *also* changes length between
  the baseline and probe requests, so a length change is no longer by itself
  evidence of a vulnerability.

The discriminative signal accordingly lives in the other features -- a SQL error
string, a status-code change, a reflected marker -- while ``SQLI_BLIND``, whose
only tell is length, stays genuinely hard to detect, exactly as blind injection
is in reality.

Run standalone to inspect one application:

    PYTHONPATH=src python tools/corpus_target_site.py
"""

from __future__ import annotations

import random
import threading
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from vulnspider.corpus.ground_truth import (
    GroundTruthKey,
    GroundTruthStore,
    ground_truth_from_entries,
)

HOST = "127.0.0.1"

SQLI_ERROR = "sqli_error"
SQLI_BLIND = "sqli_blind"
XSS_RAW = "xss_raw"
XSS_ESCAPED = "xss_escaped"
SAFE_NUMERIC = "safe_numeric"
SAFE_VALIDATION = "safe_validation"

BEHAVIOURS = (
    SQLI_ERROR,
    SQLI_BLIND,
    XSS_RAW,
    XSS_ESCAPED,
    SAFE_NUMERIC,
    SAFE_VALIDATION,
)

_SQLI_TRUE = frozenset({SQLI_ERROR, SQLI_BLIND})
_XSS_TRUE = frozenset({XSS_RAW})

# Ordered explicitly. Sampling from `list(_SQLI_TRUE | _XSS_TRUE)` would draw
# from a set of strings, whose iteration order changes with the interpreter's
# hash seed, so the "reproducible" corpus would differ run to run under an
# identical --seed. `docs/EVALUATION_PROTOCOL.md` 8 requires the seed to pin
# the result.
_VULNERABLE_BEHAVIOURS = (SQLI_BLIND, SQLI_ERROR, XSS_RAW)
_SAFE_BEHAVIOURS = (SAFE_NUMERIC, SAFE_VALIDATION, XSS_ESCAPED)

# Varied phrasing so the SQL-error regexes are exercised across dialects
# rather than one string being memorised.
_SQL_ERRORS = (
    "You have an error in your SQL syntax near '{value}'",
    "SQLSTATE[42000]: Syntax error or access violation near '{value}'",
    "Unclosed quotation mark after the character string '{value}'",
    "PostgreSQL: unterminated quoted string at or near '{value}'",
    "ORA-00933: SQL command not properly ended near '{value}'",
)

_ROUTE_NAMES = (
    ("/product", "id"),
    ("/search", "q"),
    ("/article", "article_id"),
    ("/user", "uid"),
    ("/category", "cat"),
    ("/order", "order_id"),
    ("/review", "ref"),
    ("/tag", "label"),
    ("/report", "report_id"),
    ("/note", "note"),
)


@dataclass(frozen=True, slots=True)
class RouteSpec:
    """One GET route with one query parameter and one authored behaviour.

    ``chrome_bytes``, ``result_scale`` and ``blind_rows`` are reproducible
    per-route sizes that make ``response_length_diff_ratio`` a noisy, weak
    feature instead of a perfect per-behaviour lookup (see the module docstring).
    """

    path: str
    parameter: str
    behaviour: str
    error_template: str
    chrome_bytes: int = 0
    result_scale: int = 0
    blind_rows: int = 6

    def labels(self) -> tuple[bool, bool]:
        """``(sqli_vulnerable, reflected_xss_vulnerable)``."""

        return self.behaviour in _SQLI_TRUE, self.behaviour in _XSS_TRUE


@dataclass(frozen=True, slots=True)
class ApplicationSpec:
    """One labeled application: its routes and its ground truth."""

    application_id: str
    routes: tuple[RouteSpec, ...]

    def ground_truth(self) -> GroundTruthStore:
        entries: list[tuple[GroundTruthKey, bool]] = []
        for route in self.routes:
            sqli_label, xss_label = route.labels()
            for vulnerability_type, label in (
                ("SQLI", sqli_label),
                ("REFLECTED_XSS", xss_label),
            ):
                entries.append(
                    (
                        GroundTruthKey(
                            application_id=self.application_id,
                            method="GET",
                            canonical_path=route.path,
                            parameter_location="QUERY",
                            parameter_name=route.parameter,
                            vulnerability_type=vulnerability_type,
                        ),
                        label,
                    )
                )
        return ground_truth_from_entries(entries)


def build_application(index: int, *, seed: int = 20260811) -> ApplicationSpec:
    """Generate one reproducible labeled application."""

    generator = random.Random(seed + index * 7919)
    route_count = generator.randint(4, 7)
    chosen = generator.sample(_ROUTE_NAMES, route_count)

    # Guarantee every application has at least one vulnerable and one safe
    # route, so no application degenerates into an all-positive or all-negative
    # group. Conformal calibration needs both.
    behaviours = [
        generator.choice(_VULNERABLE_BEHAVIOURS),
        generator.choice(_SAFE_BEHAVIOURS),
    ]
    while len(behaviours) < route_count:
        behaviours.append(generator.choice(BEHAVIOURS))
    generator.shuffle(behaviours)

    routes = tuple(
        RouteSpec(
            path=path,
            parameter=parameter,
            behaviour=behaviour,
            error_template=generator.choice(_SQL_ERRORS),
            # Wide, independent per-route sizes so the same behaviour lands on
            # different length-diff ratios across routes, and so vulnerable and
            # safe ratio ranges overlap rather than separating cleanly.
            chrome_bytes=generator.randint(0, 3200),
            result_scale=generator.randint(0, 18),
            blind_rows=generator.randint(3, 14),
        )
        for (path, parameter), behaviour in zip(chosen, behaviours, strict=True)
    )
    return ApplicationSpec(application_id=f"app{index:02d}", routes=routes)


def build_applications(count: int, *, seed: int = 20260811) -> tuple[
    ApplicationSpec, ...
]:
    """Generate ``count`` reproducible labeled applications."""

    return tuple(build_application(index, seed=seed) for index in range(count))


def _index_page(spec: ApplicationSpec) -> bytes:
    links = "\n".join(
        f'    <li><a href="{route.path}?{route.parameter}=1">'
        f"{escape(route.path)}</a></li>"
        for route in spec.routes
    )
    return (
        "<html><head><title>corpus target</title></head><body>\n"
        f"  <h1>{escape(spec.application_id)}</h1>\n"
        f"  <ul>\n{links}\n  </ul>\n"
        "</body></html>\n"
    ).encode("utf-8")


# Neutral boilerplate for the per-route chrome block. It carries no probe
# marker and none of the SQL-error phrasing, so padding a response with it moves
# only the length-diff denominator, never the other features.
_CHROME_SENTENCE = "This catalog page lists entries available for browsing. "


def _chrome(route: RouteSpec) -> str:
    """A static per-route boilerplate block of a reproducible size.

    Served identically on every response for the route, so it varies the
    length-diff denominator without ever creating a baseline/probe difference.
    """

    if route.chrome_bytes <= 0:
        return ""
    repeats = route.chrome_bytes // len(_CHROME_SENTENCE) + 1
    filler = (_CHROME_SENTENCE * repeats)[: route.chrome_bytes]
    return f'<div class="chrome">{filler}</div>'


def _benign_rows(route: RouteSpec, value: str) -> str:
    """Value-dependent generic result rows shared by every behaviour.

    A benign search page legitimately returns a different-length response for a
    different query, so the baseline and probe values yield different lengths.
    The rows echo neither the value nor the marker, so this adds length noise
    without touching ``marker_reflected``. ``crc32`` keeps it reproducible
    across interpreter runs, which ``hash()`` would not.
    """

    if route.result_scale <= 0:
        return ""
    count = zlib.crc32(value.encode("utf-8")) % (route.result_scale + 1)
    return "".join(f"<tr><td>result {index}</td></tr>" for index in range(count))


def _page(route: RouteSpec, value: str, inner: str) -> bytes:
    """Wrap one behaviour's ``inner`` markup in the shared chrome and rows."""

    return (
        f"<html><body>{_chrome(route)}{inner}"
        f'<table class="catalog">{_benign_rows(route, value)}</table>'
        "</body></html>"
    ).encode("utf-8")


def _route_body(route: RouteSpec, value: str) -> tuple[int, bytes]:
    numeric = value.isdigit()

    if route.behaviour == SQLI_ERROR:
        if numeric:
            inner = f"<p>Record {escape(value)} loaded.</p>"
            return 200, _page(route, value, inner)
        message = route.error_template.format(value=escape(value))
        inner = f"<p>Database error: {message}</p>"
        return 500, _page(route, value, inner)

    if route.behaviour == SQLI_BLIND:
        # No error text and no status change. A real injection is present but
        # only the response size betrays it -- and the benign rows below muddy
        # even that, which is what makes blind injection hard to detect.
        if numeric:
            leaked = "".join(
                f"<tr><td>row {index}</td><td>value {index}</td></tr>"
                for index in range(route.blind_rows)
            )
            inner = f"<table>{leaked}</table>"
        else:
            inner = "<table></table>"
        return 200, _page(route, value, inner)

    if route.behaviour == XSS_RAW:
        inner = (
            f"<h2>Results for {value}</h2>"
            f"<p>No matches for {value}.</p>"
        )
        return 200, _page(route, value, inner)

    if route.behaviour == XSS_ESCAPED:
        safe = escape(value, quote=True)
        inner = f"<p>No matches for {safe}.</p>"
        return 200, _page(route, value, inner)

    if route.behaviour == SAFE_VALIDATION:
        if numeric:
            inner = f"<p>Item {escape(value)}.</p>"
            return 200, _page(route, value, inner)
        inner = "<p>Invalid identifier supplied.</p>"
        return 400, _page(route, value, inner)

    inner = "<p>Catalog item.</p>"
    return 200, _page(route, value, inner)


def make_handler(spec: ApplicationSpec) -> type[BaseHTTPRequestHandler]:
    """Build a request handler serving exactly this application's routes."""

    routes = {route.path: route for route in spec.routes}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802 - stdlib signature
            parts = urlsplit(self.path)
            if parts.path in ("/", "/index.html"):
                self._respond(200, _index_page(spec))
                return
            route = routes.get(parts.path)
            if route is None:
                self._respond(404, b"<html><body>not found</body></html>")
                return
            value = parse_qs(parts.query).get(route.parameter, [""])[0]
            status, body = _route_body(route, value)
            self._respond(status, body)

        def _respond(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


@contextmanager
def serve(spec: ApplicationSpec) -> Iterator[str]:
    """Serve one application on an ephemeral loopback port."""

    server = ThreadingHTTPServer((HOST, 0), make_handler(spec))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{HOST}:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    spec = build_application(0)
    print(f"application: {spec.application_id}")
    for route in spec.routes:
        sqli, xss = route.labels()
        print(
            f"  {route.path}?{route.parameter}=  {route.behaviour:16s} "
            f"SQLI={sqli} XSS={xss}"
        )
    with serve(spec) as base_url:
        print(f"serving at {base_url} (Ctrl+C to stop)")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
