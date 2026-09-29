from __future__ import annotations

import io
import json
import unittest
from collections import Counter
from contextlib import redirect_stderr
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from vulnspider import cli
from vulnspider.discovery import (
    StaticCrawlerRequest,
    StaticCrawlerResponse,
    StaticCrawlerTransportError,
    extract_static_html,
)
from vulnspider.domain import HttpMethod, RequestInstance
from vulnspider.observation import TransportResponse
from vulnspider.observation.executor import RequestExecutionError
from vulnspider.pipeline import AnalysisResult, analyze_discovery_result
from vulnspider.reporting import build_analysis_report


ROOT_URL = "http://127.0.0.1/"


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


@dataclass
class SinglePageCrawlerTransport:
    html: str
    requests: list[StaticCrawlerRequest] = field(default_factory=list)

    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        self.requests.append(request)
        return StaticCrawlerResponse(
            status_code=200,
            body=self.html.encode("utf-8"),
            content_type="text/html",
            encoding="utf-8",
        )


@dataclass
class FailingCrawlerTransport:
    requests: list[StaticCrawlerRequest] = field(default_factory=list)

    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        self.requests.append(request)
        raise StaticCrawlerTransportError("timeout")


@dataclass
class MarkerTransport:
    requests: list[RequestInstance] = field(default_factory=list)

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        self.requests.append(request)
        marker = next(
            (
                value
                for _name, value in request.query
                if value.startswith("VULNSPIDER_")
            ),
            None,
        )
        body = b"baseline" if marker is None else marker.encode("utf-8")
        return TransportResponse(
            status_code=200,
            body=body,
            elapsed_ms=1.0,
            encoding="utf-8",
        )


@dataclass
class PartiallyFailingMarkerTransport(MarkerTransport):
    """Fail every request derived from one request template."""

    failing_baseline_value: str = ""

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        if self.failing_baseline_value and any(
            value == self.failing_baseline_value for _name, value in request.query
        ):
            self.requests.append(request)
            raise RequestExecutionError("timeout")
        return super().send(request, timeout_seconds=timeout_seconds)


class NativePipelineTests(unittest.TestCase):
    def test_canonical_analysis_executes_ready_get_and_post_contexts(self) -> None:
        discovery = extract_static_html(
            """
            <form method="get" action="/search">
              <input name="q" value="hello">
            </form>
            <form method="post" action="/submit">
              <input name="token" value="one">
            </form>
            <form action="/outer">
              <form action="/nested">
                <input name="incomplete" value="two">
              </form>
            """,
            ROOT_URL,
        ).discovery
        transport = MarkerTransport()

        analysis = analyze_discovery_result(
            discovery,
            top_k=3,
            transport=transport,
        )

        self.assertIsNone(analysis.adapter_result)
        self.assertIs(analysis.discovery_result, discovery)
        self.assertEqual(len(transport.requests), 4)
        self.assertEqual(
            {request.method for request in transport.requests},
            {HttpMethod.GET, HttpMethod.POST},
        )
        self.assertEqual(
            sum("/search?" in request.url for request in transport.requests),
            2,
        )
        self.assertEqual(
            sum("/submit" in request.url for request in transport.requests),
            2,
        )
        self.assertFalse(
            any("does not support HTTP method" in item for item in analysis.warnings)
        )
        self.assertEqual(
            analysis.selection.summary.total_scoring_results,
            4,
        )

    def test_repeated_contexts_produce_one_feature_vector_per_input_point(
        self,
    ) -> None:
        discovery = extract_static_html(
            """
            <a href="/search?q=one">one</a>
            <a href="/search?q=two">two</a>
            """,
            ROOT_URL,
        ).discovery
        transport = MarkerTransport()
        input_point_ids = {item.id for item in discovery.input_points}
        self.assertEqual(len(input_point_ids), 1)
        self.assertEqual(len(discovery.ready_contexts()), 2)

        analysis = analyze_discovery_result(
            discovery,
            top_k=5,
            transport=transport,
        )

        self.assertEqual(len(transport.requests), 4)
        self.assertEqual(len(analysis.feature_vectors), 1)
        vector = analysis.feature_vectors[0]
        self.assertIn(vector.input_point_id, input_point_ids)
        self.assertEqual(len(vector.probe_run_ids), 2)
        self.assertEqual(len(analysis.probe_observations), 2)
        self.assertEqual(
            {item.feature_vector_id for item in analysis.probe_observations},
            {vector.id},
        )
        self.assertEqual(len(analysis.scoring_results), 2)
        candidate_ids = [item.candidate.id for item in analysis.scoring_results]
        self.assertEqual(len(candidate_ids), len(set(candidate_ids)))
        summary = analysis.selection.summary
        self.assertEqual(summary.total_scoring_results, 2)
        self.assertEqual(summary.selected_results, 2)
        selected_ids = {
            item.scoring_result.candidate.id
            for item in analysis.selection.selected
        }
        unrankable_ids = {
            item.candidate.id for item in analysis.selection.unrankable
        }
        self.assertEqual(selected_ids & unrankable_ids, set())

        report = build_analysis_report(analysis)
        self.assertEqual(len(report["feature_vectors"]), 1)
        self.assertEqual(len(report["probe_observations"]), 2)
        self.assertEqual(
            {item["feature_vector_id"] for item in report["probe_observations"]},
            {vector.id},
        )
        self.assertEqual(
            sorted(report["feature_vectors"][0]["probe_run_ids"]),
            sorted(vector.probe_run_ids),
        )

    def test_failed_context_cannot_mask_an_observed_sibling_context(self) -> None:
        discovery = extract_static_html(
            """
            <a href="/search?q=one">one</a>
            <a href="/search?q=two">two</a>
            """,
            ROOT_URL,
        ).discovery
        transport = PartiallyFailingMarkerTransport(failing_baseline_value="two")

        analysis = analyze_discovery_result(
            discovery,
            top_k=5,
            transport=transport,
        )

        self.assertEqual(len(analysis.feature_vectors), 1)
        vector = analysis.feature_vectors[0]
        marker = vector.features["marker_reflected"]
        self.assertTrue(marker.observed)
        self.assertEqual(marker.value, 1.0)
        self.assertEqual(marker.details["unobserved_probe_runs"], 1)
        self.assertEqual(analysis.selection.summary.unrankable_results, 0)
        selected_ids = {
            item.scoring_result.candidate.id
            for item in analysis.selection.selected
        }
        unrankable_ids = {
            item.candidate.id for item in analysis.selection.unrankable
        }
        self.assertEqual(selected_ids & unrankable_ids, set())

    def test_empty_discovery_produces_empty_truthful_selection(self) -> None:
        discovery = extract_static_html(
            '<a href="mailto:test@example.test">mail</a>',
            ROOT_URL,
        ).discovery
        transport = MarkerTransport()

        analysis = analyze_discovery_result(
            discovery,
            top_k=2,
            transport=transport,
        )

        self.assertEqual(transport.requests, [])
        self.assertEqual(analysis.selection.summary.total_scoring_results, 0)
        self.assertEqual(analysis.selection.summary.selected_results, 0)
        self.assertEqual(analysis.selection.selected, ())
        self.assertTrue(
            any(item.startswith("discovery ") for item in analysis.warnings)
        )


class NativeCliTests(unittest.TestCase):
    def _url_args(self, output: Path) -> list[str]:
        return [
            "analyze",
            "--url",
            ROOT_URL,
            "--top-k",
            "2",
            "--output",
            str(output),
        ]

    def test_url_input_executes_bounded_get_and_ready_post_with_provenance(
        self,
    ) -> None:
        crawler_transport = SinglePageCrawlerTransport(
            """
            <form method="get" action="/search">
              <input name="q" value="hello">
            </form>
            <form method="post" action="/submit">
              <input name="post_value" value="one">
            </form>
            """
        )
        probe_transport = MarkerTransport()
        captured: list[AnalysisResult] = []
        real_analyze_url = cli.analyze_url

        def capture_analysis(*args: Any, **kwargs: Any) -> AnalysisResult:
            analysis = real_analyze_url(*args, **kwargs)
            captured.append(analysis)
            return analysis

        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            json_path = directory / "report.json"
            html_path = directory / "report.html"
            args = self._url_args(json_path)
            args.extend(
                [
                    "--html-output",
                    str(html_path),
                    "--max-pages",
                    "1",
                    "--max-depth",
                    "0",
                    "--max-requests",
                    "1",
                    "--timeout-seconds",
                    "1.5",
                    "--max-redirects",
                    "0",
                ]
            )

            with patch.object(cli, "analyze_url", new=capture_analysis):
                exit_code = cli.main(
                    args,
                    transport=probe_transport,
                    crawler_transport=crawler_transport,
                )

            report = json.loads(json_path.read_text(encoding="utf-8"))
            html = html_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(captured), 1)
        self.assertEqual(len(crawler_transport.requests), 1)
        self.assertEqual(crawler_transport.requests[0].method, HttpMethod.GET)

        request_counts = Counter(
            (request.method, urlsplit(request.url).path)
            for request in probe_transport.requests
        )
        self.assertEqual(
            request_counts,
            Counter(
                {
                    (HttpMethod.GET, "/search"): 2,
                    (HttpMethod.POST, "/submit"): 2,
                }
            ),
        )
        get_requests = [
            request
            for request in probe_transport.requests
            if request.method == HttpMethod.GET
        ]
        self.assertIn((("q", "hello"),), [item.query for item in get_requests])
        get_probe = next(
            item for item in get_requests if item.query != (("q", "hello"),)
        )
        self.assertEqual([name for name, _value in get_probe.query], ["q"])
        self.assertTrue(get_probe.query[0][1].startswith("VULNSPIDER_"))
        post_requests = [
            request
            for request in probe_transport.requests
            if request.method == HttpMethod.POST
        ]
        self.assertIn((("post_value", "one"),), [item.form for item in post_requests])
        post_probe = next(
            item for item in post_requests if item.form != (("post_value", "one"),)
        )
        self.assertEqual([name for name, _value in post_probe.form], ["post_value"])
        self.assertTrue(post_probe.form[0][1].startswith("VULNSPIDER_"))

        analysis = captured[0]
        discovery = analysis.discovery_result
        self.assertIsNotNone(discovery)
        assert discovery is not None
        ready_contexts = discovery.ready_contexts()
        self.assertEqual(
            {template.method for _point, template, _context in ready_contexts},
            {HttpMethod.GET, HttpMethod.POST},
        )
        discovered_input_ids = {point.id for point in discovery.input_points}
        discovered_template_ids = {
            template.id for template in discovery.request_templates
        }
        ready_context_ids = {
            context.id for _point, _template, context in ready_contexts
        }
        self.assertEqual(
            Counter(
                observation.probe_plan.baseline_request.method
                for observation in analysis.probe_observations
            ),
            Counter({HttpMethod.GET: 1, HttpMethod.POST: 1}),
        )
        for observation in analysis.probe_observations:
            plan = observation.probe_plan
            self.assertIn(observation.input_point_id, discovered_input_ids)
            self.assertIn(plan.request_template_id, discovered_template_ids)
            self.assertIn(plan.request_context_id, ready_context_ids)
            self.assertEqual(
                plan.baseline_request.method,
                plan.probe_request.method,
            )
            self.assertEqual(
                observation.baseline_response.request_id,
                plan.baseline_request.id,
            )
            self.assertEqual(
                observation.probe_response.request_id,
                plan.probe_request.id,
            )
            self.assertEqual(observation.baseline_response.probe_plan_id, plan.id)
            self.assertEqual(observation.probe_response.probe_plan_id, plan.id)

        self.assertEqual(report["selection"]["candidates_scored"], 4)
        self.assertEqual(report["selection"]["selected"], 2)
        self.assertTrue(report["verification_order"])
        self.assertIn("VulnSpider", html)
        self.assertIn("검증 순서", html)
        # The HTML surfaces one finding per input point (its top type).
        for candidate_id in _report_surfaced_candidate_ids(
            report["verification_order"]
        ):
            self.assertIn(candidate_id, html)
        self.assertFalse(
            any("executes GET request contexts only" in item for item in report["warnings"])
        )

    def test_crawler_failure_is_a_warning_not_a_finding(self) -> None:
        crawler_transport = FailingCrawlerTransport()
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"

            exit_code = cli.main(
                self._url_args(output),
                transport=MarkerTransport(),
                crawler_transport=crawler_transport,
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["verification_order"], [])
        self.assertEqual(report["selection"]["candidates_scored"], 0)
        self.assertTrue(
            any("TRANSPORT_TIMEOUT" in item for item in report["warnings"])
        )

    def test_cli_rejects_ambiguous_or_missing_source(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as both_sources:
                cli.main(
                    [
                        "analyze",
                        "--input",
                        "records.json",
                        "--url",
                        ROOT_URL,
                        "--top-k",
                        "1",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(both_sources.exception.code, 2)

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing_source:
                cli.main(
                    [
                        "analyze",
                        "--top-k",
                        "1",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(missing_source.exception.code, 2)

    def test_cli_rejects_invalid_url_and_nonpositive_budgets(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--url",
                        "not-an-absolute-url",
                        "--top-k",
                        "1",
                        "--output",
                        str(output),
                    ],
                    crawler_transport=SinglePageCrawlerTransport(""),
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("loopback", error_output.getvalue())
            self.assertFalse(output.exists())

        for option in ("--max-pages", "--max-requests", "--timeout-seconds"):
            with self.subTest(option=option), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as invalid_budget:
                    cli.main(
                        [
                            "analyze",
                            "--url",
                            ROOT_URL,
                            "--top-k",
                            "1",
                            "--output",
                            "report.json",
                            option,
                            "0",
                        ]
                    )
            self.assertEqual(invalid_budget.exception.code, 2)

    def test_cli_rejects_native_policy_options_for_legacy_input(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            records = directory / "records.json"
            records.write_text("[]", encoding="utf-8")
            error_output = io.StringIO()

            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                        "--max-pages",
                        "1",
                    ],
                    transport=MarkerTransport(),
                )

        self.assertEqual(exit_code, 2)
        self.assertIn("require --url", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
