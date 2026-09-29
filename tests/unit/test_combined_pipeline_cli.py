from __future__ import annotations

import io
import json
import pickle
import unittest
from contextlib import redirect_stderr
from dataclasses import FrozenInstanceError, dataclass, field, fields, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from vulnspider import cli
from vulnspider.discovery import (
    BrowserAuditSummary,
    CollectorKind,
    CombinedDiscoveryResult,
    CrawlPolicy,
    DiscoveryMergePolicy,
    DiscoveryMetadata,
    DiscoverySafetyInvariant,
    DynamicCapabilityCode,
    DynamicCapabilityError,
    DynamicCrawlCompletion,
    DynamicCrawlPolicy,
    DynamicCrawlResult,
    DynamicCrawlTerminationReason,
    DynamicIntegrityError,
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    DynamicPageResult,
    DynamicRequestAuthority,
    DynamicResourceKind,
    ProbeReadyStatus,
    RenderedDomExtractionResult,
    SensitiveFormElisionPolicy,
    StaticCrawlerRequest,
    StaticCrawlerResponse,
    StaticCrawlResult,
    extract_static_html,
    merge_discovery_results,
)
from vulnspider.domain import HttpMethod, RequestInstance, stable_fingerprint
from vulnspider.observation import TransportResponse
from vulnspider.pipeline import PipelineError, analyze_url


ROOT_URL = "http://127.0.0.1/"
SENTINEL = "PW_SENTINEL_M6"
HTML = f"""
<html><body>
  <a href="/surface?q=one&q=two">repeated query</a>
  <a href="/account?q=safe">independent safe account surface</a>
  <form method="get" action="/account">
    <input type="password" name="password" value="{SENTINEL}">
  </form>
  <form method="post" action="/submit">
    <input name="token" value="one">
  </form>
  <form action="/outer">
    <form action="/nested">
      <input name="incomplete" value="two">
    </form>
  </form>
</body></html>
"""


@dataclass
class SinglePageCrawlerTransport:
    html: str = HTML
    status_code: int = 200
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
            status_code=self.status_code,
            body=self.html.encode("utf-8"),
            content_type="text/html",
            encoding="utf-8",
        )


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
class RecordingDynamicCrawler:
    outcome: DynamicCrawlResult | Exception
    calls: list[
        tuple[str, DynamicCrawlPolicy, DynamicRequestAuthority]
    ] = field(default_factory=list)

    def crawl(
        self,
        root_url: str,
        policy: DynamicCrawlPolicy,
        authority: DynamicRequestAuthority,
    ) -> DynamicCrawlResult:
        self.calls.append((root_url, policy, authority))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _empty_audit() -> BrowserAuditSummary:
    tuple_fields = {
        "child_frame_commit_kinds",
        "child_frame_completion_kinds",
        "cleanup_error_codes",
        "events",
        "network_observations",
    }
    values = {
        item.name: (
            ()
            if item.name in tuple_fields
            else (True if item.name == "cleanup_complete" else 0)
        )
        for item in fields(BrowserAuditSummary)
    }
    return BrowserAuditSummary(**values)


def _extraction(
    collector_kind: CollectorKind,
    *,
    html: str = HTML,
):
    return extract_static_html(
        html,
        ROOT_URL,
        discovery_metadata=DiscoveryMetadata(
            collector_kind=collector_kind,
            collector_version=f"m6-{collector_kind.value.lower()}/1",
            configuration_fingerprint=stable_fingerprint(
                "m6-combined-pipeline",
                collector_kind.value,
            ),
        ),
        sensitive_form_policy=SensitiveFormElisionPolicy(),
    )


def _static_result(*, html: str = HTML) -> StaticCrawlResult:
    extraction = _extraction(CollectorKind.NATIVE_STATIC, html=html)
    return StaticCrawlResult(
        root_url=ROOT_URL,
        visited_urls=(ROOT_URL,),
        processed_urls=(ROOT_URL,),
        discovery=extraction.discovery,
    )


def _dynamic_result(
    *,
    html: str = HTML,
    completion: DynamicCrawlCompletion = DynamicCrawlCompletion.COMPLETE,
) -> DynamicCrawlResult:
    extraction = _extraction(CollectorKind.NATIVE_DYNAMIC, html=html)
    rendered = RenderedDomExtractionResult(
        source_url=ROOT_URL,
        snapshot_fingerprint=stable_fingerprint("m6-rendered-snapshot", html),
        navigable_links=extraction.navigable_links,
        discovery=extraction.discovery,
    )
    page = DynamicPageResult(
        requested_url=ROOT_URL,
        page_url=ROOT_URL,
        parent_url=None,
        depth=0,
        component=rendered,
    )
    termination = (
        DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED
        if completion == DynamicCrawlCompletion.COMPLETE
        else DynamicCrawlTerminationReason.COMPLETED_WITH_FAILURES
    )
    return DynamicCrawlResult(
        root_url=ROOT_URL,
        visited_urls=(ROOT_URL,),
        pages=(page,),
        completion=completion,
        termination_reason=termination,
        navigation_attempts=0,
        route_actions_attempted=0,
        discovery=extraction.discovery,
        browser_audit=_empty_audit(),
    )


def _combined_result() -> CombinedDiscoveryResult:
    static_result = _static_result()
    dynamic_result = _dynamic_result()
    return CombinedDiscoveryResult(
        root_url=ROOT_URL,
        static_crawl=static_result,
        dynamic_crawl=dynamic_result,
        discovery=merge_discovery_results(
            static_result.discovery,
            dynamic_result.discovery,
            DiscoveryMergePolicy(),
        ),
    )


class CombinedPipelineTests(unittest.TestCase):
    def test_static_http_error_keeps_elision_safety_invariant_for_merge(
        self,
    ) -> None:
        crawler_transport = SinglePageCrawlerTransport(
            "<html></html>",
            status_code=404,
        )
        dynamic_crawler = RecordingDynamicCrawler(
            _dynamic_result(html="<html></html>")
        )

        analysis = analyze_url(
            ROOT_URL,
            top_k=10,
            crawler_transport=crawler_transport,
            dynamic_authority=DynamicRequestAuthority(ROOT_URL),
            dynamic_crawler=dynamic_crawler,
            transport=MarkerTransport(),
        )

        combined = analysis.combined_result
        self.assertIsNotNone(combined)
        assert combined is not None
        self.assertEqual(
            combined.static_crawl.discovery.safety_invariants,
            (
                DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
            ),
        )
        self.assertEqual(
            tuple(item.code for item in combined.static_crawl.warnings),
            ("HTTP_ERROR",),
        )
        self.assertEqual(combined.static_crawl.processed_urls, ())
        self.assertEqual(combined.static_crawl.discovery.endpoints, ())
        combined.dynamic_crawl.discovery.validate()
        combined.discovery.validate()
        self.assertEqual(analysis.selection.summary.total_scoring_results, 0)

    def test_combined_handoff_preserves_contexts_occurrences_and_secrets(
        self,
    ) -> None:
        crawler_transport = SinglePageCrawlerTransport()
        dynamic_crawler = RecordingDynamicCrawler(_dynamic_result())
        probe_transport = MarkerTransport()

        analysis = analyze_url(
            ROOT_URL,
            top_k=10,
            crawl_policy=CrawlPolicy(max_pages=1, max_depth=0, max_requests=1),
            crawler_transport=crawler_transport,
            dynamic_authority=DynamicRequestAuthority(ROOT_URL),
            dynamic_policy=DynamicCrawlPolicy(max_pages=1, max_depth=0),
            dynamic_crawler=dynamic_crawler,
            transport=probe_transport,
        )

        combined = analysis.combined_result
        self.assertIsNotNone(combined)
        assert combined is not None
        self.assertIs(analysis.discovery_result, combined.discovery)
        self.assertIs(analysis.crawl_result, combined.static_crawl)
        self.assertIs(analysis.dynamic_crawl_result, combined.dynamic_crawl)
        self.assertEqual(
            combined.discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_COMBINED,
        )
        combined.discovery.validate()
        with self.assertRaises(FrozenInstanceError):
            combined.root_url = "http://127.0.0.1/changed"  # type: ignore[misc]

        endpoints = {
            endpoint.id: endpoint for endpoint in combined.discovery.endpoints
        }
        repeated = sorted(
            input_point.occurrence_index
            for input_point in combined.discovery.input_points
            if input_point.name == "q"
            and endpoints[input_point.endpoint_id].path == "/surface"
        )
        self.assertEqual(repeated, [0, 1])
        self.assertTrue(
            any(
                input_point.name == "q"
                and endpoints[input_point.endpoint_id].path == "/account"
                for input_point in combined.discovery.input_points
            )
        )
        self.assertFalse(
            any(
                input_point.name == "password"
                for input_point in combined.discovery.input_points
            )
        )

        provenance_by_subject: dict[str, set[CollectorKind]] = {}
        for provenance in combined.discovery.crawl_provenance:
            provenance_by_subject.setdefault(
                provenance.subject_id,
                set(),
            ).add(provenance.collector_kind)
        self.assertTrue(
            any(
                {
                    CollectorKind.NATIVE_STATIC,
                    CollectorKind.NATIVE_DYNAMIC,
                }.issubset(kinds)
                for kinds in provenance_by_subject.values()
            )
        )

        ready = sum(
            item.status == ProbeReadyStatus.READY
            for item in combined.discovery.probe_readiness
        )
        not_ready = sum(
            item.status == ProbeReadyStatus.NOT_READY
            for item in combined.discovery.probe_readiness
        )
        self.assertGreater(ready, 0)
        self.assertGreater(not_ready, 0)
        self.assertIn(
            f"discovery NATIVE_COMBINED: READY contexts={ready}; "
            f"NOT_READY contexts={not_ready}",
            analysis.warnings,
        )
        self.assertTrue(probe_transport.requests)
        get_requests = [
            request
            for request in probe_transport.requests
            if request.method == HttpMethod.GET
        ]
        post_requests = [
            request
            for request in probe_transport.requests
            if request.method == HttpMethod.POST
        ]
        self.assertEqual(len(get_requests), 6)
        self.assertEqual(len(post_requests), 2)
        self.assertEqual(
            {request.method for request in probe_transport.requests},
            {HttpMethod.GET, HttpMethod.POST},
        )
        self.assertTrue(
            all(request.url == "http://127.0.0.1/submit" for request in post_requests)
        )
        self.assertEqual(post_requests[0].form, (("token", "one"),))
        self.assertTrue(post_requests[1].form[0][1].startswith("VULNSPIDER_"))
        self.assertNotIn(SENTINEL, repr(probe_transport.requests))
        serialized = json.dumps(combined.to_dict(), ensure_ascii=False)
        self.assertNotIn(SENTINEL, serialized)
        self.assertNotIn(SENTINEL, "\n".join(analysis.warnings))

    def test_static_default_does_not_enter_combined_discovery(self) -> None:
        with patch("vulnspider.pipeline.discover_native_combined") as combined:
            analysis = analyze_url(
                ROOT_URL,
                top_k=1,
                crawler_transport=SinglePageCrawlerTransport("<html></html>"),
                transport=MarkerTransport(),
            )

        combined.assert_not_called()
        self.assertIsNone(analysis.combined_result)
        self.assertIsNone(analysis.dynamic_crawl_result)
        with self.assertRaisesRegex(PipelineError, "explicit dynamic authority"):
            analyze_url(
                ROOT_URL,
                top_k=1,
                dynamic_policy=DynamicCrawlPolicy(),
            )

    def test_mutated_combined_wrapper_is_revalidated_before_analysis(self) -> None:
        combined = _combined_result()
        object.__setattr__(
            combined.discovery,
            "crawl_statistics",
            replace(
                combined.discovery.crawl_statistics,
                endpoint_count=(
                    combined.discovery.crawl_statistics.endpoint_count + 1
                ),
            ),
        )
        probe_transport = MarkerTransport()
        published: list[CombinedDiscoveryResult] = []

        with patch(
            "vulnspider.pipeline.discover_native_combined",
            return_value=combined,
        ), self.assertRaises(DynamicIntegrityError):
            analyze_url(
                ROOT_URL,
                top_k=1,
                dynamic_authority=DynamicRequestAuthority(ROOT_URL),
                transport=probe_transport,
                on_crawl_validated=published.append,
            )

        self.assertEqual(probe_transport.requests, [])
        self.assertEqual(published, [])

    def test_validated_combined_crawl_is_handed_off_before_probe_failure(self) -> None:
        combined = _combined_result()
        published: list[CombinedDiscoveryResult | StaticCrawlResult] = []

        with (
            patch(
                "vulnspider.pipeline.discover_native_combined",
                return_value=combined,
            ),
            patch(
                "vulnspider.pipeline.analyze_discovery_result",
                side_effect=PipelineError("probe failure"),
            ),
            self.assertRaisesRegex(PipelineError, "probe failure"),
        ):
            analyze_url(
                ROOT_URL,
                top_k=1,
                dynamic_authority=DynamicRequestAuthority(ROOT_URL),
                on_crawl_validated=published.append,
            )

        self.assertEqual(len(published), 1)
        self.assertEqual(published[0], combined)


class CombinedCliTests(unittest.TestCase):
    def _url_args(self, output: Path) -> list[str]:
        return [
            "analyze",
            "--url",
            ROOT_URL,
            "--top-k",
            "4",
            "--output",
            str(output),
        ]

    def _advanced_dynamic_authority(
        self,
        *extra: str,
    ) -> DynamicRequestAuthority:
        args = cli.build_parser().parse_args(
            [
                "analyze",
                "--url",
                ROOT_URL,
                "--top-k",
                "1",
                "--output",
                "unused.json",
                "--dynamic",
                *extra,
            ]
        )
        return cli._dynamic_authority_from_args(args)

    def test_dynamic_default_constructs_strict_authority(self) -> None:
        authority = self._advanced_dynamic_authority()

        self.assertEqual(authority.navigation_urls, (ROOT_URL,))
        self.assertEqual(authority.resource_grants, ())
        self.assertFalse(authority.allow_rendered_navigation)
        self.assertFalse(authority.allow_passive_same_origin_resources)
        self.assertFalse(authority.allow_passive_same_origin_fetch_xhr)
        self.assertFalse(authority.allows_rendered_navigation(f"{ROOT_URL}dashboard"))
        for resource_type, url in (
            ("document", f"{ROOT_URL}dashboard"),
            ("script", f"{ROOT_URL}app.js"),
            ("fetch", f"{ROOT_URL}api/items"),
        ):
            with self.subTest(resource_type=resource_type):
                decision = authority.decide_http(
                    method="GET",
                    url=url,
                    resource_type=resource_type,
                    is_primary_page=True,
                    is_main_frame=resource_type == "document",
                )
                self.assertEqual(
                    decision.decision,
                    DynamicNetworkDecisionKind.BLOCK,
                )

    def test_dynamic_passive_capture_constructs_bounded_authority(self) -> None:
        authority = self._advanced_dynamic_authority(
            "--dynamic-passive-capture",
        )

        self.assertTrue(authority.allow_rendered_navigation)
        self.assertTrue(authority.allow_passive_same_origin_resources)
        self.assertTrue(authority.allow_passive_same_origin_fetch_xhr)
        self.assertTrue(authority.allows_rendered_navigation(f"{ROOT_URL}dashboard"))
        self.assertFalse(
            authority.allows_rendered_navigation(
                "http://127.0.0.1:8080/dashboard"
            )
        )

        cases = (
            (
                "GET",
                f"{ROOT_URL}app.js",
                "script",
                DynamicNetworkDecisionKind.ALLOW,
                DynamicNetworkReason.AUTHORIZED_RESOURCE,
            ),
            (
                "GET",
                f"{ROOT_URL}api/items",
                "fetch",
                DynamicNetworkDecisionKind.ALLOW,
                DynamicNetworkReason.PASSIVE_SAME_ORIGIN_FETCH_XHR,
            ),
            (
                "HEAD",
                f"{ROOT_URL}api/items",
                "xhr",
                DynamicNetworkDecisionKind.ALLOW,
                DynamicNetworkReason.PASSIVE_SAME_ORIGIN_FETCH_XHR,
            ),
            (
                "POST",
                f"{ROOT_URL}api/items",
                "fetch",
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.NON_GET_METHOD,
            ),
            (
                "GET",
                "http://127.0.0.1:8080/api/items",
                "fetch",
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
            ),
        )
        for method, url, resource_type, expected_decision, expected_reason in cases:
            with self.subTest(method=method, url=url, resource_type=resource_type):
                decision = authority.decide_http(
                    method=method,
                    url=url,
                    resource_type=resource_type,
                    is_primary_page=True,
                    is_main_frame=False,
                )
                self.assertEqual(decision.decision, expected_decision)
                self.assertEqual(decision.reason, expected_reason)

    def test_dynamic_navigation_grant_remains_exact_and_strict(self) -> None:
        granted_url = f"{ROOT_URL}dashboard"
        authority = self._advanced_dynamic_authority(
            "--dynamic-allow-navigation",
            granted_url,
        )

        self.assertEqual(authority.navigation_urls, (ROOT_URL, granted_url))
        self.assertEqual(authority.resource_grants, ())
        self.assertTrue(authority.allows_navigation(granted_url))
        self.assertFalse(authority.allows_navigation(f"{ROOT_URL}other"))
        self.assertFalse(authority.allow_rendered_navigation)
        self.assertFalse(authority.allow_passive_same_origin_resources)
        self.assertFalse(authority.allow_passive_same_origin_fetch_xhr)

    def test_dynamic_resource_grants_remain_exact_and_strict(self) -> None:
        grants = {
            DynamicResourceKind.SCRIPT: f"{ROOT_URL}app.js",
            DynamicResourceKind.STYLE: f"{ROOT_URL}app.css",
            DynamicResourceKind.FETCH_XHR: f"{ROOT_URL}api/items",
        }
        resource_args = tuple(
            value
            for kind, url in grants.items()
            for value in ("--dynamic-allow-resource", f"{kind.value}={url}")
        )
        authority = self._advanced_dynamic_authority(*resource_args)

        self.assertEqual(authority.navigation_urls, (ROOT_URL,))
        self.assertEqual(
            {(grant.kind, grant.url) for grant in authority.resource_grants},
            set(grants.items()),
        )
        self.assertFalse(authority.allow_rendered_navigation)
        self.assertFalse(authority.allow_passive_same_origin_resources)
        self.assertFalse(authority.allow_passive_same_origin_fetch_xhr)

    def test_dynamic_opt_in_constructs_exact_authority_and_policy(self) -> None:
        dynamic_crawler = RecordingDynamicCrawler(_dynamic_result())
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"
            args = self._url_args(output)
            args.extend(
                [
                    "--dynamic",
                    "--dynamic-allow-navigation",
                    f"{ROOT_URL}surface?q=one&q=two",
                    "--dynamic-allow-resource",
                    f"script={ROOT_URL}app.js",
                    "--dynamic-max-pages",
                    "2",
                    "--dynamic-max-depth",
                    "1",
                    "--dynamic-max-navigation-attempts",
                    "3",
                    "--dynamic-request-decision-budget",
                    "12",
                ]
            )

            exit_code = cli.main(
                args,
                transport=MarkerTransport(),
                crawler_transport=SinglePageCrawlerTransport(),
                dynamic_crawler=dynamic_crawler,
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(dynamic_crawler.calls), 1)
        _root, policy, authority = dynamic_crawler.calls[0]
        self.assertEqual(policy.max_pages, 2)
        self.assertEqual(policy.max_depth, 1)
        self.assertEqual(policy.max_navigation_attempts, 3)
        self.assertEqual(policy.request_decision_budget, 12)
        self.assertIn(f"{ROOT_URL}surface?q=one&q=two", authority.navigation_urls)
        self.assertEqual(len(authority.resource_grants), 1)
        self.assertFalse(authority.allow_rendered_navigation)
        self.assertFalse(authority.allow_passive_same_origin_resources)
        self.assertFalse(authority.allow_passive_same_origin_fetch_xhr)
        self.assertEqual(
            authority.resource_grants[0].kind,
            DynamicResourceKind.SCRIPT,
        )
        self.assertTrue(
            any("NATIVE_COMBINED" in warning for warning in report["warnings"])
        )
        self.assertNotIn(SENTINEL, json.dumps(report))

    def test_dynamic_authority_and_option_combinations_fail_closed(self) -> None:
        dynamic_crawler = RecordingDynamicCrawler(_dynamic_result())
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            cases = (
                (
                    [
                        "--dynamic",
                        "--dynamic-allow-navigation",
                        "http://127.0.0.2/other",
                    ],
                    "INVALID_AUTHORITY",
                ),
                (["--dynamic-max-pages", "1"], "require --dynamic"),
                (["--dynamic-passive-capture"], "require --dynamic"),
                (
                    ["--dynamic", "--dynamic-allow-resource", "bogus=/x"],
                    "category must be one of",
                ),
            )
            for index, (extra, expected) in enumerate(cases):
                with self.subTest(extra=extra):
                    output = directory / f"report-{index}.json"
                    error_output = io.StringIO()
                    with redirect_stderr(error_output):
                        exit_code = cli.main(
                            [*self._url_args(output), *extra],
                            transport=MarkerTransport(),
                            crawler_transport=SinglePageCrawlerTransport(),
                            dynamic_crawler=dynamic_crawler,
                        )
                    self.assertEqual(exit_code, 2)
                    self.assertIn(expected, error_output.getvalue())
                    self.assertFalse(output.exists())

            records = directory / "records.json"
            records.write_text("[]", encoding="utf-8")
            output = directory / "legacy-report.json"
            with redirect_stderr(io.StringIO()):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "1",
                        "--output",
                        str(output),
                        "--dynamic",
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertFalse(output.exists())

        self.assertEqual(dynamic_crawler.calls, [])

    def test_capability_failure_returns_two_without_report_or_traceback(self) -> None:
        failure = DynamicCapabilityError(
            DynamicCapabilityCode.CHROMIUM_EXECUTABLE_MISSING,
            "The matching Chromium executable is unavailable.",
            setup_hint="Install the matching browser.",
        )
        restored = pickle.loads(pickle.dumps(failure))
        self.assertIsInstance(restored, DynamicCapabilityError)
        self.assertEqual(restored.code, failure.code)
        self.assertEqual(restored.setup_hint, failure.setup_hint)
        self.assertEqual(restored.cleanup_failed, failure.cleanup_failed)
        dynamic_crawler = RecordingDynamicCrawler(failure)
        crawler_transport = SinglePageCrawlerTransport()
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [*self._url_args(output), "--dynamic"],
                    transport=MarkerTransport(),
                    crawler_transport=crawler_transport,
                    dynamic_crawler=dynamic_crawler,
                )

            self.assertEqual(exit_code, 2)
            self.assertFalse(output.exists())
            self.assertIn("CHROMIUM_EXECUTABLE_MISSING", error_output.getvalue())
            self.assertNotIn("Traceback", error_output.getvalue())
        self.assertGreaterEqual(len(crawler_transport.requests), 1)
        self.assertEqual(len(dynamic_crawler.calls), 1)

    def test_integrity_failure_returns_three_without_leaking_diagnostic(self) -> None:
        dynamic_crawler = RecordingDynamicCrawler(
            DynamicIntegrityError(f"invalid canonical value {SENTINEL}")
        )
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [*self._url_args(output), "--dynamic"],
                    transport=MarkerTransport(),
                    crawler_transport=SinglePageCrawlerTransport(),
                    dynamic_crawler=dynamic_crawler,
                )

            self.assertEqual(exit_code, 3)
            self.assertFalse(output.exists())
            self.assertIn("DYNAMIC_INTEGRITY", error_output.getvalue())
            self.assertNotIn(SENTINEL, error_output.getvalue())
            self.assertNotIn("Traceback", error_output.getvalue())

    def test_degraded_combined_result_writes_safe_report_and_returns_four(
        self,
    ) -> None:
        dynamic_crawler = RecordingDynamicCrawler(
            _dynamic_result(completion=DynamicCrawlCompletion.DEGRADED)
        )
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"
            exit_code = cli.main(
                [*self._url_args(output), "--dynamic"],
                transport=MarkerTransport(),
                crawler_transport=SinglePageCrawlerTransport(),
                dynamic_crawler=dynamic_crawler,
            )
            report_text = output.read_text(encoding="utf-8")
            report = json.loads(report_text)

        self.assertEqual(exit_code, 4)
        self.assertTrue(
            any("DYNAMIC_INCOMPLETE" in item for item in report["warnings"])
        )
        self.assertNotIn(SENTINEL, report_text)


if __name__ == "__main__":
    unittest.main()
