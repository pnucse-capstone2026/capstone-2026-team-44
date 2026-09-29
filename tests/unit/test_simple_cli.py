from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field, replace
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import vulnspider.cli as cli_module
from vulnspider.discovery import (
    CanonicalDiscoveryResult,
    CombinedDiscoveryResult,
    DiscoveryWarning,
    DiscoveryMergePolicy,
    DynamicCrawlTerminationReason,
    DynamicCrawlPolicy,
    DynamicCrawlCompletion,
    DynamicResourceKind,
    StaticCrawlerRequest,
    StaticCrawlerResponse,
    merge_discovery_results,
)
from vulnspider.domain import RequestInstance
from vulnspider.observation import TransportResponse
from vulnspider.pipeline import AnalysisResult, analyze_url as pipeline_analyze_url


ROOT_URL = "http://127.0.0.1:8080/"
STATIC_SECRET_SENTINEL = "STATIC_SECRET_SENTINEL_73d1"


@dataclass
class _CrawlerTransport:
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
            body=(
                b'<form method="get" action="/search">'
                b'<input name="q" value="safe"></form>'
                b'<form method="get" action="/login">'
                b'<input type="password" name="password" value="'
                + STATIC_SECRET_SENTINEL.encode("ascii")
                + b'"></form>'
            ),
            content_type="text/html",
            encoding="utf-8",
        )


@dataclass
class _ProbeTransport:
    requests: list[RequestInstance] = field(default_factory=list)

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        self.requests.append(request)
        return TransportResponse(
            status_code=200,
            body=b"bounded response",
            elapsed_ms=1.0,
            encoding="utf-8",
        )


def _native_analysis(*, top_k: int = 10) -> AnalysisResult:
    return pipeline_analyze_url(
        ROOT_URL,
        top_k=top_k,
        crawler_transport=_CrawlerTransport(),
        transport=_ProbeTransport(),
        elide_sensitive_forms=True,
    )


def _pipeline_stub(analysis: AnalysisResult):
    def run(*_args: object, **kwargs: object) -> AnalysisResult:
        callback = kwargs["on_crawl_validated"]
        assert callable(callback)
        crawl = analysis.combined_result or analysis.crawl_result
        assert crawl is not None
        callback(crawl)
        return analysis

    return run


class SimpleCliTests(unittest.TestCase):
    def setUp(self) -> None:
        # Simple mode now writes vulnspider-report.html to the CWD by default;
        # run every test from a throwaway CWD so the default report never lands
        # in the repo root when a test only pins --crawl-output/-o.
        self._original_cwd = os.getcwd()
        self._cwd = TemporaryDirectory(prefix="vulnspider-simple-cli-cwd-")
        os.chdir(self._cwd.name)

    def tearDown(self) -> None:
        os.chdir(self._original_cwd)
        self._cwd.cleanup()

    def test_simple_url_calls_dynamic_pipeline_and_writes_both_defaults(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        analysis = _native_analysis()
        with TemporaryDirectory() as temporary_directory:
            original_cwd = Path.cwd()
            os.chdir(temporary_directory)
            try:
                with (
                    patch.object(
                        cli_module,
                        "analyze_url",
                        side_effect=_pipeline_stub(analysis),
                    ) as analyze,
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    exit_code = cli_module.main(["-u", ROOT_URL])
                crawl_path = Path("vulnspider-crawl.json")
                analysis_path = Path("vulnspider-analysis.json")
                crawl_report = json.loads(crawl_path.read_text(encoding="utf-8"))
                analysis_report = json.loads(
                    analysis_path.read_text(encoding="utf-8")
                )
            finally:
                os.chdir(original_cwd)

        self.assertEqual(exit_code, 0)
        self.assertEqual(crawl_report["report_kind"], "crawl")
        self.assertEqual(analysis_report["report_version"], "decision-report-v1")
        self.assertEqual(analysis_report["selection"]["top_k"], 10)
        analyze.assert_called_once()
        args, kwargs = analyze.call_args
        self.assertEqual(args, (ROOT_URL,))
        self.assertEqual(kwargs["top_k"], 10)
        self.assertIsInstance(kwargs["dynamic_policy"], DynamicCrawlPolicy)
        self.assertEqual(kwargs["dynamic_policy"].max_depth, 2)
        authority = kwargs["dynamic_authority"]
        self.assertTrue(authority.allow_rendered_navigation)
        self.assertTrue(authority.allow_passive_same_origin_resources)
        self.assertTrue(authority.allow_passive_same_origin_fetch_xhr)
        self.assertNotIn("진행 상태:", stdout.getvalue())
        self.assertIn("진행 상태:", stderr.getvalue())
        self.assertEqual(
            len([line for line in stdout.getvalue().splitlines() if line]),
            4,
        )
        self.assertIn("mode=dynamic", stdout.getvalue())
        self.assertIn("vulnspider-crawl.json", stdout.getvalue())
        self.assertIn("vulnspider-analysis.json", stdout.getvalue())

    def test_custom_outputs_and_exact_advanced_grants(self) -> None:
        analysis = _native_analysis()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "crawl.json"
            analysis_output = directory / "analysis.json"
            script = ROOT_URL + "app.js"
            navigation = ROOT_URL + "advanced"
            with patch.object(
                cli_module,
                "analyze_url",
                side_effect=_pipeline_stub(analysis),
            ) as analyze:
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--crawl-output",
                        str(crawl_output),
                        "-o",
                        str(analysis_output),
                        "--dynamic-allow-navigation",
                        navigation,
                        "--dynamic-allow-resource",
                        f"script={script}",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertTrue(crawl_output.is_file())
            self.assertTrue(analysis_output.is_file())
            authority = analyze.call_args.kwargs["dynamic_authority"]
            self.assertIn(navigation, authority.navigation_urls)
            self.assertIn(
                (DynamicResourceKind.SCRIPT, script),
                {(grant.kind, grant.url) for grant in authority.resource_grants},
            )

    def test_static_only_reuses_native_static_pipeline_and_writes_both(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "static-crawl.json"
            analysis_output = directory / "static-analysis.json"
            exit_code = cli_module.main(
                [
                    "-u",
                    ROOT_URL,
                    "--static-only",
                    "--crawl-output",
                    str(crawl_output),
                    "-o",
                    str(analysis_output),
                ],
                crawler_transport=_CrawlerTransport(),
                transport=_ProbeTransport(),
            )
            crawl_report = json.loads(crawl_output.read_text(encoding="utf-8"))
            analysis_report = json.loads(
                analysis_output.read_text(encoding="utf-8")
            )
            crawl_text = crawl_output.read_text(encoding="utf-8")
            analysis_text = analysis_output.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertEqual(crawl_report["crawl_mode"], "static_only")
        self.assertEqual(crawl_report["completion"], "COMPLETE")
        self.assertGreater(analysis_report["selection"]["candidates_scored"], 0)
        self.assertTrue(analysis_report["verification_order"])
        self.assertNotIn(STATIC_SECRET_SENTINEL, crawl_text)
        self.assertNotIn(STATIC_SECRET_SENTINEL, analysis_text)

    def test_static_only_rejects_dynamic_grants_without_outputs(self) -> None:
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "must-not-exist-crawl.json"
            analysis_output = directory / "must-not-exist-analysis.json"
            with redirect_stderr(stderr):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--static-only",
                        "--dynamic-allow-navigation",
                        ROOT_URL + "next",
                        "--crawl-output",
                        str(crawl_output),
                        "-o",
                        str(analysis_output),
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertFalse(crawl_output.exists())
        self.assertFalse(analysis_output.exists())
        self.assertIn("cannot be combined", stderr.getvalue())

    def test_same_output_path_is_rejected_before_pipeline(self) -> None:
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "same.json"
            with (
                patch.object(cli_module, "analyze_url") as analyze,
                redirect_stderr(stderr),
            ):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--crawl-output",
                        str(destination),
                        "-o",
                        str(destination),
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertFalse(destination.exists())
        analyze.assert_not_called()
        self.assertIn("different files", stderr.getvalue())

    def test_probe_failure_keeps_crawl_and_does_not_publish_analysis(self) -> None:
        analysis = _native_analysis()

        def fail_after_crawl(*_args: object, **kwargs: object) -> AnalysisResult:
            callback = kwargs["on_crawl_validated"]
            assert callable(callback)
            assert analysis.crawl_result is not None
            callback(analysis.crawl_result)
            raise ValueError("probe analysis failed")

        stdout = StringIO()
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "crawl.json"
            analysis_output = directory / "analysis.json"
            with (
                patch.object(cli_module, "analyze_url", side_effect=fail_after_crawl),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--crawl-output",
                        str(crawl_output),
                        "-o",
                        str(analysis_output),
                    ]
                )
            crawl_exists = crawl_output.is_file()
            analysis_exists = analysis_output.exists()

        self.assertEqual(exit_code, 2)
        self.assertTrue(crawl_exists)
        self.assertFalse(analysis_exists)
        self.assertIn("crawl=created", stdout.getvalue())
        self.assertIn("analysis=not-written", stdout.getvalue())
        self.assertNotIn(ROOT_URL, stdout.getvalue())
        self.assertIn("probe analysis failed", stderr.getvalue())

    def test_discovery_failure_publishes_neither_file(self) -> None:
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "crawl.json"
            analysis_output = directory / "analysis.json"
            with (
                patch.object(
                    cli_module,
                    "analyze_url",
                    side_effect=cli_module.DynamicIntegrityError("invalid"),
                ),
                redirect_stderr(stderr),
            ):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--crawl-output",
                        str(crawl_output),
                        "-o",
                        str(analysis_output),
                    ]
                )

        self.assertEqual(exit_code, 3)
        self.assertFalse(crawl_output.exists())
        self.assertFalse(analysis_output.exists())
        self.assertIn("DYNAMIC_INTEGRITY", stderr.getvalue())

    def test_degraded_dynamic_publishes_marked_crawl_only_and_exits_four(
        self,
    ) -> None:
        from tests.unit.test_combined_pipeline_cli import (
            _dynamic_result,
            _static_result,
        )

        static = _static_result()
        dynamic = _dynamic_result(completion=DynamicCrawlCompletion.DEGRADED)
        combined = CombinedDiscoveryResult(
            root_url=static.root_url,
            static_crawl=static,
            dynamic_crawl=dynamic,
            discovery=merge_discovery_results(
                static.discovery,
                dynamic.discovery,
                DiscoveryMergePolicy(),
            ),
        )
        base_analysis = pipeline_analyze_url(
            ROOT_URL,
            top_k=10,
            crawler_transport=_CrawlerTransport(),
            transport=_ProbeTransport(),
        )
        analysis = replace(
            base_analysis,
            discovery_result=combined.discovery,
            crawl_result=combined.static_crawl,
            combined_result=combined,
        )
        stdout = StringIO()
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "crawl.json"
            analysis_output = directory / "analysis.json"
            with (
                patch.object(
                    cli_module,
                    "analyze_url",
                    side_effect=_pipeline_stub(analysis),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--crawl-output",
                        str(crawl_output),
                        "-o",
                        str(analysis_output),
                    ]
                )
            crawl_report = json.loads(crawl_output.read_text(encoding="utf-8"))
            analysis_exists = analysis_output.exists()

        self.assertEqual(exit_code, 4)
        self.assertEqual(crawl_report["completion"], "DEGRADED")
        self.assertTrue(crawl_report["degraded"])
        self.assertFalse(analysis_exists)
        self.assertIn("crawl=created", stdout.getvalue())
        self.assertIn("DYNAMIC_INCOMPLETE", stderr.getvalue())

    def test_degraded_dynamic_reports_safe_redirect_failure_cause(self) -> None:
        from tests.unit.test_combined_pipeline_cli import (
            _dynamic_result,
            _static_result,
        )

        static = _static_result()
        dynamic = _dynamic_result(completion=DynamicCrawlCompletion.DEGRADED)
        warning = DiscoveryWarning(
            code="DYNAMIC_OPERATIONAL_FAILURE",
            message="A bounded Dynamic browser operation failed safely.",
            details={
                "error_code": "NAVIGATION_FAILED",
                "private_provider_diagnostic": "must-not-reach-cli",
            },
        )
        source = dynamic.discovery
        dynamic_discovery = CanonicalDiscoveryResult.create(
            discovery_metadata=source.discovery_metadata,
            scope_metadata=source.scope_metadata,
            crawl_statistics=source.crawl_statistics,
            endpoints=source.endpoints,
            input_points=source.input_points,
            request_templates=source.request_templates,
            input_point_request_contexts=source.input_point_request_contexts,
            probe_readiness=source.probe_readiness,
            crawl_provenance=source.crawl_provenance,
            bac_static_hints=source.bac_static_hints,
            warnings=(warning,),
            safety_invariants=source.safety_invariants,
        )
        dynamic = replace(
            dynamic,
            termination_reason=DynamicCrawlTerminationReason.OPERATIONAL_FAILURE,
            discovery=dynamic_discovery,
            browser_audit=replace(
                dynamic.browser_audit,
                redirect_attempt_count=1,
                redirect_block_count=1,
            ),
        )
        combined = CombinedDiscoveryResult(
            root_url=static.root_url,
            static_crawl=static,
            dynamic_crawl=dynamic,
            discovery=merge_discovery_results(
                static.discovery,
                dynamic.discovery,
                DiscoveryMergePolicy(),
            ),
        )
        base_analysis = pipeline_analyze_url(
            ROOT_URL,
            top_k=10,
            crawler_transport=_CrawlerTransport(),
            transport=_ProbeTransport(),
        )
        analysis = replace(
            base_analysis,
            discovery_result=combined.discovery,
            crawl_result=combined.static_crawl,
            combined_result=combined,
        )
        stdout = StringIO()
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "crawl.json"
            analysis_output = directory / "analysis.json"
            with (
                patch.object(
                    cli_module,
                    "analyze_url",
                    side_effect=_pipeline_stub(analysis),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--crawl-output",
                        str(crawl_output),
                        "-o",
                        str(analysis_output),
                    ]
                )
            analysis_exists = analysis_output.exists()

        diagnostic = stderr.getvalue()
        self.assertEqual(exit_code, 4)
        self.assertFalse(analysis_exists)
        self.assertIn("crawl=created", stdout.getvalue())
        self.assertIn("termination=OPERATIONAL_FAILURE", diagnostic)
        self.assertIn("warnings=DYNAMIC_OPERATIONAL_FAILURE", diagnostic)
        self.assertIn("browser_errors=NAVIGATION_FAILED", diagnostic)
        self.assertIn("redirect_blocks=1", diagnostic)
        self.assertIn("--dynamic-allow-navigation", diagnostic)
        self.assertIn("do not grant authentication, logout", diagnostic)
        self.assertIn("Authenticated browser-session import is not supported", diagnostic)
        self.assertNotIn("must-not-reach-cli", diagnostic)

    def test_analysis_publication_failure_leaves_atomic_crawl_only(self) -> None:
        analysis = _native_analysis()
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            crawl_output = directory / "crawl.json"
            analysis_output = directory / "analysis.json"
            with (
                patch.object(
                    cli_module,
                    "analyze_url",
                    side_effect=_pipeline_stub(analysis),
                ),
                patch.object(
                    cli_module,
                    "analyze_and_report",
                    side_effect=OSError("analysis replace failed"),
                ),
                redirect_stderr(stderr),
            ):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--crawl-output",
                        str(crawl_output),
                        "-o",
                        str(analysis_output),
                    ]
                )

            crawl_exists = crawl_output.is_file()
            analysis_exists = analysis_output.exists()
            temporary_files = tuple(directory.glob(".*.tmp"))

        self.assertEqual(exit_code, 2)
        self.assertTrue(crawl_exists)
        self.assertFalse(analysis_exists)
        self.assertEqual(temporary_files, ())
        self.assertIn("analysis replace failed", stderr.getvalue())

    def test_help_displays_simple_two_output_usage(self) -> None:
        help_text = cli_module.build_parser().format_help()

        self.assertIn("vulnspider -u http://127.0.0.1:8080/", help_text)
        self.assertIn("-u SIMPLE_URL", help_text)
        self.assertIn("--static-only", help_text)
        self.assertIn("--crawl-output", help_text)
        self.assertIn("vulnspider-crawl.json", help_text)
        self.assertIn("vulnspider-analysis.json", help_text)
        self.assertNotIn("vulnspider-result.json", help_text)


if __name__ == "__main__":
    unittest.main()
