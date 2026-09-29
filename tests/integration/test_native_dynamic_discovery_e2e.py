from __future__ import annotations

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
import csv
from dataclasses import dataclass
from html import escape
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from tests.integration.dynamic_loopback_site import (
    DynamicLoopbackSite,
    LoopbackRequest,
)
import vulnspider.cli as cli_module
from vulnspider.discovery import (
    CollectorKind,
    DiscoverySubjectKind,
    DynamicCrawlCompletion,
    ProbeReadyStatus,
)
from vulnspider.pipeline import AnalysisResult


PASSWORD_SENTINEL = "PW_SENTINEL"
_PROCESS_NAME_MARKERS = (
    "chrome",
    "chromium",
    "node",
    "playwright",
    "python",
)
_TEMP_PATTERNS = (
    "vulnspider-dynamic-worker-*",
    "playwright_chromiumdev_profile-*",
)


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


@dataclass(frozen=True, slots=True)
class _CliRunEvidence:
    argv: tuple[str, ...]
    exit_code: int
    analysis: AnalysisResult
    stdout: str
    stderr: str
    json_text: str
    html_text: str
    json_report: dict[str, Any]
    primary_requests: tuple[LoopbackRequest, ...]


def _run_public_cli(
    site: DynamicLoopbackSite,
    destination: Path,
) -> _CliRunEvidence:
    destination.mkdir()
    json_path = destination / "report.json"
    html_path = destination / "report.html"
    origin = site.final_e2e_url.removesuffix("/final-e2e")
    argv = (
        "analyze",
        "--url",
        site.final_e2e_url,
        "--dynamic",
        "--dynamic-allow-navigation",
        site.final_e2e_follow_url,
        "--dynamic-allow-navigation",
        f"{origin}/final/dynamic?dynamic_only=rendered",
        "--dynamic-allow-navigation",
        f"{origin}/final/shared?shared=duplicate",
        "--dynamic-allow-navigation",
        f"{origin}/final/repeated?repeat=one&repeat=two&fixed=keep",
        "--dynamic-allow-navigation",
        f"{origin}/final/probe?probe_target=base&fixed=keep",
        "--dynamic-allow-navigation",
        f"{origin}/final/search?q=safe",
        "--top-k",
        "20",
        "--output",
        str(json_path),
        "--html-output",
        str(html_path),
        "--max-pages",
        "1",
        "--max-depth",
        "0",
        "--max-requests",
        "2",
        "--timeout-seconds",
        "3",
        "--max-redirects",
        "1",
        "--dynamic-max-pages",
        "7",
        "--dynamic-max-depth",
        "1",
        "--dynamic-max-navigation-attempts",
        "7",
        "--dynamic-max-route-actions",
        "8",
        "--dynamic-max-elapsed-seconds",
        "30",
        "--dynamic-navigation-timeout-seconds",
        "3",
        "--dynamic-max-redirects",
        "2",
        "--dynamic-request-decision-budget",
        "100",
    )
    captured: list[AnalysisResult] = []
    stdout = StringIO()
    stderr = StringIO()
    request_offset = len(site.primary_requests)
    real_analyze_url = cli_module.analyze_url

    def capture_analysis(*args: Any, **kwargs: Any) -> AnalysisResult:
        analysis = real_analyze_url(*args, **kwargs)
        captured.append(analysis)
        return analysis

    with (
        patch.object(cli_module, "analyze_url", new=capture_analysis),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        exit_code = cli_module.main(list(argv))

    if len(captured) != 1:
        raise RuntimeError("public CLI did not return one captured analysis")
    if not json_path.is_file() or not html_path.is_file():
        raise RuntimeError("public CLI did not write both requested reports")
    json_text = json_path.read_text(encoding="utf-8")
    return _CliRunEvidence(
        argv=argv,
        exit_code=exit_code,
        analysis=captured[0],
        stdout=stdout.getvalue(),
        stderr=stderr.getvalue(),
        json_text=json_text,
        html_text=html_path.read_text(encoding="utf-8"),
        json_report=json.loads(json_text),
        primary_requests=site.primary_requests[request_offset:],
    )


def _browser_related_processes() -> frozenset[tuple[int, str]]:
    if os.name == "nt":
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            raise RuntimeError("PowerShell is required for process cleanup evidence")
        completed = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-Command",
                (
                    "Get-Process | Select-Object Id,ProcessName | "
                    "ConvertTo-Csv -NoTypeInformation"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        rows = csv.reader(completed.stdout.splitlines())
        processes = (
            (int(row[0]), row[1].casefold())
            for row in rows
            if len(row) >= 2 and row[0].isdigit()
        )
    else:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,comm="],
            check=True,
            capture_output=True,
            text=True,
        )
        parsed: list[tuple[int, str]] = []
        for line in completed.stdout.splitlines():
            pid, separator, name = line.strip().partition(" ")
            if separator and pid.isdigit():
                parsed.append((int(pid), name.strip().casefold()))
        processes = iter(parsed)
    return frozenset(
        (pid, name)
        for pid, name in processes
        if any(marker in name for marker in _PROCESS_NAME_MARKERS)
    )


def _new_processes_after_cleanup(
    before: frozenset[tuple[int, str]],
) -> frozenset[tuple[int, str]]:
    deadline = time.monotonic() + 5.0
    while True:
        residual = _browser_related_processes() - before
        if not residual or time.monotonic() >= deadline:
            return residual
        time.sleep(0.05)


def _dynamic_temp_artifacts() -> frozenset[str]:
    temp_root = Path(tempfile.gettempdir())
    return frozenset(
        str(path.resolve())
        for pattern in _TEMP_PATTERNS
        for path in temp_root.glob(pattern)
    )


def _request_target(url: str) -> str:
    parts = urlsplit(url)
    if parts.query:
        return f"{parts.path}?{parts.query}"
    return parts.path


def _stable_discovery_json(analysis: AnalysisResult) -> str:
    if analysis.discovery_result is None:
        raise AssertionError("combined analysis has no discovery result")
    serialized = analysis.discovery_result.to_dict()
    serialized["crawl_statistics"]["elapsed_ms"] = 0.0
    return json.dumps(serialized, sort_keys=True, separators=(",", ":"))


def _stable_report_fields(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "report_version": report["report_version"],
        "policy_version": report["policy_version"],
        "selection": report["selection"],
        "warnings": report["warnings"],
        "candidate_identity": tuple(
            (
                item["order"],
                item["candidate_id"],
                item["family"],
                item["selection_rank"],
            )
            for item in report["verification_order"]
        ),
    }


class NativeDynamicDiscoveryE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._original_cwd = Path.cwd()
        cls._workdir = tempfile.TemporaryDirectory(
            prefix="vulnspider-final-e2e-"
        )
        cls._work_path = Path(cls._workdir.name)
        os.chdir(cls._work_path)
        try:
            processes_before = _browser_related_processes()
            temp_before = _dynamic_temp_artifacts()
            site = DynamicLoopbackSite()
            with site:
                cls.start_url = site.final_e2e_url
                cls.follow_url = site.final_e2e_follow_url
                cls.sentinel_origin = site.sentinel_origin
                cls.first = _run_public_cli(site, cls._work_path / "first")
                cls.second = _run_public_cli(site, cls._work_path / "second")
                cls.sentinel_requests = site.sentinel_requests
            cls.site_cleanup_complete = site.cleanup_complete
            cls.server_threads_alive = site.server_threads_alive
            cls.residual_processes = _new_processes_after_cleanup(
                processes_before
            )
            cls.residual_temp_artifacts = (
                _dynamic_temp_artifacts() - temp_before
            )
            cls.debug_logs = tuple(cls._work_path.rglob("debug.log"))
            cls.generated_files = tuple(
                sorted(
                    path.relative_to(cls._work_path).as_posix()
                    for path in cls._work_path.rglob("*")
                    if path.is_file()
                )
            )
        except Exception:
            os.chdir(cls._original_cwd)
            cls._workdir.cleanup()
            raise
        os.chdir(cls._original_cwd)

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._original_cwd)
        cls._workdir.cleanup()

    def test_final_cli_combined_probe(self) -> None:
        evidence = self.first
        analysis = evidence.analysis
        discovery = analysis.discovery_result
        combined = analysis.combined_result
        self.assertEqual(evidence.exit_code, 0)
        self.assertIn("vulnspider: [OK] scan complete", evidence.stdout)
        self.assertIn("mode=dynamic", evidence.stdout)
        self.assertIn("vulnspider: analysis output:", evidence.stdout)
        self.assertIn("vulnspider: dashboard report ->", evidence.stdout)
        self.assertIn("vulnspider: [*]", evidence.stderr)
        self.assertIn("vulnspider: [OK]", evidence.stderr)
        cli_output = evidence.stdout + evidence.stderr
        self.assertNotIn("[ERROR]", cli_output)
        self.assertNotIn("Traceback", cli_output)
        for secret_marker in (
            PASSWORD_SENTINEL,
            "credential",
            "cookie",
            "authorization",
            "session",
        ):
            self.assertNotIn(secret_marker.casefold(), cli_output.casefold())
        self.assertIsNotNone(discovery)
        self.assertIsNotNone(combined)
        assert discovery is not None
        assert combined is not None
        discovery.validate()
        self.assertEqual(combined.completion, DynamicCrawlCompletion.COMPLETE)
        self.assertFalse(combined.degraded)

        points_by_name: dict[str, list[Any]] = {}
        for point in discovery.input_points:
            points_by_name.setdefault(point.name, []).append(point)
        for required_name in (
            "static_only",
            "dynamic_only",
            "shared",
            "dynamic_follow",
        ):
            self.assertIn(required_name, points_by_name)
        self.assertEqual(len(points_by_name["shared"]), 1)
        repeat_points = points_by_name["repeat"]
        self.assertEqual(
            {point.occurrence_index for point in repeat_points},
            {0, 1},
        )

        self.assertEqual(
            self._producer_kinds(points_by_name["static_only"][0].id or ""),
            {CollectorKind.NATIVE_STATIC},
        )
        self.assertEqual(
            self._producer_kinds(points_by_name["dynamic_only"][0].id or ""),
            {CollectorKind.NATIVE_DYNAMIC},
        )
        self.assertEqual(
            self._producer_kinds(points_by_name["shared"][0].id or ""),
            {CollectorKind.NATIVE_STATIC, CollectorKind.NATIVE_DYNAMIC},
        )
        follow_point = points_by_name["dynamic_follow"][0]
        follow_sources = {
            item.source_url
            for item in discovery.crawl_provenance
            if item.subject_kind == DiscoverySubjectKind.INPUT_POINT
            and item.subject_id == follow_point.id
        }
        self.assertEqual(follow_sources, {self.follow_url})
        self.assertEqual(
            combined.dynamic_crawl.visited_urls[:2],
            (self.start_url, self.follow_url),
        )
        self._assert_aggregate_statistics(analysis)
        self._assert_probe_execution(analysis, evidence.primary_requests)

    def test_final_sensitive_secret_free(self) -> None:
        for evidence in (self.first, self.second):
            combined = evidence.analysis.combined_result
            self.assertIsNotNone(combined)
            assert combined is not None
            surfaces = (
                json.dumps(combined.to_dict(), sort_keys=True),
                repr(evidence.analysis),
                evidence.json_text,
                evidence.html_text,
                evidence.stdout,
                evidence.stderr,
                "\n".join(
                    item.raw_target for item in evidence.primary_requests
                ),
            )
            self.assertTrue(all(PASSWORD_SENTINEL not in item for item in surfaces))
            self.assertFalse(
                any(item.method == "POST" for item in evidence.primary_requests)
            )

    def test_final_cross_authority_zero(self) -> None:
        self.assertEqual(self.sentinel_requests, ())
        for evidence in (self.first, self.second):
            self.assertFalse(
                any(
                    self.sentinel_origin in item.raw_target
                    for item in evidence.primary_requests
                )
            )
            discovery = evidence.analysis.discovery_result
            self.assertIsNotNone(discovery)
            assert discovery is not None
            self.assertIn(
                "OFF_SCOPE_LINK",
                {warning.code for warning in discovery.warnings},
            )

    def test_final_output_consistency(self) -> None:
        for evidence in (self.first, self.second):
            report = evidence.json_report
            candidate_ids = [
                item["candidate_id"] for item in report["verification_order"]
            ]
            scored_ids = {
                result.candidate.id
                for result in evidence.analysis.scoring_results
            }
            # The decision layer selects from the authoritative scoring results
            # and invents no candidate of its own.
            self.assertTrue(set(candidate_ids) <= scored_ids)
            self.assertEqual(
                report["selection"]["selected"],
                len(candidate_ids),
            )
            # The HTML surfaces one finding per input point (its top type),
            # while the JSON keeps every scored candidate.
            surfaced = _report_surfaced_candidate_ids(report["verification_order"])
            self.assertEqual(
                evidence.html_text.count('<article class="finding '),
                len(surfaced),
            )
            for candidate_id in surfaced:
                self.assertIn(candidate_id, evidence.html_text)
            for warning in report["warnings"]:
                self.assertIn(escape(warning), evidence.html_text)
            candidate_surface = json.dumps(
                report["verification_order"], sort_keys=True
            )
            self.assertNotIn("SENSITIVE_FORM_ELIDED", candidate_surface)
            self.assertNotIn(PASSWORD_SENTINEL, candidate_surface)

    def test_final_deterministic(self) -> None:
        first = self.first.analysis
        second = self.second.analysis
        self.assertEqual(
            first.combined_result.dynamic_crawl.visited_urls,
            second.combined_result.dynamic_crawl.visited_urls,
        )
        self.assertEqual(
            _stable_discovery_json(first),
            _stable_discovery_json(second),
        )
        self.assertEqual(
            tuple(
                (item.id, item.status, item.reasons)
                for item in first.discovery_result.probe_readiness
            ),
            tuple(
                (item.id, item.status, item.reasons)
                for item in second.discovery_result.probe_readiness
            ),
        )
        self.assertEqual(
            tuple(
                observation.probe_plan.id
                for observation in first.probe_observations
            ),
            tuple(
                observation.probe_plan.id
                for observation in second.probe_observations
            ),
        )
        self.assertEqual(len(first.scoring_results), len(second.scoring_results))
        self.assertEqual(
            tuple(item.candidate.id for item in first.scoring_results),
            tuple(item.candidate.id for item in second.scoring_results),
        )
        self.assertEqual(
            tuple(
                item.scoring_result.candidate.id
                for item in first.selection.selected
            ),
            tuple(
                item.scoring_result.candidate.id
                for item in second.selection.selected
            ),
        )
        self.assertEqual(first.warnings, second.warnings)
        self.assertEqual(
            _stable_report_fields(self.first.json_report),
            _stable_report_fields(self.second.json_report),
        )

    def test_final_cleanup(self) -> None:
        for evidence in (self.first, self.second):
            combined = evidence.analysis.combined_result
            self.assertIsNotNone(combined)
            assert combined is not None
            audit = combined.dynamic_crawl.browser_audit
            self.assertTrue(audit.cleanup_complete)
            self.assertEqual(audit.playwright_started, audit.playwright_stopped)
            self.assertEqual(audit.browsers_launched, audit.browsers_closed)
            self.assertEqual(audit.contexts_created, audit.contexts_closed)
            self.assertEqual(audit.pages_created, audit.pages_closed)
            self.assertGreaterEqual(audit.playwright_started, 1)
        self.assertTrue(self.site_cleanup_complete)
        self.assertEqual(self.server_threads_alive, (False, False))
        self.assertEqual(self.residual_processes, frozenset())
        self.assertEqual(self.residual_temp_artifacts, frozenset())
        self.assertEqual(self.debug_logs, ())
        self.assertEqual(
            self.generated_files,
            (
                "first/report.html",
                "first/report.json",
                "second/report.html",
                "second/report.json",
            ),
        )

    def test_final_n34_safe_anchor_collision(self) -> None:
        discovery = self.first.analysis.discovery_result
        self.assertIsNotNone(discovery)
        assert discovery is not None
        endpoints = {item.id or "": item for item in discovery.endpoints}
        q_points = [
            point
            for point in discovery.input_points
            if point.name == "q"
            and endpoints[point.endpoint_id].path == "/final/search"
        ]
        self.assertEqual(len(q_points), 1)
        q_point = q_points[0]
        self.assertEqual(q_point.baseline_values, ("safe",))
        self.assertEqual(q_point.type_hint, "query")
        self.assertEqual(q_point.metadata["raw_query_token"], "q=safe")
        self.assertEqual(q_point.metadata["origin_kinds"], ("query",))
        self.assertEqual(
            self._producer_kinds(q_point.id or ""),
            {CollectorKind.NATIVE_STATIC, CollectorKind.NATIVE_DYNAMIC},
        )
        q_contexts = [
            item
            for item in discovery.input_point_request_contexts
            if item.input_point_id == q_point.id
        ]
        self.assertEqual(len(q_contexts), 1)
        q_readiness = [
            item
            for item in discovery.probe_readiness
            if item.input_point_id == q_point.id
        ]
        self.assertEqual(len(q_readiness), 1)
        self.assertEqual(q_readiness[0].status, ProbeReadyStatus.READY)
        form_templates = [
            item
            for item in discovery.request_templates
            if urlsplit(item.url).path == "/final/search"
            and item.metadata.get("context_kind") == "form"
        ]
        self.assertEqual(form_templates, [])

        warnings = [
            item
            for item in discovery.warnings
            if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(warnings), 2)
        self.assertEqual(
            [item.details["producer_kind"] for item in warnings],
            [
                CollectorKind.NATIVE_STATIC.value,
                CollectorKind.NATIVE_DYNAMIC.value,
            ],
        )
        self.assertTrue(
            all(
                item.subject_id is None and item.provenance_id is None
                for item in warnings
            )
        )
        self.assertFalse(
            any(
                PASSWORD_SENTINEL in item.raw_target
                for item in self.first.primary_requests
            )
        )

    def _producer_kinds(self, input_point_id: str) -> set[CollectorKind]:
        discovery = self.first.analysis.discovery_result
        assert discovery is not None
        return {
            item.collector_kind
            for item in discovery.crawl_provenance
            if item.subject_kind == DiscoverySubjectKind.INPUT_POINT
            and item.subject_id == input_point_id
        }

    def _assert_probe_execution(
        self,
        analysis: AnalysisResult,
        primary_requests: tuple[LoopbackRequest, ...],
    ) -> None:
        discovery = analysis.discovery_result
        self.assertIsNotNone(discovery)
        assert discovery is not None
        points = {item.id or "": item for item in discovery.input_points}
        readiness = {
            item.input_point_id: item for item in discovery.probe_readiness
        }
        ready_ids = {
            item.input_point_id
            for item in discovery.probe_readiness
            if item.status == ProbeReadyStatus.READY
        }
        observed_ids = {
            item.input_point_id for item in analysis.probe_observations
        }
        self.assertEqual(observed_ids, ready_ids)
        not_ready_ids = {
            item.input_point_id
            for item in discovery.probe_readiness
            if item.status == ProbeReadyStatus.NOT_READY
        }
        self.assertTrue(not_ready_ids)
        self.assertTrue(
            any(
                points[item_id].name == "dynamic_follow"
                for item_id in not_ready_ids
            )
        )
        self.assertTrue(not_ready_ids.isdisjoint(observed_ids))

        expected_targets: Counter[str] = Counter()
        plan_ids: list[str] = []
        for observation in analysis.probe_observations:
            plan = observation.probe_plan
            plan_id = plan.id or ""
            plan_ids.append(plan_id)
            self.assertEqual(readiness[observation.input_point_id].status, ProbeReadyStatus.READY)
            self.assertEqual(
                plan.request_context_id,
                readiness[observation.input_point_id].request_context_id,
            )
            self.assertEqual(plan.input_point_id, observation.input_point_id)
            self.assertEqual(len(plan.changed_fields), 1)
            self._assert_one_input_change(plan.baseline_request, plan.probe_request)
            self.assertEqual(
                observation.baseline_response.probe_plan_id,
                plan_id,
            )
            self.assertEqual(observation.baseline_response.request_role, "baseline")
            self.assertEqual(
                observation.baseline_response.request_id,
                plan.baseline_request.id,
            )
            self.assertEqual(observation.probe_response.probe_plan_id, plan_id)
            self.assertEqual(observation.probe_response.request_role, "probe")
            self.assertEqual(
                observation.probe_response.request_id,
                plan.probe_request.id,
            )
            self.assertEqual(observation.baseline_response.status_code, 200)
            self.assertEqual(observation.probe_response.status_code, 200)
            self.assertNotEqual(
                observation.baseline_response.body_bytes_hash,
                observation.probe_response.body_bytes_hash,
            )
            expected_targets[_request_target(plan.baseline_request.url)] += 1
            expected_targets[_request_target(plan.probe_request.url)] += 1
        self.assertEqual(len(plan_ids), len(set(plan_ids)))

        actual_targets = Counter(item.raw_target for item in primary_requests)
        for target, count in expected_targets.items():
            self.assertGreaterEqual(actual_targets[target], count)

    def _assert_one_input_change(self, baseline: Any, probe: Any) -> None:
        self.assertEqual(baseline.method, probe.method)
        self.assertEqual(baseline.headers, probe.headers)
        self.assertEqual(baseline.cookies, probe.cookies)
        self.assertEqual(len(baseline.query), len(probe.query))
        self.assertEqual(len(baseline.form), len(probe.form))
        self.assertEqual(
            [name for name, _value in baseline.query],
            [name for name, _value in probe.query],
        )
        self.assertEqual(
            [name for name, _value in baseline.form],
            [name for name, _value in probe.form],
        )
        changed_values = sum(
            baseline_value != probe_value
            for (_name, baseline_value), (_other_name, probe_value) in (
                *zip(baseline.query, probe.query, strict=True),
                *zip(baseline.form, probe.form, strict=True),
            )
        )
        self.assertEqual(changed_values, 1)
        baseline_url = urlsplit(baseline.url)
        probe_url = urlsplit(probe.url)
        self.assertEqual(
            (baseline_url.scheme, baseline_url.netloc, baseline_url.path),
            (probe_url.scheme, probe_url.netloc, probe_url.path),
        )

    def _assert_aggregate_statistics(self, analysis: AnalysisResult) -> None:
        combined = analysis.combined_result
        self.assertIsNotNone(combined)
        assert combined is not None
        static = combined.static_crawl.discovery.crawl_statistics
        dynamic = combined.dynamic_crawl.discovery.crawl_statistics
        aggregate = combined.discovery.crawl_statistics
        for field_name in (
            "requests_attempted",
            "pages_processed",
            "html_pages",
            "links_discovered",
            "forms_discovered",
            "skipped",
            "redirects_followed",
            "request_budget",
            "page_budget",
            "elapsed_ms",
        ):
            self.assertEqual(
                getattr(aggregate, field_name),
                getattr(static, field_name) + getattr(dynamic, field_name),
            )
        for field_name in ("max_depth_reached", "depth_budget"):
            self.assertEqual(
                getattr(aggregate, field_name),
                max(getattr(static, field_name), getattr(dynamic, field_name)),
            )
        self.assertEqual(aggregate.endpoint_count, len(combined.discovery.endpoints))
        self.assertEqual(
            aggregate.input_point_count,
            len(combined.discovery.input_points),
        )
        self.assertEqual(
            aggregate.request_template_count,
            len(combined.discovery.request_templates),
        )
        self.assertEqual(
            aggregate.request_context_count,
            len(combined.discovery.input_point_request_contexts),
        )


if __name__ == "__main__":
    unittest.main()
