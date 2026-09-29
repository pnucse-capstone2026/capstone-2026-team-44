from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, TextIO
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for import_root in (ROOT, SRC):
    import_text = str(import_root)
    if import_text not in sys.path:
        sys.path.insert(0, import_text)

from vulnspider.discovery import (  # noqa: E402
    DynamicBrowserCapability,
    DynamicCapabilityError,
    preflight_dynamic_browser,
)


SUITE_BROWSER_LOOPBACK = "browser-loopback"
SUITE_RENDERED_DOM = "rendered-dom"
SUITE_BOUNDED_NAVIGATION = "bounded-navigation"
SUITE_COMBINED_DISCOVERY = "combined-discovery"
SUITE_FINAL = "final"


@dataclass(frozen=True, slots=True)
class BrowserManifestCase:
    case_id: str
    test_id: str
    invariant: str
    required: bool = True


BROWSER_LOOPBACK_CASES = (
    BrowserManifestCase(
        "base-js-http-ws",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_chromium_executes_javascript_and_blocks_external_transports"
        ),
        "JavaScript executes while unauthorized HTTP and WebSocket stay local.",
    ),
    BrowserManifestCase(
        "eventsource-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_eventsource_attempts_are_blocked"
        ),
        "Same- and cross-authority EventSource attempts are blocked pre-transport.",
    ),
    BrowserManifestCase(
        "websocket-same-cross-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_same_and_cross_authority_websockets_are_denied"
        ),
        "Same- and cross-authority WebSockets are denied before handshake.",
    ),
    BrowserManifestCase(
        "fetch-xhr-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_fetch_and_xhr_are_blocked_before_transport"
        ),
        "Unauthorized same-authority fetch and XHR are blocked pre-transport.",
    ),
    BrowserManifestCase(
        "balanced-fetch-xhr",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_balanced_fetch_xhr_allows_only_natural_same_origin_get_head"
        ),
        (
            "Balanced natural same-origin GET/HEAD fetch and XHR execute once while "
            "unsafe and off-origin attempts remain pre-transport blocked."
        ),
    ),
    BrowserManifestCase(
        "network-get-canonicalization",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_observed_get_api_canonicalization_is_transport_free"
        ),
        (
            "Allowed natural same-origin GET fetch/XHR become canonical probe-ready "
            "contracts without replay; HEAD, POST, and off-origin attempts do not."
        ),
    ),
    BrowserManifestCase(
        "blocked-post-json-structure",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_blocked_post_json_is_classified_without_browser_transport"
        ),
        (
            "Natural primary-page exact-origin POST JSON stays blocked in-browser "
            "while canonical discovery retains tiered replay-policy classification."
        ),
    ),
    BrowserManifestCase(
        "passive-network-observation",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_passive_network_observation_is_bounded_and_never_replays"
        ),
        "Fetch/XHR attempts are observed without replay or blocked transport.",
    ),
    BrowserManifestCase(
        "unsafe-same-origin-get-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_unauthorized_same_origin_get_is_blocked"
        ),
        "An unauthorized same-origin GET is denied before target transport.",
    ),
    BrowserManifestCase(
        "autosubmit-post-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_autosubmit_post_is_blocked_before_transport"
        ),
        "A JavaScript autosubmit POST is denied before target transport.",
    ),
    BrowserManifestCase(
        "dom-page-close-cleanup",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_dom_driven_page_close_is_idempotently_cleaned"
        ),
        "A DOM-driven page close is idempotent and cleanup remains complete.",
    ),
    BrowserManifestCase(
        "child-frame-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_child_frames_are_blocked_and_detached"
        ),
        "Child documents never complete and attached frames are detached.",
    ),
    BrowserManifestCase(
        "popup-guard-cleanup",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_popup_is_guarded_and_cleaned"
        ),
        "Popup traffic is guarded and every created page is closed.",
    ),
    BrowserManifestCase(
        "http-redirect-same",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_same_authority_http_redirect_completes"
        ),
        "An explicitly authorized same-authority redirect completes locally.",
    ),
    BrowserManifestCase(
        "http-redirect-cross",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_cross_authority_http_redirect_is_blocked"
        ),
        "A cross-authority redirect is denied before sentinel transport.",
    ),
    BrowserManifestCase(
        "js-location-same",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_same_authority_js_location_completes"
        ),
        "An explicitly authorized same-authority JavaScript location completes.",
    ),
    BrowserManifestCase(
        "js-location-cross",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_cross_authority_js_location_is_blocked"
        ),
        "A cross-authority JavaScript location is denied before transport.",
    ),
    BrowserManifestCase(
        "navigation-timeout-cleanup",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_navigation_timeout_preserves_error_and_cleanup_audit"
        ),
        "Navigation timeout preserves its typed error and complete cleanup audit.",
    ),
    BrowserManifestCase(
        "shared-budget-flood",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_shared_transport_budget_stops_websocket_flood"
        ),
        "The shared HTTP/WebSocket decision budget stops a WebSocket flood.",
    ),
)

RENDERED_DOM_CASES = (
    BrowserManifestCase(
        "rendered-basic",
        (
            "tests.integration.test_rendered_dom_loopback."
            "RenderedDomLoopbackTests."
            "test_rendered_basic_extracts_live_main_frame_surfaces"
        ),
        "Rendered main-frame links, forms, and live controls become canonical.",
    ),
    BrowserManifestCase(
        "rendered-sensitive-elision",
        (
            "tests.integration.test_rendered_dom_loopback."
            "RenderedDomLoopbackTests."
            "test_rendered_sensitive_elision_is_precanonical_and_secret_free"
        ),
        "A password form is omitted before serialization and canonicalization.",
    ),
    BrowserManifestCase(
        "rendered-deterministic",
        (
            "tests.integration.test_rendered_dom_loopback."
            "RenderedDomLoopbackTests."
            "test_rendered_deterministic_across_two_fresh_browser_runs"
        ),
        "Two fresh Chromium runs produce identical bounded extraction output.",
    ),
    BrowserManifestCase(
        "rendered-bounded-limit",
        (
            "tests.integration.test_rendered_dom_loopback."
            "RenderedDomLoopbackTests."
            "test_rendered_bounded_node_and_utf8_size_limits_fail_closed"
        ),
        "Node and UTF-8 byte limits fail closed with complete cleanup.",
    ),
    BrowserManifestCase(
        "rendered-timeout-cleanup",
        (
            "tests.integration.test_rendered_dom_loopback."
            "RenderedDomLoopbackTests."
            "test_rendered_timeout_has_stable_error_and_complete_cleanup"
        ),
        "Structural instability times out with stable error and full cleanup.",
    ),
    BrowserManifestCase(
        "rendered-merge-compatible",
        (
            "tests.integration.test_rendered_dom_loopback."
            "RenderedDomLoopbackTests."
            "test_rendered_merge_is_compatible_with_static_component"
        ),
        "The Native Dynamic component validates and merges with Native Static.",
    ),
)

BOUNDED_NAVIGATION_CASES = tuple(
    BrowserManifestCase(
        case_id,
        (
            "tests.integration.test_dynamic_navigation_loopback."
            "DynamicNavigationLoopbackTests."
            f"test_{case_id.replace('-', '_')}"
        ),
        invariant,
    )
    for case_id, invariant in (
        (
            "navigation-basic",
            "Authorized rendered anchors produce bounded page-level Dynamic results.",
        ),
        (
            "navigation-dedup-cycle",
            "Fragments, duplicates, and cycles cannot repeat a browser navigation.",
        ),
        (
            "navigation-authority-block",
            "Cross-authority anchors and redirects never reach the sentinel server.",
        ),
        (
            "navigation-budget",
            "Page, depth, and main-frame attempt limits terminate exactly.",
        ),
        (
            "navigation-failure-isolation",
            "HTTP failures and timeout retain only prior validated page components.",
        ),
        (
            "navigation-sensitive-elision",
            "A rendered password form remains pre-canonical and secret-free.",
        ),
        (
            "navigation-deterministic",
            "Repeated fresh Chromium crawls produce equal stable output.",
        ),
    )
)

COMBINED_DISCOVERY_CASES = (
    BrowserManifestCase(
        "combined-basic",
        (
            "tests.integration.test_combined_discovery_loopback."
            "CombinedDiscoveryLoopbackTests.test_combined_basic"
        ),
        "Static-only, Dynamic-only, and exact duplicate surfaces merge canonically.",
    ),
    BrowserManifestCase(
        "combined-sensitive-elision",
        (
            "tests.integration.test_combined_discovery_loopback."
            "CombinedDiscoveryLoopbackTests.test_combined_sensitive_elision"
        ),
        "Both producers elide a colliding sensitive form before canonical merge.",
    ),
    BrowserManifestCase(
        "combined-multipage",
        (
            "tests.integration.test_combined_discovery_loopback."
            "CombinedDiscoveryLoopbackTests.test_combined_multipage"
        ),
        "Multi-page producer provenance and canonical references survive merge.",
    ),
    BrowserManifestCase(
        "combined-deterministic",
        (
            "tests.integration.test_combined_discovery_loopback."
            "CombinedDiscoveryLoopbackTests.test_combined_deterministic"
        ),
        "Repeated Chromium orchestration preserves every stable canonical field.",
    ),
    BrowserManifestCase(
        "combined-producer-failure",
        (
            "tests.integration.test_combined_discovery_loopback."
            "CombinedDiscoveryLoopbackTests.test_combined_producer_failure"
        ),
        "A real browser operational failure remains explicitly degraded.",
    ),
)

FINAL_CASES = (
    *tuple(
        BrowserManifestCase(
            case_id,
            (
                "tests.integration.test_native_dynamic_discovery_e2e."
                "NativeDynamicDiscoveryE2ETests."
                f"test_{case_id.replace('-', '_')}"
            ),
            invariant,
        )
        for case_id, invariant in (
        (
            "final-cli-combined-probe",
            "The public CLI runs combined discovery through READY GET probes.",
        ),
        (
            "final-sensitive-secret-free",
            "The password sentinel is absent from canonical, request, and report surfaces.",
        ),
        (
            "final-cross-authority-zero",
            "The cross-authority sentinel server receives zero requests.",
        ),
        (
            "final-output-consistency",
            "JSON and HTML render the same authoritative selected findings.",
        ),
        (
            "final-deterministic",
            "Two independent public CLI runs retain every deterministic identity.",
        ),
        (
            "final-cleanup",
            "Browser, worker, temporary-directory, and loopback cleanup is complete.",
        ),
        (
            "final-n34-safe-anchor-collision",
            "N-34 retains only safe anchor metadata and two producer warnings.",
        ),
        )
    ),
    BrowserManifestCase(
        "simple-cli-real-chromium-policy",
        (
            "tests.integration.test_simple_cli_loopback."
            "SimpleDynamicCliLoopbackTests."
            "test_simple_cli_real_chromium_policy"
        ),
        "Simple CLI follows rendered same-origin GET anchors and blocks active transports.",
    ),
)

MANIFESTS = {
    SUITE_BROWSER_LOOPBACK: BROWSER_LOOPBACK_CASES,
    SUITE_RENDERED_DOM: RENDERED_DOM_CASES,
    SUITE_BOUNDED_NAVIGATION: BOUNDED_NAVIGATION_CASES,
    SUITE_COMBINED_DISCOVERY: COMBINED_DISCOVERY_CASES,
    SUITE_FINAL: FINAL_CASES,
}


@dataclass(frozen=True, slots=True)
class GateEvaluation:
    required_expected: int
    required_executed: int
    required_skipped: int
    required_failed: int
    manifest_missing: int
    preflight_passed: bool
    passed: bool


def validate_manifest(cases: Sequence[BrowserManifestCase]) -> None:
    if not cases:
        raise ValueError("dynamic gate manifest must not be empty")
    case_ids: set[str] = set()
    test_ids: set[str] = set()
    for case in cases:
        if not case.required:
            raise ValueError("dynamic gate manifest cases must be required")
        if not case.case_id or not case.test_id or not case.invariant:
            raise ValueError("dynamic gate manifest fields must not be empty")
        if case.case_id in case_ids:
            raise ValueError(f"duplicate dynamic gate case id: {case.case_id}")
        if case.test_id in test_ids:
            raise ValueError(f"duplicate dynamic gate test id: {case.test_id}")
        case_ids.add(case.case_id)
        test_ids.add(case.test_id)


def _iter_tests(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_tests(item)
        else:
            yield item


def load_manifest_suite(
    cases: Sequence[BrowserManifestCase],
) -> tuple[unittest.TestSuite, tuple[str, ...]]:
    loader = unittest.TestLoader()
    combined = unittest.TestSuite()
    missing: list[str] = []
    for case in cases:
        loaded = loader.loadTestsFromName(case.test_id)
        tests = tuple(_iter_tests(loaded))
        if len(tests) != 1 or tests[0].id() != case.test_id:
            missing.append(case.test_id)
            continue
        combined.addTest(tests[0])
    return combined, tuple(missing)


def evaluate_gate(
    *,
    preflight_passed: bool,
    required_expected: int,
    tests_run: int,
    required_skipped: int,
    required_failed: int,
    manifest_missing: int,
) -> GateEvaluation:
    required_executed = max(0, tests_run - required_skipped)
    passed = (
        preflight_passed
        and required_expected > 0
        and manifest_missing == 0
        and tests_run == required_expected
        and required_executed == required_expected
        and required_skipped == 0
        and required_failed == 0
    )
    return GateEvaluation(
        required_expected=required_expected,
        required_executed=required_executed,
        required_skipped=required_skipped,
        required_failed=required_failed,
        manifest_missing=manifest_missing,
        preflight_passed=preflight_passed,
        passed=passed,
    )


def _failure_count(result: unittest.TestResult) -> int:
    return (
        len(result.failures)
        + len(result.errors)
        + len(getattr(result, "expectedFailures", ()))
        + len(getattr(result, "unexpectedSuccesses", ()))
    )


def _write_summary(
    stream: TextIO,
    *,
    capability: DynamicBrowserCapability | None,
    preflight_code: str,
    evaluation: GateEvaluation,
    suite_name: str,
) -> None:
    version = (
        capability.playwright_version if capability is not None else "unavailable"
    )
    print(f"PLAYWRIGHT_VERSION={version}", file=stream)
    print(f"PREFLIGHT={preflight_code}", file=stream)
    print(f"SUITE={suite_name}", file=stream)
    print(
        f"REQUIRED_EXPECTED={evaluation.required_expected}",
        file=stream,
    )
    print(
        f"REQUIRED_EXECUTED={evaluation.required_executed}",
        file=stream,
    )
    print(
        f"REQUIRED_SKIPPED={evaluation.required_skipped}",
        file=stream,
    )
    print(
        f"REQUIRED_FAILED={evaluation.required_failed}",
        file=stream,
    )
    print(f"MANIFEST_MISSING={evaluation.manifest_missing}", file=stream)
    print(f"FINAL={'PASS' if evaluation.passed else 'FAIL'}", file=stream)


def run_gate(
    cases: Sequence[BrowserManifestCase] = BROWSER_LOOPBACK_CASES,
    *,
    preflight_fn: Callable[[], DynamicBrowserCapability] = (
        preflight_dynamic_browser
    ),
    test_runner: Callable[[unittest.TestSuite], unittest.TestResult] | None = None,
    stream: TextIO | None = None,
    suite_name: str = SUITE_BROWSER_LOOPBACK,
) -> GateEvaluation:
    output = stream or sys.stdout
    validate_manifest(cases)
    required_expected = len(cases)
    capability: DynamicBrowserCapability | None = None
    preflight_code = "FAIL:NOT_RUN"
    result: unittest.TestResult | None = None
    missing: tuple[str, ...] = ()

    original_cwd = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="vulnspider-dynamic-gate-") as workdir:
        os.chdir(workdir)
        try:
            try:
                capability = preflight_fn()
            except DynamicCapabilityError as exc:
                preflight_code = f"FAIL:{exc.code.value}"
            except Exception:  # noqa: BLE001 - gate output remains secret-free.
                preflight_code = "FAIL:UNEXPECTED_PREFLIGHT_ERROR"
            else:
                preflight_code = "PASS"
                suite, missing = load_manifest_suite(cases)
                if not missing:
                    if test_runner is None:
                        result = unittest.TextTestRunner(
                            stream=output,
                            verbosity=2,
                        ).run(suite)
                    else:
                        result = test_runner(suite)
        finally:
            os.chdir(original_cwd)

    tests_run = result.testsRun if result is not None else 0
    required_skipped = len(result.skipped) if result is not None else 0
    required_failed = _failure_count(result) if result is not None else 0
    evaluation = evaluate_gate(
        preflight_passed=capability is not None,
        required_expected=required_expected,
        tests_run=tests_run,
        required_skipped=required_skipped,
        required_failed=required_failed,
        manifest_missing=len(missing),
    )
    _write_summary(
        output,
        capability=capability,
        preflight_code=preflight_code,
        evaluation=evaluation,
        suite_name=suite_name,
    )
    return evaluation


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a strict real-Chromium Dynamic Discovery gate.",
    )
    parser.add_argument(
        "--suite",
        choices=tuple(MANIFESTS),
        required=True,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    evaluation = run_gate(MANIFESTS[args.suite], suite_name=args.suite)
    return 0 if evaluation.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
