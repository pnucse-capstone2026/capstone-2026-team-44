from __future__ import annotations

from io import StringIO
import unittest

from tools import check_dynamic_gate as gate
from vulnspider.discovery import (
    DynamicBrowserCapability,
    DynamicCapabilityCode,
    DynamicCapabilityError,
)


def capability() -> DynamicBrowserCapability:
    return DynamicBrowserCapability(
        playwright_version="1.61.0",
        browser_name="chromium",
        websocket_guard_callable=True,
        headless_launch_verified=True,
    )


class DynamicGateManifestTests(unittest.TestCase):
    def test_browser_loopback_manifest_is_explicit_unique_and_linked(self) -> None:
        cases = gate.BROWSER_LOOPBACK_CASES

        gate.validate_manifest(cases)
        suite, missing = gate.load_manifest_suite(cases)

        self.assertEqual(len(cases), 19)
        self.assertEqual(missing, ())
        self.assertEqual(suite.countTestCases(), len(cases))
        self.assertEqual(
            len({case.case_id for case in cases}),
            len(cases),
        )
        self.assertEqual(
            len({case.test_id for case in cases}),
            len(cases),
        )
        self.assertTrue(all(case.required for case in cases))

    def test_rendered_dom_manifest_is_explicit_unique_and_linked(self) -> None:
        cases = gate.RENDERED_DOM_CASES

        gate.validate_manifest(cases)
        suite, missing = gate.load_manifest_suite(cases)

        self.assertEqual(
            [case.case_id for case in cases],
            [
                "rendered-basic",
                "rendered-sensitive-elision",
                "rendered-deterministic",
                "rendered-bounded-limit",
                "rendered-timeout-cleanup",
                "rendered-merge-compatible",
            ],
        )
        self.assertEqual(missing, ())
        self.assertEqual(suite.countTestCases(), 6)
        self.assertEqual(len({case.test_id for case in cases}), 6)
        self.assertTrue(all(case.required for case in cases))

    def test_bounded_navigation_manifest_is_explicit_unique_and_linked(self) -> None:
        cases = gate.BOUNDED_NAVIGATION_CASES

        gate.validate_manifest(cases)
        suite, missing = gate.load_manifest_suite(cases)

        self.assertEqual(
            [case.case_id for case in cases],
            [
                "navigation-basic",
                "navigation-dedup-cycle",
                "navigation-authority-block",
                "navigation-budget",
                "navigation-failure-isolation",
                "navigation-sensitive-elision",
                "navigation-deterministic",
            ],
        )
        self.assertEqual(missing, ())
        self.assertEqual(suite.countTestCases(), 7)
        self.assertEqual(len({case.test_id for case in cases}), 7)
        self.assertTrue(all(case.required for case in cases))

    def test_combined_discovery_manifest_is_explicit_unique_and_linked(self) -> None:
        cases = gate.COMBINED_DISCOVERY_CASES

        gate.validate_manifest(cases)
        suite, missing = gate.load_manifest_suite(cases)

        self.assertEqual(
            [case.case_id for case in cases],
            [
                "combined-basic",
                "combined-sensitive-elision",
                "combined-multipage",
                "combined-deterministic",
                "combined-producer-failure",
            ],
        )
        self.assertEqual(missing, ())
        self.assertEqual(suite.countTestCases(), 5)
        self.assertEqual(len({case.test_id for case in cases}), 5)
        self.assertTrue(all(case.required for case in cases))

    def test_final_manifest_includes_simple_cli_real_chromium_policy(self) -> None:
        cases = gate.FINAL_CASES

        gate.validate_manifest(cases)
        suite, missing = gate.load_manifest_suite(cases)

        self.assertEqual(len(cases), 8)
        self.assertEqual(missing, ())
        self.assertEqual(suite.countTestCases(), 8)
        self.assertEqual(
            cases[-1].case_id,
            "simple-cli-real-chromium-policy",
        )
        self.assertTrue(all(case.required for case in cases))

    def test_missing_or_renamed_test_link_is_rejected(self) -> None:
        missing_case = gate.BrowserManifestCase(
            case_id="missing-test",
            test_id=(
                "tests.integration.test_dynamic_browser_loopback."
                "DynamicBrowserLoopbackTests.test_missing_gate_case"
            ),
            invariant="A renamed test must invalidate the manifest.",
        )

        suite, missing = gate.load_manifest_suite((missing_case,))

        self.assertEqual(suite.countTestCases(), 0)
        self.assertEqual(missing, (missing_case.test_id,))

    def test_duplicate_manifest_identifiers_are_rejected(self) -> None:
        first = gate.BROWSER_LOOPBACK_CASES[0]
        duplicate = gate.BrowserManifestCase(
            case_id=first.case_id,
            test_id=gate.BROWSER_LOOPBACK_CASES[1].test_id,
            invariant="duplicate",
        )

        with self.assertRaisesRegex(ValueError, "duplicate dynamic gate case id"):
            gate.validate_manifest((first, duplicate))


class DynamicGateDecisionTests(unittest.TestCase):
    def test_only_complete_required_execution_passes(self) -> None:
        passing = gate.evaluate_gate(
            preflight_passed=True,
            required_expected=15,
            tests_run=15,
            required_skipped=0,
            required_failed=0,
            manifest_missing=0,
        )
        self.assertTrue(passing.passed)
        self.assertEqual(passing.required_executed, 15)

        failing_inputs = (
            {"preflight_passed": False},
            {"required_expected": 0, "tests_run": 0},
            {"tests_run": 0},
            {"tests_run": 14},
            {"required_skipped": 1},
            {"required_failed": 1},
            {"manifest_missing": 1},
        )
        defaults = {
            "preflight_passed": True,
            "required_expected": 15,
            "tests_run": 15,
            "required_skipped": 0,
            "required_failed": 0,
            "manifest_missing": 0,
        }
        for overrides in failing_inputs:
            with self.subTest(overrides=overrides):
                inputs = defaults | overrides
                self.assertFalse(gate.evaluate_gate(**inputs).passed)

    def test_preflight_failure_runs_no_manifest_test_and_prints_fail(self) -> None:
        output = StringIO()
        runner_called = False

        def fail_preflight() -> DynamicBrowserCapability:
            raise DynamicCapabilityError(
                DynamicCapabilityCode.CHROMIUM_EXECUTABLE_MISSING,
                "missing",
                setup_hint="install chromium",
            )

        def runner(_: unittest.TestSuite) -> unittest.TestResult:
            nonlocal runner_called
            runner_called = True
            return unittest.TestResult()

        evaluation = gate.run_gate(
            preflight_fn=fail_preflight,
            test_runner=runner,
            stream=output,
        )

        self.assertFalse(evaluation.passed)
        self.assertFalse(runner_called)
        self.assertIn("PLAYWRIGHT_VERSION=unavailable", output.getvalue())
        self.assertIn(
            "PREFLIGHT=FAIL:CHROMIUM_EXECUTABLE_MISSING",
            output.getvalue(),
        )
        self.assertIn("REQUIRED_EXECUTED=0", output.getvalue())
        self.assertIn("FINAL=FAIL", output.getvalue())

    def test_aggregated_required_skip_and_failure_each_print_fail(self) -> None:
        def skipped_runner(suite: unittest.TestSuite) -> unittest.TestResult:
            result = unittest.TestResult()
            result.testsRun = suite.countTestCases()
            result.skipped.append((None, "required skip"))
            return result

        def failed_runner(suite: unittest.TestSuite) -> unittest.TestResult:
            result = unittest.TestResult()
            result.testsRun = suite.countTestCases()
            result.failures.append((None, "required failure"))
            return result

        for runner, expected_line in (
            (skipped_runner, "REQUIRED_SKIPPED=1"),
            (failed_runner, "REQUIRED_FAILED=1"),
        ):
            with self.subTest(expected_line=expected_line):
                output = StringIO()
                evaluation = gate.run_gate(
                    preflight_fn=capability,
                    test_runner=runner,
                    stream=output,
                )
                self.assertFalse(evaluation.passed)
                self.assertIn(expected_line, output.getvalue())
                self.assertIn("FINAL=FAIL", output.getvalue())

    def test_linked_fake_execution_prints_deterministic_pass_counts(self) -> None:
        output = StringIO()

        def runner(suite: unittest.TestSuite) -> unittest.TestResult:
            result = unittest.TestResult()
            result.testsRun = suite.countTestCases()
            return result

        evaluation = gate.run_gate(
            preflight_fn=capability,
            test_runner=runner,
            stream=output,
        )

        self.assertTrue(evaluation.passed)
        self.assertIn("PLAYWRIGHT_VERSION=1.61.0", output.getvalue())
        self.assertIn("PREFLIGHT=PASS", output.getvalue())
        self.assertIn("SUITE=browser-loopback", output.getvalue())
        self.assertIn("REQUIRED_EXPECTED=19", output.getvalue())
        self.assertIn("REQUIRED_EXECUTED=19", output.getvalue())
        self.assertIn("REQUIRED_SKIPPED=0", output.getvalue())
        self.assertIn("REQUIRED_FAILED=0", output.getvalue())
        self.assertIn("MANIFEST_MISSING=0", output.getvalue())
        self.assertIn("FINAL=PASS", output.getvalue())


if __name__ == "__main__":
    unittest.main()
