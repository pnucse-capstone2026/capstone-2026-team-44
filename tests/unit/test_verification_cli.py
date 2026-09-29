from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnspider import cli
from vulnspider.domain import RequestInstance
from vulnspider.observation import TransportResponse


@dataclass
class VulnerableTransport:
    """A loopback fake with a reflected-XSS and error-based SQLi endpoint.

    Any request whose target value carries a single quote returns a SQL error;
    otherwise the value is reflected raw. This makes both the baseline light
    probe and the verification re-probe see a real signal.
    """

    requests: list[RequestInstance] = field(default_factory=list)

    def send(
        self, request: RequestInstance, *, timeout_seconds: float
    ) -> TransportResponse:
        self.requests.append(request)
        values = [value for _name, value in request.query]
        target = values[-1] if values else ""
        if "'" in target or '"' in target:
            body = b"<html>You have an error in your SQL syntax near</html>"
            return TransportResponse(500, body, {}, 1.0, "utf-8")
        return TransportResponse(
            200, f"<div>{target}</div>".encode("utf-8"), {}, 1.0, "utf-8"
        )


_RECORDS = [
    {
        "link": "http://127.0.0.1/search?q=book",
        "parent": "http://127.0.0.1/",
        "depth": 1,
        "host": "127.0.0.1",
        "query_params": '{"q":"book"}',
        "input_fields": "[]",
    }
]


class VerificationCliTests(unittest.TestCase):
    def _write_records(self, directory: Path) -> Path:
        path = directory / "records.json"
        path.write_text(json.dumps(_RECORDS), encoding="utf-8")
        return path

    def test_analyze_verify_writes_verification_report(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with TemporaryDirectory(prefix="vulnspider-verify-cli-") as workdir:
            directory = Path(workdir)
            records = self._write_records(directory)
            output = directory / "analysis.json"
            verify_output = directory / "verification.json"
            detail_output = directory / "verification-detail.html"
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "5",
                        "--output",
                        str(output),
                        "--verify",
                        "--verify-output",
                        str(verify_output),
                        "--verify-detail-output",
                        str(detail_output),
                    ],
                    transport=VulnerableTransport(),
                )
            self.assertEqual(exit_code, 0, stderr.getvalue())
            self.assertTrue(output.exists())
            self.assertTrue(verify_output.exists())
            self.assertTrue(detail_output.exists())
            report = json.loads(verify_output.read_text(encoding="utf-8"))

        self.assertEqual(report["report_version"], "verification-report-v1")
        self.assertEqual(report["contract_version"], "0.1")
        self.assertTrue(report["candidates"])
        self.assertEqual(report["counts"]["rejected"], 0)
        self.assertGreater(report["counts"]["executed"], 0)
        outcomes = {c["final_outcome"] for c in report["candidates"]}
        self.assertIn("SUPPORTED", outcomes)
        # Every executed result must carry validated provenance and a rule-derived
        # confidence on the (0, 1) scale.
        for candidate in report["candidates"]:
            for result in candidate["results"]:
                self.assertEqual(result["validator"]["decision"], "ACCEPTED")
                conf = result["confidence"]["verification_confidence"]
                self.assertGreater(conf, 0.0)
                self.assertLess(conf, 1.0)

    def test_decision_json_reflects_final_confidence(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with TemporaryDirectory(prefix="vulnspider-verify-json-") as workdir:
            directory = Path(workdir)
            records = self._write_records(directory)
            output = directory / "analysis.json"
            detail_output = directory / "verification-detail.html"
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "5",
                        "--output",
                        str(output),
                        "--verify",
                        "--verify-output",
                        str(directory / "v.json"),
                        "--verify-detail-output",
                        str(detail_output),
                    ],
                    transport=VulnerableTransport(),
                )
            self.assertEqual(exit_code, 0, stderr.getvalue())
            self.assertTrue(detail_output.exists())
            report = json.loads(output.read_text(encoding="utf-8"))
        # The decision JSON and the verification report now agree on the final
        # score (ADR-034): every selected candidate carries a final_confidence.
        self.assertIsNotNone(report["verification"])
        self.assertTrue(report["verification"]["ran"])
        entry = report["verification_order"][0]
        self.assertIn("final_confidence", entry)
        self.assertIn("verification_outcome", entry)
        self.assertIn("prior_probability", entry)

    def test_simple_mode_defaults_to_html_dashboard(self) -> None:
        parser = cli.build_parser()
        default = cli._simple_analysis_args(parser.parse_args(["-u", "http://127.0.0.1/"]))
        self.assertEqual(default.html_output, cli._SIMPLE_DEFAULT_HTML_OUTPUT)
        disabled = cli._simple_analysis_args(
            parser.parse_args(["-u", "http://127.0.0.1/", "--no-html"])
        )
        self.assertIsNone(disabled.html_output)

    def test_verify_output_collision_is_rejected(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with TemporaryDirectory(prefix="vulnspider-verify-collide-") as workdir:
            directory = Path(workdir)
            records = self._write_records(directory)
            output = directory / "analysis.json"
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "5",
                        "--output",
                        str(output),
                        "--verify-output",
                        str(output),
                    ],
                    transport=VulnerableTransport(),
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("verify-output", stderr.getvalue())

    def test_without_verify_no_report_is_written(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with TemporaryDirectory(prefix="vulnspider-verify-off-") as workdir:
            directory = Path(workdir)
            records = self._write_records(directory)
            output = directory / "analysis.json"
            verify_output = directory / "verification.json"
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "5",
                        "--output",
                        str(output),
                    ],
                    transport=VulnerableTransport(),
                )
            self.assertEqual(exit_code, 0, stderr.getvalue())
            self.assertFalse(verify_output.exists())


if __name__ == "__main__":
    unittest.main()
