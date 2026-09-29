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
        body = b"baseline"
        if marker is not None:
            body = f"{marker} SQL syntax error".encode("utf-8")
        return TransportResponse(
            status_code=200,
            body=body,
            elapsed_ms=1.0,
            encoding="utf-8",
        )


class V01EndToEndSmokeTests(unittest.TestCase):
    def _write_records(self, directory: Path, records: object) -> Path:
        path = directory / "records.json"
        path.write_text(json.dumps(records), encoding="utf-8")
        return path

    def test_cli_smoke_runs_real_v01_boundaries_to_top_k_json(self) -> None:
        records = [
            {
                "link": "http://127.0.0.1/search?q=book",
                "parent": "http://127.0.0.1/",
                "depth": 1,
                "host": "127.0.0.1",
                "query_params": '{"q":"book"}',
                "input_fields": "[]",
                "source": "legacy_fixture",
            }
        ]
        transport = MarkerTransport()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, records)
            output_path = directory / "report.json"
            html_output_path = directory / "report.html"

            exit_code = cli.main(
                [
                    "analyze",
                    "--input",
                    str(input_path),
                    "--top-k",
                    "1",
                    "--output",
                    str(output_path),
                    "--html-output",
                    str(html_output_path),
                ],
                transport=transport,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(transport.requests), 2)
            report_text = output_path.read_text(encoding="utf-8")
            report = json.loads(report_text)
            html_text = html_output_path.read_text(encoding="utf-8")

        self.assertEqual(report["selection"]["candidates_scored"], 2)
        self.assertEqual(report["selection"]["selected"], 1)
        self.assertEqual(report["selection"]["top_k"], 1)
        self.assertEqual(len(report["verification_order"]), 1)
        candidate = report["verification_order"][0]
        self.assertEqual(candidate["order"], 1)
        self.assertIn(candidate["family"], {"SQLI", "REFLECTED_XSS"})
        self.assertIn("probability", candidate)

        # The HTML dashboard renders the same validated decision outcome, plus
        # the real endpoint/param join and the actually-executed baseline/probe
        # request pair — not a recomputation.
        self.assertIn("Reflected XSS", html_text)
        self.assertIn("/search", html_text)
        self.assertIn(candidate["candidate_id"], html_text)
        self.assertIn("실행된 요청", html_text)
        self.assertIn("baseline", html_text)
        self.assertIn("probe", html_text)
        # These probabilities are pre-verification priorities, not confirmations.
        self.assertIn("검증 이전의 우선순위", html_text)

    def test_cli_html_output_is_optional_and_does_not_change_json_behavior(
        self,
    ) -> None:
        records = [
            {
                "link": "http://127.0.0.1/search?q=book",
                "parent": "http://127.0.0.1/",
                "depth": 1,
                "host": "127.0.0.1",
                "query_params": '{"q":"book"}',
                "input_fields": "[]",
                "source": "legacy_fixture",
            }
        ]
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, records)
            output_path = directory / "report.json"

            exit_code = cli.main(
                [
                    "analyze",
                    "--input",
                    str(input_path),
                    "--top-k",
                    "1",
                    "--output",
                    str(output_path),
                ],
                transport=MarkerTransport(),
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            self.assertEqual(
                sorted(path.name for path in directory.iterdir()),
                ["records.json", "report.json"],
            )

    def test_cli_rejects_equivalent_report_destinations_before_writing(self) -> None:
        records = [
            {
                "link": "http://127.0.0.1/search?q=book",
                "query_params": '{"q":"book"}',
                "input_fields": "[]",
            }
        ]
        transport = MarkerTransport()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, records)
            json_output_path = directory / "reports" / ".." / "report.json"
            html_output_path = directory / "report.json"
            error_output = io.StringIO()

            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(input_path),
                        "--top-k",
                        "1",
                        "--output",
                        str(json_output_path),
                        "--html-output",
                        str(html_output_path),
                    ],
                    transport=transport,
                )

            self.assertEqual(exit_code, 2)
            self.assertIn("must refer to different files", error_output.getvalue())
            self.assertEqual(transport.requests, [])
            self.assertEqual(
                sorted(path.name for path in directory.iterdir()),
                ["records.json"],
            )

    def test_cli_rejects_invalid_top_k_and_missing_required_input(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as invalid_k:
                cli.main(
                    [
                        "analyze",
                        "--input",
                        "records.json",
                        "--top-k",
                        "0",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(invalid_k.exception.code, 2)

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing_input:
                cli.main(
                    [
                        "analyze",
                        "--top-k",
                        "1",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(missing_input.exception.code, 2)

    def test_cli_rejects_malformed_adapter_input_without_traceback(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = directory / "malformed.json"
            input_path.write_text("not-json", encoding="utf-8")
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(input_path),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                    ],
                    transport=MarkerTransport(),
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("not valid JSON", error_output.getvalue())
        self.assertNotIn("Traceback", error_output.getvalue())

        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, [{"query_params": "{}"}])
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(input_path),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                    ],
                    transport=MarkerTransport(),
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("requires a non-empty link", error_output.getvalue())
        self.assertNotIn("Traceback", error_output.getvalue())

    def test_cli_rejects_non_loopback_record(self) -> None:
        records = [
            {
                "link": "http://example.test/search?q=book",
                "query_params": '{"q":"book"}',
                "input_fields": "[]",
            }
        ]
        transport = MarkerTransport()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, records)
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(input_path),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                    ],
                    transport=transport,
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("loopback", error_output.getvalue())
        self.assertEqual(transport.requests, [])

    def test_version_command_regression(self) -> None:
        standard_output = io.StringIO()
        with redirect_stdout(standard_output):
            with self.assertRaises(SystemExit) as version_exit:
                cli.main(["--version"])
        self.assertEqual(version_exit.exception.code, 0)
        self.assertEqual(standard_output.getvalue().strip(), "vulnspider 0.1.0")


if __name__ == "__main__":
    unittest.main()
