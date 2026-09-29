from __future__ import annotations

import unittest
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.results_pack import Scenario, _demoshop_bac, _display_command, _run


class ResultsPackCommandTests(unittest.TestCase):
    def test_display_command_redacts_cookie_values_without_mutating_args(self) -> None:
        sentinel = "RESULTS_PACK_COOKIE_SENTINEL"
        args = [
            "analyze",
            "--cookie",
            f"sid={sentinel}",
            f"--cookie=csrf={sentinel}",
            "--top-k",
            "1",
        ]
        original = list(args)

        command = _display_command(args)

        self.assertEqual(args, original)
        self.assertNotIn(sentinel, command)
        self.assertIn("--cookie sid=<redacted>", command)
        self.assertIn("--cookie=csrf=<redacted>", command)

    def test_scenario_eval_path_uses_requested_output_root(self) -> None:
        output_root = Path("custom-results-pack")

        scenario = _demoshop_bac(output_root, 8899, 10)

        self.assertEqual(
            scenario.eval_path,
            output_root / "demoshop-bac" / "evaluation.json",
        )

    def test_failed_run_log_and_detail_redact_malformed_cookie(self) -> None:
        sentinel = "MALFORMED_DVWA_COOKIE_SENTINEL"
        with TemporaryDirectory() as directory:
            output_root = Path(directory)
            scenario = Scenario(
                "dvwa",
                "DVWA",
                "http://127.0.0.1:4280/",
                ["analyze", "--cookie", sentinel],
                output_root,
            )
            completed = CompletedProcess(
                args=(),
                returncode=2,
                stdout="",
                stderr=f"--cookie must be NAME=VALUE, got {sentinel!r}\n",
            )

            with patch("tools.results_pack.subprocess.run", return_value=completed):
                _run(scenario, output_root)

            run_log = (output_root / "dvwa" / "run.log").read_text(
                encoding="utf-8"
            )
            command = (output_root / "dvwa" / "command.txt").read_text(
                encoding="utf-8"
            )
            self.assertNotIn(sentinel, run_log)
            self.assertNotIn(sentinel, command)
            self.assertNotIn(sentinel, scenario.detail)
            self.assertIn("<redacted>", run_log)
            self.assertIn("<redacted>", scenario.detail)


if __name__ == "__main__":
    unittest.main()
