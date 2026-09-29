from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tests.unit.test_simple_cli import _native_analysis
from vulnspider.reporting import (
    ReportingError,
    build_analysis_report,
    build_crawl_report,
    write_analysis_report,
    write_crawl_report,
)


class SplitOutputReportingTests(unittest.TestCase):
    def test_crawl_report_delegates_to_canonical_serializer(self) -> None:
        analysis = _native_analysis()
        crawl = analysis.crawl_result
        assert crawl is not None

        report = build_crawl_report(crawl)

        self.assertEqual(report["crawl"], crawl.to_dict())
        self.assertEqual(report["report_kind"], "crawl")
        self.assertEqual(report["crawl_mode"], "static_only")
        self.assertEqual(report["completion"], "COMPLETE")
        self.assertFalse(report["degraded"])
        self.assertNotIn("probe_observations", report)
        self.assertNotIn("feature_vectors", report)
        self.assertNotIn("scoring_results", report)
        self.assertNotIn("candidates", report)

    def test_analysis_report_preserves_authoritative_stable_links(self) -> None:
        analysis = _native_analysis()
        discovery = analysis.discovery_result
        assert discovery is not None

        report = build_analysis_report(analysis)

        crawl_input_ids = {item.id for item in discovery.input_points}
        self.assertEqual(
            set(report["crawl_reference"]["input_point_ids"]),
            crawl_input_ids,
        )
        self.assertEqual(
            report["crawl_reference"]["discovery_run_id"],
            discovery.discovery_run_id,
        )
        vectors = {item["id"]: item for item in report["feature_vectors"]}
        self.assertEqual(set(vectors), {item.id for item in analysis.feature_vectors})
        for observation in report["probe_observations"]:
            self.assertIn(observation["input_point_id"], crawl_input_ids)
            self.assertIn(observation["feature_vector_id"], vectors)
            self.assertEqual(
                observation["response_pair_ids"],
                vectors[observation["feature_vector_id"]]["probe_run_ids"],
            )
            self.assertNotIn("url", observation["probe_plan"]["baseline_request"])
            self.assertNotIn("query", observation["probe_plan"]["probe_request"])
            self.assertNotIn("decoded_text", observation["baseline_response"])
            self.assertNotIn("headers", observation["probe_response"])
            self.assertNotIn("redirect_location", observation["probe_response"])
        self.assertEqual(
            {item["candidate_id"] for item in report["candidates"]},
            {item.scoring_result.candidate.id for item in analysis.selection.selected},
        )

    def test_analysis_report_rejects_missing_feature_provenance(self) -> None:
        analysis = replace(_native_analysis(), feature_vectors=())

        with self.assertRaisesRegex(ReportingError, "FeatureVector"):
            build_analysis_report(analysis)

    def test_analysis_report_rejects_swapped_response_roles(self) -> None:
        analysis = _native_analysis()
        observation = analysis.probe_observations[0]
        swapped = replace(
            observation,
            baseline_response=observation.probe_response,
            probe_response=observation.baseline_response,
        )
        malformed = replace(
            analysis,
            probe_observations=(swapped, *analysis.probe_observations[1:]),
        )

        with self.assertRaisesRegex(ReportingError, "response pairing"):
            build_analysis_report(malformed)

    def test_analysis_report_rejects_mismatched_response_pair_id(self) -> None:
        analysis = _native_analysis()
        vector = analysis.feature_vectors[0]
        malformed_vector = replace(
            vector,
            probe_run_ids=("pair_mismatched",),
        )
        malformed = replace(
            analysis,
            feature_vectors=(malformed_vector, *analysis.feature_vectors[1:]),
        )

        with self.assertRaisesRegex(ReportingError, "ResponsePair ownership"):
            build_analysis_report(malformed)

    def test_analysis_report_rejects_selection_scoring_disagreement(self) -> None:
        analysis = _native_analysis()
        malformed = replace(
            analysis,
            scoring_results=analysis.scoring_results[:-1],
        )

        with self.assertRaisesRegex(ReportingError, "exact ownership|selection"):
            build_analysis_report(malformed)

    def test_crawl_atomic_replace_failure_preserves_old_file_and_cleans_temp(
        self,
    ) -> None:
        analysis = _native_analysis()
        crawl = analysis.crawl_result
        assert crawl is not None
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            destination = directory / "crawl.json"
            destination.write_text('{"old": true}\n', encoding="utf-8")

            with (
                patch(
                    "vulnspider.reporting.json_report.os.replace",
                    side_effect=OSError("replace failed"),
                ),
                self.assertRaisesRegex(OSError, "replace failed"),
            ):
                write_crawl_report(crawl, destination)

            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                {"old": True},
            )
            self.assertEqual(tuple(directory.glob(".crawl.json.*.tmp")), ())

    def test_analysis_atomic_replace_failure_preserves_old_file_and_cleans_temp(
        self,
    ) -> None:
        analysis = _native_analysis()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            destination = directory / "analysis.json"
            destination.write_text('{"old": true}\n', encoding="utf-8")

            with (
                patch(
                    "vulnspider.reporting.json_report.os.replace",
                    side_effect=OSError("replace failed"),
                ),
                self.assertRaisesRegex(OSError, "replace failed"),
            ):
                write_analysis_report(analysis, destination)

            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                {"old": True},
            )
            self.assertEqual(tuple(directory.glob(".analysis.json.*.tmp")), ())


if __name__ == "__main__":
    unittest.main()
