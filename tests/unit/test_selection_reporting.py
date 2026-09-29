from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from itertools import permutations
from unittest.mock import patch

from vulnspider.domain import (
    FeatureObservation,
    FeatureVector,
    InputLocation,
    InputPoint,
    ScoreEvidence,
    VulnerabilityCandidate,
    VulnerabilityType,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)
from vulnspider.reporting import (
    ReportingError,
    build_json_report,
    render_json_report,
    write_json_report,
)
from vulnspider.scoring import (
    SQLI_SCORER_VERSION,
    ScoringResult,
    SQLiScorer,
    XSSScorer,
)
from vulnspider.selection import (
    RankedScoringResult,
    SelectionError,
    SelectionOutcome,
    SelectionSummary,
    select_top_k,
)


class SelectionReportingTests(unittest.TestCase):
    def _vector(
        self,
        input_point_id: str,
        *,
        status_code_changed: float = 0.0,
        response_length_diff_ratio: float = 0.0,
        marker_reflected: float = 0.0,
        sql_error_pattern: float = 0.0,
        all_missing: bool = False,
        probe_run_id: str = "pair_selection",
    ) -> FeatureVector:
        values = {
            STATUS_CODE_CHANGED: status_code_changed,
            RESPONSE_LENGTH_DIFF_RATIO: response_length_diff_ratio,
            MARKER_REFLECTED: marker_reflected,
            SQL_ERROR_PATTERN: sql_error_pattern,
        }
        features = {}
        for name, value in values.items():
            if all_missing:
                features[name] = FeatureObservation.missing(
                    name,
                    source="execution-error",
                    extractor_version="unit-v1",
                    details={"reason": "execution-error"},
                )
            else:
                features[name] = FeatureObservation(
                    name=name,
                    value=value,
                    observed=True,
                    source="selection-test",
                    extractor_version="unit-v1",
                )
        return FeatureVector(
            input_point_id=input_point_id,
            probe_run_ids=(probe_run_id,),
            features=features,
        )

    def test_cross_type_selection_uses_exact_policy_maximum(self) -> None:
        sqli_vector = self._vector(
            "inp_sqli",
            response_length_diff_ratio=0.75,
            sql_error_pattern=1.0,
        )
        xss_vector = self._vector(
            "inp_xss",
            response_length_diff_ratio=1.0,
            marker_reflected=1.0,
        )
        sqli = SQLiScorer().score(sqli_vector)
        xss = XSSScorer().score(xss_vector)

        outcome = select_top_k((sqli, xss), k=2)

        self.assertAlmostEqual(sqli.candidate.rank_score or 0.0, 50.0)
        self.assertEqual(xss.candidate.rank_score, 45.0)
        self.assertEqual(
            outcome.selected[0].scoring_result.candidate.vulnerability_type,
            VulnerabilityType.REFLECTED_XSS,
        )
        self.assertEqual(outcome.selected[0].selection_priority, 1.0)
        self.assertAlmostEqual(outcome.selected[1].selection_priority, 50.0 / 75.0)

    def test_raw_rank_score_is_preserved_alongside_priority(self) -> None:
        result = SQLiScorer().score(
            self._vector(
                "inp_raw",
                status_code_changed=1.0,
                response_length_diff_ratio=0.5,
                sql_error_pattern=1.0,
            )
        )
        selected = select_top_k((result,), k=1).selected[0]
        self.assertEqual(result.candidate.rank_score, 65.0)
        self.assertEqual(selected.raw_rank_score, 65.0)
        self.assertEqual(selected.raw_rank_score_max, 75.0)
        self.assertAlmostEqual(selected.selection_priority, 65.0 / 75.0)

    def test_equal_priorities_use_candidate_id_independent_of_input_order(self) -> None:
        sqli = SQLiScorer().score(
            self._vector(
                "inp_tie_sqli",
                status_code_changed=1.0,
                response_length_diff_ratio=1.0,
                sql_error_pattern=1.0,
            )
        )
        xss = XSSScorer().score(
            self._vector(
                "inp_tie_xss",
                response_length_diff_ratio=1.0,
                marker_reflected=1.0,
            )
        )
        expected = tuple(sorted((sqli.candidate.id or "", xss.candidate.id or "")))
        for ordering in permutations((sqli, xss)):
            actual = tuple(
                item.scoring_result.candidate.id
                for item in select_top_k(ordering, k=2).selected
            )
            self.assertEqual(actual, expected)

    def test_invalid_and_oversized_k(self) -> None:
        result = SQLiScorer().score(self._vector("inp_k"))
        for invalid in (0, -1):
            with self.subTest(k=invalid):
                with self.assertRaisesRegex(SelectionError, "positive integer"):
                    select_top_k((result,), k=invalid)
        selected = select_top_k((result,), k=10).selected
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].scoring_result.candidate.id, result.candidate.id)

    def test_all_missing_is_unrankable_but_observed_zero_is_rankable(self) -> None:
        missing_vector = self._vector("inp_missing", all_missing=True)
        zero_vector = self._vector("inp_zero")
        missing_results = (
            SQLiScorer().score(missing_vector),
            XSSScorer().score(missing_vector),
        )
        zero_results = (
            SQLiScorer().score(zero_vector),
            XSSScorer().score(zero_vector),
        )

        outcome = select_top_k((*missing_results, *zero_results), k=10)

        self.assertEqual(outcome.summary.total_scoring_results, 4)
        self.assertEqual(outcome.summary.rankable_results, 2)
        self.assertEqual(outcome.summary.unrankable_results, 2)
        self.assertEqual(outcome.summary.selected_results, 2)
        self.assertTrue(
            all(item.raw_rank_score == 0.0 for item in outcome.selected)
        )
        self.assertTrue(
            all(not any(evidence.observed for evidence in item.evidence) for item in outcome.unrankable)
        )
        self.assertNotIn("safe", render_json_report(outcome).lower())

    def test_same_input_cross_type_candidates_can_both_be_selected(self) -> None:
        vector = self._vector(
            "inp_cross_type",
            status_code_changed=1.0,
            response_length_diff_ratio=1.0,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
        )
        results = (SQLiScorer().score(vector), XSSScorer().score(vector))
        selected = select_top_k(results, k=2).selected
        self.assertEqual(len(selected), 2)
        self.assertEqual(
            {item.scoring_result.candidate.vulnerability_type for item in selected},
            {VulnerabilityType.SQLI, VulnerabilityType.REFLECTED_XSS},
        )

    def test_equal_repeated_occurrences_remain_distinct(self) -> None:
        first = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=0,
            baseline_value="a",
        )
        second = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=1,
            baseline_value="a",
        )
        results = (
            SQLiScorer().score(self._vector(first.id or "")),
            SQLiScorer().score(self._vector(second.id or "")),
        )
        selected = select_top_k(results, k=2).selected
        self.assertEqual(len(selected), 2)
        self.assertEqual(
            len({item.scoring_result.candidate.id for item in selected}),
            2,
        )

    def test_duplicate_exact_candidate_uses_best_context_once(self) -> None:
        weaker = SQLiScorer().score(
            self._vector("inp_duplicate", probe_run_id="pair_weak")
        )
        stronger = SQLiScorer().score(
            self._vector(
                "inp_duplicate",
                status_code_changed=1.0,
                response_length_diff_ratio=1.0,
                sql_error_pattern=1.0,
                probe_run_id="pair_strong",
            )
        )
        for ordering in ((weaker, stronger), (stronger, weaker)):
            selected = select_top_k(ordering, k=10).selected
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0].raw_rank_score, 75.0)
            self.assertEqual(
                selected[0].scoring_result.feature_vector_id,
                stronger.feature_vector_id,
            )

    def test_report_preserves_ownership_evidence_and_is_deterministic(self) -> None:
        vector = self._vector(
            "inp_report",
            status_code_changed=1.0,
            response_length_diff_ratio=0.5,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
        )
        results = (SQLiScorer().score(vector), XSSScorer().score(vector))
        first = select_top_k(results, k=2)
        second = select_top_k(tuple(reversed(results)), k=2)

        first_text = render_json_report(first, warnings=("z", "a", "z"))
        second_text = render_json_report(second, warnings=("a", "z"))
        self.assertEqual(first_text, second_text)
        for misleading_name in ("confidence", "probability", "confirmed"):
            self.assertNotIn(misleading_name, first_text.lower())
        parsed = json.loads(first_text)
        self.assertEqual(parsed["warnings"], ["a", "z"])
        self.assertEqual(len(parsed["candidates"]), 2)
        for candidate in parsed["candidates"]:
            self.assertEqual(candidate["input_point_id"], vector.input_point_id)
            self.assertEqual(candidate["feature_vector_id"], vector.id)
            self.assertTrue(candidate["evidence"])
            for evidence in candidate["evidence"]:
                self.assertEqual(evidence["candidate_id"], candidate["candidate_id"])
                self.assertEqual(
                    evidence["feature_vector_id"],
                    candidate["feature_vector_id"],
                )
                self.assertEqual(
                    evidence["vulnerability_type"],
                    candidate["vulnerability_type"],
                )

    def test_non_finite_numbers_cannot_be_selected_or_serialized(self) -> None:
        vector = self._vector("inp_non_finite")
        candidate = VulnerabilityCandidate(
            input_point_id=vector.input_point_id,
            vulnerability_type=VulnerabilityType.SQLI,
            rank_score=0.0,
            scorer_version=SQLI_SCORER_VERSION,
        )
        evidence = ScoreEvidence(
            candidate_id=candidate.id or "",
            feature_name=STATUS_CODE_CHANGED,
            feature_value=float("nan"),
            weight=20.0,
            contribution=float("nan"),
            reason="non-finite-test",
            observed=True,
            vulnerability_type=VulnerabilityType.SQLI,
            feature_vector_id=vector.id,
        )
        result = ScoringResult.from_objects(vector, candidate, (evidence,))
        outcome = select_top_k((result,), k=1)
        with self.assertRaisesRegex(ReportingError, "non-finite"):
            render_json_report(outcome)

        non_finite_candidate = VulnerabilityCandidate(
            input_point_id=vector.input_point_id,
            vulnerability_type=VulnerabilityType.SQLI,
            rank_score=float("inf"),
            scorer_version=SQLI_SCORER_VERSION,
        )
        non_finite_result = ScoringResult.from_objects(
            vector,
            non_finite_candidate,
            (evidence,),
        )
        with self.assertRaisesRegex(SelectionError, "finite"):
            select_top_k((non_finite_result,), k=1)

    def test_report_summary_matches_selection(self) -> None:
        result = XSSScorer().score(self._vector("inp_summary"))
        report = build_json_report(select_top_k((result,), k=5))
        self.assertEqual(report["schema_version"], "0.1")
        self.assertEqual(report["summary"]["top_k_requested"], 5)
        self.assertEqual(report["summary"]["selected_results"], 1)

    def test_json_write_failure_preserves_previous_result_and_removes_temp(
        self,
    ) -> None:
        outcome = select_top_k((), k=1)
        with TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "result.json"
            destination.write_text("previous-success\n", encoding="utf-8")

            with (
                patch(
                    "vulnspider.reporting.json_report.os.replace",
                    side_effect=OSError("replace failed"),
                ),
                self.assertRaises(OSError),
            ):
                write_json_report(outcome, destination)

            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                "previous-success\n",
            )
            self.assertEqual(tuple(Path(temporary_directory).iterdir()), (destination,))


class SelectionTruthfulnessTests(unittest.TestCase):
    def _vector(
        self,
        input_point_id: str,
        *,
        status_code_changed: float = 0.0,
        response_length_diff_ratio: float = 0.0,
        marker_reflected: float = 0.0,
        sql_error_pattern: float = 0.0,
    ) -> FeatureVector:
        values = {
            STATUS_CODE_CHANGED: status_code_changed,
            RESPONSE_LENGTH_DIFF_RATIO: response_length_diff_ratio,
            MARKER_REFLECTED: marker_reflected,
            SQL_ERROR_PATTERN: sql_error_pattern,
        }
        return FeatureVector(
            input_point_id=input_point_id,
            probe_run_ids=("pair_truthfulness",),
            features={
                name: FeatureObservation(
                    name=name,
                    value=value,
                    observed=True,
                    source="truthfulness-test",
                    extractor_version="unit-v1",
                )
                for name, value in values.items()
            },
        )

    def _sqli_65(self) -> ScoringResult:
        return SQLiScorer().score(
            self._vector(
                "inp_truth_sqli",
                status_code_changed=1.0,
                response_length_diff_ratio=0.5,
                sql_error_pattern=1.0,
            )
        )

    def test_old_forged_ranked_result_construction_is_closed(self) -> None:
        result = self._sqli_65()
        self.assertEqual(result.candidate.rank_score, 65.0)
        with self.assertRaisesRegex(TypeError, "from_scoring_result"):
            RankedScoringResult(
                scoring_result=result,
                raw_rank_score=0.0,
                raw_rank_score_max=75.0,
                selection_priority=0.0,
            )

    def test_arbitrary_priority_and_wrong_maximum_are_not_public_inputs(self) -> None:
        sqli = self._sqli_65()
        xss = XSSScorer().score(
            self._vector(
                "inp_truth_xss",
                response_length_diff_ratio=1.0,
                marker_reflected=1.0,
            )
        )
        for result, maximum, priority in (
            (sqli, 45.0, 65.0 / 45.0),
            (sqli, 75.0, 0.0),
            (xss, 75.0, 45.0 / 75.0),
        ):
            with self.subTest(
                vulnerability_type=result.candidate.vulnerability_type,
                maximum=maximum,
                priority=priority,
            ):
                with self.assertRaisesRegex(TypeError, "from_scoring_result"):
                    RankedScoringResult(
                        scoring_result=result,
                        raw_rank_score=float(result.candidate.rank_score or 0.0),
                        raw_rank_score_max=maximum,
                        selection_priority=priority,
                    )

    def test_ranked_factory_derives_authoritative_values(self) -> None:
        sqli = RankedScoringResult.from_scoring_result(self._sqli_65())
        xss = RankedScoringResult.from_scoring_result(
            XSSScorer().score(
                self._vector(
                    "inp_truth_xss_factory",
                    response_length_diff_ratio=1.0,
                    marker_reflected=1.0,
                )
            )
        )
        self.assertEqual(sqli.raw_rank_score, 65.0)
        self.assertEqual(sqli.raw_rank_score_max, 75.0)
        self.assertAlmostEqual(sqli.selection_priority, 65.0 / 75.0)
        self.assertEqual(xss.raw_rank_score, 45.0)
        self.assertEqual(xss.raw_rank_score_max, 45.0)
        self.assertEqual(xss.selection_priority, 1.0)

    def test_false_selected_count_outcome_is_rejected(self) -> None:
        valid = select_top_k((self._sqli_65(),), k=1)
        with self.assertRaisesRegex(TypeError, "select_top_k"):
            SelectionSummary(
                total_scoring_results=0,
                rankable_results=0,
                unrankable_results=0,
                selected_results=0,
                top_k_requested=99,
            )
        with self.assertRaisesRegex(TypeError, "select_top_k"):
            SelectionOutcome(
                summary=valid.summary,
                selected=valid.selected,
                unrankable=(),
            )

    def test_summary_arithmetic_mismatch_is_rejected(self) -> None:
        outcome = select_top_k((self._sqli_65(),), k=1)
        object.__setattr__(outcome.summary, "total_scoring_results", 3)
        with self.assertRaisesRegex(SelectionError, "rankable plus unrankable"):
            outcome.summary.validate()

    def test_reporting_boundary_revalidates_outcome(self) -> None:
        outcome = select_top_k((self._sqli_65(),), k=1)
        object.__setattr__(outcome.summary, "selected_results", 0)
        with self.assertRaisesRegex(ReportingError, "internally inconsistent"):
            render_json_report(outcome)

    def test_reporting_boundary_rejects_corrupted_ranked_values(self) -> None:
        outcome = select_top_k((self._sqli_65(),), k=1)
        object.__setattr__(outcome.selected[0], "raw_rank_score", 0.0)
        object.__setattr__(outcome.selected[0], "selection_priority", 0.0)
        with self.assertRaisesRegex(ReportingError, "internally inconsistent"):
            render_json_report(outcome)

    def test_valid_report_counts_match_candidates(self) -> None:
        sqli = self._sqli_65()
        xss = XSSScorer().score(
            self._vector(
                "inp_truth_xss_report",
                response_length_diff_ratio=1.0,
                marker_reflected=1.0,
            )
        )
        outcome = select_top_k((sqli, xss), k=2)
        report = json.loads(render_json_report(outcome))
        self.assertEqual(
            report["summary"]["selected_results"],
            len(report["candidates"]),
        )
        self.assertEqual(report["summary"]["total_scoring_results"], 2)
        self.assertEqual(report["summary"]["rankable_results"], 2)
        self.assertEqual(report["summary"]["unrankable_results"], 0)


if __name__ == "__main__":
    unittest.main()
