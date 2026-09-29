"""The per-input-point random predictor: config, determinism, and its metrics."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from vulnspider.cli import CLIError, _evaluation_request_from_args
from vulnspider.corpus.ground_truth import GroundTruthKey
from vulnspider.evaluation.live import ScoredCandidate
from vulnspider.evaluation.random_predictor import (
    DEFAULT_TRIALS,
    PREDICTION_CLASSES,
    RANDOM_PREDICTOR_ARM,
    RandomPredictor,
    RandomPredictorError,
    evaluate_random_predictor,
    safe_biased_weights,
    uniform_weights,
)

APPLICATION = "app"


def _key(path: str, name: str, family: str) -> GroundTruthKey:
    return GroundTruthKey(
        application_id=APPLICATION,
        method="GET",
        canonical_path=path,
        parameter_location="QUERY",
        parameter_name=name,
        vulnerability_type=family,
    )


def _scored(
    candidate_id: str,
    *,
    family: str,
    label: bool | None,
    path: str = "/a",
    name: str = "q",
) -> ScoredCandidate:
    return ScoredCandidate(
        candidate_id=candidate_id,
        key=_key(path, name, family),
        prior=0.5,
        final=0.5,
        verified=False,
        label=label,
    )


def _one_point_pool() -> tuple[ScoredCandidate, ...]:
    """One input point with a vulnerable SQLI candidate and a safe XSS one."""

    return (
        _scored("sqli", family="SQLI", label=True),
        _scored("xss", family="REFLECTED_XSS", label=False),
    )


class WeightHelperTests(unittest.TestCase):
    def test_uniform_weights_cover_every_class(self) -> None:
        weights = uniform_weights()
        self.assertEqual(set(weights), set(PREDICTION_CLASSES))
        self.assertEqual(set(weights.values()), {1.0})

    def test_safe_biased_weights_only_lifts_safe(self) -> None:
        weights = safe_biased_weights(4.0)
        self.assertEqual(weights["SAFE"], 4.0)
        self.assertEqual(weights["SQLI"], 1.0)
        self.assertEqual(weights["REFLECTED_XSS"], 1.0)
        self.assertEqual(weights["BROKEN_ACCESS_CONTROL"], 1.0)

    def test_safe_biased_weights_rejects_negative(self) -> None:
        with self.assertRaises(RandomPredictorError):
            safe_biased_weights(-1.0)


class RandomPredictorConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        predictor = RandomPredictor(uniform_weights())
        self.assertEqual(predictor.trials, DEFAULT_TRIALS)
        self.assertEqual(predictor.seed, 0)

    def test_rejects_empty_weights(self) -> None:
        with self.assertRaises(RandomPredictorError):
            RandomPredictor({})

    def test_rejects_unknown_class(self) -> None:
        with self.assertRaises(RandomPredictorError):
            RandomPredictor({"LFI": 1.0})

    def test_rejects_negative_weight(self) -> None:
        with self.assertRaises(RandomPredictorError):
            RandomPredictor({"SQLI": -1.0})

    def test_rejects_all_zero_weights(self) -> None:
        with self.assertRaises(RandomPredictorError):
            RandomPredictor({"SQLI": 0.0, "SAFE": 0.0})

    def test_rejects_bad_trials(self) -> None:
        with self.assertRaises(RandomPredictorError):
            RandomPredictor(uniform_weights(), trials=0)

    def test_with_safe_weight_builds_predictor(self) -> None:
        predictor = RandomPredictor.with_safe_weight(3.0, trials=10, seed=2)
        self.assertEqual(predictor.trials, 10)
        self.assertEqual(predictor.seed, 2)


class ForcedGuessMetricTests(unittest.TestCase):
    """A single positive weight forces the guess, so the metric is exact."""

    def test_always_guessing_the_vulnerable_family_is_perfect(self) -> None:
        predictor = RandomPredictor({"SQLI": 1.0}, trials=1)
        report = evaluate_random_predictor(
            _one_point_pool(),
            application_id=APPLICATION,
            predictor=predictor,
            cutoffs=(1, 2),
        )
        self.assertEqual(report.at(1).precision, 1.0)
        self.assertEqual(report.at(1).recall, 1.0)
        self.assertEqual(report.at(1).mean_average_precision, 1.0)

    def test_always_guessing_safe_leaves_a_single_tie(self) -> None:
        # Nothing is boosted: the two candidates tie at score 0, so the expected
        # relevant fraction in the top-1 of that tie is exactly 1/2.
        predictor = RandomPredictor({"SAFE": 1.0}, trials=1)
        report = evaluate_random_predictor(
            _one_point_pool(),
            application_id=APPLICATION,
            predictor=predictor,
            cutoffs=(1, 2),
        )
        self.assertAlmostEqual(report.at(1).precision, 0.5)
        self.assertAlmostEqual(report.at(1).recall, 0.5)
        self.assertAlmostEqual(report.at(2).recall, 1.0)

    def test_always_guessing_a_wrong_family_ranks_the_bug_last(self) -> None:
        predictor = RandomPredictor({"REFLECTED_XSS": 1.0}, trials=1)
        report = evaluate_random_predictor(
            _one_point_pool(),
            application_id=APPLICATION,
            predictor=predictor,
            cutoffs=(1, 2),
        )
        self.assertEqual(report.at(1).precision, 0.0)
        self.assertEqual(report.at(1).recall, 0.0)
        self.assertEqual(report.at(2).recall, 1.0)

    def test_guessing_a_family_with_no_candidate_boosts_nothing(self) -> None:
        # The pool has no BAC candidate, so a forced BAC guess boosts nobody --
        # identical to guessing SAFE.
        predictor = RandomPredictor({"BROKEN_ACCESS_CONTROL": 1.0}, trials=1)
        report = evaluate_random_predictor(
            _one_point_pool(),
            application_id=APPLICATION,
            predictor=predictor,
            cutoffs=(1,),
        )
        self.assertAlmostEqual(report.at(1).precision, 0.5)


class RandomPredictorReportTests(unittest.TestCase):
    def test_report_carries_pool_counts_and_arm_name(self) -> None:
        pool = _one_point_pool() + (
            _scored("safe", family="SQLI", label=None, path="/b", name="r"),
        )
        report = evaluate_random_predictor(
            pool,
            application_id=APPLICATION,
            predictor=RandomPredictor(uniform_weights(), trials=50),
            cutoffs=(1, 3),
        )
        self.assertEqual(report.name, RANDOM_PREDICTOR_ARM)
        self.assertEqual(report.total_candidates, 3)
        self.assertEqual(report.total_relevant, 1)
        self.assertEqual(report.total_unlabeled, 1)
        self.assertEqual({s.k for s in report.summaries}, {1, 3})

    def test_same_seed_is_deterministic(self) -> None:
        pool = _one_point_pool()
        first = evaluate_random_predictor(
            pool,
            application_id=APPLICATION,
            predictor=RandomPredictor(uniform_weights(), trials=200, seed=7),
            cutoffs=(1, 2),
        )
        second = evaluate_random_predictor(
            pool,
            application_id=APPLICATION,
            predictor=RandomPredictor(uniform_weights(), trials=200, seed=7),
            cutoffs=(1, 2),
        )
        self.assertEqual(first.at(1).precision, second.at(1).precision)
        self.assertEqual(
            first.at(2).mean_average_precision,
            second.at(2).mean_average_precision,
        )

    def test_metrics_stay_in_unit_interval(self) -> None:
        report = evaluate_random_predictor(
            _one_point_pool(),
            application_id=APPLICATION,
            predictor=RandomPredictor(safe_biased_weights(4.0), trials=300),
            cutoffs=(1, 2),
        )
        for summary in report.summaries:
            for value in (summary.precision, summary.recall, summary.ndcg):
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 1.0)


class RandomPredictorGuardTests(unittest.TestCase):
    def test_rejects_empty_pool(self) -> None:
        with self.assertRaises(RandomPredictorError):
            evaluate_random_predictor(
                (),
                application_id=APPLICATION,
                predictor=RandomPredictor(uniform_weights()),
                cutoffs=(1,),
            )

    def test_rejects_pool_without_a_vulnerable_label(self) -> None:
        pool = (_scored("safe", family="SQLI", label=False),)
        with self.assertRaises(RandomPredictorError):
            evaluate_random_predictor(
                pool,
                application_id=APPLICATION,
                predictor=RandomPredictor(uniform_weights()),
                cutoffs=(1,),
            )

    def test_rejects_empty_application_id(self) -> None:
        with self.assertRaises(RandomPredictorError):
            evaluate_random_predictor(
                _one_point_pool(),
                application_id="",
                predictor=RandomPredictor(uniform_weights()),
                cutoffs=(1,),
            )


def _eval_args(
    ground_truth: Path | None,
    *,
    random_predictor: bool = False,
    random_safe_weight: float | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        ground_truth=ground_truth,
        eval_output=None,
        eval_cutoffs=None,
        application_id=None,
        random_predictor=random_predictor,
        random_safe_weight=random_safe_weight,
    )


class CliWiringTests(unittest.TestCase):
    def test_flag_builds_a_predictor_on_the_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            truth = Path(tmp) / "truth.json"
            truth.write_text("{}", encoding="utf-8")
            request = _evaluation_request_from_args(
                _eval_args(truth, random_predictor=True),
                other_destinations=(),
            )
            assert request is not None
            self.assertIsInstance(request.random_predictor, RandomPredictor)

    def test_safe_weight_implies_the_predictor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            truth = Path(tmp) / "truth.json"
            truth.write_text("{}", encoding="utf-8")
            request = _evaluation_request_from_args(
                _eval_args(truth, random_safe_weight=4.0),
                other_destinations=(),
            )
            assert request is not None
            self.assertIsInstance(request.random_predictor, RandomPredictor)

    def test_no_flag_leaves_the_predictor_unset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            truth = Path(tmp) / "truth.json"
            truth.write_text("{}", encoding="utf-8")
            request = _evaluation_request_from_args(
                _eval_args(truth),
                other_destinations=(),
            )
            assert request is not None
            self.assertIsNone(request.random_predictor)

    def test_flag_requires_ground_truth(self) -> None:
        with self.assertRaises(CLIError):
            _evaluation_request_from_args(
                _eval_args(None, random_predictor=True),
                other_destinations=(),
            )


if __name__ == "__main__":
    unittest.main()
