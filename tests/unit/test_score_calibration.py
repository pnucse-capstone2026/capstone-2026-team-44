from __future__ import annotations

import random
import unittest

from vulnspider.domain import FeatureObservation
from vulnspider.features import (
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)
from vulnspider.scoring import SQLiScorer
from vulnspider.scoring.calibration import (
    DEFAULT_BASE_RATE,
    DEFAULT_PRIOR_SCALE,
    FAMILY_SQLI,
    CalibratedScorer,
    CalibrationError,
    CalibrationFeatureSpace,
    LogisticPrior,
    TrainingSample,
    fit_calibrated_scorer,
    fit_naive_bayes_llr,
    heuristic_prior_for_family,
)
from vulnspider.domain import FeatureVector

SQLI_FEATURES = (
    STATUS_CODE_CHANGED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
)


def _observation(name: str, value: float) -> FeatureObservation:
    return FeatureObservation(
        name=name,
        value=value,
        observed=True,
        source="unit-test",
        extractor_version="unit-v1",
    )


def _observations(**values: float) -> dict[str, FeatureObservation]:
    return {name: _observation(name, value) for name, value in values.items()}


def _feature_vector(**values: float) -> FeatureVector:
    return FeatureVector(
        input_point_id="ip_1",
        probe_run_ids=("pair_1",),
        features=_observations(**values),
        feature_schema_version="feature-v0.1",
    )


class HeuristicPriorTests(unittest.TestCase):
    def test_prior_encodes_the_existing_scoring_weights(self) -> None:
        prior = heuristic_prior_for_family(FAMILY_SQLI)
        self.assertEqual(prior.feature_space.feature_names, SQLI_FEATURES)
        self.assertEqual(
            prior.weight_means,
            (
                20.0 / DEFAULT_PRIOR_SCALE,
                20.0 / DEFAULT_PRIOR_SCALE,
                35.0 / DEFAULT_PRIOR_SCALE,
            ),
        )

    def test_unknown_family_is_rejected(self) -> None:
        with self.assertRaises(CalibrationError):
            heuristic_prior_for_family("CSRF")

    def test_prior_rejects_impossible_base_rate(self) -> None:
        with self.assertRaises(CalibrationError):
            heuristic_prior_for_family(FAMILY_SQLI, base_rate=0.0)


class PriorOnlyEquivalenceTests(unittest.TestCase):
    """The zero-data model must not change today's ranking."""

    def test_logit_mean_is_affine_in_the_heuristic_rank_score(self) -> None:
        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        generator = random.Random(20260811)
        for _trial in range(200):
            values = {
                STATUS_CODE_CHANGED: float(generator.randint(0, 1)),
                RESPONSE_LENGTH_DIFF_RATIO: generator.random(),
                SQL_ERROR_PATTERN: float(generator.randint(0, 1)),
            }
            heuristic = SQLiScorer().score(_feature_vector(**values))
            calibrated = scorer.probability(_observations(**values))
            rank_score = heuristic.candidate.rank_score
            self.assertIsNotNone(rank_score)
            expected = scorer.intercept + float(rank_score) / DEFAULT_PRIOR_SCALE
            self.assertAlmostEqual(calibrated.logit_mean, expected, places=9)

    def test_logit_ordering_matches_the_heuristic_ordering(self) -> None:
        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        generator = random.Random(7)
        rows = []
        for _trial in range(60):
            values = {
                STATUS_CODE_CHANGED: float(generator.randint(0, 1)),
                RESPONSE_LENGTH_DIFF_RATIO: generator.random(),
                SQL_ERROR_PATTERN: float(generator.randint(0, 1)),
            }
            heuristic = SQLiScorer().score(_feature_vector(**values))
            calibrated = scorer.probability(_observations(**values))
            rows.append((float(heuristic.candidate.rank_score or 0.0), calibrated))
        by_heuristic = [item[1].logit_mean for item in sorted(rows, key=lambda r: r[0])]
        self.assertEqual(by_heuristic, sorted(by_heuristic))

    def test_zero_data_fit_returns_the_prior_scorer(self) -> None:
        prior = heuristic_prior_for_family(FAMILY_SQLI)
        fitted = fit_calibrated_scorer((), prior)
        self.assertEqual(fitted.training_samples, 0)
        self.assertEqual(fitted.weights, prior.weight_means)


class MissingFeatureTests(unittest.TestCase):
    def test_absent_feature_leaves_the_logit_unchanged(self) -> None:
        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        full = scorer.probability(_observations(**{STATUS_CODE_CHANGED: 1.0}))
        with_absent = scorer.probability(
            {
                STATUS_CODE_CHANGED: _observation(STATUS_CODE_CHANGED, 1.0),
                SQL_ERROR_PATTERN: FeatureObservation.missing(
                    SQL_ERROR_PATTERN,
                    source="sql_error_probe",
                    extractor_version="sql-signal-v1",
                    details={"reason": "execution-error"},
                ),
            }
        )
        self.assertAlmostEqual(full.logit_mean, with_absent.logit_mean, places=12)
        self.assertEqual(with_absent.observed_feature_count, 1)

    def test_unobserved_evidence_carries_no_contribution(self) -> None:
        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        result = scorer.probability(_observations(**{STATUS_CODE_CHANGED: 1.0}))
        missing = [item for item in result.evidence if not item.observed]
        self.assertEqual(len(missing), 2)
        for item in missing:
            self.assertIsNone(item.feature_value)
            self.assertIsNone(item.logit_contribution)

    def test_evidence_is_reported_for_every_feature_in_the_space(self) -> None:
        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        result = scorer.probability(_observations(**{SQL_ERROR_PATTERN: 1.0}))
        self.assertEqual(
            tuple(item.feature_name for item in result.evidence),
            SQLI_FEATURES,
        )

    def test_logit_variance_accumulates_over_active_features(self) -> None:
        """Variance is ``Var(intercept) + Σ f² Var(w)``, so more active
        features means more accumulated weight uncertainty -- not less."""

        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        concentrated = scorer.probability(_observations(**{SQL_ERROR_PATTERN: 1.0}))
        spread = scorer.probability(
            _observations(
                **{
                    STATUS_CODE_CHANGED: 1.0,
                    RESPONSE_LENGTH_DIFF_RATIO: 0.75,
                }
            )
        )
        self.assertAlmostEqual(concentrated.logit_mean, spread.logit_mean, places=9)
        self.assertGreater(spread.logit_variance, concentrated.logit_variance)
        self.assertLess(spread.probability, concentrated.probability)


class RejectionTests(unittest.TestCase):
    def test_out_of_range_feature_value_is_rejected(self) -> None:
        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        with self.assertRaises(CalibrationError):
            scorer.probability(_observations(**{STATUS_CODE_CHANGED: 1.5}))

    def test_mismatched_observation_name_is_rejected(self) -> None:
        scorer = CalibratedScorer.from_prior(heuristic_prior_for_family(FAMILY_SQLI))
        with self.assertRaises(CalibrationError):
            scorer.probability(
                {STATUS_CODE_CHANGED: _observation(SQL_ERROR_PATTERN, 1.0)}
            )

    def test_probability_stays_strictly_inside_the_unit_interval(self) -> None:
        space = CalibrationFeatureSpace(FAMILY_SQLI, (STATUS_CODE_CHANGED,))
        scorer = CalibratedScorer.from_prior(
            LogisticPrior(
                feature_space=space,
                intercept_mean=0.0,
                intercept_stddev=1e-6,
                weight_means=(400.0,),
                weight_stddevs=(1e-6,),
            )
        )
        result = scorer.probability(_observations(**{STATUS_CODE_CHANGED: 1.0}))
        self.assertLess(result.probability, 1.0)
        self.assertGreater(result.probability, 0.0)

    def test_feature_space_rejects_duplicates(self) -> None:
        with self.assertRaises(CalibrationError):
            CalibrationFeatureSpace(FAMILY_SQLI, (STATUS_CODE_CHANGED,) * 2)

    def test_training_sample_rejects_non_numeric_feature(self) -> None:
        with self.assertRaises(CalibrationError):
            TrainingSample(features={STATUS_CODE_CHANGED: True}, label=True)


class FittingTests(unittest.TestCase):
    def _corpus(self, seed: int, size: int) -> list[TrainingSample]:
        generator = random.Random(seed)
        samples: list[TrainingSample] = []
        for index in range(size):
            error = float(generator.random() < 0.35)
            status = float(generator.random() < 0.30)
            length = generator.random()
            # Ground truth depends strongly on the SQL error signal, weakly on
            # status change, and not at all on the length ratio.
            logit = -2.0 + 4.0 * error + 1.0 * status
            probability = 1.0 / (1.0 + pow(2.718281828459045, -logit))
            samples.append(
                TrainingSample(
                    features={
                        STATUS_CODE_CHANGED: status,
                        RESPONSE_LENGTH_DIFF_RATIO: length,
                        SQL_ERROR_PATTERN: error,
                    },
                    label=generator.random() < probability,
                    group=f"app{index % 5}",
                )
            )
        return samples

    def test_fit_recovers_the_dominant_signal(self) -> None:
        prior = heuristic_prior_for_family(FAMILY_SQLI)
        fitted = fit_calibrated_scorer(self._corpus(11, 900), prior)
        weights = dict(zip(prior.feature_space.feature_names, fitted.weights))
        self.assertGreater(weights[SQL_ERROR_PATTERN], weights[STATUS_CODE_CHANGED])
        self.assertGreater(
            weights[STATUS_CODE_CHANGED],
            weights[RESPONSE_LENGTH_DIFF_RATIO],
        )
        self.assertEqual(fitted.training_samples, 900)

    def test_fit_reports_finite_posterior_variances(self) -> None:
        prior = heuristic_prior_for_family(FAMILY_SQLI)
        fitted = fit_calibrated_scorer(self._corpus(3, 300), prior)
        for variance in fitted.weight_variances:
            self.assertGreater(variance, 0.0)
            self.assertLess(variance, prior.weight_stddevs[0] ** 2)

    def test_perfectly_separable_corpus_stays_finite(self) -> None:
        """The prior's precision is the ridge that keeps separation bounded."""

        samples = [
            TrainingSample(features={SQL_ERROR_PATTERN: 1.0}, label=True)
            for _index in range(40)
        ] + [
            TrainingSample(features={SQL_ERROR_PATTERN: 0.0}, label=False)
            for _index in range(40)
        ]
        space = CalibrationFeatureSpace(FAMILY_SQLI, (SQL_ERROR_PATTERN,))
        prior = LogisticPrior(
            feature_space=space,
            intercept_mean=0.0,
            intercept_stddev=1.5,
            weight_means=(3.5,),
            weight_stddevs=(1.5,),
        )
        fitted = fit_calibrated_scorer(samples, prior)
        self.assertLess(abs(fitted.weights[0]), 30.0)
        self.assertGreater(fitted.weights[0], 0.0)

    def test_evidence_shrinks_the_prior_only_as_far_as_it_justifies(self) -> None:
        """The corpus says the length ratio is irrelevant; the prior says it
        is worth 2.0 logits. Four samples must not be enough to overturn
        that, and nine hundred must be."""

        prior = heuristic_prior_for_family(FAMILY_SQLI)
        index = prior.feature_space.index_of(RESPONSE_LENGTH_DIFF_RATIO)
        prior_mean = prior.weight_means[index]

        small = fit_calibrated_scorer(self._corpus(5, 4), prior).weights[index]
        large = fit_calibrated_scorer(self._corpus(5, 900), prior).weights[index]

        self.assertLess(abs(small - prior_mean), abs(large - prior_mean))
        self.assertLess(abs(large), abs(small))

    def test_well_measured_weights_are_damped_less_than_rare_ones(self) -> None:
        """The point of carrying a posterior variance: an equal logit backed
        by a weight the corpus pinned down beats one backed by a guess."""

        space = CalibrationFeatureSpace(
            FAMILY_SQLI,
            (STATUS_CODE_CHANGED, SQL_ERROR_PATTERN),
        )
        prior = LogisticPrior(
            feature_space=space,
            intercept_mean=-1.7,
            intercept_stddev=1.5,
            weight_means=(2.0, 2.0),
            weight_stddevs=(1.5, 1.5),
        )
        generator = random.Random(1)
        samples: list[TrainingSample] = []
        for _index in range(600):
            common = float(generator.random() < 0.5)
            features = {STATUS_CODE_CHANGED: common}
            if generator.random() < 0.05:
                features[SQL_ERROR_PATTERN] = float(generator.random() < 0.5)
            logit = -2.0 + 2.0 * common + 2.0 * features.get(SQL_ERROR_PATTERN, 0.0)
            probability = 1.0 / (1.0 + pow(2.718281828459045, -logit))
            samples.append(
                TrainingSample(
                    features=features,
                    label=generator.random() < probability,
                )
            )
        fitted = fit_calibrated_scorer(samples, prior)
        common_variance, rare_variance = fitted.weight_variances
        self.assertLess(common_variance, rare_variance)

        on_common = fitted.probability(
            _observations(**{STATUS_CODE_CHANGED: 1.0})
        )
        on_rare = fitted.probability(_observations(**{SQL_ERROR_PATTERN: 1.0}))
        self.assertLess(on_rare.logit_mean, on_common.logit_mean + 5.0)
        self.assertLess(on_common.logit_variance, on_rare.logit_variance)


class NaiveBayesTests(unittest.TestCase):
    def test_rates_separate_the_classes(self) -> None:
        samples = [
            TrainingSample(
                features={SQL_ERROR_PATTERN: 1.0, STATUS_CODE_CHANGED: 0.0},
                label=True,
            )
            for _index in range(30)
        ] + [
            TrainingSample(
                features={SQL_ERROR_PATTERN: 0.0, STATUS_CODE_CHANGED: 1.0},
                label=False,
            )
            for _index in range(30)
        ]
        space = CalibrationFeatureSpace(
            FAMILY_SQLI,
            (STATUS_CODE_CHANGED, SQL_ERROR_PATTERN),
        )
        rates = fit_naive_bayes_llr(samples, space)
        positive, negative = rates.rates_for(SQL_ERROR_PATTERN)
        self.assertGreater(positive, negative)
        self.assertGreater(rates.log_likelihood_ratio(SQL_ERROR_PATTERN), 0.0)
        self.assertLess(rates.log_likelihood_ratio(STATUS_CODE_CHANGED), 0.0)

    def test_smoothing_keeps_rates_inside_the_open_interval(self) -> None:
        space = CalibrationFeatureSpace(FAMILY_SQLI, (SQL_ERROR_PATTERN,))
        rates = fit_naive_bayes_llr((), space)
        for value in (*rates.positive_rates, *rates.negative_rates):
            self.assertGreater(value, 0.0)
            self.assertLess(value, 1.0)
        self.assertAlmostEqual(rates.base_rate, 0.5, places=9)

    def test_learned_rates_can_seed_a_logistic_prior(self) -> None:
        samples = [
            TrainingSample(features={SQL_ERROR_PATTERN: 1.0}, label=True)
            for _index in range(20)
        ] + [
            TrainingSample(features={SQL_ERROR_PATTERN: 0.0}, label=False)
            for _index in range(20)
        ]
        space = CalibrationFeatureSpace(FAMILY_SQLI, (SQL_ERROR_PATTERN,))
        prior = fit_naive_bayes_llr(samples, space).as_prior()
        self.assertEqual(prior.feature_space, space)
        self.assertGreater(prior.weight_means[0], 0.0)

    def test_unseen_feature_name_is_rejected(self) -> None:
        space = CalibrationFeatureSpace(FAMILY_SQLI, (SQL_ERROR_PATTERN,))
        rates = fit_naive_bayes_llr((), space)
        with self.assertRaises(CalibrationError):
            rates.rates_for(STATUS_CODE_CHANGED)


class BaseRateTests(unittest.TestCase):
    def test_no_evidence_scores_at_the_base_rate(self) -> None:
        scorer = CalibratedScorer.from_prior(
            heuristic_prior_for_family(FAMILY_SQLI, prior_stddev=1e-9)
        )
        result = scorer.probability({})
        self.assertEqual(result.observed_feature_count, 0)
        self.assertAlmostEqual(result.probability, DEFAULT_BASE_RATE, places=6)


if __name__ == "__main__":
    unittest.main()
