from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vulnspider.corpus.collection import (
    CorpusDataset,
    CorpusError,
    LabeledSample,
    append_corpus,
    collect_labeled_samples,
    ground_truth_key_for,
    read_corpus,
    write_corpus,
)
from vulnspider.corpus.fitting import (
    base_rate_brier_score,
    calibrate_from_corpus,
    candidate_identifier,
    evaluate_calibration,
    fit_family_scorers,
    heuristic_baseline_predictions,
    out_of_fold_calibration_groups,
    out_of_fold_predictions,
    prior_family_scorers,
    sample_observations,
    scorers_as_mapping,
    scorers_from_mapping,
)
from vulnspider.corpus.fitting import CorpusFittingError
from vulnspider.corpus.ground_truth import (
    GroundTruthError,
    GroundTruthKey,
    GroundTruthStore,
    ground_truth_from_entries,
    read_ground_truth,
    write_ground_truth,
)
from vulnspider.domain import (
    Endpoint,
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    InputPoint,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)

SQLI = "SQLI"
XSS = "REFLECTED_XSS"


def _key(
    *,
    application_id: str = "app0",
    path: str = "/product",
    parameter: str = "id",
    vulnerability_type: str = SQLI,
) -> GroundTruthKey:
    return GroundTruthKey(
        application_id=application_id,
        method="GET",
        canonical_path=path,
        parameter_location="QUERY",
        parameter_name=parameter,
        vulnerability_type=vulnerability_type,
    )


def _sample(
    *,
    application_id: str = "app0",
    path: str = "/product",
    parameter: str = "id",
    vulnerability_type: str = SQLI,
    label: bool = True,
    **features: float,
) -> LabeledSample:
    return LabeledSample(
        key=_key(
            application_id=application_id,
            path=path,
            parameter=parameter,
            vulnerability_type=vulnerability_type,
        ),
        features=dict(features),
        label=label,
        group=application_id,
        feature_schema_version="feature-v0.1",
    )


class GroundTruthKeyTests(unittest.TestCase):
    def test_normalization_is_applied(self) -> None:
        key = GroundTruthKey(
            application_id="app0",
            method="get",
            canonical_path="/product",
            parameter_location="query",
            parameter_name="  ID  ",
            vulnerability_type="sqli",
        )
        self.assertEqual(key.method, "GET")
        self.assertEqual(key.parameter_location, "QUERY")
        self.assertEqual(key.parameter_name, "id")
        self.assertEqual(key.vulnerability_type, "SQLI")

    def test_normalized_keys_compare_equal(self) -> None:
        self.assertEqual(
            GroundTruthKey("app0", "get", "/p", "query", "Id", "sqli"),
            GroundTruthKey("app0", "GET", "/p", "QUERY", "id", "SQLI"),
        )

    def test_empty_field_is_rejected(self) -> None:
        with self.assertRaises(GroundTruthError):
            GroundTruthKey("", "GET", "/p", "QUERY", "id", "SQLI")

    def test_missing_field_in_mapping_is_rejected(self) -> None:
        with self.assertRaises(GroundTruthError):
            GroundTruthKey.from_mapping({"application_id": "app0"})


class GroundTruthStoreTests(unittest.TestCase):
    def test_absent_key_is_unlabeled_not_negative(self) -> None:
        """The rule that keeps unlabeled candidates from becoming free
        negatives and inflating precision."""

        store = GroundTruthStore(labels={_key(): True})
        self.assertIs(store.label_for(_key()), True)
        self.assertIsNone(store.label_for(_key(path="/unseen")))

    def test_store_without_negatives_is_rejected(self) -> None:
        store = GroundTruthStore(labels={_key(): True})
        with self.assertRaises(GroundTruthError):
            store.validate_usable()

    def test_store_without_positives_is_rejected(self) -> None:
        store = GroundTruthStore(labels={_key(): False})
        with self.assertRaises(GroundTruthError):
            store.validate_usable()

    def test_balanced_store_is_usable(self) -> None:
        store = ground_truth_from_entries(
            ((_key(), True), (_key(path="/safe"), False))
        )
        store.validate_usable()
        self.assertEqual(store.positives, 1)
        self.assertEqual(store.negatives, 1)

    def test_contradictory_entries_are_rejected(self) -> None:
        with self.assertRaises(GroundTruthError):
            ground_truth_from_entries(((_key(), True), (_key(), False)))

    def test_round_trip_through_json(self) -> None:
        store = ground_truth_from_entries(
            ((_key(), True), (_key(path="/safe"), False))
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gt.json"
            write_ground_truth(store, path)
            self.assertEqual(read_ground_truth(path).labels, store.labels)

    def test_non_boolean_label_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gt.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "ground-truth-v1",
                        "entries": [{**_key().as_mapping(), "vulnerable": 1}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(GroundTruthError):
                read_ground_truth(path)

    def test_unknown_schema_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gt.json"
            path.write_text(
                json.dumps({"schema_version": "v99", "entries": []}),
                encoding="utf-8",
            )
            with self.assertRaises(GroundTruthError):
                read_ground_truth(path)


class CollectionTests(unittest.TestCase):
    def _fixture(self) -> tuple[Endpoint, InputPoint, FeatureVector]:
        endpoint = Endpoint(
            method=HttpMethod.GET,
            scheme="http",
            host="127.0.0.1",
            path="/product",
        )
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="id",
            baseline_value="1",
        )
        vector = FeatureVector(
            input_point_id=input_point.id or "",
            probe_run_ids=("pair_1",),
            features={
                STATUS_CODE_CHANGED: FeatureObservation(
                    name=STATUS_CODE_CHANGED,
                    value=1.0,
                    observed=True,
                    source="unit-test",
                    extractor_version="unit-v1",
                ),
                SQL_ERROR_PATTERN: FeatureObservation.missing(
                    SQL_ERROR_PATTERN,
                    source="sql_error_probe",
                    extractor_version="unit-v1",
                    details={"reason": "execution-error"},
                ),
            },
            feature_schema_version="feature-v0.1",
        )
        return endpoint, input_point, vector

    def test_key_is_built_from_authoritative_objects(self) -> None:
        endpoint, input_point, _vector = self._fixture()
        key = ground_truth_key_for(
            application_id="app0",
            endpoint=endpoint,
            input_point=input_point,
            vulnerability_type=SQLI,
        )
        self.assertEqual(key.canonical_path, "/product")
        self.assertEqual(key.parameter_name, "id")
        self.assertEqual(key.method, "GET")

    def test_only_observed_features_are_collected(self) -> None:
        endpoint, input_point, vector = self._fixture()
        store = ground_truth_from_entries(
            (
                (
                    ground_truth_key_for(
                        application_id="app0",
                        endpoint=endpoint,
                        input_point=input_point,
                        vulnerability_type=SQLI,
                    ),
                    True,
                ),
            )
        )
        result = collect_labeled_samples(
            application_id="app0",
            endpoints=(endpoint,),
            input_points=(input_point,),
            feature_vectors=(vector,),
            scored_candidates=(
                (input_point.id or "", vector.id or "", SQLI),
            ),
            ground_truth=store,
        )
        self.assertEqual(len(result.samples), 1)
        self.assertEqual(
            set(result.samples[0].features), {STATUS_CODE_CHANGED}
        )

    def test_unlabeled_candidates_are_reported_not_defaulted(self) -> None:
        endpoint, input_point, vector = self._fixture()
        result = collect_labeled_samples(
            application_id="app0",
            endpoints=(endpoint,),
            input_points=(input_point,),
            feature_vectors=(vector,),
            scored_candidates=(
                (input_point.id or "", vector.id or "", SQLI),
                (input_point.id or "", vector.id or "", XSS),
            ),
            ground_truth=GroundTruthStore(labels={}),
        )
        self.assertEqual(result.samples, ())
        self.assertEqual(len(result.unlabeled_keys), 2)

    def test_candidate_without_observed_features_is_not_collected(self) -> None:
        endpoint, input_point, _vector = self._fixture()
        empty = FeatureVector(
            input_point_id=input_point.id or "",
            probe_run_ids=("pair_1",),
            features={
                STATUS_CODE_CHANGED: FeatureObservation.missing(
                    STATUS_CODE_CHANGED,
                    source="response_diff",
                    extractor_version="unit-v1",
                    details={"reason": "execution-error"},
                )
            },
            feature_schema_version="feature-v0.1",
        )
        result = collect_labeled_samples(
            application_id="app0",
            endpoints=(endpoint,),
            input_points=(input_point,),
            feature_vectors=(empty,),
            scored_candidates=((input_point.id or "", empty.id or "", SQLI),),
            ground_truth=GroundTruthStore(labels={}),
        )
        self.assertEqual(result.samples, ())
        self.assertEqual(result.unrankable_candidates, 1)
        self.assertEqual(result.unlabeled_keys, ())

    def test_unknown_reference_is_rejected(self) -> None:
        endpoint, input_point, vector = self._fixture()
        with self.assertRaises(CorpusError):
            collect_labeled_samples(
                application_id="app0",
                endpoints=(endpoint,),
                input_points=(input_point,),
                feature_vectors=(vector,),
                scored_candidates=(("ghost", vector.id or "", SQLI),),
                ground_truth=GroundTruthStore(labels={}),
            )


class CorpusFileTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        samples = (
            _sample(**{STATUS_CODE_CHANGED: 1.0}),
            _sample(path="/search", parameter="q", label=False, **{
                MARKER_REFLECTED: 1.0
            }),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.jsonl"
            self.assertEqual(write_corpus(samples, path), 2)
            dataset = read_corpus(path)
        self.assertEqual(len(dataset.samples), 2)
        self.assertEqual(dataset.counts()["positives"], 1)

    def test_write_is_order_independent(self) -> None:
        """Identical content must produce an identical file whatever order
        discovery happened to walk it in."""

        samples = [
            _sample(path=f"/r{index}", parameter=f"p{index}", label=index % 2 == 0)
            for index in range(6)
        ]
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "a.jsonl"
            second = Path(directory) / "b.jsonl"
            write_corpus(samples, first)
            write_corpus(list(reversed(samples)), second)
            self.assertEqual(
                first.read_text(encoding="utf-8"),
                second.read_text(encoding="utf-8"),
            )

    def test_append_adds_without_rewriting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.jsonl"
            write_corpus((_sample(),), path)
            append_corpus((_sample(path="/search", parameter="q"),), path)
            self.assertEqual(len(read_corpus(path).samples), 2)

    def test_empty_corpus_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.jsonl"
            self.assertEqual(write_corpus((), path), 0)
            self.assertEqual(read_corpus(path).samples, ())

    def test_malformed_line_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.jsonl"
            path.write_text("{not json}\n", encoding="utf-8")
            with self.assertRaises(CorpusError):
                read_corpus(path)


class DatasetTests(unittest.TestCase):
    def _dataset(self) -> CorpusDataset:
        return CorpusDataset(
            samples=tuple(
                _sample(
                    application_id=f"app{index % 3}",
                    path=f"/r{index}",
                    parameter=f"p{index}",
                    vulnerability_type=SQLI if index % 2 == 0 else XSS,
                    label=index % 4 == 0,
                    **{STATUS_CODE_CHANGED: float(index % 2)},
                )
                for index in range(12)
            )
        )

    def test_group_and_family_slicing(self) -> None:
        dataset = self._dataset()
        self.assertEqual(dataset.groups, ("app0", "app1", "app2"))
        self.assertEqual(dataset.families, (XSS, SQLI))
        self.assertTrue(
            all(
                sample.family == SQLI
                for sample in dataset.for_family(SQLI).samples
            )
        )

    def test_leave_one_group_out_partitions_by_application(self) -> None:
        dataset = self._dataset()
        folds = dataset.leave_one_group_out()
        self.assertEqual(len(folds), 3)
        for group, train, test in folds:
            self.assertNotIn(group, train.groups)
            self.assertEqual(test.groups, (group,))
            self.assertEqual(
                len(train.samples) + len(test.samples), len(dataset.samples)
            )

    def test_counts_are_consistent(self) -> None:
        counts = self._dataset().counts()
        self.assertEqual(counts["samples"], 12)
        self.assertEqual(counts["positives"] + counts["negatives"], 12)


class FittingTests(unittest.TestCase):
    def _separable_corpus(self) -> CorpusDataset:
        """Quasi-complete separation: no positive ever has the feature at 0."""

        samples: list[LabeledSample] = []
        for app in range(4):
            for index in range(6):
                vulnerable = index < 2
                samples.append(
                    _sample(
                        application_id=f"app{app}",
                        path=f"/r{index}",
                        parameter=f"p{index}",
                        vulnerability_type=SQLI,
                        label=vulnerable,
                        **{
                            SQL_ERROR_PATTERN: 1.0 if vulnerable else 0.0,
                            STATUS_CODE_CHANGED: 1.0 if index < 4 else 0.0,
                            RESPONSE_LENGTH_DIFF_RATIO: 0.5,
                        },
                    )
                )
        return CorpusDataset(samples=tuple(samples))

    def test_separation_does_not_diverge(self) -> None:
        """Regression: undamped Newton runs away here, producing a model whose
        Brier score is worse than a constant."""

        scorers = fit_family_scorers(self._separable_corpus())
        scorer = scorers[SQLI]
        self.assertLess(abs(scorer.intercept), 20.0)
        for weight in scorer.weights:
            self.assertLess(abs(weight), 20.0)
        for variance in scorer.weight_variances:
            self.assertGreater(variance, 0.0)

    def test_fit_beats_the_base_rate_on_separable_data(self) -> None:
        dataset = self._separable_corpus()
        report = evaluate_calibration(out_of_fold_predictions(dataset))
        self.assertLess(report.brier_score, base_rate_brier_score(dataset))

    def test_fit_can_contradict_the_prior(self) -> None:
        """The corpus says status_code_changed is uninformative here even
        though the heuristic assigns it +20."""

        samples: list[LabeledSample] = []
        for app in range(5):
            for index in range(10):
                vulnerable = index < 3
                samples.append(
                    _sample(
                        application_id=f"app{app}",
                        path=f"/r{index}",
                        parameter=f"p{index}",
                        vulnerability_type=SQLI,
                        label=vulnerable,
                        **{
                            SQL_ERROR_PATTERN: 1.0 if vulnerable else 0.0,
                            # Fires on safe candidates more than vulnerable ones.
                            STATUS_CODE_CHANGED: 0.0 if vulnerable else 1.0,
                            RESPONSE_LENGTH_DIFF_RATIO: 0.3,
                        },
                    )
                )
        scorer = fit_family_scorers(CorpusDataset(samples=tuple(samples)))[SQLI]
        weights = dict(
            zip(scorer.feature_space.feature_names, scorer.weights, strict=True)
        )
        self.assertLess(weights[STATUS_CODE_CHANGED], 0.0)
        self.assertGreater(weights[SQL_ERROR_PATTERN], 0.0)

    def test_out_of_fold_model_never_saw_its_own_group(self) -> None:
        dataset = self._separable_corpus()
        predictions = out_of_fold_predictions(dataset)
        self.assertEqual(len(predictions), len(dataset.samples))
        self.assertEqual(
            {prediction.sample.group for prediction in predictions},
            set(dataset.groups),
        )

    def test_out_of_fold_needs_two_applications(self) -> None:
        single = CorpusDataset(
            samples=tuple(
                _sample(path=f"/r{index}", parameter=f"p{index}")
                for index in range(3)
            )
        )
        with self.assertRaises(CorpusFittingError):
            out_of_fold_predictions(single)

    def test_heuristic_baseline_scores_every_sample(self) -> None:
        dataset = self._separable_corpus()
        baseline = heuristic_baseline_predictions(dataset)
        self.assertEqual(len(baseline), len(dataset.samples))

    def test_replayed_sample_keeps_missing_features_missing(self) -> None:
        sample = _sample(**{STATUS_CODE_CHANGED: 1.0})
        observations = sample_observations(sample)
        self.assertEqual(set(observations), {STATUS_CODE_CHANGED})
        scorer = prior_family_scorers((SQLI,))[SQLI]
        self.assertEqual(scorer.probability(observations).observed_feature_count, 1)

    def test_calibration_report_bins_sum_to_the_sample_count(self) -> None:
        report = evaluate_calibration(
            out_of_fold_predictions(self._separable_corpus())
        )
        self.assertEqual(sum(count for _l, _p, _o, count in report.bins), report.samples)
        self.assertGreaterEqual(report.expected_calibration_error, 0.0)

    def test_model_round_trips_through_json(self) -> None:
        scorers = fit_family_scorers(self._separable_corpus())
        payload = json.loads(json.dumps(scorers_as_mapping(scorers)))
        rebuilt = scorers_from_mapping(payload)
        self.assertEqual(set(rebuilt), set(scorers))
        self.assertEqual(rebuilt[SQLI].weights, scorers[SQLI].weights)
        self.assertEqual(
            rebuilt[SQLI].weight_variances, scorers[SQLI].weight_variances
        )

    def test_unknown_model_version_is_rejected(self) -> None:
        with self.assertRaises(CorpusFittingError):
            scorers_from_mapping({"fitting_version": "nope", "models": {}})

    def test_candidate_identifier_is_stable(self) -> None:
        sample = _sample()
        self.assertEqual(candidate_identifier(sample), candidate_identifier(sample))
        self.assertNotEqual(
            candidate_identifier(sample),
            candidate_identifier(_sample(path="/other")),
        )


class ConformalFromCorpusTests(unittest.TestCase):
    def _corpus(self, applications: int) -> CorpusDataset:
        samples: list[LabeledSample] = []
        for app in range(applications):
            for index in range(8):
                vulnerable = index < 2
                samples.append(
                    _sample(
                        application_id=f"app{app:02d}",
                        path=f"/r{index}",
                        parameter=f"p{index}",
                        vulnerability_type=SQLI,
                        label=vulnerable,
                        **{
                            SQL_ERROR_PATTERN: 1.0 if vulnerable else 0.0,
                            STATUS_CODE_CHANGED: 1.0 if index < 5 else 0.0,
                            RESPONSE_LENGTH_DIFF_RATIO: 0.4,
                        },
                    )
                )
        return CorpusDataset(samples=tuple(samples))

    def test_groups_match_the_applications(self) -> None:
        dataset = self._corpus(12)
        groups = out_of_fold_calibration_groups(dataset)
        self.assertEqual(len(groups), 12)
        self.assertEqual(
            tuple(group.group_id for group in groups), dataset.groups
        )

    def test_enough_applications_certifies_the_target(self) -> None:
        threshold = calibrate_from_corpus(self._corpus(12), target_risk=0.1)
        self.assertTrue(threshold.guarantee_attainable)
        self.assertLessEqual(
            threshold.empirical_risk, threshold.corrected_risk_bound + 1e-12
        )

    def test_too_few_applications_cannot_certify(self) -> None:
        threshold = calibrate_from_corpus(self._corpus(4), target_risk=0.1)
        self.assertFalse(threshold.guarantee_attainable)
        self.assertEqual(threshold.threshold, 0.0)


if __name__ == "__main__":
    unittest.main()
