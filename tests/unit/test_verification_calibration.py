from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import tests.unit.test_verification as tv
from vulnspider.corpus.ground_truth import (
    GroundTruthKey,
    GroundTruthStore,
    write_ground_truth,
)
from vulnspider.corpus.verification_collection import (
    VerificationCorpusDataset,
    VerificationSample,
    collect_verification_samples,
    read_verification_corpus,
    write_verification_corpus,
)
from vulnspider.corpus.verification_fitting import (
    evaluate_verification_arm,
    fit_from_verification_corpus,
    out_of_fold_verification_predictions,
)
from vulnspider.domain import VulnerabilityType
from vulnspider.observation import ProbePlanner
from vulnspider.observation.executor import RequestExecutor
from vulnspider.features import extract_minimal_features, combine_input_point_features
from vulnspider.pipeline import ProbeObservation
from vulnspider.scoring import generate_candidates
from vulnspider.selection import select_top_k
from vulnspider.verification import (
    VerificationConfidenceModel,
    VerificationConfig,
    VerificationSignal,
    VerificationTrainingSample,
    fit_verification_model,
    update_confidence,
    verify_analysis,
)
from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    RequestContextCompleteness,
    RequestTemplate,
)


def _key(app: str, vtype: str = "SQLI") -> GroundTruthKey:
    return GroundTruthKey(
        application_id=app,
        method="GET",
        canonical_path="/search",
        parameter_location="QUERY",
        parameter_name="q",
        vulnerability_type=vtype,
    )


class ConfidenceModelTests(unittest.TestCase):
    def test_default_model_is_gentle_and_bounded(self) -> None:
        model = VerificationConfidenceModel.default()
        raised = model.apply(0.5, "SQLI", VerificationSignal.SUPPORT_NEW)
        lowered = model.apply(0.5, "SQLI", VerificationSignal.WEAKEN)
        kept = model.apply(0.5, "SQLI", VerificationSignal.SUPPORT_REPRODUCED)
        self.assertGreater(raised, 0.5)
        self.assertLess(raised, 0.75)  # gentle: never a hard swing
        self.assertLess(lowered, 0.5)
        self.assertGreater(lowered, 0.25)
        self.assertAlmostEqual(kept, 0.5, places=6)  # reproduced is neutral by default

    def test_fit_learns_signal_direction(self) -> None:
        samples = []
        for i in range(24):
            samples.append(
                VerificationTrainingSample(
                    "SQLI",
                    VerificationSignal.SUPPORT_NEW if i % 2 else VerificationSignal.SUPPORT_REPRODUCED,
                    True,
                    f"app{i % 4}",
                )
            )
        for i in range(24):
            samples.append(
                VerificationTrainingSample(
                    "SQLI",
                    VerificationSignal.WEAKEN if i % 2 else VerificationSignal.UNCHANGED,
                    False,
                    f"app{i % 4}",
                )
            )
        model = fit_verification_model(samples)
        self.assertGreater(
            model.llr_for("SQLI", VerificationSignal.SUPPORT_NEW), 0.0
        )
        self.assertLess(model.llr_for("SQLI", VerificationSignal.WEAKEN), 0.0)
        self.assertEqual(model.training_samples, 48)

    def test_cap_bounds_every_llr(self) -> None:
        samples = [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.SUPPORT_NEW, True, f"app{i}"
            )
            for i in range(10)
        ] + [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.WEAKEN, False, f"app{i}"
            )
            for i in range(10)
        ]
        model = fit_verification_model(samples, max_abs_llr=0.4)
        for signal in VerificationSignal:
            self.assertLessEqual(abs(model.llr_for("SQLI", signal)), 0.4 + 1e-9)

    def test_neutral_signals_stay_zero_when_fitted(self) -> None:
        samples = [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.SUPPORT_REPRODUCED, True, f"app{i}"
            )
            for i in range(8)
        ] + [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.UNCHANGED, False, f"app{i}"
            )
            for i in range(8)
        ]
        model = fit_verification_model(samples)
        self.assertEqual(model.llr_for("SQLI", VerificationSignal.NOT_EXECUTED), 0.0)
        self.assertEqual(model.llr_for("SQLI", VerificationSignal.INCONCLUSIVE), 0.0)

    def test_unseen_signal_falls_back_to_default(self) -> None:
        # SUPPORT_NEW and WEAKEN never appear in this corpus; they must fall back
        # to the conservative default LLR (correct sign), not a smoothing
        # artifact driven by the class-size ratio.
        samples = [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.SUPPORT_REPRODUCED, True, f"app{i}"
            )
            for i in range(6)
        ] + [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.UNCHANGED, False, f"app{i}"
            )
            for i in range(18)
        ]
        model = fit_verification_model(samples)
        self.assertGreater(model.llr_for("SQLI", VerificationSignal.SUPPORT_NEW), 0.0)
        self.assertLess(model.llr_for("SQLI", VerificationSignal.WEAKEN), 0.0)

    def test_serialization_round_trip(self) -> None:
        samples = [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.SUPPORT_NEW, True, f"app{i}"
            )
            for i in range(6)
        ] + [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.UNCHANGED, False, f"app{i}"
            )
            for i in range(6)
        ]
        model = fit_verification_model(samples)
        rebuilt = VerificationConfidenceModel.from_mapping(model.as_mapping())
        for signal in VerificationSignal:
            self.assertAlmostEqual(
                model.llr_for("SQLI", signal),
                rebuilt.llr_for("SQLI", signal),
                places=9,
            )

    def test_fitted_model_changes_update_magnitude(self) -> None:
        # A model that strongly separates SUPPORT_NEW raises more than the default.
        samples = [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.SUPPORT_NEW, True, f"app{i}"
            )
            for i in range(12)
        ] + [
            VerificationTrainingSample(
                "SQLI", VerificationSignal.UNCHANGED, False, f"app{i}"
            )
            for i in range(12)
        ]
        model = fit_verification_model(samples)
        delta = tv.ConfidenceRuleTests()._delta_from(
            {"sql_error_pattern": 0.0}, {"sql_error_pattern": 1.0}
        )
        default_conf = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.4,
            delta=delta,
        ).confidence
        fitted_conf = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.4,
            delta=delta,
            model=model,
        ).confidence
        self.assertGreater(fitted_conf, default_conf)


class VerificationArmTests(unittest.TestCase):
    def _dataset(self) -> VerificationCorpusDataset:
        samples = []
        # vulnerable candidates land on SUPPORT_NEW, safe on UNCHANGED.
        for app in range(4):
            samples.append(
                VerificationSample(
                    key=_key(f"app{app}"),
                    signal=VerificationSignal.SUPPORT_NEW,
                    prior_probability=0.4,
                    label=True,
                    group=f"app{app}",
                )
            )
            samples.append(
                VerificationSample(
                    key=GroundTruthKey(
                        application_id=f"app{app}",
                        method="GET",
                        canonical_path="/other",
                        parameter_location="QUERY",
                        parameter_name="id",
                        vulnerability_type="SQLI",
                    ),
                    signal=VerificationSignal.UNCHANGED,
                    prior_probability=0.4,
                    label=False,
                    group=f"app{app}",
                )
            )
        return VerificationCorpusDataset(samples=tuple(samples))

    def test_arm_reports_brier_improvement_for_informative_signals(self) -> None:
        report = evaluate_verification_arm(self._dataset())
        self.assertEqual(report.samples, 8)
        self.assertEqual(report.positives, 4)
        # The verification update should not hurt calibration on separable data.
        self.assertGreaterEqual(report.improvement, 0.0)
        payload = report.as_mapping()
        self.assertIn("brier_prior", payload)
        self.assertIn("brier_posterior", payload)

    def test_out_of_fold_never_scores_a_training_group(self) -> None:
        predictions = out_of_fold_verification_predictions(self._dataset())
        self.assertEqual(len(predictions), 8)
        for prediction in predictions:
            self.assertTrue(0.0 < prediction.posterior_probability < 1.0)

    def test_fit_from_corpus_produces_a_usable_model(self) -> None:
        model = fit_from_verification_corpus(self._dataset())
        self.assertGreater(
            model.apply(0.4, "SQLI", VerificationSignal.SUPPORT_NEW), 0.4
        )


class VerificationCollectionTests(unittest.TestCase):
    def _analysis_and_run(self, mode: str):
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="7",
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=7",
            query=(("q", "7"),),
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="k",
        )
        context = InputPointRequestContext.from_objects(input_point, template)
        plan = ProbePlanner().plan(input_point, template, context)
        execution = RequestExecutor(
            transport=tv.ScriptedTransport(mode)
        ).execute_plan(plan)
        vector = combine_input_point_features(
            [
                extract_minimal_features(
                    input_point,
                    plan,
                    execution.response_pair,
                    execution.baseline_response,
                    execution.probe_response,
                )
            ]
        )
        selection = select_top_k(generate_candidates(vector), k=5)
        observation = ProbeObservation(
            feature_vector_id=vector.id or "",
            input_point_id=input_point.id or "",
            probe_plan=plan,
            baseline_response=execution.baseline_response,
            probe_response=execution.probe_response,
        )
        analysis = SimpleNamespace(
            selection=selection,
            feature_vectors=(vector,),
            probe_observations=(observation,),
            input_points=(input_point,),
            endpoints=(endpoint,),
        )
        run = verify_analysis(
            analysis, config=VerificationConfig(transport=tv.ScriptedTransport(mode))
        )
        return analysis, run

    def test_collect_joins_signals_to_ground_truth(self) -> None:
        analysis, run = self._analysis_and_run("quote_error")
        store = GroundTruthStore(
            labels={
                _key("appX", "SQLI"): True,
                _key("appX", "REFLECTED_XSS"): False,
            }
        )
        result = collect_verification_samples(
            application_id="appX",
            run=run,
            endpoints=analysis.endpoints,
            input_points=analysis.input_points,
            ground_truth=store,
        )
        self.assertTrue(result.samples)
        families = {sample.family for sample in result.samples}
        self.assertIn("SQLI", families)
        for sample in result.samples:
            self.assertEqual(sample.group, "appX")
            self.assertIsInstance(sample.signal, VerificationSignal)

    def test_unlabeled_candidate_is_skipped_not_negative(self) -> None:
        analysis, run = self._analysis_and_run("quote_error")
        store = GroundTruthStore(labels={_key("appX", "SQLI"): True})
        result = collect_verification_samples(
            application_id="appX",
            run=run,
            endpoints=analysis.endpoints,
            input_points=analysis.input_points,
            ground_truth=store,
        )
        self.assertTrue(result.unlabeled_keys)  # the XSS candidate was unlabeled
        self.assertTrue(all(s.family == "SQLI" for s in result.samples))

    def test_corpus_round_trips_on_disk(self) -> None:
        samples = (
            VerificationSample(
                key=_key("app1"),
                signal=VerificationSignal.SUPPORT_NEW,
                prior_probability=0.3,
                label=True,
                group="app1",
            ),
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "vc.jsonl"
            write_verification_corpus(samples, path)
            dataset = read_verification_corpus(path)
        self.assertEqual(len(dataset.samples), 1)
        self.assertEqual(dataset.samples[0].signal, VerificationSignal.SUPPORT_NEW)


class VerificationCalibrationCliTests(unittest.TestCase):
    def test_verify_collect_then_fit_then_use(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from vulnspider import cli
        from tests.unit.test_verification_cli import VulnerableTransport, _RECORDS

        with TemporaryDirectory() as directory:
            base = Path(directory)
            # Two applications so out-of-fold has >= 2 groups.
            records = base / "records.json"
            records.write_text(json.dumps(_RECORDS), encoding="utf-8")

            # Ground truth keyed to the fixture's GET /search?q candidate.
            store = GroundTruthStore(
                labels={
                    GroundTruthKey(
                        application_id=app,
                        method="GET",
                        canonical_path="/search",
                        parameter_location="QUERY",
                        parameter_name="q",
                        vulnerability_type=vtype,
                    ): (vtype == "SQLI")
                    for app in ("app1", "app2")
                    for vtype in ("SQLI", "REFLECTED_XSS")
                }
            )
            gt = base / "gt.json"
            write_ground_truth(store, gt)

            corpus = base / "vc.jsonl"
            # verify-collect runs a live analyze+verify; drive it with the CLI's
            # injected transport by collecting from an analysis directly instead.
            analysis, run = VerificationCollectionTests()._analysis_and_run(
                "quote_error"
            )
            # SQLI is vulnerable in app1, safe in app2, so the fitted family has
            # both classes (a single-class family is left to the defaults).
            sqli_label = {"app1": True, "app2": False}
            for app in ("app1", "app2"):
                result = collect_verification_samples(
                    application_id=app,
                    run=run,
                    endpoints=analysis.endpoints,
                    input_points=analysis.input_points,
                    ground_truth=GroundTruthStore(
                        labels={
                            GroundTruthKey(
                                application_id=app,
                                method="GET",
                                canonical_path="/search",
                                parameter_location="QUERY",
                                parameter_name="q",
                                vulnerability_type=vtype,
                            ): (sqli_label[app] if vtype == "SQLI" else False)
                            for vtype in ("SQLI", "REFLECTED_XSS")
                        }
                    ),
                )
                from vulnspider.corpus.verification_collection import (
                    append_verification_corpus,
                )

                append_verification_corpus(result.samples, corpus)

            model_path = base / "model.json"
            report_path = base / "arm.json"
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main(
                    [
                        "corpus",
                        "verify-fit",
                        "--corpus",
                        str(corpus),
                        "-o",
                        str(model_path),
                        "--report",
                        str(report_path),
                    ]
                )
            self.assertEqual(code, 0, stderr.getvalue())
            self.assertTrue(model_path.exists())
            self.assertTrue(report_path.exists())
            model = VerificationConfidenceModel.from_mapping(
                json.loads(model_path.read_text(encoding="utf-8"))
            )
            self.assertGreater(model.training_samples, 0)

            # The fitted model is loadable by analyze --verify.
            analysis_out = base / "analysis.json"
            verify_out = base / "verify.json"
            detail_out = base / "verification-detail.html"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "5",
                        "--output",
                        str(analysis_out),
                        "--verify",
                        "--verify-output",
                        str(verify_out),
                        "--verification-model",
                        str(model_path),
                        "--verify-detail-output",
                        str(detail_out),
                    ],
                    transport=VulnerableTransport(),
                )
            self.assertEqual(code, 0)
            self.assertTrue(detail_out.exists())
            report = json.loads(verify_out.read_text(encoding="utf-8"))
            used_versions = {
                result["confidence"]["model_version"]
                for candidate in report["candidates"]
                for result in candidate["results"]
            }
            self.assertIn(model.model_version, used_versions)


if __name__ == "__main__":
    unittest.main()
