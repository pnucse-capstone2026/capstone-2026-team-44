"""Live-run ranking evaluation: the arms, the join, and the failure modes."""

from __future__ import annotations

import unittest

from vulnspider.corpus.ground_truth import GroundTruthKey, ground_truth_from_entries
from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.domain import Endpoint, HttpMethod, InputLocation, InputPoint
from vulnspider.evaluation.live import (
    ARM_PRIOR,
    ARM_RANDOM,
    ARM_VULNSPIDER,
    LIVE_EVALUATION_VERSION,
    LiveEvaluationError,
    ScoredCandidate,
    build_scored_candidates,
    evaluate_live_run,
    render_live_evaluation_table,
)

APPLICATION = "app"


def _endpoint(path: str) -> Endpoint:
    return Endpoint(
        method=HttpMethod.GET,
        scheme="http",
        host="127.0.0.1:8899",
        path=path,
        id=f"end_{path.strip('/').replace('/', '_') or 'root'}",
    )


def _input_point(endpoint: Endpoint, name: str) -> InputPoint:
    return InputPoint(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        location=InputLocation.QUERY,
        name=name,
        baseline_value="seed",
        id=f"inp_{endpoint.path.strip('/').replace('/', '_')}_{name}",
    )


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
    prior: float,
    final: float | None = None,
    label: bool | None = True,
    path: str = "/a",
    name: str = "q",
    family: str = "SQLI",
) -> ScoredCandidate:
    return ScoredCandidate(
        candidate_id=candidate_id,
        key=_key(path, name, family),
        prior=prior,
        final=prior if final is None else final,
        verified=final is not None,
        label=label,
    )


class BuildScoredCandidatesTests(unittest.TestCase):
    def test_joins_candidates_to_ground_truth_through_discovery_objects(self) -> None:
        endpoint = _endpoint("/search")
        point = _input_point(endpoint, "q")
        candidate = DecisionCandidate(
            candidate_id="cand_1",
            family="SQLI",
            probability=0.4,
            subject_ref=point.id or "",
            feature_vector_ref="fv_1",
        )
        store = ground_truth_from_entries(
            (
                (_key("/search", "q", "SQLI"), True),
                (_key("/search", "q", "REFLECTED_XSS"), False),
            )
        )

        scored = build_scored_candidates(
            (candidate,),
            application_id=APPLICATION,
            ground_truth=store,
            endpoints=(endpoint,),
            input_points=(point,),
            final_confidence={"cand_1": 0.9},
        )

        self.assertEqual(len(scored), 1)
        self.assertTrue(scored[0].label)
        self.assertEqual(scored[0].prior, 0.4)
        self.assertEqual(scored[0].final, 0.9)
        self.assertTrue(scored[0].verified)

    def test_unverified_candidate_keeps_its_prior_as_the_final_score(self) -> None:
        endpoint = _endpoint("/search")
        point = _input_point(endpoint, "q")
        candidate = DecisionCandidate(
            candidate_id="cand_1",
            family="SQLI",
            probability=0.4,
            subject_ref=point.id or "",
        )
        store = ground_truth_from_entries(
            ((_key("/search", "q", "SQLI"), True), (_key("/x", "y", "SQLI"), False))
        )

        scored = build_scored_candidates(
            (candidate,),
            application_id=APPLICATION,
            ground_truth=store,
            endpoints=(endpoint,),
            input_points=(point,),
        )

        self.assertEqual(scored[0].final, scored[0].prior)
        self.assertFalse(scored[0].verified)

    def test_candidate_outside_ground_truth_is_unlabeled_not_negative(self) -> None:
        endpoint = _endpoint("/search")
        point = _input_point(endpoint, "unlisted")
        candidate = DecisionCandidate(
            candidate_id="cand_1",
            family="SQLI",
            probability=0.4,
            subject_ref=point.id or "",
        )
        store = ground_truth_from_entries(
            ((_key("/search", "q", "SQLI"), True), (_key("/x", "y", "SQLI"), False))
        )

        scored = build_scored_candidates(
            (candidate,),
            application_id=APPLICATION,
            ground_truth=store,
            endpoints=(endpoint,),
            input_points=(point,),
        )

        self.assertIsNone(scored[0].label)

    def test_access_candidate_resolves_through_its_probe_plan(self) -> None:
        endpoint = _endpoint("/admin/users")
        point = _input_point(endpoint, "id")
        candidate = DecisionCandidate(
            candidate_id="cand_bac",
            family="BROKEN_ACCESS_CONTROL",
            probability=0.6,
            subject_ref="plan_1",
        )
        store = ground_truth_from_entries(
            (
                (_key("/admin/users", "id", "BROKEN_ACCESS_CONTROL"), True),
                (_key("/admin/users", "id", "SQLI"), False),
            )
        )

        scored = build_scored_candidates(
            (candidate,),
            application_id=APPLICATION,
            ground_truth=store,
            endpoints=(endpoint,),
            input_points=(point,),
            access_input_points={"cand_bac": point.id or ""},
        )

        self.assertTrue(scored[0].label)

    def test_endpoint_level_access_candidate_is_skipped_not_errored(self) -> None:
        # A CREDENTIAL_STRIP access candidate carries no InputPoint (it is
        # endpoint-level), so it has no parameter-keyed ground truth. It must be
        # dropped from the evaluation rather than crashing it.
        endpoint = _endpoint("/admin/users")
        point = _input_point(endpoint, "id")
        idor = DecisionCandidate(
            candidate_id="cand_idor",
            family="BROKEN_ACCESS_CONTROL",
            probability=0.9,
            subject_ref="plan_idor",
        )
        strip = DecisionCandidate(
            candidate_id="cand_strip",
            family="BROKEN_ACCESS_CONTROL",
            probability=0.8,
            subject_ref="plan_strip",
        )
        store = ground_truth_from_entries(
            (
                (_key("/admin/users", "id", "BROKEN_ACCESS_CONTROL"), True),
                (_key("/admin/users", "id", "SQLI"), False),
            )
        )

        scored = build_scored_candidates(
            (idor, strip),
            application_id=APPLICATION,
            ground_truth=store,
            endpoints=(endpoint,),
            input_points=(point,),
            access_input_points={
                "cand_idor": point.id or "",
                "cand_strip": "",  # credential strip: no input point
            },
        )

        self.assertEqual([item.candidate_id for item in scored], ["cand_idor"])

    def test_unknown_input_point_is_an_error_not_a_silent_drop(self) -> None:
        endpoint = _endpoint("/search")
        point = _input_point(endpoint, "q")
        candidate = DecisionCandidate(
            candidate_id="cand_1",
            family="SQLI",
            probability=0.4,
            subject_ref="inp_missing",
        )
        store = ground_truth_from_entries(
            ((_key("/search", "q", "SQLI"), True), (_key("/x", "y", "SQLI"), False))
        )

        with self.assertRaises(LiveEvaluationError):
            build_scored_candidates(
                (candidate,),
                application_id=APPLICATION,
                ground_truth=store,
                endpoints=(endpoint,),
                input_points=(point,),
            )


class EvaluateLiveRunTests(unittest.TestCase):
    def _report(self, pool: tuple[ScoredCandidate, ...], cutoffs=(1, 2, 4)):
        return evaluate_live_run(
            pool,
            application_id=APPLICATION,
            target="http://127.0.0.1:8899/",
            top_k=2,
            cutoffs=cutoffs,
        )

    def test_random_arm_precision_is_the_prevalence(self) -> None:
        pool = (
            _scored("a", prior=0.9, label=True, name="a"),
            _scored("b", prior=0.8, label=False, name="b"),
            _scored("c", prior=0.7, label=False, name="c"),
            _scored("d", prior=0.6, label=False, name="d"),
        )

        report = self._report(pool)

        random_arm = report.arm(ARM_RANDOM)
        for k in (1, 2, 4):
            self.assertAlmostEqual(random_arm.at(k).precision, 0.25)

    def test_verification_reordering_shows_up_in_the_full_arm(self) -> None:
        # The prior puts a safe candidate first; verification demotes it and
        # promotes the vulnerable one, which is exactly the contribution the
        # ablation arm is there to isolate.
        pool = (
            _scored("safe", prior=0.9, final=0.2, label=False, name="safe"),
            _scored("vuln", prior=0.8, final=0.95, label=True, name="vuln"),
        )

        report = self._report(pool, cutoffs=(1, 2))

        self.assertAlmostEqual(report.arm(ARM_PRIOR).at(1).precision, 0.0)
        self.assertAlmostEqual(report.arm(ARM_VULNSPIDER).at(1).precision, 1.0)
        # Same set at K = 2, so only the order-sensitive metric separates them.
        self.assertAlmostEqual(report.arm(ARM_PRIOR).at(2).precision, 0.5)
        self.assertAlmostEqual(report.arm(ARM_VULNSPIDER).at(2).precision, 0.5)
        self.assertLess(
            report.arm(ARM_PRIOR).at(2).mean_average_precision,
            report.arm(ARM_VULNSPIDER).at(2).mean_average_precision,
        )

    def test_report_counts_and_serialization(self) -> None:
        pool = (
            _scored("a", prior=0.9, final=0.95, label=True, name="a"),
            _scored("b", prior=0.8, label=False, name="b"),
            _scored("c", prior=0.7, label=None, name="c"),
        )

        payload = self._report(pool, cutoffs=(1, 3)).as_mapping()

        self.assertEqual(payload["report_version"], LIVE_EVALUATION_VERSION)
        self.assertEqual(
            payload["counts"],
            {"candidates": 3, "relevant": 1, "unlabeled": 1, "verified": 1},
        )
        self.assertEqual(len(payload["arms"]), 3)
        self.assertEqual(payload["candidates"][0]["candidate_id"], "a")

    def test_a_pool_with_no_vulnerable_candidate_is_rejected(self) -> None:
        pool = (_scored("a", prior=0.9, label=False),)

        with self.assertRaises(LiveEvaluationError):
            self._report(pool)

    def test_an_empty_pool_is_rejected(self) -> None:
        with self.assertRaises(LiveEvaluationError):
            self._report(())

    def test_table_names_every_arm(self) -> None:
        pool = (
            _scored("a", prior=0.9, label=True, name="a"),
            _scored("b", prior=0.8, label=False, name="b"),
        )

        text = render_live_evaluation_table(self._report(pool, cutoffs=(1,)))

        for arm in (ARM_RANDOM, ARM_PRIOR, ARM_VULNSPIDER):
            self.assertIn(arm, text)
        self.assertIn("Precision@K", text)
        self.assertIn("MAP@K", text)


if __name__ == "__main__":
    unittest.main()
