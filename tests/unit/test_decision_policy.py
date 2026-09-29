from __future__ import annotations

import unittest

from vulnspider.access.selection import select_top_k_access
from vulnspider.decision.candidate import (
    DecisionCandidate,
    DecisionCandidateError,
    decision_candidate_from_context,
)
from vulnspider.decision.conformal import (
    ConformalCalibrationGroup,
    ConformalCalibrationItem,
    calibrate_conformal_threshold,
)
from vulnspider.decision.policy import (
    DecisionPolicyRunError,
    run_decision_layer,
)
from vulnspider.domain import FeatureObservation, FeatureVector
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)
from vulnspider.scoring import SQLiScorer, XSSScorer
from vulnspider.scoring.calibration import (
    CalibratedScorer,
    heuristic_prior_for_family,
)
from vulnspider.selection import (
    build_mutation_handoff,
    select_combined_top_k,
    select_top_k,
)


def _candidate(
    identifier: str,
    *,
    probability: float,
    family: str = "SQLI",
) -> DecisionCandidate:
    return DecisionCandidate(
        candidate_id=identifier,
        family=family,
        probability=probability,
    )


class TopKArgmaxTests(unittest.TestCase):
    def test_selects_the_k_most_probable(self) -> None:
        pool = (
            _candidate("a", probability=0.2),
            _candidate("b", probability=0.9),
            _candidate("c", probability=0.5),
        )
        outcome = run_decision_layer(pool, top_k=2)
        self.assertEqual(
            [item.candidate_id for item in outcome.selected], ["b", "c"]
        )
        self.assertEqual(outcome.top_k, 2)
        self.assertEqual(outcome.initial_candidates, 3)

    def test_scored_holds_every_candidate_ranked(self) -> None:
        pool = (
            _candidate("a", probability=0.2),
            _candidate("b", probability=0.9),
            _candidate("c", probability=0.5),
        )
        outcome = run_decision_layer(pool, top_k=1)
        self.assertEqual(
            [item.candidate_id for item in outcome.scored], ["b", "c", "a"]
        )
        self.assertEqual(
            [item.candidate_id for item in outcome.deferred], ["c", "a"]
        )

    def test_expected_findings_is_the_sum_of_selected_probabilities(self) -> None:
        pool = (
            _candidate("a", probability=0.9),
            _candidate("b", probability=0.5),
            _candidate("c", probability=0.1),
        )
        outcome = run_decision_layer(pool, top_k=2)
        self.assertAlmostEqual(outcome.expected_findings, 1.4)

    def test_ties_break_by_family_then_candidate_id(self) -> None:
        pool = (
            _candidate("z_xss", probability=0.5, family="REFLECTED_XSS"),
            _candidate("a_sqli", probability=0.5, family="SQLI"),
            _candidate("m_sqli", probability=0.5, family="SQLI"),
        )
        outcome = run_decision_layer(pool, top_k=3)
        # SQLI outranks REFLECTED_XSS on the family tie-break; within SQLI the
        # candidate_id settles it.
        self.assertEqual(
            [item.candidate_id for item in outcome.selected],
            ["a_sqli", "m_sqli", "z_xss"],
        )

    def test_top_k_larger_than_pool_selects_everything(self) -> None:
        pool = (_candidate("a", probability=0.6), _candidate("b", probability=0.3))
        outcome = run_decision_layer(pool, top_k=10)
        self.assertEqual(len(outcome.selected), 2)
        self.assertEqual(outcome.deferred, ())

    def test_top_k_zero_selects_nothing(self) -> None:
        pool = (_candidate("a", probability=0.6),)
        outcome = run_decision_layer(pool, top_k=0)
        self.assertEqual(outcome.selected, ())
        self.assertEqual(len(outcome.deferred), 1)


class ConformalCutTests(unittest.TestCase):
    def _groups(self) -> tuple[ConformalCalibrationGroup, ...]:
        groups = []
        for g in range(12):
            items = tuple(
                ConformalCalibrationItem(
                    candidate_id=f"g{g}c{i}",
                    probability=0.1 + 0.08 * i,
                    label=(i >= 6),
                )
                for i in range(10)
            )
            groups.append(
                ConformalCalibrationGroup(group_id=f"app{g}", items=items)
            )
        return tuple(groups)

    def test_conformal_cut_precedes_top_k(self) -> None:
        threshold = calibrate_conformal_threshold(
            self._groups(), target_risk=0.1
        )
        pool = (
            _candidate("high", probability=0.95),
            _candidate("mid", probability=0.5),
            _candidate("low", probability=0.02),
        )
        outcome = run_decision_layer(pool, top_k=10, conformal=threshold)
        selected = {item.candidate_id for item in outcome.selected}
        # Anything below the calibrated threshold is cut before Top-K, so a very
        # low-probability candidate never enters the selection even with room.
        self.assertNotIn("low", selected)
        self.assertEqual(outcome.conformal_set_size, len(outcome.selected))
        self.assertIs(outcome.conformal, threshold)

    def test_no_conformal_leaves_every_candidate_eligible(self) -> None:
        pool = (_candidate("a", probability=0.01), _candidate("b", probability=0.99))
        outcome = run_decision_layer(pool, top_k=10)
        self.assertEqual(outcome.conformal, None)
        self.assertEqual(outcome.conformal_set_size, 2)
        self.assertEqual(len(outcome.selected), 2)


class ValidationTests(unittest.TestCase):
    def test_duplicate_candidate_ids_are_rejected(self) -> None:
        pool = (_candidate("a", probability=0.5), _candidate("a", probability=0.6))
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer(pool, top_k=1)

    def test_negative_top_k_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer((), top_k=-1)

    def test_non_integer_top_k_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer((), top_k=True)

    def test_non_candidate_pool_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer((object(),), top_k=1)

    def test_bad_conformal_type_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer((), top_k=1, conformal=object())


class SelectionHandoffIntegrationTests(unittest.TestCase):
    """End to end from the real selection handoff into the decision layer."""

    def _feature_vector(self, input_point_id: str, **values: float) -> FeatureVector:
        defaults = {
            STATUS_CODE_CHANGED: 0.0,
            RESPONSE_LENGTH_DIFF_RATIO: 0.0,
            MARKER_REFLECTED: 0.0,
            SQL_ERROR_PATTERN: 0.0,
        }
        defaults.update(values)
        return FeatureVector(
            input_point_id=input_point_id,
            probe_run_ids=("pair_1",),
            features={
                name: FeatureObservation(
                    name=name,
                    value=value,
                    observed=True,
                    source="unit-test",
                    extractor_version="unit-v1",
                )
                for name, value in defaults.items()
            },
            feature_schema_version="feature-v0.1",
        )

    def test_handoff_contexts_become_decision_candidates(self) -> None:
        strong = self._feature_vector(
            "ip_strong",
            **{
                STATUS_CODE_CHANGED: 1.0,
                SQL_ERROR_PATTERN: 1.0,
                RESPONSE_LENGTH_DIFF_RATIO: 0.8,
            },
        )
        weak = self._feature_vector(
            "ip_weak", **{RESPONSE_LENGTH_DIFF_RATIO: 0.1}
        )
        results = [
            SQLiScorer().score(strong),
            XSSScorer().score(strong),
            SQLiScorer().score(weak),
            XSSScorer().score(weak),
        ]
        injection = select_top_k(results, k=4)
        access = select_top_k_access((), k=4)
        combined = select_combined_top_k(injection, access, k=4)
        handoff = build_mutation_handoff(combined, selection_run_id="run_1")

        scorers = {
            family: CalibratedScorer.from_prior(heuristic_prior_for_family(family))
            for family in ("SQLI", "REFLECTED_XSS")
        }
        candidates = []
        for context in handoff.contexts:
            source = strong if "strong" in context.candidate_subject_ref else weak
            candidates.append(
                decision_candidate_from_context(
                    context,
                    scorers[context.family].probability(source.features),
                )
            )

        self.assertEqual(len(candidates), len(handoff.contexts))
        for candidate, context in zip(candidates, handoff.contexts):
            self.assertEqual(candidate.candidate_id, context.candidate_id)
            self.assertEqual(candidate.selection_rank, context.rank)

        outcome = run_decision_layer(tuple(candidates), top_k=2)
        self.assertEqual(len(outcome.selected), 2)
        selected = {item.candidate_id for item in outcome.selected}
        self.assertTrue(
            selected <= {context.candidate_id for context in handoff.contexts}
        )

    def test_family_mismatch_between_score_and_context_is_rejected(self) -> None:
        vector = self._feature_vector("ip_1", **{SQL_ERROR_PATTERN: 1.0})
        injection = select_top_k([SQLiScorer().score(vector)], k=1)
        combined = select_combined_top_k(injection, select_top_k_access((), k=1), k=1)
        handoff = build_mutation_handoff(combined, selection_run_id="run_1")

        xss_probability = CalibratedScorer.from_prior(
            heuristic_prior_for_family("REFLECTED_XSS")
        ).probability(vector.features)
        self.assertEqual(handoff.contexts[0].family, "SQLI")
        with self.assertRaises(DecisionCandidateError):
            decision_candidate_from_context(handoff.contexts[0], xss_probability)


if __name__ == "__main__":
    unittest.main()
