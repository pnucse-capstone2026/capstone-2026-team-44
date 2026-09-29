from __future__ import annotations

import random
import unittest

from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.conformal import (
    ConformalCalibrationGroup,
    ConformalCalibrationItem,
    ConformalError,
    calibrate_conformal_threshold,
    minimum_groups_for_target,
    select_by_threshold,
)


def _group(
    group_id: str,
    items: tuple[tuple[float, bool], ...],
) -> ConformalCalibrationGroup:
    return ConformalCalibrationGroup(
        group_id=group_id,
        items=tuple(
            ConformalCalibrationItem(
                candidate_id=f"{group_id}_{index}",
                probability=probability,
                label=label,
            )
            for index, (probability, label) in enumerate(items)
        ),
    )


def _synthetic_groups(
    count: int,
    *,
    seed: int,
    positives_per_group: int = 3,
    negatives_per_group: int = 12,
) -> tuple[ConformalCalibrationGroup, ...]:
    """Positives score higher than negatives, but the two ranges overlap."""

    generator = random.Random(seed)
    groups: list[ConformalCalibrationGroup] = []
    for index in range(count):
        items: list[tuple[float, bool]] = []
        for _positive in range(positives_per_group):
            items.append((generator.uniform(0.35, 0.98), True))
        for _negative in range(negatives_per_group):
            items.append((generator.uniform(0.02, 0.60), False))
        groups.append(_group(f"app{index}", tuple(items)))
    return tuple(groups)


class GroupRiskTests(unittest.TestCase):
    def test_risk_is_one_minus_recall(self) -> None:
        group = _group("a", ((0.9, True), (0.4, True), (0.8, False)))
        self.assertAlmostEqual(group.risk_at(0.5), 0.5)
        self.assertAlmostEqual(group.risk_at(0.0), 0.0)
        self.assertAlmostEqual(group.risk_at(0.95), 1.0)

    def test_group_without_positives_carries_no_risk(self) -> None:
        group = _group("a", ((0.9, False), (0.4, False)))
        self.assertEqual(group.risk_at(0.99), 0.0)
        self.assertEqual(group.positives, 0)

    def test_risk_is_monotone_in_the_threshold(self) -> None:
        group = _group(
            "a", ((0.9, True), (0.7, True), (0.5, True), (0.3, True))
        )
        risks = [group.risk_at(step / 10.0) for step in range(11)]
        self.assertEqual(risks, sorted(risks))

    def test_duplicate_candidate_ids_are_rejected(self) -> None:
        with self.assertRaises(ConformalError):
            ConformalCalibrationGroup(
                group_id="a",
                items=(
                    ConformalCalibrationItem("same", 0.5, True),
                    ConformalCalibrationItem("same", 0.6, False),
                ),
            )


class AttainabilityTests(unittest.TestCase):
    def test_minimum_groups_matches_the_stated_bound(self) -> None:
        self.assertEqual(minimum_groups_for_target(0.1), 9)
        self.assertEqual(minimum_groups_for_target(0.2), 4)
        self.assertEqual(minimum_groups_for_target(0.5), 1)

    def test_too_few_groups_cannot_certify_the_target(self) -> None:
        groups = _synthetic_groups(4, seed=1)
        threshold = calibrate_conformal_threshold(groups, target_risk=0.1)
        self.assertFalse(threshold.guarantee_attainable)
        self.assertEqual(threshold.threshold, 0.0)

    def test_enough_groups_can_certify_the_target(self) -> None:
        groups = _synthetic_groups(20, seed=2)
        threshold = calibrate_conformal_threshold(groups, target_risk=0.1)
        self.assertTrue(threshold.guarantee_attainable)
        self.assertLessEqual(
            threshold.empirical_risk, threshold.corrected_risk_bound + 1e-12
        )

    def test_uncertifiable_target_still_returns_a_usable_threshold(self) -> None:
        """Falling back to "select everything" is the only honest answer when
        the corpus cannot support the target."""

        groups = _synthetic_groups(3, seed=3)
        threshold = calibrate_conformal_threshold(groups, target_risk=0.05)
        self.assertEqual(threshold.threshold, 0.0)
        self.assertFalse(threshold.guarantee_attainable)


class ThresholdTests(unittest.TestCase):
    def test_threshold_is_the_largest_that_meets_the_bound(self) -> None:
        groups = _synthetic_groups(30, seed=5)
        threshold = calibrate_conformal_threshold(groups, target_risk=0.2)
        self.assertGreater(threshold.threshold, 0.0)

        higher = min(
            (
                float(item.probability)
                for group in groups
                for item in group.items
                if float(item.probability) > threshold.threshold
            ),
            default=None,
        )
        if higher is not None:
            risk_above = sum(group.risk_at(higher) for group in groups) / len(groups)
            self.assertGreater(risk_above, threshold.corrected_risk_bound)

    def test_a_looser_target_permits_a_higher_cut(self) -> None:
        groups = _synthetic_groups(30, seed=6)
        strict = calibrate_conformal_threshold(groups, target_risk=0.05)
        loose = calibrate_conformal_threshold(groups, target_risk=0.4)
        self.assertGreaterEqual(loose.threshold, strict.threshold)

    def test_corrected_bound_is_stricter_than_the_target(self) -> None:
        groups = _synthetic_groups(10, seed=7)
        threshold = calibrate_conformal_threshold(groups, target_risk=0.25)
        self.assertLess(threshold.corrected_risk_bound, 0.25)


class CoverageTests(unittest.TestCase):
    def test_held_out_risk_respects_the_target_on_average(self) -> None:
        """The guarantee is about a fresh group, so calibrate and test on
        disjoint groups and check realised risk against the target."""

        target = 0.2
        violations: list[float] = []
        for seed in range(30):
            groups = _synthetic_groups(21, seed=100 + seed)
            calibration, held_out = groups[:20], groups[20]
            threshold = calibrate_conformal_threshold(
                calibration, target_risk=target
            )
            self.assertTrue(threshold.guarantee_attainable)
            violations.append(held_out.risk_at(threshold.threshold))
        self.assertLessEqual(sum(violations) / len(violations), target)

    def test_a_stricter_target_selects_at_least_as_many(self) -> None:
        groups = _synthetic_groups(30, seed=11)
        candidates = tuple(
            DecisionCandidate(
                candidate_id=f"c{index}",
                family="SQLI",
                probability=0.05 + index * 0.03,
            )
            for index in range(30)
        )
        strict = calibrate_conformal_threshold(groups, target_risk=0.05)
        loose = calibrate_conformal_threshold(groups, target_risk=0.4)
        self.assertGreaterEqual(
            len(select_by_threshold(candidates, strict.threshold)),
            len(select_by_threshold(candidates, loose.threshold)),
        )


class SelectionTests(unittest.TestCase):
    def _candidates(self) -> tuple[DecisionCandidate, ...]:
        return tuple(
            DecisionCandidate(
                candidate_id=f"c{index}",
                family="SQLI",
                probability=probability,
            )
            for index, probability in enumerate((0.9, 0.5, 0.2))
        )

    def test_selection_keeps_candidates_at_or_above_the_threshold(self) -> None:
        selected = select_by_threshold(self._candidates(), 0.5)
        self.assertEqual([item.candidate_id for item in selected], ["c0", "c1"])

    def test_selection_is_ordered_by_probability(self) -> None:
        selected = select_by_threshold(self._candidates(), 0.0)
        probabilities = [float(item.probability) for item in selected]
        self.assertEqual(probabilities, sorted(probabilities, reverse=True))

    def test_out_of_range_threshold_is_rejected(self) -> None:
        with self.assertRaises(ConformalError):
            select_by_threshold(self._candidates(), 1.5)


class ValidationTests(unittest.TestCase):
    def test_empty_calibration_is_rejected(self) -> None:
        with self.assertRaises(ConformalError):
            calibrate_conformal_threshold(())

    def test_duplicate_group_ids_are_rejected(self) -> None:
        group = _group("a", ((0.9, True),))
        with self.assertRaises(ConformalError):
            calibrate_conformal_threshold((group, group), target_risk=0.5)

    def test_target_risk_outside_the_open_interval_is_rejected(self) -> None:
        groups = _synthetic_groups(5, seed=9)
        for target in (0.0, 1.0, -0.1):
            with self.assertRaises(ConformalError):
                calibrate_conformal_threshold(groups, target_risk=target)

    def test_non_bool_label_is_rejected(self) -> None:
        with self.assertRaises(ConformalError):
            ConformalCalibrationItem("c1", 0.5, 1)


if __name__ == "__main__":
    unittest.main()
