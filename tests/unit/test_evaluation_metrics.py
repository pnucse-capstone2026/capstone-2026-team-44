from __future__ import annotations

import random
import unittest
from itertools import permutations
from math import log2

from vulnspider.evaluation.metrics import (
    MetricError,
    RankedItem,
    RankingQuery,
    average_precision_at_k,
    dcg_at_k,
    evaluate_ranking,
    expected_hits_at_k,
    ideal_dcg_at_k,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
)


def _query(*specs: tuple[float, bool | None], query_id: str = "app0") -> RankingQuery:
    return RankingQuery(
        query_id=query_id,
        items=tuple(
            RankedItem(candidate_id=f"c{index}", score=score, label=label)
            for index, (score, label) in enumerate(specs)
        ),
    )


def _exact_expectation(query: RankingQuery, k: int, metric) -> float:
    """Average the metric over *every* tie order, by exhaustive enumeration.

    The closed-form tie handling in `metrics` must reproduce this exactly.
    Enumerating all permutations and stable-sorting by descending score visits
    each tie order equally often, so the mean is the true expectation -- no
    sampling tolerance needed. Only used on queries small enough to enumerate.
    """

    if len(query.items) > 6:
        raise AssertionError("exhaustive tie enumeration needs a small query")

    total = 0.0
    orders = 0
    for permutation in permutations(query.items):
        ordered = sorted(permutation, key=lambda item: -float(item.score))
        # Re-score strictly decreasing so the metric sees no ties at all.
        broken = RankingQuery(
            query_id=query.query_id,
            items=tuple(
                RankedItem(
                    candidate_id=item.candidate_id,
                    score=float(len(ordered) - index),
                    label=item.label,
                )
                for index, item in enumerate(ordered)
            ),
        )
        value = metric(broken, k)
        total += 0.0 if value is None else value
        orders += 1
    return total / orders


class HandComputedTests(unittest.TestCase):
    """Worked examples whose answers were computed by hand."""

    def test_recall_and_precision_without_ties(self) -> None:
        # Ranks:      1     2      3     4
        # Relevant:   yes   no     yes   no
        query = _query((0.9, True), (0.8, False), (0.7, True), (0.6, False))
        self.assertAlmostEqual(recall_at_k(query, 1), 0.5)
        self.assertAlmostEqual(recall_at_k(query, 3), 1.0)
        self.assertAlmostEqual(precision_at_k(query, 1), 1.0)
        self.assertAlmostEqual(precision_at_k(query, 2), 0.5)
        self.assertAlmostEqual(precision_at_k(query, 4), 0.5)

    def test_dcg_matches_the_definition(self) -> None:
        query = _query((0.9, True), (0.8, False), (0.7, True))
        expected = 1.0 / log2(2) + 1.0 / log2(4)
        self.assertAlmostEqual(dcg_at_k(query, 3), expected)
        self.assertAlmostEqual(ideal_dcg_at_k(query, 3), 1.0 / log2(2) + 1.0 / log2(3))

    def test_average_precision_matches_the_definition(self) -> None:
        # Relevant at ranks 1 and 3: AP = (1/1 + 2/3) / 2
        query = _query((0.9, True), (0.8, False), (0.7, True))
        self.assertAlmostEqual(average_precision_at_k(query, 3), (1.0 + 2.0 / 3.0) / 2)

    def test_straddling_tie_splits_proportionally(self) -> None:
        # One tie group of 4 holding 2 relevant; k=2 takes half of it.
        query = _query((0.5, True), (0.5, True), (0.5, False), (0.5, False))
        self.assertAlmostEqual(expected_hits_at_k(query, 2), 1.0)
        self.assertAlmostEqual(precision_at_k(query, 2), 0.5)
        self.assertAlmostEqual(recall_at_k(query, 2), 0.5)


class TieExpectationTests(unittest.TestCase):
    """Closed-form tie handling must match exhaustive enumeration."""

    def _tied_queries(self) -> tuple[RankingQuery, ...]:
        return (
            _query((0.5, True), (0.5, False), (0.5, True), (0.5, False)),
            _query((0.9, True), (0.5, False), (0.5, True), (0.1, False)),
            _query((0.8, False), (0.8, False), (0.8, True), (0.2, True)),
            _query((0.7, True), (0.7, True), (0.7, False)),
        )

    def test_recall_matches_enumeration(self) -> None:
        for query in self._tied_queries():
            for k in range(1, len(query.items) + 1):
                self.assertAlmostEqual(
                    recall_at_k(query, k),
                    _exact_expectation(query, k, recall_at_k),
                    places=9,
                )

    def test_ndcg_matches_enumeration(self) -> None:
        for query in self._tied_queries():
            for k in range(1, len(query.items) + 1):
                self.assertAlmostEqual(
                    ndcg_at_k(query, k),
                    _exact_expectation(query, k, ndcg_at_k),
                    places=9,
                )

    def test_average_precision_matches_enumeration(self) -> None:
        for query in self._tied_queries():
            for k in range(1, len(query.items) + 1):
                self.assertAlmostEqual(
                    average_precision_at_k(query, k),
                    _exact_expectation(query, k, average_precision_at_k),
                    places=9,
                )

    def test_tie_break_order_cannot_change_the_result(self) -> None:
        forward = _query((0.5, True), (0.5, False), (0.5, False))
        reversed_labels = RankingQuery(
            query_id="app0",
            items=tuple(reversed(forward.items)),
        )
        for k in (1, 2, 3):
            self.assertAlmostEqual(
                recall_at_k(forward, k), recall_at_k(reversed_labels, k)
            )


class InvariantTests(unittest.TestCase):
    def _random_query(self, generator: random.Random, size: int) -> RankingQuery:
        return RankingQuery(
            query_id="app0",
            items=tuple(
                RankedItem(
                    candidate_id=f"c{index}",
                    # Coarse scores so ties occur often.
                    score=float(generator.randint(0, 3)),
                    label=generator.random() < 0.3,
                )
                for index in range(size)
            ),
        )

    def test_recall_is_monotone_in_k(self) -> None:
        generator = random.Random(11)
        for _trial in range(200):
            query = self._random_query(generator, generator.randint(2, 12))
            if query.relevant_count == 0:
                continue
            values = [recall_at_k(query, k) for k in range(1, len(query.items) + 1)]
            for earlier, later in zip(values[:-1], values[1:], strict=True):
                self.assertLessEqual(earlier, later + 1e-12)

    def test_recall_at_full_depth_is_one(self) -> None:
        generator = random.Random(12)
        for _trial in range(200):
            query = self._random_query(generator, generator.randint(2, 12))
            if query.relevant_count == 0:
                continue
            self.assertAlmostEqual(recall_at_k(query, len(query.items)), 1.0)

    def test_ndcg_stays_inside_the_unit_interval(self) -> None:
        generator = random.Random(13)
        for _trial in range(200):
            query = self._random_query(generator, generator.randint(2, 12))
            if query.relevant_count == 0:
                continue
            for k in range(1, len(query.items) + 1):
                value = ndcg_at_k(query, k)
                self.assertGreaterEqual(value, -1e-12)
                self.assertLessEqual(value, 1.0 + 1e-12)

    def test_perfect_ranking_scores_one(self) -> None:
        query = _query((0.9, True), (0.8, True), (0.7, False), (0.6, False))
        self.assertAlmostEqual(ndcg_at_k(query, 4), 1.0)
        self.assertAlmostEqual(average_precision_at_k(query, 4), 1.0)
        self.assertAlmostEqual(recall_at_k(query, 2), 1.0)

    def test_worst_ranking_scores_below_perfect(self) -> None:
        worst = _query((0.9, False), (0.8, False), (0.7, True), (0.6, True))
        best = _query((0.9, True), (0.8, True), (0.7, False), (0.6, False))
        self.assertLess(ndcg_at_k(worst, 4), ndcg_at_k(best, 4))
        self.assertLess(
            average_precision_at_k(worst, 4), average_precision_at_k(best, 4)
        )

    def test_average_precision_is_one_only_when_positives_lead(self) -> None:
        self.assertAlmostEqual(
            average_precision_at_k(_query((0.9, True), (0.8, False)), 2), 1.0
        )
        self.assertLess(
            average_precision_at_k(_query((0.9, False), (0.8, True)), 2), 1.0
        )


class RandomBaselineIdentityTests(unittest.TestCase):
    """A ranking that is entirely one tie group *is* the random baseline.

    Its expected Precision@K must equal the prevalence exactly, at every K.
    This checks the tie machinery and Baseline B at the same time.
    """

    def test_precision_equals_prevalence_at_every_k(self) -> None:
        for total, positives in ((10, 3), (20, 5), (7, 1), (12, 6)):
            specs = [(0.0, True)] * positives + [(0.0, False)] * (total - positives)
            query = _query(*specs)
            prevalence = positives / total
            for k in range(1, total + 1):
                self.assertAlmostEqual(precision_at_k(query, k), prevalence)

    def test_recall_is_linear_in_k(self) -> None:
        specs = [(0.0, True)] * 4 + [(0.0, False)] * 16
        query = _query(*specs)
        for k in range(1, 21):
            self.assertAlmostEqual(recall_at_k(query, k), k / 20)


class DegenerateCaseTests(unittest.TestCase):
    def test_query_without_relevant_items_is_undefined_not_zero(self) -> None:
        query = _query((0.9, False), (0.8, None))
        self.assertIsNone(recall_at_k(query, 2))
        self.assertIsNone(ndcg_at_k(query, 2))
        self.assertIsNone(average_precision_at_k(query, 2))
        self.assertAlmostEqual(precision_at_k(query, 2), 0.0)

    def test_all_relevant(self) -> None:
        query = _query((0.9, True), (0.8, True))
        self.assertAlmostEqual(recall_at_k(query, 2), 1.0)
        self.assertAlmostEqual(precision_at_k(query, 2), 1.0)
        self.assertAlmostEqual(ndcg_at_k(query, 2), 1.0)

    def test_k_beyond_the_pool_is_allowed(self) -> None:
        query = _query((0.9, True), (0.8, False))
        self.assertAlmostEqual(recall_at_k(query, 50), 1.0)
        self.assertAlmostEqual(precision_at_k(query, 50), 0.5)

    def test_unlabeled_counts_as_non_relevant(self) -> None:
        labeled = _query((0.9, True), (0.8, False))
        unlabeled = _query((0.9, True), (0.8, None))
        self.assertAlmostEqual(
            precision_at_k(labeled, 2), precision_at_k(unlabeled, 2)
        )
        self.assertEqual(unlabeled.unlabeled_count, 1)

    def test_non_positive_k_is_rejected(self) -> None:
        query = _query((0.9, True))
        for k in (0, -1):
            with self.assertRaises(MetricError):
                recall_at_k(query, k)

    def test_duplicate_candidate_ids_are_rejected(self) -> None:
        with self.assertRaises(MetricError):
            RankingQuery(
                query_id="app0",
                items=(
                    RankedItem(candidate_id="same", score=1.0, label=True),
                    RankedItem(candidate_id="same", score=0.5, label=False),
                ),
            )


class AggregateReportTests(unittest.TestCase):
    def test_report_averages_over_queries(self) -> None:
        first = _query((0.9, True), (0.8, False), query_id="app0")
        second = _query((0.9, False), (0.8, True), query_id="app1")
        report = evaluate_ranking("test", (first, second), cutoffs=(1, 2))
        self.assertEqual(report.total_candidates, 4)
        self.assertEqual(report.total_relevant, 2)
        self.assertAlmostEqual(report.at(1).recall, 0.5)
        self.assertAlmostEqual(report.at(2).recall, 1.0)
        self.assertEqual(report.at(1).queries, 2)

    def test_queries_without_positives_are_excluded_from_means(self) -> None:
        scored = _query((0.9, True), (0.8, False), query_id="app0")
        empty = _query((0.9, False), (0.8, False), query_id="app1")
        report = evaluate_ranking("test", (scored, empty), cutoffs=(1,))
        self.assertEqual(report.at(1).queries, 2)
        self.assertEqual(report.at(1).scored_queries, 1)
        self.assertAlmostEqual(report.at(1).recall, 1.0)

    def test_duplicate_query_ids_are_rejected(self) -> None:
        query = _query((0.9, True))
        with self.assertRaises(MetricError):
            evaluate_ranking("test", (query, query), cutoffs=(1,))

    def test_corpus_without_any_positive_is_rejected(self) -> None:
        with self.assertRaises(MetricError):
            evaluate_ranking("test", (_query((0.9, False)),), cutoffs=(1,))


if __name__ == "__main__":
    unittest.main()
