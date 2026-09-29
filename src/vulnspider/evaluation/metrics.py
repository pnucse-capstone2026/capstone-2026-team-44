"""Ranking metrics with exact tie handling.

``docs/EVALUATION_PROTOCOL.md`` §6 names Recall@K, Precision@K, MAP@K and
NDCG@K as the core measures, and §6-A fixes the five judgment calls that make
them computable. This module implements §6-A and nothing else: it takes a
ranking and labels, and returns numbers. It knows nothing about candidates,
scorers, or the corpus, so the same code measures the heuristic RankScore, the
calibrated probability, and every baseline on identical terms.

Ties are the part that is easy to get quietly wrong. Real rankings tie often --
``app01`` in the current corpus has ten candidates and eight distinct scores --
and when a tie group straddles the K boundary, the metric depends on an
arbitrary tie-break. Rather than inherit ``selection``'s ``candidate_id``
ordering, which is reproducible but meaningless, every metric here reports the
**expected value under a uniformly random order within each tie group**.

That choice has a useful side effect: a ranking where everything ties is
exactly Baseline B (random Top-K), so its expected Precision@K comes out as the
prevalence analytically, with no simulation. ``tests/unit/
test_evaluation_metrics.py`` uses that identity to check the implementation.

Unlabeled items count as non-relevant (§6-A rule 2). Callers that want them
excluded must filter before building the query, and must say so.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite, log2

METRICS_VERSION = "ranking-metrics-v1"


class MetricError(ValueError):
    """Raised when a metric cannot be computed as defined."""


@dataclass(frozen=True, slots=True)
class RankedItem:
    """One scored candidate and its ground truth.

    ``label`` is ``None`` when the candidate has no ground truth entry. Per
    §6-A rule 2 that counts as non-relevant, but it is kept distinct from an
    explicit ``False`` so the unlabeled count can be reported.
    """

    candidate_id: str
    score: float
    label: bool | None = None
    bug_key: str = ""

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise MetricError("candidate_id must not be empty")
        if isinstance(self.score, bool) or not isinstance(self.score, int | float):
            raise MetricError("score must be numeric")
        if not isfinite(float(self.score)):
            raise MetricError("score must be finite")
        if self.label is not None and not isinstance(self.label, bool):
            raise MetricError("label must be a bool or None")

    @property
    def relevant(self) -> bool:
        return self.label is True


@dataclass(frozen=True, slots=True)
class RankingQuery:
    """One application's scored candidate pool (§6-A rule 3)."""

    query_id: str
    items: tuple[RankedItem, ...]

    def __post_init__(self) -> None:
        if not self.query_id:
            raise MetricError("query_id must not be empty")
        identifiers = [item.candidate_id for item in self.items]
        if len(identifiers) != len(set(identifiers)):
            raise MetricError("a query must not repeat a candidate_id")

    @property
    def relevant_count(self) -> int:
        return sum(1 for item in self.items if item.relevant)

    @property
    def unlabeled_count(self) -> int:
        return sum(1 for item in self.items if item.label is None)

    def tie_groups(self) -> tuple[tuple[RankedItem, ...], ...]:
        """Items ordered by descending score, grouped by equal score."""

        ordered = sorted(self.items, key=lambda item: -float(item.score))
        groups: list[list[RankedItem]] = []
        for item in ordered:
            if groups and float(groups[-1][0].score) == float(item.score):
                groups[-1].append(item)
            else:
                groups.append([item])
        return tuple(tuple(group) for group in groups)


def expected_hits_at_k(query: RankingQuery, k: int) -> float:
    """Expected relevant items within the top ``k`` under random tie order."""

    _validate_k(k)
    hits = 0.0
    taken = 0
    for group in query.tie_groups():
        if taken >= k:
            break
        size = len(group)
        relevant = sum(1 for item in group if item.relevant)
        room = min(size, k - taken)
        hits += relevant * room / size
        taken += room
    return hits


def recall_at_k(query: RankingQuery, k: int) -> float | None:
    """Expected fraction of relevant items retrieved. ``None`` if none exist."""

    if query.relevant_count == 0:
        return None
    return expected_hits_at_k(query, k) / query.relevant_count


def precision_at_k(query: RankingQuery, k: int) -> float:
    """Expected fraction of the top ``k`` that is relevant."""

    _validate_k(k)
    denominator = min(k, len(query.items))
    if denominator == 0:
        return 0.0
    return expected_hits_at_k(query, k) / denominator


def dcg_at_k(query: RankingQuery, k: int) -> float:
    """Expected discounted cumulative gain with binary relevance.

    Linearity of expectation makes this exact: a tie group occupying ranks
    ``p..p+g-1`` places each of its members uniformly, so every visible rank in
    that span has expected gain ``R / g``.
    """

    _validate_k(k)
    total = 0.0
    rank = 1
    for group in query.tie_groups():
        if rank > k:
            break
        size = len(group)
        relevant = sum(1 for item in group if item.relevant)
        expected_gain = relevant / size
        for position in range(rank, min(rank + size, k + 1)):
            total += expected_gain / log2(position + 1)
        rank += size
    return total


def ideal_dcg_at_k(query: RankingQuery, k: int) -> float:
    """DCG of the perfect ranking: every relevant item first, no ties."""

    _validate_k(k)
    return sum(
        1.0 / log2(position + 1)
        for position in range(1, min(k, query.relevant_count) + 1)
    )


def ndcg_at_k(query: RankingQuery, k: int) -> float | None:
    """Normalized DCG in ``[0, 1]``. ``None`` when the query has no relevant item."""

    ideal = ideal_dcg_at_k(query, k)
    if ideal <= 0.0:
        return None
    return dcg_at_k(query, k) / ideal


def average_precision_at_k(query: RankingQuery, k: int) -> float | None:
    """Expected average precision under random tie order (McSherry & Najork).

    For a relevant item in a tie group of size ``g`` holding ``R`` relevant
    items, its position within the group is uniform on ``1..g``. Given position
    ``i``, the expected number of relevant items at or above it is
    ``r_before + 1 + (i - 1)(R - 1)/(g - 1)``, so its expected precision
    contribution is that over its absolute rank ``n_before + i``. Summing over
    ``i`` and weighting by ``R/g`` gives the group's exact contribution.
    """

    _validate_k(k)
    if query.relevant_count == 0:
        return None

    total = 0.0
    seen = 0
    relevant_before = 0
    for group in query.tie_groups():
        size = len(group)
        relevant = sum(1 for item in group if item.relevant)
        if relevant and seen < k:
            for offset in range(1, size + 1):
                rank = seen + offset
                if rank > k:
                    break
                if size == 1:
                    expected_relevant_at_or_above = relevant_before + 1
                else:
                    expected_relevant_at_or_above = (
                        relevant_before
                        + 1
                        + (offset - 1) * (relevant - 1) / (size - 1)
                    )
                total += (relevant / size) * (
                    expected_relevant_at_or_above / rank
                )
        seen += size
        relevant_before += relevant
    return total / min(query.relevant_count, k)


@dataclass(frozen=True, slots=True)
class MetricSummary:
    """Mean metrics across queries at one cut-off."""

    k: int
    queries: int
    scored_queries: int
    recall: float
    precision: float
    ndcg: float
    mean_average_precision: float

    def as_mapping(self) -> dict[str, float | int]:
        return {
            "k": self.k,
            "queries": self.queries,
            "scored_queries": self.scored_queries,
            "recall_at_k": self.recall,
            "precision_at_k": self.precision,
            "ndcg_at_k": self.ndcg,
            "map_at_k": self.mean_average_precision,
        }


@dataclass(frozen=True, slots=True)
class RankingReport:
    """One ranking's measured quality across several cut-offs."""

    name: str
    metrics_version: str
    total_candidates: int
    total_relevant: int
    total_unlabeled: int
    summaries: tuple[MetricSummary, ...]

    def at(self, k: int) -> MetricSummary:
        for summary in self.summaries:
            if summary.k == k:
                return summary
        raise MetricError(f"no summary computed at k={k}")

    def as_mapping(self) -> dict[str, object]:
        return {
            "name": self.name,
            "metrics_version": self.metrics_version,
            "total_candidates": self.total_candidates,
            "total_relevant": self.total_relevant,
            "total_unlabeled": self.total_unlabeled,
            "cutoffs": [summary.as_mapping() for summary in self.summaries],
        }


def evaluate_ranking(
    name: str,
    queries: Sequence[RankingQuery],
    *,
    cutoffs: Sequence[int],
) -> RankingReport:
    """Mean Recall/Precision/NDCG/MAP over queries, per §6-A rule 3.

    Queries without a relevant item are excluded from every mean that is
    undefined for them, and ``scored_queries`` reports how many remained.
    """

    if not name:
        raise MetricError("ranking name must not be empty")
    pool = tuple(queries)
    if not pool:
        raise MetricError("at least one query is required")
    for query in pool:
        if not isinstance(query, RankingQuery):
            raise MetricError("queries must contain RankingQuery objects")
    identifiers = [query.query_id for query in pool]
    if len(identifiers) != len(set(identifiers)):
        raise MetricError("queries must be unique by query_id")

    summaries: list[MetricSummary] = []
    for k in cutoffs:
        _validate_k(k)
        scored = [query for query in pool if query.relevant_count > 0]
        if not scored:
            raise MetricError("no query has a relevant item; metrics are undefined")
        summaries.append(
            MetricSummary(
                k=k,
                queries=len(pool),
                scored_queries=len(scored),
                recall=_mean(recall_at_k(query, k) for query in scored),
                precision=_mean(precision_at_k(query, k) for query in scored),
                ndcg=_mean(ndcg_at_k(query, k) for query in scored),
                mean_average_precision=_mean(
                    average_precision_at_k(query, k) for query in scored
                ),
            )
        )
    return RankingReport(
        name=name,
        metrics_version=METRICS_VERSION,
        total_candidates=sum(len(query.items) for query in pool),
        total_relevant=sum(query.relevant_count for query in pool),
        total_unlabeled=sum(query.unlabeled_count for query in pool),
        summaries=tuple(summaries),
    )


def _mean(values: object) -> float:
    collected = [value for value in values if value is not None]  # type: ignore[union-attr]
    if not collected:
        raise MetricError("no query produced a defined metric value")
    return sum(collected) / len(collected)


def _validate_k(k: int) -> None:
    if isinstance(k, bool) or not isinstance(k, int):
        raise MetricError("k must be an integer")
    if k <= 0:
        raise MetricError("k must be a positive integer")
