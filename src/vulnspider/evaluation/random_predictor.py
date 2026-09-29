"""A random-predictor baseline that guesses one class per input point.

``evaluation/live.py`` already carries ``ARM_RANDOM``: the *uniform random
ordering* baseline whose expected metrics ``metrics`` returns in closed form,
with no seed and no simulation. This module is a different, more literal random
baseline: a naive classifier that looks at each **input point** and guesses one
of ``{SQLI, REFLECTED_XSS, BROKEN_ACCESS_CONTROL, SAFE}`` at random. ``SAFE`` can
be given a heavier weight, because most input points are not vulnerable, so an
honest "coin flip" leans towards abstaining.

A guess of a vulnerability family predicts *that* ``InputPoint x family``
candidate positive (score ``1.0``); every other candidate of the same input
point -- and every candidate of an input point whose guess is ``SAFE`` or names
a family it has no candidate for -- is predicted negative (score ``0.0``). The
resulting two-tier ranking is scored with the very same ``evaluate_ranking`` the
other arms use, so the number is directly comparable to VulnSpider's on the same
candidates and labels.

Because each guess is random, one draw is noise. The predictor's reported metric
is the mean over ``trials`` independent seeded draws (Monte Carlo). Each draw's
metric is itself the exact tie-aware expectation ``metrics`` computes, so only
the class guesses -- never the within-tier order -- are simulated. The result is
deterministic for a given ``seed``.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from vulnspider.evaluation.live import ScoredCandidate
from vulnspider.evaluation.metrics import (
    METRICS_VERSION,
    MetricError,
    MetricSummary,
    RankedItem,
    RankingQuery,
    RankingReport,
    evaluate_ranking,
)

RANDOM_PREDICTOR_ARM = "Random predictor (per-input-point type guess)"

SAFE_PREDICTION = "SAFE"
VULNERABILITY_PREDICTIONS: tuple[str, ...] = (
    "SQLI",
    "REFLECTED_XSS",
    "BROKEN_ACCESS_CONTROL",
)
PREDICTION_CLASSES: tuple[str, ...] = (*VULNERABILITY_PREDICTIONS, SAFE_PREDICTION)

DEFAULT_TRIALS = 1000
DEFAULT_SEED = 0


class RandomPredictorError(ValueError):
    """Raised when the random predictor cannot be configured or scored."""


def uniform_weights() -> dict[str, float]:
    """Equal weight on each of the four classes (SQLI/XSS/BAC/SAFE)."""

    return {prediction: 1.0 for prediction in PREDICTION_CLASSES}


def safe_biased_weights(safe_weight: float) -> dict[str, float]:
    """Weight ``SAFE`` by ``safe_weight`` and each vulnerability family by ``1``.

    ``safe_weight == 1`` is uniform; a larger value makes the predictor abstain
    more often, which is the realistic prior when most input points are safe.
    """

    if isinstance(safe_weight, bool) or not isinstance(safe_weight, int | float):
        raise RandomPredictorError("safe_weight must be numeric")
    if safe_weight < 0:
        raise RandomPredictorError("safe_weight must not be negative")
    weights = {family: 1.0 for family in VULNERABILITY_PREDICTIONS}
    weights[SAFE_PREDICTION] = float(safe_weight)
    return weights


@dataclass(frozen=True, slots=True)
class RandomPredictor:
    """Guess one of the four classes per input point, weighted by ``weights``.

    ``weights`` maps a subset of ``PREDICTION_CLASSES`` to non-negative numbers
    that need not sum to one; a class absent from the mapping is never guessed.
    ``trials`` is the number of Monte Carlo draws the metric is averaged over,
    and ``seed`` makes those draws reproducible.
    """

    weights: Mapping[str, float]
    trials: int = DEFAULT_TRIALS
    seed: int = DEFAULT_SEED
    _classes: tuple[str, ...] = field(init=False, repr=False, compare=False)
    _weights: tuple[float, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.trials, bool) or not isinstance(self.trials, int):
            raise RandomPredictorError("trials must be an integer")
        if self.trials < 1:
            raise RandomPredictorError("trials must be a positive integer")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise RandomPredictorError("seed must be an integer")
        if not self.weights:
            raise RandomPredictorError("weights must not be empty")
        unknown = set(self.weights) - set(PREDICTION_CLASSES)
        if unknown:
            raise RandomPredictorError(
                f"weights has unknown classes: {sorted(unknown)}; "
                f"allowed: {list(PREDICTION_CLASSES)}"
            )
        classes: list[str] = []
        weights: list[float] = []
        for prediction in PREDICTION_CLASSES:
            weight = self.weights.get(prediction, 0.0)
            if isinstance(weight, bool) or not isinstance(weight, int | float):
                raise RandomPredictorError(f"weight for {prediction} must be numeric")
            if weight < 0:
                raise RandomPredictorError(f"weight for {prediction} must be >= 0")
            if weight > 0:
                classes.append(prediction)
                weights.append(float(weight))
        if not weights:
            raise RandomPredictorError("at least one class must have a positive weight")
        object.__setattr__(self, "_classes", tuple(classes))
        object.__setattr__(self, "_weights", tuple(weights))

    @classmethod
    def with_safe_weight(
        cls,
        safe_weight: float = 1.0,
        *,
        trials: int = DEFAULT_TRIALS,
        seed: int = DEFAULT_SEED,
    ) -> RandomPredictor:
        """A predictor that weights ``SAFE`` and leaves the families uniform."""

        return cls(weights=safe_biased_weights(safe_weight), trials=trials, seed=seed)

    def _guess(self, rng: random.Random) -> str:
        return rng.choices(self._classes, weights=self._weights, k=1)[0]

    def predicted_scores(
        self,
        candidates: Sequence[ScoredCandidate],
        rng: random.Random,
    ) -> dict[str, float]:
        """One random draw: ``candidate_id -> 1.0`` if guessed, else ``0.0``.

        Input points are visited in a fixed sorted order so the draw is
        reproducible for a given ``rng`` state.
        """

        groups: dict[tuple[str, str, str], list[ScoredCandidate]] = defaultdict(list)
        for candidate in candidates:
            key = (
                candidate.key.canonical_path,
                candidate.key.parameter_location,
                candidate.key.parameter_name,
            )
            groups[key].append(candidate)

        scores: dict[str, float] = {}
        for key in sorted(groups):
            guess = self._guess(rng)
            for candidate in groups[key]:
                scores[candidate.candidate_id] = (
                    1.0 if candidate.family == guess else 0.0
                )
        return scores


def evaluate_random_predictor(
    candidates: Sequence[ScoredCandidate],
    *,
    application_id: str,
    predictor: RandomPredictor,
    cutoffs: Sequence[int],
    name: str = RANDOM_PREDICTOR_ARM,
) -> RankingReport:
    """Mean Recall/Precision/NDCG/MAP of ``predictor`` over its Monte Carlo draws.

    The candidates, their labels, and the cut-offs are exactly those the other
    arms are measured on, so the returned ``RankingReport`` drops straight into
    the same comparison table.
    """

    if not application_id:
        raise RandomPredictorError("application_id must not be empty")
    pool = tuple(candidates)
    if not pool:
        raise RandomPredictorError("a random-predictor run needs at least one candidate")
    if not any(item.label is True for item in pool):
        raise RandomPredictorError(
            "no candidate is labeled vulnerable; ranking metrics are undefined"
        )
    resolved = tuple(sorted({int(value) for value in cutoffs}))
    if not resolved:
        raise RandomPredictorError("at least one cut-off is required")

    templates = tuple(
        (
            item.candidate_id,
            item.label,
            f"{item.key.canonical_path}|{item.key.parameter_name}|{item.family}",
        )
        for item in pool
    )

    rng = random.Random(predictor.seed)
    totals = {k: [0.0, 0.0, 0.0, 0.0] for k in resolved}  # recall, precision, ndcg, map
    for _ in range(predictor.trials):
        scores = predictor.predicted_scores(pool, rng)
        query = RankingQuery(
            query_id=application_id,
            items=tuple(
                RankedItem(
                    candidate_id=candidate_id,
                    score=scores[candidate_id],
                    label=label,
                    bug_key=bug_key,
                )
                for candidate_id, label, bug_key in templates
            ),
        )
        try:
            report = evaluate_ranking(name, (query,), cutoffs=resolved)
        except MetricError as exc:  # pragma: no cover - guarded by the label check
            raise RandomPredictorError(f"{name}: {exc}") from exc
        for k in resolved:
            summary = report.at(k)
            bucket = totals[k]
            bucket[0] += summary.recall
            bucket[1] += summary.precision
            bucket[2] += summary.ndcg
            bucket[3] += summary.mean_average_precision

    trials = float(predictor.trials)
    summaries = tuple(
        MetricSummary(
            k=k,
            queries=1,
            scored_queries=1,
            recall=totals[k][0] / trials,
            precision=totals[k][1] / trials,
            ndcg=totals[k][2] / trials,
            mean_average_precision=totals[k][3] / trials,
        )
        for k in resolved
    )
    return RankingReport(
        name=name,
        metrics_version=METRICS_VERSION,
        total_candidates=len(pool),
        total_relevant=sum(1 for item in pool if item.label is True),
        total_unlabeled=sum(1 for item in pool if item.label is None),
        summaries=summaries,
    )
