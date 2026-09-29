"""Score one live scan's ranking against the target's known ground truth.

``evaluation/baselines.py`` measures rankings over a *stored corpus*: features
collected earlier, scored offline, out-of-fold. That answers "is the calibrated
probability a better ordering than the heuristic?" It cannot answer the
question this module exists for -- **does focused verification improve the
final ordering?** -- because a corpus holds no verification evidence.

This module measures the numbers the product actually emits, from one run
against one authorized target whose labels are known (``tools/demo_shop.py``):

* ``ARM_RANDOM`` -- a random predictor. Every candidate gets the same score, so
  the whole pool is one tie group and ``metrics`` returns its expectation in
  closed form, with no simulation and no seed.
* ``ARM_PRIOR`` -- the pipeline with the focused-verification stage removed:
  candidates ordered by the calibrated pre-verification probability.
* ``ARM_VULNSPIDER`` -- the shipped product: the same probabilities, replaced
  by the post-verification ``final_confidence`` wherever verification ran.

The three arms rank **the same candidates with the same labels**, so they
differ only in the number each candidate is sorted by. That is the whole point:
a difference between the last two arms is the verification stage's
contribution, measured on the metric the protocol names, not asserted.

Two consequences of measuring a live run, both worth stating plainly:

* Verification only visits the Top-K, so below that cut ``ARM_VULNSPIDER``
  scores exactly what ``ARM_PRIOR`` scores. At ``K == top_k`` the two arms hold
  the *same set* and therefore the same ``Recall@K`` and ``Precision@K``; they
  differ in ``MAP@K``, which is order-sensitive, and at every ``K < top_k``.
* One live run is one application, so per-§6-A rule 3 it is one query. ``MAP@K``
  over a single query is that query's average precision. Averaging over several
  applications needs several runs, which the harness leaves to the caller.

Unlabeled candidates count as non-relevant (§6-A rule 2) and are reported.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from vulnspider.corpus.ground_truth import GroundTruthKey, GroundTruthStore
from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.domain import Endpoint, InputPoint
from vulnspider.evaluation.metrics import (
    METRICS_VERSION,
    MetricError,
    RankedItem,
    RankingQuery,
    RankingReport,
    evaluate_ranking,
)

LIVE_EVALUATION_VERSION = "live-evaluation-v1"

DEFAULT_CUTOFFS: tuple[int, ...] = (1, 3, 5, 10, 20)

ARM_RANDOM = "Random predictor"
ARM_PRIOR = "VulnSpider without focused verification"
ARM_VULNSPIDER = "VulnSpider (full pipeline)"


class LiveEvaluationError(ValueError):
    """Raised when a live run cannot be scored as stated."""


@dataclass(frozen=True, slots=True)
class ScoredCandidate:
    """One ranked candidate, both of its scores, and its ground truth.

    ``prior`` is the calibrated probability the decision layer produced;
    ``final`` is the confidence after focused verification, which equals
    ``prior`` for every candidate verification did not visit. ``label`` is
    ``None`` when the target's ground truth has no entry for this key.
    """

    candidate_id: str
    key: GroundTruthKey
    prior: float
    final: float
    verified: bool
    label: bool | None

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise LiveEvaluationError("candidate_id must not be empty")
        for name in ("prior", "final"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise LiveEvaluationError(f"{name} must be numeric")
        if self.label is not None and not isinstance(self.label, bool):
            raise LiveEvaluationError("label must be a bool or None")

    @property
    def family(self) -> str:
        return self.key.vulnerability_type

    def as_mapping(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "canonical_path": self.key.canonical_path,
            "parameter_name": self.key.parameter_name,
            "parameter_location": self.key.parameter_location,
            "family": self.family,
            "prior_probability": self.prior,
            "final_confidence": self.final,
            "verified": self.verified,
            "vulnerable": self.label,
        }


@dataclass(frozen=True, slots=True)
class LiveEvaluationReport:
    """The comparison table for one scan, plus the rows it was computed from."""

    application_id: str
    target: str
    top_k: int
    cutoffs: tuple[int, ...]
    candidates: tuple[ScoredCandidate, ...]
    arms: tuple[RankingReport, ...]

    @property
    def relevant(self) -> int:
        return sum(1 for item in self.candidates if item.label is True)

    @property
    def unlabeled(self) -> int:
        return sum(1 for item in self.candidates if item.label is None)

    @property
    def verified(self) -> int:
        return sum(1 for item in self.candidates if item.verified)

    def arm(self, name: str) -> RankingReport:
        for report in self.arms:
            if report.name == name:
                return report
        raise LiveEvaluationError(f"no arm named {name!r}")

    def as_mapping(self) -> dict[str, object]:
        return {
            "report_version": LIVE_EVALUATION_VERSION,
            "metrics_version": METRICS_VERSION,
            "application_id": self.application_id,
            "target": self.target,
            "top_k": self.top_k,
            "cutoffs": list(self.cutoffs),
            "counts": {
                "candidates": len(self.candidates),
                "relevant": self.relevant,
                "unlabeled": self.unlabeled,
                "verified": self.verified,
            },
            "arms": [report.as_mapping() for report in self.arms],
            "candidates": [
                item.as_mapping()
                for item in sorted(
                    self.candidates,
                    key=lambda item: (-item.final, item.candidate_id),
                )
            ],
        }


def build_scored_candidates(
    candidates: Sequence[DecisionCandidate],
    *,
    application_id: str,
    ground_truth: GroundTruthStore,
    endpoints: Sequence[Endpoint],
    input_points: Sequence[InputPoint],
    final_confidence: Mapping[str, float] | None = None,
    access_input_points: Mapping[str, str] | None = None,
) -> tuple[ScoredCandidate, ...]:
    """Join every ranked candidate to its ground truth key.

    The key is rebuilt from the authoritative ``Endpoint`` and ``InputPoint``
    the discovery layer produced -- never from a report or a display string --
    exactly as ``corpus.collection`` does, so a live evaluation and a collected
    corpus agree on what a candidate *is*.

    ``access_input_points`` maps a Broken Access Control candidate to the input
    point its probe plan was built from; injection candidates carry that
    reference directly in ``subject_ref``.
    """

    if not application_id:
        raise LiveEvaluationError("application_id must not be empty")
    if not isinstance(ground_truth, GroundTruthStore):
        raise LiveEvaluationError("ground_truth must be a GroundTruthStore")

    confidences = final_confidence or {}
    access_points = access_input_points or {}
    endpoints_by_id = {endpoint.id or "": endpoint for endpoint in endpoints}
    points_by_id = {point.id or "": point for point in input_points}

    scored: list[ScoredCandidate] = []
    for candidate in candidates:
        input_point_id = access_points.get(
            candidate.candidate_id, candidate.subject_ref
        )
        # A CREDENTIAL_STRIP access candidate is endpoint-level: it carries no
        # InputPoint, so it has no parameter-keyed ground truth entry to score
        # against. It is excluded from the ranking evaluation (which is scored
        # per candidate x vulnerability_type at parameter granularity) rather
        # than errored on -- it is still ranked and shown in the dashboard, just
        # not measured here. Only a genuinely dangling reference is an error.
        if not input_point_id:
            continue
        input_point = points_by_id.get(input_point_id)
        if input_point is None:
            raise LiveEvaluationError(
                f"candidate {candidate.candidate_id!r} references unknown "
                f"input point {input_point_id!r}"
            )
        endpoint = endpoints_by_id.get(input_point.endpoint_id)
        if endpoint is None:
            raise LiveEvaluationError(
                f"input point references unknown endpoint "
                f"{input_point.endpoint_id!r}"
            )
        key = GroundTruthKey(
            application_id=application_id,
            method=endpoint.method.value,
            canonical_path=endpoint.path,
            parameter_location=input_point.location.value,
            parameter_name=input_point.name,
            vulnerability_type=candidate.family,
        )
        final = confidences.get(candidate.candidate_id)
        scored.append(
            ScoredCandidate(
                candidate_id=candidate.candidate_id,
                key=key,
                prior=float(candidate.probability),
                final=float(candidate.probability if final is None else final),
                verified=final is not None,
                label=ground_truth.label_for(key),
            )
        )
    return tuple(scored)


def _query(
    scored: Sequence[ScoredCandidate],
    *,
    application_id: str,
    score_for: str,
) -> RankingQuery:
    return RankingQuery(
        query_id=application_id,
        items=tuple(
            RankedItem(
                candidate_id=item.candidate_id,
                score=(0.0 if score_for == "random" else getattr(item, score_for)),
                label=item.label,
                bug_key=f"{item.key.canonical_path}|{item.key.parameter_name}"
                f"|{item.family}",
            )
            for item in scored
        ),
    )


def evaluate_live_run(
    scored: Sequence[ScoredCandidate],
    *,
    application_id: str,
    target: str,
    top_k: int,
    cutoffs: Sequence[int] = DEFAULT_CUTOFFS,
) -> LiveEvaluationReport:
    """Measure the three comparison arms over one scan's candidate pool."""

    pool = tuple(scored)
    if not pool:
        raise LiveEvaluationError("a live evaluation needs at least one candidate")
    if not any(item.label is True for item in pool):
        raise LiveEvaluationError(
            "no ranked candidate is labeled vulnerable; ranking metrics are "
            "undefined. Check that --ground-truth matches the scanned target."
        )
    resolved = tuple(sorted({int(value) for value in cutoffs}))
    if not resolved:
        raise LiveEvaluationError("at least one cut-off is required")

    arms: list[RankingReport] = []
    for name, score_for in (
        (ARM_RANDOM, "random"),
        (ARM_PRIOR, "prior"),
        (ARM_VULNSPIDER, "final"),
    ):
        try:
            arms.append(
                evaluate_ranking(
                    name,
                    (_query(pool, application_id=application_id, score_for=score_for),),
                    cutoffs=resolved,
                )
            )
        except MetricError as exc:
            raise LiveEvaluationError(f"{name}: {exc}") from exc

    return LiveEvaluationReport(
        application_id=application_id,
        target=target,
        top_k=top_k,
        cutoffs=resolved,
        candidates=pool,
        arms=tuple(arms),
    )


def render_live_evaluation_table(report: LiveEvaluationReport) -> str:
    """The comparison table as printable text, one block per metric."""

    lines = [
        f"ranking evaluation -- {report.application_id} ({report.target})",
        f"  candidates {len(report.candidates)}, "
        f"vulnerable {report.relevant}, "
        f"unlabeled {report.unlabeled}, "
        f"verified {report.verified} (top-{report.top_k})",
        "",
    ]
    width = max(len(arm.name) for arm in report.arms)
    for metric, label in (
        ("recall_at_k", "Recall@K"),
        ("precision_at_k", "Precision@K"),
        ("map_at_k", "MAP@K"),
        ("ndcg_at_k", "NDCG@K"),
    ):
        header = "  ".join(f"K={k:<4d}" for k in report.cutoffs)
        lines.append(f"{label:<14s} {'':<{width}s}  {header}")
        for arm in report.arms:
            cells = "  ".join(
                f"{float(arm.at(k).as_mapping()[metric]):<6.3f}"
                for k in report.cutoffs
            )
            lines.append(f"{'':<14s} {arm.name:<{width}s}  {cells}")
        lines.append("")
    return "\n".join(lines)
