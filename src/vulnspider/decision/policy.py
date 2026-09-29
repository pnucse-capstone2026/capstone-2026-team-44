"""The decision-layer policy: an optional conformal cut, then Top-K by probability.

One pass over two steps:

1. **Cut (optional).** If a conformal threshold has been calibrated, keep the
   smallest candidate set carrying the target recall guarantee. Without one,
   every candidate stays eligible.
2. **Commit.** Rank the eligible candidates by calibrated probability and take
   the Top-K.

Top-K by probability is not an approximation. The quantity we maximise is the
expected number of truly vulnerable candidates in the selected set, which by
linearity of expectation is the sum of their probabilities; maximising a sum
under a cardinality constraint is achieved exactly by taking the K largest. So
there is no submodular search, no budget knapsack, and no approximation ratio to
report -- a sort is the optimum.

The policy performs no I/O and never invents a candidate: everything it returns
traces back to a ``DecisionCandidate`` the caller supplied, which the selection
layer authoritatively produced.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.conformal import ConformalThreshold, select_by_threshold

DECISION_POLICY_VERSION = "top-k-argmax-v1"


class DecisionPolicyRunError(ValueError):
    """Raised when the decision policy cannot run as configured."""


def _ranking_key(candidate: DecisionCandidate) -> tuple[float, int, str]:
    # Probability decides the order; family order and candidate_id only settle
    # exact ties so the result is reproducible.
    return (
        -float(candidate.probability),
        candidate.family_priority,
        candidate.candidate_id,
    )


@dataclass(frozen=True, slots=True, init=False)
class DecisionOutcome:
    """Everything the decision layer decided, and the pool it decided over."""

    policy_version: str
    initial_candidates: int
    top_k: int
    scored: tuple[DecisionCandidate, ...]
    conformal: ConformalThreshold | None
    conformal_set_size: int
    selected: tuple[DecisionCandidate, ...]
    deferred: tuple[DecisionCandidate, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("DecisionOutcome is produced only by run_decision_layer()")

    @classmethod
    def _from_parts(
        cls,
        *,
        initial_candidates: int,
        top_k: int,
        scored: tuple[DecisionCandidate, ...],
        conformal: ConformalThreshold | None,
        conformal_set_size: int,
        selected: tuple[DecisionCandidate, ...],
        deferred: tuple[DecisionCandidate, ...],
    ) -> DecisionOutcome:
        instance = object.__new__(cls)
        object.__setattr__(instance, "policy_version", DECISION_POLICY_VERSION)
        object.__setattr__(instance, "initial_candidates", initial_candidates)
        object.__setattr__(instance, "top_k", top_k)
        object.__setattr__(instance, "scored", scored)
        object.__setattr__(instance, "conformal", conformal)
        object.__setattr__(instance, "conformal_set_size", conformal_set_size)
        object.__setattr__(instance, "selected", selected)
        object.__setattr__(instance, "deferred", deferred)
        instance.validate()
        return instance

    @property
    def expected_findings(self) -> float:
        """Expected number of true findings among the selected candidates."""

        return sum(candidate.expected_value for candidate in self.selected)

    def validate(self) -> None:
        if self.initial_candidates != len(self.scored):
            raise DecisionPolicyRunError(
                "scored candidates must account for every input candidate"
            )
        if self.top_k < 0:
            raise DecisionPolicyRunError("top_k must not be negative")
        if self.conformal_set_size > len(self.scored):
            raise DecisionPolicyRunError(
                "conformal set cannot exceed the scored candidates"
            )
        if len(self.selected) > self.top_k:
            raise DecisionPolicyRunError(
                "selection cannot exceed top_k candidates"
            )
        scored_ids = {item.candidate_id for item in self.scored}
        for item in self.selected:
            if item.candidate_id not in scored_ids:
                raise DecisionPolicyRunError(
                    "selection must not introduce an unscored candidate"
                )


def run_decision_layer(
    candidates: Sequence[DecisionCandidate],
    *,
    top_k: int,
    conformal: ConformalThreshold | None = None,
) -> DecisionOutcome:
    """Run cut-then-commit over one already-selected candidate pool."""

    pool = tuple(candidates)
    for candidate in pool:
        if not isinstance(candidate, DecisionCandidate):
            raise DecisionPolicyRunError(
                "candidates must contain DecisionCandidate objects"
            )
    identifiers = [candidate.candidate_id for candidate in pool]
    if len(identifiers) != len(set(identifiers)):
        raise DecisionPolicyRunError("candidates must be unique by candidate_id")
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        raise DecisionPolicyRunError("top_k must be an integer")
    if top_k < 0:
        raise DecisionPolicyRunError("top_k must not be negative")
    if conformal is not None and not isinstance(conformal, ConformalThreshold):
        raise DecisionPolicyRunError("conformal must be a ConformalThreshold")

    eligible = (
        select_by_threshold(pool, conformal.threshold)
        if conformal is not None
        else pool
    )
    ranked_all = tuple(sorted(pool, key=_ranking_key))
    ranked_eligible = sorted(eligible, key=_ranking_key)
    selected = tuple(ranked_eligible[:top_k])
    selected_ids = {candidate.candidate_id for candidate in selected}
    deferred = tuple(
        candidate
        for candidate in ranked_all
        if candidate.candidate_id not in selected_ids
    )
    return DecisionOutcome._from_parts(
        initial_candidates=len(pool),
        top_k=top_k,
        scored=ranked_all,
        conformal=conformal,
        conformal_set_size=len(eligible),
        selected=selected,
        deferred=deferred,
    )
