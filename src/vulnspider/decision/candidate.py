"""The unit the decision layer ranks: a candidate with a calibrated probability.

A :class:`DecisionCandidate` is what one already-selected, already-validated
candidate looks like once a calibrated probability has been attached to it. It is
deliberately a *projection*, in the same sense as ``selection/handoff.py``:
nothing here recomputes a RankScore, re-derives evidence, or invents an
identifier. The selection layer stays the authority on which candidates exist and
what they are called (ADR-017, ADR-021); the decision layer only ranks them by
probability and takes the Top-K.

Budget, verification cost, and severity used to live here. They were removed when
the submodular/knapsack budget selector was dropped: "취약도" is the probability
of being vulnerable, Top-K is a plain argmax over that probability, and neither
cost nor severity enters the ranking. Family order remains only as a
reproducibility device for exact probability ties.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite

from vulnspider.scoring.calibration import CalibratedProbability
from vulnspider.selection.handoff import RankedCandidateContext

# Tie-break order when two candidates share an identical probability. This is a
# determinism device, not a severity ranking: probability alone decides the
# order, and this only settles exact ties before candidate_id does.
FAMILY_PRIORITY: dict[str, int] = {
    "SQLI": 0,
    "REFLECTED_XSS": 1,
    "BROKEN_ACCESS_CONTROL": 2,
}
DEFAULT_FAMILY_PRIORITY = 99


class DecisionCandidateError(ValueError):
    """Raised when a candidate cannot enter the decision layer honestly."""


@dataclass(frozen=True, slots=True)
class DecisionCandidate:
    """One candidate carrying the calibrated probability it is ranked by."""

    candidate_id: str
    family: str
    probability: float
    selection_rank: int | None = None
    subject_ref: str = ""
    """The InputPoint or AccessProbePlan this candidate was derived from."""

    feature_vector_ref: str = ""
    """The FeatureVector the probability was computed from.

    Both refs are carried forward from the handoff so a report can join a
    selected candidate back to its input point and to the baseline/probe pair
    that was actually executed. Reporting must not re-derive either
    (ARCHITECTURE.md: reporting displays authoritative results).
    """

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise DecisionCandidateError("candidate_id must not be empty")
        if not self.family:
            raise DecisionCandidateError("family must not be empty")
        if isinstance(self.probability, bool) or not isinstance(
            self.probability, int | float
        ):
            raise DecisionCandidateError("probability must be numeric")
        if not isfinite(float(self.probability)):
            raise DecisionCandidateError("probability must be finite")
        if not 0.0 < float(self.probability) < 1.0:
            raise DecisionCandidateError(
                "probability must lie strictly inside (0, 1)"
            )
        if self.selection_rank is not None:
            if isinstance(self.selection_rank, bool) or not isinstance(
                self.selection_rank, int
            ):
                raise DecisionCandidateError("selection_rank must be an integer")
            if self.selection_rank <= 0:
                raise DecisionCandidateError("selection_rank must be positive")

    @property
    def expected_value(self) -> float:
        """Expected findings from verifying this candidate: its probability.

        Because a candidate is either vulnerable or not, the expected number of
        true findings in a selected set is the sum of these values. That is what
        makes Top-K by probability the exact optimum for a cardinality
        constraint (linearity of expectation).
        """

        return float(self.probability)

    @property
    def family_priority(self) -> int:
        """Tie-break rank when two candidates share a probability."""

        return FAMILY_PRIORITY.get(self.family, DEFAULT_FAMILY_PRIORITY)


def decision_candidate_from_context(
    context: RankedCandidateContext,
    calibrated: CalibratedProbability,
) -> DecisionCandidate:
    """Attach a calibrated probability to one handoff entry.

    This is the decision layer's only entry point from the selection contract.
    ``calibrated`` must have been produced for the same family the handoff
    reports, which stops a SQLi probability from being attached to an XSS
    candidate.
    """

    if not isinstance(context, RankedCandidateContext):
        raise DecisionCandidateError("context must be a RankedCandidateContext")
    if not isinstance(calibrated, CalibratedProbability):
        raise DecisionCandidateError("calibrated must be a CalibratedProbability")
    if calibrated.family != context.family:
        raise DecisionCandidateError(
            "calibrated probability family does not match the handoff family"
        )

    return DecisionCandidate(
        candidate_id=context.candidate_id,
        family=context.family,
        probability=calibrated.probability,
        selection_rank=context.rank,
        subject_ref=context.candidate_subject_ref,
        feature_vector_ref=context.feature_vector_id or "",
    )
