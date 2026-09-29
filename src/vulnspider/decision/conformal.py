"""Conformal risk control: how many candidates the selected set must contain.

``k`` is currently a hyperparameter a human picks, and nothing connects it to
how much of the true positive set survives the cut. Conformal risk control
(Angelopoulos, Bates, Fisch, Lei, Schuster, 2022) replaces that guess with a
threshold carrying a distribution-free guarantee:

``E[ 1 − Recall(S_λ̂) ] ≤ α``

for a fresh application drawn from the same distribution as the calibration
applications. The selection rule becomes "take every candidate whose calibrated
probability is at least ``λ̂``", and the set size follows from the target rather
than being chosen in advance.

Method
------
The loss ``L_g(λ) = 1 − Recall_g(λ)`` is non-decreasing in ``λ`` (raising the
cutoff can only drop candidates), which is the monotonicity the theorem needs.
With ``n`` calibration groups and loss bounded by ``B = 1``, the largest
threshold satisfying

``R̂_n(λ) ≤ α − (B − α) / n``

controls the risk on the next group. The correction term is what makes this a
finite-sample statement rather than an asymptotic one.

Two consequences the thesis should state plainly rather than bury:

* The guarantee is only attainable when ``α ≥ 1 / (n + 1)``. A 90 % recall
  guarantee needs at least nine calibration applications; with five the honest
  answer is that no threshold can be certified, and
  :attr:`ConformalThreshold.guarantee_attainable` reports exactly that instead
  of returning a number that looks certified and is not.
* The guarantee assumes the calibration groups and the target are
  exchangeable. Web applications are visibly *not* exchangeable -- DVWA and a
  bespoke Spring app differ in ways that matter. Calibrating leave-one-app-out
  and reporting the observed violation rate is the defensible way to use this,
  and the gap between nominal and realised coverage is a finding in its own
  right rather than a flaw to hide.

Groups with no positive candidate have undefined recall; they are scored as
zero loss, since a set cannot miss what does not exist.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import ceil, isfinite

from vulnspider.decision.candidate import DecisionCandidate

CONFORMAL_METHOD_VERSION = "conformal-risk-control-v1"

MAXIMUM_LOSS = 1.0


class ConformalError(ValueError):
    """Raised when a conformal threshold cannot be calibrated as stated."""


@dataclass(frozen=True, slots=True)
class ConformalCalibrationItem:
    """One labeled candidate from a calibration application."""

    candidate_id: str
    probability: float
    label: bool

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ConformalError("candidate_id must not be empty")
        if not isinstance(self.label, bool):
            raise ConformalError("label must be a bool")
        if isinstance(self.probability, bool) or not isinstance(
            self.probability, int | float
        ):
            raise ConformalError("probability must be numeric")
        if not isfinite(float(self.probability)):
            raise ConformalError("probability must be finite")
        if not 0.0 <= float(self.probability) <= 1.0:
            raise ConformalError("probability must lie inside [0, 1]")


@dataclass(frozen=True, slots=True)
class ConformalCalibrationGroup:
    """One calibration application's scored, labeled candidate pool.

    The group is the exchangeability unit. Splitting one application's
    candidates across groups would leak, which is the failure
    ``docs/EVALUATION_PROTOCOL.md`` §4 already warns about for train/test
    splits and which applies identically here.
    """

    group_id: str
    items: tuple[ConformalCalibrationItem, ...]

    def __post_init__(self) -> None:
        if not self.group_id:
            raise ConformalError("group_id must not be empty")
        for item in self.items:
            if not isinstance(item, ConformalCalibrationItem):
                raise ConformalError(
                    "items must contain ConformalCalibrationItem objects"
                )
        identifiers = [item.candidate_id for item in self.items]
        if len(identifiers) != len(set(identifiers)):
            raise ConformalError("calibration items must be unique by candidate_id")

    @property
    def positives(self) -> int:
        return sum(1 for item in self.items if item.label)

    def risk_at(self, threshold: float) -> float:
        """``1 − Recall`` when selecting every item scoring at least ``threshold``."""

        total_positives = self.positives
        if total_positives == 0:
            return 0.0
        retained = sum(
            1
            for item in self.items
            if item.label and float(item.probability) >= threshold
        )
        return 1.0 - retained / total_positives


@dataclass(frozen=True, slots=True, init=False)
class ConformalThreshold:
    """A probability cutoff and the recall guarantee attached to it."""

    method_version: str
    target_risk: float
    corrected_risk_bound: float
    threshold: float
    empirical_risk: float
    calibration_groups: int
    guarantee_attainable: bool

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "ConformalThreshold is produced only by calibrate_conformal_threshold()"
        )

    @classmethod
    def _from_parts(
        cls,
        *,
        target_risk: float,
        corrected_risk_bound: float,
        threshold: float,
        empirical_risk: float,
        calibration_groups: int,
        guarantee_attainable: bool,
    ) -> ConformalThreshold:
        instance = object.__new__(cls)
        object.__setattr__(instance, "method_version", CONFORMAL_METHOD_VERSION)
        object.__setattr__(instance, "target_risk", target_risk)
        object.__setattr__(
            instance, "corrected_risk_bound", corrected_risk_bound
        )
        object.__setattr__(instance, "threshold", threshold)
        object.__setattr__(instance, "empirical_risk", empirical_risk)
        object.__setattr__(instance, "calibration_groups", calibration_groups)
        object.__setattr__(
            instance, "guarantee_attainable", guarantee_attainable
        )
        instance.validate()
        return instance

    def as_mapping(self) -> dict[str, object]:
        """Serialize the calibrated threshold and the guarantee it carries."""

        return {
            "method_version": self.method_version,
            "target_risk": self.target_risk,
            "corrected_risk_bound": self.corrected_risk_bound,
            "threshold": self.threshold,
            "empirical_risk": self.empirical_risk,
            "calibration_groups": self.calibration_groups,
            "guarantee_attainable": self.guarantee_attainable,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> ConformalThreshold:
        """Rebuild a calibrated threshold, re-running every invariant check."""

        if not isinstance(payload, Mapping):
            raise ConformalError("conformal threshold payload must be a mapping")
        version = payload.get("method_version")
        if version != CONFORMAL_METHOD_VERSION:
            raise ConformalError(f"unsupported conformal method version: {version!r}")
        for field_name in (
            "target_risk",
            "corrected_risk_bound",
            "threshold",
            "empirical_risk",
            "calibration_groups",
            "guarantee_attainable",
        ):
            if field_name not in payload:
                raise ConformalError(
                    f"conformal threshold is missing {field_name!r}"
                )
        attainable = payload["guarantee_attainable"]
        if not isinstance(attainable, bool):
            raise ConformalError("'guarantee_attainable' must be a JSON boolean")
        return cls._from_parts(
            target_risk=float(payload["target_risk"]),  # type: ignore[arg-type]
            corrected_risk_bound=float(
                payload["corrected_risk_bound"]  # type: ignore[arg-type]
            ),
            threshold=float(payload["threshold"]),  # type: ignore[arg-type]
            empirical_risk=float(payload["empirical_risk"]),  # type: ignore[arg-type]
            calibration_groups=int(
                payload["calibration_groups"]  # type: ignore[arg-type]
            ),
            guarantee_attainable=attainable,
        )

    def validate(self) -> None:
        if not 0.0 < self.target_risk < 1.0:
            raise ConformalError("target_risk must lie strictly inside (0, 1)")
        if not 0.0 <= self.threshold <= 1.0:
            raise ConformalError("threshold must lie inside [0, 1]")
        if not 0.0 <= self.empirical_risk <= 1.0:
            raise ConformalError("empirical_risk must lie inside [0, 1]")
        if self.calibration_groups < 1:
            raise ConformalError("at least one calibration group is required")
        if self.guarantee_attainable and self.empirical_risk > (
            self.corrected_risk_bound + 1e-12
        ):
            raise ConformalError(
                "a certified threshold must satisfy the corrected risk bound"
            )


def minimum_groups_for_target(target_risk: float) -> int:
    """Calibration groups needed before ``target_risk`` can be certified at all."""

    if not 0.0 < target_risk < 1.0:
        raise ConformalError("target_risk must lie strictly inside (0, 1)")
    return max(int(ceil(1.0 / target_risk)) - 1, 1)


def calibrate_conformal_threshold(
    groups: Sequence[ConformalCalibrationGroup],
    *,
    target_risk: float = 0.1,
) -> ConformalThreshold:
    """Find the largest cutoff whose expected recall loss stays under the target.

    The largest such cutoff gives the *smallest* set meeting the guarantee,
    which is the point: verifying fewer candidates for the same certified
    recall is the entire efficiency claim.
    """

    if not 0.0 < target_risk < 1.0:
        raise ConformalError("target_risk must lie strictly inside (0, 1)")
    calibration = tuple(groups)
    for group in calibration:
        if not isinstance(group, ConformalCalibrationGroup):
            raise ConformalError(
                "groups must contain ConformalCalibrationGroup objects"
            )
    if not calibration:
        raise ConformalError("at least one calibration group is required")
    identifiers = [group.group_id for group in calibration]
    if len(identifiers) != len(set(identifiers)):
        raise ConformalError("calibration groups must be unique by group_id")

    count = len(calibration)
    corrected = target_risk - (MAXIMUM_LOSS - target_risk) / count
    attainable = corrected >= 0.0

    thresholds = sorted(
        {float(item.probability) for group in calibration for item in group.items}
        | {0.0},
        reverse=True,
    )
    chosen = 0.0
    chosen_risk = _mean_risk(calibration, 0.0)
    if attainable:
        for threshold in thresholds:
            risk = _mean_risk(calibration, threshold)
            if risk <= corrected + 1e-12:
                chosen = threshold
                chosen_risk = risk
                break

    return ConformalThreshold._from_parts(
        target_risk=target_risk,
        corrected_risk_bound=corrected,
        threshold=chosen,
        empirical_risk=chosen_risk,
        calibration_groups=count,
        guarantee_attainable=attainable,
    )


def select_by_threshold(
    candidates: Sequence[DecisionCandidate],
    threshold: float,
) -> tuple[DecisionCandidate, ...]:
    """Every candidate scoring at least ``threshold``, most probable first."""

    if not isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ConformalError("threshold must lie inside [0, 1]")
    return tuple(
        sorted(
            (
                candidate
                for candidate in candidates
                if float(candidate.probability) >= threshold
            ),
            key=lambda item: (-float(item.probability), item.candidate_id),
        )
    )


def _mean_risk(
    groups: Sequence[ConformalCalibrationGroup],
    threshold: float,
) -> float:
    return sum(group.risk_at(threshold) for group in groups) / len(groups)
