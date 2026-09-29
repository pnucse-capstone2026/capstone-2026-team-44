"""Corpus-calibrated confidence update, in log-odds space.

The confidence update used to move the prior by hand-picked constants
(``SUPPORT_GAIN=0.6``, ``WEAKEN_FACTOR=0.5``). This module replaces those with a
data-derived, bounded shift.

The model treats one verification as a **categorical signal** per candidate
(SUPPORT_NEW, SUPPORT_REPRODUCED, WEAKEN, ...), and asks the corpus how often
each signal appears among vulnerable versus safe candidates. The
log-likelihood-ratio of the signal is added to the prior's log-odds:

``logit(posterior) = logit(prior) + LLR(family, signal)``

This is the same weight-of-evidence composition ``scoring/calibration.py`` uses
for features (``NaiveBayesRates.log_likelihood_ratio``), applied to the
verification outcome. Two consequences the design wants:

* **Gentle by construction.** An additive logit shift is monotone and bounded,
  and every LLR is clamped to ``max_abs_llr`` so no single verification can
  swing a score hard. With the default model a signal moves a 0.5 prior by at
  most ~0.17; a fitted model stays inside the same cap.
* **Zero-data reproduces a conservative default.** :meth:`default` ships small
  fixed LLRs (a new signal nudges up, a weakening nudges down, everything else
  is exactly neutral), so with no corpus the update is defensible and small.
  A reproduced signal is neutral by default -- the corpus decides whether
  confirming an already-suspected candidate should earn anything.

`AGENTS.md` rules 6/7 are unchanged: the prior is the calibrated probability, a
pre-verification quantity, and this only refines it with verification evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from math import exp, isfinite, log

VERIFICATION_MODEL_VERSION = "verification-confidence-model-v1"
DEFAULT_VERIFICATION_MODEL_VERSION = "verification-confidence-default-v1"

# Hard cap on |LLR|, in logits. 1.0 logit is about a 2.7:1 odds shift: enough to
# matter, small enough that "the score does not change too much" holds even for
# a strongly separating corpus.
DEFAULT_MAX_ABS_LLR = 1.0

# Dirichlet smoothing for the categorical signal distribution per class. One
# pseudo-count per signal keeps a never-seen signal from producing an infinite
# LLR and shrinks sparse estimates toward neutral.
DEFAULT_SIGNAL_SMOOTHING = 1.0

_MIN_PROBABILITY = 1e-6
_MAX_PROBABILITY = 1.0 - 1e-6


class VerificationCalibrationError(ValueError):
    """Raised when a verification confidence model cannot be built or applied."""


class VerificationSignal(StrEnum):
    """The categorical verification evidence class for one candidate.

    Finer than the public outcome so the calibration can price a *reproduced*
    signal (baseline already suspected) differently from a *newly revealed* one
    (baseline under-suspected).
    """

    SUPPORT_NEW = "SUPPORT_NEW"
    SUPPORT_REPRODUCED = "SUPPORT_REPRODUCED"
    WEAKEN = "WEAKEN"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNCHANGED = "UNCHANGED"
    NOT_EXECUTED = "NOT_EXECUTED"


ALL_SIGNALS: tuple[VerificationSignal, ...] = tuple(VerificationSignal)

# Signals that carry no vulnerability evidence and must never move the score,
# fitted or not: a payload that did not execute, and an inconclusive server
# error. Pinning them to a 0 LLR keeps the "no evidence -> keep the prior"
# semantics and stops a smoothing artifact from nudging a rarely-seen signal.
_NEUTRAL_SIGNALS: frozenset[VerificationSignal] = frozenset(
    {VerificationSignal.NOT_EXECUTED, VerificationSignal.INCONCLUSIVE}
)

# Small, conservative LLRs used when no corpus model is supplied. A reproduced
# signal is exactly neutral by default; the corpus is what decides whether it
# should earn a small bump.
_DEFAULT_LLR: dict[VerificationSignal, float] = {
    VerificationSignal.SUPPORT_NEW: 0.7,
    VerificationSignal.SUPPORT_REPRODUCED: 0.0,
    VerificationSignal.WEAKEN: -0.7,
    VerificationSignal.INCONCLUSIVE: 0.0,
    VerificationSignal.UNCHANGED: 0.0,
    VerificationSignal.NOT_EXECUTED: 0.0,
}


@dataclass(frozen=True, slots=True)
class VerificationTrainingSample:
    """One labeled verification observation: the signal and the ground truth."""

    family: str
    signal: VerificationSignal
    label: bool
    group: str

    def __post_init__(self) -> None:
        if not self.family:
            raise VerificationCalibrationError("family must not be empty")
        object.__setattr__(self, "signal", VerificationSignal(self.signal))
        if not isinstance(self.label, bool):
            raise VerificationCalibrationError("label must be a bool")
        if not self.group:
            raise VerificationCalibrationError("group must not be empty")


def _logit(probability: float) -> float:
    clamped = min(max(probability, _MIN_PROBABILITY), _MAX_PROBABILITY)
    return log(clamped / (1.0 - clamped))


def _sigmoid(value: float) -> float:
    if value >= 0.0:
        return 1.0 / (1.0 + exp(-value))
    exponential = exp(value)
    return exponential / (1.0 + exponential)


@dataclass(frozen=True, slots=True)
class VerificationConfidenceModel:
    """Per-(family, signal) LLRs that refine a prior probability."""

    model_version: str
    max_abs_llr: float
    default_llr: Mapping[str, float]
    family_llr: Mapping[str, Mapping[str, float]]
    training_samples: int

    def __post_init__(self) -> None:
        if not isfinite(self.max_abs_llr) or self.max_abs_llr <= 0.0:
            raise VerificationCalibrationError("max_abs_llr must be positive")
        if isinstance(self.training_samples, bool) or not isinstance(
            self.training_samples, int
        ):
            raise VerificationCalibrationError("training_samples must be an integer")
        if self.training_samples < 0:
            raise VerificationCalibrationError("training_samples must be non-negative")
        object.__setattr__(
            self, "default_llr", _frozen_llr(self.default_llr, self.max_abs_llr)
        )
        object.__setattr__(
            self,
            "family_llr",
            {
                str(family): _frozen_llr(values, self.max_abs_llr)
                for family, values in self.family_llr.items()
            },
        )

    @classmethod
    def default(cls) -> VerificationConfidenceModel:
        """The zero-corpus model: small fixed LLRs, no per-family override."""

        return cls(
            model_version=DEFAULT_VERIFICATION_MODEL_VERSION,
            max_abs_llr=DEFAULT_MAX_ABS_LLR,
            default_llr={signal.value: llr for signal, llr in _DEFAULT_LLR.items()},
            family_llr={},
            training_samples=0,
        )

    def llr_for(self, family: str, signal: VerificationSignal) -> float:
        """The clamped log-likelihood ratio for one family and signal."""

        signal = VerificationSignal(signal)
        family_map = self.family_llr.get(family)
        if family_map is not None and signal.value in family_map:
            value = family_map[signal.value]
        elif signal.value in self.default_llr:
            value = self.default_llr[signal.value]
        else:
            value = _DEFAULT_LLR.get(signal, 0.0)
        return _clamp_llr(value, self.max_abs_llr)

    def apply(
        self,
        prior_probability: float,
        family: str,
        signal: VerificationSignal,
    ) -> float:
        """Return the posterior probability after the verification signal."""

        llr = self.llr_for(family, signal)
        posterior = _sigmoid(_logit(float(prior_probability)) + llr)
        return min(max(posterior, _MIN_PROBABILITY), _MAX_PROBABILITY)

    def as_mapping(self) -> dict[str, object]:
        return {
            "model_version": self.model_version,
            "max_abs_llr": self.max_abs_llr,
            "training_samples": self.training_samples,
            "default_llr": {
                signal.value: self.llr_for("", signal) for signal in ALL_SIGNALS
            },
            "family_llr": {
                family: dict(sorted(values.items()))
                for family, values in sorted(self.family_llr.items())
            },
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> VerificationConfidenceModel:
        if not isinstance(payload, Mapping):
            raise VerificationCalibrationError("model payload must be a mapping")
        version = payload.get("model_version")
        if not isinstance(version, str) or not version:
            raise VerificationCalibrationError("model_version must be a non-empty string")
        max_abs = payload.get("max_abs_llr", DEFAULT_MAX_ABS_LLR)
        default_llr = payload.get("default_llr")
        family_llr = payload.get("family_llr", {})
        if not isinstance(default_llr, Mapping):
            raise VerificationCalibrationError("default_llr must be an object")
        if not isinstance(family_llr, Mapping):
            raise VerificationCalibrationError("family_llr must be an object")
        training = payload.get("training_samples", 0)
        return cls(
            model_version=version,
            max_abs_llr=float(max_abs),  # type: ignore[arg-type]
            default_llr={str(k): float(v) for k, v in default_llr.items()},
            family_llr={
                str(family): {str(k): float(v) for k, v in values.items()}
                for family, values in family_llr.items()
                if isinstance(values, Mapping)
            },
            training_samples=int(training),  # type: ignore[arg-type]
        )


def fit_verification_model(
    samples: Sequence[VerificationTrainingSample],
    *,
    max_abs_llr: float = DEFAULT_MAX_ABS_LLR,
    smoothing: float = DEFAULT_SIGNAL_SMOOTHING,
) -> VerificationConfidenceModel:
    """Estimate per-(family, signal) LLRs from labeled verification samples.

    The signal is categorical, so each class-conditional distribution
    ``P(signal | vulnerable)`` and ``P(signal | safe)`` is a Dirichlet-smoothed
    multinomial, and ``LLR(signal) = log[P(signal|vuln) / P(signal|safe)]``.
    Every LLR is clamped to ``max_abs_llr`` so the update stays gentle.
    """

    if not isfinite(max_abs_llr) or max_abs_llr <= 0.0:
        raise VerificationCalibrationError("max_abs_llr must be positive")
    if not isfinite(smoothing) or smoothing <= 0.0:
        raise VerificationCalibrationError("smoothing must be positive")

    training = tuple(samples)
    for sample in training:
        if not isinstance(sample, VerificationTrainingSample):
            raise VerificationCalibrationError(
                "samples must be VerificationTrainingSample objects"
            )

    signal_count = len(ALL_SIGNALS)
    families = sorted({sample.family for sample in training})
    family_llr: dict[str, dict[str, float]] = {}
    total = 0
    for family in families:
        family_samples = [s for s in training if s.family == family]
        vuln = [s for s in family_samples if s.label]
        safe = [s for s in family_samples if not s.label]
        if not vuln or not safe:
            # Without both classes an LLR is unidentifiable; leave this family
            # to the default LLRs rather than inventing a direction.
            continue
        total += len(family_samples)
        vuln_counts = _signal_counts(vuln)
        safe_counts = _signal_counts(safe)
        vuln_denom = len(vuln) + smoothing * signal_count
        safe_denom = len(safe) + smoothing * signal_count
        llrs: dict[str, float] = {}
        for signal in ALL_SIGNALS:
            if signal in _NEUTRAL_SIGNALS:
                llrs[signal.value] = 0.0
                continue
            if vuln_counts[signal] + safe_counts[signal] == 0:
                # Never observed in this family: fall back to the conservative
                # default LLR (correct sign) rather than a smoothing artifact
                # driven only by the class-size ratio.
                llrs[signal.value] = _clamp_llr(
                    _DEFAULT_LLR.get(signal, 0.0), max_abs_llr
                )
                continue
            p_vuln = (vuln_counts[signal] + smoothing) / vuln_denom
            p_safe = (safe_counts[signal] + smoothing) / safe_denom
            llrs[signal.value] = _clamp_llr(log(p_vuln / p_safe), max_abs_llr)
        family_llr[family] = llrs

    return VerificationConfidenceModel(
        model_version=VERIFICATION_MODEL_VERSION,
        max_abs_llr=max_abs_llr,
        default_llr={signal.value: llr for signal, llr in _DEFAULT_LLR.items()},
        family_llr=family_llr,
        training_samples=total,
    )


def _signal_counts(
    samples: Sequence[VerificationTrainingSample],
) -> dict[VerificationSignal, int]:
    counts = {signal: 0 for signal in ALL_SIGNALS}
    for sample in samples:
        counts[sample.signal] += 1
    return counts


def _clamp_llr(value: float, max_abs_llr: float) -> float:
    if not isfinite(value):
        raise VerificationCalibrationError("LLR must be finite")
    return max(-max_abs_llr, min(max_abs_llr, value))


def _frozen_llr(values: Mapping[str, float], max_abs_llr: float) -> dict[str, float]:
    frozen: dict[str, float] = {}
    for key, value in values.items():
        frozen[str(key)] = _clamp_llr(float(value), max_abs_llr)
    return frozen
