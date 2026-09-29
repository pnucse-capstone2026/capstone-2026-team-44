"""Fit the verification confidence model and evaluate its calibration arm.

This is the evaluation arm the confidence calibration rests on. It answers one
question with data: **does the verification update actually improve the
probability, or just move it around?** It compares the Brier score of the
pre-verification prior against the Brier score of the post-verification
confidence, out-of-fold, so the model is never scored on an application it was
fitted on (`docs/EVALUATION_PROTOCOL.md` §4).

A negative improvement is a real, publishable result: it says verification is
not adding calibrated information on this corpus and the update should stay
conservative (which the LLR cap already guarantees). A positive improvement is
the evidence that the fitted LLRs are worth deploying over the defaults.
"""

from __future__ import annotations

from dataclasses import dataclass

from vulnspider.corpus.collection import CorpusError
from vulnspider.corpus.verification_collection import (
    VerificationCorpusDataset,
    VerificationSample,
)
from vulnspider.verification.calibration import (
    DEFAULT_MAX_ABS_LLR,
    DEFAULT_SIGNAL_SMOOTHING,
    ALL_SIGNALS,
    VerificationConfidenceModel,
    fit_verification_model,
)


def fit_from_verification_corpus(
    dataset: VerificationCorpusDataset,
    *,
    max_abs_llr: float = DEFAULT_MAX_ABS_LLR,
    smoothing: float = DEFAULT_SIGNAL_SMOOTHING,
) -> VerificationConfidenceModel:
    """Fit one deployable confidence model from the whole verification corpus."""

    if not isinstance(dataset, VerificationCorpusDataset):
        raise CorpusError("dataset must be a VerificationCorpusDataset")
    return fit_verification_model(
        dataset.training_samples(),
        max_abs_llr=max_abs_llr,
        smoothing=smoothing,
    )


@dataclass(frozen=True, slots=True)
class VerificationPrediction:
    """One sample's prior and the posterior from a model that never saw its app."""

    sample: VerificationSample
    prior_probability: float
    posterior_probability: float


def out_of_fold_verification_predictions(
    dataset: VerificationCorpusDataset,
    *,
    max_abs_llr: float = DEFAULT_MAX_ABS_LLR,
    smoothing: float = DEFAULT_SIGNAL_SMOOTHING,
) -> tuple[VerificationPrediction, ...]:
    """Apply a per-fold model to each held-out application's samples."""

    if not isinstance(dataset, VerificationCorpusDataset):
        raise CorpusError("dataset must be a VerificationCorpusDataset")
    if len(dataset.groups) < 2:
        raise CorpusError(
            "leave-one-application-out needs at least two applications"
        )

    predictions: list[VerificationPrediction] = []
    for _group, train, test in dataset.leave_one_group_out():
        model = fit_verification_model(
            train.training_samples(),
            max_abs_llr=max_abs_llr,
            smoothing=smoothing,
        )
        for sample in test.samples:
            posterior = model.apply(
                sample.prior_probability, sample.family, sample.signal
            )
            predictions.append(
                VerificationPrediction(
                    sample=sample,
                    prior_probability=sample.prior_probability,
                    posterior_probability=posterior,
                )
            )
    return tuple(predictions)


def _brier(pairs: list[tuple[float, bool]]) -> float:
    return sum((p - (1.0 if label else 0.0)) ** 2 for p, label in pairs) / len(pairs)


@dataclass(frozen=True, slots=True)
class VerificationArmReport:
    """Whether the verification update improved calibration, measured out-of-fold."""

    samples: int
    positives: int
    groups: int
    brier_prior: float
    brier_posterior: float
    signal_counts: tuple[tuple[str, int, int], ...]

    @property
    def improvement(self) -> float:
        """Brier reduction from the verification update. Positive is better."""

        return self.brier_prior - self.brier_posterior

    def as_mapping(self) -> dict[str, object]:
        return {
            "samples": self.samples,
            "positives": self.positives,
            "groups": self.groups,
            "brier_prior": self.brier_prior,
            "brier_posterior": self.brier_posterior,
            "brier_improvement": self.improvement,
            "signal_counts": [
                {
                    "signal": signal,
                    "vulnerable": vulnerable,
                    "safe": safe,
                }
                for signal, vulnerable, safe in self.signal_counts
            ],
        }


def evaluate_verification_arm(
    dataset: VerificationCorpusDataset,
    *,
    max_abs_llr: float = DEFAULT_MAX_ABS_LLR,
    smoothing: float = DEFAULT_SIGNAL_SMOOTHING,
) -> VerificationArmReport:
    """Compare Brier(prior) with Brier(posterior) out-of-fold."""

    predictions = out_of_fold_verification_predictions(
        dataset,
        max_abs_llr=max_abs_llr,
        smoothing=smoothing,
    )
    if not predictions:
        raise CorpusError("verification arm evaluation needs predictions")

    prior_pairs = [
        (p.prior_probability, p.sample.label) for p in predictions
    ]
    posterior_pairs = [
        (p.posterior_probability, p.sample.label) for p in predictions
    ]
    counts: dict[str, list[int]] = {
        signal.value: [0, 0] for signal in ALL_SIGNALS
    }
    for prediction in predictions:
        bucket = counts[prediction.sample.signal.value]
        bucket[0 if prediction.sample.label else 1] += 1

    return VerificationArmReport(
        samples=len(predictions),
        positives=sum(1 for p in predictions if p.sample.label),
        groups=len(dataset.groups),
        brier_prior=_brier(prior_pairs),
        brier_posterior=_brier(posterior_pairs),
        signal_counts=tuple(
            (signal, vulnerable_safe[0], vulnerable_safe[1])
            for signal, vulnerable_safe in sorted(counts.items())
        ),
    )
