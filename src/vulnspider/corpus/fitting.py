"""Fit Layer 1 models and calibrate the Layer 3 threshold from a corpus.

Two things here are easy to get wrong and are therefore done explicitly.

**Out-of-fold conformal calibration.** Calibrating the conformal threshold on
probabilities the model was itself fitted on inflates the guarantee: the model
has already seen those labels, so its scores separate them better than it will
on a fresh application, and the certified recall comes out optimistic.
:func:`out_of_fold_calibration_groups` refits the model once per held-out
application and scores that application with a model that never saw it. This
is the leave-one-app-out split ``docs/EVALUATION_PROTOCOL.md`` §4 requires,
applied to calibration rather than only to reporting.

**Calibration quality is measured separately from ranking.** A model can rank
perfectly and still be badly calibrated, and a mis-calibrated probability
silently corrupts every expected-utility comparison the decision layer makes.
:func:`evaluate_calibration` reports Brier score and expected calibration error
over out-of-fold predictions, which is the evidence ADR-022 rests on.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from vulnspider.corpus.collection import CorpusDataset, LabeledSample
from vulnspider.decision.conformal import (
    ConformalCalibrationGroup,
    ConformalCalibrationItem,
    ConformalThreshold,
    calibrate_conformal_threshold,
)
from vulnspider.domain import FeatureObservation, stable_fingerprint
from vulnspider.scoring.calibration import (
    DEFAULT_BASE_RATE,
    DEFAULT_PRIOR_SCALE,
    DEFAULT_PRIOR_STDDEV,
    CalibratedScorer,
    CalibrationError,
    fit_calibrated_scorer,
    heuristic_prior_for_family,
)

CORPUS_FITTING_VERSION = "corpus-fitting-v1"

_CORPUS_SOURCE = "corpus"
_CORPUS_EXTRACTOR_VERSION = "corpus-replay-v1"


class CorpusFittingError(ValueError):
    """Raised when a corpus cannot produce a usable model."""


def sample_observations(
    sample: LabeledSample,
) -> dict[str, FeatureObservation]:
    """Replay a stored sample's observed features as ``FeatureObservation``.

    Only features actually recorded during collection appear. A feature the
    pipeline never measured stays absent, so scoring a replayed sample follows
    exactly the same missing-feature path as scoring a live one.
    """

    return {
        name: FeatureObservation(
            name=name,
            value=float(value),
            observed=True,
            source=_CORPUS_SOURCE,
            extractor_version=_CORPUS_EXTRACTOR_VERSION,
        )
        for name, value in sample.features.items()
    }


def candidate_identifier(sample: LabeledSample) -> str:
    """Stable identifier for one labeled candidate."""

    fingerprint = stable_fingerprint(
        "corpus-candidate",
        sample.key.application_id,
        sample.key.method,
        sample.key.canonical_path,
        sample.key.parameter_location,
        sample.key.parameter_name,
        sample.key.vulnerability_type,
    )
    return f"gt_{fingerprint[:16]}"


def fit_family_scorers(
    dataset: CorpusDataset,
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> dict[str, CalibratedScorer]:
    """Fit one calibrated scorer per family present in the corpus.

    Families the corpus does not cover are simply absent from the result; the
    caller falls back to the heuristic prior for those, which is the whole
    point of the prior being the heuristic.
    """

    if not isinstance(dataset, CorpusDataset):
        raise CorpusFittingError("dataset must be a CorpusDataset")

    scorers: dict[str, CalibratedScorer] = {}
    for family in dataset.families:
        try:
            prior = heuristic_prior_for_family(
                family,
                base_rate=base_rate,
                prior_scale=prior_scale,
                prior_stddev=prior_stddev,
            )
        except CalibrationError:
            # A family with no heuristic prior cannot be fitted honestly.
            continue
        scorers[family] = fit_calibrated_scorer(
            dataset.for_family(family).training_samples(),
            prior,
        )
    return scorers


def prior_family_scorers(
    families: Sequence[str],
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> dict[str, CalibratedScorer]:
    """Zero-data scorers for the given families, i.e. the current heuristic."""

    scorers: dict[str, CalibratedScorer] = {}
    for family in families:
        try:
            prior = heuristic_prior_for_family(
                family,
                base_rate=base_rate,
                prior_scale=prior_scale,
                prior_stddev=prior_stddev,
            )
        except CalibrationError:
            continue
        scorers[family] = CalibratedScorer.from_prior(prior)
    return scorers


@dataclass(frozen=True, slots=True)
class OutOfFoldPrediction:
    """One sample scored by a model that never saw its application."""

    sample: LabeledSample
    probability: float
    logit_mean: float


def out_of_fold_predictions(
    dataset: CorpusDataset,
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> tuple[OutOfFoldPrediction, ...]:
    """Score every sample with a model fitted without its application."""

    if not isinstance(dataset, CorpusDataset):
        raise CorpusFittingError("dataset must be a CorpusDataset")
    if len(dataset.groups) < 2:
        raise CorpusFittingError(
            "leave-one-application-out needs at least two applications"
        )

    predictions: list[OutOfFoldPrediction] = []
    for group, train, test in dataset.leave_one_group_out():
        scorers = fit_family_scorers(
            train,
            base_rate=base_rate,
            prior_scale=prior_scale,
            prior_stddev=prior_stddev,
        )
        fallback = prior_family_scorers(
            test.families,
            base_rate=base_rate,
            prior_scale=prior_scale,
            prior_stddev=prior_stddev,
        )
        for sample in test.samples:
            scorer = scorers.get(sample.family) or fallback.get(sample.family)
            if scorer is None:
                raise CorpusFittingError(
                    f"no scorer available for family {sample.family!r} "
                    f"while holding out {group!r}"
                )
            scored = scorer.probability(sample_observations(sample))
            predictions.append(
                OutOfFoldPrediction(
                    sample=sample,
                    probability=scored.probability,
                    logit_mean=scored.logit_mean,
                )
            )
    return tuple(predictions)


def out_of_fold_calibration_groups(
    dataset: CorpusDataset,
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> tuple[ConformalCalibrationGroup, ...]:
    """Conformal calibration groups built from out-of-fold probabilities."""

    predictions = out_of_fold_predictions(
        dataset,
        base_rate=base_rate,
        prior_scale=prior_scale,
        prior_stddev=prior_stddev,
    )
    by_group: dict[str, list[ConformalCalibrationItem]] = {}
    for prediction in predictions:
        by_group.setdefault(prediction.sample.group, []).append(
            ConformalCalibrationItem(
                candidate_id=candidate_identifier(prediction.sample),
                probability=prediction.probability,
                label=prediction.sample.label,
            )
        )
    return tuple(
        ConformalCalibrationGroup(group_id=group, items=tuple(items))
        for group, items in sorted(by_group.items())
    )


def calibrate_from_corpus(
    dataset: CorpusDataset,
    *,
    target_risk: float = 0.1,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> ConformalThreshold:
    """Calibrate the conformal threshold on out-of-fold probabilities."""

    return calibrate_conformal_threshold(
        out_of_fold_calibration_groups(
            dataset,
            base_rate=base_rate,
            prior_scale=prior_scale,
            prior_stddev=prior_stddev,
        ),
        target_risk=target_risk,
    )


def heuristic_baseline_predictions(
    dataset: CorpusDataset,
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> tuple[OutOfFoldPrediction, ...]:
    """Score every sample with the zero-data heuristic model.

    No folds are needed: the prior never sees a label, so evaluating it on the
    whole corpus is already out-of-sample. This is Baseline D in
    ``docs/EVALUATION_PROTOCOL.md`` §5, and comparing its Brier score against
    the fitted model's is the evidence for ADR-022.
    """

    if not isinstance(dataset, CorpusDataset):
        raise CorpusFittingError("dataset must be a CorpusDataset")
    scorers = prior_family_scorers(
        dataset.families,
        base_rate=base_rate,
        prior_scale=prior_scale,
        prior_stddev=prior_stddev,
    )
    predictions: list[OutOfFoldPrediction] = []
    for sample in dataset.samples:
        scorer = scorers.get(sample.family)
        if scorer is None:
            raise CorpusFittingError(
                f"no heuristic prior for family {sample.family!r}"
            )
        scored = scorer.probability(sample_observations(sample))
        predictions.append(
            OutOfFoldPrediction(
                sample=sample,
                probability=scored.probability,
                logit_mean=scored.logit_mean,
            )
        )
    return tuple(predictions)


def base_rate_brier_score(dataset: CorpusDataset) -> float:
    """Brier score of always predicting the corpus base rate.

    The floor any useful model must beat. A scorer that loses to this is not
    merely weak, it is worse than a constant.
    """

    if not dataset.samples:
        raise CorpusFittingError("base rate needs at least one sample")
    positives = sum(1 for sample in dataset.samples if sample.label)
    rate = positives / len(dataset.samples)
    return rate * (1.0 - rate)


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    """Layer 1 quality, measured out-of-fold."""

    samples: int
    positives: int
    brier_score: float
    expected_calibration_error: float
    bins: tuple[tuple[float, float, float, int], ...]

    def as_mapping(self) -> dict[str, object]:
        return {
            "samples": self.samples,
            "positives": self.positives,
            "brier_score": self.brier_score,
            "expected_calibration_error": self.expected_calibration_error,
            "reliability_bins": [
                {
                    "bin_lower": lower,
                    "mean_predicted": predicted,
                    "observed_frequency": observed,
                    "count": count,
                }
                for lower, predicted, observed, count in self.bins
            ],
        }


def evaluate_calibration(
    predictions: Sequence[OutOfFoldPrediction],
    *,
    bin_count: int = 10,
) -> CalibrationReport:
    """Brier score, expected calibration error, and a reliability table."""

    if isinstance(bin_count, bool) or not isinstance(bin_count, int):
        raise CorpusFittingError("bin_count must be an integer")
    if bin_count <= 0:
        raise CorpusFittingError("bin_count must be positive")
    scored = tuple(predictions)
    if not scored:
        raise CorpusFittingError("calibration evaluation needs predictions")

    total = len(scored)
    brier = (
        sum(
            (item.probability - (1.0 if item.sample.label else 0.0)) ** 2
            for item in scored
        )
        / total
    )

    buckets: list[list[OutOfFoldPrediction]] = [[] for _index in range(bin_count)]
    for item in scored:
        index = min(int(item.probability * bin_count), bin_count - 1)
        buckets[index].append(item)

    bins: list[tuple[float, float, float, int]] = []
    error = 0.0
    for index, bucket in enumerate(buckets):
        if not bucket:
            continue
        mean_predicted = sum(entry.probability for entry in bucket) / len(bucket)
        observed = sum(1 for entry in bucket if entry.sample.label) / len(bucket)
        error += (len(bucket) / total) * abs(mean_predicted - observed)
        bins.append((index / bin_count, mean_predicted, observed, len(bucket)))

    return CalibrationReport(
        samples=total,
        positives=sum(1 for item in scored if item.sample.label),
        brier_score=brier,
        expected_calibration_error=error,
        bins=tuple(bins),
    )


def scorers_as_mapping(
    scorers: Mapping[str, CalibratedScorer],
) -> dict[str, object]:
    """Serialize a family-to-model mapping for on-disk storage."""

    return {
        "fitting_version": CORPUS_FITTING_VERSION,
        "models": {
            family: scorer.as_mapping()
            for family, scorer in sorted(scorers.items())
        },
    }


def scorers_from_mapping(
    payload: Mapping[str, object],
) -> dict[str, CalibratedScorer]:
    """Rebuild a family-to-model mapping, re-running every invariant check."""

    if not isinstance(payload, Mapping):
        raise CorpusFittingError("model payload must be a mapping")
    version = payload.get("fitting_version")
    if version != CORPUS_FITTING_VERSION:
        raise CorpusFittingError(f"unsupported fitting version: {version!r}")
    models = payload.get("models")
    if not isinstance(models, Mapping):
        raise CorpusFittingError("model payload must contain a 'models' object")
    rebuilt: dict[str, CalibratedScorer] = {}
    for family, model in models.items():
        if not isinstance(model, Mapping):
            raise CorpusFittingError(f"model for {family!r} must be an object")
        scorer = CalibratedScorer.from_mapping(model)
        if scorer.feature_space.family != family:
            raise CorpusFittingError(
                f"model stored under {family!r} declares family "
                f"{scorer.feature_space.family!r}"
            )
        rebuilt[str(family)] = scorer
    return rebuilt
