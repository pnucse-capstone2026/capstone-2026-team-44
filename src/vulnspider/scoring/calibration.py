"""Bayesian logistic calibration of candidate scores (decision-layer Layer 1).

``scoring/engine.py`` produces an uncalibrated ``RankScore``: a weighted sum
whose weights were chosen by hand and whose maximum differs per family (0..75
for SQLi, 0..45 for Reflected XSS, 0..75 for BAC). ADR-010 compared families by
dividing each raw score by its own maximum, which is a selection convenience
rather than a statement anyone can defend: nothing makes ``45/75`` and ``27/45``
commensurable.

This module replaces that quotient with a calibrated probability
``P(vulnerable | observed evidence)``. Probabilities from different families are
comparable by construction, which is what the decision layer needs in order to
compute an expected utility at all.

The existing hand-tuned weights are not discarded. They are rescaled into logit
space and used as the **mean of a Gaussian prior** over the model weights
(:func:`heuristic_prior_for`). Three consequences follow:

* With no training data, :meth:`CalibratedScorer.from_prior` gives a
  ``logit_mean`` that is an exact affine transform of the heuristic
  ``RankScore``: ``logit_mean = logit(base_rate) + RankScore / prior_scale``.
  Ordering by ``logit_mean`` is therefore ordering by the heuristic, exactly,
  and adopting the model changes nothing before a corpus exists.
* With training data, the posterior moves off the heuristic only as far as the
  evidence justifies, which is the behavior wanted from a small corpus.
* The rule-based scorer is describable as the zero-data special case of this
  model rather than as a rejected alternative.

``probability`` is deliberately *not* a monotone function of ``logit_mean``. It
integrates over the weight posterior rather than plugging in the MAP point, so
a score is damped toward the base rate in proportion to how uncertain the
weights it leans on actually are: ``Var(logit) = Var(intercept) + Σ fᵢ²·Var(wᵢ)``.

Under the untrained prior every weight is equally uncertain and that variance
only tracks how many features fired, which carries no information. It becomes
meaningful after fitting, where a weight the corpus pins down precisely gets a
small variance and one the corpus barely constrains stays near its prior width
-- so a score resting on a well-understood signal survives damping while an
equal score resting on a barely-measured one is pulled back toward the base
rate. That is the difference from the heuristic that lets the decision layer
tell a confident 0.9 from a speculative one.

Consumers wanting the pure heuristic order should read ``logit_mean``;
consumers computing an expected utility want ``probability``.

Missing features
----------------
A missing feature contributes nothing to the logit sum. That is the same
discipline ``engine.py`` already applies (``contribution=None``, excluded from
the total) and in log-odds space it reads correctly: absent evidence leaves the
posterior where the prior put it.

The honest limitation: a linear model gives an observed ``0.0`` the same zero
logit contribution as an unobserved feature. The two are distinguished in
:class:`CalibrationEvidence` (``observed``) and in
``CalibratedProbability.observed_feature_count`` so downstream consumers and
the evaluation harness can tell them apart, but they are not distinguished in
the score itself. Separating them requires per-feature missingness indicators,
which needs more labeled data than this project currently has.

Everything here is standard library only (``pyproject.toml`` declares
``dependencies = []``). The design matrix is at most a dozen columns wide, so a
dense Cholesky solve is entirely adequate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import exp, isfinite, log, log1p, pi, sqrt
from typing import Any

from vulnspider.access.scoring import ACCESS_TERMS
from vulnspider.domain import FeatureObservation
from vulnspider.features import (
    REFLECTION_COUNT_NORM,
    SAFE_HTML_ENCODING_DETECTED,
)
from vulnspider.scoring.engine import SQLI_TERMS, XSS_TERMS

CALIBRATION_MODEL_VERSION = "bayesian-logistic-v1"
NAIVE_BAYES_MODEL_VERSION = "naive-bayes-llr-v1"

FAMILY_SQLI = "SQLI"
FAMILY_REFLECTED_XSS = "REFLECTED_XSS"
FAMILY_BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"

# Heuristic weights live on a 0..100 "rank score" scale. One logit is worth
# this many of those units when they are read as prior evidence strength. At
# 10.0 the strongest current term (SQL error pattern, weight 35) becomes a
# 3.5-logit prior, i.e. roughly a 30:1 likelihood ratio -- strong but not
# absolute, which matches how that signal actually behaves.
DEFAULT_PRIOR_SCALE = 10.0

# Prior standard deviation on each weight, in logits. Wide enough that a few
# hundred labeled samples can overrule the heuristic, tight enough that a
# handful cannot.
DEFAULT_PRIOR_STDDEV = 1.5

# P(vulnerable) for a candidate with no observed evidence.
DEFAULT_BASE_RATE = 0.15

_MAX_PROBABILITY = 1.0 - 1e-12
_MIN_PROBABILITY = 1e-12
_LOGITS_PER_DECIBAN = 10.0 / log(10.0)

# Backtracking budget per Newton step. Each halving costs one log-posterior
# evaluation, and 40 halvings reduce the step below floating-point relevance.
_MAX_LINE_SEARCH_HALVINGS = 40

# Floor on mu(1-mu) so the information matrix stays positive definite when the
# fit saturates. Line search, not this floor, is what prevents divergence.
_MINIMUM_WORKING_VARIANCE = 1e-10

# Features that enter the calibrated model but not the heuristic engine's
# `RankScore`. The rule-based scoring path was retired, so a feature only needs a
# heuristic term to seed the fit's prior; keeping these out of `scoring/engine.py`
# avoids a negative-weight penalty perturbing `selection_priority`, which still
# seeds the handoff order. Weights follow `docs/FEATURE_SCHEMA.md` §7 and are
# just prior means -- the corpus fits the real value (ADR-031).
_CALIBRATION_ONLY_TERMS: dict[str, tuple[tuple[str, float], ...]] = {
    FAMILY_REFLECTED_XSS: (
        (SAFE_HTML_ENCODING_DETECTED, -30.0),
        (REFLECTION_COUNT_NORM, 10.0),
    ),
}

HEURISTIC_TERMS: dict[str, tuple[tuple[str, float], ...]] = {
    FAMILY_SQLI: tuple((term.feature_name, term.weight) for term in SQLI_TERMS)
    + _CALIBRATION_ONLY_TERMS.get(FAMILY_SQLI, ()),
    FAMILY_REFLECTED_XSS: tuple(
        (term.feature_name, term.weight) for term in XSS_TERMS
    )
    + _CALIBRATION_ONLY_TERMS.get(FAMILY_REFLECTED_XSS, ()),
    FAMILY_BROKEN_ACCESS_CONTROL: tuple(
        (term.feature_name, term.weight) for term in ACCESS_TERMS
    )
    + _CALIBRATION_ONLY_TERMS.get(FAMILY_BROKEN_ACCESS_CONTROL, ()),
}


class CalibrationError(ValueError):
    """Raised when a calibrated model cannot be built or applied honestly."""


@dataclass(frozen=True, slots=True)
class CalibrationFeatureSpace:
    """The fixed, ordered feature list one family's weights are indexed by."""

    family: str
    feature_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.family:
            raise CalibrationError("family must not be empty")
        if not self.feature_names:
            raise CalibrationError("feature space must contain at least one feature")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise CalibrationError("feature space must not repeat a feature name")
        for name in self.feature_names:
            if not name:
                raise CalibrationError("feature names must not be empty")

    @property
    def dimension(self) -> int:
        return len(self.feature_names)

    def index_of(self, feature_name: str) -> int:
        try:
            return self.feature_names.index(feature_name)
        except ValueError as exc:
            raise CalibrationError(
                f"feature {feature_name!r} is not in the {self.family} feature space"
            ) from exc


@dataclass(frozen=True, slots=True)
class LogisticPrior:
    """Gaussian prior over the intercept and weights, in logit space."""

    feature_space: CalibrationFeatureSpace
    intercept_mean: float
    intercept_stddev: float
    weight_means: tuple[float, ...]
    weight_stddevs: tuple[float, ...]

    def __post_init__(self) -> None:
        dimension = self.feature_space.dimension
        if len(self.weight_means) != dimension:
            raise CalibrationError("weight_means must match the feature space size")
        if len(self.weight_stddevs) != dimension:
            raise CalibrationError("weight_stddevs must match the feature space size")
        for value in (self.intercept_mean, *self.weight_means):
            if not isfinite(value):
                raise CalibrationError("prior means must be finite")
        for value in (self.intercept_stddev, *self.weight_stddevs):
            if not isfinite(value) or value <= 0.0:
                raise CalibrationError("prior standard deviations must be positive")


def heuristic_prior_for(
    family: str,
    terms: Sequence[tuple[str, float]],
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> LogisticPrior:
    """Build the prior that encodes one family's existing heuristic weights."""

    if not terms:
        raise CalibrationError("a heuristic prior needs at least one scoring term")
    if not 0.0 < base_rate < 1.0:
        raise CalibrationError("base_rate must be strictly between 0 and 1")
    if not isfinite(prior_scale) or prior_scale <= 0.0:
        raise CalibrationError("prior_scale must be positive")
    if not isfinite(prior_stddev) or prior_stddev <= 0.0:
        raise CalibrationError("prior_stddev must be positive")

    feature_space = CalibrationFeatureSpace(
        family=family,
        feature_names=tuple(name for name, _weight in terms),
    )
    return LogisticPrior(
        feature_space=feature_space,
        intercept_mean=_logit(base_rate),
        intercept_stddev=prior_stddev,
        weight_means=tuple(weight / prior_scale for _name, weight in terms),
        weight_stddevs=tuple(prior_stddev for _term in terms),
    )


def heuristic_prior_for_family(
    family: str,
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    prior_scale: float = DEFAULT_PRIOR_SCALE,
    prior_stddev: float = DEFAULT_PRIOR_STDDEV,
) -> LogisticPrior:
    """Build the prior for a known family label used by the handoff contract."""

    terms = HEURISTIC_TERMS.get(family)
    if terms is None:
        known = ", ".join(sorted(HEURISTIC_TERMS))
        raise CalibrationError(f"unknown family {family!r}; known families: {known}")
    return heuristic_prior_for(
        family,
        terms,
        base_rate=base_rate,
        prior_scale=prior_scale,
        prior_stddev=prior_stddev,
    )


@dataclass(frozen=True, slots=True)
class TrainingSample:
    """One labeled candidate: its observed features and its ground truth.

    ``group`` carries the leakage-control key ``docs/EVALUATION_PROTOCOL.md``
    requires (application or route family). Only observed features belong in
    ``features``; omit anything that was not measured rather than passing 0.0.
    """

    features: Mapping[str, float]
    label: bool
    group: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.label, bool):
            raise CalibrationError("training label must be a bool")
        for name, value in self.features.items():
            if not name:
                raise CalibrationError("training feature names must not be empty")
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise CalibrationError(f"training feature {name!r} must be numeric")
            if not isfinite(float(value)):
                raise CalibrationError(f"training feature {name!r} must be finite")


@dataclass(frozen=True, slots=True)
class CalibrationEvidence:
    """One feature's signed contribution to the log-odds of vulnerability."""

    feature_name: str
    feature_value: float | None
    weight: float
    logit_contribution: float | None
    deciban_contribution: float | None
    observed: bool
    reason: str

    def __post_init__(self) -> None:
        if self.observed:
            if self.feature_value is None or self.logit_contribution is None:
                raise CalibrationError(
                    "observed evidence must carry a value and a contribution"
                )
        elif (
            self.feature_value is not None
            or self.logit_contribution is not None
            or self.deciban_contribution is not None
        ):
            raise CalibrationError(
                "unobserved evidence must not carry a value or contribution"
            )


@dataclass(frozen=True, slots=True, init=False)
class CalibratedProbability:
    """A calibrated ``P(vulnerable | evidence)`` and the evidence behind it.

    ``logit_variance`` is the Laplace-approximated posterior variance of the
    log-odds. It is what the value-of-information layer uses to tell "0.5
    because the evidence is balanced" apart from "0.5 because nothing is
    known", which are very different situations for a budget allocator.
    """

    family: str
    model_version: str
    probability: float
    logit_mean: float
    logit_variance: float
    observed_feature_count: int
    evidence: tuple[CalibrationEvidence, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "CalibratedProbability is produced only by CalibratedScorer.probability()"
        )

    @classmethod
    def _from_parts(
        cls,
        *,
        family: str,
        model_version: str,
        probability: float,
        logit_mean: float,
        logit_variance: float,
        observed_feature_count: int,
        evidence: tuple[CalibrationEvidence, ...],
    ) -> CalibratedProbability:
        instance = object.__new__(cls)
        object.__setattr__(instance, "family", family)
        object.__setattr__(instance, "model_version", model_version)
        object.__setattr__(instance, "probability", probability)
        object.__setattr__(instance, "logit_mean", logit_mean)
        object.__setattr__(instance, "logit_variance", logit_variance)
        object.__setattr__(
            instance, "observed_feature_count", observed_feature_count
        )
        object.__setattr__(instance, "evidence", evidence)
        instance.validate()
        return instance

    def validate(self) -> None:
        if not 0.0 < self.probability < 1.0:
            raise CalibrationError("probability must lie strictly inside (0, 1)")
        if not isfinite(self.logit_mean):
            raise CalibrationError("logit mean must be finite")
        if not isfinite(self.logit_variance) or self.logit_variance < 0.0:
            raise CalibrationError("logit variance must be finite and non-negative")
        observed = sum(1 for item in self.evidence if item.observed)
        if observed != self.observed_feature_count:
            raise CalibrationError(
                "observed_feature_count must match the observed evidence"
            )


@dataclass(frozen=True, slots=True, init=False)
class CalibratedScorer:
    """Posterior weights for one family, ready to score a feature vector."""

    model_version: str
    feature_space: CalibrationFeatureSpace
    intercept: float
    intercept_variance: float
    weights: tuple[float, ...]
    weight_variances: tuple[float, ...]
    training_samples: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "CalibratedScorer is produced by from_prior() or fit_calibrated_scorer()"
        )

    @classmethod
    def _from_parts(
        cls,
        *,
        feature_space: CalibrationFeatureSpace,
        intercept: float,
        intercept_variance: float,
        weights: tuple[float, ...],
        weight_variances: tuple[float, ...],
        training_samples: int,
    ) -> CalibratedScorer:
        instance = object.__new__(cls)
        object.__setattr__(instance, "model_version", CALIBRATION_MODEL_VERSION)
        object.__setattr__(instance, "feature_space", feature_space)
        object.__setattr__(instance, "intercept", intercept)
        object.__setattr__(instance, "intercept_variance", intercept_variance)
        object.__setattr__(instance, "weights", weights)
        object.__setattr__(instance, "weight_variances", weight_variances)
        object.__setattr__(instance, "training_samples", training_samples)
        instance.validate()
        return instance

    @classmethod
    def from_prior(cls, prior: LogisticPrior) -> CalibratedScorer:
        """The zero-data scorer: the posterior is exactly the prior.

        Under this scorer ``logit_mean`` is an affine transform of the
        heuristic ``RankScore`` the prior was built from, so ranking by
        ``logit_mean`` reproduces the heuristic order exactly before any
        corpus exists. ``probability`` additionally damps by how much evidence
        was observed and therefore may reorder -- see the module docstring.
        """

        if not isinstance(prior, LogisticPrior):
            raise CalibrationError("prior must be a LogisticPrior")
        return cls._from_parts(
            feature_space=prior.feature_space,
            intercept=prior.intercept_mean,
            intercept_variance=prior.intercept_stddev**2,
            weights=tuple(prior.weight_means),
            weight_variances=tuple(value**2 for value in prior.weight_stddevs),
            training_samples=0,
        )

    def validate(self) -> None:
        dimension = self.feature_space.dimension
        if len(self.weights) != dimension:
            raise CalibrationError("weights must match the feature space size")
        if len(self.weight_variances) != dimension:
            raise CalibrationError("weight variances must match the feature space size")
        for value in (self.intercept, *self.weights):
            if not isfinite(value):
                raise CalibrationError("model parameters must be finite")
        for value in (self.intercept_variance, *self.weight_variances):
            if not isfinite(value) or value < 0.0:
                raise CalibrationError("parameter variances must be non-negative")
        if isinstance(self.training_samples, bool):
            raise CalibrationError("training_samples must be an integer")
        if not isinstance(self.training_samples, int) or self.training_samples < 0:
            raise CalibrationError("training_samples must be a non-negative integer")

    def as_mapping(self) -> dict[str, Any]:
        """Serialize the fitted model, including its posterior variances."""

        return {
            "model_version": self.model_version,
            "family": self.feature_space.family,
            "feature_names": list(self.feature_space.feature_names),
            "intercept": self.intercept,
            "intercept_variance": self.intercept_variance,
            "weights": list(self.weights),
            "weight_variances": list(self.weight_variances),
            "training_samples": self.training_samples,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> CalibratedScorer:
        """Rebuild a fitted model, re-running every invariant check."""

        if not isinstance(payload, Mapping):
            raise CalibrationError("calibrated model payload must be a mapping")
        version = payload.get("model_version")
        if version != CALIBRATION_MODEL_VERSION:
            raise CalibrationError(f"unsupported model version: {version!r}")
        for field_name in (
            "family",
            "feature_names",
            "intercept",
            "intercept_variance",
            "weights",
            "weight_variances",
            "training_samples",
        ):
            if field_name not in payload:
                raise CalibrationError(f"calibrated model is missing {field_name!r}")
        feature_space = CalibrationFeatureSpace(
            family=str(payload["family"]),
            feature_names=tuple(str(name) for name in payload["feature_names"]),
        )
        return cls._from_parts(
            feature_space=feature_space,
            intercept=float(payload["intercept"]),
            intercept_variance=float(payload["intercept_variance"]),
            weights=tuple(float(value) for value in payload["weights"]),
            weight_variances=tuple(
                float(value) for value in payload["weight_variances"]
            ),
            training_samples=int(payload["training_samples"]),
        )

    def probability(
        self,
        features: Mapping[str, FeatureObservation],
    ) -> CalibratedProbability:
        """Score one family's feature observations into a calibrated probability."""

        if not isinstance(features, Mapping):
            raise CalibrationError("features must be a mapping of FeatureObservation")

        logit_mean = self.intercept
        logit_variance = self.intercept_variance
        evidence: list[CalibrationEvidence] = []
        observed_count = 0

        for index, feature_name in enumerate(self.feature_space.feature_names):
            weight = self.weights[index]
            observation = features.get(feature_name)
            value = _observed_value(feature_name, observation)
            if value is None:
                evidence.append(
                    CalibrationEvidence(
                        feature_name=feature_name,
                        feature_value=None,
                        weight=weight,
                        logit_contribution=None,
                        deciban_contribution=None,
                        observed=False,
                        reason=_missing_reason(observation),
                    )
                )
                continue

            contribution = weight * value
            observed_count += 1
            logit_mean += contribution
            logit_variance += self.weight_variances[index] * value * value
            evidence.append(
                CalibrationEvidence(
                    feature_name=feature_name,
                    feature_value=value,
                    weight=weight,
                    logit_contribution=contribution,
                    deciban_contribution=contribution * _LOGITS_PER_DECIBAN,
                    observed=True,
                    reason=(
                        f"Observed {feature_name}={value:g} shifts the log-odds of "
                        f"{self.feature_space.family} by {contribution:+.3f} logits."
                    ),
                )
            )

        return CalibratedProbability._from_parts(
            family=self.feature_space.family,
            model_version=self.model_version,
            probability=_probit_approximated_mean(logit_mean, logit_variance),
            logit_mean=logit_mean,
            logit_variance=logit_variance,
            observed_feature_count=observed_count,
            evidence=tuple(evidence),
        )


def fit_calibrated_scorer(
    samples: Sequence[TrainingSample],
    prior: LogisticPrior,
    *,
    max_iterations: int = 100,
    tolerance: float = 1e-9,
) -> CalibratedScorer:
    """Fit MAP weights by damped Newton, then take a Laplace approximation.

    The prior's precision is the ridge term, so the fit is well posed even when
    the corpus is small, separable, or missing a feature entirely -- all three
    of which happen with a handful of deliberately vulnerable training
    applications. With ``samples`` empty this returns
    :meth:`CalibratedScorer.from_prior` unchanged.

    The Newton step is damped by backtracking line search on the log posterior.
    Without it the fit diverges under quasi-complete separation, which is the
    normal case here rather than an edge case: if no vulnerable candidate ever
    shows ``marker_reflected = 0``, the undamped step drives that weight toward
    infinity, the working variance ``mu(1-mu)`` collapses, the information
    matrix degenerates to the prior precision alone, and each iteration
    overshoots further than the last. Requiring every accepted step to increase
    the log posterior removes the failure entirely.
    """

    if not isinstance(prior, LogisticPrior):
        raise CalibrationError("prior must be a LogisticPrior")
    if isinstance(max_iterations, bool) or not isinstance(max_iterations, int):
        raise CalibrationError("max_iterations must be an integer")
    if max_iterations <= 0:
        raise CalibrationError("max_iterations must be positive")
    if not isfinite(tolerance) or tolerance <= 0.0:
        raise CalibrationError("tolerance must be a positive finite number")

    training = tuple(samples)
    for sample in training:
        if not isinstance(sample, TrainingSample):
            raise CalibrationError("samples must contain TrainingSample objects")
    if not training:
        return CalibratedScorer.from_prior(prior)

    feature_space = prior.feature_space
    dimension = feature_space.dimension + 1
    design = [_design_row(sample.features, feature_space) for sample in training]
    labels = [1.0 if sample.label else 0.0 for sample in training]

    prior_mean = [prior.intercept_mean, *prior.weight_means]
    precision = [
        1.0 / (prior.intercept_stddev**2),
        *(1.0 / (stddev**2) for stddev in prior.weight_stddevs),
    ]

    parameters = list(prior_mean)
    objective = _log_posterior(parameters, design, labels, prior_mean, precision)
    hessian = _information_matrix(parameters, design, precision)
    for _iteration in range(max_iterations):
        gradient = _log_posterior_gradient(
            parameters,
            design,
            labels,
            prior_mean,
            precision,
        )
        hessian = _information_matrix(parameters, design, precision)
        step = _solve_symmetric_positive_definite(hessian, gradient)

        scale = 1.0
        accepted = False
        for _attempt in range(_MAX_LINE_SEARCH_HALVINGS):
            trial = [
                parameters[j] + scale * step[j] for j in range(dimension)
            ]
            trial_objective = _log_posterior(
                trial,
                design,
                labels,
                prior_mean,
                precision,
            )
            if trial_objective >= objective:
                parameters = trial
                accepted = True
                break
            scale *= 0.5
        if not accepted:
            # No downhill-free step remains; the current point is the MAP to
            # within floating-point resolution.
            break

        new_objective = _log_posterior(
            parameters,
            design,
            labels,
            prior_mean,
            precision,
        )
        converged = (
            max(abs(scale * value) for value in step) < tolerance
            or abs(new_objective - objective) < tolerance
        )
        objective = new_objective
        if converged:
            break

    hessian = _information_matrix(parameters, design, precision)
    covariance_diagonal = _inverse_diagonal(hessian)
    return CalibratedScorer._from_parts(
        feature_space=feature_space,
        intercept=parameters[0],
        intercept_variance=covariance_diagonal[0],
        weights=tuple(parameters[1:]),
        weight_variances=tuple(covariance_diagonal[1:]),
        training_samples=len(training),
    )


@dataclass(frozen=True, slots=True, init=False)
class NaiveBayesRates:
    """Smoothed class-conditional feature rates for one family.

    Kept alongside the logistic model for two reasons. It is the ablation arm
    ``docs/EVALUATION_PROTOCOL.md`` calls for -- it assumes conditional
    independence, which ``status_code_changed`` and
    ``response_length_diff_ratio`` visibly violate, so the gap between the two
    models measures how much that violation costs. And its rates are exactly
    the ``P(observation | state)`` likelihoods the value-of-information layer
    needs, which is what lets Layer 1 and Layer 2 compose.
    """

    model_version: str
    feature_space: CalibrationFeatureSpace
    base_rate: float
    positive_rates: tuple[float, ...]
    negative_rates: tuple[float, ...]
    training_samples: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("NaiveBayesRates is produced only by fit_naive_bayes_llr()")

    @classmethod
    def _from_parts(
        cls,
        *,
        feature_space: CalibrationFeatureSpace,
        base_rate: float,
        positive_rates: tuple[float, ...],
        negative_rates: tuple[float, ...],
        training_samples: int,
    ) -> NaiveBayesRates:
        instance = object.__new__(cls)
        object.__setattr__(instance, "model_version", NAIVE_BAYES_MODEL_VERSION)
        object.__setattr__(instance, "feature_space", feature_space)
        object.__setattr__(instance, "base_rate", base_rate)
        object.__setattr__(instance, "positive_rates", positive_rates)
        object.__setattr__(instance, "negative_rates", negative_rates)
        object.__setattr__(instance, "training_samples", training_samples)
        instance.validate()
        return instance

    def validate(self) -> None:
        dimension = self.feature_space.dimension
        if len(self.positive_rates) != dimension:
            raise CalibrationError("positive rates must match the feature space size")
        if len(self.negative_rates) != dimension:
            raise CalibrationError("negative rates must match the feature space size")
        if not 0.0 < self.base_rate < 1.0:
            raise CalibrationError("base rate must lie strictly inside (0, 1)")
        for value in (*self.positive_rates, *self.negative_rates):
            if not 0.0 < value < 1.0:
                raise CalibrationError("smoothed rates must lie strictly inside (0, 1)")

    def rates_for(self, feature_name: str) -> tuple[float, float]:
        """Return ``(P(f=1 | vulnerable), P(f=1 | not vulnerable))``."""

        index = self.feature_space.index_of(feature_name)
        return self.positive_rates[index], self.negative_rates[index]

    def log_likelihood_ratio(self, feature_name: str) -> float:
        """Weight of evidence, in logits, for observing this feature."""

        positive, negative = self.rates_for(feature_name)
        return log(positive / negative)

    def as_prior(
        self,
        *,
        prior_stddev: float = DEFAULT_PRIOR_STDDEV,
    ) -> LogisticPrior:
        """Reuse the learned log-likelihood ratios as a logistic prior mean."""

        return LogisticPrior(
            feature_space=self.feature_space,
            intercept_mean=_logit(self.base_rate),
            intercept_stddev=prior_stddev,
            weight_means=tuple(
                self.log_likelihood_ratio(name)
                for name in self.feature_space.feature_names
            ),
            weight_stddevs=tuple(
                prior_stddev for _name in self.feature_space.feature_names
            ),
        )


def fit_naive_bayes_llr(
    samples: Sequence[TrainingSample],
    feature_space: CalibrationFeatureSpace,
    *,
    smoothing_alpha: float = 1.0,
    smoothing_beta: float = 1.0,
) -> NaiveBayesRates:
    """Estimate Beta-smoothed class-conditional rates for each feature.

    Feature values live in ``[0, 1]``. Binary features give the usual Bernoulli
    rate; graded features (``response_length_diff_ratio``) contribute their
    value as a soft count, which is the standard relaxation and keeps a strong
    partial signal from being rounded away.
    """

    if not isinstance(feature_space, CalibrationFeatureSpace):
        raise CalibrationError("feature_space must be a CalibrationFeatureSpace")
    for value in (smoothing_alpha, smoothing_beta):
        if not isfinite(value) or value <= 0.0:
            raise CalibrationError("smoothing parameters must be positive")

    training = tuple(samples)
    for sample in training:
        if not isinstance(sample, TrainingSample):
            raise CalibrationError("samples must contain TrainingSample objects")

    positive_totals = [0.0] * feature_space.dimension
    negative_totals = [0.0] * feature_space.dimension
    positive_counts = [0] * feature_space.dimension
    negative_counts = [0] * feature_space.dimension
    positives = 0

    for sample in training:
        if sample.label:
            positives += 1
        for index, feature_name in enumerate(feature_space.feature_names):
            raw = sample.features.get(feature_name)
            if raw is None:
                continue
            value = min(max(float(raw), 0.0), 1.0)
            if sample.label:
                positive_totals[index] += value
                positive_counts[index] += 1
            else:
                negative_totals[index] += value
                negative_counts[index] += 1

    denominator = len(training) + smoothing_alpha + smoothing_beta
    base_rate = (positives + smoothing_alpha) / denominator
    return NaiveBayesRates._from_parts(
        feature_space=feature_space,
        base_rate=base_rate,
        positive_rates=tuple(
            (positive_totals[index] + smoothing_alpha)
            / (positive_counts[index] + smoothing_alpha + smoothing_beta)
            for index in range(feature_space.dimension)
        ),
        negative_rates=tuple(
            (negative_totals[index] + smoothing_alpha)
            / (negative_counts[index] + smoothing_alpha + smoothing_beta)
            for index in range(feature_space.dimension)
        ),
        training_samples=len(training),
    )


def _observed_value(
    feature_name: str,
    observation: FeatureObservation | None,
) -> float | None:
    if observation is None:
        return None
    if not isinstance(observation, FeatureObservation):
        raise CalibrationError(f"{feature_name} must be a FeatureObservation")
    if observation.name != feature_name:
        raise CalibrationError(
            f"feature key {feature_name!r} does not match observation name "
            f"{observation.name!r}"
        )
    if not observation.observed:
        return None
    value = observation.value
    if value is None or not isinstance(value, bool | int | float):
        raise CalibrationError(f"observed feature {feature_name} must be numeric")
    numeric = float(value)
    if not isfinite(numeric):
        raise CalibrationError(f"observed feature {feature_name} must be finite")
    if not 0.0 <= numeric <= 1.0:
        raise CalibrationError(
            f"observed feature {feature_name} must be between 0.0 and 1.0"
        )
    return numeric


def _missing_reason(observation: FeatureObservation | None) -> str:
    if observation is None:
        return "Feature is absent from this observation; the log-odds are unchanged."
    detail = observation.details.get("reason")
    context = f" ({detail})" if isinstance(detail, str) else ""
    return (
        f"Feature is unavailable{context} from {observation.source}; "
        "the log-odds are unchanged."
    )


def _design_row(
    features: Mapping[str, float],
    feature_space: CalibrationFeatureSpace,
) -> list[float]:
    row = [1.0]
    for feature_name in feature_space.feature_names:
        raw = features.get(feature_name)
        row.append(0.0 if raw is None else float(raw))
    return row


def _logit(probability: float) -> float:
    clamped = min(max(probability, _MIN_PROBABILITY), _MAX_PROBABILITY)
    return log(clamped / (1.0 - clamped))


def _sigmoid(value: float) -> float:
    if value >= 0.0:
        return 1.0 / (1.0 + exp(-value))
    exponential = exp(value)
    return exponential / (1.0 + exponential)


def _probit_approximated_mean(mean: float, variance: float) -> float:
    """MacKay's approximation to ``E[sigmoid(x)]`` for ``x ~ N(mean, variance)``.

    Averaging over the weight posterior instead of plugging in the MAP point
    pulls uncertain scores toward the base rate, which is the behavior the
    budget allocator needs: a 0.9 backed by one observed feature should not
    outrank a 0.85 backed by four.
    """

    if variance <= 0.0:
        return min(max(_sigmoid(mean), _MIN_PROBABILITY), _MAX_PROBABILITY)
    damped = mean / sqrt(1.0 + pi * variance / 8.0)
    return min(max(_sigmoid(damped), _MIN_PROBABILITY), _MAX_PROBABILITY)


def _dot(left: Sequence[float], right: Sequence[float]) -> float:
    return sum(a * b for a, b in zip(left, right, strict=True))


def _log_sum_exp_zero(value: float) -> float:
    """``log(1 + exp(value))`` without overflowing for large ``value``."""

    if value > 0.0:
        return value + log1p(exp(-value))
    return log1p(exp(value))


def _log_posterior(
    parameters: Sequence[float],
    design: Sequence[Sequence[float]],
    labels: Sequence[float],
    prior_mean: Sequence[float],
    precision: Sequence[float],
) -> float:
    """Log likelihood plus log prior, up to an additive constant."""

    total = 0.0
    for row, label in zip(design, labels, strict=True):
        linear = _dot(parameters, row)
        total += label * linear - _log_sum_exp_zero(linear)
    for value, mean, weight in zip(parameters, prior_mean, precision, strict=True):
        deviation = value - mean
        total -= 0.5 * weight * deviation * deviation
    return total


def _log_posterior_gradient(
    parameters: Sequence[float],
    design: Sequence[Sequence[float]],
    labels: Sequence[float],
    prior_mean: Sequence[float],
    precision: Sequence[float],
) -> list[float]:
    gradient = [
        -precision[index] * (parameters[index] - prior_mean[index])
        for index in range(len(parameters))
    ]
    for row, label in zip(design, labels, strict=True):
        residual = label - _sigmoid(_dot(parameters, row))
        for index, value in enumerate(row):
            gradient[index] += residual * value
    return gradient


def _information_matrix(
    parameters: Sequence[float],
    design: Sequence[Sequence[float]],
    precision: Sequence[float],
) -> list[list[float]]:
    """``X' W X + Lambda``, the negative Hessian of the log posterior."""

    dimension = len(parameters)
    matrix = [
        [precision[row] if row == column else 0.0 for column in range(dimension)]
        for row in range(dimension)
    ]
    for row in design:
        mean = _sigmoid(_dot(parameters, row))
        variance = max(mean * (1.0 - mean), _MINIMUM_WORKING_VARIANCE)
        for index in range(dimension):
            weighted = variance * row[index]
            for column in range(index, dimension):
                matrix[index][column] += weighted * row[column]
    for index in range(dimension):
        for column in range(index):
            matrix[index][column] = matrix[column][index]
    return matrix


def _identity(dimension: int) -> list[list[float]]:
    return [
        [1.0 if row == column else 0.0 for column in range(dimension)]
        for row in range(dimension)
    ]


def _cholesky(matrix: Sequence[Sequence[float]]) -> list[list[float]]:
    dimension = len(matrix)
    lower = [[0.0] * dimension for _row in range(dimension)]
    for row in range(dimension):
        for column in range(row + 1):
            total = matrix[row][column] - sum(
                lower[row][k] * lower[column][k] for k in range(column)
            )
            if row == column:
                if total <= 0.0:
                    raise CalibrationError(
                        "information matrix is not positive definite"
                    )
                lower[row][column] = sqrt(total)
            else:
                lower[row][column] = total / lower[column][column]
    return lower


def _cholesky_solve(
    lower: Sequence[Sequence[float]],
    vector: Sequence[float],
) -> list[float]:
    dimension = len(lower)
    forward = [0.0] * dimension
    for row in range(dimension):
        total = vector[row] - sum(lower[row][k] * forward[k] for k in range(row))
        forward[row] = total / lower[row][row]
    solution = [0.0] * dimension
    for row in reversed(range(dimension)):
        total = forward[row] - sum(
            lower[k][row] * solution[k] for k in range(row + 1, dimension)
        )
        solution[row] = total / lower[row][row]
    return solution


def _solve_symmetric_positive_definite(
    matrix: Sequence[Sequence[float]],
    vector: Sequence[float],
) -> list[float]:
    return _cholesky_solve(_cholesky(matrix), vector)


def _inverse_diagonal(matrix: Sequence[Sequence[float]]) -> list[float]:
    lower = _cholesky(matrix)
    dimension = len(matrix)
    diagonal: list[float] = []
    for index in range(dimension):
        basis = [1.0 if position == index else 0.0 for position in range(dimension)]
        diagonal.append(_cholesky_solve(lower, basis)[index])
    return diagonal
