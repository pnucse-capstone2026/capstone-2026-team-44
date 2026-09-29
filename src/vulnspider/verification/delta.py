"""Compare a re-probed feature vector against the baseline one.

This is the measurement the user's confidence rule turns on: "if the difference
from the previously collected features is small, keep the confidence; if it is
large, decide whether it is a genuine weak point or just an error." The module
computes the difference only. It assigns no meaning and touches no confidence --
that is `confidence.py`'s job, keeping the numeric comparison separate from the
policy that interprets it.

Both vectors are produced by the same extractor (`features.extraction`), so they
share feature names and the [0, 1] value convention. A feature is compared only
when both sides observed it; an *observability flip* (observed on one side,
missing on the other) is recorded separately because "missing is not observed
zero" (`AGENTS.md` rule 8, `docs/FEATURE_SCHEMA.md`).
"""

from __future__ import annotations

from dataclasses import dataclass

from vulnspider.domain import FeatureObservation, FeatureVector

# Absolute change at or above this counts as "large" for a continuous feature.
# The boolean features move by exactly 1.0 when they flip, so any flip is always
# above it; this threshold only matters for response_length_diff_ratio and
# reflection_count_norm.
DEFAULT_MATERIAL_DELTA = 0.3


class FeatureDeltaError(ValueError):
    """Raised when two feature vectors cannot be compared honestly."""


@dataclass(frozen=True, slots=True)
class FeatureDelta:
    """The change in one feature between baseline and verification."""

    feature_name: str
    baseline_value: float | None
    baseline_observed: bool
    verification_value: float | None
    verification_observed: bool
    delta: float | None
    abs_delta: float | None
    observability_flip: bool

    @property
    def became_observed(self) -> bool:
        return self.verification_observed and not self.baseline_observed

    @property
    def became_unobserved(self) -> bool:
        return self.baseline_observed and not self.verification_observed

    @property
    def material_flip(self) -> bool:
        """An observability flip that carries a real signal, not an artifact.

        A marker-based feature legitimately becomes unobserved when the
        verification payload carries no marker (a SQL or boundary payload). That
        flip is only meaningful when the observed side actually saw the signal
        (value > 0): a signal appearing, or a positive baseline signal vanishing.
        A flip to or from a plain ``0.0`` is a probe-design artifact, not a
        change in how the application behaved.
        """

        if not self.observability_flip:
            return False
        observed_value = (
            self.verification_value
            if self.verification_observed
            else self.baseline_value
        )
        return bool(observed_value and observed_value > 0.0)


@dataclass(frozen=True, slots=True)
class FeatureVectorDelta:
    """The full baseline-vs-verification comparison for one candidate probe."""

    input_point_id: str
    baseline_feature_vector_id: str
    verification_feature_vector_id: str
    material_delta_threshold: float
    deltas: tuple[FeatureDelta, ...]
    execution_ok: bool

    def get(self, feature_name: str) -> FeatureDelta | None:
        for delta in self.deltas:
            if delta.feature_name == feature_name:
                return delta
        return None

    @property
    def max_abs_delta(self) -> float:
        values = [d.abs_delta for d in self.deltas if d.abs_delta is not None]
        return max(values) if values else 0.0

    @property
    def observability_flips(self) -> tuple[str, ...]:
        return tuple(d.feature_name for d in self.deltas if d.observability_flip)

    @property
    def material_flips(self) -> tuple[str, ...]:
        return tuple(d.feature_name for d in self.deltas if d.material_flip)

    @property
    def changed(self) -> bool:
        """Whether the verification moved the feature vector materially.

        True when any compared feature moved at least the threshold, or when a
        real signal appeared or a positive baseline signal vanished. A flip to
        or from a plain ``0.0`` -- a marker-based feature the verification
        payload simply did not probe -- is a probe-design artifact and does not
        count (see :attr:`FeatureDelta.material_flip`).
        """

        if self.material_flips:
            return True
        return self.max_abs_delta >= self.material_delta_threshold


def compute_feature_delta(
    baseline: FeatureVector,
    verification: FeatureVector,
    *,
    material_delta_threshold: float = DEFAULT_MATERIAL_DELTA,
    execution_ok: bool = True,
) -> FeatureVectorDelta:
    """Difference two feature vectors of the same schema, feature by feature."""

    if not isinstance(baseline, FeatureVector):
        raise FeatureDeltaError("baseline must be a FeatureVector")
    if not isinstance(verification, FeatureVector):
        raise FeatureDeltaError("verification must be a FeatureVector")
    if baseline.input_point_id != verification.input_point_id:
        raise FeatureDeltaError("feature vectors must belong to one InputPoint")
    if baseline.feature_schema_version != verification.feature_schema_version:
        raise FeatureDeltaError("feature vectors must share one schema version")
    if not (0.0 <= material_delta_threshold <= 1.0):
        raise FeatureDeltaError("material_delta_threshold must be within [0, 1]")

    names = sorted(set(baseline.features) | set(verification.features))
    deltas = tuple(
        _feature_delta(
            name,
            baseline.features.get(name),
            verification.features.get(name),
        )
        for name in names
    )
    return FeatureVectorDelta(
        input_point_id=baseline.input_point_id,
        baseline_feature_vector_id=baseline.id or "",
        verification_feature_vector_id=verification.id or "",
        material_delta_threshold=material_delta_threshold,
        deltas=deltas,
        execution_ok=execution_ok,
    )


def _feature_delta(
    name: str,
    baseline: FeatureObservation | None,
    verification: FeatureObservation | None,
) -> FeatureDelta:
    baseline_observed = bool(baseline and baseline.observed)
    verification_observed = bool(verification and verification.observed)
    baseline_value = _numeric(baseline) if baseline_observed else None
    verification_value = _numeric(verification) if verification_observed else None

    if baseline_observed and verification_observed:
        delta: float | None = verification_value - baseline_value  # type: ignore[operator]
        abs_delta: float | None = abs(delta)
        observability_flip = False
    else:
        delta = None
        abs_delta = None
        observability_flip = baseline_observed != verification_observed

    return FeatureDelta(
        feature_name=name,
        baseline_value=baseline_value,
        baseline_observed=baseline_observed,
        verification_value=verification_value,
        verification_observed=verification_observed,
        delta=delta,
        abs_delta=abs_delta,
        observability_flip=observability_flip,
    )


def _numeric(observation: FeatureObservation) -> float:
    value = observation.value
    if value is None or isinstance(value, str) or not isinstance(value, bool | int | float):
        raise FeatureDeltaError(
            f"observed feature {observation.name} must be numeric"
        )
    return float(value)
