"""Turn a real analysis run into labeled training samples.

The corpus is collected from the *actual* pipeline: real HTTP against an
authorized loopback target, real crawler, real probe execution, real feature
extraction. Nothing here synthesises a feature value. If the pipeline did not
observe a feature, it is absent from the sample, exactly as it is absent from
the ``FeatureVector``.

Joining features to labels goes through the evaluation protocol's ground truth
key, which is reconstructed from the authoritative ``Endpoint`` and
``InputPoint`` the discovery layer produced -- never from a report or a display
string.

Samples are stored as JSON Lines so a corpus can be appended to one application
at a time without rewriting it, and so a partially collected corpus is still
readable.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnspider.corpus.ground_truth import (
    GroundTruthError,
    GroundTruthKey,
    GroundTruthStore,
)
from vulnspider.domain import Endpoint, FeatureVector, InputPoint
from vulnspider.scoring.calibration import TrainingSample

CORPUS_SCHEMA_VERSION = "corpus-v1"


class CorpusError(ValueError):
    """Raised when a corpus cannot be collected or read as stated."""


@dataclass(frozen=True, slots=True)
class LabeledSample:
    """One candidate's observed features joined to its ground truth."""

    key: GroundTruthKey
    features: Mapping[str, float]
    label: bool
    group: str
    feature_schema_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.label, bool):
            raise CorpusError("label must be a bool")
        if not self.group:
            raise CorpusError("group must not be empty")
        for name, value in self.features.items():
            if not name:
                raise CorpusError("feature names must not be empty")
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise CorpusError(f"feature {name!r} must be numeric")

    @property
    def family(self) -> str:
        """The scoring family this sample belongs to."""

        return self.key.vulnerability_type

    def as_mapping(self) -> dict[str, Any]:
        return {
            **self.key.as_mapping(),
            "vulnerable": self.label,
            "group": self.group,
            "feature_schema_version": self.feature_schema_version,
            "features": {
                name: float(value) for name, value in sorted(self.features.items())
            },
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> LabeledSample:
        features = payload.get("features")
        if not isinstance(features, Mapping):
            raise CorpusError("sample 'features' must be an object")
        if "vulnerable" not in payload:
            raise CorpusError("sample needs a 'vulnerable' label")
        label = payload["vulnerable"]
        if not isinstance(label, bool):
            raise CorpusError("'vulnerable' must be a JSON boolean")
        key = GroundTruthKey.from_mapping(payload)
        return cls(
            key=key,
            features={name: float(value) for name, value in features.items()},
            label=label,
            group=str(payload.get("group") or key.application_id),
            feature_schema_version=str(payload.get("feature_schema_version") or ""),
        )

    def to_training_sample(self) -> TrainingSample:
        return TrainingSample(
            features=dict(self.features),
            label=self.label,
            group=self.group,
        )


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """What one application's collection run produced, and what it could not."""

    samples: tuple[LabeledSample, ...]
    unlabeled_keys: tuple[GroundTruthKey, ...]
    unrankable_candidates: int

    @property
    def positives(self) -> int:
        return sum(1 for sample in self.samples if sample.label)

    @property
    def negatives(self) -> int:
        return sum(1 for sample in self.samples if not sample.label)


def ground_truth_key_for(
    *,
    application_id: str,
    endpoint: Endpoint,
    input_point: InputPoint,
    vulnerability_type: str,
) -> GroundTruthKey:
    """Build the evaluation protocol key from authoritative discovery objects."""

    return GroundTruthKey(
        application_id=application_id,
        method=endpoint.method.value,
        canonical_path=endpoint.path,
        parameter_location=input_point.location.value,
        parameter_name=input_point.name,
        vulnerability_type=vulnerability_type,
    )


def collect_labeled_samples(
    *,
    application_id: str,
    endpoints: Sequence[Endpoint],
    input_points: Sequence[InputPoint],
    feature_vectors: Sequence[FeatureVector],
    scored_candidates: Sequence[tuple[str, str, str]],
    ground_truth: GroundTruthStore,
) -> CollectionResult:
    """Join observed features to ground truth for one analysed application.

    ``scored_candidates`` carries ``(input_point_id, feature_vector_id,
    vulnerability_type)`` for every candidate the scoring layer produced. It is
    passed in rather than derived so this module never needs to know how
    candidates are generated.
    """

    if not application_id:
        raise CorpusError("application_id must not be empty")
    if not isinstance(ground_truth, GroundTruthStore):
        raise CorpusError("ground_truth must be a GroundTruthStore")

    endpoints_by_id = {endpoint.id or "": endpoint for endpoint in endpoints}
    points_by_id = {point.id or "": point for point in input_points}
    vectors_by_id = {vector.id or "": vector for vector in feature_vectors}

    samples: list[LabeledSample] = []
    unlabeled: list[GroundTruthKey] = []
    unrankable = 0

    for input_point_id, feature_vector_id, vulnerability_type in scored_candidates:
        input_point = points_by_id.get(input_point_id)
        if input_point is None:
            raise CorpusError(
                f"candidate references unknown input point {input_point_id!r}"
            )
        endpoint = endpoints_by_id.get(input_point.endpoint_id)
        if endpoint is None:
            raise CorpusError(
                f"input point references unknown endpoint {input_point.endpoint_id!r}"
            )
        vector = vectors_by_id.get(feature_vector_id)
        if vector is None:
            raise CorpusError(
                f"candidate references unknown feature vector {feature_vector_id!r}"
            )

        observed = {
            name: float(observation.value)
            for name, observation in vector.features.items()
            if observation.observed and observation.value is not None
        }
        if not observed:
            unrankable += 1
            continue

        key = ground_truth_key_for(
            application_id=application_id,
            endpoint=endpoint,
            input_point=input_point,
            vulnerability_type=vulnerability_type,
        )
        label = ground_truth.label_for(key)
        if label is None:
            unlabeled.append(key)
            continue
        samples.append(
            LabeledSample(
                key=key,
                features=observed,
                label=label,
                group=application_id,
                feature_schema_version=vector.feature_schema_version,
            )
        )

    return CollectionResult(
        samples=tuple(samples),
        unlabeled_keys=tuple(dict.fromkeys(unlabeled)),
        unrankable_candidates=unrankable,
    )


@dataclass(frozen=True, slots=True)
class CorpusDataset:
    """A collected corpus, sliced the way the evaluation protocol requires."""

    samples: tuple[LabeledSample, ...]

    def __post_init__(self) -> None:
        for sample in self.samples:
            if not isinstance(sample, LabeledSample):
                raise CorpusError("dataset must contain LabeledSample objects")

    @property
    def groups(self) -> tuple[str, ...]:
        return tuple(sorted({sample.group for sample in self.samples}))

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(sorted({sample.family for sample in self.samples}))

    def for_family(self, family: str) -> CorpusDataset:
        return CorpusDataset(
            samples=tuple(
                sample for sample in self.samples if sample.family == family
            )
        )

    def excluding_group(self, group: str) -> CorpusDataset:
        return CorpusDataset(
            samples=tuple(sample for sample in self.samples if sample.group != group)
        )

    def only_group(self, group: str) -> CorpusDataset:
        return CorpusDataset(
            samples=tuple(sample for sample in self.samples if sample.group == group)
        )

    def training_samples(self) -> tuple[TrainingSample, ...]:
        return tuple(sample.to_training_sample() for sample in self.samples)

    def counts(self) -> dict[str, int]:
        return {
            "samples": len(self.samples),
            "positives": sum(1 for sample in self.samples if sample.label),
            "negatives": sum(1 for sample in self.samples if not sample.label),
            "groups": len(self.groups),
        }

    def leave_one_group_out(
        self,
    ) -> tuple[tuple[str, CorpusDataset, CorpusDataset], ...]:
        """``(held_out_group, train, test)`` for every group.

        This is the split ``docs/EVALUATION_PROTOCOL.md`` §4 mandates when the
        corpus is small: whole applications move together, so two near-identical
        input points on one templated route can never straddle the split.
        """

        return tuple(
            (group, self.excluding_group(group), self.only_group(group))
            for group in self.groups
        )


def corpus_sort_key(sample: LabeledSample) -> tuple[str, ...]:
    """Canonical ordering key for a corpus file."""

    return (
        sample.group,
        sample.key.application_id,
        sample.key.canonical_path,
        sample.key.method,
        sample.key.parameter_location,
        sample.key.parameter_name,
        sample.key.vulnerability_type,
    )


def write_corpus(samples: Iterable[LabeledSample], path: Path) -> int:
    """Write samples as JSON Lines in canonical order. Returns the count.

    Order carries no information -- a corpus is a bag of samples -- so it is
    canonicalised here. Discovery does not guarantee a stable traversal order
    between runs, and without this an identical ``--seed`` produces files that
    differ only by line order, which makes real changes impossible to spot in a
    diff and undercuts the reproducibility ``docs/EVALUATION_PROTOCOL.md`` §8
    asks for.
    """

    lines = [
        json.dumps(sample.as_mapping(), sort_keys=True)
        for sample in sorted(samples, key=corpus_sort_key)
    ]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def append_corpus(samples: Iterable[LabeledSample], path: Path) -> int:
    """Append samples to an existing JSON Lines corpus.

    Appending cannot canonicalise the whole file; incremental collection
    trades that for being able to add one application at a time. Read the
    corpus and rewrite it with :func:`write_corpus` when a canonical file is
    wanted.
    """

    lines = [
        json.dumps(sample.as_mapping(), sort_keys=True) for sample in samples
    ]
    if not lines:
        return 0
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return len(lines)


def read_corpus(path: Path) -> CorpusDataset:
    """Read a JSON Lines corpus."""

    samples: list[LabeledSample] = []
    text = path.read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise CorpusError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise CorpusError(f"{path}:{number}: each line must be an object")
        try:
            samples.append(LabeledSample.from_mapping(payload))
        except GroundTruthError as exc:
            raise CorpusError(f"{path}:{number}: {exc}") from exc
    return CorpusDataset(samples=tuple(samples))
