"""Labeled verification corpus: the protocol behind confidence calibration.

The ranking corpus (`corpus/collection.py`) joins observed *features* to ground
truth so the calibrated scorer can be fit. This module does the same for the
*verification* stage: it joins each candidate's verification **signal** (and the
prior it started from) to ground truth, so the confidence model
(`verification/calibration.py`) can learn how much each signal should move the
score.

One sample per verified candidate: the ground-truth key, the aggregate signal
the verification landed on, the pre-verification prior, and the label. Samples
are JSON Lines in canonical order, the same discipline the ranking corpus uses,
so an identical run produces an identical file.

The join goes through the evaluation-protocol key
(`docs/EVALUATION_PROTOCOL.md` §3), reconstructed from the authoritative
``Endpoint`` and ``InputPoint`` -- never from a report or display string. An
absent key is *unlabeled*, never negative (the same rule the ranking corpus
enforces).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnspider.corpus.collection import CorpusError, ground_truth_key_for
from vulnspider.corpus.ground_truth import GroundTruthKey, GroundTruthStore
from vulnspider.domain import Endpoint, InputPoint
from vulnspider.verification.calibration import (
    VerificationSignal,
    VerificationTrainingSample,
)
from vulnspider.verification.focused import VerificationRun

VERIFICATION_CORPUS_SCHEMA_VERSION = "verification-corpus-v1"


@dataclass(frozen=True, slots=True)
class VerificationSample:
    """One verified candidate's signal and prior joined to its ground truth."""

    key: GroundTruthKey
    signal: VerificationSignal
    prior_probability: float
    label: bool
    group: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "signal", VerificationSignal(self.signal))
        if isinstance(self.prior_probability, bool) or not isinstance(
            self.prior_probability, int | float
        ):
            raise CorpusError("prior_probability must be numeric")
        if not 0.0 <= float(self.prior_probability) <= 1.0:
            raise CorpusError("prior_probability must lie within [0, 1]")
        if not isinstance(self.label, bool):
            raise CorpusError("label must be a bool")
        if not self.group:
            raise CorpusError("group must not be empty")

    @property
    def family(self) -> str:
        return self.key.vulnerability_type

    def to_training_sample(self) -> VerificationTrainingSample:
        return VerificationTrainingSample(
            family=self.family,
            signal=self.signal,
            label=self.label,
            group=self.group,
        )

    def as_mapping(self) -> dict[str, Any]:
        return {
            **self.key.as_mapping(),
            "signal": self.signal.value,
            "prior_probability": float(self.prior_probability),
            "vulnerable": self.label,
            "group": self.group,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> VerificationSample:
        if "signal" not in payload:
            raise CorpusError("verification sample needs a 'signal'")
        if "vulnerable" not in payload:
            raise CorpusError("verification sample needs a 'vulnerable' label")
        label = payload["vulnerable"]
        if not isinstance(label, bool):
            raise CorpusError("'vulnerable' must be a JSON boolean")
        key = GroundTruthKey.from_mapping(payload)
        return cls(
            key=key,
            signal=VerificationSignal(str(payload["signal"])),
            prior_probability=float(payload.get("prior_probability", 0.0)),
            label=label,
            group=str(payload.get("group") or key.application_id),
        )


@dataclass(frozen=True, slots=True)
class VerificationCollectionResult:
    """What one application's verification collection produced, and what it did not."""

    samples: tuple[VerificationSample, ...]
    unlabeled_keys: tuple[GroundTruthKey, ...]

    @property
    def positives(self) -> int:
        return sum(1 for sample in self.samples if sample.label)

    @property
    def negatives(self) -> int:
        return sum(1 for sample in self.samples if not sample.label)


def collect_verification_samples(
    *,
    application_id: str,
    run: VerificationRun,
    endpoints: Sequence[Endpoint],
    input_points: Sequence[InputPoint],
    ground_truth: GroundTruthStore,
) -> VerificationCollectionResult:
    """Join one verification run's candidate signals to ground truth."""

    if not application_id:
        raise CorpusError("application_id must not be empty")
    if not isinstance(run, VerificationRun):
        raise CorpusError("run must be a VerificationRun")
    if not isinstance(ground_truth, GroundTruthStore):
        raise CorpusError("ground_truth must be a GroundTruthStore")

    endpoints_by_id = {endpoint.id or "": endpoint for endpoint in endpoints}
    points_by_id = {point.id or "": point for point in input_points}

    samples: list[VerificationSample] = []
    unlabeled: list[GroundTruthKey] = []
    for candidate in run.candidates:
        input_point = points_by_id.get(candidate.input_point_id)
        if input_point is None:
            raise CorpusError(
                f"candidate references unknown input point "
                f"{candidate.input_point_id!r}"
            )
        endpoint = endpoints_by_id.get(input_point.endpoint_id)
        if endpoint is None:
            raise CorpusError(
                f"input point references unknown endpoint "
                f"{input_point.endpoint_id!r}"
            )
        key = ground_truth_key_for(
            application_id=application_id,
            endpoint=endpoint,
            input_point=input_point,
            vulnerability_type=candidate.vulnerability_type.value,
        )
        label = ground_truth.label_for(key)
        if label is None:
            unlabeled.append(key)
            continue
        samples.append(
            VerificationSample(
                key=key,
                signal=candidate.final_signal,
                prior_probability=candidate.prior_probability,
                label=label,
                group=application_id,
            )
        )
    return VerificationCollectionResult(
        samples=tuple(samples),
        unlabeled_keys=tuple(dict.fromkeys(unlabeled)),
    )


@dataclass(frozen=True, slots=True)
class VerificationCorpusDataset:
    """A collected verification corpus, sliced for leave-one-application-out."""

    samples: tuple[VerificationSample, ...]

    def __post_init__(self) -> None:
        for sample in self.samples:
            if not isinstance(sample, VerificationSample):
                raise CorpusError("dataset must contain VerificationSample objects")

    @property
    def groups(self) -> tuple[str, ...]:
        return tuple(sorted({sample.group for sample in self.samples}))

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(sorted({sample.family for sample in self.samples}))

    def excluding_group(self, group: str) -> VerificationCorpusDataset:
        return VerificationCorpusDataset(
            samples=tuple(s for s in self.samples if s.group != group)
        )

    def only_group(self, group: str) -> VerificationCorpusDataset:
        return VerificationCorpusDataset(
            samples=tuple(s for s in self.samples if s.group == group)
        )

    def training_samples(self) -> tuple[VerificationTrainingSample, ...]:
        return tuple(sample.to_training_sample() for sample in self.samples)

    def counts(self) -> dict[str, int]:
        return {
            "samples": len(self.samples),
            "positives": sum(1 for s in self.samples if s.label),
            "negatives": sum(1 for s in self.samples if not s.label),
            "groups": len(self.groups),
        }

    def leave_one_group_out(
        self,
    ) -> tuple[tuple[str, VerificationCorpusDataset, VerificationCorpusDataset], ...]:
        return tuple(
            (group, self.excluding_group(group), self.only_group(group))
            for group in self.groups
        )


def _sort_key(sample: VerificationSample) -> tuple[str, ...]:
    return (
        sample.group,
        sample.key.application_id,
        sample.key.canonical_path,
        sample.key.method,
        sample.key.parameter_location,
        sample.key.parameter_name,
        sample.key.vulnerability_type,
        sample.signal.value,
    )


def write_verification_corpus(
    samples: Iterable[VerificationSample], path: Path
) -> int:
    """Write verification samples as JSON Lines in canonical order."""

    lines = [
        json.dumps(sample.as_mapping(), sort_keys=True)
        for sample in sorted(samples, key=_sort_key)
    ]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def append_verification_corpus(
    samples: Iterable[VerificationSample], path: Path
) -> int:
    """Append verification samples to an existing JSON Lines corpus."""

    lines = [json.dumps(sample.as_mapping(), sort_keys=True) for sample in samples]
    if not lines:
        return 0
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return len(lines)


def read_verification_corpus(path: Path) -> VerificationCorpusDataset:
    """Read a JSON Lines verification corpus."""

    samples: list[VerificationSample] = []
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
        samples.append(VerificationSample.from_mapping(payload))
    return VerificationCorpusDataset(samples=tuple(samples))
