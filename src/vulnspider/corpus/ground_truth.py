"""Candidate-level ground truth, keyed exactly as the evaluation protocol says.

``docs/EVALUATION_PROTOCOL.md`` §3 fixes the key:

``(application_id, method, canonical_path, parameter_location,
parameter_name, vulnerability_type)``

Two rules from that section are enforced here rather than left to convention.

**Absent is not negative.** A key missing from the store is *unlabeled*, and
:func:`GroundTruthStore.label_for` returns ``None`` for it. Treating unlabeled
as safe would silently manufacture negatives, inflate every precision figure,
and mirror the "missing feature is not observed zero" mistake the feature
schema already forbids. Collection reports unlabeled keys instead of guessing.

**Safe input points must be labeled too.** A store containing only vulnerable
keys cannot support a false-positive measurement, so
:meth:`GroundTruthStore.validate_usable` rejects one.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GROUND_TRUTH_SCHEMA_VERSION = "ground-truth-v1"

_KEY_FIELDS = (
    "application_id",
    "method",
    "canonical_path",
    "parameter_location",
    "parameter_name",
    "vulnerability_type",
)


class GroundTruthError(ValueError):
    """Raised when ground truth cannot be read or used as stated."""


@dataclass(frozen=True, slots=True)
class GroundTruthKey:
    """One labeled candidate identity."""

    application_id: str
    method: str
    canonical_path: str
    parameter_location: str
    parameter_name: str
    vulnerability_type: str

    def __post_init__(self) -> None:
        for field_name in _KEY_FIELDS:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise GroundTruthError(f"{field_name} must be a non-empty string")
        object.__setattr__(self, "method", self.method.upper())
        object.__setattr__(
            self, "parameter_location", self.parameter_location.upper()
        )
        object.__setattr__(
            self, "vulnerability_type", self.vulnerability_type.upper()
        )
        object.__setattr__(self, "parameter_name", self.parameter_name.strip().lower())

    def as_mapping(self) -> dict[str, str]:
        return {field_name: getattr(self, field_name) for field_name in _KEY_FIELDS}

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> GroundTruthKey:
        missing = [name for name in _KEY_FIELDS if name not in payload]
        if missing:
            raise GroundTruthError(
                f"ground truth key is missing fields: {', '.join(missing)}"
            )
        return cls(**{name: str(payload[name]) for name in _KEY_FIELDS})


@dataclass(frozen=True, slots=True)
class GroundTruthStore:
    """Every labeled candidate identity for one corpus."""

    labels: Mapping[GroundTruthKey, bool]
    schema_version: str = GROUND_TRUTH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for key, label in self.labels.items():
            if not isinstance(key, GroundTruthKey):
                raise GroundTruthError("ground truth keys must be GroundTruthKey")
            if not isinstance(label, bool):
                raise GroundTruthError(f"label for {key} must be a bool")

    @property
    def applications(self) -> tuple[str, ...]:
        return tuple(sorted({key.application_id for key in self.labels}))

    @property
    def positives(self) -> int:
        return sum(1 for label in self.labels.values() if label)

    @property
    def negatives(self) -> int:
        return sum(1 for label in self.labels.values() if not label)

    def label_for(self, key: GroundTruthKey) -> bool | None:
        """``True``/``False`` when labeled, ``None`` when this key is unknown."""

        return self.labels.get(key)

    def validate_usable(self) -> None:
        """Reject a store that cannot support a false-positive measurement."""

        if not self.labels:
            raise GroundTruthError("ground truth store is empty")
        if self.positives == 0:
            raise GroundTruthError(
                "ground truth has no vulnerable candidate; nothing can be learned"
            )
        if self.negatives == 0:
            raise GroundTruthError(
                "ground truth has no safe candidate; false positives would be "
                "unmeasurable (EVALUATION_PROTOCOL.md 3)"
            )

    def merged_with(self, other: GroundTruthStore) -> GroundTruthStore:
        """Combine two stores, rejecting contradictory labels for one key."""

        combined = dict(self.labels)
        for key, label in other.labels.items():
            existing = combined.get(key)
            if existing is not None and existing != label:
                raise GroundTruthError(f"contradictory ground truth for {key}")
            combined[key] = label
        return GroundTruthStore(labels=combined)


def write_ground_truth(store: GroundTruthStore, path: Path) -> None:
    """Write a ground truth store as JSON."""

    payload = {
        "schema_version": store.schema_version,
        "entries": [
            {**key.as_mapping(), "vulnerable": label}
            for key, label in sorted(
                store.labels.items(),
                key=lambda item: tuple(
                    getattr(item[0], name) for name in _KEY_FIELDS
                ),
            )
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def read_ground_truth(path: Path) -> GroundTruthStore:
    """Read a ground truth store from JSON."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GroundTruthError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise GroundTruthError(f"{path} must contain a JSON object")
    version = payload.get("schema_version")
    if version != GROUND_TRUTH_SCHEMA_VERSION:
        raise GroundTruthError(
            f"unsupported ground truth schema version: {version!r}"
        )
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise GroundTruthError(f"{path} must contain an 'entries' array")

    labels: dict[GroundTruthKey, bool] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise GroundTruthError("each ground truth entry must be an object")
        if "vulnerable" not in entry:
            raise GroundTruthError("each ground truth entry needs 'vulnerable'")
        vulnerable = entry["vulnerable"]
        if not isinstance(vulnerable, bool):
            raise GroundTruthError("'vulnerable' must be a JSON boolean")
        key = GroundTruthKey.from_mapping(entry)
        existing = labels.get(key)
        if existing is not None and existing != vulnerable:
            raise GroundTruthError(f"contradictory ground truth for {key}")
        labels[key] = vulnerable
    return GroundTruthStore(labels=labels)


def ground_truth_from_entries(
    entries: Iterable[tuple[GroundTruthKey, bool]],
) -> GroundTruthStore:
    """Build a store from key/label pairs, rejecting contradictions."""

    labels: dict[GroundTruthKey, bool] = {}
    for key, label in entries:
        existing = labels.get(key)
        if existing is not None and existing != label:
            raise GroundTruthError(f"contradictory ground truth for {key}")
        labels[key] = label
    return GroundTruthStore(labels=labels)
