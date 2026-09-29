"""Turn a labeled corpus into the rankings ``EVALUATION_PROTOCOL.md`` §5 compares.

Every baseline is a scoring function over the same corpus samples, so they are
measured on identical candidates with identical labels and differ only in how
they order them.

Fairness rules that are easy to violate and are enforced here:

* The calibrated ranking uses **out-of-fold** probabilities. Scoring a sample
  with a model fitted on that sample's own application would be training on the
  test set and would make the proposed method look better than it is.
* The heuristic ranking uses ``raw RankScore / scorer maximum``, which is
  exactly today's ``selection_priority`` (ADR-010). Baseline D therefore
  reproduces current behaviour rather than a reconstruction of it.
* Baseline B scores every candidate identically. That is not a trick to avoid
  a random number generator -- one tie group is the *exact* representation of a
  uniformly random ranking, and the tie machinery in ``metrics`` then yields
  its expectation in closed form.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from vulnspider.corpus.collection import CorpusDataset, LabeledSample
from vulnspider.corpus.fitting import (
    out_of_fold_predictions,
    sample_observations,
)
from vulnspider.evaluation.metrics import RankedItem, RankingQuery
from vulnspider.features import MARKER_REFLECTED
from vulnspider.scoring.calibration import HEURISTIC_TERMS

BASELINE_RANDOM = "Baseline B: random Top-K"
BASELINE_REFLECTION = "Baseline C: reflection-only heuristic"
BASELINE_HEURISTIC = "Baseline D: heuristic weighted sum"
PROPOSED_CALIBRATED = "Proposed: calibrated probability"

# Path segments that identify one instance of a templated route rather than a
# distinct code path (EVALUATION_PROTOCOL.md 6-A rule 1).
_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_HEX_SEGMENT = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class BaselineError(ValueError):
    """Raised when a baseline ranking cannot be built."""


def normalize_route(path: str) -> str:
    """Collapse instance identifiers in a path to a template placeholder.

    ``/product/1`` and ``/product/2`` are one code path and therefore one bug.
    ``canonical_path()`` deliberately does not do this -- it must preserve the
    exact path for request reconstruction -- so bug-level aggregation does it
    here instead.
    """

    segments = []
    for segment in path.split("/"):
        if (
            _UUID_SEGMENT.match(segment)
            or _NUMERIC_SEGMENT.match(segment)
            or _HEX_SEGMENT.match(segment)
        ):
            segments.append("{id}")
        else:
            segments.append(segment)
    return "/".join(segments)


def bug_key_for(sample: LabeledSample) -> str:
    """Identity of the underlying defect a candidate is evidence of."""

    return "|".join(
        (
            sample.key.application_id,
            normalize_route(sample.key.canonical_path),
            sample.key.parameter_location,
            sample.key.parameter_name,
            sample.key.vulnerability_type,
        )
    )


def random_score(_sample: LabeledSample) -> float:
    """Baseline B: one tie group, i.e. a uniformly random ranking."""

    return 0.0


def reflection_only_score(sample: LabeledSample) -> float:
    """Baseline C: the single strongest static-ish signal, reflection presence.

    ``EVALUATION_PROTOCOL.md`` §5 also names "numeric parameter first", but
    ``numeric_value`` is still not extracted (``FEATURE_SCHEMA.md`` §9), so
    fabricating it here would misreport what the pipeline observes.
    """

    return float(sample.features.get(MARKER_REFLECTED, 0.0))


def heuristic_score(sample: LabeledSample) -> float:
    """Baseline D: today's ``selection_priority`` -- raw RankScore over maximum."""

    terms = HEURISTIC_TERMS.get(sample.family)
    if terms is None:
        raise BaselineError(f"no heuristic terms for family {sample.family!r}")
    maximum = sum(weight for _name, weight in terms)
    if maximum <= 0.0:
        raise BaselineError(f"heuristic maximum for {sample.family!r} is not positive")
    raw = sum(
        weight * float(sample.features.get(name, 0.0)) for name, weight in terms
    )
    return raw / maximum


def build_queries(
    dataset: CorpusDataset,
    score_for: Callable[[LabeledSample], float],
    *,
    bug_level: bool = False,
) -> tuple[RankingQuery, ...]:
    """Group a corpus into one ranking query per application (§6-A rule 3)."""

    if not isinstance(dataset, CorpusDataset):
        raise BaselineError("dataset must be a CorpusDataset")
    scores = {id(sample): float(score_for(sample)) for sample in dataset.samples}
    return _queries_from_scores(dataset, scores, bug_level=bug_level)


def build_calibrated_queries(
    dataset: CorpusDataset,
    *,
    bug_level: bool = False,
) -> tuple[RankingQuery, ...]:
    """The proposed ranking, scored strictly out-of-fold."""

    scores = {
        id(prediction.sample): prediction.probability
        for prediction in out_of_fold_predictions(dataset)
    }
    if len(scores) != len(dataset.samples):
        raise BaselineError("out-of-fold prediction did not cover every sample")
    return _queries_from_scores(dataset, scores, bug_level=bug_level)


def _queries_from_scores(
    dataset: CorpusDataset,
    scores: Mapping[int, float],
    *,
    bug_level: bool,
) -> tuple[RankingQuery, ...]:
    by_group: dict[str, list[LabeledSample]] = {}
    for sample in dataset.samples:
        by_group.setdefault(sample.group, []).append(sample)

    queries: list[RankingQuery] = []
    for group, samples in sorted(by_group.items()):
        if bug_level:
            items = _aggregate_bugs(samples, scores)
        else:
            items = tuple(
                RankedItem(
                    candidate_id=_candidate_key(sample),
                    score=scores[id(sample)],
                    label=sample.label,
                    bug_key=bug_key_for(sample),
                )
                for sample in samples
            )
        queries.append(RankingQuery(query_id=group, items=items))
    return tuple(queries)


def _aggregate_bugs(
    samples: Sequence[LabeledSample],
    scores: Mapping[int, float],
) -> tuple[RankedItem, ...]:
    """Collapse candidates of one templated route into a single bug.

    The bug is relevant if any of its candidates is, and it is scored by its
    best candidate, since that is the one selection would surface first.
    """

    grouped: dict[str, list[LabeledSample]] = {}
    for sample in samples:
        grouped.setdefault(bug_key_for(sample), []).append(sample)
    return tuple(
        RankedItem(
            candidate_id=key,
            score=max(scores[id(sample)] for sample in members),
            label=(
                True
                if any(sample.label for sample in members)
                else (
                    False
                    if any(sample.label is False for sample in members)
                    else None
                )
            ),
            bug_key=key,
        )
        for key, members in sorted(grouped.items())
    )


def _candidate_key(sample: LabeledSample) -> str:
    return "|".join(
        (
            sample.key.application_id,
            sample.key.method,
            sample.key.canonical_path,
            sample.key.parameter_location,
            sample.key.parameter_name,
            sample.key.vulnerability_type,
        )
    )


@dataclass(frozen=True, slots=True)
class FullVerificationReference:
    """Baseline A: verify every candidate.

    Not a ranking -- it has perfect recall by construction. It exists to price
    that recall, so the other rows can be read as "how much of Baseline A's
    result for how much of its cost".
    """

    candidates: int
    relevant: int
    total_requests: int

    def as_mapping(self) -> dict[str, object]:
        return {
            "name": "Baseline A: all-input verification",
            "candidates": self.candidates,
            "relevant": self.relevant,
            "recall": 1.0,
            "total_requests": self.total_requests,
        }


# Per-family request count used only to price the full-verification baseline in
# the evaluation harness. It is not a decision input: the shipped algorithm ranks
# by probability alone and knows nothing about verification cost.
_EVAL_FAMILY_REQUEST_COST: dict[str, int] = {
    "SQLI": 6,
    "REFLECTED_XSS": 3,
    "BROKEN_ACCESS_CONTROL": 4,
}
_DEFAULT_EVAL_REQUEST_COST = 4


def full_verification_reference(
    dataset: CorpusDataset,
) -> FullVerificationReference:
    """Price verifying every discovered candidate (evaluation harness only)."""

    return FullVerificationReference(
        candidates=len(dataset.samples),
        relevant=sum(1 for sample in dataset.samples if sample.label),
        total_requests=sum(
            _EVAL_FAMILY_REQUEST_COST.get(sample.family, _DEFAULT_EVAL_REQUEST_COST)
            for sample in dataset.samples
        ),
    )
