"""Labeled corpus collection, model fitting, and conformal calibration.

The decision layer works from its heuristic prior with no data at all, but
Layer 1's weights and Layer 3's guarantee only become meaningful once a labeled
corpus exists. This package collects one from real pipeline runs against
authorized targets and joins it to ground truth through the key
``docs/EVALUATION_PROTOCOL.md`` §3 defines.

See ADR-025 and ``docs/exec-plans/completed/decision-layer-cli-and-corpus.md``.
"""

from vulnspider.corpus.collection import (
    CORPUS_SCHEMA_VERSION,
    CollectionResult,
    CorpusDataset,
    CorpusError,
    LabeledSample,
    append_corpus,
    collect_labeled_samples,
    ground_truth_key_for,
    read_corpus,
    write_corpus,
)
from vulnspider.corpus.fitting import (
    CORPUS_FITTING_VERSION,
    CalibrationReport,
    CorpusFittingError,
    OutOfFoldPrediction,
    calibrate_from_corpus,
    candidate_identifier,
    evaluate_calibration,
    fit_family_scorers,
    out_of_fold_calibration_groups,
    out_of_fold_predictions,
    prior_family_scorers,
    sample_observations,
    scorers_as_mapping,
    scorers_from_mapping,
)
from vulnspider.corpus.ground_truth import (
    GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthError,
    GroundTruthKey,
    GroundTruthStore,
    ground_truth_from_entries,
    read_ground_truth,
    write_ground_truth,
)

__all__ = [
    "CORPUS_FITTING_VERSION",
    "CORPUS_SCHEMA_VERSION",
    "GROUND_TRUTH_SCHEMA_VERSION",
    "CalibrationReport",
    "CollectionResult",
    "CorpusDataset",
    "CorpusError",
    "CorpusFittingError",
    "GroundTruthError",
    "GroundTruthKey",
    "GroundTruthStore",
    "LabeledSample",
    "OutOfFoldPrediction",
    "append_corpus",
    "calibrate_from_corpus",
    "candidate_identifier",
    "collect_labeled_samples",
    "evaluate_calibration",
    "fit_family_scorers",
    "ground_truth_from_entries",
    "ground_truth_key_for",
    "out_of_fold_calibration_groups",
    "out_of_fold_predictions",
    "prior_family_scorers",
    "read_corpus",
    "read_ground_truth",
    "sample_observations",
    "scorers_as_mapping",
    "scorers_from_mapping",
    "write_corpus",
    "write_ground_truth",
]
