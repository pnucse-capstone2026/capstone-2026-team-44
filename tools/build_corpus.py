"""Build the labeled corpus by running the real pipeline against loopback apps.

For every generated application this starts a real HTTP server on 127.0.0.1,
runs the actual `analyze_url` pipeline against it -- real crawler, real probe
execution, real feature extraction -- and joins the observed features to the
authored ground truth. No feature value is synthesised anywhere.

    PYTHONPATH=src python tools/build_corpus.py --applications 14

Writes, under ``data/corpus/`` by default:

    ground-truth/<app>.json   one ground truth file per application
    corpus.jsonl              the collected labeled samples
    model.json                fitted per-family calibrated models
    calibration-report.json   out-of-fold Brier score and reliability bins
    conformal.json            calibrated recall threshold
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnspider.cli_decision import collect_from_analysis
from vulnspider.corpus.collection import CorpusDataset, read_corpus, write_corpus
from vulnspider.corpus.fitting import (
    base_rate_brier_score,
    calibrate_from_corpus,
    evaluate_calibration,
    fit_family_scorers,
    heuristic_baseline_predictions,
    out_of_fold_predictions,
    scorers_as_mapping,
)
from vulnspider.corpus.ground_truth import write_ground_truth
from vulnspider.discovery import CrawlPolicy
from vulnspider.pipeline import analyze_url

sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus_target_site import build_applications, serve  # noqa: E402

DEFAULT_OUTPUT_DIR = Path("data/corpus")
DEFAULT_APPLICATIONS = 14
DEFAULT_TARGET_RECALL = 0.9


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_corpus",
        description="Collect, fit, and calibrate from loopback target applications.",
    )
    parser.add_argument(
        "--applications",
        type=int,
        default=DEFAULT_APPLICATIONS,
        help=f"Number of labeled applications (default: {DEFAULT_APPLICATIONS}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Artifact directory (default: {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--target-recall",
        type=float,
        default=DEFAULT_TARGET_RECALL,
        help=f"Recall to certify (default: {DEFAULT_TARGET_RECALL}).",
    )
    parser.add_argument("--seed", type=int, default=20260811)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.applications < 2:
        print("build_corpus: need at least two applications", file=sys.stderr)
        return 1

    output_dir = args.output_dir
    ground_truth_dir = output_dir / "ground-truth"
    ground_truth_dir.mkdir(parents=True, exist_ok=True)

    corpus_path = output_dir / "corpus.jsonl"
    policy = CrawlPolicy(max_pages=12, max_depth=2, max_requests=60)

    collected = []
    total_unlabeled = 0
    print(f"build_corpus: collecting {args.applications} applications")
    for spec in build_applications(args.applications, seed=args.seed):
        ground_truth = spec.ground_truth()
        ground_truth_path = ground_truth_dir / f"{spec.application_id}.json"
        write_ground_truth(ground_truth, ground_truth_path)

        with serve(spec) as base_url:
            analysis = analyze_url(base_url, top_k=1, crawl_policy=policy)
        result = collect_from_analysis(
            analysis,
            application_id=spec.application_id,
            ground_truth_path=ground_truth_path,
        )
        collected.extend(result.samples)
        total_unlabeled += len(result.unlabeled_keys)
        print(
            f"  {spec.application_id}: {len(result.samples):3d} samples "
            f"({result.positives} vulnerable, {result.negatives} safe)"
            + (
                f"  [{len(result.unlabeled_keys)} unlabeled skipped]"
                if result.unlabeled_keys
                else ""
            )
        )

    written = write_corpus(collected, corpus_path)
    dataset = read_corpus(corpus_path)
    counts = dataset.counts()
    print(
        f"build_corpus: wrote {written} samples to {corpus_path} "
        f"({counts['positives']} vulnerable, {counts['negatives']} safe, "
        f"{counts['groups']} applications)"
    )
    if total_unlabeled:
        print(f"build_corpus: {total_unlabeled} discovered candidates were unlabeled")
    if counts["positives"] == 0 or counts["negatives"] == 0:
        print("build_corpus: corpus lacks both classes; stopping", file=sys.stderr)
        return 1

    _fit_and_calibrate(dataset, output_dir, target_recall=args.target_recall)
    return 0


def _fit_and_calibrate(
    dataset: CorpusDataset,
    output_dir: Path,
    *,
    target_recall: float,
) -> None:
    scorers = fit_family_scorers(dataset)
    model_path = output_dir / "model.json"
    _write_json(scorers_as_mapping(scorers), model_path)
    print(f"build_corpus: fitted {len(scorers)} family models -> {model_path}")
    for family, scorer in sorted(scorers.items()):
        family_counts = dataset.for_family(family).counts()
        weights = ", ".join(
            f"{name}={weight:+.3f}"
            for name, weight in zip(
                scorer.feature_space.feature_names, scorer.weights, strict=True
            )
        )
        print(
            f"  {family} (n={family_counts['samples']}, "
            f"pos={family_counts['positives']}): "
            f"intercept={scorer.intercept:+.3f} {weights}"
        )

    fitted_report = evaluate_calibration(out_of_fold_predictions(dataset))
    heuristic_report = evaluate_calibration(heuristic_baseline_predictions(dataset))
    floor = base_rate_brier_score(dataset)
    report_path = output_dir / "calibration-report.json"
    _write_json(
        {
            "fitted_out_of_fold": fitted_report.as_mapping(),
            "heuristic_baseline": heuristic_report.as_mapping(),
            "base_rate_brier_score": floor,
        },
        report_path,
    )
    print(f"build_corpus: calibration quality over {fitted_report.samples} predictions")
    print(
        f"  fitted (out-of-fold)  Brier={fitted_report.brier_score:.4f} "
        f"ECE={fitted_report.expected_calibration_error:.4f}"
    )
    print(
        f"  heuristic baseline    Brier={heuristic_report.brier_score:.4f} "
        f"ECE={heuristic_report.expected_calibration_error:.4f}"
    )
    print(f"  always-base-rate      Brier={floor:.4f}")
    print(f"  -> {report_path}")

    threshold = calibrate_from_corpus(dataset, target_risk=1.0 - target_recall)
    conformal_path = output_dir / "conformal.json"
    _write_json(threshold.as_mapping(), conformal_path)
    if threshold.guarantee_attainable:
        print(
            f"build_corpus: threshold={threshold.threshold:.4f} certifies "
            f"recall >= {target_recall:.2f} (empirical risk "
            f"{threshold.empirical_risk:.4f} <= "
            f"{threshold.corrected_risk_bound:.4f}) -> {conformal_path}"
        )
    else:
        print(
            f"build_corpus: recall {target_recall:.2f} not certifiable with "
            f"{threshold.calibration_groups} applications -> {conformal_path}"
        )


def _write_json(payload: object, path: Path) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
