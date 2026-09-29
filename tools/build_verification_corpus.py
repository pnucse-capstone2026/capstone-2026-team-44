"""Build the labeled *verification* corpus by re-probing loopback apps.

The ranking corpus (``build_corpus.py``) fits the pre-verification scorer. This
is its verification counterpart: for every generated application it starts a
real HTTP server on 127.0.0.1, runs the actual ``analyze_url`` pipeline, then
runs focused verification against it -- real mutation payloads, real re-probing,
real feature deltas -- and joins each candidate's verification *signal* to the
authored ground truth. Nothing is synthesised.

The generated applications reproduce the same signal families a real target
like DVWA exposes -- error-based SQLi, blind SQLi, raw reflected XSS, safely
escaped reflection, and safe endpoints -- which is what lets the confidence
model learn a useful per-signal log-likelihood ratio without needing an
authenticated crawl of DVWA itself.

    PYTHONPATH=src python tools/build_verification_corpus.py --applications 14

Writes, under ``data/corpus/`` by default:

    ground-truth/<app>.json          one ground truth file per application
    verification-corpus.jsonl        the collected verification samples
    verification-model.json          the fitted confidence model
    verification-arm.json            out-of-fold Brier(prior) vs Brier(posterior)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnspider.corpus.ground_truth import write_ground_truth
from vulnspider.corpus.verification_collection import (
    read_verification_corpus,
    write_verification_corpus,
)
from vulnspider.corpus.verification_fitting import (
    evaluate_verification_arm,
    fit_from_verification_corpus,
)
from vulnspider.discovery import CrawlPolicy
from vulnspider.pipeline import analyze_url
from vulnspider.verification import VerificationConfig, verify_analysis
from vulnspider.corpus.verification_collection import collect_verification_samples

sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus_target_site import build_applications, serve  # noqa: E402

DEFAULT_OUTPUT_DIR = Path("data/corpus")
DEFAULT_APPLICATIONS = 14
# Verify every rankable candidate the app exposes, not just one, so the corpus
# has enough per-signal counts to fit.
VERIFY_TOP_K = 100


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_verification_corpus",
        description="Collect and fit the confidence model from loopback apps.",
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
        "--max-abs-llr",
        type=float,
        default=1.0,
        help="Cap on |LLR| in logits (default: 1.0), keeping the update gentle.",
    )
    parser.add_argument("--seed", type=int, default=20260811)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.applications < 2:
        print("build_verification_corpus: need at least two apps", file=sys.stderr)
        return 1

    output_dir = args.output_dir
    ground_truth_dir = output_dir / "ground-truth"
    ground_truth_dir.mkdir(parents=True, exist_ok=True)
    corpus_path = output_dir / "verification-corpus.jsonl"
    policy = CrawlPolicy(max_pages=12, max_depth=2, max_requests=60)

    collected = []
    total_unlabeled = 0
    print(f"build_verification_corpus: collecting {args.applications} applications")
    for spec in build_applications(args.applications, seed=args.seed):
        ground_truth = spec.ground_truth()
        write_ground_truth(ground_truth, ground_truth_dir / f"{spec.application_id}.json")

        with serve(spec) as base_url:
            analysis = analyze_url(base_url, top_k=VERIFY_TOP_K, crawl_policy=policy)
            run = verify_analysis(
                analysis,
                config=VerificationConfig(max_candidates=VERIFY_TOP_K),
            )
        result = collect_verification_samples(
            application_id=spec.application_id,
            run=run,
            endpoints=analysis.endpoints,
            input_points=analysis.input_points,
            ground_truth=ground_truth,
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

    written = write_verification_corpus(collected, corpus_path)
    dataset = read_verification_corpus(corpus_path)
    counts = dataset.counts()
    print(
        f"build_verification_corpus: wrote {written} samples to {corpus_path} "
        f"({counts['positives']} vulnerable, {counts['negatives']} safe, "
        f"{counts['groups']} applications)"
    )
    if total_unlabeled:
        print(
            f"build_verification_corpus: {total_unlabeled} candidates were unlabeled"
        )
    if counts["positives"] == 0 or counts["negatives"] == 0:
        print(
            "build_verification_corpus: corpus lacks both classes; stopping",
            file=sys.stderr,
        )
        return 1

    _fit_and_evaluate(dataset, output_dir, max_abs_llr=args.max_abs_llr)
    return 0


def _fit_and_evaluate(dataset, output_dir: Path, *, max_abs_llr: float) -> None:
    model = fit_from_verification_corpus(dataset, max_abs_llr=max_abs_llr)
    model_path = output_dir / "verification-model.json"
    _write_json(model.as_mapping(), model_path)
    print(
        f"build_verification_corpus: fitted the confidence model "
        f"(|LLR| capped at {model.max_abs_llr:.2f}) -> {model_path}"
    )
    for family in sorted(model.family_llr):
        detail = ", ".join(
            f"{signal}={model.family_llr[family][signal]:+.3f}"
            for signal in sorted(model.family_llr[family])
        )
        print(f"  {family}: {detail}")

    if len(dataset.groups) >= 2:
        report = evaluate_verification_arm(dataset, max_abs_llr=max_abs_llr)
        arm_path = output_dir / "verification-arm.json"
        _write_json(report.as_mapping(), arm_path)
        print(
            f"build_verification_corpus: out-of-fold Brier "
            f"prior={report.brier_prior:.4f} posterior={report.brier_posterior:.4f} "
            f"improvement={report.improvement:+.4f} ({report.samples} predictions)"
        )
        print(f"  -> {arm_path}")


def _write_json(payload: object, path: Path) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
