"""Measure decision-layer recall and request cost on unseen applications.

The corpus in ``data/corpus/`` is built from applications 0..N-1. This script
generates a *disjoint* range of applications, runs the real pipeline against
each, and compares three configurations at one fixed budget:

1. the heuristic prior with no guarantee (today's behaviour),
2. the fitted model with no guarantee (Layer 1 only),
3. the fitted model plus the conformal threshold (Layers 1 and 3).

Recall is measured against the authored ground truth of each held-out
application, so no configuration has ever seen these labels.

    PYTHONPATH=src python tools/evaluate_heldout.py --top-k 5
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from vulnspider.cli_decision import build_decision_candidates
from vulnspider.corpus.collection import ground_truth_key_for
from vulnspider.corpus.fitting import prior_family_scorers, scorers_from_mapping
from vulnspider.corpus.ground_truth import write_ground_truth
from vulnspider.decision.conformal import ConformalThreshold
from vulnspider.decision.policy import run_decision_layer
from vulnspider.discovery import CrawlPolicy
from vulnspider.pipeline import analyze_url
from vulnspider.scoring.calibration import CalibratedScorer

sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus_target_site import build_application, serve  # noqa: E402

FAMILIES = ("SQLI", "REFLECTED_XSS")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluate_heldout",
        description="Held-out recall and request cost for the decision layer.",
    )
    parser.add_argument("--corpus-dir", type=Path, default=Path("data/corpus"))
    parser.add_argument(
        "--first-application",
        type=int,
        default=100,
        help="First held-out application index; must not overlap the corpus.",
    )
    parser.add_argument("--applications", type=int, default=12)
    parser.add_argument("--top-k", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    model_path = args.corpus_dir / "model.json"
    conformal_path = args.corpus_dir / "conformal.json"
    if not model_path.exists() or not conformal_path.exists():
        print(
            f"evaluate_heldout: run tools/build_corpus.py first ({model_path})",
            file=sys.stderr,
        )
        return 1

    fitted = scorers_from_mapping(json.loads(model_path.read_text(encoding="utf-8")))
    prior = prior_family_scorers(FAMILIES)
    conformal = ConformalThreshold.from_mapping(
        json.loads(conformal_path.read_text(encoding="utf-8"))
    )

    indices = range(args.first_application, args.first_application + args.applications)
    print(
        f"evaluate_heldout: {args.applications} unseen applications, "
        f"top-k {args.top_k} each"
    )
    with tempfile.TemporaryDirectory() as directory:
        observations = _observe(indices, Path(directory))

    print(f"{'configuration':34s} {'recall':>12s} {'verified':>9s}")
    for label, scorers, threshold in (
        ("heuristic prior, no guarantee", prior, None),
        ("fitted model, no guarantee", fitted, None),
        ("fitted model + conformal", fitted, conformal),
    ):
        found, positives, verified = _score(
            observations, scorers, threshold, top_k=args.top_k
        )
        recall = found / positives if positives else 0.0
        print(
            f"{label:34s} {found:3d}/{positives:<3d}={recall:4.2f} {verified:9d}"
        )
    return 0


def _observe(
    indices: range,
    workspace: Path,
) -> tuple[tuple[tuple[object, ...], dict[str, bool]], ...]:
    """Run the pipeline once per application and keep candidates plus labels."""

    policy = CrawlPolicy(max_pages=12, max_depth=2, max_requests=60)
    collected = []
    for index in indices:
        spec = build_application(index)
        ground_truth = spec.ground_truth()
        write_ground_truth(ground_truth, workspace / f"{spec.application_id}.json")
        with serve(spec) as base_url:
            analysis = analyze_url(base_url, top_k=1, crawl_policy=policy)

        endpoints = {endpoint.id: endpoint for endpoint in analysis.endpoints}
        points = {point.id: point for point in analysis.input_points}
        labels: dict[str, bool] = {}
        for result in analysis.scoring_results:
            point = points[result.candidate.input_point_id]
            key = ground_truth_key_for(
                application_id=spec.application_id,
                endpoint=endpoints[point.endpoint_id],
                input_point=point,
                vulnerability_type=result.candidate.vulnerability_type.value,
            )
            label = ground_truth.label_for(key)
            if label is not None:
                labels[result.candidate.id or ""] = label
        collected.append((analysis, labels))
    return tuple(collected)


def _score(
    observations: tuple[tuple[object, ...], ...],
    scorers: Mapping[str, CalibratedScorer],
    conformal: ConformalThreshold | None,
    *,
    top_k: int,
) -> tuple[int, int, int]:
    found = positives = verified = 0
    for analysis, labels in observations:
        candidates, _probabilities = build_decision_candidates(analysis, scorers)
        outcome = run_decision_layer(
            candidates,
            top_k=top_k,
            conformal=conformal,
        )
        chosen = {item.candidate_id for item in outcome.selected}
        positives += sum(1 for label in labels.values() if label)
        found += sum(
            1
            for candidate_id, label in labels.items()
            if label and candidate_id in chosen
        )
        verified += len(chosen)
    return found, positives, verified


if __name__ == "__main__":
    raise SystemExit(main())
