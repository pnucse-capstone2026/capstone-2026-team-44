"""Produce the ranking comparison table `EVALUATION_PROTOCOL.md` §5-§6 specifies.

Runs every comparison arm over the same corpus with the same labels, so the
rows differ only in how candidates are ordered.

    PYTHONPATH=src python tools/evaluate_ranking.py --corpus data/corpus/corpus.jsonl

`--bug-level` repeats the table with candidates of one templated route collapsed
into a single bug (§6-A rule 1). On the current synthetic corpus the two are
identical because every route has a distinct path; the difference appears on
real applications.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnspider.corpus.collection import read_corpus
from vulnspider.evaluation.baselines import (
    BASELINE_HEURISTIC,
    BASELINE_RANDOM,
    BASELINE_REFLECTION,
    PROPOSED_CALIBRATED,
    build_calibrated_queries,
    build_queries,
    full_verification_reference,
    heuristic_score,
    random_score,
    reflection_only_score,
)
from vulnspider.evaluation.metrics import RankingReport, evaluate_ranking

DEFAULT_CUTOFFS = (1, 3, 5, 10)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluate_ranking",
        description="Compare ranking arms on one labeled corpus.",
    )
    parser.add_argument("--corpus", type=Path, default=Path("data/corpus/corpus.jsonl"))
    parser.add_argument(
        "--cutoffs",
        type=int,
        nargs="+",
        default=list(DEFAULT_CUTOFFS),
        help=f"K values to report (default: {' '.join(map(str, DEFAULT_CUTOFFS))}).",
    )
    parser.add_argument(
        "--bug-level",
        action="store_true",
        help="Collapse candidates of one templated route into a single bug.",
    )
    parser.add_argument("-o", "--output", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.corpus.exists():
        print(
            f"evaluate_ranking: {args.corpus} not found; run tools/build_corpus.py",
            file=sys.stderr,
        )
        return 1

    dataset = read_corpus(args.corpus)
    if not dataset.samples:
        print("evaluate_ranking: corpus is empty", file=sys.stderr)
        return 1

    cutoffs = tuple(sorted(set(args.cutoffs)))
    level = "bug-level" if args.bug_level else "candidate-level"
    reference = full_verification_reference(dataset)

    reports: list[RankingReport] = []
    for name, score_for in (
        (BASELINE_RANDOM, random_score),
        (BASELINE_REFLECTION, reflection_only_score),
        (BASELINE_HEURISTIC, heuristic_score),
    ):
        reports.append(
            evaluate_ranking(
                name,
                build_queries(dataset, score_for, bug_level=args.bug_level),
                cutoffs=cutoffs,
            )
        )
    reports.append(
        evaluate_ranking(
            PROPOSED_CALIBRATED,
            build_calibrated_queries(dataset, bug_level=args.bug_level),
            cutoffs=cutoffs,
        )
    )

    counts = dataset.counts()
    print(
        f"evaluate_ranking: {level}, {counts['groups']} applications, "
        f"{reports[0].total_candidates} items, "
        f"{reports[0].total_relevant} relevant, "
        f"{reports[0].total_unlabeled} unlabeled"
    )
    print(
        f"  {reference.as_mapping()['name']}: recall 1.00 at "
        f"{reference.total_requests} requests over {reference.candidates} candidates"
    )
    print()
    _print_table(reports, cutoffs)

    if args.output is not None:
        args.output.write_text(
            json.dumps(
                {
                    "level": level,
                    "cutoffs": list(cutoffs),
                    "full_verification": reference.as_mapping(),
                    "rankings": [report.as_mapping() for report in reports],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nevaluate_ranking: wrote {args.output}")
    return 0


def _print_table(reports: list[RankingReport], cutoffs: tuple[int, ...]) -> None:
    for metric, label in (
        ("recall_at_k", "Recall@K"),
        ("precision_at_k", "Precision@K"),
        ("map_at_k", "MAP@K"),
        ("ndcg_at_k", "NDCG@K"),
    ):
        header = "  ".join(f"K={k:<5d}" for k in cutoffs)
        print(f"{label:<14s} {header}")
        for report in reports:
            cells = "  ".join(
                f"{report.at(k).as_mapping()[metric]:<7.3f}" for k in cutoffs
            )
            print(f"  {report.name:<38s} {cells}")
        print()


if __name__ == "__main__":
    raise SystemExit(main())
