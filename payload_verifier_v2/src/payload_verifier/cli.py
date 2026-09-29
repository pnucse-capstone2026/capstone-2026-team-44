from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapter import (
    load_top_candidates,
)
from .models import (
    MutationOutput,
)
from .mutation import (
    LocalPayloadMutator,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "LLM-assisted payload mutation"
        )
    )

    parser.add_argument(
        "result",
        help=(
            "Ranking result JSON path"
        ),
    )

    parser.add_argument(
        "--context",
        required=True,
        help=(
            "Context registry JSON path"
        ),
    )

    parser.add_argument(
        "--out",
        default=(
            "output/"
            "mutation_result.json"
        ),
        help=(
            "Output JSON path"
        ),
    )

    parser.add_argument(
        "--top-k",
        type=int,
        default=4,
        help=(
            "Number of ranked candidates "
            "to mutate"
        ),
    )

    parser.add_argument(
        "--model",
        default=None,
        help=(
            "Gemini model name"
        ),
    )

    return parser


def main() -> None:
    parser = build_parser()

    args = parser.parse_args()

    if args.top_k <= 0:
        parser.error(
            "--top-k must be greater than 0"
        )

    candidates = load_top_candidates(
        result_path=args.result,
        registry_path=args.context,
        top_k=args.top_k,
    )

    mutator = LocalPayloadMutator(
        model=args.model
    )

    records = []

    for candidate in candidates:
        print(
            "[Mutation] "
            f"rank={candidate.rank} "
            f"id={candidate.candidate_id} "
            f"type={candidate.vulnerability_type.value}"
        )

        record = mutator.mutate(
            candidate
        )

        print(
            "  -> "
            f"status={record.status} "
            f"payloads={len(record.payloads)}"
        )

        if record.warnings:
            for warning in record.warnings:
                print(
                    f"  warning: {warning}"
                )

        records.append(
            record
        )

    output = MutationOutput(
        top_k=args.top_k,
        records=records,
    )

    output_path = Path(
        args.out
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            output.model_dump(
                mode="json"
            ),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"Saved: {output_path}"
    )


if __name__ == "__main__":
    main()
