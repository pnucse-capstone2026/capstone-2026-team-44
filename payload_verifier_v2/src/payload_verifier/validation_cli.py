from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .models import (
    MutationOutput,
)
from .validator import (
    PayloadValidator,
    ValidatorPolicy,
)


def load_json(
    path: str | Path,
) -> dict[str, Any]:
    return json.loads(
        Path(path).read_text(
            encoding="utf-8-sig"
        )
    )


def load_allowlists(
    context_path: str | Path | None,
    mutation_output: MutationOutput,
) -> tuple[
    dict[str, set[str]],
    dict[str, set[str]],
]:
    """
    context_registry.json에서 BAC 허용 목록을 구성한다.

    Mutation 결과에는 endpoint_id가 없으므로,
    현재 구현에서는 모든 endpoint의 BAC resource/auth context를
    합쳐서 BAC 후보에 적용한다.

    이후 MutationRecord에 endpoint_id를 추가하면
    후보별 endpoint allowlist로 좁히는 것이 더 안전하다.
    """

    if context_path is None:
        return {}, {}

    context = load_json(
        context_path
    )

    all_resources: set[str] = set()
    all_auth_context_ids: set[str] = set()

    for endpoint in (
        context
        .get("endpoints", {})
        .values()
    ):
        for resource in endpoint.get(
            "resources",
            [],
        ):
            value = resource.get(
                "value"
            )

            if value is not None:
                all_resources.add(
                    str(value)
                )

        for auth_context in endpoint.get(
            "auth_contexts",
            [],
        ):
            context_id = auth_context.get(
                "context_id"
            )

            if context_id is not None:
                all_auth_context_ids.add(
                    str(context_id)
                )

    resource_allowlist: dict[
        str,
        set[str],
    ] = {}

    auth_context_allowlist: dict[
        str,
        set[str],
    ] = {}

    for record in mutation_output.records:
        resource_allowlist[
            record.candidate_id
        ] = set(
            all_resources
        )

        auth_context_allowlist[
            record.candidate_id
        ] = set(
            all_auth_context_ids
        )

    return (
        resource_allowlist,
        auth_context_allowlist,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate generated payload mutations"
        )
    )

    parser.add_argument(
        "mutation_result",
        help=(
            "mutation_result.json path"
        ),
    )

    parser.add_argument(
        "--context",
        default=None,
        help=(
            "context_registry.json path"
        ),
    )

    parser.add_argument(
        "--out",
        default=(
            "output/"
            "validation_result.json"
        ),
    )

    parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help=(
            "허용할 host. 여러 번 지정할 수 있습니다."
        ),
    )

    parser.add_argument(
        "--max-payload-length",
        type=int,
        default=256,
    )

    parser.add_argument(
        "--disable-url-restriction",
        action="store_true",
    )

    return parser


def main() -> None:
    parser = build_parser()

    args = parser.parse_args()

    raw_mutation = load_json(
        args.mutation_result
    )

    mutation_output = (
        MutationOutput.model_validate(
            raw_mutation
        )
    )

    policy = ValidatorPolicy(
        enforce_url_restriction=(
            not args.disable_url_restriction
        ),
        allowed_hosts={
            host.lower()
            for host in args.allowed_host
        },
        max_payload_length=(
            args.max_payload_length
        ),
    )

    validator = PayloadValidator(
        policy=policy
    )

    (
        resource_allowlist,
        auth_context_allowlist,
    ) = load_allowlists(
        args.context,
        mutation_output,
    )

    output = validator.validate_output(
        mutation_output,
        resource_allowlist=(
            resource_allowlist
        ),
        auth_context_allowlist=(
            auth_context_allowlist
        ),
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
        "[Validation] "
        f"records={output.summary['total_records']} "
        f"approved_payloads="
        f"{output.summary['approved_payloads']} "
        f"rejected_payloads="
        f"{output.summary['rejected_payloads']}"
    )

    for record in output.records:
        print(
            f"  candidate={record.candidate_id} "
            f"type={record.vulnerability_type.value} "
            f"status={record.status} "
            f"approved={record.approved_payloads}/"
            f"{record.total_payloads}"
        )

        for validated in record.payloads:
            if validated.approved:
                continue

            for validation_issue in (
                validated.issues
            ):
                print(
                    "    rejected "
                    f"payload={validated.payload_index} "
                    f"code={validation_issue.code} "
                    f"message={validation_issue.message}"
                )

    print(
        f"Saved: {output_path}"
    )


if __name__ == "__main__":
    main()