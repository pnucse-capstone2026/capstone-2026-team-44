from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from .models import (
    MaterializedPayload,
    MutationOutput,
    MutationRecord,
    ValidatedPayload,
    ValidationIssue,
    ValidationOutput,
    ValidationRecord,
    VulnerabilityType,
)


# ---------------------------------------------------------------------------
# 기본 정책
# ---------------------------------------------------------------------------

ALLOWED_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",   # 추가
    "PUT",    # 추가
    "PATCH",  # 추가
    "DELETE"
}

MAX_PAYLOAD_LENGTH = 256

MAX_PAYLOADS_PER_CANDIDATE = {
    VulnerabilityType.SQLI: 4,
    VulnerabilityType.REFLECTED_XSS: 3,
    VulnerabilityType.BROKEN_ACCESS_CONTROL: 4,
}

EXPECTED_KIND_COUNTS = {
    VulnerabilityType.SQLI: Counter(
        {
            "true_condition": 2,
            "false_condition": 2,
        }
    ),
    VulnerabilityType.REFLECTED_XSS: Counter(
        {
            "reflection_control": 1,
            "reflection_marker": 2,
        }
    ),
    VulnerabilityType.BROKEN_ACCESS_CONTROL: Counter(
        {
            "authorization_control": 1,
            "authorization_variant": 3,
        }
    ),
}


# SQLi에서 허용하지 않을 구문.
SQL_BLOCK_PATTERNS: list[
    tuple[str, re.Pattern[str]]
] = [
    (
        "SQL_STACKED_QUERY",
        re.compile(
            r";",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL_COMMENT",
        re.compile(
            r"(--|#)",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL_TIME_DELAY",
        re.compile(
            r"\b("
            r"sleep|benchmark|pg_sleep|"
            r"waitfor\s+delay|dbms_lock\.sleep"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL_EXTRACTION",
        re.compile(
            r"\b("
            r"union|select|information_schema|"
            r"load_file|outfile|dumpfile|"
            r"xp_cmdshell"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL_MODIFICATION",
        re.compile(
            r"\b("
            r"insert|update|delete|drop|alter|"
            r"truncate|create|replace|merge|"
            r"grant|revoke"
            r")\b",
            re.IGNORECASE,
        ),
    ),
]


# 실행 가능성이 있는 XSS 구문.
XSS_BLOCK_PATTERNS: list[
    tuple[str, re.Pattern[str]]
] = [
    (
        "XSS_SCRIPT_ELEMENT",
        re.compile(
            r"<\s*/?\s*script\b",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS_EVENT_HANDLER",
        re.compile(
            r"\bon[a-z0-9_-]+\s*=",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS_ACTIVE_SCHEME",
        re.compile(
            r"\b("
            r"javascript|vbscript|data"
            r")\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS_ACTIVE_ELEMENT",
        re.compile(
            r"<\s*/?\s*("
            r"iframe|object|embed|svg|math"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS_EXTERNAL_RESOURCE",
        re.compile(
            r"https?://",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS_COOKIE_ACCESS",
        re.compile(
            r"\bdocument\s*\.\s*cookie\b",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS_STORAGE_ACCESS",
        re.compile(
            r"\b("
            r"localStorage|sessionStorage"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS_EXECUTION_FUNCTION",
        re.compile(
            r"\b("
            r"eval|Function|setTimeout|setInterval"
            r")\s*\(",
            re.IGNORECASE,
        ),
    ),
]


@dataclass
class ValidatorPolicy:
    """
    Validator 실행 정책.

    allowed_hosts가 비어 있으면 baseline host만 허용한다.
    allowed_schemes는 일반적으로 http/https만 허용한다.
    """

    enforce_url_restriction: bool = True

    allowed_hosts: set[str] = field(
        default_factory=set
    )

    allowed_schemes: set[str] = field(
        default_factory=lambda: {
            "http",
            "https",
        }
    )

    allowed_methods: set[str] = field(
        default_factory=lambda: set(
            ALLOWED_METHODS
        )
    )

    max_payload_length: int = MAX_PAYLOAD_LENGTH

    allow_private_targets: bool = True

    require_same_path: bool = True

    require_same_method: bool = True


def issue(
    code: str,
    message: str,
    severity: str = "error",
) -> ValidationIssue:
    return ValidationIssue(
        code=code,
        message=message,
        severity=severity,
    )


def normalize_host(
    url: str,
) -> str:
    return (
        urlsplit(url)
        .hostname
        or ""
    ).lower()


def effective_port(
    url: str,
) -> int | None:
    parts = urlsplit(url)

    if parts.port is not None:
        return parts.port

    if parts.scheme == "http":
        return 80

    if parts.scheme == "https":
        return 443

    return None


def is_private_or_local_host(
    host: str,
) -> bool:
    lowered = host.lower()

    if lowered in {
        "localhost",
        "localhost.localdomain",
    }:
        return True

    try:
        address = ipaddress.ip_address(
            lowered
        )

    except ValueError:
        return False

    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
    )


def compare_query_parameters(
    baseline_url: str,
    mutated_url: str,
) -> list[
    tuple[str, str | None, str | None]
]:
    """
    baseline과 mutated URL의 query 값을 비교한다.

    반환값:
    [
        (parameter_name, baseline_value, mutated_value)
    ]
    """

    baseline_pairs = parse_qsl(
        urlsplit(baseline_url).query,
        keep_blank_values=True,
    )

    mutated_pairs = parse_qsl(
        urlsplit(mutated_url).query,
        keep_blank_values=True,
    )

    max_length = max(
        len(baseline_pairs),
        len(mutated_pairs),
    )

    differences: list[
        tuple[str, str | None, str | None]
    ] = []

    for index in range(max_length):
        baseline_item = (
            baseline_pairs[index]
            if index < len(baseline_pairs)
            else None
        )

        mutated_item = (
            mutated_pairs[index]
            if index < len(mutated_pairs)
            else None
        )

        if baseline_item == mutated_item:
            continue

        if baseline_item is not None:
            name = baseline_item[0]
            baseline_value = baseline_item[1]

        elif mutated_item is not None:
            name = mutated_item[0]
            baseline_value = None

        else:
            continue

        mutated_value = (
            mutated_item[1]
            if mutated_item is not None
            else None
        )

        differences.append(
            (
                name,
                baseline_value,
                mutated_value,
            )
        )

    return differences


class PayloadValidator:
    def __init__(
        self,
        policy: ValidatorPolicy | None = None,
    ) -> None:
        self.policy = (
            policy
            or ValidatorPolicy()
        )

    # ------------------------------------------------------------------
    # 공통 검사
    # ------------------------------------------------------------------

    def validate_common(
        self,
        payload: MaterializedPayload,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []

        baseline = payload.baseline_request
        mutated = payload.mutated_request

        baseline_method = (
            baseline.method.upper()
        )

        mutated_method = (
            mutated.method.upper()
        )

        if (
            mutated_method
            not in self.policy.allowed_methods
        ):
            issues.append(
                issue(
                    "METHOD_NOT_ALLOWED",
                    (
                        "허용되지 않은 HTTP Method입니다: "
                        f"{mutated_method}"
                    ),
                )
            )

        if (
            self.policy.require_same_method
            and baseline_method
            != mutated_method
        ):
            issues.append(
                issue(
                    "METHOD_CHANGED",
                    (
                        "Mutation 과정에서 HTTP Method가 "
                        "변경되었습니다."
                    ),
                )
            )

        baseline_parts = urlsplit(
            baseline.url
        )

        mutated_parts = urlsplit(
            mutated.url
        )

        if (
            mutated_parts.scheme
            not in self.policy.allowed_schemes
        ):
            issues.append(
                issue(
                    "SCHEME_NOT_ALLOWED",
                    (
                        "허용되지 않은 URL scheme입니다: "
                        f"{mutated_parts.scheme}"
                    ),
                )
            )

        if (
            normalize_host(baseline.url)
            != normalize_host(mutated.url)
        ):
            issues.append(
                issue(
                    "HOST_CHANGED",
                    (
                        "Mutation 과정에서 URL host가 "
                        "변경되었습니다."
                    ),
                )
            )

        if (
            effective_port(baseline.url)
            != effective_port(mutated.url)
        ):
            issues.append(
                issue(
                    "PORT_CHANGED",
                    (
                        "Mutation 과정에서 대상 port가 "
                        "변경되었습니다."
                    ),
                )
            )

        if (
            self.policy.require_same_path
            and payload.target.location
            != "path"
            and baseline_parts.path
            != mutated_parts.path
        ):
            issues.append(
                issue(
                    "PATH_CHANGED",
                    (
                        "path 입력 지점이 아닌데 URL path가 "
                        "변경되었습니다."
                    ),
                )
            )

        mutated_host = normalize_host(
            mutated.url
        )

        if (
            self.policy.enforce_url_restriction
        ):
            allowed_hosts = set(
                self.policy.allowed_hosts
            )

            if not allowed_hosts:
                allowed_hosts.add(
                    normalize_host(
                        baseline.url
                    )
                )

            if (
                mutated_host
                not in allowed_hosts
            ):
                issues.append(
                    issue(
                        "HOST_NOT_ALLOWED",
                        (
                            "허용 목록에 없는 host입니다: "
                            f"{mutated_host}"
                        ),
                    )
                )

        if (
            not self.policy.allow_private_targets
            and is_private_or_local_host(
                mutated_host
            )
        ):
            issues.append(
                issue(
                    "PRIVATE_TARGET_NOT_ALLOWED",
                    (
                        "정책에서 사설 또는 로컬 대상 접근을 "
                        "허용하지 않습니다."
                    ),
                )
            )

        value = payload.value

        if (
            value is not None
            and len(value)
            > self.policy.max_payload_length
        ):
            issues.append(
                issue(
                    "PAYLOAD_TOO_LONG",
                    (
                        "페이로드 길이가 제한을 초과했습니다. "
                        f"length={len(value)}, "
                        f"max={self.policy.max_payload_length}"
                    ),
                )
            )

        issues.extend(
            self.validate_target_mutation(
                payload
            )
        )

        return issues

    def validate_target_mutation(
        self,
        payload: MaterializedPayload,
    ) -> list[ValidationIssue]:
        """
        지정한 입력 지점 외의 값이 함께 변경됐는지 확인한다.
        """

        issues: list[ValidationIssue] = []

        target = payload.target
        baseline = payload.baseline_request
        mutated = payload.mutated_request

        if target.location == "query":
            differences = (
                compare_query_parameters(
                    baseline.url,
                    mutated.url,
                )
            )

            changed_names = {
                name
                for name, _, _ in differences
            }

            if target.parameter_name is None:
                issues.append(
                    issue(
                        "TARGET_PARAMETER_MISSING",
                        (
                            "query mutation인데 "
                            "parameter_name이 없습니다."
                        ),
                    )
                )

            elif (
                changed_names
                - {target.parameter_name}
            ):
                issues.append(
                    issue(
                        "UNEXPECTED_PARAMETER_CHANGE",
                        (
                            "지정되지 않은 query parameter도 "
                            "변경되었습니다: "
                            f"{sorted(changed_names)}"
                        ),
                    )
                )

            if (
                payload.operation
                not in {
                    "keep_original",
                    "remove_credentials",
                    "change_auth_context",
                }
                and target.parameter_name
                not in changed_names
            ):
                issues.append(
                    issue(
                        "TARGET_NOT_CHANGED",
                        (
                            "지정된 query parameter 값이 "
                            "변경되지 않았습니다."
                        ),
                    )
                )

        elif target.location in {
            "json",
            "form",
        }:
            baseline_body = baseline.body
            mutated_body = mutated.body

            if not isinstance(
                baseline_body,
                dict,
            ):
                baseline_body = {}

            if not isinstance(
                mutated_body,
                dict,
            ):
                mutated_body = {}

            keys = (
                set(baseline_body)
                | set(mutated_body)
            )

            changed_keys = {
                key
                for key in keys
                if baseline_body.get(key)
                != mutated_body.get(key)
            }

            if target.parameter_name is None:
                issues.append(
                    issue(
                        "TARGET_PARAMETER_MISSING",
                        (
                            "body mutation인데 "
                            "parameter_name이 없습니다."
                        ),
                    )
                )

            elif (
                changed_keys
                - {target.parameter_name}
            ):
                issues.append(
                    issue(
                        "UNEXPECTED_BODY_CHANGE",
                        (
                            "지정되지 않은 body field도 "
                            "변경되었습니다: "
                            f"{sorted(changed_keys)}"
                        ),
                    )
                )

        elif target.location == "credentials":
            if payload.operation == "remove_credentials":
                if (
                    mutated.credentials_mode
                    != "omit"
                ):
                    issues.append(
                        issue(
                            "CREDENTIALS_NOT_REMOVED",
                            (
                                "remove_credentials인데 "
                                "credentials_mode가 omit이 아닙니다."
                            ),
                        )
                    )

                if (
                    mutated.auth_context_id
                    is not None
                ):
                    issues.append(
                        issue(
                            "ANONYMOUS_CONTEXT_INVALID",
                            (
                                "인증 제거 요청에 "
                                "auth_context_id가 남아 있습니다."
                            ),
                        )
                    )

                if baseline.url != mutated.url:
                    issues.append(
                        issue(
                            "URL_CHANGED_DURING_CREDENTIAL_STRIP",
                            (
                                "Credential Strip 과정에서 "
                                "URL이 변경되었습니다."
                            ),
                        )
                    )

                if baseline.body != mutated.body:
                    issues.append(
                        issue(
                            "BODY_CHANGED_DURING_CREDENTIAL_STRIP",
                            (
                                "Credential Strip 과정에서 "
                                "request body가 변경되었습니다."
                            ),
                        )
                    )

        return issues

    # ------------------------------------------------------------------
    # SQLi 검사
    # ------------------------------------------------------------------

    def validate_sqli(
        self,
        payload: MaterializedPayload,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []

        value = payload.value or ""

        if not value:
            issues.append(
                issue(
                    "SQLI_EMPTY_PAYLOAD",
                    "SQLi 페이로드 값이 비어 있습니다.",
                )
            )

            return issues

        for code, pattern in SQL_BLOCK_PATTERNS:
            match = pattern.search(
                value
            )

            if match:
                issues.append(
                    issue(
                        code,
                        (
                            "허용되지 않은 SQL 구문이 "
                            "포함되어 있습니다: "
                            f"{match.group(0)}"
                        ),
                    )
                )

        if payload.kind not in {
            "true_condition",
            "false_condition",
        }:
            issues.append(
                issue(
                    "SQLI_KIND_INVALID",
                    (
                        "SQLi에서 허용되지 않은 "
                        f"payload kind입니다: {payload.kind}"
                    ),
                )
            )

        return issues

    # ------------------------------------------------------------------
    # XSS 검사
    # ------------------------------------------------------------------

    def validate_xss(
        self,
        payload: MaterializedPayload,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []

        value = payload.value or ""

        if "xss-probe" not in value.lower():
            issues.append(
                issue(
                    "XSS_MARKER_MISSING",
                    (
                        "XSS 페이로드에 필수 marker인 "
                        "'xss-probe'가 없습니다."
                    ),
                )
            )

        for code, pattern in XSS_BLOCK_PATTERNS:
            match = pattern.search(
                value
            )

            if match:
                issues.append(
                    issue(
                        code,
                        (
                            "실행 가능성이 있는 XSS 구문이 "
                            "포함되어 있습니다: "
                            f"{match.group(0)}"
                        ),
                    )
                )

        if payload.kind not in {
            "reflection_control",
            "reflection_marker",
        }:
            issues.append(
                issue(
                    "XSS_KIND_INVALID",
                    (
                        "XSS에서 허용되지 않은 "
                        f"payload kind입니다: {payload.kind}"
                    ),
                )
            )

        return issues

    # ------------------------------------------------------------------
    # BAC 검사
    # ------------------------------------------------------------------

    def validate_bac(
        self,
        payload: MaterializedPayload,
        allowed_resource_values: set[str],
        allowed_auth_context_ids: set[str],
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []

        if payload.kind not in {
            "authorization_control",
            "authorization_variant",
        }:
            issues.append(
                issue(
                    "BAC_KIND_INVALID",
                    (
                        "BAC에서 허용되지 않은 "
                        f"payload kind입니다: {payload.kind}"
                    ),
                )
            )
        """
        if payload.operation in {
            "substitute_resource",
            "keep_original",
        }:
            if (
                payload.value is not None
                and payload.value
                not in allowed_resource_values
            ):
                issues.append(
                    issue(
                        "BAC_RESOURCE_NOT_ALLOWED",
                        (
                            "허용 목록에 없는 resource "
                            f"value입니다: {payload.value}"
                        ),
                    )
                )

        if (
            payload.auth_context_id
            is not None
            and payload.auth_context_id
            not in allowed_auth_context_ids
        ):
            issues.append(
                issue(
                    "BAC_AUTH_CONTEXT_NOT_ALLOWED",
                    (
                        "허용 목록에 없는 auth_context_id입니다: "
                        f"{payload.auth_context_id}"
                    ),
                )
            )
        """
        if payload.operation == "remove_credentials":
            if payload.mutated_request.credentials_mode != "omit":
                issues.append(
                    issue(
                        "BAC_CREDENTIAL_MODE_INVALID",
                        (
                            "remove_credentials 요청은 "
                            "credentials_mode=omit이어야 합니다."
                        ),
                    )
                )

        elif payload.operation == "change_auth_context":
            """
            if (
                payload.mutated_request.auth_context_id
                is None
            ):
                issues.append(
                    issue(
                        "BAC_AUTH_CONTEXT_MISSING",
                        (
                            "change_auth_context 요청에 "
                            "auth_context_id가 없습니다."
                        ),
                    )
                )
            """
            pass
        return issues

    # ------------------------------------------------------------------
    # 개별 payload / record 검사
    # ------------------------------------------------------------------

    def validate_payload(
        self,
        record: MutationRecord,
        payload: MaterializedPayload,
        payload_index: int,
        allowed_resource_values: set[str],
        allowed_auth_context_ids: set[str],
    ) -> ValidatedPayload:
        issues = self.validate_common(
            payload
        )

        if (
            record.vulnerability_type
            == VulnerabilityType.SQLI
        ):
            issues.extend(
                self.validate_sqli(
                    payload
                )
            )

        elif (
            record.vulnerability_type
            == VulnerabilityType.REFLECTED_XSS
        ):
            issues.extend(
                self.validate_xss(
                    payload
                )
            )

        elif (
            record.vulnerability_type
            == VulnerabilityType.BROKEN_ACCESS_CONTROL
        ):
            issues.extend(
                self.validate_bac(
                    payload,
                    allowed_resource_values,
                    allowed_auth_context_ids,
                )
            )

        approved = not any(
            item.severity == "error"
            for item in issues
        )

        return ValidatedPayload(
            candidate_id=record.candidate_id,
            vulnerability_type=(
                record.vulnerability_type
            ),
            payload_index=payload_index,
            kind=payload.kind,
            approved=approved,
            payload=payload,
            issues=issues,
        )

    def validate_record(
        self,
        record: MutationRecord,
        allowed_resource_values: set[str] | None = None,
        allowed_auth_context_ids: set[str] | None = None,
    ) -> ValidationRecord:
        allowed_resource_values = (
            allowed_resource_values
            or set()
        )

        allowed_auth_context_ids = (
            allowed_auth_context_ids
            or set()
        )

        if record.status != "generated":
            return ValidationRecord(
                candidate_id=record.candidate_id,
                vulnerability_type=(
                    record.vulnerability_type
                ),
                status="skipped",
                total_payloads=0,
                approved_payloads=0,
                rejected_payloads=0,
                payloads=[],
                warnings=[
                    (
                        "Mutation status가 generated가 "
                        f"아닙니다: {record.status}"
                    )
                ],
            )

        record_warnings: list[str] = []

        max_count = MAX_PAYLOADS_PER_CANDIDATE[
            record.vulnerability_type
        ]

        if len(record.payloads) > max_count:
            record_warnings.append(
                (
                    "허용된 페이로드 수를 초과했습니다. "
                    f"actual={len(record.payloads)}, "
                    f"max={max_count}"
                )
            )
        """
        actual_kinds = Counter(
            item.kind
            for item in record.payloads
        )

        expected_kinds = EXPECTED_KIND_COUNTS[
            record.vulnerability_type
        ]

        kind_structure_valid = (
            actual_kinds
            == expected_kinds
        )

        if not kind_structure_valid:
            record_warnings.append(
                (
                    "취약점 유형별 payload kind 구성이 "
                    "예상과 다릅니다. "
                    f"expected={dict(expected_kinds)}, "
                    f"actual={dict(actual_kinds)}"
                )
            )
        """
        validated_payloads: list[
            ValidatedPayload
        ] = []

        for index, payload in enumerate(
            record.payloads
        ):
            validated = self.validate_payload(
                record=record,
                payload=payload,
                payload_index=index,
                allowed_resource_values=(
                    allowed_resource_values
                ),
                allowed_auth_context_ids=(
                    allowed_auth_context_ids
                ),
            )

            if (
                len(record.payloads) > max_count
            ):
                validated.approved = False

                validated.issues.append(
                    issue(
                        "PAYLOAD_SET_INVALID",
                        (
                            "후보 전체의 payload 개수가 "
                            "제한을 초과했습니다."
                        ),
                    )
                )

            validated_payloads.append(
                validated
            )

        approved_count = sum(
            1
            for item in validated_payloads
            if item.approved
        )

        total_count = len(
            validated_payloads
        )

        rejected_count = (
            total_count
            - approved_count
        )

        if (
            total_count > 0
            and approved_count
            == total_count
        ):
            status = "approved"

        elif approved_count > 0:
            status = "partially_approved"

        else:
            status = "rejected"

        return ValidationRecord(
            candidate_id=record.candidate_id,
            vulnerability_type=(
                record.vulnerability_type
            ),
            status=status,
            total_payloads=total_count,
            approved_payloads=approved_count,
            rejected_payloads=rejected_count,
            payloads=validated_payloads,
            warnings=record_warnings,
        )

    def validate_output(
        self,
        mutation_output: MutationOutput,
        resource_allowlist: dict[
            str,
            set[str],
        ] | None = None,
        auth_context_allowlist: dict[
            str,
            set[str],
        ] | None = None,
    ) -> ValidationOutput:
        resource_allowlist = (
            resource_allowlist
            or {}
        )

        auth_context_allowlist = (
            auth_context_allowlist
            or {}
        )

        records: list[
            ValidationRecord
        ] = []

        for mutation_record in (
            mutation_output.records
        ):
            validation_record = (
                self.validate_record(
                    mutation_record,
                    allowed_resource_values=(
                        resource_allowlist.get(
                            mutation_record.candidate_id,
                            set(),
                        )
                    ),
                    allowed_auth_context_ids=(
                        auth_context_allowlist.get(
                            mutation_record.candidate_id,
                            set(),
                        )
                    ),
                )
            )

            records.append(
                validation_record
            )

        total_payloads = sum(
            record.total_payloads
            for record in records
        )

        approved_payloads = sum(
            record.approved_payloads
            for record in records
        )

        rejected_payloads = sum(
            record.rejected_payloads
            for record in records
        )

        return ValidationOutput(
            source_schema_version=(
                mutation_output.schema_version
            ),
            records=records,
            summary={
                "total_records": len(records),
                "approved_records": sum(
                    record.status == "approved"
                    for record in records
                ),
                "partially_approved_records": sum(
                    record.status
                    == "partially_approved"
                    for record in records
                ),
                "rejected_records": sum(
                    record.status == "rejected"
                    for record in records
                ),
                "skipped_records": sum(
                    record.status == "skipped"
                    for record in records
                ),
                "total_payloads": total_payloads,
                "approved_payloads": (
                    approved_payloads
                ),
                "rejected_payloads": (
                    rejected_payloads
                ),
            },
        )