from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class VulnerabilityType(str, Enum):
    SQLI = "SQLI"
    REFLECTED_XSS = "REFLECTED_XSS"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"


ParameterLocation = Literal[
    "query",
    "form",
    "json",
    "path",
    "header",
    "cookie",
]


PayloadKind = Literal[
    "true_condition",
    "false_condition",
    "reflection_control",
    "reflection_marker",
    "authorization_control",
    "authorization_variant",
]


MutationOperation = Literal[
    "replace_parameter",
    "substitute_resource",
    "remove_credentials",
    "change_auth_context",
    "keep_original",
]


CredentialsMode = Literal[
    "preserve",
    "use_context",
    "omit",
]


class RequestContext(BaseModel):
    """
    SQLi / XSS 입력 지점의 요청 문맥.
    """

    method: str
    url: str

    parameter_name: str | None = None
    parameter_location: ParameterLocation | None = None
    parameter_occurrence: int = 0

    original_value: str | None = None

    body: dict[str, Any] | str | None = None


class ResourceItem(BaseModel):
    """
    BAC 검증에 사용할 리소스 식별자.
    """

    value: str
    owner_context_id: str | None = None


class AuthContext(BaseModel):
    """
    로컬 인증 컨텍스트 식별자.

    실제 Cookie, JWT, Authorization 값은 저장하지 않는다.
    """

    context_id: str
    role: str | None = None
    is_anonymous: bool = False


class AccessContext(BaseModel):
    """
    Broken Access Control 검증 문맥.
    """

    method: str
    url: str

    parameter_name: str | None = None
    parameter_location: ParameterLocation | None = None
    parameter_occurrence: int = 0

    original_value: str | None = None

    body: dict[str, Any] | str | None = None

    baseline_auth_context_id: str | None = None

    resources: list[ResourceItem] = Field(
        default_factory=list
    )

    auth_contexts: list[AuthContext] = Field(
        default_factory=list
    )


class NormalizedCandidate(BaseModel):
    """
    result.json 후보와 context_registry.json 문맥을 합친 객체.
    """

    candidate_id: str
    vulnerability_type: VulnerabilityType

    rank: int
    raw_rank_score: float
    selection_priority: float

    input_point_id: str | None = None
    endpoint_id: str | None = None

    evidence: list[dict[str, Any]] = Field(
        default_factory=list
    )

    request_context: RequestContext | None = None
    access_context: AccessContext | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class PayloadDraft(BaseModel):
    """
    Gemini가 생성하는 페이로드 초안.
    """

    kind: PayloadKind
    value: str | None = None
    auth_context_id: str | None = None
    rationale: str
    expected_signal: str


class GeminiMutationResponse(BaseModel):
    """
    Gemini API 응답 형식.
    """

    payloads: list[PayloadDraft]

    warnings: list[Any] = Field(
        default_factory=list
    )


class MutationTarget(BaseModel):
    """
    실제로 변경할 입력 지점.
    """

    location: ParameterLocation | Literal["credentials"]
    parameter_name: str | None = None
    parameter_occurrence: int = 0


class RequestPreview(BaseModel):
    """
    Focused Verification 단계에서 전송할 요청 미리보기.
    """

    method: str
    url: str
    body: dict[str, Any] | str | None = None
    auth_context_id: str | None = None
    credentials_mode: CredentialsMode = "preserve"


class MaterializedPayload(BaseModel):
    """
    PayloadDraft를 실제 요청 변경 형태로 변환한 결과.
    """

    kind: PayloadKind
    value: str | None = None
    operation: MutationOperation
    target: MutationTarget
    auth_context_id: str | None = None
    rationale: str
    expected_signal: str
    baseline_request: RequestPreview
    mutated_request: RequestPreview


class MutationRecord(BaseModel):
    """
    후보 하나에 대한 Mutation 결과.
    """

    candidate_id: str
    vulnerability_type: VulnerabilityType

    status: Literal[
        "generated",
        "skipped_missing_context",
        "generation_failed",
    ]

    model: str | None = None

    payloads: list[MaterializedPayload] = Field(
        default_factory=list
    )

    warnings: list[Any] = Field(
        default_factory=list
    )


class MutationOutput(BaseModel):
    """
    전체 Mutation 실행 결과.
    """

    schema_version: str = "0.1"
    top_k: int
    records: list[MutationRecord]

class ValidationIssue(BaseModel):
    """
    페이로드 검증 중 발견된 문제 하나.
    """

    code: str
    message: str
    severity: Literal[
        "warning",
        "error",
    ] = "error"


class ValidatedPayload(BaseModel):
    """
    개별 MaterializedPayload에 대한 검증 결과.
    """

    candidate_id: str
    vulnerability_type: VulnerabilityType

    payload_index: int
    kind: PayloadKind

    approved: bool

    payload: MaterializedPayload

    issues: list[ValidationIssue] = Field(
        default_factory=list
    )


class ValidationRecord(BaseModel):
    """
    후보 하나에 대한 전체 검증 결과.
    """

    candidate_id: str
    vulnerability_type: VulnerabilityType

    status: Literal[
        "approved",
        "partially_approved",
        "rejected",
        "skipped",
    ]

    total_payloads: int
    approved_payloads: int
    rejected_payloads: int

    payloads: list[ValidatedPayload] = Field(
        default_factory=list
    )

    warnings: list[str] = Field(
        default_factory=list
    )


class ValidationOutput(BaseModel):
    """
    validator.py의 최종 출력 형식.
    """

    schema_version: str = "0.1"

    source_schema_version: str | None = None

    records: list[ValidationRecord]

    summary: dict[str, int]

class VerificationRecord(BaseModel):
    verification_id: str
    candidate_id: str
    vulnerability_type: VulnerabilityType

    result: Literal[
        "supporting",
        "inconclusive",
        "contradicting",
        "execution_failed",
    ]

    observations: list[dict[str, Any]] = Field(
        default_factory=list
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict
    )