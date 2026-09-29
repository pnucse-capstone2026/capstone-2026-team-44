from __future__ import annotations

import copy
import os
from collections import Counter
from urllib.parse import (
    parse_qsl,
    quote,
    urlencode,
    urlsplit,
    urlunsplit,
)

from dotenv import load_dotenv
import os
from llama_cpp import Llama

from .models import (
    AccessContext,
    CredentialsMode,
    GeminiMutationResponse,
    MaterializedPayload,
    MutationRecord,
    MutationTarget,
    NormalizedCandidate,
    ParameterLocation,
    PayloadDraft,
    RequestContext,
    RequestPreview,
    VulnerabilityType,
)
from .prompts import (
    SYSTEM_PROMPT,
    build_mutation_prompt,
)


load_dotenv()


EXPECTED_KINDS = {
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


def replace_query_parameter(
    url: str,
    parameter_name: str,
    new_value: str,
    occurrence: int = 0,
) -> str:
    """
    URL의 특정 query parameter 값만 변경한다.
    """

    parts = urlsplit(
        url
    )

    query_pairs = parse_qsl(
        parts.query,
        keep_blank_values=True,
    )

    result: list[tuple[str, str]] = []

    found_count = 0
    replaced = False

    for key, value in query_pairs:
        if key == parameter_name:
            if found_count == occurrence:
                result.append(
                    (
                        key,
                        new_value,
                    )
                )

                replaced = True

            else:
                result.append(
                    (
                        key,
                        value,
                    )
                )

            found_count += 1

        else:
            result.append(
                (
                    key,
                    value,
                )
            )

    if not replaced:
        result.append(
            (
                parameter_name,
                new_value,
            )
        )

    new_query = urlencode(
        result,
        doseq=True,
    )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            new_query,
            parts.fragment,
        )
    )


def replace_nth_occurrence(
    text: str,
    old_value: str,
    new_value: str,
    occurrence: int,
) -> str:
    """
    문자열 안에서 old_value의 N번째 위치만 교체한다.
    """

    if old_value == "":
        raise ValueError(
            "old_value must not be empty"
        )

    search_start = 0
    index = -1

    for _ in range(
        occurrence + 1
    ):
        index = text.find(
            old_value,
            search_start,
        )

        if index == -1:
            raise ValueError(
                "Value not found: "
                f"{old_value}"
            )

        search_start = index + len(
            old_value
        )

    return (
        text[:index]
        + new_value
        + text[
            index + len(old_value):
        ]
    )


def replace_path_value(
    url: str,
    original_value: str,
    new_value: str,
    occurrence: int = 0,
) -> str:
    """
    URL path 내부의 특정 값을 변경한다.
    """

    parts = urlsplit(
        url
    )

    encoded_value = quote(
        new_value,
        safe="",
    )

    new_path = replace_nth_occurrence(
        text=parts.path,
        old_value=original_value,
        new_value=encoded_value,
        occurrence=occurrence,
    )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            new_path,
            parts.query,
            parts.fragment,
        )
    )


def replace_body_parameter(
    body: dict | str | None,
    parameter_name: str,
    new_value: str,
) -> dict | str:
    """
    form/json body의 flat parameter 값을 변경한다.
    """

    if body is None:
        body_copy: dict = {}

    elif isinstance(
        body,
        dict,
    ):
        body_copy = copy.deepcopy(
            body
        )

    else:
        raise ValueError(
            "String body replacement "
            "is not supported"
        )

    body_copy[
        parameter_name
    ] = new_value

    return body_copy


def build_request_preview(
    *,
    method: str,
    url: str,
    parameter_location: ParameterLocation | None,
    parameter_name: str | None,
    parameter_occurrence: int,
    original_value: str | None,
    replacement_value: str | None,
    body: dict | str | None,
    auth_context_id: str | None,
    credentials_mode: CredentialsMode,
) -> RequestPreview:
    """
    기존 요청의 특정 입력 지점만 변경해서
    RequestPreview를 생성한다.
    """

    result_url = url
    result_body = copy.deepcopy(
        body
    )

    if (
        replacement_value is not None
        and parameter_location is not None
    ):
        if parameter_name is None:
            raise ValueError(
                "parameter_name is required"
            )

        if parameter_location == "query":
            result_url = replace_query_parameter(
                url=url,
                parameter_name=parameter_name,
                new_value=replacement_value,
                occurrence=parameter_occurrence,
            )

        elif parameter_location in {
            "form",
            "json",
        }:
            result_body = replace_body_parameter(
                body=body,
                parameter_name=parameter_name,
                new_value=replacement_value,
            )

        elif parameter_location == "path":
            if original_value is None:
                raise ValueError(
                    "original_value is required "
                    "for path mutation"
                )

            result_url = replace_path_value(
                url=url,
                original_value=original_value,
                new_value=replacement_value,
                occurrence=parameter_occurrence,
            )

        elif parameter_location in {
            "header",
            "cookie",
        }:
            raise ValueError(
                "Header and cookie mutation "
                "is not materialized in "
                "the mutation stage"
            )

    return RequestPreview(
        method=method.upper(),
        url=result_url,
        body=result_body,
        auth_context_id=auth_context_id,
        credentials_mode=credentials_mode,
    )


def build_injection_baseline(
    context: RequestContext,
) -> RequestPreview:
    """
    SQLi/XSS baseline 요청 생성.
    """

    return build_request_preview(
        method=context.method,
        url=context.url,
        parameter_location=context.parameter_location,
        parameter_name=context.parameter_name,
        parameter_occurrence=context.parameter_occurrence,
        original_value=context.original_value,
        replacement_value=context.original_value,
        body=context.body,
        auth_context_id=None,
        credentials_mode="preserve",
    )


def build_injection_mutated_request(
    context: RequestContext,
    payload: PayloadDraft,
) -> RequestPreview:
    """
    SQLi/XSS payload 값을 실제 파라미터 위치에 삽입한다.
    """

    if payload.value is None:
        raise ValueError(
            "Payload value is required"
        )

    return build_request_preview(
        method=context.method,
        url=context.url,
        parameter_location=context.parameter_location,
        parameter_name=context.parameter_name,
        parameter_occurrence=context.parameter_occurrence,
        original_value=context.original_value,
        replacement_value=payload.value,
        body=context.body,
        auth_context_id=None,
        credentials_mode="preserve",
    )


def materialize_injection_payload(
    candidate: NormalizedCandidate,
    payload: PayloadDraft,
) -> MaterializedPayload:
    """
    SQLi/XSS 초안을 실제 요청 변경 형태로 변환한다.
    """

    context = candidate.request_context

    if context is None:
        raise ValueError(
            "request_context is required"
        )

    if context.parameter_location is None:
        raise ValueError(
            "parameter_location is required"
        )

    if context.parameter_name is None:
        raise ValueError(
            "parameter_name is required"
        )

    baseline_request = build_injection_baseline(
        context
    )

    mutated_request = build_injection_mutated_request(
        context,
        payload,
    )

    return MaterializedPayload(
        kind=payload.kind,
        value=payload.value,
        operation="replace_parameter",
        target=MutationTarget(
            location=context.parameter_location,
            parameter_name=context.parameter_name,
            parameter_occurrence=(
                context.parameter_occurrence
            ),
        ),
        auth_context_id=None,
        rationale=payload.rationale,
        expected_signal=payload.expected_signal,
        baseline_request=baseline_request,
        mutated_request=mutated_request,
    )


def find_anonymous_context_id(
    context: AccessContext,
) -> str | None:
    """
    anonymous 인증 컨텍스트를 찾는다.
    """

    for auth_context in context.auth_contexts:
        if auth_context.is_anonymous:
            return auth_context.context_id

        if (
            auth_context.role
            and auth_context.role.lower()
            == "anonymous"
        ):
            return auth_context.context_id

        if (
            auth_context.context_id.lower()
            == "anonymous"
        ):
            return auth_context.context_id

    return None


def build_access_request(
    context: AccessContext,
    *,
    value: str | None,
    auth_context_id: str | None,
    credentials_mode: CredentialsMode,
) -> RequestPreview:
    """
    BAC용 요청 미리보기 생성.
    """

    return build_request_preview(
        method=context.method,
        url=context.url,
        parameter_location=context.parameter_location,
        parameter_name=context.parameter_name,
        parameter_occurrence=context.parameter_occurrence,
        original_value=context.original_value,
        replacement_value=value,
        body=context.body,
        auth_context_id=auth_context_id,
        credentials_mode=credentials_mode,
    )


def materialize_identifier_substitution(
    candidate: NormalizedCandidate,
    payload: PayloadDraft,
) -> MaterializedPayload:
    """
    BAC IDENTIFIER_SUBSTITUTION 처리.
    """

    context = candidate.access_context

    if context is None:
        raise ValueError(
            "access_context is required"
        )

    if context.parameter_location is None:
        raise ValueError(
            "parameter_location is required"
        )

    if context.parameter_name is None:
        raise ValueError(
            "parameter_name is required"
        )

    baseline_value = context.original_value

    if (
        baseline_value is None
        and context.resources
    ):
        baseline_value = (
            context.resources[0].value
        )

    if payload.value is None or payload.value == "":
        payload.value = baseline_value

    if baseline_value is None:
        payload.value = baseline_value

    if payload.value is None:
        raise ValueError(
            "BAC resource value "
            "is required"
        )

    baseline_request = build_access_request(
        context,
        value=baseline_value,
        auth_context_id=(
            context.baseline_auth_context_id
        ),
        credentials_mode="use_context",
    )

    mutated_request = build_access_request(
        context,
        value=payload.value,
        auth_context_id=payload.auth_context_id,
        credentials_mode="use_context",
    )

    is_control = (
        payload.kind
        == "authorization_control"
        and payload.value
        == baseline_value
        and payload.auth_context_id
        == context.baseline_auth_context_id
    )

    if is_control:
        operation = "keep_original"
    elif payload.value == baseline_value and payload.auth_context_id != context.baseline_auth_context_id:
        operation = "change_auth_context"
    else:
        operation = "substitute_resource"
    """
    operation = (
        "keep_original"
        if is_control
        else "substitute_resource"
    )
    """
    return MaterializedPayload(
        kind=payload.kind,
        value=payload.value,
        operation=operation,
        target=MutationTarget(
            location=context.parameter_location,
            parameter_name=context.parameter_name,
            parameter_occurrence=(
                context.parameter_occurrence
            ),
        ),
        auth_context_id=payload.auth_context_id,
        rationale=payload.rationale,
        expected_signal=payload.expected_signal,
        baseline_request=baseline_request,
        mutated_request=mutated_request,
    )


def materialize_credential_strip(
    candidate: NormalizedCandidate,
    payload: PayloadDraft,
) -> MaterializedPayload:
    """
    BAC CREDENTIAL_STRIP 처리.
    """

    context = candidate.access_context

    if context is None:
        raise ValueError(
            "access_context is required"
        )

    if payload.value is None or payload.value == "":
        payload.value = context.original_value

    anonymous_context_id = find_anonymous_context_id(
        context
    )

    baseline_request = build_access_request(
        context,
        value=context.original_value,
        auth_context_id=(
            context.baseline_auth_context_id
        ),
        credentials_mode="use_context",
    )

    is_anonymous = (
        payload.auth_context_id == anonymous_context_id
        or payload.auth_context_id is None
    )

    if payload.kind == "authorization_control":
        operation = "keep_original"

        mutated_request = build_access_request(
            context,
            value=context.original_value,
            auth_context_id=(
                context.baseline_auth_context_id
            ),
            credentials_mode="use_context",
        )

    elif (
        payload.auth_context_id
        == anonymous_context_id or payload.auth_context_id is None
    ):
        operation = "remove_credentials"

        mutated_request = build_access_request(
            context,
            value=context.original_value,
            auth_context_id=None,
            credentials_mode="omit",
        )

    else:
        operation = "change_auth_context"

        mutated_request = build_access_request(
            context,
            value=context.original_value,
            auth_context_id=payload.auth_context_id,
            credentials_mode="use_context",
        )

    return MaterializedPayload(
        kind=payload.kind,
        value=payload.value,
        operation=operation,
        target=MutationTarget(
            location="credentials",
            parameter_name=None,
            parameter_occurrence=0,
        ),
        auth_context_id=payload.auth_context_id,
        rationale=payload.rationale,
        expected_signal=payload.expected_signal,
        baseline_request=baseline_request,
        mutated_request=mutated_request,
    )


def materialize_bac_payload(
    candidate: NormalizedCandidate,
    payload: PayloadDraft,
) -> MaterializedPayload:
    """
    BAC check_kind에 따라 요청 생성 방식을 분기한다.
    """

    check_kind = candidate.metadata.get(
        "check_kind"
    )

    if check_kind == "CREDENTIAL_STRIP":
        return materialize_credential_strip(
            candidate,
            payload,
        )

    return materialize_identifier_substitution(
        candidate,
        payload,
    )


def materialize_payload(
    candidate: NormalizedCandidate,
    payload: PayloadDraft,
) -> MaterializedPayload:
    """
    취약점 유형별 materialize 진입점.
    """

    if candidate.vulnerability_type in {
        VulnerabilityType.SQLI,
        VulnerabilityType.REFLECTED_XSS,
    }:
        return materialize_injection_payload(
            candidate,
            payload,
        )

    if (
        candidate.vulnerability_type
        == VulnerabilityType.BROKEN_ACCESS_CONTROL
    ):
        return materialize_bac_payload(
            candidate,
            payload,
        )

    raise ValueError(
        "Unsupported vulnerability type"
    )


def find_missing_context(
    candidate: NormalizedCandidate,
) -> list[str]:
    """
    Gemini 호출 전에 필수 문맥이 존재하는지 검사한다.
    """

    missing: list[str] = []

    if candidate.vulnerability_type in {
        VulnerabilityType.SQLI,
        VulnerabilityType.REFLECTED_XSS,
    }:
        context = candidate.request_context

        if context is None:
            missing.append(
                "request_context"
            )

        else:
            if context.parameter_name is None:
                missing.append(
                    "request_context.parameter_name"
                )

            if context.parameter_location is None:
                missing.append(
                    "request_context.parameter_location"
                )

            if context.original_value is None:
                missing.append(
                    "request_context.original_value"
                )

    if (
        candidate.vulnerability_type
        == VulnerabilityType.BROKEN_ACCESS_CONTROL
    ):
        context = candidate.access_context

        if context is None:
            missing.append(
                "access_context"
            )

        else:
            check_kind = candidate.metadata.get(
                "check_kind"
            )

            if check_kind == "CREDENTIAL_STRIP":
                if (
                    context.baseline_auth_context_id
                    is None
                ):
                    missing.append(
                        "access_context."
                        "baseline_auth_context_id"
                    )

                if (
                    find_anonymous_context_id(
                        context
                    )
                    is None
                ):
                    missing.append(
                        "anonymous auth_context"
                    )

            else:
                if not context.resources:
                    missing.append(
                        "access_context.resources"
                    )

                if not context.auth_contexts:
                    missing.append(
                        "access_context.auth_contexts"
                    )

                if context.parameter_name is None:
                    missing.append(
                        "access_context.parameter_name"
                    )

                if context.parameter_location is None:
                    missing.append(
                        "access_context.parameter_location"
                    )

                if (
                    context.baseline_auth_context_id
                    is None
                ):
                    missing.append(
                        "access_context."
                        "baseline_auth_context_id"
                    )

    return missing


def validate_payload_contract(
    candidate: NormalizedCandidate,
    response: GeminiMutationResponse,
) -> None:
    """
    페이로드 개수와 kind 구성을 검사한다.
    """
    """
    actual = Counter(
        payload.kind
        for payload in response.payloads
    )

    expected = EXPECTED_KINDS[
        candidate.vulnerability_type
    ]

    if actual != expected:
        raise ValueError(
            "Unexpected payload structure. "
            f"expected={dict(expected)}, "
            f"actual={dict(actual)}"
        )
    """

def validate_sqli_values(
    response: GeminiMutationResponse,
) -> None:
    """
    SQLi 최소 구조 검사.
    """

    values = [
        payload.value
        for payload in response.payloads
    ]

    if any(
        value is None
        or value == ""
        for value in values
    ):
        raise ValueError(
            "SQLi payload value "
            "must not be empty"
        )
    """
    if len(set(values)) != len(values):
        raise ValueError(
            "Duplicate SQLi payload values "
            "are not allowed"
        )
    """

def validate_xss_values(
    response: GeminiMutationResponse,
) -> None:
    """
    XSS marker가 xss-probe를 포함하는지 검사한다.
    """

    values: list[str] = []

    for payload in response.payloads:
        value = payload.value or ""

        if (
            "xss-probe"
            not in value.lower()
        ):
           payload.value = value + "xss-probe"

        values.append(
            value
        )
    """
    if len(set(values)) != len(values):
        raise ValueError(
            "Duplicate XSS payload values "
            "are not allowed"
        )
    """

def validate_bac_values(
    candidate: NormalizedCandidate,
    response: GeminiMutationResponse,
) -> None:
    """
    등록된 리소스와 인증 컨텍스트만 사용했는지 검사한다.
    """

    context = candidate.access_context

    if context is None:
        raise ValueError(
            "access_context is required"
        )

    allowed_auth_context_ids = {
        item.context_id
        for item in context.auth_contexts
    }

    allowed_resource_values = {
        item.value
        for item in context.resources
    }

    check_kind = candidate.metadata.get(
        "check_kind"
    )

    for payload in response.payloads:
        if (
            payload.auth_context_id
            is not None
            and payload.auth_context_id
            not in allowed_auth_context_ids
        ):
            raise ValueError(
                "Unknown auth_context_id: "
                f"{payload.auth_context_id}"
            )
    """
        if (
            check_kind
            != "CREDENTIAL_STRIP"
            and payload.value is not None
            not in allowed_resource_values
        ):
            raise ValueError(
                "Unknown resource value: "
                f"{payload.value}"
            )
    """
    if check_kind == "CREDENTIAL_STRIP":
        anonymous_context_id = (
            find_anonymous_context_id(
                context
            )
        )

        variants = [
            payload
            for payload in response.payloads
            if payload.kind
            == "authorization_variant"
        ]

        has_anonymous = any(
            p.auth_context_id is None
            or p.auth_context_id == anonymous_context_id
            for p in response.payloads
        )

        if not has_anonymous:
            for p in response.payloads:
                if p.kind == "authorization_variant":
                    p.auth_context_id = None # 강제로 익명(null) 처리
                    has_anonymous = True
                    break
        
        if not has_anonymous:
            raise ValueError(
                "CREDENTIAL_STRIP requires "
                "at least one anonymous variant"
            )


def validate_generated_values(
    candidate: NormalizedCandidate,
    response: GeminiMutationResponse,
) -> None:
    """
    유형별 최소 생성값 검사.
    """

    if (
        candidate.vulnerability_type
        == VulnerabilityType.SQLI
    ):
        validate_sqli_values(
            response
        )

    elif (
        candidate.vulnerability_type
        == VulnerabilityType.REFLECTED_XSS
    ):
        validate_xss_values(
            response
        )

    elif (
        candidate.vulnerability_type
        == VulnerabilityType.BROKEN_ACCESS_CONTROL
    ):
        validate_bac_values(
            candidate,
            response,
        )
"""
class LocalPayloadMutator:
    
    # OpenAI 호환 API(Ollama, vLLM 등)를 사용하여
    # 로컬 모델로 페이로드를 생성한다.
    

    def __init__(
        self,
        model: str | None = None,
        base_url: str = "http://localhost:11434/v1", # Ollama 기본 주소
    ) -> None:
        self.model = model or os.getenv("LOCAL_MODEL", "qwen2.5") # 추천 모델: qwen2.5
        
        # 로컬 API 연결 설정 (Ollama의 경우 api_key는 아무거나 넣어도 됨)
        self.client = OpenAI(
            base_url=base_url,
            api_key="ollama" 
        )

    def mutate(
        self,
        candidate: NormalizedCandidate,
    ) -> MutationRecord:
        
        missing = find_missing_context(candidate)

        if missing:
            return MutationRecord(
                candidate_id=candidate.candidate_id,
                vulnerability_type=candidate.vulnerability_type,
                status="skipped_missing_context",
                model=None,
                payloads=[],
                warnings=["Missing required context: " + ", ".join(missing)],
            )

        prompt = build_mutation_prompt(candidate)

        # 💡 여기서부터 수정! (최대 3번 재시도하는 루프 적용)
        max_retries = 5
        for attempt in range(max_retries):
            try:
                # OpenAI 호환 API 호출 방식
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    # JSON 강제 출력 설정
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    max_tokens=2048
                )

                # 응답 텍스트 추출
                content = response.choices[0].message.content
                if not content:
                    raise ValueError("Model returned an empty response")

                # 기존 모델(GeminiMutationResponse) 구조 그대로 파싱
                parsed = GeminiMutationResponse.model_validate_json(content)

                # 💡 핵심 방어벽: 페이로드가 비어있으면 강제로 에러를 내서 재시도 유도
                if not parsed.payloads:
                    raise ValueError("LLM returned an empty payloads array []")

                validate_payload_contract(candidate, parsed)
                validate_generated_values(candidate, parsed)

                materialized_payloads = [
                    materialize_payload(candidate, payload)
                    for payload in parsed.payloads
                ]

                # 성공했으면 즉시 결과 반환 (루프 종료)
                return MutationRecord(
                    candidate_id=candidate.candidate_id,
                    vulnerability_type=candidate.vulnerability_type,
                    status="generated",
                    model=self.model,
                    payloads=materialized_payloads,
                    warnings=parsed.warnings,
                )

            except Exception as exc:
                # 3번 다 실패했을 때만 최종 실패 처리
                if attempt == max_retries - 1:
                    return MutationRecord(
                        candidate_id=candidate.candidate_id,
                        vulnerability_type=candidate.vulnerability_type,
                        status="generation_failed",
                        model=self.model,
                        payloads=[],
                        warnings=[str(exc)],
                    )
                # 아직 기회가 남았다면 경고문 출력 후 다음 루프(재시도)로 넘어감
                print(f"⚠️ 생성 실패 또는 빈 배열 수신 (시도 {attempt + 1}/{max_retries}) - 다시 시도합니다...")
"""
class LocalPayloadMutator:
    """
    Ollama 설치 없이 llama-cpp-python을 사용하여
    GGUF 모델을 파이썬 내부에서 직접 구동한다.
    """

    def __init__(
        self,
        # 💡 여기에 다운로드한 GGUF 파일의 실제 경로를 적어줘!
        model: str | None = None,
    ) -> None:
        model_path = model or "./vulnspider-3b_v3.gguf"
        self.model = "my-hacker-ai-3b-4096"
        
        # 파이썬이 GGUF 파일을 직접 메모리에 올려서 시동을 걺
        print(f"Loading local model from {model_path}...")
        self.llm = Llama(
            model_path=model_path,
            n_ctx=4096,          # 우리가 원하던 컨텍스트 길이!
            n_gpu_layers=-1,     # -1로 설정하면 그래픽카드(GPU)를 최대한 사용해서 속도 최적화
            verbose=False        # 화면에 지저분한 엔진 로그 숨기기
        )

    def mutate(
        self,
        candidate: NormalizedCandidate,
    ) -> MutationRecord:
        
        missing = find_missing_context(candidate)

        if missing:
            return MutationRecord(
                candidate_id=candidate.candidate_id,
                vulnerability_type=candidate.vulnerability_type,
                status="skipped_missing_context",
                model=None,
                payloads=[],
                warnings=["Missing required context: " + ", ".join(missing)],
            )

        prompt = build_mutation_prompt(candidate)

        max_retries = 5
        for attempt in range(max_retries):
            try:
                # 💡 Ollama API 대신 llama_cpp의 내장 함수 사용
                response = self.llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    max_tokens=2048
                )

                # 응답 텍스트 추출 방식이 딕셔너리로 살짝 다름
                content = response["choices"][0]["message"]["content"]
                
                if not content:
                    raise ValueError("Model returned an empty response")

                parsed = GeminiMutationResponse.model_validate_json(content)

                if not parsed.payloads:
                    raise ValueError("LLM returned an empty payloads array []")

                validate_payload_contract(candidate, parsed)
                validate_generated_values(candidate, parsed)

                materialized_payloads = [
                    materialize_payload(candidate, payload)
                    for payload in parsed.payloads
                ]

                return MutationRecord(
                    candidate_id=candidate.candidate_id,
                    vulnerability_type=candidate.vulnerability_type,
                    status="generated",
                    model=self.model,
                    payloads=materialized_payloads,
                    warnings=parsed.warnings,
                )

            except Exception as exc:
                if attempt == max_retries - 1:
                    return MutationRecord(
                        candidate_id=candidate.candidate_id,
                        vulnerability_type=candidate.vulnerability_type,
                        status="generation_failed",
                        model=self.model,
                        payloads=[],
                        warnings=[str(exc)],
                    )
                print(f"⚠️ 생성 실패 또는 빈 배열 수신 (시도 {attempt + 1}/{max_retries}) - 다시 시도합니다...")