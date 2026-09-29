"""Case-aware defensive guidance for the decision dashboard.

The report's "방어 지침" block is the part a reader acts on, so it must be
richer than one generic sentence per family. This module maps a candidate's
family and the signals actually observed for it to a structured countermeasure
block: a one-line lead framing the concrete case, a short list of primary
(root-cause) fixes, a short list of secondary (defense-in-depth) measures, and
an optional case-specific check.

The case axes are the ones the pipeline can determine reliably:

* SQLI      -- error-based (a DB error signature was reflected) vs inferential
              (only response-size/status differences), from the evidence.
* XSS       -- one context-aware encoding block; the reflection context
              classifier (text/attribute/script) is not implemented yet, so
              the three contexts are all spelled out rather than branched.
* BAC       -- IDOR (identifier substitution) vs authentication bypass
              (credential strip), from the access probe's ``check_kind``.

No scoring or evidence is invented here; ``evidence`` is read duck-typed for
``feature_name``/``observed``/``logit_contribution`` only.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

_SQLI = "SQLI"
_XSS = "REFLECTED_XSS"
_BAC = "BROKEN_ACCESS_CONTROL"

_SQL_ERROR_FEATURE = "sql_error_pattern"


@dataclass(frozen=True)
class DefenseGuidance:
    """A structured, case-aware countermeasure block for one candidate."""

    family: str
    case_label: str
    lead: str
    primary: tuple[str, ...]
    secondary: tuple[str, ...]
    note: str = ""


_SQLI_PRIMARY: tuple[str, ...] = (
    "쿼리를 파라미터화(prepared statement)해 사용자 입력을 코드가 아닌 데이터로 "
    "처리하세요. 문자열을 이어붙여 SQL을 만들지 않습니다.",
    "ORM·쿼리빌더를 쓰더라도 raw SQL 조각에 입력을 직접 결합하지 말고 바인딩 "
    "파라미터를 사용하세요.",
    "DB 계정에는 최소 권한만 부여하고(필요한 테이블·작업으로 한정), 애플리케이션 "
    "계정에 관리·DDL 권한을 주지 마세요.",
)
_SQLI_SECONDARY: tuple[str, ...] = (
    "입력을 허용 목록 기준(타입·길이·형식)으로 검증하되, 이는 보조 방어이며 "
    "파라미터화를 대체하지 않습니다.",
    "저장 프로시저도 내부에서 동적 SQL을 문자열로 조립하면 똑같이 취약합니다.",
)

_XSS_PRIMARY: tuple[str, ...] = (
    "반사 지점의 출력 문맥에 맞는 인코딩을 적용하세요: HTML 본문은 엔티티 "
    "인코딩(< > & \" '), 속성값은 속성 인코딩 후 따옴표로 감싸기, <script>·이벤트 "
    "핸들러 등 자바스크립트 문맥은 JS 문자열/JSON 인코딩, URL 파라미터는 URL "
    "인코딩입니다.",
    "프레임워크의 자동 이스케이프(React·Angular·서버 템플릿 auto-escape)를 "
    "신뢰하고, innerHTML·dangerouslySetInnerHTML·템플릿의 |safe/raw 같은 우회를 "
    "피하세요.",
)
_XSS_SECONDARY: tuple[str, ...] = (
    "엄격한 Content-Security-Policy(script-src 화이트리스트 또는 nonce)로 인라인·"
    "외부 스크립트 실행을 제한해 잔여 위험을 줄이세요.",
    "세션 쿠키에 HttpOnly·SameSite를 설정해 탈취 시 영향을 줄이고, 입력 검증은 "
    "보조 방어로만 사용하세요.",
)
_XSS_LEAD = (
    "사용자 입력이 응답에 반사되며, 위험 문자가 인코딩 없이 그대로 출력되면 "
    "브라우저에서 스크립트가 실행될 수 있습니다."
)
_XSS_NOTE = (
    "인코딩은 반드시 '출력 문맥'에 맞아야 합니다. 본문용 HTML 인코딩을 자바스크립트 "
    "문맥에 그대로 쓰면 여전히 우회될 수 있습니다."
)

_BAC_PRIMARY: tuple[str, ...] = (
    "모든 요청에서 서버 측 권한 검사를 수행하세요. 화면에서 링크·버튼을 숨기는 "
    "것은 접근제어가 아닙니다.",
    "리소스 접근 시 '이 요청자가 이 객체에 대한 권한이 있는가'를 서버가 매번 "
    "확인하고, 기본적으로 거부(deny by default)하세요.",
)
_BAC_SECONDARY: tuple[str, ...] = (
    "인가 로직을 한 곳에 모아(중앙집중) 개별 핸들러의 누락을 줄이고, 기능·데이터 "
    "단위 접근제어를 테스트로 검증하세요.",
    "예측 가능한 순차 ID보다 소유권 검증을 우선하고, 필요하면 불투명 "
    "식별자(UUID)나 간접 참조를 사용하세요.",
)


def _feature_present(evidence: Sequence[Any], name: str) -> bool:
    """True if ``name`` was observed with a positive log-odds contribution."""

    for item in evidence:
        if getattr(item, "feature_name", None) != name:
            continue
        if not getattr(item, "observed", False):
            continue
        if (getattr(item, "logit_contribution", 0.0) or 0.0) > 1e-9:
            return True
    return False


def _sqli_guidance(evidence: Sequence[Any]) -> DefenseGuidance:
    if _feature_present(evidence, _SQL_ERROR_FEATURE):
        return DefenseGuidance(
            family=_SQLI,
            case_label="에러 기반 (DB 오류 노출)",
            lead=(
                "DB 오류 패턴이 관찰된 후보입니다. 실제 원인을 확인하고, 입력이 "
                "질의 구조에 영향을 주지 않도록 파라미터화와 오류 처리를 점검하세요."
            ),
            primary=_SQLI_PRIMARY,
            secondary=_SQLI_SECONDARY,
            note=(
                "운영 환경에서는 상세 오류를 감추고 일반화된 오류 페이지를 "
                "반환하세요. 단, 오류 은닉은 정보 노출만 줄일 뿐 주입 자체는 "
                "파라미터화로 막아야 합니다."
            ),
        )
    return DefenseGuidance(
        family=_SQLI,
        case_label="추론 신호 점검 / 일반 SQLi 방어",
        lead=(
            "DB 오류를 근거로 한 분류는 제공되지 않았습니다. 응답 차이가 있다면 "
            "정상적인 기능 변화인지 먼저 확인하세요. 차이만으로 블라인드 SQLi를 "
            "판정하지 않으며, 아래는 이 유형에 대한 일반 방어 지침입니다."
        ),
        primary=_SQLI_PRIMARY,
        secondary=_SQLI_SECONDARY,
        note=(
            "반복적인 탐침을 탐지하도록 이상 요청 로깅·레이트리밋을 두세요. 근본 "
            "대응은 동일하게 파라미터화입니다."
        ),
    )


def _bac_guidance(access_check_kind: str | None) -> DefenseGuidance:
    kind = (access_check_kind or "").upper()
    if kind == "IDENTIFIER_SUBSTITUTION":
        return DefenseGuidance(
            family=_BAC,
            case_label="IDOR (식별자 치환)",
            lead=(
                "식별자를 바꾼 요청을 비교한 후보입니다. 다른 사용자의 리소스에 "
                "권한 없이 접근되는지는 실제 객체 소유권과 응답 내용을 확인해야 합니다."
            ),
            primary=_BAC_PRIMARY,
            secondary=_BAC_SECONDARY,
            note=(
                "매 요청마다 대상 객체의 소유자가 현재 인증 주체와 일치하는지 "
                "서버에서 확인하고, 순차 ID를 불투명 식별자로 대체하세요."
            ),
        )
    if kind == "CREDENTIAL_STRIP":
        return DefenseGuidance(
            family=_BAC,
            case_label="인증 우회 (자격증명 제거)",
            lead=(
                "인증 정보를 제거한 요청을 비교한 후보입니다. 보호 리소스가 실제로 "
                "노출되는지와 인증 검사의 적용 여부를 확인하세요."
            ),
            primary=_BAC_PRIMARY,
            secondary=_BAC_SECONDARY,
            note=(
                "인증 미들웨어가 모든 보호 경로에 실제로 적용되는지, 세션·토큰 검증 "
                "누락이 없는지 점검하세요."
            ),
        )
    return DefenseGuidance(
        family=_BAC,
        case_label="접근제어 미흡",
        lead=(
            "인증·인가 검사 없이, 보호되어야 할 데이터가 노출될 수 있는 상태입니다."
        ),
        primary=_BAC_PRIMARY,
        secondary=_BAC_SECONDARY,
        note="",
    )


def build_defense_guidance(
    family: str,
    *,
    evidence: Sequence[Any] = (),
    access_check_kind: str | None = None,
) -> DefenseGuidance | None:
    """Return case-aware guidance for ``family``, or ``None`` if unsupported."""

    if family == _SQLI:
        return _sqli_guidance(evidence)
    if family == _XSS:
        return DefenseGuidance(
            family=_XSS,
            case_label="반사형",
            lead=_XSS_LEAD,
            primary=_XSS_PRIMARY,
            secondary=_XSS_SECONDARY,
            note=_XSS_NOTE,
        )
    if family == _BAC:
        return _bac_guidance(access_check_kind)
    return None
