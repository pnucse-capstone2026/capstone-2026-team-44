"""Plain-language explanations backed only by supplied evidence records."""

from __future__ import annotations

from html import escape
from typing import Any

from vulnspider.reporting.dashboard_layout import STATUS_LABELS
from vulnspider.scoring.calibration import CalibratedProbability
from vulnspider.verification.focused import CandidateVerification

FEATURE_LABELS = {
    "sql_error_pattern": ("데이터베이스 오류 신호", "입력을 바꾼 응답에서 SQL 오류 패턴이 관찰되는지 살펴봅니다."),
    "marker_reflected": ("입력값의 응답 반사", "보낸 표식이 응답에 다시 나타나는지 살펴봅니다. 반사만으로 스크립트 실행이 입증되지는 않습니다."),
    "safe_html_encoding_detected": ("HTML 안전 인코딩", "특수 문자가 HTML 코드로 해석되지 않도록 변환되는지 살펴봅니다."),
    "response_length_diff_ratio": ("응답 크기의 변화", "일반 요청과 입력을 바꾼 요청의 응답 크기 차이입니다. 정상적인 검색 결과 변화도 원인이 될 수 있습니다."),
    "status_code_changed": ("HTTP 상태의 변화", "정상 응답·오류·리다이렉트 등 응답 상태가 달라졌는지 나타냅니다. 오류 자체가 취약점을 뜻하지는 않습니다."),
    "reflection_count_norm": ("표식의 반복 반사", "표식이 응답에 등장한 횟수를 정규화한 값입니다."),
    "access_unauthorized_success": ("권한을 바꾼 요청의 성공 신호", "접근 조건을 바꿔도 응답이 성공하는지 살펴봅니다. 실제 소유권과 권한 정책의 추가 확인이 필요합니다."),
}

FAMILY_EXPLANATIONS = {
    "SQLI": "SQL Injection은 입력값이 데이터베이스 질의의 의미를 바꿀 수 있는 문제입니다. 아래 신호를 근거로 이 유형의 추가 점검 대상으로 선정되었습니다.",
    "REFLECTED_XSS": "반사형 XSS는 입력값이 웹 응답에 포함되어 브라우저에서 코드로 해석될 수 있는 문제입니다. 아래 신호를 근거로 출력 처리 방식을 살펴볼 후보로 선정되었습니다.",
    "BROKEN_ACCESS_CONTROL": "접근제어 문제는 요청자가 허용되지 않은 기능이나 다른 사람의 데이터에 접근할 수 있는 문제입니다. 원본 요청과 접근 조건을 바꾼 요청의 관계를 분석한 후보입니다.",
}

SIGNAL_EXPLANATIONS = {
    "SUPPORT_NEW": "추가 확인에서 유형에 해당하는 새로운 신호가 관찰되어 후보 가능성을 뒷받침합니다.",
    "SUPPORT_REPRODUCED": "처음 관찰한 유형별 신호가 추가 확인에서도 재현되었습니다. 재현되어도 사용한 신뢰도 모델에 따라 수치가 유지될 수 있습니다.",
    "WEAKEN": "추가 관찰이 기존 의심을 약화하는 방향으로 기록되었습니다. 이 결과가 대상 전체의 안전을 보장하지는 않습니다.",
    "INCONCLUSIVE": "요청 또는 응답 오류 때문에 추가 판단을 보류했습니다. 오류를 취약점 근거로 사용하지 않습니다.",
    "UNCHANGED": "추가 확인에서 신뢰도를 바꿀 결정적인 유형별 신호가 기록되지 않았습니다.",
    "NOT_EXECUTED": "실행된 추가 확인이 없어 새로운 취약점 근거가 추가되지 않았습니다.",
}


def _esc(value: Any) -> str:
    return escape(str(value), quote=True)


def _value(value: float | None, observed: bool = True) -> str:
    return f"{value:.4g}" if observed and value is not None else "미관측"


def explain_candidate(family: str, calibrated: CalibratedProbability | None) -> str:
    intro = FAMILY_EXPLANATIONS.get(family, "제공된 분석 신호를 근거로 추가 점검 대상으로 선정된 후보입니다.")
    if calibrated is None or not calibrated.evidence:
        return f'<p class="plain-intro">{_esc(intro)}</p><div class="missing-note">세부 채점 근거가 이 리포트에 제공되지 않았습니다. 표시 점수만으로 원인을 추정하지 않습니다.</div>'
    # Show strongest positive/negative contributions and explicitly retain missing
    # observations in the technical evidence view rendered by the caller.
    evidence = sorted(calibrated.evidence, key=lambda e: (
        not e.observed, -abs(e.logit_contribution or 0.0), e.feature_name,
    ))
    cards = []
    for item in evidence[:4]:
        label, description = FEATURE_LABELS.get(item.feature_name, (item.feature_name, "분석기가 기록한 관찰 신호입니다. 세부 산출 근거는 기술 기록에서 확인할 수 있습니다."))
        contribution = item.logit_contribution
        if not item.observed:
            impact = "미관측 · 안전하다는 뜻이 아닙니다"
        elif contribution is None:
            impact = "기여도 미제공"
        elif contribution > 0:
            impact = "검증 전 확률을 높이는 방향"
        elif contribution < 0:
            impact = "검증 전 확률을 낮추는 방향"
        else:
            impact = "검증 전 확률에 추가 기여 없음"
        cards.append(
            f'<div class="evidence-item"><b>{_esc(label)}</b><p>{_esc(description)}</p>'
            f'<p><strong>{_esc(impact)}</strong> · 관측값 {_value(item.feature_value, item.observed)}</p>'
            f'<div class="evidence-meta">{_esc(item.feature_name)}</div></div>'
        )
    return f'<p class="plain-intro">{_esc(intro)}</p><div class="evidence-grid">{"".join(cards)}</div>'


def verification_explanation(verified: CandidateVerification | None) -> str:
    if verified is None:
        return '<div class="missing-note">추가 검증 기록이 없습니다. 최종 신뢰도는 검증 전 확률을 그대로 사용합니다. 추가 페이로드가 실행되었거나 가능성이 강화되었다고 판단할 수 없습니다.</div>'
    explanation = SIGNAL_EXPLANATIONS.get(verified.final_signal.value, "제공된 추가 확인 결과를 아래에 표시합니다.")
    return f'<p class="plain-intro">{_esc(explanation)}</p>'


def payload_records(verified: CandidateVerification | None) -> str:
    if verified is None:
        return ""
    if not verified.results:
        attempted = getattr(verified, "attempted", 0)
        if attempted:
            return (
                f'<div class="missing-note">접근제어 재확인: 다른 식별자 {attempted}개 중 '
                f'{getattr(verified, "reproduced", 0)}개에서 신호 재현. '
                '개별 식별자 값과 요청·응답 기록은 이 집계에 포함되지 않아 표시하지 않습니다.</div>'
            )
        return '<div class="missing-note">개별 페이로드 기록이 제공되지 않았습니다. 위의 집계 결과만 확인할 수 있습니다.</div>'
    cards = []
    for index, result in enumerate(verified.results, 1):
        refs = result.execution_refs
        executed = refs is not None
        state = result.outcome_status.value
        execution_label = "실행 기록 있음" if executed else "실행되지 않음"
        validator = "승인" if result.validator_decision == "ACCEPTED" else "거부"
        based_on = '<span>원래 값 미제공</span>' if result.based_on_value is None else f'<pre>{_esc(result.based_on_value)}</pre>'
        reasons = "".join(
            f'<li>{_esc(FEATURE_LABELS.get(item.feature_name, (item.feature_name, ""))[0])}: '
            f'초기 {_value(item.baseline_value)} → 추가 {_value(item.verification_value)}</li>'
            for item in result.verification_confidence.evidence
        )
        original_reasons = "".join(f'<li>{_esc(item.reason)}</li>' for item in result.verification_confidence.evidence)
        if result.validator_rejection_reasons:
            reasons += "".join(f'<li>검증기 거부 사유: {_esc(reason)}</li>' for reason in result.validator_rejection_reasons)
        confidence = result.verification_confidence
        detail_rows = []
        if result.feature_delta is not None:
            for delta in result.feature_delta.deltas:
                name = FEATURE_LABELS.get(delta.feature_name, (delta.feature_name, ""))[0]
                detail_rows.append(
                    f'<tr><td>{_esc(name)}<div class="evidence-meta">{_esc(delta.feature_name)}</div></td>'
                    f'<td>{_value(delta.baseline_value, delta.baseline_observed)}</td>'
                    f'<td>{_value(delta.verification_value, delta.verification_observed)}</td></tr>'
                )
        comparison = (
            '<details class="technical"><summary>페이로드별 관찰값 비교</summary>'
            '<p>초기 Light Probe의 특징값과 추가 검증 특징값을 비교합니다. 미관측은 0과 다릅니다.</p>'
            '<table class="delta-table"><thead><tr><th>관찰 신호</th><th>초기 관찰</th><th>추가 확인</th></tr></thead>'
            f'<tbody>{"".join(detail_rows)}</tbody></table></details>'
            if detail_rows else ''
        )
        provenance = (
            f'probe plan {_esc(refs.probe_plan_id)}<br>baseline response {_esc(refs.baseline_response_id)}'
            f'<br>probe response {_esc(refs.probe_response_id)}<br>feature vector {_esc(refs.verification_feature_vector_id)}'
            if refs is not None else '실행 참조 없음'
        )
        errors = "".join(
            f'<li>실행 오류: {_esc(error)}</li>'
            for error in (refs.baseline_execution_error, refs.probe_execution_error)
            if error
        ) if refs is not None else ''
        warnings = "".join(f'<li>{_esc(warning)}</li>' for warning in result.warnings)
        cards.append(f"""<section class="payload-card">
<div class="payload-head"><b>추가 페이로드 {index:02d} · 검증기 {validator} · {execution_label}</b>
<span class="state {_esc(state)}">{_esc(STATUS_LABELS.get(state, state))}</span></div>
<div class="payload-body"><div class="payload-values"><div><label>기준 입력값</label>{based_on}</div>
<div><label>{'실행 기록에 연결된' if executed else '제안된'} 변형 입력값</label><pre>{_esc(result.mutated_value)}</pre></div></div>
<p class="payload-confidence"><b>검증 전 {confidence.prior_probability * 100:.1f}% → 이 페이로드 신뢰도 {confidence.confidence * 100:.1f}%</b></p>
<ul>{reasons}{errors}{warnings}</ul>{comparison}
<details class="technical"><summary>원문 근거 · 제안 정보와 실행 출처</summary><ul>{original_reasons}</ul><div class="payload-meta">
제안자: {_esc(result.provider)} · {_esc(result.proposer_version)}<br>
제안 사유 (관찰 근거와 별개): {_esc(result.rationale)}<br>
proposal {_esc(result.proposal_id)}<br>result {_esc(result.verification_result_id)}<br>
검증기 {_esc(result.validator_policy_version)} · 신뢰도 규칙 {_esc(result.confidence_rule_version)}<br>
{provenance}</div></details></div></section>""")
    return (
        '<p class="panel-desc">각 페이로드의 결과는 같은 검증 전 확률에서 계산됩니다. '
        '아래 수치를 차례로 누적하지 않으며, 최종 신뢰도는 분석기가 집계한 값입니다.</p>'
        + "".join(cards)
    )


def fix_acceptance(family: str) -> str:
    checks = {
        "SQLI": "일반 입력의 기능은 유지되고, SQL 특수 문자가 질의 구조를 바꾸지 않는지 코드와 재검사로 확인하세요. DB 오류 메시지 숨기기만으로 수정이 끝난 것은 아닙니다.",
        "REFLECTED_XSS": "입력이 들어가는 각 출력 문맥에서 특수 문자가 데이터로 표시되고 스크립트로 실행되지 않는지 확인하세요. 정상적인 검색·표시 기능도 함께 점검하세요.",
        "BROKEN_ACCESS_CONTROL": "본인에게 허용된 요청은 성공하고, 다른 사용자 객체나 권한 없는 요청은 거부되는지 계정·역할별로 확인하세요. HTTP 상태뿐 아니라 응답 본문에 보호 데이터가 없는지도 점검하세요.",
    }
    text = checks.get(family, "수정 후 같은 입력점에서 정상 기능과 방어 동작을 함께 확인하세요.")
    return f'<div class="missing-note"><b>수정 후 확인할 기준</b><br>{_esc(text)}<br>아래 방어 안내는 권장 조치이며, 이 리포트에서 수정 작업을 수행한 것은 아닙니다.</div>'
