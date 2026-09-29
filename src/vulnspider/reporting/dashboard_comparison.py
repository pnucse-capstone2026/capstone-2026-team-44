"""Escaped, bounded views of retained response pairs; no feature extraction."""

from __future__ import annotations

import re
from html import escape

from vulnspider.domain import InputPoint, RequestInstance, ResponseSnapshot
from vulnspider.reporting.html_report import ProbeRun
from vulnspider.scoring.calibration import CalibratedProbability


def _input_value(request: RequestInstance, point: InputPoint) -> str:
    fields = {"QUERY": request.query, "FORM": request.form,
              "JSON": request.json_body, "JSON_BODY": request.json_body}
    values = [value for name, value in fields.get(point.location.value, ()) if name == point.name]
    occurrence = point.occurrence_index
    if occurrence is None and len(values) != 1:
        return "입력값 미제공 또는 중복 입력 위치 불명"
    index = occurrence or 0
    return values[index] if index < len(values) else "입력값 미제공"


def _excerpt(text: str | None, anchor: str | None, fallback: int) -> str:
    if text is None:
        return '<p class="missing-note">응답 본문이 보관되지 않았습니다.</p>'
    if not text:
        return '<p class="missing-note">보관된 응답 본문이 비어 있습니다.</p>'
    # Anchors pick display context only. They never become a feature or verdict.
    position = text.rfind(anchor) if anchor else -1
    if position < 0:
        position = min(fallback, max(0, len(text) - 240))
    start = max(0, position - 100)
    end = min(len(text), start + 560)
    snippet = text[start:end]
    rendered = escape(snippet)
    if anchor and anchor in snippet:
        rendered = rendered.replace(escape(anchor), f'<mark>{escape(anchor)}</mark>')
    return '<pre class="response-excerpt">' + ('…' if start else '') + rendered + ('…' if end < len(text) else '') + '</pre>'


def _baseline_context(before: str, after: str, anchor: str | None, fallback: int) -> int:
    """Align display excerpts using nearby literal context, never evidence.

    Prefer the closest unambiguous 16-character context before the probe's
    display anchor. The 160-character window keeps the excerpt near that
    location; short or repeated fragments do not relocate the baseline view.
    """
    position = after.rfind(anchor) if anchor else -1
    if position < 0:
        return fallback
    context = after[max(0, position - 160):position]
    for end in range(len(context), 15, -1):
        shared = context[end - 16:end]
        start = before.find(shared)
        if start >= 0 and before.find(shared, start + 1) < 0:
            return start + len(shared)
    return fallback


def _interpretation(family: str, calibrated: CalibratedProbability | None) -> tuple[str, str, str]:
    observed = {
        item.feature_name: item.feature_value for item in calibrated.evidence if item.observed
    } if calibrated is not None and calibrated.family == family else {}
    if family == "SQLI":
        if observed.get("sql_error_pattern") == 1:
            return ("이 후보에는 새 데이터베이스 오류 패턴이 기록돼 있습니다.",
                    "분석기의 sql_error_pattern=1은 초기 관찰 중 Baseline에는 없던 SQL 오류 패턴이 Probe에서 나타났다는 뜻입니다. SQLi는 입력이 데이터베이스의 조회 명령에 영향을 주는 문제입니다. 이 신호는 그 가능성을 점검할 근거가 됩니다.",
                    "오류만으로 질의 조작이 입증되지는 않습니다. 안전하게 값을 바인딩한 코드도 형 변환 오류를 노출할 수 있으므로, 실제 조회 조건이 바뀌는지 추가 확인해야 합니다.")
        if observed.get("sql_error_pattern") == 0:
            return ("새 SQL 오류 패턴은 관찰되지 않았습니다.",
                    "기록된 sql_error_pattern=0은 분석기가 확인했지만 새 SQL 오류 패턴을 찾지 못했다는 뜻입니다. 상태 코드나 응답 크기만 달라졌다면 정상적인 입력 검사나 검색 결과 변화일 수도 있습니다.",
                    "새 오류가 없다는 결과는 안전하다는 판정이 아닙니다. 오류를 숨기는 경우도 있으므로 다른 근거와 함께 읽어야 합니다.")
        return ("새 SQL 오류의 긍정 신호가 제공되지 않았습니다.",
                "이 후보의 SQL 오류 관찰값이 미관측이거나 제공되지 않았습니다. 미관측은 확인했으나 오류가 없었던 0과 다릅니다. 표시된 원문만으로 관찰값이나 점수를 새로 만들지 않습니다.",
                "자료가 없다는 이유로 안전하다고 판단할 수 없습니다. 응답 기록과 분석 근거가 더 필요합니다.")
    if family == "REFLECTED_XSS":
        if observed.get("safe_html_encoding_detected") == 1:
            return ("이 후보에는 안전 인코딩 신호가 기록돼 있습니다.",
                    "< 같은 특수 문자를 &lt;처럼 바꾸면 브라우저가 태그 대신 글자로 표시할 수 있습니다. XSS는 입력이 페이지의 실행 코드로 해석되는 문제입니다. 이 인코딩은 일반적으로 XSS 가능성을 낮추는 근거이며, 실제 기여 방향은 아래 기록된 점수 근거에서 확인합니다.",
                    "본문의 한 부분만으로 모든 출력 위치가 안전하다고 단정할 수 없습니다. 실제 삽입 위치와 브라우저 실행 여부는 별도로 확인해야 합니다.")
        if observed.get("marker_reflected") == 1:
            return ("이 후보에는 보낸 표식이 응답에 나타난 기록이 있습니다.",
                    "marker_reflected=1은 입력한 고유 표식이 응답 본문에 포함됐다는 뜻입니다. XSS는 입력이 페이지의 실행 코드로 해석되는 문제입니다. 표식 주변의 특수 문자가 태그나 스크립트로 해석될 수 있는지 점검할 근거가 됩니다.",
                    "반사만으로 XSS 실행을 입증하지는 않습니다. 인코딩 미관측도 인코딩 부재와 다릅니다. 아래 원문은 실행하지 않고 글자로 표시합니다.")
        if observed.get("marker_reflected") == 0:
            return ("입력 표식의 반사는 관찰되지 않았습니다.",
                    "기록된 marker_reflected=0은 분석기가 확인한 응답에서 표식 반사를 찾지 못했다는 뜻입니다. 본문을 확인하지 못한 미관측과는 구분합니다.",
                    "다른 입력이나 화면에서도 반사가 없다는 보장은 아닙니다. 이 결과만으로 XSS 가능성을 배제하지 않습니다.")
        return ("반사에 관한 긍정 신호가 제공되지 않았습니다.",
                "이 후보의 반사 관찰값이 미관측이거나 제공되지 않았습니다. 미관측은 확인했으나 반사가 없었던 0과 다릅니다.",
                "이 화면에서 브라우저 코드 실행을 검사하거나 XSS 성공을 판정한 것은 아닙니다.")
    return ("기록된 요청과 응답을 비교합니다.", "점수에 사용된 관찰 근거는 아래에 표시됩니다.", "응답 차이 자체는 취약점 확정이 아닙니다.")


def _change_strip(baseline: ResponseSnapshot, probe: ResponseSnapshot, has_error: bool) -> str:
    """A glance-level summary of what changed between the two real responses.

    Uses only retained response metadata. Finding a word in an excerpt must
    never create an SQL-error or reflection feature in the reporting layer.
    """
    status_changed = baseline.status_code != probe.status_code
    size_changed = baseline.body_length_bytes != probe.body_length_bytes
    body_changed = baseline.body_bytes_hash != probe.body_bytes_hash
    highlight = (status_changed or size_changed or body_changed) and not has_error
    if has_error:
        summary = "요청 실패"
    elif status_changed:
        summary = "상태 코드 변화"
    elif size_changed:
        summary = "응답 크기 변화"
    elif body_changed:
        summary = "응답 내용 변화"
    else:
        summary = "상태·크기·응답 내용 동일"
    return (
        '<div class="comparison-lead"><div class="cmp-flow">'
        '<div class="cmp-chip"><span class="cmp-role">평소 입력 · Baseline</span>'
        f'<b>HTTP {escape(str(baseline.status_code))}</b>'
        f'<small>{baseline.body_length_bytes:,} bytes</small></div>'
        f'<div class="cmp-arrow{" hot" if highlight else ""}">'
        f'<span class="cmp-arrow-mark" aria-hidden="true">→</span><em>{summary}</em></div>'
        f'<div class="cmp-chip probe{" changed" if highlight else ""}">'
        '<span class="cmp-role">변형 입력 · Probe</span>'
        f'<b>HTTP {escape(str(probe.status_code))}</b>'
        f'<small>{probe.body_length_bytes:,} bytes</small></div>'
        '</div></div>'
    )


def response_comparison(point: InputPoint | None, run: ProbeRun | None, family: str,
                        calibrated: CalibratedProbability | None) -> str:
    if point is None or run is None:
        return '<div class="missing-note">비교할 초기 요청·응답 본문이 제공되지 않았습니다.</div>'
    plan, baseline, probe = run
    if (plan.input_point_id != point.id or baseline.request_id != plan.baseline_request.id
            or probe.request_id != plan.probe_request.id
            or baseline.probe_plan_id != plan.id or probe.probe_plan_id != plan.id
            or baseline.request_role != "baseline" or probe.request_role != "probe"):
        return '<div class="missing-note">요청·응답의 소속이 일치하지 않아 비교를 표시하지 않습니다.</div>'
    before, after = baseline.decoded_text or "", probe.decoded_text or ""
    common = 0
    while common < min(len(before), len(after)) and before[common] == after[common]:
        common += 1
    anchor = plan.probe_marker
    if family == "SQLI":
        # Select an excerpt position only; this match is not analysis evidence.
        match = re.search(r"Database error:|SQLSTATE|SQLite error:|SQL syntax|ORA-\d+|PostgreSQL:|Unclosed quotation", after)
        if match:
            anchor = match.group()
    baseline_context = _baseline_context(before, after, anchor, common)
    has_error = bool(baseline.execution_error or probe.execution_error)
    cards = []
    for index, (label, request, response) in enumerate((
        ("평소 입력 · Baseline", plan.baseline_request, baseline),
        ("한 입력 변경 · Probe", plan.probe_request, probe),
    )):
        excerpt = _excerpt(response.decoded_text, anchor if index else None, common if index else baseline_context)
        error = f'<p class="missing-note">실행 오류: {escape(response.execution_error)}</p>' if response.execution_error else ''
        cards.append(
            f'<article class="response-card {"probe" if index else "baseline"}">'
            f'<h3><span>0{index + 1}</span> {label}</h3><label>{escape(point.name)}에 보낸 값</label>'
            f'<pre class="request-value">{escape(_input_value(request, point))}</pre>'
            f'<div class="response-stats"><b>HTTP {response.status_code}</b><span>{response.body_length_bytes:,} bytes</span></div>'
            '<p class="excerpt-label">보관된 응답 원문 발췌 · 일부</p>' + error + excerpt
            + f'<details class="technical"><summary>요청 주소와 응답 출처</summary>'
            f'<code>{escape(request.method.value)} {escape(request.url)}</code>'
            f'<p>response {escape(response.id or "")}<br>request {escape(response.request_id)}'
            f'<br>plan {escape(plan.id or "")}<br>role {escape(response.request_role or "")}</p></details></article>'
        )
    title, explanation, limit = _interpretation(family, calibrated)
    if has_error:
        title, explanation, limit = ("실행 오류로 응답 비교를 해석할 수 없습니다.",
                                     "요청 실패는 취약점 신호로 설명하지 않습니다.", "오류를 해결한 뒤 다시 관찰해야 합니다.")
    strip = _change_strip(baseline, probe, has_error)
    reasoning = (
        '<div class="evidence-takeaway"><span class="eyebrow">기록된 후보 근거를 어떻게 읽나요?</span>'
        f'<h3>{escape(title)}</h3>'
        f'<div class="reason-why"><b>왜 이 응답이 근거가 되나요</b><p>{escape(explanation)}</p></div>'
        f'<div class="reason-limit"><b>그래도 주의할 점</b><p>{escape(limit)}</p></div>'
        '<p class="comparison-provenance">위 원문은 보관된 초기 요청·응답 한 쌍입니다. '
        '후보 근거는 같은 입력점의 여러 관찰을 합칠 수 있어, 이 한 쌍이 모든 근거의 출처라는 뜻은 아닙니다. '
        '추가 검증 후 신뢰도 변화는 아래 별도 기록에서 확인합니다.</p></div>'
    )
    return (strip + '<div class="response-comparison">' + ''.join(cards) + '</div>' + reasoning)
