"""Screen composition using presentation projections of authoritative candidates."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from html import escape
from typing import Any
from urllib.parse import urlencode

from vulnspider.reporting.charts import Slice, donut_chart
from vulnspider.reporting.dashboard_assets import SPIDER_MARK
from vulnspider.reporting.dashboard_story import analysis_journey, candidate_caption, confidence_comparison
from vulnspider.reporting.dashboard_presentation import evidence_summary
from vulnspider.reporting.html_report import _fmt_percent

FAMILY_LABELS = {
    "SQLI": "SQL Injection",
    "REFLECTED_XSS": "Reflected XSS",
    "BROKEN_ACCESS_CONTROL": "접근제어 (BAC)",
}
STATUS_LABELS = {
    "SUPPORTED": "근거 뒷받침",
    "WEAKENED": "가능성 약화",
    "UNCHANGED": "변화 없음",
    "INCONCLUSIVE_ERROR": "오류로 판단 보류",
    "REJECTED": "페이로드 거부",
    "NOT_EXECUTED": "미실행",
    "UNVERIFIED": "추가 검증 전",
}


def _esc(value: Any) -> str:
    return escape(str(value), quote=True)


FAMILY_ICONS = {
    "SQLI": (
        '<svg class="fam-ico" viewBox="0 0 20 20" fill="none" stroke="currentColor" '
        'stroke-width="1.5" aria-hidden="true"><ellipse cx="10" cy="4.6" rx="6" ry="2.3"/>'
        '<path d="M4 4.6v10.8c0 1.27 2.69 2.3 6 2.3s6-1.03 6-2.3V4.6"/>'
        '<path d="M4 10c0 1.27 2.69 2.3 6 2.3s6-1.03 6-2.3"/></svg>'
    ),
    "REFLECTED_XSS": (
        '<svg class="fam-ico" viewBox="0 0 20 20" fill="none" stroke="currentColor" '
        'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M7 5 2.5 10 7 15M13 5l4.5 5L13 15M11.6 3.6 8.4 16.4"/></svg>'
    ),
    "BROKEN_ACCESS_CONTROL": (
        '<svg class="fam-ico" viewBox="0 0 20 20" fill="none" stroke="currentColor" '
        'stroke-width="1.5" aria-hidden="true"><rect x="4.3" y="9" width="11.4" height="8.2" rx="1.6"/>'
        '<path d="M7 9V6.6a3 3 0 0 1 6 0V9"/></svg>'
    ),
}


def family_icon(family: str) -> str:
    """A small monochrome type glyph that inherits the family colour."""

    return FAMILY_ICONS.get(family, '<i class="family-dot" aria-hidden="true"></i>')


def family_tag(family: str) -> str:
    label = FAMILY_LABELS.get(family, family)
    return f'<span class="family-tag {_esc(family)}">{family_icon(family)}{_esc(label)}</span>'


_HEADLINE_SAY = {
    "SQLI": "입력값이 데이터베이스 질의문에 섞여 들어갈 수 있는 자리입니다.",
    "REFLECTED_XSS": "입력값이 화면에 그대로 출력돼 스크립트가 실행될 수 있는 자리입니다.",
    "BROKEN_ACCESS_CONTROL": "권한 확인 없이 다른 사용자의 자원이 열릴 수 있는 자리입니다.",
}


def _risk_gauge(percent: str) -> str:
    return (
        '<div class="risk-gauge"><svg viewBox="0 0 36 36" aria-hidden="true">'
        '<circle class="g-bg" cx="18" cy="18" r="15.9" pathLength="100"/>'
        f'<circle class="g-fg" cx="18" cy="18" r="15.9" pathLength="100" '
        f'stroke-dasharray="{percent} 100"/></svg>'
        f'<div class="risk-pct"><b>{percent}</b><small>%</small></div></div>'
    )


def risk_headline(rows: Sequence[Mapping[str, Any]]) -> str:
    """A visual, at-a-glance hero: where to look first, with confidence gauges."""

    if not rows:
        return ""
    cards = []
    for index, row in enumerate(rows[:3]):
        family = _esc(row["family"])
        percent = _fmt_percent(row["score"])
        lead = " lead" if index == 0 else ""
        say = (
            f'<p class="risk-say">{_esc(_HEADLINE_SAY.get(row["family"], ""))}</p>'
            if index == 0 and row["family"] in _HEADLINE_SAY else ""
        )
        cards.append(
            f'<a class="risk-card {family}{lead}" href="#candidate-{row["rank"]}">'
            f'<span class="risk-rank">{row["rank"]:02d}</span>'
            f'<span class="risk-ico">{family_icon(row["family"])}</span>'
            '<span class="risk-main">'
            f'<span class="risk-fam">{_esc(FAMILY_LABELS.get(row["family"], row["family"]))}</span>'
            f'<span class="risk-loc">{candidate_caption(row)}</span>{say}</span>'
            f'{_risk_gauge(percent)}</a>'
        )
    return (
        '<section class="panel risk-headline"><div class="panel-head"><div>'
        '<h2>가장 먼저 확인할 곳</h2>'
        '<p class="panel-desc">최종 신뢰도가 높은 상위 후보입니다. 카드를 누르면 그 후보의 판단 근거로 이동합니다.</p>'
        f'</div><a class="text-link" href="#candidates">전체 {len(rows)}개 →</a></div>'
        f'<div class="risk-grid">{"".join(cards)}</div></section>'
    )


def page_heading(title: str, description: str, *, eyebrow: str = "SCAN REPORT") -> str:
    return (
        f'<div class="eyebrow">{_esc(eyebrow)}</div>'
        f'<h1 class="page-title" tabindex="-1">{_esc(title)}</h1>'
        f'<p class="subtitle">{_esc(description)}</p>'
    )


def shell(body: str, footer: str) -> str:
    return f"""<a class="skip-link" href="#overview">본문으로 이동</a>
<aside class="sidebar" aria-label="리포트 탐색">
  <a class="app-brand" href="#overview"><span class="brand-mark" aria-hidden="true">{SPIDER_MARK}</span>VulnSpider</a>
  <small>SECURITY INSIGHTS</small>
  <div class="nav-label">WORKSPACE</div>
  <nav aria-label="주 메뉴">
    <a href="#overview" aria-current="page"><span class="nav-icon" aria-hidden="true">▦</span>분석 개요</a>
    <a href="#candidates"><span class="nav-icon" aria-hidden="true">◎</span>취약점 후보</a>
    <a href="#methodology"><span class="nav-icon" aria-hidden="true">▤</span>리포트 읽는 법</a>
  </nav>
  <div class="sidebar-bottom"><strong>작은 신호에서, 우선순위로.</strong><br>
  입력점 기반 취약점 후보 분석<br><span>VulnSpider · Graduation Project</span></div>
</aside>
<div class="workspace">
  <div class="topbar"><div class="crumb">리포트 &nbsp; / &nbsp; <b id="current-page">분석 개요</b></div>
    <nav class="projector-nav" aria-label="발표 화면 이동"><a href="#overview">개요</a><a href="#candidates">후보 목록</a></nav>
    <div class="top-actions"><span class="snapshot-badge">● 저장된 분석 결과</span>
    <button class="button projector-toggle" type="button" data-projector aria-pressed="false">화면 크게</button>
    <button class="button" type="button" data-print>현재 화면 인쇄 ↗</button></div>
  </div>
  <main class="main-content">{body}{footer}</main>
</div>"""


def metric(value: int, label: str, note: str, *, accent: bool = False) -> str:
    css = "metric accent" if accent else "metric"
    return (
        f'<div class="{css}"><div class="metric-label">{_esc(label)}<span aria-hidden="true">↗</span></div>'
        f'<div class="metric-value">{value:,}<small>개</small></div>'
        f'<div class="metric-note">{_esc(note)}</div></div>'
    )


def selection_note(selected_count: int, displayed_count: int) -> str:
    return (
        f'선택된 유형별 후보 {selected_count}개 → 대표 후보 {displayed_count}개 표시. '
        '같은 입력점의 여러 취약점 유형은 최종 신뢰도가 가장 높은 하나로 묶었습니다. '
        '접근제어 후보는 요청 간 관계를 별도로 분석한 결과입니다.'
    )


def candidate_table(rows: Sequence[Mapping[str, Any]], *, table_id: str) -> str:
    body = []
    for row in rows:
        score = _fmt_percent(row["score"])
        family, state = _esc(row["family"]), _esc(row["state"])
        body.append(
            f'<tr data-family="{family}" data-state="{state}"><td>{row["rank"]:02d}</td>'
            f'<td><a class="location-link" href="#candidate-{row["rank"]}">{candidate_caption(row)}</a>'
            f'<div class="location-sub">{_esc(row["path"])}</div>'
            f'<div class="location-sub">{_esc(row["parameter"])}</div></td>'
            f'<td>{family_tag(row["family"])}</td>'
            f'<td class="score-cell">{score}%<div class="mini-meter" aria-hidden="true">'
            f'<i style="width:{score}%"></i></div><div class="location-sub">{_esc(row["score_kind"])}</div></td>'
            f'<td><span class="state {state}">{_esc(STATUS_LABELS.get(row["state"], row["state"]))}</span></td>'
            f'<td><a class="text-link" href="#candidate-{row["rank"]}" '
            f'aria-label="{row["rank"]}번 후보 상세 보기">상세 보기 ↗</a></td></tr>'
        )
    return (
        f'<div class="table-scroll"><table class="candidate-table" id="{table_id}">'
        '<caption class="location-sub">최종 신뢰도 내림차순 · 상세 보기에서 근거 확인</caption>'
        '<thead><tr><th scope="col">순서</th><th scope="col">엔드포인트 / 입력점</th>'
        '<th scope="col">후보 유형</th><th scope="col">최종 신뢰도</th>'
        '<th scope="col">추가 검증 상태</th><th scope="col">탐색</th></tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table></div>'
    )


def relationship_map(rows: Sequence[Mapping[str, Any]]) -> str:
    # These edges represent canonical ownership, never discovered navigation.
    visible = rows[:8]
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for row in visible:
        groups.setdefault(row["endpoint_key"], []).append(row)
    nodes = []
    for group in groups.values():
        links = "".join(
            f'<a class="candidate-node" href="#candidate-{row["rank"]}" '
            f'aria-label="{row["rank"]}번 {_esc(row["parameter"])} 후보 상세">'
            f'<i class="family-dot {_esc(row["family"])}" aria-hidden="true"></i>'
            f'<span class="node-name">{_esc(row.get("friendly_parameter") or row["parameter"])}'
            + (f'<small>입력점 #{_esc(row["input_number"])}</small>' if row.get("input_number") else '')
            + '</span>'
            f'<strong>{_fmt_percent(row["score"])}% ↗</strong></a>'
            for row in group
        )
        nodes.append(
            f'<div class="endpoint-node"><div class="node-path">'
            + (f'<b>{_esc(group[0]["friendly_path"])}</b>' if group[0].get("friendly_path") else '')
            + f'{_esc(group[0]["path"])}</div>{links}</div>'
        )
    graph = (
        '<div class="map-canvas"><div class="map-root"><div class="map-root-icon" aria-hidden="true">▧</div>'
        '<strong>분석 대상</strong><small>엔드포인트 → 입력점</small></div>'
        f'<div class="map-branches">{"".join(nodes)}</div></div>'
        if nodes else '<div class="panel-body missing-note">표시할 상위 후보가 없습니다. '
        '이번 결과만으로 대상 전체의 안전 여부를 판단할 수 없습니다.</div>'
    )
    legend = "".join(
        f'<span class="{_esc(family)}">{family_icon(family)}{_esc(label)}</span>'
        for family, label in FAMILY_LABELS.items()
    )
    return (
        '<section class="panel"><div class="panel-head"><div><h2>상위 후보 연결 지도</h2>'
        '<p class="panel-desc">어느 경로의 어떤 입력점을 먼저 살펴볼까요?</p></div>'
        f'<a class="text-link" href="#candidates">{len(visible)} / {len(rows)}개 ↗</a></div>'
        f'{graph}<div class="map-legend">{legend}</div>'
        '<div class="selection-note">선은 경로와 후보의 소속 관계입니다. 페이지 간 이동이나 공격 경로를 의미하지 않습니다.</div></section>'
    )


def family_chart(rows: Sequence[Mapping[str, Any]]) -> str:
    colors = {"SQLI": "sqli", "REFLECTED_XSS": "xss", "BROKEN_ACCESS_CONTROL": "bac"}
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["family"]] = counts.get(row["family"], 0) + 1
    chart = donut_chart(
        [Slice(FAMILY_LABELS.get(family, family), count, colors.get(family, "muted"))
         for family, count in sorted(counts.items())],
        center_value=str(len(rows)), center_caption="대표 후보",
        empty_caption="선택된 후보가 없습니다.",
    )
    return (
        '<section class="panel family-panel"><div class="panel-head"><div><h2>어떤 유형이 보이나요?</h2>'
        '<p class="panel-desc">대표 후보의 유형별 구성</p></div></div>'
        f'<div class="panel-body">{chart}<p class="panel-desc">유형은 점검해야 할 문제의 종류입니다. '
        '취약점 확정 건수나 위험 등급을 의미하지 않습니다.</p></div></section>'
    )


def overview(
    rows: Sequence[Mapping[str, Any]], *, target: str, endpoint_count: int,
    input_point_count: int, scored_count: int, selected_count: int, warnings_html: str,
) -> str:
    heading = page_heading(
        "웹사이트 취약점 분석 결과 개요",
        "대상 웹사이트에서 수집한 입력점과 상위 취약점 후보를 종합한 최종 분석 결과입니다. 후보별 판단 근거, 검증 기록과 개선 방법을 확인할 수 있습니다.",
        eyebrow="FINAL ANALYSIS OVERVIEW",
    )
    metrics = analysis_journey(endpoint_count, input_point_count, scored_count, selected_count, len(rows))
    table = candidate_table(rows[:5], table_id="overview-list") if rows else '<div class="empty">선택된 후보가 없습니다.</div>'
    steps = (
        ("발견", "크롤링으로 경로와 입력점을 수집"),
        ("관찰", "입력 하나를 바꿔 응답 차이를 기록"),
        ("우선순위", "유형별 신호로 상위 후보를 선택"),
        ("추가 확인", "검증 기록이 있는 후보의 근거를 비교"),
    )
    journey = "".join(
        f'<div class="journey-step"><span class="step-number">0{i}</span><div><b>{title}</b>{text}</div></div>'
        for i, (title, text) in enumerate(steps, 1)
    )
    return f"""<section class="report-page overview" id="overview" aria-label="분석 개요">
<div class="page-heading"><div>{heading}<div class="target-chip">◎ {_esc(target or '분석 대상 정보 미제공')}</div></div>
<a class="button primary" href="#candidates">상위 후보 자세히 보기 <span aria-hidden="true">→</span></a></div>
{risk_headline(rows)}
{metrics}{evidence_summary(rows)}{confidence_comparison(rows)}{warnings_html}
<div class="overview-grid">{relationship_map(rows)}{family_chart(rows)}</div>
<section class="panel"><div class="panel-head"><div><h2>상위 취약점 후보</h2>
<p class="panel-desc">현재까지의 최종 신뢰도를 표시합니다. 추가 검증이 없으면 검증 전 확률을 그대로 사용합니다.</p></div>
<a class="text-link" href="#candidates">전체 {len(rows)}개 보기 →</a></div>{table}
<div class="selection-note">{selection_note(selected_count, len(rows))}</div></section>
<div class="journey">{journey}</div></section>"""


def candidates_page(rows: Sequence[Mapping[str, Any]], selected_count: int, unselected: str) -> str:
    family_options = "".join(f'<option value="{key}">{label}</option>' for key, label in FAMILY_LABELS.items())
    state_options = "".join(f'<option value="{key}">{label}</option>' for key, label in STATUS_LABELS.items())
    heading = page_heading("취약점 후보", "경로, 입력점 이름, 유형으로 후보를 찾아보세요. 표시 순서는 검증 전 선택 집합을 유지하면서 최종 신뢰도로 정렬한 결과입니다.")
    return f"""<section class="report-page" id="candidates" aria-label="취약점 후보 목록">
<div class="page-heading"><div>{heading}</div></div>
<section class="panel"><div class="panel-head"><h2>검토할 대표 후보 <span class="ko-en">{len(rows)} candidates</span></h2></div>
<div class="filters"><label>후보 검색<input id="candidate-search" type="search" placeholder="경로 또는 입력점 이름 검색" autocomplete="off"></label>
<label>취약점 유형<select id="family-filter"><option value="">모든 유형</option>{family_options}</select></label>
<label>추가 검증 상태<select id="state-filter"><option value="">모든 상태</option>{state_options}</select></label>
<button class="button" id="reset-filters" type="button">초기화</button>
<span class="filter-count" id="filter-count" role="status" aria-live="polite"></span></div>
{candidate_table(rows, table_id='candidate-list')}
<div class="filter-empty" id="filter-empty" hidden>검색 조건에 맞는 후보가 없습니다. 검색어나 필터를 바꿔 주세요.</div>
<div class="selection-note">{selection_note(selected_count, len(rows))}</div></section>
<details class="list-foot"><summary>선택되지 않은 후보와 제외 사유</summary>{unselected or '<p>선택되지 않은 후보가 없습니다.</p>'}</details>
</section>"""


def _verify_button(row: Mapping[str, Any] | None, verify_base: str) -> str:
    """A one-click link to send the live confirming payload on DemoShop."""

    if not verify_base or row is None or not row.get("canonical_path"):
        return ""
    query = urlencode({"path": row["canonical_path"], "param": row.get("param_name", "")})
    return (
        f'<a class="button primary verify-live" href="{_esc(verify_base)}/_verify?{_esc(query)}" '
        'target="_blank" rel="noopener">\U0001f3af DemoShop에서 취약점 검증 '
        '<span aria-hidden="true">↗</span></a>'
    )


def detail_page(card: str, rank: int, total: int, label: str, row: Mapping[str, Any] | None = None, *, verify_base: str = "") -> str:
    previous = f'<a class="button" href="#candidate-{rank - 1}">← 이전 후보</a>' if rank > 1 else '<span></span>'
    following = f'<a class="button" href="#candidate-{rank + 1}">다음 후보 →</a>' if rank < total else '<a class="button" href="#candidates">목록으로 →</a>'
    return (
        f'<section class="report-page" id="candidate-{rank}" aria-label="{rank}번 후보 상세">'
        '<a class="back-link" href="#candidates">← 취약점 후보 목록</a>'
        f'<div class="page-heading"><div>{page_heading(f"후보 {rank:02d} · {label}", "위치와 관찰 근거부터 추가 검증, 개선 방법까지 차례로 확인하세요.", eyebrow="CANDIDATE DETAIL")}</div>{_verify_button(row, verify_base)}</div>'
        + (f'<div class="source-caption"><strong>{candidate_caption(row)}</strong>'
           '<p>이름과 번호는 일반 요청의 응답에 표시된 DemoShop 안내입니다. 후보 순위와 입력점 번호는 서로 다릅니다.</p></div>'
           if row is not None and row.get("input_number") else '')
        + f'{card}<nav class="detail-pager" aria-label="후보 간 이동">{previous}{following}</nav></section>'
    )
