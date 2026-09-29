"""Display-only journey, confidence comparisons and source-authored captions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from html import escape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from vulnspider.domain import Endpoint, InputPoint
from vulnspider.reporting.html_report import ProbeRun, _fmt_percent


class _MarkerParser(HTMLParser):
    """Read only authored captions in an exact, matching GET form."""

    def __init__(self, request_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.request_url = request_url
        self.stack: list[tuple[str, dict[str, str]]] = []
        self.title = ""
        self.field: dict[str, Any] | None = None
        self.fields: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag == "div" and "input-point-field" in values.get("class", "").split():
            form = next((item for name, item in reversed(self.stack) if name == "form"), {})
            source = urlsplit(self.request_url)
            try:
                action = urlsplit(urljoin(self.request_url, form.get("action", "")))
            except ValueError:
                action = urlsplit("")
            matches = (
                bool(form) and form.get("method", "get").lower() == "get"
                and (action.scheme, action.netloc, action.path) == (source.scheme, source.netloc, source.path)
                and not action.query and not action.fragment
            )
            self.field = {"depth": len(self.stack), "number": values.get("data-input-point", ""),
                          "controls": [], "caption": "", "matches": matches}
        if self.field is not None and tag in ("input", "select", "textarea"):
            self.field["controls"].append((values.get("name"), values.get("id")))
        if tag not in ("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"):
            self.stack.append((tag, values))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        index = next((i for i in range(len(self.stack) - 1, -1, -1) if self.stack[i][0] == tag), None)
        if index is None:
            return
        if self.field is not None and index <= self.field["depth"]:
            self.fields.append(self.field)
            self.field = None
        del self.stack[index:]

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1][0] == "title":
            self.title += data
        if self.field is not None:
            ancestors = self.stack[self.field["depth"]:]
            if (any("field-caption" in attrs.get("class", "").split() for _, attrs in ancestors)
                    and not any(tag == "button" or "input-tooltip" in attrs.get("class", "").split()
                                for tag, attrs in ancestors)):
                self.field["caption"] += data


def source_caption(point: InputPoint | None, endpoint: Endpoint | None, run: ProbeRun | None) -> dict[str, str]:
    """Annotate from a retained baseline; never infer scanner IDs from UI text."""
    if point is None or endpoint is None or run is None:
        return {}
    plan, baseline, _ = run
    request = plan.baseline_request
    url = urlsplit(request.url)
    if (point.location.value != "QUERY" or point.occurrence_index is not None
            or point.endpoint_id != endpoint.id or plan.input_point_id != point.id
            or request.method.value != "GET" or endpoint.method.value != "GET"
            or (url.scheme, url.netloc, url.path) != (endpoint.scheme, endpoint.host, endpoint.path)
            or baseline.request_id != request.id or baseline.execution_error
            or baseline.redirect_location or not 200 <= baseline.status_code < 300
            or not baseline.decoded_text):
        return {}
    parser = _MarkerParser(request.url)
    parser.feed(baseline.decoded_text)
    # This annotation convention is authored by DemoShop, not a generic guess.
    if not parser.title.endswith(" · DemoShop"):
        return {}
    fields = [field for field in parser.fields if field["matches"]
              and any(name == point.name for name, _ in field["controls"])]
    if len(fields) != 1:
        return {}
    field = fields[0]
    number = field["number"]
    caption = " ".join(field["caption"].split())
    title = parser.title.removesuffix(" · DemoShop").strip()
    if (len(number) != 3 or not number.isascii() or not number.isdigit() or not 1 <= int(number) <= 100
            or field["controls"] != [(point.name, f"input-point-{number}")]
            or sum(item["number"] == number for item in parser.fields) != 1
            or not 0 < len(caption) <= 100 or not 0 < len(title) <= 100):
        return {}
    return {"friendly_path": title, "friendly_parameter": caption, "input_number": number}


def candidate_caption(row: Mapping[str, Any]) -> str:
    title = row.get("friendly_path") or row["path"]
    parameter = row.get("friendly_parameter") or row["parameter"]
    marker = f' <span class="input-number">입력점 #{escape(row["input_number"])}</span>' if row.get("input_number") else ""
    return f'{escape(str(title))} · {escape(str(parameter))}{marker}'


def analysis_journey(endpoint_count: int, input_count: int, scored_count: int, selected_count: int, displayed_count: int) -> str:
    stages = (
        (endpoint_count, "발견한 엔드포인트", "요청 방식과 경로로 구분한 검사 대상", "경로 수집"),
        (input_count, "발견한 입력점", "검색어·상품 번호처럼 값을 받는 자리", "입력점 관찰"),
        (scored_count, "채점한 유형별 후보", "입력점 × 유형 및 접근제어 관계", "유형별 평가"),
        (selected_count, "상위 취약점 후보", f"같은 입력점의 유형을 묶어 대표 {displayed_count}개 표시", "집중 검토 대상"),
    )
    items = "".join(
        f'<li class="analysis-stage"><div class="stage-top"><span>0{i}</span>{stage}</div>'
        f'<div class="stage-count">{value:,}<small>개</small></div><h3>{label}</h3><p>{note}</p></li>'
        for i, (value, label, note, stage) in enumerate(stages, 1)
    )
    return (
        '<section class="analysis-journey" aria-label="분석 과정 요약">'
        '<div class="journey-heading"><div><span class="eyebrow">FROM DISCOVERY TO EVIDENCE</span>'
        '<h2>입력점을 발견하고, 검토할 후보를 좁혔습니다.</h2></div>'
        '<a href="#methodology" class="text-link">분석 과정 이해하기 ↗</a></div>'
        f'<ol class="analysis-stages">{items}</ol>'
        '<p class="journey-note">단계마다 집계 단위가 다릅니다. 후보 수는 확정된 취약점 수가 아닙니다.</p></section>'
    )


def confidence_comparison(rows: Sequence[Mapping[str, Any]]) -> str:
    cards = []
    for row in rows[:3]:
        prior, final = row["prior"], row["score"]
        before, after = _fmt_percent(prior), _fmt_percent(final)
        state = row["state"]
        explanation = row["verification_explanation"]
        if state == "UNVERIFIED":
            explanation = "추가 검증 기록이 없습니다. 검증 전 확률을 최종 신뢰도로 그대로 표시합니다."
        delta = (final - prior) * 100
        change = "변화 없음" if abs(delta) < 0.05 else f'{delta:+.1f}%p'
        if state == "UNVERIFIED":
            change = "추가 검증 전"
        cards.append(
            f'<article class="comparison-card"><div class="comparison-top"><span>후보 {row["rank"]:02d}</span>'
            f'<span class="change-label">{change}</span></div>'
            f'<h3><a href="#candidate-{row["rank"]}">{candidate_caption(row)}</a></h3>'
            f'<div class="comparison-type">{escape(str(row["family_label"]))}</div>'
            f'<div class="confidence-values"><span>검증 전 확률<b>{before}%</b></span>'
            f'<span>최종 신뢰도<b>{after}%</b></span></div>'
            '<div class="confidence-track" aria-hidden="true">'
            f'<span class="confidence-span" style="left:{min(prior, final) * 100:.4f}%;width:{abs(delta):.4f}%"></span>'
            f'<i class="final-dot" style="left:{final * 100:.4f}%"></i>'
            f'<i class="prior-dot" style="left:{prior * 100:.4f}%"></i></div>'
            '<div class="confidence-scale" aria-hidden="true"><span>0%</span><span>100%</span></div>'
            f'<p>{escape(explanation)}</p><a class="text-link" href="#candidate-{row["rank"]}">판단 근거 보기 ↗</a></article>'
        )
    return (
        '<section class="panel comparison-panel"><div class="panel-head"><div><h2>추가 확인으로 판단이 어떻게 달라졌나요?</h2>'
        '<p class="panel-desc">최종 신뢰도 순 대표 후보 최대 3개 · 같은 0–100% 눈금으로 비교합니다.</p></div></div>'
        '<div class="confidence-legend"><span><i class="prior-dot"></i>검증 전 확률</span>'
        '<span><i class="final-dot"></i>최종 신뢰도</span></div>'
        f'<div class="comparison-grid">{"".join(cards) or "<p class=missing-note>비교할 상위 후보가 없습니다.</p>"}</div></section>'
    )
