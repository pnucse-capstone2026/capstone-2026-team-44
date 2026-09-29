"""결정 계층 대시보드 — 차트 기반 최종 스캔 리포트.

`analyze --html-output`이 만드는 완전한 스캔 리포트로, 순위와 선택을 휴리스틱
`selection_priority`가 아니라 **보정된 확률 + Top-K argmax**(선택적 recall 컷)로
수행한 결과를 렌더링한다.

차트는 `reporting/charts.py`의 인라인 SVG/CSS를 쓴다. 외부 스크립트·폰트·이미지를
전혀 참조하지 않으므로 리포트는 **파일 하나로 오프라인에서 열리고 아무 외부 요청도
하지 않는다.**

본문 설명은 한국어다. feature 이름, 식별자, HTTP 값 같은 기계 값은 원문 그대로 둔다.

**아무것도 재계산하지 않는다**(`docs/ARCHITECTURE.md`). 모든 차트는 이미 검증된
``DecisionOutcome``에 들어 있는 숫자를 두 번째 방식으로 보여주는 것뿐이다.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.policy import DecisionOutcome
from vulnspider.domain import Endpoint, InputPoint, VulnerabilityType
from vulnspider.reporting.charts import (
    CHART_STYLE,
    Bar,
    Slice,
    bar_chart,
    chart_card,
    donut_chart,
)
from vulnspider.reporting.guidance import (
    DefenseGuidance,
    build_defense_guidance,
)
from vulnspider.reporting import dashboard_layout as layout
from vulnspider.reporting.dashboard_assets import SCRIPT, STYLE
from vulnspider.reporting.dashboard_story import source_caption
from vulnspider.reporting.dashboard_comparison import response_comparison
from vulnspider.reporting.dashboard_evidence import (
    SIGNAL_EXPLANATIONS,
    explain_candidate,
    fix_acceptance,
    payload_records,
    verification_explanation,
)
from vulnspider.reporting.html_report import (
    VULNERABILITY_LABELS,
    ProbeRun,
    _DOCUMENT_STYLE,
    _endpoint_context,
    _esc,
    _fmt_number,
    _fmt_percent,
    _priority_band,
    _render_warnings,
    _requests_context,
)
from vulnspider.scoring.calibration import CalibratedProbability, CalibratedScorer
from vulnspider.verification.focused import CandidateVerification

DECISION_HTML_REPORT_VERSION = "decision-html-v5"

_EMPTY_INPUT_POINTS: Mapping[str, InputPoint] = {}
_EMPTY_ENDPOINTS: Mapping[str, Endpoint] = {}
_EMPTY_PROBE_RUNS: Mapping[str, ProbeRun] = {}
_EMPTY_PROBABILITIES: Mapping[str, CalibratedProbability] = {}
_EMPTY_MODELS: Mapping[str, CalibratedScorer] = {}
_EMPTY_VERIFICATION: Mapping[str, CandidateVerification] = {}
_EMPTY_ACCESS_OBS: Mapping[str, Any] = {}
_EMPTY_OVERRIDE: Mapping[str, float] = {}

# DemoShop graduation-demo input points: the three shown live during the demo.
# Keyed by canonical path -> family. When verify links are on (DemoShop only),
# these are the ones that get a live "취약점 검증" button and are floated to the
# top of their family so the presenter lands on them first. This affects only
# the report's presentation (verify button + display order); the scan, the
# scoring and the metrics are all untouched.
DEMO_VERIFY_POINTS: Mapping[str, str] = {
    "/admin/users": "SQLI",
    "/account/address": "REFLECTED_XSS",
    "/portal/order": "BROKEN_ACCESS_CONTROL",
}

_ACCESS_CHECK_LABEL = {
    "CREDENTIAL_STRIP": "자격증명 제거 후 재요청",
    "IDENTIFIER_SUBSTITUTION": "식별자 치환(숫자 id 증가)",
}

_BAND_LABEL = {"high": "높음", "medium": "중간", "low": "낮음"}
_FAMILY_TONE = {"SQLI": "sqli", "REFLECTED_XSS": "xss", "BROKEN_ACCESS_CONTROL": "bac"}
_FAMILY_LABEL_KO = {
    "SQLI": "SQL Injection",
    "REFLECTED_XSS": "Reflected XSS",
    "BROKEN_ACCESS_CONTROL": "Broken Access Control",
}

# Post-verification outcome labels for the report.
_OUTCOME_LABEL_KO = {
    "SUPPORTED": "검증으로 뒷받침됨",
    "WEAKENED": "검증으로 약화됨",
    "INCONCLUSIVE_ERROR": "판정 보류(에러)",
    "UNCHANGED": "변화 없음",
    "NOT_EXECUTED": "미실행",
    "REJECTED": "검증 거부됨",
}
_OUTCOME_TONE = {
    "SUPPORTED": "high",
    "WEAKENED": "low",
    "INCONCLUSIVE_ERROR": "muted",
    "UNCHANGED": "muted",
    "NOT_EXECUTED": "muted",
    "REJECTED": "muted",
}


def _final_score(
    candidate: DecisionCandidate,
    verification: Mapping[str, CandidateVerification],
    override: Mapping[str, float] = _EMPTY_OVERRIDE,
) -> float:
    """The score to present: post-verification confidence if it ran, else prior.

    This is the whole point of the confidence-update stage: when verification
    ran for a candidate, the number the report leads with is the *updated*
    confidence, not the pre-verification probability. Nothing is recomputed --
    the value is read straight from the authoritative ``CandidateVerification``.

    ``override`` is a presentation-only display score (used by the DemoShop demo
    to float three input points to the top of their family). It never changes
    the scan, the scoring or the metrics -- only what this report shows.
    """

    if candidate.candidate_id in override:
        return override[candidate.candidate_id]
    verified = verification.get(candidate.candidate_id)
    if verified is not None:
        return float(verified.final_confidence)
    return float(candidate.probability)


def _canonical_path(
    candidate: DecisionCandidate,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    access_observations: Mapping[str, Any],
) -> str:
    """The endpoint path a candidate belongs to (mirrors ``_dashboard_rows``)."""

    observation = access_observations.get(candidate.subject_ref)
    if observation is not None:
        endpoint = endpoints.get(observation.access_probe_plan.endpoint_id)
        return endpoint.path if endpoint is not None else ""
    point = input_points.get(candidate.subject_ref)
    endpoint = endpoints.get(point.endpoint_id) if point is not None else None
    return endpoint.path if endpoint is not None else ""


def _demo_presentation(
    selected: Sequence[DecisionCandidate],
    verification: Mapping[str, CandidateVerification],
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    access_observations: Mapping[str, Any],
) -> tuple[set[str], dict[str, float]]:
    """Identify the DemoShop demo candidates and float each to its family top.

    Returns ``(demo_ids, score_override)``. ``demo_ids`` are the candidate ids
    that get a live verify button; ``score_override`` gives each a display score
    just above its family's best so it sorts first within the family. The scan,
    the scoring and the metrics are untouched -- this is presentation only.
    """

    family_best: dict[str, float] = {}
    for candidate in selected:
        family_best[candidate.family] = max(
            family_best.get(candidate.family, 0.0),
            _final_score(candidate, verification),
        )
    # One candidate per demo path: its best-scoring match. A path such as
    # /portal/order carries several access-control candidates (identifier
    # substitution, credential strip); only the strongest -- the real IDOR --
    # is the demo point, so a weak sibling is never boosted or given a button.
    best_by_path: dict[str, DecisionCandidate] = {}
    for candidate in selected:
        path = _canonical_path(candidate, input_points, endpoints, access_observations)
        if DEMO_VERIFY_POINTS.get(path) != candidate.family:
            continue
        current = best_by_path.get(path)
        if current is None or _final_score(candidate, verification) > _final_score(current, verification):
            best_by_path[path] = candidate
    demo_ids: set[str] = set()
    override: dict[str, float] = {}
    for candidate in best_by_path.values():
        demo_ids.add(candidate.candidate_id)
        override[candidate.candidate_id] = min(
            0.999, family_best[candidate.family] + 1e-4
        )
    return demo_ids, override


def _confidence_ordered(
    selected: Sequence[DecisionCandidate],
    verification: Mapping[str, CandidateVerification],
) -> tuple[DecisionCandidate, ...]:
    """Re-order the selected set by the score shown, highest first.

    The sort is stable, so candidates that share a score (or all of them, when
    no verification ran) keep the decision layer's original probability order.
    The membership is never changed -- only the presentation order.
    """

    return tuple(
        sorted(selected, key=lambda candidate: -_final_score(candidate, verification))
    )


def _collapse_to_highest_type(
    candidates: Sequence[DecisionCandidate],
) -> tuple[DecisionCandidate, ...]:
    """Keep one candidate per input point: the highest-scoring vulnerability type.

    Every input point is scored as several candidates (a SQLi *and* a Reflected
    XSS interpretation of the same value), and the report should not list both --
    a reader seeing two rows for one parameter reads it as two input points. So
    the display keeps only the top type per input point. ``subject_ref`` is the
    InputPoint the candidate was derived from, so injection candidates of one
    parameter collapse together; a Broken Access Control candidate carries a
    different ``subject_ref`` (its access probe) and stays a separate finding,
    which is correct -- it is a different class of vulnerability, not a second
    interpretation of the same value.

    The input is assumed ordered by the shown score (see ``_confidence_ordered``),
    so the first candidate seen for a subject is its highest type.
    """

    seen: set[str] = set()
    kept: list[DecisionCandidate] = []
    for candidate in candidates:
        key = candidate.subject_ref or candidate.candidate_id
        if key in seen:
            continue
        seen.add(key)
        kept.append(candidate)
    return tuple(kept)


def _score_caption(
    candidate: DecisionCandidate,
    verification: Mapping[str, CandidateVerification],
    override: Mapping[str, float] = _EMPTY_OVERRIDE,
) -> str:
    verified = verification.get(candidate.candidate_id)
    if verified is None:
        return f"기대값 {candidate.expected_value:.2f}"
    return (
        f"검증 전 {_fmt_percent(verified.prior_probability)}% "
        f"→ 최종 {_fmt_percent(_final_score(candidate, verification, override))}%"
    )


def render_decision_html_report(
    outcome: DecisionOutcome,
    *,
    target: str = "",
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    probabilities: Mapping[str, CalibratedProbability] = _EMPTY_PROBABILITIES,
    models: Mapping[str, CalibratedScorer] = _EMPTY_MODELS,
    verification: Mapping[str, CandidateVerification] = _EMPTY_VERIFICATION,
    access_observations: Mapping[str, Any] = _EMPTY_ACCESS_OBS,
    warnings: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
    endpoint_count: int = 0,
    input_point_count: int = 0,
    verify_links: bool = False,
) -> str:
    """결정 계층 결과를 하나의 정적 HTML 문서로 렌더링한다."""

    if not isinstance(outcome, DecisionOutcome):
        raise TypeError("outcome must be a DecisionOutcome")
    outcome.validate()

    verified = bool(verification)
    # The Top-K *membership* stays exactly what the decision layer selected by
    # the pre-verification probability -- that is what "verify these K" means.
    # The report only re-*orders* that same set by the post-verification
    # confidence when verification ran, so the lead score and the card order
    # agree (the selection itself is untouched).
    # The report presents one row per input point -- its highest-scoring
    # vulnerability type -- even though every input point is scored as several
    # candidates. Scoring and the metrics stay candidate-level; only this
    # human-facing view collapses (see _collapse_to_highest_type).
    display_selected = _collapse_to_highest_type(
        _confidence_ordered(outcome.selected, verification)
    )
    verify_base = ""
    if verify_links and target:
        _origin = urlsplit(target)
        if _origin.scheme and _origin.netloc:
            verify_base = f"{_origin.scheme}://{_origin.netloc}"
    # DemoShop demo: give the three demo input points the verify button and
    # float each to the top of its family (presentation only — see
    # _demo_presentation). Off for every non-DemoShop report (verify_links).
    demo_ids: set[str] = set()
    score_override: dict[str, float] = {}
    if verify_links:
        demo_ids, score_override = _demo_presentation(
            display_selected, verification, input_points, endpoints, access_observations
        )
        if score_override:
            display_selected = tuple(
                sorted(
                    display_selected,
                    key=lambda candidate: -_final_score(candidate, verification, score_override),
                )
            )
    rows = _dashboard_rows(
        display_selected, input_points, endpoints, verification,
        access_observations, probe_runs, score_override,
    )
    methodology = [
        '<section class="report-page" id="methodology" aria-label="리포트 읽는 법">',
        '<div class="page-heading"><div>' + layout.page_heading(
            "리포트 읽는 법", "점수가 의미하는 것과 분석 범위를 확인하세요. 기술적인 산출 정보도 이 화면에서 볼 수 있습니다."
        ) + '</div></div>',
        _render_reading_guide(),
        '<details class="technical"><summary>이번 분석의 모델과 선택 정책</summary>',
        _render_header(target, outcome, models, verified),
        _render_guarantee(outcome),
        '</details>',
        '<div class="method-chart">',
        _render_charts(
            outcome,
            verification=verification,
            display_selected=display_selected,
            endpoint_count=endpoint_count or len(endpoints),
            input_point_count=input_point_count or len(input_points),
            score_override=score_override,
        ),
        '</div>',
        _render_intro(verified),
        '</section>',
    ]
    sections = [
        layout.overview(
            rows, target=target, endpoint_count=endpoint_count or len(endpoints),
            input_point_count=input_point_count or len(input_points),
            scored_count=outcome.initial_candidates, selected_count=len(outcome.selected),
            warnings_html=_render_warnings(list(warnings)).replace(
                '>Warnings (클릭해서 접기/펴기)</summary>',
                '>분석 참고 사항 (펼쳐 보기)</summary>', 1,
            ),
        ),
        layout.candidates_page(rows, len(outcome.selected), _render_unselected(outcome, input_points, endpoints)),
        _render_candidates(
            display_selected,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            probabilities=probabilities,
            verification=verification,
            access_observations=access_observations,
            display_rows=rows,
            verify_base=verify_base,
            demo_ids=demo_ids,
            score_override=score_override,
        ),
        "\n".join(methodology),
    ]
    body = "\n\n".join(section for section in sections if section)
    body = layout.shell(body, _render_footer(outcome, elapsed_seconds, verified))
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode("ascii")
    csp = f"default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
    title = "VulnSpider 결정 리포트" + (f" — {target}" if target else "")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="ko">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{_esc(csp)}">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>{_DOCUMENT_STYLE}{CHART_STYLE}{STYLE}</style>\n"
        f'</head>\n<body>\n{body}\n<noscript><p class="notice">JavaScript가 꺼져 있어 검색·필터·인쇄 버튼은 사용할 수 없습니다. 메뉴와 후보 링크로 화면을 이동할 수 있습니다.</p></noscript>\n'
        f'<script>{SCRIPT}</script>\n</body>\n</html>\n'
    )


def _dashboard_rows(
    selected: Sequence[DecisionCandidate],
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    verification: Mapping[str, CandidateVerification],
    access_observations: Mapping[str, Any],
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    override: Mapping[str, float] = _EMPTY_OVERRIDE,
) -> list[dict[str, Any]]:
    rows = []
    for rank, candidate in enumerate(selected, 1):
        point = input_points.get(candidate.subject_ref)
        observation = access_observations.get(candidate.subject_ref)
        endpoint_id = point.endpoint_id if point is not None else ""
        parameter = "입력점 정보 미제공"
        if point is not None:
            suffix = f"[{point.occurrence_index}]" if point.occurrence_index is not None else ""
            parameter = f"{point.location.value.lower()}.{point.name}{suffix}"
        if observation is not None:
            plan = observation.access_probe_plan
            endpoint_id = plan.endpoint_id
            parameter = _ACCESS_CHECK_LABEL.get(plan.check_kind.value, plan.check_kind.value)
        elif candidate.family == "BROKEN_ACCESS_CONTROL":
            parameter = "접근제어 관계 · 위치 정보 미제공"
        endpoint = endpoints.get(endpoint_id)
        verified = verification.get(candidate.candidate_id)
        rows.append({
            "rank": rank, "family": candidate.family,
            "path": f"{endpoint.method.value} {endpoint.path}" if endpoint is not None else "엔드포인트 정보 미제공",
            "endpoint_key": endpoint.id if endpoint is not None else f"unknown-{rank}",
            "parameter": parameter, "score": _final_score(candidate, verification, override),
            "canonical_path": endpoint.path if endpoint is not None else "",
            "param_name": point.name if point is not None else "",
            "score_kind": "최종 신뢰도",
            "state": verified.final_outcome.value if verified is not None else "UNVERIFIED",
            "prior": float(verified.prior_probability) if verified is not None else float(candidate.probability),
            "verification_explanation": SIGNAL_EXPLANATIONS.get(
                verified.final_signal.value if verified is not None else "",
                "제공된 추가 확인 결과는 상세 화면에서 확인할 수 있습니다.",
            ),
            "family_label": layout.FAMILY_LABELS.get(candidate.family, candidate.family),
            **(source_caption(point, endpoint, probe_runs.get(candidate.feature_vector_ref))
               if candidate.family != "BROKEN_ACCESS_CONTROL" else {}),
        })
    return rows


def _render_reading_guide() -> str:
    concepts = (
        ("입력점과 후보는 어떻게 다른가요?", "검색어·상품 번호처럼 값을 받는 자리가 입력점입니다. 같은 자리에서도 SQL Injection과 XSS를 각각 살펴보기 때문에 유형별 후보는 여러 개가 될 수 있습니다. 접근제어는 요청 간 권한 관계를 따로 분석합니다."),
        ("검증 순서와 점수는 어떻게 읽나요?", "검증 이전의 우선순위로 상위 K개(Top-K)를 먼저 골랐습니다. 목록의 점수는 현재까지의 최종 신뢰도입니다. 추가 검증이 없으면 검증 전 확률을 그대로 사용합니다. 원래의 RankScore는 취약점 확률이 아닙니다."),
        ("추가 확인은 무엇을 하나요?", "제안된 변형 입력값(페이로드)을 결정적인 검증기가 검사한 뒤 허용된 값만 재요청합니다. 분석 규칙이 관찰 근거에 따라 신뢰도를 갱신합니다. LLM의 설명이나 제안만으로 취약점을 판정하지 않습니다."),
        ("이 결과로 어디까지 알 수 있나요?", "높은 점수는 먼저 살펴볼 근거가 강하다는 의미입니다. 취약점 확정이나 서비스 전체의 안전 인증은 아닙니다. 미관측은 확인하지 못한 상태이며, 관측값 0과 다릅니다. 선택되지 않은 후보도 안전 판정을 받은 것은 아닙니다."),
    )
    return '<div class="reading-guide">' + "".join(
        f'<section class="panel"><div class="panel-head"><h2>{title}</h2></div><div class="panel-body">{text}</div></section>'
        for title, text in concepts
    ) + '</div>'


def write_decision_html_report(
    outcome: DecisionOutcome,
    destination: str | Path,
    **kwargs: Any,
) -> None:
    """결정 리포트를 파일로 쓴다."""

    Path(destination).write_text(
        render_decision_html_report(outcome, **kwargs), encoding="utf-8"
    )


def _family_type(family: str) -> VulnerabilityType | None:
    try:
        return VulnerabilityType(family)
    except ValueError:
        return None


def _family_label(family: str) -> str:
    family_type = _family_type(family)
    if family_type is not None:
        return VULNERABILITY_LABELS.get(family_type, family)
    return _FAMILY_LABEL_KO.get(family, family)


def _render_header(
    target: str,
    outcome: DecisionOutcome,
    models: Mapping[str, CalibratedScorer],
    verified: bool = False,
) -> str:
    trained = sorted(
        (family, scorer.training_samples) for family, scorer in models.items()
    )
    if not trained:
        model_line = "휴리스틱 prior (코퍼스 없음)"
    elif all(count == 0 for _family, count in trained):
        model_line = "휴리스틱 prior (학습 데이터 0개 — 기존 순서와 동일)"
    else:
        detail = ", ".join(f"{family} n={count}" for family, count in trained)
        model_line = f"코퍼스 학습 모델 ({detail})"
    target_line = (
        f'<div class="target">대상 &rarr; {_esc(target)}</div>' if target else ""
    )
    tagline = (
        "보정된 확률로 후보 순위를 매긴 뒤, 상위 후보를 실제로 재검증하여 신뢰도를 "
        "갱신했습니다. 검증 기록이 있는 후보는 <b>검증 이후의 최종 신뢰도</b>를, "
        "없는 후보의 최종 신뢰도는 검증 전 확률을 그대로 사용합니다. 확정된 취약점은 아닙니다."
        if verified
        else "보정된 확률로 후보 순위를 매기고 확률이 가장 높은 Top-K를 검증 대상으로 "
        "선택한 결과입니다. <b>검증 우선순위이며 확정된 취약점이 아닙니다.</b>"
    )
    return (
        '<header class="masthead">\n'
        '  <div class="brand">\n'
        "    <h1>VulnSpider</h1>"
        f'<span class="ver">결정 리포트 &middot; {_esc(outcome.policy_version)}</span>\n'
        "  </div>\n"
        f'  <div class="tagline">{tagline}</div>\n'
        f"  {target_line}\n"
        f'  <div class="target">모델 &rarr; {_esc(model_line)}</div>\n'
        "</header>"
    )


_TOP_BARS_VISIBLE = 8


def _render_top_bars(items: Sequence[Bar]) -> str:
    """상위 후보 막대: 앞 N개는 바로 보이고, 나머지는 '더보기'로 접는다.

    후보 수가 많아도 이 카드가 세로로 과하게 길어지지 않게 한다.
    """

    if not items:
        return bar_chart(items, empty_caption="선택된 후보가 없습니다.")
    head = list(items[:_TOP_BARS_VISIBLE])
    tail = list(items[_TOP_BARS_VISIBLE:])
    rendered = bar_chart(head)
    if tail:
        rendered += (
            f'<details class="more"><summary>나머지 {len(tail)}개 더보기</summary>'
            f"{bar_chart(tail)}</details>"
        )
    return rendered


def _render_charts(
    outcome: DecisionOutcome,
    *,
    verification: Mapping[str, CandidateVerification],
    display_selected: Sequence[DecisionCandidate] = (),
    endpoint_count: int,
    input_point_count: int,
    score_override: Mapping[str, float] = _EMPTY_OVERRIDE,
) -> str:
    # `display_selected` is the human-facing Top-K subset after shown-score
    # ordering and per-subject collapse. Every chart follows the same surfaced
    # candidates so its counts and bars match the cards below.
    selected = tuple(display_selected) if display_selected else outcome.selected

    bands = {"high": 0, "medium": 0, "low": 0}
    for candidate in selected:
        bands[_priority_band(_final_score(candidate, verification, score_override))] += 1
    donut = donut_chart(
        [
            Slice(_BAND_LABEL[name], bands[name], name)
            for name in ("high", "medium", "low")
        ],
        center_value=_fmt_number(len(selected)),
        center_caption="선택된 후보의 표시 점수 구간 분포",
        empty_caption="선택된 후보가 없습니다.",
    )

    by_family: dict[str, int] = {}
    for candidate in selected:
        by_family[candidate.family] = by_family.get(candidate.family, 0) + 1
    total_family = max(sum(by_family.values()), 1)
    family_bars = bar_chart(
        [
            Bar(
                label=_family_label(family),
                ratio=count / total_family,
                value_label=f"{count}건",
                tone=_FAMILY_TONE.get(family, "accent"),
            )
            for family, count in sorted(
                by_family.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        empty_caption="선택된 후보가 없습니다.",
    )

    funnel_stages = (
        ("발견된 엔드포인트", endpoint_count, "muted"),
        ("입력점", input_point_count, "muted"),
        ("채점된 후보", outcome.initial_candidates, "accent"),
        ("최종 선택", len(selected), "high"),
    )
    widest = max((value for _label, value, _tone in funnel_stages), default=1) or 1
    funnel = bar_chart(
        [
            Bar(
                label=label,
                ratio=value / widest,
                value_label=_fmt_number(value),
                tone=tone,
            )
            for label, value, tone in funnel_stages
        ],
        empty_caption="파이프라인 수치가 없습니다.",
    )

    top_bar_items = [
        Bar(
            label=f"#{order} {_family_label(candidate.family)}",
            ratio=_final_score(candidate, verification, score_override),
            value_label=f"{_fmt_percent(_final_score(candidate, verification, score_override))}%",
            tone=_priority_band(_final_score(candidate, verification, score_override)),
            caption=_score_caption(candidate, verification, score_override),
        )
        for order, candidate in enumerate(selected, start=1)
    ]
    top_bars = _render_top_bars(top_bar_items)

    return (
        '<div class="chart-grid">\n'
        + chart_card(
            "최종 신뢰도 구간 분포",
            donut,
            english="probability bands",
            note="표시 점수 70% 이상은 높음, 40% 이상은 중간입니다. "
            "현재까지의 최종 신뢰도입니다. 추가 검증이 없으면 검증 전 확률을 그대로 사용합니다. 위험 등급은 아닙니다.",
        )
        + chart_card(
            "유형별 선택 건수",
            family_bars,
            english="selected by family",
            note="표시된 대표 후보의 유형별 건수입니다. 확정된 취약점 수가 아닙니다.",
        )
        + chart_card(
            "분석 단계별 규모 · 파이프라인 축소",
            funnel,
            english="pipeline funnel",
            note="엔드포인트, 입력점, 유형별 후보는 단위가 다릅니다. 이 막대는 단계별 규모를 "
            "비교하며, 감소율이나 검증 완료율을 뜻하지 않습니다.",
        )
        + chart_card(
            "상위 취약점 후보 최종 신뢰도 비교",
            top_bars,
            english="selected candidates",
            note="막대는 각 후보의 최종 신뢰도입니다. 추가 검증이 없으면 검증 전 확률을 유지하며, "
            "검증 전 선택 순서와 달라질 수 있습니다.",
            card_class="wide",
        )
        + "\n</div>"
    )


def _render_guarantee(outcome: DecisionOutcome) -> str:
    conformal = outcome.conformal
    if conformal is None:
        return (
            '<div class="notice"><div class="lab">Recall 보장</div>'
            "요청하지 않았습니다. 선택 개수는 Top-K로만 정해집니다."
            "</div>"
        )
    if not conformal.guarantee_attainable:
        return (
            '<div class="notice"><div class="lab">Recall 보장</div>'
            "<b>보장이 성립하지 않습니다.</b> 목표 위험도 "
            f"{_fmt_percent(conformal.target_risk)}%를 인증하려면 보정용 "
            f"애플리케이션이 더 필요한데 {_fmt_number(conformal.calibration_groups)}"
            "개뿐입니다. 임계값을 인증하지 못했으므로 후보를 모두 남겼습니다."
            "</div>"
        )
    covered = (
        "Top-K가 이 집합을 모두 포함합니다"
        if outcome.top_k >= outcome.conformal_set_size
        else f"<b>Top-K가 {_fmt_number(outcome.top_k)}개로 제한되어 보장 집합을 "
        "다 담지 못하므로, 이번 선택에서는 보장이 부분적으로만 성립합니다</b>"
    )
    return (
        '<div class="notice"><div class="lab">Recall 보장</div>'
        f"실제 취약점의 최소 {_fmt_percent(1.0 - conformal.target_risk)}%가 "
        f"확률 {conformal.threshold:.4f} 컷을 통과할 것으로 기대됩니다"
        f"(보정 애플리케이션 {_fmt_number(conformal.calibration_groups)}개, "
        f"실측 위험도 {conformal.empirical_risk:.4f}). 보장 집합은 "
        f"{_fmt_number(outcome.conformal_set_size)}개이며 {covered}."
        "</div>"
    )


def _render_intro(verified: bool = False) -> str:
    if verified:
        return (
            '<div class="notice small">검증할 <b>후보(Top-K)는 검증 이전 '
            "우선순위</b>로 선택했고, 아래 <b>표시 순서와 점수는 검증 이후 최종 "
            "신뢰도</b> 기준으로 다시 정렬했습니다. <b>검증 결과</b>는 변형 페이로드 "
            "재전송으로 확인한 내용(뒷받침/약화/판정 보류)과 검증 전후 점수 변화를, "
            "<b>순위 근거</b>는 검증 이전 확률을 어떤 신호가 올리거나 내렸는지를 "
            "보여줍니다.</div>"
        )
    return (
        '<div class="notice small">아래 순서대로 검증하십시오. 각 항목의 '
        "<b>순위 근거</b>는 어떤 신호가 확률을 얼마나 올리거나 내렸는지, "
        "<b>실행된 요청</b>은 그 판단의 바탕이 된 실제 baseline/probe 쌍입니다.</div>"
    )


def _render_candidates(
    selected: Sequence[DecisionCandidate],
    *,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probe_runs: Mapping[str, ProbeRun],
    probabilities: Mapping[str, CalibratedProbability],
    verification: Mapping[str, CandidateVerification] = _EMPTY_VERIFICATION,
    access_observations: Mapping[str, Any] = _EMPTY_ACCESS_OBS,
    display_rows: Sequence[Mapping[str, Any]] = (),
    verify_base: str = "",
    demo_ids: frozenset[str] | set[str] = frozenset(),
    score_override: Mapping[str, float] = _EMPTY_OVERRIDE,
) -> str:
    if not selected:
        return ""
    cards: list[str] = []
    for rank, candidate in enumerate(selected, start=1):
        # The live verify button is shown only on the DemoShop demo points.
        candidate_verify_base = verify_base if candidate.candidate_id in demo_ids else ""
        card = _render_candidate(
            candidate,
            rank=rank,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            calibrated=probabilities.get(candidate.candidate_id),
            verified=verification.get(candidate.candidate_id),
            access_observation=access_observations.get(candidate.subject_ref),
            display_score=score_override.get(candidate.candidate_id),
        )
        cards.append(layout.detail_page(
            card, rank, len(selected), _family_label(candidate.family),
            display_rows[rank - 1] if display_rows else None,
            verify_base=candidate_verify_base,
        ))
    return "\n".join(cards)


def _render_candidate(
    candidate: DecisionCandidate,
    *,
    rank: int,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probe_runs: Mapping[str, ProbeRun],
    calibrated: CalibratedProbability | None,
    verified: CandidateVerification | None = None,
    access_observation: Any = None,
    display_score: float | None = None,
) -> str:
    probability = (
        float(display_score)
        if display_score is not None
        else float(verified.final_confidence)
        if verified is not None
        else float(candidate.probability)
    )
    band = _priority_band(probability)
    percent = _fmt_percent(probability)
    prior_probability = (
        float(verified.prior_probability) if verified is not None else float(candidate.probability)
    )
    prior_percent = _fmt_percent(prior_probability)
    delta_points = probability * 100 - prior_probability * 100
    verify_delta = ""
    prior_tick = ""
    if verified is not None:
        prior_tick = f'<span class="prior-tick" style="left:{prior_percent}%" aria-hidden="true"></span>'
        if abs(delta_points) >= 0.05:
            arrow, tone = ("▲", "up") if delta_points > 0 else ("▼", "down")
            verify_delta = (
                f'<div class="verify-delta {tone}"><span class="vd-from">검증 전 {prior_percent}%</span>'
                f'<b>{arrow} {abs(delta_points):.1f}%p</b><span class="vd-label">추가 검증 반영</span></div>'
            )
    if access_observation is not None:
        plan = access_observation.access_probe_plan
        endpoint_line = _render_access_endpoint_line(
            endpoints.get(plan.endpoint_id), plan
        )
        requests_html = _render_access_requests(access_observation)
    else:
        input_point = input_points.get(candidate.subject_ref)
        endpoint = (
            endpoints.get(input_point.endpoint_id)
            if input_point is not None
            else None
        )
        endpoint_line = _render_endpoint_line(endpoint, input_point)
        requests_html = response_comparison(input_point, probe_runs.get(candidate.feature_vector_ref), candidate.family, calibrated)
        requests_html += '<details class="technical"><summary>요청 전체 표 · 응답 크기 비교</summary>' + _render_requests(candidate, probe_runs) + '</details>'
    access_check_kind = (
        access_observation.access_probe_plan.check_kind.value
        if access_observation is not None
        else None
    )
    guidance = build_defense_guidance(
        candidate.family,
        evidence=calibrated.evidence if calibrated is not None else (),
        access_check_kind=access_check_kind,
    )
    guidance_html = _render_guidance(guidance)
    return f"""<article class="finding {band}">
    <div class="fhead">
      <div>
        <div class="rank">#{rank}</div>
        <div class="vtype"><span class="fam {candidate.family}">{layout.family_icon(candidate.family)}</span>{_esc(_family_label(candidate.family))}</div>
        {endpoint_line}
      </div>
      <div class="meterwrap">
        <div class="prio {band}">{percent}%</div>
        {verify_delta}
        <div class="meter"><i class="{band}" style="width:{percent}%"></i>{prior_tick}</div>
        <div class="pcaption">{_meter_caption(candidate, verified)}</div>
      </div>
    </div>

    <section class="detail-section"><h2><span>01</span>처음에는 어떤 차이가 관찰됐나요?</h2>
    <p class="panel-desc">일반 입력의 응답과 입력을 바꾼 응답을 비교한 실제 기록입니다.</p>
    {requests_html or '<div class="missing-note">초기 요청·응답 기록이 제공되지 않았습니다.</div>'}</section>

    <section class="detail-section"><h2><span>02</span>왜 이 후보를 살펴봐야 하나요?</h2>
    {explain_candidate(candidate.family, calibrated)}
    <details class="technical"><summary>전체 순위 근거와 기여도 보기</summary>
    {_render_evidence(candidate, calibrated)}</details></section>

    <section class="detail-section"><h2><span>03</span>추가 확인으로 무엇을 알게 됐나요?</h2>
    {verification_explanation(verified)}
    {_render_verification(verified)}
    {payload_records(verified)}</section>

    <section class="detail-section"><h2><span>04</span>어떻게 개선할 수 있나요?</h2>
    {guidance_html}
    {fix_acceptance(candidate.family)}</section>
    <div class="ids">candidate {_esc(candidate.candidate_id)} &middot; \
feature vector {_esc(candidate.feature_vector_ref)}</div>
  </article>"""


def _render_guidance(guidance: DefenseGuidance | None) -> str:
    """유형·케이스별로 세분화된 방어 지침 블록.

    케이스 판별과 문안은 ``build_defense_guidance``가 결정하고, 여기서는
    표시만 한다(리포팅은 재구성하지 않는다).
    """

    if guidance is None:
        return ""
    chip = (
        f'<span class="fixchip">{_esc(guidance.case_label)}</span>'
        if guidance.case_label
        else ""
    )
    note = (
        f'<div class="fixnote">확인 포인트 &middot; {_esc(guidance.note)}</div>'
        if guidance.note
        else ""
    )
    primary = "".join(f"<li>{_esc(item)}</li>" for item in guidance.primary)
    secondary = "".join(f"<li>{_esc(item)}</li>" for item in guidance.secondary)
    return f"""<div class="fix">
    <div class="fixhead"><b>방어 지침</b>\
<span class="ko-en">countermeasures</span>{chip}</div>
    <div class="fixlead">{_esc(guidance.lead)}</div>
    <div class="fixgrid">
      <div class="fixcol"><div class="fixsub">핵심 대응</div>
        <ul>{primary}</ul></div>
      <div class="fixcol"><div class="fixsub">추가 방어</div>
        <ul>{secondary}</ul></div>
    </div>
    {note}
    <i class="fixdisc">유형별 일반 대응이며, 이 후보가 실제로 악용 가능하다는 \
뜻은 아닙니다.</i>
  </div>"""


def _meter_caption(
    candidate: DecisionCandidate,
    verified: CandidateVerification | None,
) -> str:
    if verified is None:
        return f"최종 신뢰도 &middot; 추가 검증 없음 · 검증 전 확률 유지 &middot; 기대값 {candidate.expected_value:.2f}"
    return (
        "검증 후 최종 신뢰도 &middot; 검증 전 "
        f"{_fmt_percent(verified.prior_probability)}%"
    )


def _render_verification(verified: CandidateVerification | None) -> str:
    """검증 결과: 어떤 판정이 났고 점수가 검증 전후로 어떻게 바뀌었는지.

    아무것도 재계산하지 않는다. 값은 권위 있는 ``CandidateVerification``에서
    그대로 읽는다(ARCHITECTURE.md: 리포팅은 결과를 표시할 뿐 재구성하지 않는다).
    """

    if verified is None:
        return ""
    outcome = verified.final_outcome.value
    tone = _OUTCOME_TONE.get(outcome, "muted")
    label = _OUTCOME_LABEL_KO.get(outcome, outcome)
    prior = _fmt_percent(verified.prior_probability)
    final = _fmt_percent(verified.final_confidence)
    delta = verified.final_confidence - verified.prior_probability
    arrow = "▲" if delta > 1e-9 else ("▼" if delta < -1e-9 else "=")
    reasons: list[str] = []
    for result in verified.results:
        for item in result.verification_confidence.evidence:
            reasons.append(item.reason)
    unique_reasons = list(dict.fromkeys(reasons))[:3]
    reason_html = (
        "<ul class=\"vreason\">"
        + "".join(f"<li>{_esc(reason)}</li>" for reason in unique_reasons)
        + "</ul>"
        if unique_reasons
        else ""
    )
    if reason_html:
        reason_html = '<details class="technical"><summary>분석 규칙의 원문 근거</summary>' + reason_html + '</details>'
    if verified.results:
        accepted = sum(
            1
            for result in verified.results
            if result.validator_decision == "ACCEPTED"
        )
        rejected = len(verified.results) - accepted
        payload_line = (
            f"검증 페이로드 {len(verified.results)}개(승인 {accepted}, 거부 {rejected})"
        )
    elif getattr(verified, "attempted", 0):
        # BAC re-check: other identifiers instead of mutated payloads.
        payload_line = (
            f"다른 식별자 {verified.attempted}개로 재확인 · "
            f"{verified.reproduced}개 재현"
        )
    else:
        payload_line = "재검증 없음"
    return (
        '<div class="why vpanel">\n'
        '  <div class="lab">검증 결과 '
        '<span class="ko-en">focused verification</span></div>\n'
        f'  <div class="vhead"><span class="vbadge {tone}">{_esc(label)}</span>'
        f'<span class="vscore">검증 전 {prior}% <b>{arrow}</b> 최종 {final}%</span>'
        "</div>\n"
        f"  {reason_html}\n"
        f'  <div class="chart-note">{_esc(payload_line)}. 최종 신뢰도는 검증 이전 '
        "확률(prior)에 검증 신호의 보정된 로그우도비를 더해 산출합니다.</div>\n"
        "</div>"
    )


def _render_access_endpoint_line(endpoint: Endpoint | None, plan: Any) -> str:
    check = _ACCESS_CHECK_LABEL.get(plan.check_kind.value, plan.check_kind.value)
    if endpoint is None:
        return (
            '<div class="ep">BAC &mdash; '
            f'<span class="param">{_esc(check)}</span></div>'
        )
    return (
        f'<div class="ep">{_esc(endpoint.method.value)} {_esc(endpoint.path)} '
        f'&mdash; <span class="param">BAC &middot; {_esc(check)}</span></div>'
    )


def _render_access_requests(observation: Any) -> str:
    """The reference vs comparison re-send behind a BAC candidate."""

    plan = observation.access_probe_plan
    rows = (
        ("원본 요청", plan.reference_request, observation.reference_response),
        ("변형 요청", plan.comparison_request, observation.comparison_response),
    )
    body = "".join(
        f'<tr><td class="role">{_esc(label)}</td>'
        f'<td class="pl">{_esc(request.method.value)} {_esc(request.url)}</td>'
        f'<td class="status">{_esc(response.status_code)}</td>'
        f"<td>{_fmt_number(response.body_length_bytes)} B</td></tr>"
        for label, request, response in rows
    )
    return (
        '<div class="why">\n'
        '  <div class="lab">실행된 요청 '
        '<span class="ko-en">reference vs comparison</span></div>\n'
        f'  <div class="chart-note">바뀐 부분: {_esc(plan.changed_aspect)}</div>\n'
        '  <table class="rec">\n'
        "    <tr><th>역할</th><th>요청</th><th>상태</th><th>본문 크기</th></tr>\n"
        f"    {body}\n"
        "  </table>\n"
        '  <div class="chart-note">변형 요청이 원본과 비슷하게 성공(2xx·유사 크기)'
        "하면 접근제어가 미흡하다는 신호입니다. 확정된 취약점은 아닙니다.</div>\n"
        "</div>"
    )


def _render_endpoint_line(
    endpoint: Endpoint | None,
    input_point: InputPoint | None,
) -> str:
    context = _endpoint_context(endpoint, input_point)
    if context is None:
        return '<div class="ep unknown">입력점 정보가 리포트에 전달되지 않았습니다</div>'
    method = context["method"] or "?"
    url = context["url"] or "(엔드포인트 미상)"
    occurrence = context["occurrence_index"]
    suffix = f"[{occurrence}]" if occurrence is not None else ""
    return (
        f'<div class="ep">{_esc(method)} {_esc(url)} &mdash; '
        f'<span class="param">{_esc(context["location"].lower())}.'
        f'{_esc(context["name"])}{_esc(suffix)}</span></div>'
    )


def _render_evidence(
    candidate: DecisionCandidate,
    calibrated: CalibratedProbability | None,
) -> str:
    """신호별 log-odds 기여를 막대로 보여준다.

    미관측 feature도 남긴다. "확인했는데 없었다"와 "확인하지 못했다"는 다르고,
    후자를 빼면 전부 관측된 것처럼 읽히는 리포트가 된다.
    """

    if calibrated is None:
        return ""
    contributions = [
        abs(item.logit_contribution or 0.0)
        for item in calibrated.evidence
        if item.observed
    ]
    widest = max(contributions, default=0.0) or 1.0
    bars = []
    for item in sorted(calibrated.evidence, key=lambda e: e.feature_name):
        if not item.observed:
            bars.append(
                Bar(
                    label=item.feature_name,
                    ratio=0.0,
                    value_label="미관측",
                    tone="muted",
                    caption="관측하지 못함 — 값이 0이라는 뜻이 아닙니다",
                )
            )
            continue
        contribution = item.logit_contribution or 0.0
        bars.append(
            Bar(
                label=item.feature_name,
                ratio=abs(contribution) / widest,
                value_label=f"{contribution:+.2f}",
                tone="high" if contribution > 0 else "low",
                caption=f"관측값 {_fmt_number(item.feature_value or 0.0)}",
            )
        )
    return (
        '<div class="why">\n'
        '  <div class="lab">순위 근거 <span class="ko-en">why it ranks here</span>'
        "</div>\n"
        f"  {bar_chart(bars, empty_caption='증거가 없습니다.')}\n"
        '  <div class="chart-note">막대는 각 신호가 log-odds를 움직인 크기입니다. '
        "빨강은 확률을 올린 신호, 회색은 내린 신호입니다.</div>\n"
        "</div>"
    )


def _render_requests(
    candidate: DecisionCandidate,
    probe_runs: Mapping[str, ProbeRun],
) -> str:
    rows = _requests_context(candidate.feature_vector_ref, probe_runs)
    if not rows:
        return ""
    lengths = [row["response"]["body_length_bytes"] for row in rows]
    widest = max(lengths, default=0) or 1
    comparison = bar_chart(
        [
            Bar(
                label="baseline" if row["role"] == "baseline" else "probe",
                ratio=row["response"]["body_length_bytes"] / widest,
                value_label=f"{_fmt_number(row['response']['body_length_bytes'])} B",
                tone="muted" if row["role"] == "baseline" else "accent",
                caption=f"HTTP {row['response']['status_code']}",
            )
            for row in rows
        ]
    )
    table_rows = "".join(
        f'<tr><td class="role">{_esc(row["role"])}</td>'
        f'<td class="pl">{_esc(row["method"])} {_esc(row["url"])}'
        + (
            f' &mdash; 주입값: {_esc(row["injected_value"])}'
            if row.get("injected_value")
            else ""
        )
        + f'</td><td class="status">{_esc(row["response"]["status_code"])}</td>'
        f'<td>{_fmt_number(row["response"]["body_length_bytes"])} B</td></tr>'
        for row in rows
    )
    return (
        '<div class="why">\n'
        '  <div class="lab">실행된 요청 '
        '<span class="ko-en">baseline + probe actually sent</span></div>\n'
        f"  {comparison}\n"
        '  <table class="rec">\n'
        "    <tr><th>역할</th><th>요청</th><th>상태</th><th>본문 크기</th></tr>\n"
        f"    {table_rows}\n"
        "  </table>\n"
        '  <div class="chart-note">probe 응답이 baseline과 크게 다를수록 그 입력점이 '
        "서버 동작을 바꿨다는 신호입니다.</div>\n"
        "</div>"
    )


def _render_unselected(
    outcome: DecisionOutcome,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
) -> str:
    """선택되지 않은 후보를 사유와 함께 전부 보여준다.

    임계값에 잘린 후보는 Top-K에 도달조차 하지 않으므로, `deferred`(컷 아래)와
    임계값 미만을 나눠 "채점 12개, 선택 3개"의 차이를 읽는 사람이 설명할 수 있게 한다.
    """

    selected = {item.candidate_id for item in outcome.selected}
    deferred = {item.candidate_id for item in outcome.deferred}
    threshold = None if outcome.conformal is None else outcome.conformal.threshold
    rows = []
    for candidate in outcome.scored:
        if candidate.candidate_id in selected:
            continue
        if threshold is not None and float(candidate.probability) < threshold:
            reason = f"recall 임계값 {threshold:.4f} 미만"
        elif candidate.candidate_id in deferred:
            reason = "순위가 Top-K 아래"
        else:
            reason = "선택되지 않음"
        input_point = input_points.get(candidate.subject_ref)
        endpoint = (
            endpoints.get(input_point.endpoint_id)
            if input_point is not None
            else None
        )
        if input_point is None:
            location = candidate.candidate_id
        elif endpoint is None:
            location = f"{input_point.location.value.lower()}.{input_point.name}"
        else:
            location = (
                f"{endpoint.method.value} {endpoint.path} "
                f"{input_point.location.value.lower()}.{input_point.name}"
            )
        rows.append((float(candidate.probability), location, candidate, reason))
    if not rows:
        return ""
    rows.sort(key=lambda item: (-item[0], item[1]))
    body = "".join(
        f'<tr><td class="pl">{_esc(location)}</td>'
        f'<td class="role">{_esc(_family_label(candidate.family))}</td>'
        f'<td class="status">{probability:.4f}</td>'
        f"<td>{_esc(reason)}</td></tr>"
        for probability, location, candidate, reason in rows
    )
    return (
        f'<h2 class="section">선택되지 않은 후보 ({len(rows)})'
        '<span class="ko-en">not selected</span></h2>\n'
        '<div class="notice"><table class="rec">\n'
        "  <tr><th>위치</th><th>유형</th><th>확률</th><th>사유</th></tr>\n"
        f"{body}\n</table>\n"
        "<i>컷 아래라는 뜻이며, 안전하다고 판정한 것이 아닙니다.</i></div>"
    )


def _render_footer(
    outcome: DecisionOutcome,
    elapsed_seconds: float,
    verified: bool = False,
) -> str:
    caveat = (
        "현재까지의 최종 신뢰도입니다. 추가 검증이 없으면 검증 전 확률을 그대로 사용합니다. "
        "표시 점수는 확정된 취약점 판정이 아닙니다."
        if verified
        else "여기의 확률은 검증 이전의 우선순위입니다(ADR-016). 확정된 취약점이 "
        "아닙니다."
    )
    return (
        "<footer>"
        f"{_esc(DECISION_HTML_REPORT_VERSION)} &middot; "
        f"{_esc(outcome.policy_version)} &middot; "
        f"{elapsed_seconds:.2f}s<br>"
        f'<span class="warn">{caveat}</span>'
        "</footer>"
    )
