"""Per-input-point *explainability* HTML report for focused verification.

The dashboard report (``decision_html_report``) answers "which candidates moved
and by how much". This companion answers **why**, one input point at a time:

    baseline 요청은 이렇고 (GET http://host/path?param=value),
    변형 페이로드로 이런 요청들을 만들어 재프로브했으며,
    각 변형의 결과(feature delta / 판정)가 이렇기 때문에,
    confidence 는 prior -> final (delta) 로 갱신되었다.

It consumes only serialisable report dicts -- the verification report
(``VerificationRun.to_dict``) and, optionally, a crawl report
(``reporting.crawl_report.render_crawl_report``) -- so it never re-derives a
score or reaches into a domain object. Input-point ids are stable fingerprints,
so the crawl report may come from any run against the same target; with it,
every baseline / mutated value is rendered as the full request URL rather than a
bare ``item`` / ``en``.

Payload strings are attacker-shaped (they carry ``<``, ``>``, quotes); every one
is HTML-escaped before it reaches the page, so the report can display a raw XSS
probe without the probe affecting the report.
"""

from __future__ import annotations

import datetime as _dt
import html
from collections.abc import Mapping
from typing import Any

# Outcome -> (badge label, css class). The css classes are styled in _CSS.
_OUTCOME_STYLE: dict[str, tuple[str, str]] = {
    "SUPPORTED": ("SUPPORTED", "ok"),
    "WEAKENED": ("WEAKENED", "warn"),
    "INCONCLUSIVE_ERROR": ("INCONCLUSIVE", "muted"),
    "UNCHANGED": ("UNCHANGED", "muted"),
    "NOT_EXECUTED": ("NOT EXECUTED", "muted"),
    "REJECTED": ("REJECTED", "bad"),
}


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _fmt_prob(value: Any) -> str:
    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return "—"


def _fmt_delta(value: Any) -> str:
    try:
        return f"{float(value):+.3f}"
    except (TypeError, ValueError):
        return "±0.000"


# --- crawl join: input_point_id -> request context --------------------------


def _iter_lists(report: Any, key: str) -> Any:
    if isinstance(report, dict):
        value = report.get(key)
        if isinstance(value, list):
            yield value
        for nested in report.values():
            yield from _iter_lists(nested, key)
    elif isinstance(report, list):
        for item in report:
            yield from _iter_lists(item, key)


def crawl_index_from_report(
    crawl_report: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Map ``input_point_id -> {method, base_url, name, location, baseline_value}``.

    Accepts the dict produced by ``render_crawl_report``. Returns an empty index
    for ``None`` (the report then falls back to the bare parameter value).
    """

    if crawl_report is None:
        return {}
    endpoints: dict[str, dict[str, Any]] = {}
    for group in _iter_lists(crawl_report, "endpoints"):
        for endpoint in group:
            if isinstance(endpoint, dict) and endpoint.get("id"):
                endpoints[endpoint["id"]] = endpoint
    index: dict[str, dict[str, Any]] = {}
    for group in _iter_lists(crawl_report, "input_points"):
        for point in group:
            if not isinstance(point, dict) or not point.get("id"):
                continue
            endpoint = endpoints.get(point.get("endpoint_id"), {})
            scheme = endpoint.get("scheme", "http")
            host = endpoint.get("host", "")
            path = endpoint.get("path", "/")
            index[point["id"]] = {
                "method": endpoint.get("method", "GET"),
                "base_url": f"{scheme}://{host}{path}",
                "name": point.get("name"),
                "location": point.get("location", "QUERY"),
                "baseline_value": point.get("baseline_value"),
            }
    return index


def _request_html(ctx: dict[str, Any] | None, value: Any) -> str:
    """Render one request as ``METHOD scheme://host/path?name=value`` with the
    injected parameter highlighted. Falls back to the bare value if no context."""

    if ctx is None:
        return f"<code class='reqval'>{_esc(value)}</code>"
    method = _esc(ctx.get("method", "GET"))
    base = _esc(ctx.get("base_url", ""))
    name = _esc(ctx.get("name", ""))
    inj = f"<mark class='inj'>{name}={_esc(value)}</mark>"
    if ctx.get("location") == "QUERY":
        return (
            f"<span class='req'><span class='m'>{method}</span> "
            f"<span class='u'>{base}?{inj}</span></span>"
        )
    return (
        f"<span class='req'><span class='m'>{method}</span> "
        f"<span class='u'>{base}</span> "
        f"<span class='bodytag'>body</span> {inj}</span>"
    )


def _resolve_baseline_value(
    candidate: dict[str, Any], ctx: dict[str, Any] | None
) -> Any:
    if ctx is not None and ctx.get("baseline_value") is not None:
        return ctx["baseline_value"]
    for result in candidate["results"]:
        if result.get("based_on_value") is not None:
            return result["based_on_value"]
    for result in candidate["results"]:
        reasons = result.get("validator", {}).get("rejection_reasons", [])
        if "UNCHANGED_FROM_BASELINE" in reasons:
            return result.get("mutated_value")
    return None


def _validator_cell(result: dict[str, Any]) -> str:
    validator = result.get("validator", {})
    if validator.get("decision") == "ACCEPTED":
        return '<span class="pill ok">통과</span>'
    reasons = ", ".join(validator.get("rejection_reasons", []))
    return (
        '<span class="pill bad">차단</span> '
        f'<span class="reason">{_esc(reasons)}</span>'
    )


def _evidence_html(result: dict[str, Any]) -> str:
    confidence = result.get("confidence", {})
    delta = result.get("feature_delta") or {}
    flips = delta.get("observability_flips", [])
    rows: list[str] = []
    for item in confidence.get("evidence", []):
        rows.append(
            "<li><code>{name}</code>: {base} → {ver} "
            "<span class='dir'>({dir})</span> — {reason}</li>".format(
                name=_esc(item.get("feature_name")),
                base=_esc(item.get("baseline_value")),
                ver=_esc(item.get("verification_value")),
                dir=_esc(item.get("direction")),
                reason=_esc(item.get("reason")),
            )
        )
    parts: list[str] = []
    if rows:
        parts.append("<ul class='evidence'>" + "".join(rows) + "</ul>")
    if flips:
        parts.append(
            "<div class='flips'>관측 전환(observability flips): "
            + ", ".join(f"<code>{_esc(f)}</code>" for f in flips)
            + "</div>"
        )
    if not parts:
        parts.append("<div class='flips muted-text'>추가 feature 변화 없음</div>")
    return "".join(parts)


def _payload_row(
    index: int, result: dict[str, Any], ctx: dict[str, Any] | None
) -> str:
    outcome = result.get("outcome_status", "")
    label, css = _OUTCOME_STYLE.get(outcome, (outcome, "muted"))
    conf = result.get("confidence", {})
    return f"""
      <tr class="payload-row">
        <td class="idx">{index}</td>
        <td class="pv">{_request_html(ctx, result.get('mutated_value'))}</td>
        <td class="fam">{_esc(result.get('mutation_family'))}</td>
        <td>{_validator_cell(result)}</td>
        <td><span class="pill {css}">{_esc(label)}</span>\
<div class="sig">{_esc(conf.get('signal'))}</div></td>
        <td class="num">{_fmt_delta(conf.get('confidence_delta'))}</td>
      </tr>
      <tr class="detail-row"><td></td><td colspan="5">
        <div class="rationale"><span class="tag">모델 근거</span> \
{_esc(result.get('rationale'))}</div>
        {_evidence_html(result)}
      </td></tr>"""


def _narrative(candidate: dict[str, Any], ctx: dict[str, Any] | None) -> str:
    results = candidate["results"]
    n = len(results)
    accepted = sum(
        r.get("validator", {}).get("decision") == "ACCEPTED" for r in results
    )
    executed = sum(r.get("execution") is not None for r in results)
    baseline = _resolve_baseline_value(candidate, ctx)
    prior = _fmt_prob(candidate.get("prior_probability"))
    final = _fmt_prob(candidate.get("final_confidence"))
    delta = _fmt_delta(candidate.get("confidence_delta"))
    param = _esc(ctx.get("name")) if ctx else "파라미터"
    return (
        f"<p class='narrative'>baseline 요청 {_request_html(ctx, baseline)} 의 "
        f"<code>{param}</code> 파라미터를 변형 페이로드 <b>{n}</b>개로 치환해 "
        f"재프로브했습니다. 검증기가 <b>{accepted}</b>개 통과·"
        f"<b>{n - accepted}</b>개 차단했고, 실행된 <b>{executed}</b>개의 결과가 "
        f"<b>{_esc(candidate.get('final_outcome'))}</b> "
        f"(신호 <code>{_esc(candidate.get('final_signal'))}</code>)로 판정되어, "
        f"confidence 는 <b>{prior}</b> → <b>{final}</b> "
        f"(<span class='delta'>{delta}</span>) 로 갱신되었습니다.</p>"
    )


def _candidate_card(
    candidate: dict[str, Any], index: dict[str, dict[str, Any]]
) -> str:
    ctx = index.get(candidate.get("input_point_id"))
    vtype = candidate.get("vulnerability_type", "")
    outcome = candidate.get("final_outcome", "")
    label, css = _OUTCOME_STYLE.get(outcome, (outcome, "muted"))
    baseline = _resolve_baseline_value(candidate, ctx)
    prior = candidate.get("prior_probability") or 0.0
    final = candidate.get("final_confidence") or 0.0
    rows = "".join(
        _payload_row(i + 1, r, ctx) for i, r in enumerate(candidate["results"])
    )
    try:
        prior_pct = max(0.0, min(1.0, float(prior))) * 100
        final_pct = max(0.0, min(1.0, float(final))) * 100
    except (TypeError, ValueError):
        prior_pct = final_pct = 0.0
    return f"""
    <section class="card">
      <div class="card-head">
        <span class="rank">#{_esc(candidate.get('selection_rank'))}</span>
        <span class="vtype {('sqli' if vtype == 'SQLI' else 'xss')}">\
{_esc(vtype)}</span>
        <span class="pill {css} outcome-badge">{_esc(label)}</span>
      </div>
      <div class="baseline-box">
        <span class="blabel">baseline 요청</span>
        {_request_html(ctx, baseline)}
      </div>
      {_narrative(candidate, ctx)}
      <div class="confbar" title="prior → final">
        <div class="bar"><div class="fill prior" \
style="width:{prior_pct:.1f}%"></div></div>
        <div class="bar"><div class="fill final" \
style="width:{final_pct:.1f}%"></div></div>
        <div class="conflabels"><span>prior {_fmt_prob(prior)}</span>\
<span>final {_fmt_prob(final)}</span></div>
      </div>
      <table class="payloads">
        <thead><tr>
          <th>#</th><th>변형 요청 (mutated request)</th><th>family</th>
          <th>검증기</th><th>결과 / 신호</th><th>Δconf</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--muted:#6b7280;--line:#e5e7eb;
--ok:#0e9f6e;--bad:#e02424;--warn:#c27803;--accent:#2563eb;--code:#f3f4f6;\
--inj:#fde68a;--injink:#92400e;}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;\
--ink:#e6e9ee;--muted:#9aa4b2;--line:#262b33;--ok:#31c48d;--bad:#f98080;\
--warn:#e3a008;--accent:#60a5fa;--code:#1f242c;--inj:#78500a;--injink:#fde68a;}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,\
"Malgun Gothic",sans-serif;}
.wrap{max-width:1120px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 18px;\
font-size:13px}
.summary{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;\
padding:10px 14px;min-width:96px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;\
padding:18px 20px;margin:0 0 18px}
.card-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;\
margin-bottom:10px}
.rank{font-weight:700;color:var(--muted)}
.vtype{font-weight:700;font-size:12px;padding:2px 8px;border-radius:6px;\
color:#fff}
.vtype.sqli{background:#7c3aed}.vtype.xss{background:#0ea5e9}
.outcome-badge{margin-left:auto}
.baseline-box{background:var(--code);border:1px solid var(--line);\
border-radius:8px;padding:8px 12px;margin-bottom:10px;overflow-x:auto}
.blabel{display:inline-block;font-size:11px;font-weight:700;color:var(--muted);\
margin-right:8px;text-transform:uppercase}
.req{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;\
white-space:nowrap}
.req .m{color:#fff;background:var(--accent);border-radius:4px;padding:1px 6px;\
font-weight:700;font-size:11px}
.req .u{color:var(--ink);word-break:break-all}
.req .bodytag{color:var(--muted);font-size:11px;border:1px solid var(--line);\
border-radius:4px;padding:0 4px}
mark.inj{background:var(--inj);color:var(--injink);border-radius:4px;\
padding:0 3px;font-weight:700}
.reqval{background:var(--code);padding:2px 6px;border-radius:5px;\
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.narrative{margin:8px 0 12px}.delta{font-weight:700}
.confbar{margin:0 0 14px}.bar{height:8px;background:var(--code);\
border-radius:5px;overflow:hidden;margin:3px 0}
.fill{height:100%}.fill.prior{background:var(--muted)}\
.fill.final{background:var(--accent)}
.conflabels{display:flex;justify-content:space-between;color:var(--muted);\
font-size:11px}
table.payloads{width:100%;border-collapse:collapse;font-size:13px;margin-top:4px}
table.payloads th{text-align:left;color:var(--muted);font-weight:600;\
border-bottom:1px solid var(--line);padding:6px 8px}
table.payloads td{padding:7px 8px;vertical-align:top;\
border-bottom:1px solid var(--line)}
.payload-row td{border-bottom:none}.idx{color:var(--muted)}\
.num{text-align:right;font-variant-numeric:tabular-nums}
.pv{max-width:560px;overflow-x:auto}
.fam{color:var(--muted);font-size:12px}.sig{color:var(--muted);font-size:11px;\
margin-top:2px}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;\
border-radius:999px;color:#fff;white-space:nowrap}
.pill.ok{background:var(--ok)}.pill.bad{background:var(--bad)}\
.pill.warn{background:var(--warn)}
.pill.muted{background:var(--muted)}.reason{color:var(--bad);font-size:11px}
.detail-row td{padding-top:0;padding-bottom:12px}
.rationale{font-size:12px;color:var(--muted);margin:2px 0 6px}
.rationale .tag{display:inline-block;background:var(--code);color:var(--ink);\
border-radius:5px;padding:1px 6px;margin-right:6px;font-weight:600}
ul.evidence{margin:4px 0;padding-left:18px;font-size:12px;color:var(--muted)}
ul.evidence code{background:var(--code);padding:1px 4px;border-radius:4px}
.dir{color:var(--accent)}.flips{font-size:12px;color:var(--muted);margin-top:4px}
.flips code{background:var(--code);padding:1px 5px;border-radius:4px}
.muted-text{color:var(--muted)}
footer{color:var(--muted);font-size:12px;margin-top:24px;text-align:center}
"""


def build_verification_detail_html(
    verify_report: Mapping[str, Any],
    crawl_report: Mapping[str, Any] | None = None,
    *,
    source: str = "verification report",
) -> str:
    """Render the per-input-point detail report as a self-contained HTML string."""

    index = crawl_index_from_report(crawl_report)
    counts = verify_report.get("counts", {})
    candidates = verify_report.get("candidates", [])
    providers = sorted(
        {r.get("provider") for c in candidates for r in c.get("results", [])}
    )
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats = [
        ("검증 후보", counts.get("candidates_verified", len(candidates))),
        ("변형 페이로드", counts.get("proposals", "—")),
        ("검증기 통과", counts.get("accepted", "—")),
        ("검증기 차단", counts.get("rejected", "—")),
        ("SUPPORTED", counts.get("supported", "—")),
        ("WEAKENED", counts.get("weakened", "—")),
    ]
    stat_html = "".join(
        f"<div class='stat'><b>{_esc(v)}</b><span>{_esc(k)}</span></div>"
        for k, v in stats
    )
    cards = "".join(_candidate_card(c, index) for c in candidates)
    join_note = (
        "요청 URL은 크롤 결과와 조인해 구성"
        if index
        else "crawl 리포트 미제공 — 파라미터 원본값만 표시"
    )
    provider_label = _esc(", ".join(p for p in providers if p) or "—")
    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnSpider 검증 상세 리포트</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>VulnSpider · 변형 페이로드 검증 상세 리포트</h1>
<p class="sub">target <b>{_esc(verify_report.get('target'))}</b> · \
provider {provider_label} · 생성 {generated} · source <code>{_esc(source)}</code> \
· {join_note}</p>
<div class="summary">{stat_html}</div>
{cards}
<footer>각 변형 페이로드는 전송 전에 결정적 PayloadValidator를 통과했으며, \
재프로브는 loopback 대상에 한정됩니다. 변형 요청 값은 모델이 생성한 원문 그대로\
(HTML 문자만 이스케이프) 표시됩니다.</footer>
</div></body></html>"""
