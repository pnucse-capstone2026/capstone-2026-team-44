"""Static HTML dashboard reporting for deterministic v0.1 Top-K outcomes.

Renders the same validated `SelectionOutcome` the JSON reporter renders
(`vulnspider.reporting.json_report`), plus optional display-only joins to the
`InputPoint`/`Endpoint` objects the adapter already produced and the
`ProbePlan`/`ResponseSnapshot` pair `execute_probe_plan()` already produced
for each `FeatureVector`. No score is recomputed and no evidence is
invented here (ADR-011, docs/PROTOTYPE_V0_1.md §13).
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

from vulnspider.domain import (
    Endpoint,
    InputPoint,
    ProbePlan,
    RequestInstance,
    ResponseSnapshot,
    ScoreEvidence,
    VulnerabilityType,
)
from vulnspider.reporting.json_report import ReportingError
from vulnspider.scoring import ScoringResult
from vulnspider.selection import RankedScoringResult, SelectionError, SelectionOutcome

HTML_REPORT_SCHEMA_VERSION = "0.1"

PRIORITY_BAND_HIGH = 0.7
PRIORITY_BAND_MEDIUM = 0.4

VULNERABILITY_LABELS: Mapping[VulnerabilityType, str] = MappingProxyType(
    {
        VulnerabilityType.SQLI: "SQL Injection",
        VulnerabilityType.REFLECTED_XSS: "Reflected XSS",
    }
)

VULNERABILITY_SHORT_TAGS: Mapping[str, str] = MappingProxyType(
    {
        VulnerabilityType.SQLI.value: "sqli",
        VulnerabilityType.REFLECTED_XSS.value: "xss",
    }
)

GENERAL_GUIDANCE: Mapping[VulnerabilityType, str] = MappingProxyType(
    {
        VulnerabilityType.SQLI: (
            "Use parameterized queries or prepared statements instead of "
            "building SQL from string concatenation, and run the database "
            "account with least privilege."
        ),
        VulnerabilityType.REFLECTED_XSS: (
            "Apply context-aware output encoding to any reflected input, "
            "add a strict Content-Security-Policy, and validate input where "
            "possible."
        ),
    }
)

ProbeRun = tuple[ProbePlan, ResponseSnapshot, ResponseSnapshot]

_EMPTY_INPUT_POINTS: Mapping[str, InputPoint] = MappingProxyType({})
_EMPTY_ENDPOINTS: Mapping[str, Endpoint] = MappingProxyType({})
_EMPTY_PROBE_RUNS: Mapping[str, ProbeRun] = MappingProxyType({})


def build_html_report_context(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    requests_executed: int | None = None,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> dict[str, Any]:
    """Build a plain-data rendering context from an already-validated outcome.

    This performs no scoring, ranking, or feature-extraction work; it only
    joins the outcome to optional display data the caller already produced
    elsewhere in the pipeline.
    """

    if not isinstance(outcome, SelectionOutcome):
        raise ReportingError("outcome must be a SelectionOutcome")
    try:
        outcome.validate()
    except SelectionError as exc:
        raise ReportingError("selection outcome is internally inconsistent") from exc

    summary = outcome.summary
    band_counts = {"high": 0, "medium": 0, "low": 0}
    candidates: list[dict[str, Any]] = []
    for rank, item in enumerate(outcome.selected, start=1):
        candidate_context = _candidate_context(
            item,
            rank=rank,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
        )
        band_counts[candidate_context["priority_band"]] += 1
        candidates.append(candidate_context)

    return {
        "schema_version": HTML_REPORT_SCHEMA_VERSION,
        "target": str(target),
        "summary": {
            "endpoints": len(endpoints),
            "input_points": len(input_points),
            "total_scoring_results": summary.total_scoring_results,
            "rankable_results": summary.rankable_results,
            "unrankable_results": summary.unrankable_results,
            "selected_results": summary.selected_results,
            "top_k_requested": summary.top_k_requested,
            "requests_executed": (
                2 * len(probe_runs)
                if requests_executed is None
                else int(requests_executed)
            ),
            "elapsed_seconds": float(elapsed_seconds),
        },
        "priority_bands": band_counts,
        "warnings": sorted(dict.fromkeys(str(item) for item in warnings)),
        "candidates": candidates,
        "unrankable": [
            _unrankable_context(result) for result in outcome.unrankable
        ],
    }


def render_html_report(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    requests_executed: int | None = None,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> str:
    context = build_html_report_context(
        outcome,
        warnings=warnings,
        input_points=input_points,
        endpoints=endpoints,
        probe_runs=probe_runs,
        requests_executed=requests_executed,
        target=target,
        elapsed_seconds=elapsed_seconds,
    )
    return _render_document(context)


def write_html_report(
    outcome: SelectionOutcome,
    destination: str | Path,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    requests_executed: int | None = None,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> None:
    Path(destination).write_text(
        render_html_report(
            outcome,
            warnings=warnings,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            requests_executed=requests_executed,
            target=target,
            elapsed_seconds=elapsed_seconds,
        ),
        encoding="utf-8",
    )


def _priority_band(priority: float) -> str:
    if priority >= PRIORITY_BAND_HIGH:
        return "high"
    if priority >= PRIORITY_BAND_MEDIUM:
        return "medium"
    return "low"


def _candidate_context(
    item: RankedScoringResult,
    *,
    rank: int,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probe_runs: Mapping[str, ProbeRun],
) -> dict[str, Any]:
    result = item.scoring_result
    candidate = result.candidate
    vulnerability_type = candidate.vulnerability_type
    input_point = input_points.get(candidate.input_point_id)
    endpoint = (
        endpoints.get(input_point.endpoint_id) if input_point is not None else None
    )
    return {
        "rank": rank,
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "vulnerability_type": vulnerability_type.value,
        "vulnerability_label": VULNERABILITY_LABELS.get(
            vulnerability_type, vulnerability_type.value
        ),
        "scorer_version": candidate.scorer_version,
        "raw_rank_score": item.raw_rank_score,
        "raw_rank_score_max": item.raw_rank_score_max,
        "selection_priority": item.selection_priority,
        "priority_band": _priority_band(item.selection_priority),
        "endpoint": _endpoint_context(endpoint, input_point),
        "evidence": [
            _evidence_context(evidence)
            for evidence in sorted(
                result.evidence, key=lambda evidence: evidence.feature_name
            )
        ],
        "requests": _requests_context(result.feature_vector_id, probe_runs),
        "general_guidance": GENERAL_GUIDANCE.get(vulnerability_type),
    }


def _endpoint_context(
    endpoint: Endpoint | None,
    input_point: InputPoint | None,
) -> dict[str, Any] | None:
    if input_point is None:
        return None
    return {
        "method": endpoint.method.value if endpoint is not None else None,
        "url": (
            f"{endpoint.scheme}://{endpoint.host}{endpoint.path}"
            if endpoint is not None
            else None
        ),
        "location": input_point.location.value,
        "name": input_point.name,
        "occurrence_index": input_point.occurrence_index,
    }


def _evidence_context(evidence: ScoreEvidence) -> dict[str, Any]:
    signal_on = (
        evidence.observed
        and evidence.feature_value is not None
        and evidence.feature_value > 0.0
    )
    return {
        "vulnerability_type": (
            evidence.vulnerability_type.value
            if evidence.vulnerability_type is not None
            else None
        ),
        "feature_name": evidence.feature_name,
        "feature_value": evidence.feature_value,
        "observed": evidence.observed,
        "weight": evidence.weight,
        "contribution": evidence.contribution,
        "reason": evidence.reason,
        "signal_on": signal_on,
    }


def _requests_context(
    feature_vector_id: str,
    probe_runs: Mapping[str, ProbeRun],
) -> list[dict[str, Any]]:
    run = probe_runs.get(feature_vector_id)
    if run is None:
        return []
    probe_plan, baseline_response, probe_response = run
    return [
        {
            "role": "baseline",
            **_request_context(probe_plan.baseline_request),
            "injected_value": None,
            "response": _response_context(baseline_response),
        },
        {
            "role": "probe",
            **_request_context(probe_plan.probe_request),
            "injected_value": probe_plan.probe_marker,
            "changed_field": (
                probe_plan.changed_fields[0] if probe_plan.changed_fields else None
            ),
            "response": _response_context(probe_response),
        },
    ]


def _request_context(request: RequestInstance) -> dict[str, Any]:
    return {
        "method": request.method.value,
        "url": request.url,
        "form": [{"name": name, "value": value} for name, value in request.form],
    }


def _response_context(response: ResponseSnapshot) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "elapsed_ms": response.elapsed_ms,
        "body_length_bytes": response.body_length_bytes,
        "execution_error": response.execution_error,
    }


def _unrankable_context(result: ScoringResult) -> dict[str, Any]:
    candidate = result.candidate
    return {
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "vulnerability_type": candidate.vulnerability_type.value,
        "reasons": sorted(
            dict.fromkeys(
                evidence.reason
                for evidence in result.evidence
                if not evidence.observed
            )
        ),
    }


# ---------------------------------------------------------------------------
# Rendering: everything below turns a plain-data context into an HTML string.
# All interpolated text is escaped; the context above may hold text observed
# from a scanned target (endpoint paths, evidence reasons, warnings), which
# is untrusted.
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _fmt_number(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _fmt_percent(priority: float) -> str:
    return f"{priority * 100:.1f}".rstrip("0").rstrip(".")


def _render_document(context: Mapping[str, Any]) -> str:
    target = context["target"]
    title = "VulnSpider report" + (f" — {target}" if target else "")
    sections = [
        _render_header(context),
        _render_stats(context["summary"]),
        _render_band_bar(context["priority_bands"]),
        _render_warnings(context["warnings"]),
        '<h2 class="section">Ranked candidates</h2>',
        _render_candidates(context["candidates"]),
        _render_unrankable(context["unrankable"]),
        _render_footer(),
    ]
    body = "\n\n".join(section for section in sections if section)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{_DOCUMENT_STYLE}</style>\n"
        f'</head>\n<body>\n<div class="wrap">\n\n{body}\n\n</div>\n</body>\n</html>\n'
    )


def _render_header(context: Mapping[str, Any]) -> str:
    target = context["target"]
    schema_version = context["schema_version"]
    target_line = (
        f'<div class="target">target &rarr; {_esc(target)}</div>' if target else ""
    )
    version_line = f"v0.1 &middot; scan report (schema {_esc(schema_version)})"
    return (
        '<header class="masthead">\n'
        '  <div class="brand">\n'
        "    <h1>VulnSpider</h1>"
        f'<span class="ver">{version_line}</span>\n'
        "  </div>\n"
        '  <div class="tagline">Prioritized SQLi / Reflected XSS candidates '
        "with the evidence and requests behind each rank. RankScore is a "
        "verification-priority signal, not a vulnerability verdict.</div>\n"
        f"  {target_line}\n"
        "</header>"
    )


def _render_stats(summary: Mapping[str, Any]) -> str:
    stats = (
        (str(summary["endpoints"]), "Endpoints"),
        (str(summary["input_points"]), "Input points"),
        (str(summary["selected_results"]), "Selected (Top-K)"),
        (str(summary["requests_executed"]), "Requests executed"),
        (f"{summary['elapsed_seconds']:.1f}s", "Elapsed"),
    )
    cells = "".join(
        f'<div class="stat"><div class="n">{_esc(value)}</div>'
        f'<div class="l">{_esc(label)}</div></div>'
        for value, label in stats
    )
    return f'<div class="stats">{cells}</div>'


def _render_band_bar(bands: Mapping[str, int]) -> str:
    pills = "".join(
        f'<span class="pill"><span class="dot {band}"></span>'
        f"{_esc(bands[band])} {band} priority</span>"
        for band in ("high", "medium", "low")
    )
    return f'<div class="bandbar">{pills}</div>'


_WARNINGS_DISPLAY_LIMIT = 8


def _render_warnings(warnings: Sequence[str]) -> str:
    """Collapse identical warnings and cap the list.

    Discovery emits one warning per occurrence, so a normal crawl produces the
    same message many times over (a duplicate URL, an unbound control). Printing
    each one buries the report under repetition, so identical messages are
    folded into ``message (xN)`` in first-seen order and the distinct list is
    capped, with an overflow line for the remainder.
    """

    if not warnings:
        return ""
    counts: dict[str, int] = {}
    for warning in warnings:
        message = str(warning)
        counts[message] = counts.get(message, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    shown = ordered[:_WARNINGS_DISPLAY_LIMIT]
    items = "".join(
        f"<li>{_esc(message)}{'' if count == 1 else f' (&times;{count})'}</li>"
        for message, count in shown
    )
    hidden = len(ordered) - len(shown)
    if hidden > 0:
        items += f'<li class="muted">… and {hidden} more distinct warning(s)</li>'
    return (
        '<details>'
        '<summary class="lab" style="cursor: pointer; outline: none;">Warnings (클릭해서 접기/펴기)</summary>'
        '<div class="notice">'
        f'<div class="lab">Warnings ({len(ordered)} distinct, '
        f"{sum(counts.values())} total)</div>"
        f"<ul>{items}</ul></div>"
        '</details>'
    )


def _render_candidates(candidates: Sequence[Mapping[str, Any]]) -> str:
    if not candidates:
        return '<div class="empty">No rankable candidates were selected.</div>'
    return "\n".join(_render_candidate(candidate) for candidate in candidates)


def _render_candidate(candidate: Mapping[str, Any]) -> str:
    band = candidate["priority_band"]
    rank = candidate["rank"]
    vulnerability_label = _esc(candidate["vulnerability_label"])
    percent = _fmt_percent(candidate["selection_priority"])
    raw_score = _fmt_number(candidate["raw_rank_score"])
    raw_score_max = _fmt_number(candidate["raw_rank_score_max"])
    candidate_id = _esc(candidate["candidate_id"])
    feature_vector_id = _esc(candidate["feature_vector_id"])
    endpoint_line = _render_endpoint_line(candidate["endpoint"])
    # The decision-layer report reuses this renderer but scores candidates as
    # probabilities, where "raw N / max M" would be meaningless. It supplies
    # its own caption; the v0.1 report supplies none and keeps the old line.
    caption = candidate.get("caption") or (
        f"priority &middot; raw {raw_score} / max {raw_score_max}"
    )
    evidence_html = "".join(
        _render_evidence_item(item) for item in candidate["evidence"]
    )
    requests_html = _render_requests_table(candidate["requests"])
    guidance = candidate["general_guidance"]
    guidance_html = (
        f'<div class="fix"><b>General guidance</b><br>{_esc(guidance)}'
        "<br><i>General practice for this vulnerability type — not a "
        "statement that this specific candidate is exploitable.</i></div>"
        if guidance
        else ""
    )
    ids_line = (
        f'<div class="ids">candidate {candidate_id} '
        f"&middot; feature vector {feature_vector_id}</div>"
    )
    return f"""<article class="finding {band}">
    <div class="fhead">
      <div>
        <div class="rank">#{rank}</div>
        <div class="vtype">{vulnerability_label}</div>
        {endpoint_line}
      </div>
      <div class="meterwrap">
        <div class="prio {band}">{percent}%</div>
        <div class="meter"><i class="{band}" style="width:{percent}%"></i></div>
        <div class="pcaption">{caption}</div>
      </div>
    </div>

    <div class="why">
      <div class="lab">Why it ranks here</div>
      <ul class="ev">{evidence_html}</ul>
    </div>

    {requests_html}

    {guidance_html}
    {ids_line}
  </article>"""


def _render_endpoint_line(endpoint: Mapping[str, Any] | None) -> str:
    if endpoint is None:
        return '<div class="ep unknown">endpoint not supplied to report builder</div>'
    method = endpoint["method"] or "?"
    url = endpoint["url"] or "(unknown endpoint)"
    location = endpoint["location"].lower()
    name = endpoint["name"]
    occurrence = endpoint["occurrence_index"]
    occurrence_label = f"[{occurrence}]" if occurrence is not None else ""
    return (
        f'<div class="ep">{_esc(method)} {_esc(url)}'
        f' &mdash; <span class="param">{_esc(location)}.{_esc(name)}'
        f"{_esc(occurrence_label)}</span></div>"
    )


def _render_evidence_item(evidence: Mapping[str, Any]) -> str:
    raw_type = evidence["vulnerability_type"] or ""
    vuln = _esc(VULNERABILITY_SHORT_TAGS.get(raw_type, raw_type.lower()))
    name = _esc(evidence["feature_name"])
    weight = _fmt_number(evidence["weight"])
    dot_class = (
        "on" if evidence["signal_on"] else ("off" if evidence["observed"] else "na")
    )
    dot = f'<span class="sig {dot_class}"></span>'
    if evidence["observed"]:
        value = _fmt_number(evidence["feature_value"])
        contribution = _fmt_number(evidence["contribution"])
        detail = f"{name}={value} x +{weight} &rarr; +{contribution}"
    else:
        detail = f"{name}: not observed &mdash; {_esc(evidence['reason'])} (weight +{weight})"
    return f'<li>{dot}[{vuln}] {detail}</li>'


def _render_requests_table(requests: Sequence[Mapping[str, Any]]) -> str:
    if not requests:
        return (
            '<div class="notice small">No executed-request detail was supplied '
            "to the report builder for this candidate.</div>"
        )
    rows = "".join(_render_request_row(request) for request in requests)
    return f"""<div class="why">
      <div class="lab">Executed requests (baseline + probe actually sent)</div>
      <table class="rec">
        <thead><tr><th>Role</th><th>Request</th><th>Status</th><th>Body length</th><th>Elapsed</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


def _render_request_row(request: Mapping[str, Any]) -> str:
    role = request["role"]
    method = request["method"]
    url = request["url"]
    form = request["form"]
    injected = request.get("injected_value")
    response = request["response"]
    request_text = f"{method} {url}"
    if form:
        pairs = "&".join(f"{item['name']}={item['value']}" for item in form)
        request_text += f" (form: {pairs})"
    if injected:
        request_text += f" — injected: {injected}"
    status = response["execution_error"] or str(response["status_code"])
    elapsed_text = f"{response['elapsed_ms']:.1f} ms"
    return (
        "<tr>"
        f'<td class="role">{_esc(role)}</td>'
        f'<td class="pl">{_esc(request_text)}</td>'
        f'<td class="status">{_esc(status)}</td>'
        f"<td>{_esc(response['body_length_bytes'])} B</td>"
        f"<td>{_esc(elapsed_text)}</td>"
        "</tr>"
    )


def _render_unrankable(unrankable: Sequence[Mapping[str, Any]]) -> str:
    if not unrankable:
        return ""
    items = "".join(
        f"<li>{_esc(item['vulnerability_type'])} &middot; "
        f"input point {_esc(item['input_point_id'])}: "
        f"{_esc('; '.join(item['reasons']) or 'no observed scoring term')}</li>"
        for item in unrankable
    )
    return (
        '<div class="notice">'
        '<div class="lab">Unrankable (no observed scoring term — excluded, not "safe")</div>'
        f"<ul>{items}</ul></div>"
    )


def _render_footer() -> str:
    return (
        "<footer>"
        '<span class="warn">Authorized testing only.</span> '
        "VulnSpider prioritizes candidates for review; a high priority score "
        "is a strong lead, not a verified exploit. Only the one baseline "
        "and one probe request v0.1 actually sent per input point are "
        "shown above — no additional verification payloads were sent. "
        "Generated by VulnSpider v0.1."
        "</footer>"
    )


_DOCUMENT_STYLE = """
  :root{
    --paper:#f6f7f9; --card:#ffffff; --ink:#12161d; --muted:#5b6472;
    --line:#e3e7ee; --accent:#2f4b7c;
    --low:#7c8798; --medium:#c08a2d; --high:#c0463b;
    --sqli:#2f6f8f; --xss:#7a5aa8; --bac:#2f7d5f; --track:#eef1f6;
    --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
       line-height:1.5;-webkit-font-smoothing:antialiased}
  .wrap{max-width:900px;margin:0 auto;padding:40px 24px 80px}
  header.masthead{border-bottom:2px solid var(--ink);padding-bottom:18px;margin-bottom:8px}
  .brand{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .brand h1{font-size:26px;margin:0;letter-spacing:-.02em}
  .tagline{color:var(--muted);font-size:14px;margin-top:4px}
  .target{font-family:var(--mono);font-size:13px;margin-top:14px;
          word-break:break-all;color:var(--accent)}
  .stats{display:flex;flex-wrap:wrap;gap:0;border:1px solid var(--line);
         border-radius:8px;background:var(--card);margin:22px 0 8px;overflow:hidden}
  .stat{flex:1 1 120px;padding:14px 16px;border-right:1px solid var(--line)}
  .stat:last-child{border-right:0}
  .stat .n{font-family:var(--mono);font-size:22px;font-weight:600}
  .stat .l{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-top:2px}
  .bandbar{display:flex;gap:8px;margin:20px 0 30px;font-size:13px;flex-wrap:wrap}
  .pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:999px;
        border:1px solid var(--line);background:var(--card)}
  .dot{width:9px;height:9px;border-radius:50%;display:inline-block}
  .dot.high{background:var(--high)} .dot.medium{background:var(--medium)} .dot.low{background:var(--low)}
  h2.section{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);
             margin:34px 0 14px;font-weight:600}
  .finding{background:var(--card);border:1px solid var(--line);border-radius:10px;
           padding:20px 22px;margin-bottom:16px;border-left:4px solid var(--low)}
  .finding.high{border-left-color:var(--high)}
  .finding.medium{border-left-color:var(--medium)}
  .fhead{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
  .rank{font-family:var(--mono);font-size:13px;color:var(--muted)}
  .vtype{font-weight:600;font-size:16px;margin:2px 0}
  .ep{font-family:var(--mono);font-size:12.5px;color:var(--ink);word-break:break-all}
  .ep.unknown{color:var(--muted);font-style:italic}
  .ep .param{color:var(--accent)}
  .meterwrap{min-width:200px;text-align:right}
  .prio{font-family:var(--mono);font-size:20px;font-weight:600}
  .prio.high{color:var(--high)} .prio.medium{color:var(--medium)} .prio.low{color:var(--low)}
  .meter{height:7px;border-radius:4px;background:var(--line);margin-top:6px;overflow:hidden}
  .meter > i{display:block;height:100%;border-radius:4px}
  .meter > i.high{background:var(--high)} .meter > i.medium{background:var(--medium)} .meter > i.low{background:var(--low)}
  .pcaption{font-size:11px;color:var(--muted);margin-top:5px;font-family:var(--mono)}
  .why{margin-top:16px}
  .why .lab{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:6px}
  ul.ev{list-style:none;margin:0;padding:0;font-family:var(--mono);font-size:12px;color:#333}
  ul.ev li{padding:2px 0;border-bottom:1px dotted var(--line)}
  ul.ev li:last-child{border-bottom:0}
  .sig{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--line);margin-right:6px}
  .sig.on{background:var(--high)} .sig.off{background:var(--low)} .sig.na{background:var(--line)}
  table.rec{width:100%;border-collapse:collapse;margin-top:6px;font-size:12px}
  table.rec th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;
               color:var(--muted);border-bottom:1px solid var(--line);padding:6px 8px}
  table.rec td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  table.rec td.pl{font-family:var(--mono);color:var(--accent);word-break:break-all;max-width:340px}
  table.rec td.role{font-family:var(--mono);text-transform:uppercase;font-size:10.5px;color:var(--muted)}
  .status{font-family:var(--mono)}
  .fix{margin-top:14px;padding:11px 13px;background:#f3f6fb;border:1px solid #e0e8f3;
       border-radius:7px;font-size:13px}
  .fix b{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--accent)}
  .fix i{color:var(--muted)}
  .ids{margin-top:10px;font-size:10.5px;color:var(--muted);font-family:var(--mono)}
  .notice{background:var(--card);border:1px solid var(--line);border-radius:10px;
          padding:14px 18px;margin:16px 0;font-size:13px}
  .notice.small{padding:10px 14px;color:var(--muted);font-style:italic}
  .notice .lab{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:6px}
  .notice ul{margin:0;padding-left:18px}
  .empty{background:var(--card);border:1px dashed var(--line);border-radius:10px;
         padding:40px;text-align:center;color:var(--muted)}
  footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);
         font-size:12px;color:var(--muted)}
  footer .warn{color:var(--high)}
  @media (max-width:560px){.meterwrap{text-align:left;min-width:0;width:100%}}
"""
