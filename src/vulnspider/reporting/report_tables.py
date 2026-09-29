"""Report-ready tables: the ranking-evaluation comparison and, for a labeled
target, the per-input-point vulnerability map.

The live evaluation already prints a text table and writes a JSON document.
This module renders the same numbers as **paste-ready** tables for the final
report: a Markdown version (drops straight into a doc, Notion, or a Git host)
and a styled standalone HTML version (opens in a browser, screenshots cleanly).
Nothing here recomputes a metric or a label; it only formats what the
evaluation and the ground truth already established.
"""

from __future__ import annotations

import html
from collections import defaultdict
from collections.abc import Mapping, Sequence

from vulnspider.corpus.ground_truth import GroundTruthKey, GroundTruthStore
from vulnspider.evaluation.live import LiveEvaluationReport

# Metric column order shared by both the Markdown and HTML evaluation tables.
_METRICS: tuple[tuple[str, str], ...] = (
    ("recall_at_k", "Recall@K"),
    ("precision_at_k", "Precision@K"),
    ("map_at_k", "MAP@K"),
    ("ndcg_at_k", "NDCG@K"),
)

# The vulnerability families a ground-truth entry can name, with report labels.
_FAMILY_LABEL: Mapping[str, str] = {
    "SQLI": "SQLi",
    "REFLECTED_XSS": "Reflected XSS",
    "BROKEN_ACCESS_CONTROL": "BAC",
}
_FAMILY_TONE: Mapping[str, str] = {
    "SQLI": "sqli",
    "REFLECTED_XSS": "xss",
    "BROKEN_ACCESS_CONTROL": "bac",
}
_FAMILY_ORDER: tuple[str, ...] = (
    "SQLI",
    "REFLECTED_XSS",
    "BROKEN_ACCESS_CONTROL",
)
_SAFE_LABEL = "안전"


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _fmt(value: float) -> str:
    return f"{float(value):.3f}"


def _is_full_pipeline(name: str) -> bool:
    return "full pipeline" in name.lower()


# --------------------------------------------------------------------------- #
# Ranking-evaluation comparison table
# --------------------------------------------------------------------------- #


def _summary_line(report: LiveEvaluationReport) -> tuple[str, ...]:
    return (
        f"후보 {len(report.candidates)}개",
        f"취약 {report.relevant}개",
        f"미라벨 {report.unlabeled}개",
        f"검증 {report.verified}개",
        f"Top-K {report.top_k}",
    )


def render_evaluation_markdown(report: LiveEvaluationReport) -> str:
    """The arm-by-metric comparison as GitHub-flavored Markdown."""

    metrics_version = report.arms[0].metrics_version if report.arms else ""
    lines = [
        f"# 랭킹 평가 지표 — {report.application_id}",
        "",
        f"- 대상: `{report.target}`" if report.target else "- 대상: (미지정)",
        "- " + " · ".join(_summary_line(report)),
    ]
    if metrics_version:
        lines.append(f"- 지표 버전: `{metrics_version}`")
    lines.append("")

    header = "| Arm | " + " | ".join(f"K={k}" for k in report.cutoffs) + " |"
    divider = "| --- | " + " | ".join("---:" for _ in report.cutoffs) + " |"
    for metric_key, metric_label in _METRICS:
        lines.append(f"## {metric_label}")
        lines.append("")
        lines.append(header)
        lines.append(divider)
        for arm in report.arms:
            name = f"**{arm.name}**" if _is_full_pipeline(arm.name) else arm.name
            cells = " | ".join(
                _fmt(arm.at(k).as_mapping()[metric_key]) for k in report.cutoffs
            )
            lines.append(f"| {name} | {cells} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_evaluation_html(report: LiveEvaluationReport) -> str:
    """The same comparison as a styled, standalone HTML document."""

    metrics_version = report.arms[0].metrics_version if report.arms else ""
    title = f"랭킹 평가 지표 — {report.application_id}"
    chips = "".join(f"<span class='chip'>{_esc(item)}</span>" for item in _summary_line(report))

    blocks: list[str] = []
    for metric_key, metric_label in _METRICS:
        head = "".join(f"<th>K={_esc(k)}</th>" for k in report.cutoffs)
        rows: list[str] = []
        for arm in report.arms:
            full = _is_full_pipeline(arm.name)
            cells = "".join(
                f"<td>{_fmt(arm.at(k).as_mapping()[metric_key])}</td>"
                for k in report.cutoffs
            )
            cls = " class='full'" if full else ""
            rows.append(f"<tr{cls}><th scope='row'>{_esc(arm.name)}</th>{cells}</tr>")
        blocks.append(
            f"<section class='metric'><h2>{_esc(metric_label)}</h2>"
            f"<div class='scroll'><table><thead><tr>"
            f"<th scope='col'>Arm</th>{head}</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div></section>"
        )

    meta = f"<div class='meta'>지표 버전 {_esc(metrics_version)}</div>" if metrics_version else ""
    target = f"<div class='target'>대상 &rarr; {_esc(report.target)}</div>" if report.target else ""
    return (
        "<!DOCTYPE html>\n<html lang='ko'>\n<head>\n<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        f"<title>{_esc(title)}</title>\n<style>{_TABLE_STYLE}</style>\n</head>\n"
        f"<body>\n<div class='wrap'>\n<header><h1>{_esc(title)}</h1>{target}"
        f"<div class='chips'>{chips}</div>{meta}</header>\n"
        f"{''.join(blocks)}\n</div>\n</body>\n</html>\n"
    )


# --------------------------------------------------------------------------- #
# Per-input-point vulnerability map (from ground truth)
# --------------------------------------------------------------------------- #


def _input_point_rows(
    store: GroundTruthStore,
    application_id: str,
) -> list[tuple[str, str, str, str, tuple[str, ...]]]:
    """One row per (method, path, location, name): the families labeled True."""

    grouped: dict[tuple[str, str, str, str], dict[str, bool]] = defaultdict(dict)
    for key, label in store.labels.items():
        if key.application_id != application_id:
            continue
        point = (
            key.method,
            key.canonical_path,
            key.parameter_location,
            key.parameter_name,
        )
        grouped[point][key.vulnerability_type] = label

    rows: list[tuple[str, str, str, str, tuple[str, ...]]] = []
    for (method, path, location, name) in sorted(grouped):
        families = grouped[(method, path, location, name)]
        vulnerable = tuple(
            family
            for family in _FAMILY_ORDER
            if families.get(family) is True
        )
        # Preserve any labeled family outside the known order, still True.
        extra = tuple(
            family
            for family, is_vuln in sorted(families.items())
            if is_vuln and family not in _FAMILY_ORDER
        )
        rows.append((method, path, location, name, vulnerable + extra))
    return rows


def _family_counts(
    rows: Sequence[tuple[str, str, str, str, tuple[str, ...]]],
) -> tuple[int, int, dict[str, int]]:
    per_family: dict[str, int] = defaultdict(int)
    vulnerable_points = 0
    for *_rest, families in rows:
        if families:
            vulnerable_points += 1
            for family in families:
                per_family[family] += 1
    return len(rows), vulnerable_points, per_family


def _family_summary_chips(per_family: Mapping[str, int]) -> list[str]:
    ordered = list(_FAMILY_ORDER) + [
        family for family in sorted(per_family) if family not in _FAMILY_ORDER
    ]
    return [
        f"{_FAMILY_LABEL.get(family, family)} {per_family[family]}"
        for family in ordered
        if per_family.get(family)
    ]


def _vuln_label(families: Sequence[str]) -> str:
    if not families:
        return _SAFE_LABEL
    return " / ".join(_FAMILY_LABEL.get(family, family) for family in families)


def render_ground_truth_markdown(
    store: GroundTruthStore,
    application_id: str,
) -> str:
    """Per-input-point vulnerability map for one application, as Markdown."""

    rows = _input_point_rows(store, application_id)
    total, vulnerable_points, per_family = _family_counts(rows)
    safe_points = total - vulnerable_points
    chips = _family_summary_chips(per_family)
    family_line = f" ({' · '.join(chips)})" if chips else ""

    lines = [
        f"# 입력점별 취약 유형 — {application_id}",
        "",
        f"- 입력점 {total}개 · 취약 {vulnerable_points}개{family_line} · "
        f"안전 {safe_points}개",
        "",
        "| # | 경로 | 파라미터 | 위치 | 취약 유형 |",
        "| ---: | --- | --- | --- | --- |",
    ]
    for index, (_method, path, location, name, families) in enumerate(rows, start=1):
        label = _vuln_label(families)
        cell = f"**{label}**" if families else label
        lines.append(
            f"| {index} | `{path}` | `{name}` | {location} | {cell} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_ground_truth_html(
    store: GroundTruthStore,
    application_id: str,
) -> str:
    """Per-input-point vulnerability map for one application, as HTML."""

    rows = _input_point_rows(store, application_id)
    total, vulnerable_points, per_family = _family_counts(rows)
    safe_points = total - vulnerable_points
    title = f"입력점별 취약 유형 — {application_id}"

    chips = "".join(
        f"<span class='chip'>{_esc(item)}</span>"
        for item in (
            f"입력점 {total}개",
            f"취약 {vulnerable_points}개",
            *(_family_summary_chips(per_family)),
            f"안전 {safe_points}개",
        )
    )

    body_rows: list[str] = []
    for index, (_method, path, location, name, families) in enumerate(rows, start=1):
        if families:
            badges = "".join(
                f"<span class='tag {_FAMILY_TONE.get(family, '')}'>"
                f"{_esc(_FAMILY_LABEL.get(family, family))}</span>"
                for family in families
            )
        else:
            badges = f"<span class='tag safe'>{_SAFE_LABEL}</span>"
        cls = "" if families else " class='is-safe'"
        body_rows.append(
            f"<tr{cls}><td class='num'>{index}</td>"
            f"<td class='path'>{_esc(path)}</td>"
            f"<td class='param'>{_esc(name)}</td>"
            f"<td class='loc'>{_esc(location)}</td>"
            f"<td class='vuln'>{badges}</td></tr>"
        )

    return (
        "<!DOCTYPE html>\n<html lang='ko'>\n<head>\n<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        f"<title>{_esc(title)}</title>\n<style>{_TABLE_STYLE}</style>\n</head>\n"
        f"<body>\n<div class='wrap'>\n<header><h1>{_esc(title)}</h1>"
        f"<div class='chips'>{chips}</div></header>\n"
        "<section class='metric'><div class='scroll'><table class='points'>"
        "<thead><tr><th scope='col'>#</th><th scope='col'>경로</th>"
        "<th scope='col'>파라미터</th><th scope='col'>위치</th>"
        "<th scope='col'>취약 유형</th></tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table></div></section>\n"
        "</div>\n</body>\n</html>\n"
    )


_TABLE_STYLE = """
  :root{
    --paper:#f6f7f9; --card:#ffffff; --ink:#12161d; --muted:#5b6472;
    --line:#e3e7ee; --accent:#2f4b7c; --head:#eef1f6;
    --sqli:#2f6f8f; --xss:#7a5aa8; --bac:#2f7d5f; --safe:#7c8798;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
       line-height:1.5;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1180px;margin:0 auto;padding:36px 28px 72px}
  header{border-bottom:2px solid var(--ink);padding-bottom:16px;margin-bottom:22px}
  h1{font-size:23px;margin:0 0 10px;letter-spacing:-.01em}
  .target{font-family:var(--mono);font-size:13px;color:var(--accent);
          word-break:break-all;margin-bottom:10px}
  .chips{display:flex;flex-wrap:wrap;gap:8px}
  .chip{display:inline-flex;align-items:center;padding:4px 11px;border-radius:999px;
        border:1px solid var(--line);background:var(--card);font-size:12.5px;
        font-family:var(--mono);color:var(--muted)}
  .meta{margin-top:10px;font-size:11px;color:var(--muted);font-family:var(--mono)}
  section.metric{margin:26px 0}
  section.metric h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;
        color:var(--muted);margin:0 0 12px;font-weight:600}
  .scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  thead th{background:var(--head);text-align:right;padding:11px 16px;font-size:11px;
        text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
        border-bottom:1px solid var(--line);white-space:nowrap}
  thead th[scope=col]:first-child{text-align:left}
  tbody th[scope=row]{text-align:left;padding:11px 16px;font-weight:500;white-space:nowrap;
        border-bottom:1px solid var(--line)}
  tbody td{text-align:right;padding:11px 16px;font-family:var(--mono);
        border-bottom:1px solid var(--line)}
  tbody tr:last-child th,tbody tr:last-child td{border-bottom:0}
  tr.full{background:rgba(47,75,124,.06)}
  tr.full th[scope=row]{font-weight:700;color:var(--accent)}
  table.points td{text-align:left}
  table.points td.num{font-family:var(--mono);color:var(--muted);text-align:right;width:1%}
  table.points td.path{font-family:var(--mono);color:var(--ink);word-break:break-all}
  table.points td.param{font-family:var(--mono);color:var(--accent)}
  table.points td.loc{font-family:var(--mono);font-size:11.5px;color:var(--muted);
        text-transform:uppercase}
  tr.is-safe{color:var(--muted)}
  .tag{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;
        font-weight:600;color:#fff;margin:1px 3px 1px 0}
  .tag.sqli{background:var(--sqli)} .tag.xss{background:var(--xss)}
  .tag.bac{background:var(--bac)} .tag.safe{background:var(--safe)}
"""
