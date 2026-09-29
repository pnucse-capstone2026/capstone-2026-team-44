"""Deterministic inline chart primitives for the static HTML dashboard.

Ported unchanged from `f6a70f0` on `prototype_han/v0.1` (HanSH4426), where it
was written for the v0.1 dashboard. Kept verbatim so both dashboards draw the
same shapes; only this note was added.

Everything here is presentation only: charts are SVG/CSS markup built from
numbers the report context already holds. Nothing in this module scores,
weights, or re-derives a signal, and it deliberately imports no domain or
selection type so both `html_report` and `combined_report` can share it
(`docs/ARCHITECTURE.md` §6).

Charts are inlined rather than drawn by a charting library so the report
stays a single dependency-free static file that renders offline and issues
no outbound request when opened.
"""

from __future__ import annotations

import html
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

DONUT_SIZE = 148
DONUT_RADIUS = 56
DONUT_STROKE = 22
DONUT_CIRCUMFERENCE = math.tau * DONUT_RADIUS

# Tone names are an internal whitelist, never interpolated from observed
# data: a chart colour can only ever be one of these CSS variables.
TONE_VARIABLES: Mapping[str, str] = MappingProxyType(
    {
        "high": "var(--high)",
        "medium": "var(--medium)",
        "low": "var(--low)",
        "sqli": "var(--sqli)",
        "xss": "var(--xss)",
        "bac": "var(--bac)",
        "accent": "var(--accent)",
        "muted": "var(--line)",
    }
)
DEFAULT_TONE = "muted"


def escape_text(value: Any) -> str:
    """Escape any value for HTML text/attribute interpolation."""

    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def tone_color(tone: str) -> str:
    """Resolve a tone name to a CSS variable, falling back to the neutral one."""

    return TONE_VARIABLES.get(tone, TONE_VARIABLES[DEFAULT_TONE])


def clamp_ratio(value: float) -> float:
    """Clamp a display ratio into 0..1 (NaN-safe)."""

    number = float(value)
    if math.isnan(number):
        return 0.0
    return min(max(number, 0.0), 1.0)


@dataclass(frozen=True)
class Slice:
    """One donut segment."""

    label: str
    value: float
    tone: str = DEFAULT_TONE


@dataclass(frozen=True)
class Bar:
    """One horizontal bar row."""

    label: str
    value_label: str
    ratio: float
    tone: str = DEFAULT_TONE
    caption: str = ""


@dataclass(frozen=True)
class Segment:
    """One slice of a stacked bar."""

    label: str
    ratio: float
    tone: str = DEFAULT_TONE


def donut_chart(
    slices: Sequence[Slice],
    *,
    center_value: str,
    center_caption: str,
    empty_caption: str,
) -> str:
    """Render a donut chart with a legend beneath it."""

    values = [max(0.0, float(item.value)) for item in slices]
    total = math.fsum(values)
    center = DONUT_SIZE / 2
    rings: list[str] = [
        f'<circle class="donut-track" cx="{center:.1f}" cy="{center:.1f}" '
        f'r="{DONUT_RADIUS}" stroke-width="{DONUT_STROKE}"></circle>'
    ]
    if total > 0.0:
        offset = 0.0
        for item, value in zip(slices, values):
            if value <= 0.0:
                continue
            length = DONUT_CIRCUMFERENCE * (value / total)
            gap = DONUT_CIRCUMFERENCE - length
            rings.append(
                f'<circle class="donut-seg" cx="{center:.1f}" cy="{center:.1f}" '
                f'r="{DONUT_RADIUS}" stroke-width="{DONUT_STROKE}" '
                f'style="stroke:{tone_color(item.tone)}" '
                f'stroke-dasharray="{length:.3f} {gap:.3f}" '
                f'stroke-dashoffset="{-offset:.3f}"></circle>'
            )
            offset += length
    legend = "".join(
        f'<li><span class="swatch" style="background:{tone_color(item.tone)}">'
        f"</span>{escape_text(item.label)}"
        f'<b>{escape_text(_fmt_count(value))}</b></li>'
        for item, value in zip(slices, values)
    )
    caption = center_caption if total > 0.0 else empty_caption
    return (
        '<div class="donut">\n'
        f'  <svg viewBox="0 0 {DONUT_SIZE} {DONUT_SIZE}" role="img" '
        f'aria-label="{escape_text(center_caption)}" class="donut-svg">\n'
        f'    <g transform="rotate(-90 {center:.1f} {center:.1f})">'
        f"{''.join(rings)}</g>\n"
        f'    <text class="donut-total" x="{center:.1f}" y="{center:.1f}" '
        f'text-anchor="middle">{escape_text(center_value)}</text>\n'
        "  </svg>\n"
        f'  <ul class="legend">{legend}</ul>\n'
        f'  <div class="chart-caption">{escape_text(caption)}</div>\n'
        "</div>"
    )


def bar_chart(bars: Sequence[Bar], *, empty_caption: str = "") -> str:
    """Render a list of labelled horizontal bars."""

    if not bars:
        return f'<div class="chart-empty">{escape_text(empty_caption)}</div>'
    rows = "".join(_bar_row(bar) for bar in bars)
    return f'<div class="bars">{rows}</div>'


def _bar_row(bar: Bar) -> str:
    width = clamp_ratio(bar.ratio) * 100.0
    caption = (
        f'<div class="bar-caption">{escape_text(bar.caption)}</div>'
        if bar.caption
        else ""
    )
    return (
        '<div class="bar-row">'
        f'<div class="bar-label">{escape_text(bar.label)}</div>'
        '<div class="bar-track">'
        f'<i style="width:{width:.1f}%;background:{tone_color(bar.tone)}"></i>'
        "</div>"
        f'<div class="bar-value">{escape_text(bar.value_label)}</div>'
        f"{caption}"
        "</div>"
    )


def stacked_bar(segments: Sequence[Segment], *, caption: str = "") -> str:
    """Render one bar whose segments are proportional slices of a whole."""

    pieces: list[str] = []
    for segment in segments:
        width = clamp_ratio(segment.ratio) * 100.0
        if width <= 0.0:
            continue
        pieces.append(
            f'<i style="width:{width:.2f}%;background:{tone_color(segment.tone)}" '
            f'title="{escape_text(segment.label)}"></i>'
        )
    caption_html = (
        f'<div class="chart-caption">{escape_text(caption)}</div>' if caption else ""
    )
    return f'<div class="stack">{"".join(pieces)}</div>{caption_html}'


def chart_card(
    title: str,
    body: str,
    *,
    english: str = "",
    note: str = "",
    card_class: str = "",
) -> str:
    """Wrap a chart in a titled card.

    ``card_class`` adds an extra CSS class to the section (e.g. ``"wide"`` to
    let a card span the full grid width); it is a fixed caller-supplied string,
    never interpolated from observed data.
    """

    english_html = (
        f'<span class="en">{escape_text(english)}</span>' if english else ""
    )
    note_html = (
        f'<div class="chart-note">{escape_text(note)}</div>' if note else ""
    )
    class_attr = f"chart-card {card_class}".rstrip()
    return (
        f'<section class="{class_attr}">\n'
        f'  <h3>{escape_text(title)}{english_html}</h3>\n'
        f"  {body}\n"
        f"  {note_html}\n"
        "</section>"
    )


def _fmt_count(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}"


CHART_STYLE = """
  .chart-grid{display:grid;gap:14px;margin:18px 0 6px;
              grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
  .chart-card{background:var(--card);border:1px solid var(--line);
              border-radius:12px;padding:16px 18px 14px}
  .chart-card.wide{grid-column:1/-1}
  .chart-card.wide .bars{display:grid;gap:9px 26px;
              grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
  details.more{margin-top:11px}
  details.more > summary{cursor:pointer;font-size:12px;color:var(--accent);
              font-weight:600;list-style:none;padding:3px 0}
  details.more > summary::-webkit-details-marker{display:none}
  details.more > summary::before{content:"\\25B8  "}
  details.more[open] > summary::before{content:"\\25BE  "}
  details.more .bars{margin-top:9px}
  .chart-card h3{margin:0 0 12px;font-size:13px;font-weight:600;
                 display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
  .chart-card h3 .en{font-size:10.5px;text-transform:uppercase;
                     letter-spacing:.08em;color:var(--muted);font-weight:500}
  .chart-note{margin-top:10px;font-size:11.5px;color:var(--muted);line-height:1.45}
  .chart-caption{margin-top:8px;font-size:11.5px;color:var(--muted)}
  .chart-empty{font-size:12.5px;color:var(--muted);font-style:italic;padding:10px 0}
  .donut{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  .donut-svg{width:118px;height:118px;flex:0 0 auto}
  .donut-track{fill:none;stroke:var(--line)}
  .donut-seg{fill:none;stroke-linecap:butt}
  .donut-total{fill:var(--ink);font-family:var(--mono);font-size:30px;
               font-weight:600;dominant-baseline:central}
  .donut .chart-caption{flex-basis:100%}
  ul.legend{list-style:none;margin:0;padding:0;font-size:12.5px;min-width:120px}
  ul.legend li{display:flex;align-items:center;gap:8px;padding:3px 0}
  ul.legend li b{margin-left:auto;font-family:var(--mono);font-weight:600}
  .swatch{width:10px;height:10px;border-radius:3px;flex:0 0 auto}
  .bars{display:flex;flex-direction:column;gap:9px}
  .bar-row{display:grid;grid-template-columns:minmax(84px,auto) 1fr auto;
           align-items:center;gap:10px;font-size:12.5px}
  .bar-label{color:var(--ink);word-break:break-word}
  .bar-track{height:9px;border-radius:5px;background:var(--track);overflow:hidden}
  .bar-track > i{display:block;height:100%;border-radius:5px;min-width:2px}
  .bar-value{font-family:var(--mono);font-size:12px;color:var(--muted);
             white-space:nowrap}
  .bar-caption{grid-column:2/-1;font-size:11px;color:var(--muted);
               font-family:var(--mono);margin-top:-3px}
  .stack{display:flex;height:10px;border-radius:5px;overflow:hidden;
         background:var(--track);margin-top:8px}
  .stack > i{display:block;height:100%}
"""
