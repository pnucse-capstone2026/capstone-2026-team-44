"""Fold an access-control (BAC) dashboard into the injection dashboard as a page.

Injection and access-control are two separate scans on purpose (access-control
only means something on a protected area; see ``tools/demo.py``). But the two
results read best as one deliverable: this takes the injection dashboard as the
base and appends the BAC dashboard's candidate list and detail screens as a
dedicated "접근제어 (BAC)" page, with every id/href re-namespaced to ``ac-`` so
the two candidate lists never collide. When no BAC dashboard is supplied, the
page shows a short notice instead of the findings.

    python tools/merge_dashboard.py --injection A.html --bac B.html --out C.html
    python tools/merge_dashboard.py --injection A.html --out C.html   # no BAC
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

NAV_ICON = "▨"

_METHODOLOGY = '<section class="report-page" id="methodology"'
_SIDEBAR_ANCHOR = (
    '<a href="#candidates"><span class="nav-icon" aria-hidden="true">◎</span>취약점 후보</a>'
)
_PROJECTOR_ANCHOR = '<a href="#candidates">후보 목록</a>'


def _report_pages(html: str) -> dict[str, str]:
    """Every top-level ``report-page`` section (children of <main>), by id."""

    pages: dict[str, str] = {}
    stack: list[re.Match[str]] = []
    for tag in re.finditer(r"<section\b[^>]*>|</section>", html):
        if tag.group().startswith("</"):
            if stack:
                start = stack.pop()
                if not stack:
                    marker = re.search(r'id="([^"]+)"', start.group())
                    if marker and "report-page" in start.group():
                        pages[marker.group(1)] = html[start.start():tag.end()]
        else:
            stack.append(tag)
    return pages


def _namespace(section: str) -> str:
    """Prefix every id and in-page href in one BAC section so it stays distinct."""

    section = re.sub(r'\bid="', 'id="ac-', section)
    return section.replace('href="#', 'href="#ac-')


def _relabel_candidates(section: str) -> str:
    """Turn the BAC "취약점 후보" list into the "접근제어 (BAC)" page."""

    section = re.sub(r'<div class="filters">.*?</div>', "", section, count=1, flags=re.S)
    section = re.sub(r'<div class="filter-empty"[^>]*>.*?</div>', "", section, count=1, flags=re.S)
    section = section.replace(
        '<div class="eyebrow">SCAN REPORT</div>',
        '<div class="eyebrow">ACCESS CONTROL · BAC</div>', 1,
    )
    section = section.replace(
        'class="page-title" tabindex="-1">취약점 후보</h1>',
        'class="page-title" tabindex="-1">접근제어 (BAC)</h1>', 1,
    )
    section = re.sub(
        r'(<p class="subtitle">).*?(</p>)',
        r"\1로그인 세션으로 스캔한 접근제어 후보입니다. 식별자를 바꿔 다른 사용자의 "
        r"자원이 열리는지(IDOR) 확인한 결과입니다.\2",
        section, count=1, flags=re.S,
    )
    return section.replace("검토할 대표 후보", "접근제어(BAC) 후보", 1)


def _placeholder() -> str:
    return (
        '<section class="report-page" id="ac-candidates" aria-label="접근제어(BAC)">'
        '<div class="page-heading"><div>'
        '<div class="eyebrow">ACCESS CONTROL · BAC</div>'
        '<h1 class="page-title" tabindex="-1">접근제어 (BAC)</h1>'
        '<p class="subtitle">이번 실행에는 접근제어(BAC) 스캔 결과가 포함되지 않았습니다.</p>'
        "</div></div>"
        '<section class="panel"><div class="panel-body">'
        '<div class="missing-note">접근제어(BAC)는 로그인 세션이 필요한 별도 스캔입니다. '
        '주입 스캔과 함께 실행하면 이 페이지에 <b>다른 사용자의 주문 조회 같은 IDOR 후보</b>가 '
        "표시됩니다. 한 번에 두 스캔을 돌리려면:</div>"
        '<pre style="background:#122c3a;color:#e7f6f2;padding:14px 16px;border-radius:9px;'
        'overflow:auto;font:13px/1.7 Consolas,monospace;margin:14px 0 0">'
        "PYTHONPATH=src python tools/demo.py</pre>"
        "</div></section></section>"
    )


def _bac_page(bac_html: str | None) -> str:
    if not bac_html:
        return _placeholder()
    pages = _report_pages(bac_html)
    candidates = pages.get("candidates")
    details = [pages[key] for key in pages if re.fullmatch(r"candidate-\d+", key)]
    if not candidates or not details:
        return _placeholder()
    block = _namespace(_relabel_candidates(candidates))
    block += "\n\n" + "\n\n".join(_namespace(detail) for detail in details)
    return block


def merge(injection_html: str, bac_html: str | None = None) -> str:
    """Return the injection dashboard with a "접근제어 (BAC)" page folded in."""

    if _METHODOLOGY not in injection_html or _SIDEBAR_ANCHOR not in injection_html:
        raise ValueError("base dashboard is not a recognised injection dashboard")
    out = injection_html.replace(_METHODOLOGY, _bac_page(bac_html) + "\n\n" + _METHODOLOGY, 1)
    out = out.replace(
        _SIDEBAR_ANCHOR,
        _SIDEBAR_ANCHOR
        + f'\n    <a href="#ac-candidates"><span class="nav-icon" aria-hidden="true">'
        f"{NAV_ICON}</span>접근제어 (BAC)</a>",
        1,
    )
    if _PROJECTOR_ANCHOR in out:
        out = out.replace(
            _PROJECTOR_ANCHOR,
            _PROJECTOR_ANCHOR + '<a href="#ac-candidates">접근제어</a>', 1,
        )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--injection", required=True, type=Path)
    parser.add_argument("--bac", type=Path, default=None)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    injection_html = args.injection.read_text(encoding="utf-8")
    bac_html = (
        args.bac.read_text(encoding="utf-8")
        if args.bac is not None and args.bac.is_file()
        else None
    )
    args.out.write_text(merge(injection_html, bac_html), encoding="utf-8")
    print(f"combined dashboard -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
