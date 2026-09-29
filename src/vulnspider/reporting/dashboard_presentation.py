"""Audience-oriented summary screens from authoritative display projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def evidence_summary(rows: Sequence[Mapping[str, Any]]) -> str:
    groups = (
        ("SUPPORTED", "근거 뒷받침", "추가 확인에서도 유형별 신호 관찰", "supported"),
        ("WEAKENED", "가능성 약화", "기존 의심을 낮추는 관찰", "weakened"),
        ("OTHER", "유지·보류·미검증", "상세 기록을 더 살펴볼 후보", "pending"),
    )
    cards = []
    for state, label, note, tone in groups:
        count = sum(row["state"] == state if state != "OTHER" else row["state"] not in {"SUPPORTED", "WEAKENED"} for row in rows)
        width = count / len(rows) * 100 if rows else 0
        cards.append(f'<div class="evidence-count {tone}"><span>{label}</span><strong>{count}<small>개</small></strong>'
                     f'<div class="status-track" aria-hidden="true"><i style="width:{width:.2f}%"></i></div><p>{note}</p></div>')
    return ('<section class="panel evidence-summary"><div class="panel-head"><div><h2>추가 확인 결과, 한눈에</h2>'
            f'<p class="panel-desc">표시된 대표 후보 {len(rows)}개 기준 · 확정 취약점 수가 아닙니다.</p></div></div>'
            '<div class="evidence-counts">' + ''.join(cards) + '</div></section>')
