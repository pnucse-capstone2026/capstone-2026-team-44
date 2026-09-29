"""CLI wrapper: render the per-input-point verification detail report to a file.

The rendering lives in the library
(``vulnspider.reporting.verification_detail_report``) so the public ``analyze``
CLI can emit the same report directly. This wrapper only reads the JSON files
and writes the HTML, for the case where you already have ``verify.json`` (and
optionally the crawl JSON) on disk:

    PYTHONPATH=src python tools/verification_detail_report.py \
        --verify verify.json --crawl vulnspider-crawl.json \
        --out verification-detail.html

Input-point ids are stable fingerprints, so the crawl JSON can come from any run
against the same target. Without ``--crawl`` the report still renders, falling
back to the bare parameter value.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnspider.reporting.verification_detail_report import (
    build_verification_detail_html,
    crawl_index_from_report,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        type=Path,
        required=True,
        help="verification JSON (--verify-output)",
    )
    parser.add_argument(
        "--crawl",
        type=Path,
        default=None,
        help="matching crawl JSON (--crawl-output) for full request URLs",
    )
    parser.add_argument(
        "--out", type=Path, required=True, help="destination HTML path"
    )
    args = parser.parse_args(argv)

    report = json.loads(args.verify.read_text(encoding="utf-8"))
    crawl = (
        json.loads(args.crawl.read_text(encoding="utf-8"))
        if args.crawl is not None
        else None
    )
    html_doc = build_verification_detail_html(report, crawl, source=args.verify.name)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(html_doc, encoding="utf-8")

    index = crawl_index_from_report(crawl)
    candidates = report.get("candidates", [])
    joined = sum(1 for c in candidates if c.get("input_point_id") in index)
    print(f"Wrote {args.out} ({len(candidates)} candidates, "
          f"{joined} joined to request URLs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
