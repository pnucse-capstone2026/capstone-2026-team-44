"""Run the DemoShop loopback target used for demos and ranking evaluation.

The site itself lives in ``tools/demo_shop.py`` (so it is covered by the repo's
format/lint checks and importable from tests); this file stays at the repo root
because every runbook in ``docs/`` starts with:

    python demo_target_server.py            # http://127.0.0.1:8899

DemoShop is an authored online store with 100 query input points, 40 of them
vulnerable, and it knows its own ground truth. That is what lets a live scan be
scored with Precision@K / Recall@K / MAP@K:

    PYTHONPATH=src python -m vulnspider analyze --url http://127.0.0.1:8899/ \\
        --max-pages 60 --max-requests 250 --top-k 20 --output analysis.json \\
        --verify --verify-output verify.json \\
        --verification-model data/corpus/verification-model.json \\
        --ground-truth data/demo/demoshop-ground-truth.json \\
        --eval-output evaluation.json

The ground truth file is committed at ``data/demo/demoshop-ground-truth.json``;
``--ground-truth PATH`` here regenerates it after the site changes.

DemoShop also has an authenticated area (``/portal/``) for demonstrating Broken
Access Control. Log in for a session cookie and scan it separately -- protected
resources answer 403 without the cookie, so the BAC scan must be authenticated::

    PYTHONPATH=src python -m vulnspider analyze --url http://127.0.0.1:8899/portal/ \\
        --access-control --cookie demoshop_session=<token from /login?as=admin> \\
        --max-pages 20 --max-requests 100 --top-k 10 \\
        --ground-truth data/demo/demoshop-ground-truth.json \\
        --application-id demoshop --eval-output portal-eval.json

``http://127.0.0.1:8899/_lab`` explains every input point (and the ``/portal/``
BAC routes): what it does, why it is (or is not) a vulnerability, and a link
that reproduces it in the browser.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tools import demo_shop  # noqa: E402 - needs the sys.path setup above


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="demo_target_server",
        description="Serve the DemoShop loopback target on 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=demo_shop.PORT,
        help=f"Port to bind on 127.0.0.1 (default: {demo_shop.PORT}).",
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=None,
        help="Write the site's ground truth JSON to this path and keep serving.",
    )
    parser.add_argument(
        "--ground-truth-only",
        action="store_true",
        help="Write the ground truth file and exit without serving.",
    )
    args = parser.parse_args(argv)

    if args.ground_truth is not None:
        args.ground_truth.parent.mkdir(parents=True, exist_ok=True)
        args.ground_truth.write_text(
            json.dumps(
                demo_shop.ground_truth_document(),
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"ground truth -> {args.ground_truth}")
    elif args.ground_truth_only:
        parser.error("--ground-truth-only requires --ground-truth")
    if args.ground_truth_only:
        return 0

    server = demo_shop.build_server(args.port)
    print(demo_shop.banner(args.port))
    print("Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
