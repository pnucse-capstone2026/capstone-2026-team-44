"""One-command DemoShop demo: scan both surfaces, open both dashboards.

A short live demo needs one action, not three. This starts DemoShop, runs the
public **injection** scan (SQLi / Reflected XSS over the storefront) and the
authenticated **access-control** scan (logged in as ``soohoon``; the portal's
IDOR returns another member's -- ``sanghyun`` -- order), writes both dashboards
to ``docs/results/``, opens them in Chrome, and keeps the store running so the
live PoC-confirmation links (``/_lab`` -> "취약점 검증") stay clickable.

Injection and access-control are two scans on purpose: access-control decides
"got the protected resource without authorisation" only where a resource is
actually protected, so pointing it at the whole public storefront would flag
every public route. Each scan therefore keeps its own clean dashboard; this
runner just does both from one command.

    PYTHONPATH=src python tools/demo.py            # scan + open both dashboards
    PYTHONPATH=src python tools/demo.py --no-open  # scan only, print the links
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from tools import demo_shop, merge_dashboard, results_pack  # noqa: E402


def _chrome() -> str | None:
    """Locate chrome.exe so the demo opens in the browser the user asked for."""

    candidates = [
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                     r"Google\Chrome\Application\chrome.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                     r"Google\Chrome\Application\chrome.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     r"Google\Chrome\Application\chrome.exe"),
    ]
    for path in candidates:
        if path and Path(path).is_file():
            return path
    return None


def _open(urls: list[str]) -> None:
    chrome = _chrome()
    if chrome:
        subprocess.Popen([chrome, *urls])
        return
    for url in urls:
        webbrowser.open(url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="DemoShop 시연: 한 번의 실행으로 주입 + BAC 스캔 후 대시보드를 엽니다.",
    )
    parser.add_argument("--port", type=int, default=demo_shop.PORT)
    parser.add_argument("--top-k", type=int, default=20)
    parser.add_argument("--out", type=Path, default=results_pack.DEFAULT_OUT)
    parser.add_argument("--no-open", action="store_true", help="브라우저를 열지 않습니다.")
    args = parser.parse_args(argv)

    # This process stays alive to keep the store running, so flush each line as
    # it is printed -- otherwise the progress and links sit in a buffer unseen.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    if not results_pack._free(args.port):
        print(
            f"[!] 포트 {args.port} 가 이미 사용 중입니다. 기존 DemoShop을 종료하고 다시 실행하세요.",
            file=sys.stderr,
        )
        return 2

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    server = demo_shop.build_server(args.port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] DemoShop 실행 중: http://127.0.0.1:{args.port}")

    scenarios = [
        results_pack._demoshop_public(out, args.port, args.top_k),
        results_pack._demoshop_bac(out, args.port, args.top_k),
    ]
    try:
        for scenario in scenarios:
            print(f"[*] 스캔: {scenario.name} ...")
            results_pack._run(scenario, out)
            print(f"    -> {scenario.status}")
    finally:
        pass

    failed = [s.name for s in scenarios if s.status != "ok"]
    injection = out / "demoshop" / "dashboard.html"
    bac = out / "demoshop-bac" / "dashboard.html"
    combined = out / "combined-dashboard.html"

    # One dashboard: the injection report with the BAC scan folded in as a
    # dedicated "접근제어 (BAC)" page. If the BAC scan did not produce a
    # dashboard, that page shows a short notice instead.
    bac_ok = len(scenarios) > 1 and scenarios[1].status == "ok" and bac.is_file()
    if injection.is_file():
        combined.write_text(
            merge_dashboard.merge(
                injection.read_text(encoding="utf-8"),
                bac.read_text(encoding="utf-8") if bac_ok else None,
            ),
            encoding="utf-8",
        )

    print("\n[*] 통합 대시보드 (주입 + 접근제어 BAC 한 화면)")
    print(f"    {combined.resolve().as_uri()}")
    print(f"[*] 시연 진입점(정답지): http://127.0.0.1:{args.port}/_lab")
    if not bac_ok:
        print("[!] BAC 스캔 결과가 없어 '접근제어(BAC)' 페이지에는 안내만 표시됩니다.", file=sys.stderr)
    if failed:
        print(f"[!] 실패한 스캔: {', '.join(failed)} — run.log 확인", file=sys.stderr)

    if not args.no_open and combined.is_file():
        _open([combined.resolve().as_uri()])
        print("[*] Chrome에서 통합 대시보드를 열었습니다.")

    print("\n[*] DemoShop을 계속 실행합니다 (라이브 PoC 링크 사용 가능). 종료: Ctrl+C")
    try:
        while thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 종료합니다.")
        server.shutdown()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
