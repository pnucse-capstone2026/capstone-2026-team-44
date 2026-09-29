"""Reproducible results pack: run each target once and save every artifact.

The final report and the demo both need their numbers to come from a single,
captured set of runs -- not from whatever happened to be on screen. This script
is that single source of truth. It:

* starts the self-contained DemoShop server on loopback,
* runs the public storefront scan (Static + focused **verification**, so the
  ``full pipeline`` arm actually differs from ``without verification``) and the
  authenticated ``/portal/`` Broken Access Control scan,
* optionally runs external DVWA pages when their URLs (and session cookies) are
  supplied -- skipped cleanly when they are not (Docker is not assumed),
* writes every dashboard, verification, evaluation JSON, and the paste-ready
  comparison / input-point tables under ``docs/results/<scenario>/``,
* records the exact command, environment, and headline metrics in
  ``docs/results/README.md``.

Every scan is the real CLI (``python -m vulnspider ...``) run as a subprocess,
so the command printed in the README is the command that produced the numbers.

Usage (from the repo root)::

    python tools/results_pack.py
    python tools/results_pack.py --dvwa-sqli-url http://localhost:4280/vulnerabilities/sqli/ \
        --dvwa-xss-url http://localhost:4280/vulnerabilities/xss_r/ \
        --dvwa-cookie PHPSESSID=... --dvwa-cookie security=low
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT))

from tools import demo_shop  # noqa: E402  (path set above)
from vulnspider import __version__  # noqa: E402

DEMO_GROUND_TRUTH = "data/demo/demoshop-ground-truth.json"
DVWA_GROUND_TRUTH = "data/demo/dvwa-ground-truth.json"
VERIFICATION_MODEL = "data/corpus/verification-model.json"
DEFAULT_OUT = "docs/results"


def _free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "(unknown)"


def _display_command(cli_args: list[str]) -> str:
    """The command as documented: repo convention, forward slashes, copy-ready."""

    display_args: list[str] = []
    redact_cookie_value = False
    for arg in cli_args:
        if redact_cookie_value:
            display_args.append(_redacted_cookie(arg))
            redact_cookie_value = False
        elif arg == "--cookie":
            display_args.append(arg)
            redact_cookie_value = True
        elif arg.startswith("--cookie="):
            display_args.append(
                "--cookie=" + _redacted_cookie(arg.removeprefix("--cookie="))
            )
        else:
            display_args.append(arg)
    return "PYTHONPATH=src python -m vulnspider " + " ".join(
        arg.replace("\\", "/") for arg in display_args
    )


def _redacted_cookie(value: str) -> str:
    name, separator, _secret = value.partition("=")
    return f"{name}=<redacted>" if separator and name else "<redacted>"


def _redact_cookie_output(value: str, cli_args: list[str]) -> str:
    cookie_values: list[str] = []
    next_value_is_cookie = False
    for arg in cli_args:
        if next_value_is_cookie:
            cookie_values.append(arg)
            next_value_is_cookie = False
        elif arg == "--cookie":
            next_value_is_cookie = True
        elif arg.startswith("--cookie="):
            cookie_values.append(arg.removeprefix("--cookie="))
    redacted = value
    for cookie in sorted(set(cookie_values), key=len, reverse=True):
        if cookie:
            redacted = redacted.replace(cookie, _redacted_cookie(cookie))
    return redacted


def _model_args() -> list[str]:
    return (
        ["--verification-model", VERIFICATION_MODEL]
        if (ROOT / VERIFICATION_MODEL).is_file()
        else []
    )


class Scenario:
    """One scan: a name, a CLI argument list, and where its outputs land."""

    def __init__(
        self,
        name: str,
        title: str,
        target: str,
        cli_args: list[str],
        output_root: Path,
    ):
        self.name = name
        self.title = title
        self.target = target
        self.cli_args = cli_args
        self.output_root = output_root
        self.status = "pending"
        self.detail = ""

    @property
    def eval_path(self) -> Path:
        return self.output_root / self.name / "evaluation.json"


def _demoshop_public(out: Path, port: int, top_k: int) -> Scenario:
    d = out / "demoshop"
    args = [
        "analyze",
        "--url", f"http://127.0.0.1:{port}/",
        "--top-k", str(top_k),
        "--max-pages", "40", "--max-requests", "220",
        "--output", str(d / "analysis.json"),
        "--html-output", str(d / "dashboard.html"),
        "--verify",
        *_model_args(),
        "--verify-output", str(d / "verification.json"),
        "--verify-detail-output", str(d / "verification-detail.html"),
        "--ground-truth", DEMO_GROUND_TRUTH,
        "--application-id", "demoshop",
        "--verify-links",
        "--eval-output", str(d / "evaluation.json"),
        "--random-predictor", "--random-safe-weight", "4",
    ]
    return Scenario(
        "demoshop",
        "DemoShop — 공개 상점 (Static + Focused Verification)",
        f"http://127.0.0.1:{port}/",
        args,
        out,
    )


def _demoshop_bac(out: Path, port: int, top_k: int) -> Scenario:
    d = out / "demoshop-bac"
    cookie = f"{demo_shop.SESSION_COOKIE}={demo_shop.session_token('user')}"
    args = [
        "analyze",
        "--url", f"http://127.0.0.1:{port}/portal/",
        "--access-control",
        "--cookie", cookie,
        "--top-k", str(top_k),
        "--max-pages", "20", "--max-requests", "100",
        "--output", str(d / "analysis.json"),
        "--html-output", str(d / "dashboard.html"),
        "--verify",
        *_model_args(),
        "--verify-output", str(d / "verification.json"),
        "--verify-detail-output", str(d / "verification-detail.html"),
        "--ground-truth", DEMO_GROUND_TRUTH,
        "--application-id", "demoshop",
        "--verify-links",
        "--eval-output", str(d / "evaluation.json"),
        "--random-predictor", "--random-safe-weight", "4",
    ]
    return Scenario(
        "demoshop-bac",
        "DemoShop — 인증 영역 BAC (`/portal/`, user 세션)",
        f"http://127.0.0.1:{port}/portal/",
        args,
        out,
    )


def _dvwa(name: str, title: str, url: str, cookies: list[str], out: Path) -> Scenario:
    d = out / name
    cookie_args: list[str] = []
    for cookie in cookies:
        cookie_args += ["--cookie", cookie]
    args = [
        "analyze",
        "--url", url,
        "--max-depth", "0", "--max-pages", "1", "--top-k", "5",
        *cookie_args,
        "--output", str(d / "analysis.json"),
        "--html-output", str(d / "dashboard.html"),
        "--verify",
        *_model_args(),
        "--verify-output", str(d / "verification.json"),
        "--verify-detail-output", str(d / "verification-detail.html"),
        "--ground-truth", DVWA_GROUND_TRUTH,
        "--application-id", "dvwa",
        "--eval-output", str(d / "evaluation.json"),
        "--random-predictor", "--random-safe-weight", "4",
    ]
    return Scenario(name, title, url, args, out)


def _run(scenario: Scenario, out: Path) -> None:
    directory = out / scenario.name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "command.txt").write_text(
        _display_command(scenario.cli_args) + "\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [sys.executable, "-m", "vulnspider", *scenario.cli_args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    safe_stdout = _redact_cookie_output(completed.stdout or "", scenario.cli_args)
    safe_stderr = _redact_cookie_output(completed.stderr or "", scenario.cli_args)
    (directory / "run.log").write_text(
        safe_stdout + safe_stderr,
        encoding="utf-8",
    )
    if completed.returncode == 0 and scenario.eval_path.is_file():
        scenario.status = "ok"
    else:
        scenario.status = "failed"
        tail = "\n".join((safe_stdout or safe_stderr).splitlines()[-3:])
        scenario.detail = tail


def _headline(eval_path: Path) -> tuple[list[int], list[tuple[str, dict[int, dict]]]]:
    payload = json.loads(eval_path.read_text(encoding="utf-8"))
    cutoffs = [int(k) for k in payload["cutoffs"]]
    arms: list[tuple[str, dict[int, dict]]] = []
    for arm in payload["arms"]:
        by_k = {int(row["k"]): row for row in arm["cutoffs"]}
        arms.append((arm["name"], by_k))
    return cutoffs, arms


def _metric_table(eval_path: Path) -> list[str]:
    cutoffs, arms = _headline(eval_path)
    shown = [k for k in (1, 5, 10, 20) if k in cutoffs] or cutoffs[:1]
    header = ["Arm"]
    for k in shown:
        header += [f"P@{k}", f"R@{k}", f"MAP@{k}"]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join(["---"] * len(header)) + " |"]
    for name, by_k in arms:
        label = f"**{name}**" if "full pipeline" in name.lower() else name
        cells = [label]
        for k in shown:
            row = by_k[k]
            cells += [
                f"{row['precision_at_k']:.3f}",
                f"{row['recall_at_k']:.3f}",
                f"{row['map_at_k']:.3f}",
            ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def _verification_note(eval_path: Path) -> str:
    """One line on what focused verification changed, read from the numbers."""

    cutoffs, arms = _headline(eval_path)
    named = dict(arms)
    before = next((v for k, v in named.items() if "without" in k.lower()), None)
    after = next((v for k, v in named.items() if "full pipeline" in k.lower()), None)
    if before is None or after is None:
        return ""
    changes: list[str] = []
    for k in cutoffs:
        for key, label in (("precision_at_k", "P"), ("recall_at_k", "R"), ("map_at_k", "MAP"), ("ndcg_at_k", "NDCG")):
            x, y = before[k].get(key), after[k].get(key)
            if x is None or y is None or abs(x - y) < 0.0005:
                continue
            changes.append(f"{label}@{k} {x:.3f}→{y:.3f}")
    if not changes:
        return (
            "- 검증 효과: 검증 전 랭킹이 이미 최적이라 `full pipeline`과 "
            "`without focused verification`의 랭킹 지표가 **동일**하다. 기여는 각 후보의 "
            "**confidence 값**(대시보드·`verification-detail.html`)에서 드러난다."
        )
    return "- 검증 효과: focused verification이 상위 K 안의 순위를 바로잡았다 — " + ", ".join(changes) + "."


def _write_readme(scenarios: list[Scenario], out: Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# VulnSpider 결과 팩",
        "",
        "보고서·시연에 싣는 모든 수치의 **단일 출처**. 아래 실행을 한 번에 캡처한다.",
        "",
        "| 항목 | 값 |",
        "| --- | --- |",
        f"| 생성 시각 | {now} |",
        f"| VulnSpider 버전 | {__version__} |",
        f"| git 커밋 | {_git_commit()} |",
        f"| Python | {sys.version.split()[0]} |",
        f"| 검증 모델 | {'있음 (' + VERIFICATION_MODEL + ')' if (ROOT / VERIFICATION_MODEL).is_file() else '내장 기본값'} |",
        f"| 랜덤 예측기 | per-input-point, safe-weight 4, 시드 0, 1000 trials |",
        "",
        "각 시나리오 폴더에는 `dashboard.html`, `verification-detail.html`, "
        "`evaluation.json`, `evaluation-table.{md,html}`(3-arm 비교), "
        "`evaluation-inputs.{md,html}`(입력점별 취약 유형), `command.txt`, "
        "`run.log`가 들어 있다.",
        "",
        "> 참고: `VulnSpider (full pipeline)`은 `without focused verification`의 상위 K 후보를 "
        "focused verification으로 재검증한 뒤의 랭킹이다. 두 arm의 지표가 같으면 검증이 "
        "순위를 바꿀 여지가 없었다는 뜻이고, 다르면 검증이 경계의 후보를 바로잡은 것이다 — "
        "시나리오별 '검증 효과' 줄이 실제 수치로 말해 준다. 랭킹은 응답 바이트에 민감하므로 "
        "타깃 HTML이 바뀌면 수치는 이 팩을 다시 생성해서 인용한다.",
        "",
    ]
    for scenario in scenarios:
        lines.append(f"## {scenario.title}")
        lines.append("")
        lines.append(f"- 대상: `{scenario.target}`")
        lines.append(f"- 폴더: [`{scenario.name}/`]({scenario.name}/)")
        lines.append(f"- 상태: **{scenario.status}**"
                     + (f" — {scenario.detail}" if scenario.detail else ""))
        lines.append("")
        if scenario.status == "ok":
            lines.append("```bash")
            lines.append(_display_command(scenario.cli_args))
            lines.append("```")
            lines.append("")
            lines.extend(_metric_table(scenario.eval_path))
            lines.append("")
            note = _verification_note(scenario.eval_path)
            if note:
                lines.append(note)
                lines.append("")
    (out / "README.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the VulnSpider results pack.")
    parser.add_argument("--out", default=DEFAULT_OUT, type=Path)
    parser.add_argument("--port", default=demo_shop.PORT, type=int)
    parser.add_argument("--top-k", default=10, type=int)
    parser.add_argument("--dvwa-sqli-url", default=None)
    parser.add_argument("--dvwa-xss-url", default=None)
    parser.add_argument("--dvwa-cookie", action="append", default=[])
    parser.add_argument(
        "--skip-demoshop",
        action="store_true",
        help="Only run the external DVWA targets that were supplied.",
    )
    args = parser.parse_args()

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    scenarios: list[Scenario] = []
    server = None
    thread = None
    if not args.skip_demoshop:
        if not _free(args.port):
            print(f"[!] port {args.port} is in use; free it or pass --port", file=sys.stderr)
            return 2
        server = demo_shop.build_server(args.port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"[*] DemoShop serving on 127.0.0.1:{args.port}")
        scenarios.append(_demoshop_public(out, args.port, args.top_k))
        scenarios.append(_demoshop_bac(out, args.port, args.top_k))

    if args.dvwa_sqli_url:
        scenarios.append(
            _dvwa("dvwa-sqli", "DVWA — SQL Injection (`/vulnerabilities/sqli/`)",
                  args.dvwa_sqli_url, args.dvwa_cookie, out)
        )
    if args.dvwa_xss_url:
        scenarios.append(
            _dvwa("dvwa-xss", "DVWA — Reflected XSS (`/vulnerabilities/xss_r/`)",
                  args.dvwa_xss_url, args.dvwa_cookie, out)
        )

    if not scenarios:
        print("[!] nothing to run (--skip-demoshop with no DVWA URLs)", file=sys.stderr)
        return 2

    try:
        for scenario in scenarios:
            print(f"[*] running {scenario.name} ...", flush=True)
            _run(scenario, out)
            print(f"    -> {scenario.status}{': ' + scenario.detail if scenario.detail else ''}")
    finally:
        if server is not None:
            server.shutdown()

    _write_readme(scenarios, out)
    ok = sum(1 for s in scenarios if s.status == "ok")
    print(f"\n[*] results pack: {ok}/{len(scenarios)} scenarios ok -> {out / 'README.md'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
