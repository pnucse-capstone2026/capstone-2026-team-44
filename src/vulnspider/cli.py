"""Command-line entrypoint for the VulnSpider prototype."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from tqdm import tqdm  # 진행률 바를 위해 추가

from vulnspider import __version__
from vulnspider.cli_branding import detect_capabilities, write_banner
from vulnspider.cli_decision import (
    CalibrationError,
    ConformalError,
    CorpusError,
    CorpusFittingError,
    DecisionCLIError,
    EvaluationRequest,
    GroundTruthError,
    add_algorithm_options,
    add_decision_subcommands,
    analyze_and_report,
    rank_analysis,
    run_corpus_command,
    verification_selection,
)
from vulnspider.evaluation.live import DEFAULT_CUTOFFS, LiveEvaluationError
from vulnspider.evaluation.random_predictor import RandomPredictor
from vulnspider.discovery import (
    CombinedDiscoveryResult,
    CrawlPolicy,
    DiscoveryContractError,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicCapabilityError,
    DynamicCrawler,
    DynamicCrawlerError,
    DynamicCrawlPolicy,
    DynamicIntegrityError,
    DynamicRequestAuthority,
    DynamicResourceGrant,
    DynamicResourceKind,
    StaticCrawler,
    StaticCrawlResult,
    StaticCrawlerTransport,
)
from vulnspider.domain import Endpoint
from vulnspider.observation.executor import RequestTransport
from vulnspider.pipeline import (
    AnalysisResult,
    analyze_legacy_records,
    analyze_url,
)
from vulnspider.reporting import write_crawl_report
from vulnspider.reporting.crawl_report import build_crawl_report
from vulnspider.reporting.json_report import write_json_document
from vulnspider.reporting.verification_detail_report import (
    build_verification_detail_html,
)
from vulnspider.verification import (
    LLM_MODEL_PATH_ENV,
    DeterministicMutationProposer,
    LLMProposerError,
    LocalLLMMutationProposer,
    PayloadProposer,
    VerificationConfidenceModel,
    VerificationConfig,
    verify_analysis,
)
from vulnspider.verification.access_verify import AccessVerificationConfig


_SIMPLE_DEFAULT_CRAWL_OUTPUT = Path("vulnspider-crawl.json")
_SIMPLE_DEFAULT_ANALYSIS_OUTPUT = Path("vulnspider-analysis.json")
_SIMPLE_DEFAULT_HTML_OUTPUT = Path("vulnspider-report.html")
_DEFAULT_VERIFICATION_OUTPUT = Path("vulnspider-verification.json")
_DEFAULT_EVALUATION_OUTPUT = Path("vulnspider-evaluation.json")
_DEFAULT_VERIFY_DETAIL_OUTPUT = Path("vulnspider-verification-detail.html")
_SIMPLE_DEFAULT_TOP_K = 10
_MAX_TOP_K = 20
_SIMPLE_DEFAULT_DYNAMIC_MAX_DEPTH = 2
_DYNAMIC_DEGRADATION_WARNING_CODES = frozenset(
    {
        "DYNAMIC_CLEANUP_INCOMPLETE",
        "DYNAMIC_DEPTH_BUDGET_EXHAUSTED",
        "DYNAMIC_ELAPSED_BUDGET_EXHAUSTED",
        "DYNAMIC_HTTP_ERROR",
        "DYNAMIC_NAVIGATION_BUDGET_EXHAUSTED",
        "DYNAMIC_OPERATIONAL_FAILURE",
        "DYNAMIC_PAGE_BUDGET_EXHAUSTED",
    }
)
_DYNAMIC_RUNTIME_ERROR_CODES = frozenset(
    {
        DynamicBrowserErrorCode.PLAYWRIGHT_START_FAILED,
        DynamicBrowserErrorCode.BROWSER_LAUNCH_FAILED,
        DynamicBrowserErrorCode.CONTEXT_CREATE_FAILED,
        DynamicBrowserErrorCode.PAGE_CREATE_FAILED,
    }
)

# `analyze` and simple `-u` mode run the calibrated Top-K algorithm directly, so
# `decide` no longer exists. This maps only the corpus-building tooling.
_DECISION_COMMANDS = {
    "corpus": run_corpus_command,
}


class CLIError(ValueError):
    """Raised for normal user-facing CLI input errors."""


class _SimpleDegradedCrawl(RuntimeError):
    """Stop the simple adapter before probes when crawl is degraded."""

    def __init__(self, crawl: CombinedDiscoveryResult) -> None:
        super().__init__(crawl.dynamic_crawl.termination_reason.value)
        self.crawl = crawl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnspider",
        description="VulnSpider prototype command line interface.",
        # Simple-mode --dynamic-allow-* options otherwise make the analyze
        # subcommand's --dynamic an ambiguous top-level abbreviation.
        allow_abbrev=False,
        epilog=(
            "Simple scan: vulnspider -u http://127.0.0.1:8080/ "
            "[--crawl-output crawl.json] [-o analysis.json] [--static-only]. "
            "Defaults: vulnspider-crawl.json and vulnspider-analysis.json."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--no-banner",
        dest="simple_no_banner",
        action="store_true",
        help="Do not show the interactive VulnSpider startup banner.",
    )
    parser.add_argument(
        "-u",
        "--url",
        dest="simple_url",
        help="Run the simple bounded scan for an authorized loopback URL.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="simple_output",
        type=Path,
        default=None,
        help="Analysis JSON file (default: vulnspider-analysis.json).",
    )
    parser.add_argument(
        "-k",
        "--top-k",
        dest="simple_top_k",
        type=_bounded_top_k,
        default=None,
        help=(
            "Number of top candidates to select and verify "
            f"(default: {_SIMPLE_DEFAULT_TOP_K}, max: {_MAX_TOP_K})."
        ),
    )
    parser.add_argument(
        "--crawl-output",
        dest="simple_crawl_output",
        type=Path,
        default=None,
        help="Crawl JSON file (default: vulnspider-crawl.json).",
    )
    parser.add_argument(
        "--html-output",
        dest="simple_html_output",
        type=Path,
        default=None,
        help=(
            "End-to-end HTML dashboard report; this is the primary report in "
            f"simple mode (default: {_SIMPLE_DEFAULT_HTML_OUTPUT}). Use "
            "--no-html to skip it."
        ),
    )
    parser.add_argument(
        "--no-html",
        dest="simple_no_html",
        action="store_true",
        help="Skip the HTML dashboard report in simple mode.",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Use Native Static Discovery only in simple URL mode.",
    )
    parser.add_argument(
        "--dynamic-allow-navigation",
        action="append",
        default=None,
        dest="simple_dynamic_allow_navigation",
        metavar="URL",
        help="Add one exact same-origin navigation grant in simple mode.",
    )
    parser.add_argument(
        "--dynamic-allow-resource",
        action="append",
        default=None,
        dest="simple_dynamic_allow_resource",
        metavar="CATEGORY=URL",
        help="Add one exact same-origin resource grant in simple mode.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        dest="simple_verify",
        help="Run focused verification and write a verification JSON report.",
    )
    parser.add_argument(
        "--verify-output",
        type=Path,
        default=None,
        dest="simple_verify_output",
        help=(
            "Verification JSON file in simple mode (implies --verify; "
            f"default: {_DEFAULT_VERIFICATION_OUTPUT})."
        ),
    )
    parser.add_argument(
        "--verification-model",
        type=Path,
        default=None,
        dest="simple_verification_model",
        help="Fitted confidence model JSON from 'corpus verify-fit'.",
    )
    parser.add_argument(
        "--verify-detail-output",
        type=Path,
        default=None,
        dest="simple_verify_detail_output",
        help=(
            "Per-input-point verification detail HTML in simple mode "
            "(default: alongside the dashboard as *-detail.html)."
        ),
    )
    parser.add_argument(
        "--no-verify-detail",
        action="store_true",
        dest="simple_no_verify_detail",
        help="Skip the per-input-point verification detail HTML report.",
    )
    parser.add_argument(
        "--verify-proposer",
        choices=("deterministic", "llm"),
        default="deterministic",
        dest="simple_verify_proposer",
        help=(
            "Payload proposer for verification: 'deterministic' (default) or "
            "'llm' (local fine-tuned vulnspider-3b GGUF). LLM suggestions still "
            "pass the deterministic validator."
        ),
    )
    parser.add_argument(
        "--llm-model",
        type=Path,
        default=None,
        dest="simple_llm_model",
        help=(
            "Path to the local vulnspider-3b GGUF model for --verify-proposer "
            f"llm (default: ${LLM_MODEL_PATH_ENV})."
        ),
    )
    parser.add_argument(
        "--open",
        dest="simple_open_report",
        action="store_true",
        help="When the scan finishes, open the HTML dashboard report in the browser.",
    )
    parser.add_argument(
        "--access-control",
        dest="simple_access_control",
        action="store_true",
        help="Also probe for Broken Access Control in simple mode (opt-in).",
    )
    parser.add_argument(
        "--cookie",
        dest="simple_cookie",
        action="append",
        default=None,
        metavar="NAME=VALUE",
        help=(
            "Send an operator-supplied session cookie on every request "
            "(repeatable). Turns a Broken Access Control scan authenticated. "
            "Requires --static-only in simple mode."
        ),
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=None,
        dest="simple_ground_truth",
        help=(
            "Ground truth JSON for the scanned target. Turns on the ranking "
            "evaluation stage (Recall@K / Precision@K / MAP@K / NDCG@K)."
        ),
    )
    parser.add_argument(
        "--eval-output",
        type=Path,
        default=None,
        dest="simple_eval_output",
        help=(
            "Ranking evaluation JSON in simple mode (implies --ground-truth; "
            f"default: {_DEFAULT_EVALUATION_OUTPUT})."
        ),
    )
    parser.add_argument(
        "--eval-cutoffs",
        type=_positive_integer,
        nargs="+",
        default=None,
        dest="simple_eval_cutoffs",
        metavar="K",
        help=(
            "K values the ranking evaluation reports "
            f"(default: {' '.join(str(k) for k in DEFAULT_CUTOFFS)})."
        ),
    )
    parser.add_argument(
        "--application-id",
        default=None,
        dest="simple_application_id",
        help=(
            "Which application in the ground truth file was scanned. Only "
            "needed when the file covers more than one."
        ),
    )
    parser.add_argument(
        "--random-predictor",
        action="store_true",
        dest="simple_random_predictor",
        help=(
            "Add a random-predictor arm to the ranking evaluation: for each "
            "input point it guesses one of SQLI/XSS/BAC/SAFE at random "
            "(requires --ground-truth)."
        ),
    )
    parser.add_argument(
        "--random-safe-weight",
        type=_non_negative_float,
        default=None,
        dest="simple_random_safe_weight",
        metavar="W",
        help=(
            "Weight the random predictor's SAFE guess by W while each "
            "vulnerability family stays at 1 (default: 1 = uniform; >1 abstains "
            "more; implies --random-predictor)."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a native root URL or legacy crawl-record JSON.",
        description=(
            "Analyze one native static root URL or adapter-compatible legacy "
            "crawl records for authorized localhost or loopback test targets."
        ),
    )
    source = analyze.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--input",
        type=Path,
        help="JSON array of LegacyCrawlerAdapter-compatible crawl records.",
    )
    source.add_argument(
        "--url",
        help="Root URL for bounded native static discovery.",
    )
    analyze.add_argument(
        "--top-k",
        required=True,
        type=_bounded_top_k,
        help=f"Number of unique rankable candidates to select (max: {_MAX_TOP_K}).",
    )
    analyze.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Destination for the deterministic JSON report.",
    )
    analyze.add_argument(
        "--html-output",
        required=False,
        default=None,
        type=Path,
        help=(
            "Optional destination for a static HTML dashboard report "
            "rendering the same data as --output (ADR-011)."
        ),
    )
    analyze.add_argument(
        "--max-pages",
        type=_positive_integer,
        default=None,
        help="Maximum number of HTML pages to process for --url.",
    )
    analyze.add_argument(
        "--max-depth",
        type=_non_negative_integer,
        default=None,
        help="Maximum link depth to schedule for --url.",
    )
    analyze.add_argument(
        "--max-requests",
        type=_positive_integer,
        default=None,
        help="Maximum number of crawler requests for --url.",
    )
    analyze.add_argument(
        "--timeout-seconds",
        type=_positive_number,
        default=None,
        help="Per-request crawler timeout for --url.",
    )
    analyze.add_argument(
        "--max-redirects",
        type=_non_negative_integer,
        default=None,
        help="Maximum redirects followed per URL for --url.",
    )
    analyze.add_argument(
        "--dynamic",
        action="store_true",
        help="Opt in to bounded combined Static and Dynamic discovery.",
    )
    analyze.add_argument(
        "--dynamic-passive-capture",
        action="store_true",
        help=(
            "Observe the page's own same-origin fetch/XHR and resource "
            "requests during Dynamic discovery (SPA/REST-JSON surfaces). Off "
            "by default; requires --dynamic. Enables candidate discovery from "
            "JSON REST endpoints an SPA calls (e.g. OWASP Juice Shop)."
        ),
    )
    analyze.add_argument(
        "--dynamic-allow-navigation",
        action="append",
        default=None,
        metavar="URL",
        help="Allow one exact same-origin Dynamic navigation URL (repeatable).",
    )
    analyze.add_argument(
        "--dynamic-allow-resource",
        action="append",
        default=None,
        metavar="CATEGORY=URL",
        help=(
            "Allow one exact same-origin Dynamic resource URL in category "
            "script, style, or fetch_xhr (repeatable)."
        ),
    )
    analyze.add_argument(
        "--dynamic-max-pages",
        type=_positive_integer,
        default=None,
        help="Maximum rendered pages for combined discovery.",
    )
    analyze.add_argument(
        "--dynamic-max-depth",
        type=_non_negative_integer,
        default=None,
        help="Maximum Dynamic navigation depth.",
    )
    analyze.add_argument(
        "--dynamic-max-navigation-attempts",
        type=_positive_integer,
        default=None,
        help="Maximum Dynamic main-frame navigation attempts.",
    )
    analyze.add_argument(
        "--dynamic-max-route-actions",
        type=_positive_integer,
        default=None,
        help="Maximum passive route actions considered for navigation.",
    )
    analyze.add_argument(
        "--dynamic-max-elapsed-seconds",
        type=_positive_number,
        default=None,
        help="Hard elapsed-time limit for one Dynamic crawl.",
    )
    analyze.add_argument(
        "--dynamic-navigation-timeout-seconds",
        type=_positive_number,
        default=None,
        help="Timeout for each Dynamic main-frame navigation.",
    )
    analyze.add_argument(
        "--dynamic-max-redirects",
        type=_positive_integer,
        default=None,
        help="Maximum redirects followed per Dynamic navigation.",
    )
    analyze.add_argument(
        "--dynamic-request-decision-budget",
        type=_positive_integer,
        default=None,
        help="Maximum browser request-authority decisions.",
    )
    add_algorithm_options(analyze)
    analyze.add_argument(
        "--verify",
        action="store_true",
        help=(
            "After ranking, run focused verification over the Top-K: propose "
            "validated variant payloads, re-probe the loopback target, and "
            "update each candidate's confidence by the reviewed rule set."
        ),
    )
    analyze.add_argument(
        "--verify-output",
        type=Path,
        default=None,
        help=(
            "Destination for the verification JSON report (implies --verify; "
            f"default: {_DEFAULT_VERIFICATION_OUTPUT})."
        ),
    )
    analyze.add_argument(
        "--verification-model",
        type=Path,
        default=None,
        help=(
            "Fitted confidence model JSON from 'corpus verify-fit' "
            "(default: the conservative built-in model)."
        ),
    )
    analyze.add_argument(
        "--verify-detail-output",
        type=Path,
        default=None,
        help=(
            "Destination for the per-input-point verification detail HTML "
            "report (implies --verify). Defaults to the dashboard path with a "
            f"-detail suffix, else {_DEFAULT_VERIFY_DETAIL_OUTPUT}."
        ),
    )
    analyze.add_argument(
        "--no-verify-detail",
        action="store_true",
        help="Skip the per-input-point verification detail HTML report.",
    )
    analyze.add_argument(
        "--verify-proposer",
        choices=("deterministic", "llm"),
        default="deterministic",
        help=(
            "Which payload proposer focused verification uses: the reproducible "
            "'deterministic' baseline (default), or 'llm' to suggest variants "
            "with the local fine-tuned vulnspider-3b GGUF model. Every "
            "suggestion still passes the same deterministic validator before it "
            "is sent."
        ),
    )
    analyze.add_argument(
        "--llm-model",
        type=Path,
        default=None,
        help=(
            "Path to the local vulnspider-3b GGUF model for --verify-proposer "
            f"llm (default: the ${LLM_MODEL_PATH_ENV} environment variable)."
        ),
    )
    analyze.add_argument(
        "--open",
        dest="open_report",
        action="store_true",
        help="When the run finishes, open the HTML dashboard report in the browser.",
    )
    analyze.add_argument(
        "--access-control",
        dest="access_control",
        action="store_true",
        help=(
            "Also probe for Broken Access Control (credential-strip / "
            "identifier-substitution GET re-sends). Adds extra requests, so it "
            "is opt-in."
        ),
    )
    analyze.add_argument(
        "--verify-links",
        dest="verify_links",
        action="store_true",
        help=(
            "Add a live '취약점 검증' link to each candidate in the HTML "
            "dashboard that opens the target's /_verify endpoint (the "
            "DemoShop demo). No effect on the report without this flag."
        ),
    )
    analyze.add_argument(
        "--cookie",
        action="append",
        default=None,
        metavar="NAME=VALUE",
        help=(
            "Send an operator-supplied session cookie on every request "
            "(repeatable). This is how a Broken Access Control scan is given a "
            "logged-in session: protected resources answer 200 and are "
            "discovered, and every request template carries the credential so "
            "--access-control can strip it. Static discovery only (not "
            "--dynamic). Read-only GET; VulnSpider never logs in itself."
        ),
    )
    analyze.add_argument(
        "--ground-truth",
        type=Path,
        default=None,
        help=(
            "Ground truth JSON for the scanned target (the evaluation "
            "protocol's key). Turns on the ranking evaluation stage, which "
            "scores this run's ranking as Recall@K / Precision@K / MAP@K / "
            "NDCG@K against a random predictor and against the same run with "
            "focused verification removed."
        ),
    )
    analyze.add_argument(
        "--eval-output",
        type=Path,
        default=None,
        help=(
            "Destination for the ranking evaluation JSON (implies "
            f"--ground-truth; default: {_DEFAULT_EVALUATION_OUTPUT})."
        ),
    )
    analyze.add_argument(
        "--eval-cutoffs",
        type=_positive_integer,
        nargs="+",
        default=None,
        metavar="K",
        help=(
            "K values the ranking evaluation reports "
            f"(default: {' '.join(str(k) for k in DEFAULT_CUTOFFS)})."
        ),
    )
    analyze.add_argument(
        "--application-id",
        default=None,
        help=(
            "Which application in the ground truth file was scanned. Only "
            "needed when the file covers more than one."
        ),
    )
    analyze.add_argument(
        "--random-predictor",
        action="store_true",
        help=(
            "Add a random-predictor arm to the ranking evaluation: for each "
            "input point it guesses one of SQLI/XSS/BAC/SAFE at random "
            "(requires --ground-truth)."
        ),
    )
    analyze.add_argument(
        "--random-safe-weight",
        type=_non_negative_float,
        default=None,
        metavar="W",
        help=(
            "Weight the random predictor's SAFE guess by W while each "
            "vulnerability family stays at 1 (default: 1 = uniform; >1 abstains "
            "more; implies --random-predictor)."
        ),
    )
    add_decision_subcommands(subparsers)
    return parser


def main(
    argv: list[str] | None = None,
    *,
    transport: RequestTransport | None = None,
    crawler_transport: StaticCrawlerTransport | None = None,
    crawler: StaticCrawler | None = None,
    dynamic_crawler: DynamicCrawler | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    simple_mode = args.command is None and args.simple_url is not None
    crawl_published = False
    selected_count = 0
    verification_output: Path | None = None
    verification_detail_output: Path | None = None
    if args.command is None and not simple_mode:
        if _simple_options_without_url(args):
            parser.error("simple scan options require -u/--url")
        _write_start_banner(args)
        parser.print_help()
        return 0
    if args.command in _DECISION_COMMANDS:
        handler = _DECISION_COMMANDS[args.command]
        try:
            return handler(
                args,
                transport=transport,
                crawler=crawler,
                crawler_transport=crawler_transport,
            )
        except (
            DecisionCLIError,
            CorpusError,
            CorpusFittingError,
            GroundTruthError,
            CalibrationError,
            ConformalError,
        ) as exc:
            print(f"vulnspider: error: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"vulnspider: error: {exc}", file=sys.stderr)
            return 1
    if args.command != "analyze":
        if not simple_mode:
            parser.error(f"unsupported command: {args.command}")
    if simple_mode:
        _write_start_banner(args)
    stage = "초기화"
    pbar = tqdm(
        total=4,
        desc="(초기화)",
        bar_format="진행 상태: |{bar}| {n_fmt}/{total_fmt} 단계 {postfix}",
        colour="green",
        ncols=100,
        file=sys.stderr,
    )
    try:
        pbar.set_postfix_str(stage)
        pbar.update(1)
        time.sleep(0.5)
        if simple_mode:
            args = _simple_analysis_args(args)
        _reject_shared_report_destinations(args.output, args.html_output)
        if simple_mode:
            _reject_shared_crawl_analysis_destinations(
                args.crawl_output,
                args.output,
            )
            if args.html_output is not None and _normalized_destination(
                args.html_output
            ) == _normalized_destination(args.crawl_output):
                raise CLIError(
                    "--html-output and --crawl-output must refer to different files"
                )
        if args.verify or args.verify_output is not None:
            _reject_shared_verify_destination(
                args.verify_output or _DEFAULT_VERIFICATION_OUTPUT,
                (
                    args.output,
                    args.html_output,
                    args.crawl_output if simple_mode else None,
                ),
            )
        evaluation_request = _evaluation_request_from_args(
            args,
            other_destinations=(
                args.output,
                args.html_output,
                args.crawl_output if simple_mode else None,
                args.verify_output or _DEFAULT_VERIFICATION_OUTPUT,
            ),
        )
        stage = "크롤 + 분석"
        pbar.set_postfix_str(stage)
        pbar.update(1) # 2단계: 크롤+분석 진입
        time.sleep(0.5)

        if args.input is None:
            args.url = _normalize_scan_url(args.url)

        _progress(
            f"[*] {stage} 시작 -> "
            f"{args.url if args.input is None else args.input}"
        )
        if args.input is not None:
            _reject_native_policy_with_legacy_input(args)
            records = _load_legacy_records(args.input)
            analysis = analyze_legacy_records(
                records,
                top_k=args.top_k,
                transport=transport,
                enable_access=args.access_control,
            )
        else:
            _reject_dynamic_options_without_opt_in(args)
            dynamic_authority = (
                _dynamic_authority_from_args(args, simple_mode=simple_mode)
                if args.dynamic
                else None
            )
            on_crawl_validated = None
            if simple_mode:

                def publish_crawl(
                    crawl: StaticCrawlResult | CombinedDiscoveryResult,
                ) -> None:
                    nonlocal crawl_published
                    write_crawl_report(crawl, args.crawl_output)
                    crawl_published = True
                    if (
                        type(crawl) is CombinedDiscoveryResult
                        and crawl.degraded
                    ):
                        raise _SimpleDegradedCrawl(crawl)

                on_crawl_validated = publish_crawl
            analysis = analyze_url(
                args.url,
                top_k=args.top_k,
                crawl_policy=_crawl_policy_from_args(args),
                crawler=crawler,
                crawler_transport=crawler_transport,
                dynamic_authority=dynamic_authority,
                dynamic_policy=(
                    _dynamic_policy_from_args(args, simple_mode=simple_mode)
                    if args.dynamic
                    else None
                ),
                dynamic_crawler=(dynamic_crawler if args.dynamic else None),
                transport=transport,
                on_crawl_validated=on_crawl_validated,
                elide_sensitive_forms=simple_mode,
                enable_access=args.access_control,
            )
            if simple_mode and not crawl_published:
                raise CLIError("pipeline did not publish a validated crawl result")
        if (
            simple_mode
            and analysis.combined_result is not None
            and analysis.combined_result.degraded
        ):
            _print_partial_simple_result(args)
            _print_dynamic_incomplete(analysis.combined_result)
            return 4
        _progress(
            "[OK] 분석 완료 -- "
            f"endpoints={len(analysis.endpoints)}, "
            f"input_points={len(analysis.input_points)}"
        )
        verification_run = None
        access_verify_config = None
        ranking = None
        if args.verify or args.verify_output is not None:
            stage = "검증 (focused verification)"
            # Rank before verifying: focused verification must visit the
            # candidates the report ranks, not the v0.1 heuristic Top-K, which
            # is a different set as soon as the calibrated probability reorders
            # anything.
            pbar.set_postfix_str(stage)
            pbar.update(1) # 3단계: 검증 진입
            time.sleep(0.5)
            ranking = rank_analysis(
                analysis,
                top_k=args.top_k,
                model_path=args.model,
                conformal_path=args.conformal,
            )
            confidence_model = _load_verification_model(args.verification_model)
            proposer = _build_verification_proposer(args)
            proposer_kind = getattr(args, "verify_proposer", "deterministic")
            _progress(
                f"[*] {stage} 시작 -- proposer={proposer_kind}, top-k={args.top_k}"
            )
            if proposer_kind == "llm":
                _progress(
                    "    로컬 LLM 모델 로딩 중 (최초 1회, 수 초~수십 초 소요될 수 있음) …"
                )
            verification_progress = _VerificationProgressTimer()
            verification_run = verify_analysis(
                analysis,
                config=VerificationConfig(
                    proposer=proposer,
                    transport=transport,
                    confidence_model=confidence_model,
                    max_candidates=args.top_k,
                    progress=verification_progress,
                ),
                selection=verification_selection(ranking),
            )

            verification_progress.finish()
            _counts = verification_run.counts()
            _progress(
                "[OK] 검증 완료 -- "
                f"후보 {_counts['candidates_verified']}, "
                f"제안 {_counts['proposals']}, "
                f"통과 {_counts['accepted']}/차단 {_counts['rejected']}, "
                f"supported {_counts['supported']}, "
                f"weakened {_counts['weakened']}, "
                f"unchanged {_counts['unchanged']}"
            )
            access_verify_config = AccessVerificationConfig(
                transport=transport,
                confidence_model=confidence_model,
            )
        else:
            pbar.update(1)

        stage = "리포트 작성"
        pbar.set_postfix_str(stage)
        pbar.update(1) # 4단계: 리포트 작성 진입
        time.sleep(0.5)

        _progress(f"[*] {stage} 시작 …")
        outcome = analyze_and_report(
            analysis,
            target_url=_analysis_target(analysis),
            top_k=args.top_k,
            model_path=args.model,
            conformal_path=args.conformal,
            output=args.output,
            html_output=args.html_output,
            verification=verification_run,
            access_verify_config=access_verify_config,
            evaluation=evaluation_request,
            ranking=ranking,
            verify_links=getattr(args, "verify_links", False),
        )
        selected_count = len(outcome.selected)
        if verification_run is not None:
            verify_destination = args.verify_output or _DEFAULT_VERIFICATION_OUTPUT
            verification_output = _publish_verification(
                verification_run,
                analysis,
                destination=verify_destination,
                other_destinations=(
                    args.output,
                    args.html_output,
                    args.crawl_output if simple_mode else None,
                ),
            )
            if not getattr(args, "no_verify_detail", False):
                verification_detail_output = _publish_verification_detail(
                    verification_run,
                    analysis,
                    destination=_verify_detail_destination(args),
                    other_destinations=(
                        args.output,
                        args.html_output,
                        verify_destination,
                        args.crawl_output if simple_mode else None,
                    ),
                )
        _progress("[OK] 리포트 작성 완료")

        pbar.close()
    except _SimpleDegradedCrawl as exc:
        _print_partial_simple_result(args)
        _print_dynamic_incomplete(exc.crawl)
        return 4
    except (DiscoveryContractError, DynamicIntegrityError, DynamicCrawlerError):
        if simple_mode and crawl_published:
            _print_partial_simple_result(args)
        print(
            "vulnspider: error: DYNAMIC_INTEGRITY: "
            "combined discovery failed validation",
            file=sys.stderr,
        )
        return 3
    except DynamicCapabilityError as exc:
        if simple_mode and crawl_published:
            _print_partial_simple_result(args)
        print(
            f"vulnspider: error: {exc.code.value}: {exc}; {exc.setup_hint}",
            file=sys.stderr,
        )
        return 2
    except DynamicBrowserError as exc:
        if simple_mode and crawl_published:
            _print_partial_simple_result(args)
        if exc.code == DynamicBrowserErrorCode.INVALID_AUTHORITY:
            print(
                f"vulnspider: error: {exc.code.value}: {exc}",
                file=sys.stderr,
            )
            return 2
        print(
            f"vulnspider: error: DYNAMIC_INCOMPLETE: {exc.code.value}",
            file=sys.stderr,
        )
        return 4
    except (LiveEvaluationError, GroundTruthError) as exc:
        _progress("[ERROR] '평가 지표' 단계에서 실패했습니다")
        print(f"vulnspider: error [평가 지표]: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        if simple_mode and crawl_published:
            _print_partial_simple_result(args)
        _progress(f"[ERROR] '{stage}' 단계에서 실패했습니다")
        print(
            f"vulnspider: error [{stage}]: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    if analysis.combined_result is not None and analysis.combined_result.degraded:
        return 4
    _print_completion(
        args,
        simple_mode=simple_mode,
        selected_count=selected_count,
        verification_output=verification_output,
        verification_detail_output=verification_detail_output,
    )
    return 0


def _evaluation_request_from_args(
    args: argparse.Namespace,
    *,
    other_destinations: Sequence[Path | None],
) -> EvaluationRequest | None:
    """Build the optional ranking-evaluation stage's request, if asked for."""

    want_random = bool(args.random_predictor) or args.random_safe_weight is not None
    if args.ground_truth is None:
        if (
            args.eval_output is not None
            or args.eval_cutoffs is not None
            or want_random
        ):
            raise CLIError(
                "--eval-output, --eval-cutoffs, and --random-predictor require "
                "--ground-truth"
            )
        return None
    if not args.ground_truth.is_file():
        raise CLIError(f"--ground-truth file not found: {args.ground_truth}")
    output = args.eval_output or _DEFAULT_EVALUATION_OUTPUT
    normalized = _normalized_destination(output)
    for other in other_destinations:
        if other is not None and _normalized_destination(other) == normalized:
            raise CLIError(
                "--eval-output must differ from the analysis, HTML, crawl, "
                "and verification report destinations"
            )
    random_predictor = None
    if want_random:
        safe_weight = (
            1.0 if args.random_safe_weight is None else args.random_safe_weight
        )
        random_predictor = RandomPredictor.with_safe_weight(safe_weight)
    return EvaluationRequest(
        ground_truth_path=args.ground_truth,
        output=output,
        cutoffs=tuple(args.eval_cutoffs or DEFAULT_CUTOFFS),
        application_id=args.application_id,
        random_predictor=random_predictor,
    )


def _simple_options_without_url(args: argparse.Namespace) -> bool:
    return bool(
        args.simple_output is not None
        or args.simple_crawl_output is not None
        or args.static_only
        or args.simple_dynamic_allow_navigation
        or args.simple_dynamic_allow_resource
        or args.simple_verify
        or args.simple_verify_output is not None
        or args.simple_verification_model is not None
        or args.simple_verify_detail_output is not None
        or args.simple_no_verify_detail
        or args.simple_html_output is not None
        or args.simple_no_html
        or args.simple_top_k is not None
        or args.simple_access_control
        or args.simple_ground_truth is not None
        or args.simple_eval_output is not None
        or args.simple_eval_cutoffs is not None
        or args.simple_application_id is not None
        or args.simple_random_predictor
        or args.simple_random_safe_weight is not None
        or args.simple_cookie is not None
        or args.simple_no_banner
    )


def _write_start_banner(args: argparse.Namespace) -> None:
    capabilities = detect_capabilities(
        sys.stderr,
        hidden=bool(args.simple_no_banner),
    )
    write_banner(sys.stderr, capabilities)


def _simple_analysis_args(args: argparse.Namespace) -> argparse.Namespace:
    if args.static_only and (
        args.simple_dynamic_allow_navigation
        or args.simple_dynamic_allow_resource
    ):
        raise CLIError(
            "--dynamic-allow-* cannot be combined with --static-only"
        )
    return argparse.Namespace(
        command="analyze",
        input=None,
        url=args.simple_url,
        top_k=args.simple_top_k or _SIMPLE_DEFAULT_TOP_K,
        output=args.simple_output or _SIMPLE_DEFAULT_ANALYSIS_OUTPUT,
        crawl_output=(
            args.simple_crawl_output or _SIMPLE_DEFAULT_CRAWL_OUTPUT
        ),
        html_output=(
            None
            if args.simple_no_html
            else (args.simple_html_output or _SIMPLE_DEFAULT_HTML_OUTPUT)
        ),
        model=None,
        conformal=None,
        verify=(
            args.simple_verify
            or args.simple_verify_output is not None
            or args.simple_verification_model is not None
        ),
        verify_output=args.simple_verify_output,
        verification_model=args.simple_verification_model,
        verify_detail_output=args.simple_verify_detail_output,
        no_verify_detail=args.simple_no_verify_detail,
        verify_proposer=args.simple_verify_proposer,
        llm_model=args.simple_llm_model,
        open_report=args.simple_open_report,
        access_control=args.simple_access_control,
        cookie=args.simple_cookie,
        ground_truth=args.simple_ground_truth,
        eval_output=args.simple_eval_output,
        eval_cutoffs=args.simple_eval_cutoffs,
        application_id=args.simple_application_id,
        random_predictor=args.simple_random_predictor,
        random_safe_weight=args.simple_random_safe_weight,
        max_pages=None,
        max_depth=None,
        max_requests=None,
        timeout_seconds=None,
        max_redirects=None,
        dynamic=not args.static_only,
        dynamic_allow_navigation=args.simple_dynamic_allow_navigation,
        dynamic_allow_resource=args.simple_dynamic_allow_resource,
        dynamic_max_pages=None,
        dynamic_max_depth=None,
        dynamic_max_navigation_attempts=None,
        dynamic_max_route_actions=None,
        dynamic_max_elapsed_seconds=None,
        dynamic_navigation_timeout_seconds=None,
        dynamic_max_redirects=None,
        dynamic_request_decision_budget=None,
    )


def _publish_verification(
    run: Any,
    analysis: AnalysisResult,
    *,
    destination: Path,
    other_destinations: Sequence[Path | None],
) -> Path:
    """Atomically publish an already-computed verification run as JSON."""

    write_json_document(
        json.dumps(
            run.to_dict(target_url=_analysis_target(analysis)),
            indent=2,
            sort_keys=False,
        )
        + "\n",
        destination,
    )
    return destination


def _verify_detail_destination(args: argparse.Namespace) -> Path:
    """Where the per-input-point detail report is written.

    An explicit ``--verify-detail-output`` wins. Otherwise it sits next to the
    dashboard (``dashboard.html`` -> ``dashboard-detail.html``) so the two
    reports travel together, falling back to a fixed default when no dashboard
    is produced.
    """

    explicit = getattr(args, "verify_detail_output", None)
    if explicit is not None:
        return explicit
    html_output = getattr(args, "html_output", None)
    if html_output is not None:
        return html_output.with_name(f"{html_output.stem}-detail{html_output.suffix}")
    return _DEFAULT_VERIFY_DETAIL_OUTPUT


def _publish_verification_detail(
    run: Any,
    analysis: AnalysisResult,
    *,
    destination: Path,
    other_destinations: Sequence[Path | None],
) -> Path:
    """Render and write the per-input-point verification detail HTML report.

    Reuses the exact objects the run already produced: the verification report
    dict and, when native discovery ran, a crawl report dict so every baseline
    and mutated value renders as a full request URL. Nothing is recomputed.
    """

    normalized = _normalized_destination(destination)
    for other in other_destinations:
        if other is not None and _normalized_destination(other) == normalized:
            raise CLIError(
                "--verify-detail-output must differ from the analysis, "
                "dashboard, verification, and crawl report destinations"
            )
    crawl_source = analysis.combined_result or analysis.crawl_result
    crawl_report = (
        build_crawl_report(crawl_source) if crawl_source is not None else None
    )
    document = build_verification_detail_html(
        run.to_dict(target_url=_analysis_target(analysis)),
        crawl_report,
        source="focused verification (in-memory)",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
    return destination


def _reject_shared_verify_destination(
    destination: Path,
    other_destinations: Sequence[Path | None],
) -> None:
    normalized = _normalized_destination(destination)
    for other in other_destinations:
        if other is not None and _normalized_destination(other) == normalized:
            raise CLIError(
                "--verify-output must differ from the analysis, HTML, and "
                "crawl report destinations"
            )


def _build_verification_proposer(args: argparse.Namespace) -> PayloadProposer:
    """Select the focused-verification proposer from the CLI flags.

    The default reproducible baseline, or the local fine-tuned vulnspider-3b
    GGUF model behind the same validator gate. The model path comes from
    --llm-model or the environment; a missing model surfaces as a CLIError
    before any request is sent.
    """

    proposer_kind = getattr(args, "verify_proposer", "deterministic")
    if proposer_kind != "llm":
        return DeterministicMutationProposer()
    model_path = getattr(args, "llm_model", None)
    resolved = str(model_path) if model_path is not None else os.environ.get(
        LLM_MODEL_PATH_ENV
    )
    if not resolved:
        raise CLIError(
            "--verify-proposer llm requires the vulnspider-3b GGUF model: pass "
            f"--llm-model PATH or set ${LLM_MODEL_PATH_ENV}"
        )
    if not Path(resolved).is_file():
        raise CLIError(f"--llm-model path does not exist: {resolved}")
    try:
        return LocalLLMMutationProposer(model_path=resolved)
    except LLMProposerError as exc:
        raise CLIError(str(exc)) from exc


def _progress(message: str) -> None:
    """Emit a pipeline-stage progress line to stderr (stdout stays data-only)."""

    #print(f"vulnspider: {message}", file=sys.stderr, flush=True)
    tqdm.write(f"vulnspider: {message}", file=sys.stderr)
    tqdm.write("", file=sys.stderr)


class _VerificationProgressTimer:
    """Measure wall-clock time for each focused-verification candidate."""

    def __init__(self) -> None:
        self._started_at: float | None = None
        self._last_label: str | None = None
        self._last_index: int | None = None
        self._last_total: int | None = None

    def __call__(self, index: int, total: int, target: Any) -> None:
        now = time.perf_counter()

        # 다음 후보가 시작되는 시점 = 이전 후보가 끝난 시점
        if (
            self._started_at is not None
            and self._last_label is not None
            and self._last_index is not None
            and self._last_total is not None
        ):
            elapsed = now - self._started_at

            _progress(
                f"    - 검증 {self._last_index}/{self._last_total}: "
                f"{self._last_label:<25} "
                f"elapsed time : {elapsed:.2f}s"
            )

        self._started_at = now
        self._last_index = index
        self._last_total = total
        self._last_label = (
            f"{target.vulnerability_type.value} "
            f"rank {target.selection_rank}"
        )

    def finish(self) -> None:
        """Print the final candidate because no next callback follows it."""

        if (
            self._started_at is None
            or self._last_label is None
            or self._last_index is None
            or self._last_total is None
        ):
            return

        elapsed = time.perf_counter() - self._started_at

        _progress(
            f"    - 검증 {self._last_index}/{self._last_total}: "
            f"{self._last_label:<25} "
            f"elapsed time : {elapsed:.2f}s"
        )

        self._started_at = None
        self._last_label = None
        self._last_index = None
        self._last_total = None


def _report_uri(path: Path) -> str:
    """A clickable file:// URI (absolute, forward slashes) for a report path."""

    return path.resolve(strict=False).as_uri()


def _open_report(path: Path) -> bool:
    """Best-effort open of the HTML report in the default browser."""

    import webbrowser

    try:
        return webbrowser.open(_report_uri(path))
    except Exception:  # pragma: no cover - platform/display dependent
        return False


def _print_completion(
    args: argparse.Namespace,
    *,
    simple_mode: bool,
    selected_count: int,
    verification_output: Path | None,
    verification_detail_output: Path | None = None,
) -> None:
    """Final stdout summary with output paths and clickable report links.

    Printed for both the simple and the ``analyze`` mode (the latter had no
    completion output before), so a run always ends by telling the user where
    the reports are. The dashboard and the per-input-point detail report are
    printed as ``file://`` links -- click them to open the report in a browser
    -- and are auto-opened when ``--open`` was given.
    """

    if simple_mode:
        mode = "static-only" if not args.dynamic else "dynamic"
    else:
        mode = "dynamic" if args.dynamic else "static"
    print(f"vulnspider: [OK] scan complete (mode={mode}, selected={selected_count})")
    if simple_mode:
        print(f"vulnspider: crawl output:        {args.crawl_output.resolve(strict=False)}")
    print(f"vulnspider: analysis output:     {args.output.resolve(strict=False)}")
    if verification_output is not None:
        print(
            "vulnspider: verification output: "
            f"{verification_output.resolve(strict=False)}"
        )
    should_open = getattr(args, "open_report", False)
    if args.html_output is not None:
        print(f"vulnspider: dashboard report ->  {_report_uri(args.html_output)}")
    if verification_detail_output is not None:
        print(
            "vulnspider: detail report ->     "
            f"{_report_uri(verification_detail_output)}"
        )
    if should_open:
        opened = [
            path
            for path in (args.html_output, verification_detail_output)
            if path is not None and _open_report(path)
        ]
        if opened:
            print("vulnspider: (opened the report(s) in your browser)")
        elif args.html_output is not None or verification_detail_output is not None:
            print("vulnspider: (could not auto-open; use the link(s) above)")


def _load_verification_model(path: Path | None) -> VerificationConfidenceModel:
    """Load a fitted confidence model, or the conservative built-in default."""

    if path is None:
        return VerificationConfidenceModel.default()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CLIError(f"could not read verification model {path}: {exc}") from exc
    return VerificationConfidenceModel.from_mapping(payload)


def _analysis_target(analysis: AnalysisResult) -> str:
    if analysis.discovery_result is not None:
        return analysis.discovery_result.scope_metadata.root_url
    return _target_label(analysis.endpoints)


def _target_label(endpoints: Sequence[Endpoint]) -> str:
    origins = sorted({f"{endpoint.scheme}://{endpoint.host}" for endpoint in endpoints})
    return ", ".join(origins)


def _reject_shared_report_destinations(
    json_destination: Path,
    html_destination: Path | None,
) -> None:
    if html_destination is None:
        return
    if _normalized_destination(json_destination) == _normalized_destination(
        html_destination
    ):
        raise CLIError("--output and --html-output must refer to different files")


def _reject_shared_crawl_analysis_destinations(
    crawl_destination: Path,
    analysis_destination: Path,
) -> None:
    if _normalized_destination(crawl_destination) == _normalized_destination(
        analysis_destination
    ):
        raise CLIError("--crawl-output and --output must refer to different files")


def _print_partial_simple_result(args: argparse.Namespace) -> None:
    print("vulnspider: scan incomplete (crawl=created, analysis=not-written)")
    print(
        "vulnspider: crawl output: "
        f"{args.crawl_output.resolve(strict=False)}"
    )


def _print_dynamic_incomplete(crawl: CombinedDiscoveryResult) -> None:
    """Print only canonical, secret-free reasons from a degraded crawl."""

    dynamic = crawl.dynamic_crawl
    warning_codes = sorted(
        {
            warning.code
            for warning in dynamic.warnings
            if warning.code in _DYNAMIC_DEGRADATION_WARNING_CODES
        }
    )
    browser_error_codes: set[DynamicBrowserErrorCode] = set()
    for warning in dynamic.warnings:
        raw_code = warning.details.get("error_code")
        try:
            browser_error_codes.add(DynamicBrowserErrorCode(raw_code))
        except (TypeError, ValueError):
            continue

    details = [f"termination={dynamic.termination_reason.value}"]
    if warning_codes:
        details.append(f"warnings={','.join(warning_codes)}")
    if browser_error_codes:
        details.append(
            "browser_errors="
            + ",".join(
                code.value
                for code in sorted(browser_error_codes, key=lambda item: item.value)
            )
        )
    redirect_blocks = dynamic.browser_audit.redirect_block_count
    if redirect_blocks:
        details.append(f"redirect_blocks={redirect_blocks}")
    print(
        "vulnspider: error: DYNAMIC_INCOMPLETE: "
        + "; ".join(details)
        + "; analysis was not written",
        file=sys.stderr,
    )

    if redirect_blocks:
        print(
            "vulnspider: hint: a redirect target was blocked by exact Dynamic "
            "authority. Inspect the source and Location/final path; do not grant "
            "authentication, logout, or other state-changing transitions. Grant "
            "only an intended same-origin target with --dynamic-allow-navigation. "
            "Authenticated browser-session import is not supported.",
            file=sys.stderr,
        )
    elif browser_error_codes.intersection(_DYNAMIC_RUNTIME_ERROR_CODES):
        print(
            "vulnspider: hint: verify the Playwright/Chromium runtime; run "
            "'python -m playwright install chromium' if Chromium is missing.",
            file=sys.stderr,
        )
    else:
        print(
            "vulnspider: hint: inspect crawl.dynamic_crawl.termination_reason and "
            "crawl.dynamic_crawl.discovery.warnings in the crawl output.",
            file=sys.stderr,
        )


def _normalized_destination(destination: Path) -> str:
    return os.path.normcase(
        os.path.normpath(os.fspath(destination.resolve(strict=False)))
    )


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "value must be a positive integer"
        ) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _bounded_top_k(value: str) -> int:
    number = _positive_integer(value)
    if number > _MAX_TOP_K:
        raise argparse.ArgumentTypeError(
            f"--top-k must be between 1 and {_MAX_TOP_K}"
        )
    return number


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "value must be a non-negative number"
        ) from exc
    if parsed < 0 or not (parsed == parsed) or parsed in (float("inf"), float("-inf")):
        raise argparse.ArgumentTypeError("value must be a non-negative number")
    return parsed


def _non_negative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "value must be a non-negative integer"
        ) from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError(
            "value must be a non-negative integer"
        )
    return parsed


def _positive_number(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "value must be a positive number"
        ) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive number")
    return parsed


def _reject_native_policy_with_legacy_input(args: argparse.Namespace) -> None:
    if any(
        getattr(args, name) is not None
        for name in (
            "max_pages",
            "max_depth",
            "max_requests",
            "timeout_seconds",
            "max_redirects",
            "dynamic_allow_navigation",
            "dynamic_allow_resource",
            "dynamic_max_pages",
            "dynamic_max_depth",
            "dynamic_max_navigation_attempts",
            "dynamic_max_route_actions",
            "dynamic_max_elapsed_seconds",
            "dynamic_navigation_timeout_seconds",
            "dynamic_max_redirects",
            "dynamic_request_decision_budget",
        )
    ) or args.dynamic:
        raise CLIError("crawler policy options require --url")


_DYNAMIC_OPTION_NAMES = (
    "dynamic_allow_navigation",
    "dynamic_allow_resource",
    "dynamic_max_pages",
    "dynamic_max_depth",
    "dynamic_max_navigation_attempts",
    "dynamic_max_route_actions",
    "dynamic_max_elapsed_seconds",
    "dynamic_navigation_timeout_seconds",
    "dynamic_max_redirects",
    "dynamic_request_decision_budget",
)


def _reject_dynamic_options_without_opt_in(args: argparse.Namespace) -> None:
    if args.dynamic:
        return
    if getattr(args, "dynamic_passive_capture", False):
        raise CLIError("Dynamic policy and authority options require --dynamic")
    if any(getattr(args, name) is not None for name in _DYNAMIC_OPTION_NAMES):
        raise CLIError("Dynamic policy and authority options require --dynamic")

def _normalize_scan_url(url: str) -> str:
    """Remove URL fragments before HTTP crawling / authority checks."""

    parts = urlsplit(url)

    if not parts.fragment:
        return url

    normalized = urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            parts.query,
            "",
        )
    )

    _progress(
        f"[*] SPA/URL fragment '#{parts.fragment}' detected "
        f"-> scan URL normalized to {normalized}"
    )

    return normalized


def _dynamic_authority_from_args(
    args: argparse.Namespace,
    *,
    simple_mode: bool = False,
) -> DynamicRequestAuthority:
    grants: list[DynamicResourceGrant] = []
    for value in args.dynamic_allow_resource or ():
        category, separator, url = value.partition("=")
        if not separator or not category or not url:
            raise CLIError(
                "--dynamic-allow-resource requires CATEGORY=URL"
            )
        try:
            kind = DynamicResourceKind(category)
        except ValueError:
            allowed = ", ".join(item.value for item in DynamicResourceKind)
            raise CLIError(
                "--dynamic-allow-resource category must be one of: "
                f"{allowed}"
            ) from None
        grants.append(DynamicResourceGrant(kind=kind, url=url))

    # Passive same-origin capture (rendered navigation + resources + fetch/XHR)
    # is always on in simple URL mode; analyze mode opts in explicitly with
    # --dynamic-passive-capture so SPA/REST-JSON surfaces can be discovered.
    passive_capture = simple_mode or getattr(
        args, "dynamic_passive_capture", False
    )
    return DynamicRequestAuthority(
        root_url=args.url,
        navigation_urls=tuple(args.dynamic_allow_navigation or ()),
        resource_grants=tuple(grants),
        allow_rendered_navigation=passive_capture,
        allow_passive_same_origin_resources=passive_capture,
        allow_passive_same_origin_fetch_xhr=passive_capture,
    )


def _dynamic_policy_from_args(
    args: argparse.Namespace,
    *,
    simple_mode: bool = False,
) -> DynamicCrawlPolicy:
    defaults = DynamicCrawlPolicy()
    try:
        return DynamicCrawlPolicy(
            max_pages=(
                defaults.max_pages
                if args.dynamic_max_pages is None
                else args.dynamic_max_pages
            ),
            max_depth=(
                (
                    _SIMPLE_DEFAULT_DYNAMIC_MAX_DEPTH
                    if simple_mode
                    else defaults.max_depth
                )
                if args.dynamic_max_depth is None
                else args.dynamic_max_depth
            ),
            max_navigation_attempts=(
                defaults.max_navigation_attempts
                if args.dynamic_max_navigation_attempts is None
                else args.dynamic_max_navigation_attempts
            ),
            max_route_actions=(
                defaults.max_route_actions
                if args.dynamic_max_route_actions is None
                else args.dynamic_max_route_actions
            ),
            max_elapsed_seconds=(
                defaults.max_elapsed_seconds
                if args.dynamic_max_elapsed_seconds is None
                else args.dynamic_max_elapsed_seconds
            ),
            navigation_timeout_seconds=(
                defaults.navigation_timeout_seconds
                if args.dynamic_navigation_timeout_seconds is None
                else args.dynamic_navigation_timeout_seconds
            ),
            max_redirects_per_navigation=(
                defaults.max_redirects_per_navigation
                if args.dynamic_max_redirects is None
                else args.dynamic_max_redirects
            ),
            request_decision_budget=(
                defaults.request_decision_budget
                if args.dynamic_request_decision_budget is None
                else args.dynamic_request_decision_budget
            ),
            rendered_dom_policy=defaults.rendered_dom_policy,
        )
    except DynamicCrawlerError as exc:
        raise CLIError(str(exc)) from None


def _crawl_policy_from_args(args: argparse.Namespace) -> CrawlPolicy:
    defaults = CrawlPolicy()
    return CrawlPolicy(
        max_pages=(
            defaults.max_pages if args.max_pages is None else args.max_pages
        ),
        max_depth=(
            defaults.max_depth if args.max_depth is None else args.max_depth
        ),
        max_requests=(
            defaults.max_requests
            if args.max_requests is None
            else args.max_requests
        ),
        timeout_seconds=(
            defaults.timeout_seconds
            if args.timeout_seconds is None
            else args.timeout_seconds
        ),
        max_redirects=(
            defaults.max_redirects
            if args.max_redirects is None
            else args.max_redirects
        ),
        delay_seconds=defaults.delay_seconds,
        max_elapsed_seconds=defaults.max_elapsed_seconds,
        max_response_bytes=defaults.max_response_bytes,
        session_cookies=_session_cookies_from_args(args),
    )


def _session_cookies_from_args(
    args: argparse.Namespace,
) -> tuple[tuple[str, str], ...]:
    """Parse ``--cookie NAME=VALUE`` options into an ordered cookie tuple.

    An authenticated Broken Access Control scan needs a logged-in session, and
    ``--cookie`` is how the operator supplies it. Cookies are only meaningful on
    the static path, so combining them with Dynamic discovery is rejected rather
    than silently ignored.
    """

    raw = getattr(args, "cookie", None) or []
    if not raw:
        return ()
    if getattr(args, "dynamic", False):
        raise CLIError(
            "--cookie is only supported for static discovery; omit --dynamic "
            "(or use --static-only in simple -u mode)"
        )
    cookies: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in raw:
        name, separator, value = item.partition("=")
        name = name.strip()
        if not separator or not name:
            raise CLIError(f"--cookie must be NAME=VALUE, got {item!r}")
        if name in seen:
            raise CLIError(f"--cookie {name!r} was given more than once")
        seen.add(name)
        cookies.append((name, value))
    return tuple(cookies)


def _load_legacy_records(path: Path) -> tuple[Mapping[str, Any], ...]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CLIError(f"input is not valid JSON: {path}") from exc
    if not isinstance(parsed, list):
        raise CLIError("input JSON must be an array of legacy crawl records")
    records: list[Mapping[str, Any]] = []
    for index, item in enumerate(parsed):
        if not isinstance(item, Mapping):
            raise CLIError(f"legacy crawl record at index {index} must be an object")
        link = item.get("link") or item.get("url")
        if not isinstance(link, str) or not link:
            raise CLIError(
                f"legacy crawl record at index {index} requires a non-empty link"
            )
        try:
            parts = urlsplit(link)
        except ValueError as exc:
            raise CLIError(
                f"legacy crawl record at index {index} requires an absolute HTTP(S) link"
            ) from exc
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise CLIError(
                f"legacy crawl record at index {index} requires an absolute HTTP(S) link"
            )
        records.append(item)
    return tuple(records)
