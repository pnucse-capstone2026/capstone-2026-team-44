"""CLI surface for the decision layer and the labeled corpus.

Kept out of ``cli.py`` deliberately. ``AGENTS.md`` freezes the v0.1 command
surface, and ADR-025 adds commands rather than changing `analyze`, `-u`, or any
of their flags. This module owns the new subcommands and the glue that turns a
live ``AnalysisResult`` into decision-layer input.

The glue never reconstructs anything. It holds the in-memory analysis and walks
the same authoritative path a consumer would: rank through ``select_top_k`` and
``select_combined_top_k``, project through ``build_mutation_handoff``, and read
features from the ``FeatureVector`` the pipeline actually produced.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from vulnspider.access.selection import select_top_k_access
from vulnspider.corpus.collection import (
    CollectionResult,
    CorpusError,
    append_corpus,
    collect_labeled_samples,
    read_corpus,
    write_corpus,
)
from vulnspider.corpus.fitting import (
    CorpusFittingError,
    calibrate_from_corpus,
    evaluate_calibration,
    fit_family_scorers,
    out_of_fold_predictions,
    prior_family_scorers,
    scorers_as_mapping,
    scorers_from_mapping,
)
from vulnspider.corpus.ground_truth import GroundTruthError, read_ground_truth
from vulnspider.corpus.verification_collection import (
    append_verification_corpus,
    collect_verification_samples,
    read_verification_corpus,
    write_verification_corpus,
)
from vulnspider.corpus.verification_fitting import (
    evaluate_verification_arm,
    fit_from_verification_corpus,
)
from vulnspider.decision.candidate import (
    DecisionCandidate,
    decision_candidate_from_context,
)
from vulnspider.decision.conformal import ConformalError, ConformalThreshold
from vulnspider.decision.policy import DecisionOutcome, run_decision_layer
from vulnspider.domain import VulnerabilityType, stable_fingerprint
from vulnspider.evaluation.live import (
    DEFAULT_CUTOFFS,
    LiveEvaluationError,
    LiveEvaluationReport,
    build_scored_candidates,
    evaluate_live_run,
    render_live_evaluation_table,
)
from vulnspider.evaluation.random_predictor import (
    RandomPredictor,
    RandomPredictorError,
    evaluate_random_predictor,
)
from vulnspider.pipeline import AnalysisResult
from vulnspider.reporting.decision_html_report import write_decision_html_report
from vulnspider.reporting.report_tables import (
    render_evaluation_html,
    render_evaluation_markdown,
    render_ground_truth_html,
    render_ground_truth_markdown,
)
from vulnspider.scoring.calibration import (
    CalibratedProbability,
    CalibratedScorer,
    CalibrationError,
)
from vulnspider.verification.focused import VerificationSelection
from vulnspider.selection import (
    build_mutation_handoff,
    select_combined_top_k,
    select_top_k,
)

DECISION_REPORT_VERSION = "decision-report-v1"

DEFAULT_TOP_K = 10
DEFAULT_TARGET_RISK = 0.1

# Families the injection pipeline can currently produce candidates for. BAC
# has a scorer but no observation pipeline yet (ADR-014), so it never appears
# in an AnalysisResult and is deliberately not listed.
_FAMILIES = ("SQLI", "REFLECTED_XSS", "BROKEN_ACCESS_CONTROL")


class DecisionCLIError(ValueError):
    """Raised for user-facing decision or corpus command errors."""


def build_decision_candidates(
    analysis: AnalysisResult,
    scorers: Mapping[str, CalibratedScorer],
) -> tuple[tuple[DecisionCandidate, ...], dict[str, CalibratedProbability]]:
    """Project one analysis into decision-layer candidates.

    Every candidate the scoring layer produced is ranked -- not just a Top-K --
    so the report can show what was scored below the cut. Candidates with no
    observed evidence stay unrankable, the same rule ``select_top_k`` applies.
    """

    results = analysis.scoring_results
    access_results = analysis.access_scoring_results
    if not results and not access_results:
        return (), {}

    rank_all = len(results) + len(access_results)
    injection = select_top_k(results, k=rank_all)
    access = select_top_k_access(access_results, k=rank_all)
    combined = select_combined_top_k(injection, access, k=rank_all)
    handoff = build_mutation_handoff(
        combined,
        selection_run_id=_selection_run_id(analysis),
    )

    vectors = {vector.id or "": vector for vector in analysis.feature_vectors}
    # BAC candidates carry no InputPoint FeatureVector; their two access
    # features come from the executed reference/comparison pair instead.
    access_features = {
        observation.candidate_id: observation.features
        for observation in analysis.access_probe_observations
    }

    candidates: list[DecisionCandidate] = []
    scored: dict[str, CalibratedProbability] = {}
    for context in handoff.contexts:
        scorer = scorers.get(context.family)
        if scorer is None:
            # A BAC model is optional: when it is absent (e.g. a fitted model
            # trained only on the injection families), access candidates are
            # left out of the ranking rather than erroring. An absent injection
            # model is still a real misconfiguration.
            if context.origin == "access":
                continue
            raise DecisionCLIError(
                f"no calibrated model for family {context.family!r}"
            )
        if context.origin == "access":
            features = access_features.get(context.candidate_id)
            if features is None:
                raise DecisionCLIError(
                    f"analysis has no access features for {context.candidate_id!r}"
                )
        else:
            vector = vectors.get(context.feature_vector_id or "")
            if vector is None:
                raise DecisionCLIError(
                    f"analysis has no feature vector {context.feature_vector_id!r}"
                )
            features = vector.features
        calibrated = scorer.probability(features)
        scored[context.candidate_id] = calibrated
        candidates.append(
            decision_candidate_from_context(context, calibrated)
        )
    return tuple(candidates), scored


def decision_report(
    outcome: DecisionOutcome,
    *,
    target_url: str,
    models: Mapping[str, CalibratedScorer],
    warnings: Sequence[str] = (),
    verification: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize a decision outcome without recomputing any of it.

    When ``verification`` is given (candidate_id -> CandidateVerification), each
    selected candidate also carries its post-verification ``final_confidence``
    and outcome, and the report gains a ``verification`` summary, so the JSON
    and the HTML dashboard present the same final score (ADR-033).
    """

    verified = verification or {}

    def final_score(candidate: DecisionCandidate) -> float:
        result = verified.get(candidate.candidate_id)
        if result is not None:
            return float(result.final_confidence)
        return float(candidate.probability)

    # Same Top-K set, re-ordered by the post-verification confidence when
    # verification ran, so the JSON order matches the dashboard. The stable
    # sort keeps the decision layer's probability order when nothing verified.
    ordered = sorted(outcome.selected, key=lambda candidate: -final_score(candidate))

    def entry(position: int, candidate: DecisionCandidate) -> dict[str, Any]:
        record: dict[str, Any] = {
            "order": position,
            "candidate_id": candidate.candidate_id,
            # The input point this candidate is a type of. Two candidates of one
            # input point (a SQLi and an XSS interpretation of the same value)
            # share it; the HTML report surfaces only the top type per input
            # point, and this lets a consumer group the same way.
            "input_point_ref": candidate.subject_ref,
            "family": candidate.family,
            "probability": candidate.probability,
            "selection_rank": candidate.selection_rank,
        }
        result = verified.get(candidate.candidate_id)
        if result is not None:
            record["prior_probability"] = result.prior_probability
            record["final_confidence"] = result.final_confidence
            record["verification_outcome"] = result.final_outcome.value
            record["verification_signal"] = result.final_signal.value
        return record

    return {
        "report_version": DECISION_REPORT_VERSION,
        "target": target_url,
        "policy_version": outcome.policy_version,
        "warnings": list(warnings),
        "models": {
            family: {
                "model_version": scorer.model_version,
                "training_samples": scorer.training_samples,
            }
            for family, scorer in sorted(models.items())
        },
        "selection": {
            "top_k": outcome.top_k,
            "candidates_scored": outcome.initial_candidates,
            "selected": len(outcome.selected),
            "deferred": len(outcome.deferred),
            "expected_findings": outcome.expected_findings,
        },
        "guarantee": (
            None
            if outcome.conformal is None
            else {
                **outcome.conformal.as_mapping(),
                "conformal_set_size": outcome.conformal_set_size,
                "top_k_covers_conformal_set": (
                    outcome.top_k >= outcome.conformal_set_size
                ),
            }
        ),
        "verification": _verification_summary(verified),
        "verification_order": [
            entry(position, candidate)
            for position, candidate in enumerate(ordered, start=1)
        ],
    }


def _verification_summary(
    verified: Mapping[str, Any],
) -> dict[str, Any] | None:
    """A compact roll-up of the verification stage for the decision report."""

    if not verified:
        return None
    outcomes: dict[str, int] = {}
    for candidate in verified.values():
        key = candidate.final_outcome.value
        outcomes[key] = outcomes.get(key, 0) + 1
    return {
        "ran": True,
        "candidates_verified": len(verified),
        "outcomes": dict(sorted(outcomes.items())),
    }


def collect_from_analysis(
    analysis: AnalysisResult,
    *,
    application_id: str,
    ground_truth_path: Path,
) -> CollectionResult:
    """Join one analysis run's observed features to ground truth."""

    ground_truth = read_ground_truth(ground_truth_path)
    scored = tuple(
        (
            result.candidate.input_point_id,
            result.feature_vector_id,
            result.candidate.vulnerability_type.value,
        )
        for result in analysis.scoring_results
    )
    return collect_labeled_samples(
        application_id=application_id,
        endpoints=analysis.endpoints,
        input_points=analysis.input_points,
        feature_vectors=analysis.feature_vectors,
        scored_candidates=scored,
        ground_truth=ground_truth,
    )


def load_models(path: Path | None, families: Sequence[str]) -> dict[
    str, CalibratedScorer
]:
    """Load fitted models, or fall back to the heuristic prior."""

    if path is None:
        return prior_family_scorers(families)
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        raise DecisionCLIError(f"{path} must contain a JSON object")
    return scorers_from_mapping(payload)


def load_conformal(path: Path | None) -> ConformalThreshold | None:
    """Load a calibrated conformal threshold, if one was supplied."""

    if path is None:
        return None
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        raise DecisionCLIError(f"{path} must contain a JSON object")
    return ConformalThreshold.from_mapping(payload)


def add_decision_subcommands(subparsers: argparse._SubParsersAction) -> None:
    """Register the `corpus` subcommands on the existing parser.

    The calibrated Top-K algorithm is not a separate command anymore: `analyze`
    (and simple `-u` mode) run it directly. This registers only the corpus
    tooling that builds the model and the recall threshold `analyze` consumes.
    """

    corpus = subparsers.add_parser(
        "corpus",
        help="Collect a labeled corpus, fit models, calibrate the guarantee.",
        description=(
            "Build the labeled corpus the calibrated scorer and the conformal "
            "guarantee are estimated from."
        ),
    )
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)

    collect = corpus_commands.add_parser(
        "collect",
        help="Run one authorized target and append labeled samples.",
    )
    collect.add_argument("--url", required=True, help="Authorized target root URL.")
    collect.add_argument(
        "--application-id",
        required=True,
        help="Group key for this application (leakage control unit).",
    )
    collect.add_argument(
        "--ground-truth",
        type=Path,
        required=True,
        help="Ground truth JSON for this application.",
    )
    collect.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Corpus JSON Lines destination.",
    )
    collect.add_argument(
        "--append",
        action="store_true",
        help="Append to an existing corpus instead of overwriting it.",
    )
    _add_crawl_bounds(collect)

    fit = corpus_commands.add_parser(
        "fit",
        help="Fit one calibrated model per family from a corpus.",
    )
    fit.add_argument("--corpus", type=Path, required=True, help="Corpus JSONL.")
    fit.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Fitted model JSON destination.",
    )
    fit.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional out-of-fold calibration quality report destination.",
    )

    calibrate = corpus_commands.add_parser(
        "calibrate",
        help="Calibrate the conformal recall threshold from a corpus.",
    )
    calibrate.add_argument(
        "--corpus", type=Path, required=True, help="Corpus JSONL."
    )
    calibrate.add_argument(
        "--target-recall",
        type=float,
        default=1.0 - DEFAULT_TARGET_RISK,
        help=(
            "Recall to guarantee, in (0, 1) "
            f"(default: {1.0 - DEFAULT_TARGET_RISK})."
        ),
    )
    calibrate.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Calibrated threshold JSON destination.",
    )

    verify_collect = corpus_commands.add_parser(
        "verify-collect",
        help="Run focused verification on a labeled app and record signals.",
    )
    verify_collect.add_argument(
        "--url", required=True, help="Authorized target root URL."
    )
    verify_collect.add_argument(
        "--application-id",
        required=True,
        help="Group key for this application (leakage control unit).",
    )
    verify_collect.add_argument(
        "--ground-truth",
        type=Path,
        required=True,
        help="Ground truth JSON for this application.",
    )
    verify_collect.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Verification corpus JSON Lines destination.",
    )
    verify_collect.add_argument(
        "--top-k",
        type=int,
        default=20,
        help="Maximum candidates to verify per application (default: 20).",
    )
    verify_collect.add_argument(
        "--append",
        action="store_true",
        help="Append to an existing verification corpus.",
    )
    _add_crawl_bounds(verify_collect)

    verify_fit = corpus_commands.add_parser(
        "verify-fit",
        help="Fit the confidence model from a verification corpus.",
    )
    verify_fit.add_argument(
        "--corpus", type=Path, required=True, help="Verification corpus JSONL."
    )
    verify_fit.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Fitted confidence model JSON destination.",
    )
    verify_fit.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional out-of-fold verification arm report destination.",
    )
    verify_fit.add_argument(
        "--max-abs-llr",
        type=float,
        default=1.0,
        help="Cap on |LLR| in logits (default: 1.0), keeping the update gentle.",
    )


def add_algorithm_options(parser: argparse.ArgumentParser) -> None:
    """Attach the calibrated-model options to a parser that already has --top-k.

    ``analyze`` and simple ``-u`` mode share these: the fitted model to score
    with (default: the heuristic prior, which reproduces the old ordering) and
    the optional conformal recall threshold.
    """

    parser.add_argument(
        "--model",
        type=Path,
        default=None,
        help="Fitted model JSON from 'corpus fit' (default: heuristic prior).",
    )
    parser.add_argument(
        "--conformal",
        type=Path,
        default=None,
        help="Calibrated recall-threshold JSON from 'corpus calibrate'.",
    )


@dataclass(frozen=True, slots=True)
class EvaluationRequest:
    """Everything the optional ranking-evaluation stage needs from the CLI.

    The stage runs only when the operator supplies ground truth for the target
    they are scanning. That is the whole precondition: ``Precision@K`` needs
    labels, and VulnSpider never invents them.
    """

    ground_truth_path: Path
    output: Path
    cutoffs: tuple[int, ...] = DEFAULT_CUTOFFS
    application_id: str | None = None
    random_predictor: RandomPredictor | None = None


def run_live_evaluation(
    outcome: DecisionOutcome,
    *,
    analysis: AnalysisResult,
    target_url: str,
    top_k: int,
    verification: Mapping[str, Any],
    request: EvaluationRequest,
) -> LiveEvaluationReport:
    """Score the finished run's ranking against the target's ground truth.

    Both the selected and the deferred candidates are measured: ``Recall@K``
    is only meaningful against the whole ranked pool, not against the Top-K the
    run happened to cut at.
    """

    ground_truth = read_ground_truth(request.ground_truth_path)
    application_id = request.application_id
    if application_id is None:
        applications = ground_truth.applications
        if len(applications) != 1:
            raise LiveEvaluationError(
                f"{request.ground_truth_path} covers "
                f"{len(applications)} applications; pass --application-id to "
                "say which one was scanned"
            )
        application_id = applications[0]

    scored = build_scored_candidates(
        tuple(outcome.selected) + tuple(outcome.deferred),
        application_id=application_id,
        ground_truth=ground_truth,
        endpoints=analysis.endpoints,
        input_points=analysis.input_points,
        final_confidence={
            candidate_id: float(result.final_confidence)
            for candidate_id, result in verification.items()
        },
        access_input_points={
            observation.candidate_id: (
                observation.access_probe_plan.input_point_id or ""
            )
            for observation in analysis.access_probe_observations
        },
    )
    report = evaluate_live_run(
        scored,
        application_id=application_id,
        target=target_url,
        top_k=top_k,
        cutoffs=request.cutoffs,
    )
    if request.random_predictor is not None:
        try:
            arm = evaluate_random_predictor(
                scored,
                application_id=application_id,
                predictor=request.random_predictor,
                cutoffs=report.cutoffs,
            )
        except RandomPredictorError as exc:
            raise LiveEvaluationError(str(exc)) from exc
        report = replace(report, arms=report.arms + (arm,))
    return report


@dataclass(frozen=True, slots=True)
class DecisionRanking:
    """One analysis scored and ranked by the decision layer.

    Split out of :func:`analyze_and_report` so focused verification can run
    against the candidates the report will actually rank. Verifying first and
    ranking afterwards used to verify the v0.1 heuristic Top-K instead, which
    is a different set whenever the calibrated probability reorders anything.
    """

    outcome: DecisionOutcome
    models: Mapping[str, CalibratedScorer]
    probabilities: Mapping[str, CalibratedProbability]


def rank_analysis(
    analysis: AnalysisResult,
    *,
    top_k: int,
    model_path: Path | None,
    conformal_path: Path | None,
) -> DecisionRanking:
    """Score every candidate with the calibrated model and take the Top-K."""

    if top_k < 0:
        raise DecisionCLIError("--top-k must not be negative")
    models = load_models(model_path, _FAMILIES)
    conformal = load_conformal(conformal_path)
    candidates, probabilities = build_decision_candidates(analysis, models)
    return DecisionRanking(
        outcome=run_decision_layer(candidates, top_k=top_k, conformal=conformal),
        models=models,
        probabilities=probabilities,
    )


def verification_selection(
    ranking: DecisionRanking,
) -> tuple[VerificationSelection, ...]:
    """The injection candidates focused verification should visit, in order.

    Broken Access Control candidates are left out on purpose: they carry no
    InputPoint FeatureVector and are re-checked by ``verify_access`` instead
    (ADR-014), not by payload mutation.
    """

    injection = {family.value for family in VulnerabilityType}
    return tuple(
        VerificationSelection(
            candidate_id=candidate.candidate_id,
            input_point_id=candidate.subject_ref,
            feature_vector_id=candidate.feature_vector_ref,
            vulnerability_type=VulnerabilityType(candidate.family),
            prior_probability=float(candidate.probability),
        )
        for candidate in ranking.outcome.selected
        if candidate.family in injection
    )


def analyze_and_report(
    analysis: AnalysisResult,
    *,
    target_url: str,
    top_k: int,
    model_path: Path | None,
    conformal_path: Path | None,
    output: Path,
    html_output: Path | None = None,
    verification: Any = None,
    access_verify_config: Any = None,
    evaluation: EvaluationRequest | None = None,
    ranking: DecisionRanking | None = None,
    verify_links: bool = False,
) -> DecisionOutcome:
    """Score one analysis with the calibrated model, take the Top-K, and report.

    This is the single entry point the ``analyze`` command and simple ``-u``
    mode both run: crawl and feature extraction already happened, and this turns
    the resulting ``AnalysisResult`` into a calibrated-probability Top-K report.

    ``ranking`` is the already-computed Top-K when the caller needed it earlier
    -- a verified run must rank before it verifies, so that verification visits
    the reported candidates. Recomputing it here would be deterministic but
    wasteful, and would make the two orderings independent again.
    """

    if ranking is None:
        ranking = rank_analysis(
            analysis,
            top_k=top_k,
            model_path=model_path,
            conformal_path=conformal_path,
        )
    outcome = ranking.outcome
    models = ranking.models
    probabilities = ranking.probabilities
    verification_map = (
        {candidate.candidate_id: candidate for candidate in verification.candidates}
        if verification is not None
        else {}
    )
    if verification is not None and access_verify_config is not None:
        from vulnspider.verification.access_verify import verify_access

        selected_ids = {candidate.candidate_id for candidate in outcome.selected}
        access_map = verify_access(
            analysis,
            probabilities={
                candidate_id: probability.probability
                for candidate_id, probability in probabilities.items()
                if candidate_id in selected_ids
            },
            ranks={
                candidate.candidate_id: rank
                for rank, candidate in enumerate(outcome.selected, start=1)
            },
            config=access_verify_config,
        )
        verification_map = {**verification_map, **access_map}
    write_json(
        decision_report(
            outcome,
            target_url=target_url,
            models=models,
            warnings=analysis.warnings,
            verification=verification_map,
        ),
        output,
    )
    if html_output is not None:
        probe_runs: dict[str, Any] = {}
        for observation in sorted(
            analysis.probe_observations,
            key=lambda item: item.probe_plan.id or "",
        ):
            # One InputPoint can own several request contexts; show the first
            # probe run by stable ProbePlan id, as the v0.1 report does.
            probe_runs.setdefault(
                observation.feature_vector_id,
                (
                    observation.probe_plan,
                    observation.baseline_response,
                    observation.probe_response,
                ),
            )
        access_observations = {
            observation.access_probe_plan.id or "": observation
            for observation in analysis.access_probe_observations
        }
        write_decision_html_report(
            outcome,
            html_output,
            target=target_url,
            input_points={
                point.id or "": point for point in analysis.input_points
            },
            endpoints={
                endpoint.id or "": endpoint for endpoint in analysis.endpoints
            },
            probe_runs=probe_runs,
            probabilities=probabilities,
            models=models,
            verification=verification_map,
            access_observations=access_observations,
            warnings=analysis.warnings,
            elapsed_seconds=analysis.elapsed_seconds,
            endpoint_count=len(analysis.endpoints),
            input_point_count=len(analysis.input_points),
            verify_links=verify_links,
        )
    if evaluation is not None:
        report = run_live_evaluation(
            outcome,
            analysis=analysis,
            target_url=target_url,
            top_k=top_k,
            verification=verification_map,
            request=evaluation,
        )
        write_json(report.as_mapping(), evaluation.output)
        print(render_live_evaluation_table(report))
        _publish_report_tables(report, evaluation)
    return outcome


def _publish_report_tables(
    report: LiveEvaluationReport,
    evaluation: EvaluationRequest,
) -> None:
    """Write paste-ready comparison and input-point tables next to the eval JSON.

    Each run that has ground truth emits, alongside the evaluation JSON, a
    Markdown and an HTML rendering of (a) the arm-by-metric comparison and
    (b) the per-input-point vulnerability map, so the numbers drop straight into
    the final report. Names are derived from ``--eval-output`` so one run's
    artifacts stay grouped.
    """

    base = evaluation.output
    store = read_ground_truth(evaluation.ground_truth_path)
    application_id = report.application_id
    outputs: list[tuple[Path, str]] = [
        (base.with_name(f"{base.stem}-table.md"), render_evaluation_markdown(report)),
        (base.with_name(f"{base.stem}-table.html"), render_evaluation_html(report)),
        (
            base.with_name(f"{base.stem}-inputs.md"),
            render_ground_truth_markdown(store, application_id),
        ),
        (
            base.with_name(f"{base.stem}-inputs.html"),
            render_ground_truth_html(store, application_id),
        ),
    ]
    for path, content in outputs:
        path.write_text(content, encoding="utf-8")
    print(
        "vulnspider: comparison table -> "
        f"{outputs[1][0].resolve(strict=False).as_uri()}"
    )
    print(
        "vulnspider: input-point table -> "
        f"{outputs[3][0].resolve(strict=False).as_uri()}"
    )
    print(
        "vulnspider: (markdown copies alongside: "
        f"{outputs[0][0].name}, {outputs[2][0].name})"
    )


def run_corpus_command(
    args: argparse.Namespace,
    *,
    transport: Any = None,
    crawler: Any = None,
    crawler_transport: Any = None,
) -> int:
    """Handle `vulnspider corpus {collect,fit,calibrate}`."""

    if args.corpus_command == "collect":
        return _run_corpus_collect(
            args,
            transport=transport,
            crawler=crawler,
            crawler_transport=crawler_transport,
        )
    if args.corpus_command == "fit":
        return _run_corpus_fit(args)
    if args.corpus_command == "calibrate":
        return _run_corpus_calibrate(args)
    if args.corpus_command == "verify-collect":
        return _run_corpus_verify_collect(
            args,
            transport=transport,
            crawler=crawler,
            crawler_transport=crawler_transport,
        )
    if args.corpus_command == "verify-fit":
        return _run_corpus_verify_fit(args)
    raise DecisionCLIError(f"unsupported corpus command: {args.corpus_command}")


def _run_corpus_verify_collect(
    args: argparse.Namespace,
    *,
    transport: Any,
    crawler: Any,
    crawler_transport: Any,
) -> int:
    """Run analyze + focused verification on one labeled app and record signals."""

    from vulnspider.verification import VerificationConfig, verify_analysis

    analysis = _analyze(
        args,
        transport=transport,
        crawler=crawler,
        crawler_transport=crawler_transport,
        top_k=args.top_k,
    )
    run = verify_analysis(
        analysis,
        config=VerificationConfig(
            transport=transport, max_candidates=args.top_k
        ),
    )
    ground_truth = read_ground_truth(args.ground_truth)
    result = collect_verification_samples(
        application_id=args.application_id,
        run=run,
        endpoints=analysis.endpoints,
        input_points=analysis.input_points,
        ground_truth=ground_truth,
    )
    written = (
        append_verification_corpus(result.samples, args.output)
        if args.append
        else write_verification_corpus(result.samples, args.output)
    )
    print(
        f"vulnspider: collected {written} verification samples for "
        f"{args.application_id} ({result.positives} vulnerable, "
        f"{result.negatives} safe)"
    )
    if result.unlabeled_keys:
        print(
            f"vulnspider: warning: {len(result.unlabeled_keys)} verified "
            "candidates have no ground truth entry and were skipped"
        )
    print(f"vulnspider: verification corpus: {args.output}")
    return 0


def _run_corpus_verify_fit(args: argparse.Namespace) -> int:
    """Fit the confidence model from a verification corpus and evaluate its arm."""

    if args.max_abs_llr <= 0.0:
        raise DecisionCLIError("--max-abs-llr must be positive")
    dataset = read_verification_corpus(args.corpus)
    if not dataset.samples:
        raise DecisionCLIError(f"{args.corpus} contains no samples")
    model = fit_from_verification_corpus(
        dataset, max_abs_llr=args.max_abs_llr
    )
    write_json(model.as_mapping(), args.output)

    counts = dataset.counts()
    print(
        f"vulnspider: fitted the confidence model from {counts['samples']} "
        f"verification samples across {counts['groups']} applications "
        f"({counts['positives']} vulnerable, {counts['negatives']} safe); "
        f"|LLR| capped at {model.max_abs_llr:.2f}"
    )
    for family in sorted(model.family_llr):
        detail = ", ".join(
            f"{signal}={model.family_llr[family][signal]:+.3f}"
            for signal in sorted(model.family_llr[family])
        )
        print(f"  {family}: {detail}")

    if args.report is not None:
        if len(dataset.groups) < 2:
            raise DecisionCLIError(
                "a verification arm report needs at least two applications"
            )
        report = evaluate_verification_arm(dataset, max_abs_llr=args.max_abs_llr)
        write_json(report.as_mapping(), args.report)
        print(
            f"vulnspider: out-of-fold Brier prior={report.brier_prior:.4f} "
            f"posterior={report.brier_posterior:.4f} "
            f"improvement={report.improvement:+.4f} "
            f"({report.samples} predictions)"
        )
        print(f"vulnspider: verification arm report: {args.report}")
    print(f"vulnspider: confidence model: {args.output}")
    return 0


def _run_corpus_collect(
    args: argparse.Namespace,
    *,
    transport: Any,
    crawler: Any,
    crawler_transport: Any,
) -> int:
    analysis = _analyze(
        args,
        transport=transport,
        crawler=crawler,
        crawler_transport=crawler_transport,
    )
    result = collect_from_analysis(
        analysis,
        application_id=args.application_id,
        ground_truth_path=args.ground_truth,
    )
    written = (
        append_corpus(result.samples, args.output)
        if args.append
        else write_corpus(result.samples, args.output)
    )
    print(
        f"vulnspider: collected {written} labeled samples for "
        f"{args.application_id} ({result.positives} vulnerable, "
        f"{result.negatives} safe)"
    )
    if result.unlabeled_keys:
        print(
            f"vulnspider: warning: {len(result.unlabeled_keys)} discovered "
            "candidates have no ground truth entry and were skipped"
        )
        for key in result.unlabeled_keys[:10]:
            print(
                f"  unlabeled: {key.method} {key.canonical_path} "
                f"{key.parameter_location}:{key.parameter_name} "
                f"{key.vulnerability_type}"
            )
    if result.unrankable_candidates:
        print(
            f"vulnspider: {result.unrankable_candidates} candidates had no "
            "observed feature and were not collected"
        )
    print(f"vulnspider: corpus: {args.output}")
    return 0


def _run_corpus_fit(args: argparse.Namespace) -> int:
    dataset = read_corpus(args.corpus)
    if not dataset.samples:
        raise DecisionCLIError(f"{args.corpus} contains no samples")
    scorers = fit_family_scorers(dataset)
    if not scorers:
        raise DecisionCLIError("corpus contains no family with a known prior")
    write_json(scorers_as_mapping(scorers), args.output)

    counts = dataset.counts()
    print(
        f"vulnspider: fitted {len(scorers)} family models from "
        f"{counts['samples']} samples across {counts['groups']} applications "
        f"({counts['positives']} vulnerable, {counts['negatives']} safe)"
    )
    for family, scorer in sorted(scorers.items()):
        weights = ", ".join(
            f"{name}={weight:+.3f}"
            for name, weight in zip(
                scorer.feature_space.feature_names,
                scorer.weights,
                strict=True,
            )
        )
        print(f"  {family}: intercept={scorer.intercept:+.3f} {weights}")

    if args.report is not None:
        if len(dataset.groups) < 2:
            raise DecisionCLIError(
                "a calibration report needs at least two applications"
            )
        report = evaluate_calibration(out_of_fold_predictions(dataset))
        write_json(report.as_mapping(), args.report)
        print(
            f"vulnspider: out-of-fold Brier={report.brier_score:.4f} "
            f"ECE={report.expected_calibration_error:.4f} "
            f"({report.samples} predictions)"
        )
        print(f"vulnspider: calibration report: {args.report}")
    print(f"vulnspider: model: {args.output}")
    return 0


def _run_corpus_calibrate(args: argparse.Namespace) -> int:
    if not 0.0 < args.target_recall < 1.0:
        raise DecisionCLIError("--target-recall must lie strictly inside (0, 1)")
    dataset = read_corpus(args.corpus)
    if len(dataset.groups) < 2:
        raise DecisionCLIError(
            "conformal calibration needs at least two applications"
        )
    threshold = calibrate_from_corpus(
        dataset,
        target_risk=1.0 - args.target_recall,
    )
    write_json(threshold.as_mapping(), args.output)

    if threshold.guarantee_attainable:
        print(
            f"vulnspider: threshold={threshold.threshold:.4f} guarantees "
            f"recall >= {args.target_recall:.2f} "
            f"(empirical risk {threshold.empirical_risk:.4f} <= "
            f"{threshold.corrected_risk_bound:.4f}, "
            f"{threshold.calibration_groups} applications)"
        )
    else:
        needed = int(1.0 / (1.0 - args.target_recall)) - 1
        print(
            f"vulnspider: warning: recall {args.target_recall:.2f} cannot be "
            f"certified with {threshold.calibration_groups} applications; "
            f"at least {needed} are required. Selecting everything instead."
        )
    print(f"vulnspider: conformal threshold: {args.output}")
    return 0


def _analyze(
    args: argparse.Namespace,
    *,
    transport: Any,
    crawler: Any,
    crawler_transport: Any,
    top_k: int = 1,
) -> AnalysisResult:
    from vulnspider.discovery import CrawlPolicy
    from vulnspider.pipeline import analyze_url

    defaults = CrawlPolicy()
    policy = CrawlPolicy(
        max_pages=defaults.max_pages if args.max_pages is None else args.max_pages,
        max_depth=defaults.max_depth if args.max_depth is None else args.max_depth,
        max_requests=(
            defaults.max_requests
            if args.max_requests is None
            else args.max_requests
        ),
    )
    return analyze_url(
        args.url,
        top_k=top_k,
        crawl_policy=policy,
        crawler=crawler,
        crawler_transport=crawler_transport,
        transport=transport,
    )


def _add_crawl_bounds(parser: argparse.ArgumentParser) -> None:
    """Discovery bounds. `top_k` is deliberately absent: how many candidates to
    verify is what the decision layer computes, not something it is told."""

    parser.add_argument(
        "--max-pages", type=int, default=None, help="Maximum pages to crawl."
    )
    parser.add_argument(
        "--max-depth", type=int, default=None, help="Maximum crawl depth."
    )
    parser.add_argument(
        "--max-requests", type=int, default=None, help="Maximum crawl requests."
    )


def _selection_run_id(analysis: AnalysisResult) -> str:
    fingerprint = stable_fingerprint(
        "decision-selection-run",
        str(len(analysis.scoring_results)),
        *sorted(vector.id or "" for vector in analysis.feature_vectors),
    )
    return f"sel_{fingerprint[:16]}"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DecisionCLIError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise DecisionCLIError(f"{path} is not valid JSON: {exc}") from exc


def write_json(payload: Mapping[str, Any], path: Path) -> None:
    """Write a decision or corpus artifact as indented JSON."""

    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "DECISION_REPORT_VERSION",
    "DEFAULT_TARGET_RISK",
    "DEFAULT_TOP_K",
    "ConformalError",
    "CorpusError",
    "CorpusFittingError",
    "DecisionCLIError",
    "GroundTruthError",
    "CalibrationError",
    "add_algorithm_options",
    "add_decision_subcommands",
    "DecisionRanking",
    "analyze_and_report",
    "rank_analysis",
    "verification_selection",
    "build_decision_candidates",
    "calibrate_from_corpus",
    "collect_from_analysis",
    "decision_report",
    "evaluate_calibration",
    "fit_family_scorers",
    "load_conformal",
    "load_models",
    "out_of_fold_predictions",
    "read_corpus",
    "run_decision_layer",
    "append_corpus",
    "write_corpus",
    "scorers_as_mapping",
    "write_decision_html_report",
    "write_json",
]
