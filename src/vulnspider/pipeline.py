"""Orchestration paths from discovery inputs to Top-K results."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from time import monotonic
from typing import Any

from vulnspider.discovery import (
    CanonicalDiscoveryResult,
    CombinedDiscoveryResult,
    CrawlPolicy,
    DynamicCrawler,
    DynamicCrawlCompletion,
    DynamicCrawlPolicy,
    DynamicCrawlResult,
    DynamicIntegrityError,
    DynamicRequestAuthority,
    LegacyAdapterResult,
    LegacyCrawlerAdapter,
    LegacyCrawlRecord,
    ProbeReadyStatus,
    StaticCrawler,
    StaticCrawlerTransport,
    StaticCrawlResult,
    discover_native_combined,
    extract_static_html_with_sensitive_form_elision,
)
from vulnspider.access import (
    AccessProbeExecutionResult,
    execute_access_plan,
    extract_access_features,
    plan_credential_strip,
    plan_identifier_substitution,
    score_access_plan,
)
from vulnspider.domain import (
    AccessProbePlan,
    AccessScoringResult,
    Endpoint,
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputPoint,
    InputPointRequestContext,
    ProbePlan,
    RequestTemplate,
    ResponseSnapshot,
)
from vulnspider.features import (
    combine_input_point_features,
    extract_minimal_features,
)
from vulnspider.observation import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    ProbePlanner,
    ProbePlanningError,
    RequestExecutor,
    UrlLibTransport,
)
from vulnspider.observation.executor import RequestTransport
from vulnspider.scoring import ScoringResult, generate_candidates
from vulnspider.selection import SelectionOutcome, select_top_k
from vulnspider.scope.loopback import (
    LoopbackSafetyError,
    require_loopback_http_url,
)


class PipelineError(ValueError):
    """Raised when adapter records cannot safely traverse the v0.1 pipeline."""


# Framework-maintained state fields are useful attack-surface inventory, but
# they are outside VulnSpider's current SQLi / Reflected-XSS probe scope.
# Keep them in discovery and skip only the expensive probe/candidate path.
_FRAMEWORK_STATE_PARAMETER_NAMES = frozenset(
    {
        "__viewstate",
        "__viewstatefieldcount",
        "__viewstategenerator",
        "__viewstateencrypted",
        "__eventvalidation",
        "__eventtarget",
        "__eventargument",
        "__lastfocus",
    }
)


def _is_framework_state_input(input_point: InputPoint) -> bool:
    """Return whether an InputPoint is framework bookkeeping, not app data."""

    name = (input_point.name or "").strip().casefold()
    return name in _FRAMEWORK_STATE_PARAMETER_NAMES


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    """One executed baseline/probe request pair behind a FeatureVector.

    Retained only for reporting (ADR-011): it lets a report join a selected
    candidate back to the real request it was derived from without
    reporting recomputing or re-deriving anything. One InputPoint may own
    several probe-ready request contexts, so several observations can share
    the same combined `feature_vector_id`.
    """

    feature_vector_id: str
    input_point_id: str
    probe_plan: ProbePlan
    baseline_response: ResponseSnapshot
    probe_response: ResponseSnapshot


@dataclass(frozen=True, slots=True)
class _ProbeRun:
    """One executed request context before its InputPoint runs are combined."""

    feature_vector: FeatureVector
    probe_plan: ProbePlan
    baseline_response: ResponseSnapshot
    probe_response: ResponseSnapshot


@dataclass(frozen=True, slots=True)
class AccessProbeObservation:
    """The executed reference/comparison pair behind an ``AccessCandidate``.

    Same reporting-join purpose as :class:`ProbeObservation`, but for the
    separate BAC pipeline (ADR-012/ADR-014): credential-stripped or
    identifier-substituted GET re-sends, never an injection probe.
    """

    candidate_id: str
    access_probe_plan: AccessProbePlan
    reference_response: ResponseSnapshot
    comparison_response: ResponseSnapshot
    features: Mapping[str, FeatureObservation] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    adapter_result: LegacyAdapterResult | None
    scoring_results: tuple[ScoringResult, ...]
    selection: SelectionOutcome
    warnings: tuple[str, ...]
    probe_observations: tuple[ProbeObservation, ...]
    elapsed_seconds: float
    discovery_result: CanonicalDiscoveryResult | None = None
    crawl_result: StaticCrawlResult | None = None
    combined_result: CombinedDiscoveryResult | None = None
    feature_vectors: tuple[FeatureVector, ...] = ()
    access_scoring_results: tuple[AccessScoringResult, ...] = ()
    access_probe_observations: tuple[AccessProbeObservation, ...] = ()

    @property
    def dynamic_crawl_result(self) -> DynamicCrawlResult | None:
        """Return Dynamic crawl evidence when combined discovery was requested."""

        if self.combined_result is None:
            return None
        return self.combined_result.dynamic_crawl

    @property
    def endpoints(self) -> tuple[Endpoint, ...]:
        if self.discovery_result is not None:
            return self.discovery_result.endpoints
        if self.adapter_result is not None:
            return self.adapter_result.endpoints
        raise PipelineError("analysis result has no discovery source")

    @property
    def input_points(self) -> tuple[InputPoint, ...]:
        if self.discovery_result is not None:
            return self.discovery_result.input_points
        if self.adapter_result is not None:
            return self.adapter_result.input_points
        raise PipelineError("analysis result has no discovery source")


def analyze_legacy_records(
    records: Sequence[LegacyCrawlRecord | Mapping[str, Any]],
    *,
    top_k: int,
    transport: RequestTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    enable_access: bool = False,
) -> AnalysisResult:
    """Run adapter-compatible records through the implemented v0.1 pipeline."""

    adapter_result = LegacyCrawlerAdapter().convert(records)
    input_points = {
        input_point.id or "": input_point
        for input_point in adapter_result.input_points
    }
    request_templates = {
        template.id or "": template
        for template in adapter_result.request_templates
    }
    ready_contexts: list[
        tuple[InputPoint, RequestTemplate, InputPointRequestContext]
    ] = []
    for context in sorted(
        adapter_result.input_point_request_contexts,
        key=lambda item: item.id,
    ):
        input_point = input_points.get(context.input_point_id)
        request_template = request_templates.get(context.request_template_id)
        if input_point is None or request_template is None:
            raise PipelineError("adapter emitted an unresolved request context")
        ready_contexts.append((input_point, request_template, context))

    return _analyze_contexts(
        ready_contexts,
        top_k=top_k,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        initial_warnings=adapter_result.warnings,
        adapter_result=adapter_result,
        enable_access=enable_access,
    )


def analyze_discovery_result(
    discovery_result: CanonicalDiscoveryResult,
    *,
    top_k: int,
    transport: RequestTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    enable_access: bool = False,
) -> AnalysisResult:
    """Analyze READY GET/POST contexts from a canonical native discovery result."""

    if not isinstance(discovery_result, CanonicalDiscoveryResult):
        raise PipelineError(
            "discovery_result must be a CanonicalDiscoveryResult"
        )
    discovery_result.validate()
    return _analyze_contexts(
        discovery_result.ready_contexts(),
        top_k=top_k,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        initial_warnings=tuple(
            f"discovery {warning.code}: {warning.message}"
            for warning in discovery_result.warnings
        ),
        discovery_result=discovery_result,
        allowed_methods=frozenset({HttpMethod.GET, HttpMethod.POST}),
        enable_access=enable_access,
    )


def analyze_url(
    root_url: str,
    *,
    top_k: int,
    crawl_policy: CrawlPolicy | None = None,
    crawler: StaticCrawler | None = None,
    crawler_transport: StaticCrawlerTransport | None = None,
    dynamic_authority: DynamicRequestAuthority | None = None,
    dynamic_policy: DynamicCrawlPolicy | None = None,
    dynamic_crawler: DynamicCrawler | None = None,
    transport: RequestTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    on_crawl_validated: Callable[
        [StaticCrawlResult | CombinedDiscoveryResult], None
    ]
    | None = None,
    elide_sensitive_forms: bool = False,
    enable_access: bool = False,
) -> AnalysisResult:
    """Analyze Static discovery, or explicit Static-plus-Dynamic discovery."""

    if crawler is not None and crawler_transport is not None:
        raise PipelineError(
            "crawler and crawler_transport cannot be supplied together"
        )
    if on_crawl_validated is not None and not callable(on_crawl_validated):
        raise PipelineError("on_crawl_validated must be callable")
    if type(elide_sensitive_forms) is not bool:
        raise PipelineError("elide_sensitive_forms must be a bool")
    if dynamic_authority is None and (
        dynamic_policy is not None or dynamic_crawler is not None
    ):
        raise PipelineError(
            "dynamic policy and crawler require explicit dynamic authority"
        )
    _require_loopback_request(root_url)
    if dynamic_authority is not None:
        try:
            combined = discover_native_combined(
                root_url,
                authority=dynamic_authority,
                static_policy=crawl_policy,
                dynamic_policy=dynamic_policy,
                static_crawler=_combined_static_crawler(
                    crawler=crawler,
                    crawler_transport=crawler_transport,
                ),
                dynamic_crawler=dynamic_crawler,
            )
        except TypeError as exc:
            raise DynamicIntegrityError(
                "combined discovery boundary returned an invalid type"
            ) from exc
        if type(combined) is not CombinedDiscoveryResult:
            raise DynamicIntegrityError(
                "combined discovery must return CombinedDiscoveryResult"
            )
        try:
            combined = replace(combined)
        except (TypeError, ValueError) as exc:
            raise DynamicIntegrityError(
                "combined discovery wrapper failed revalidation"
            ) from exc
        if on_crawl_validated is not None:
            on_crawl_validated(combined)
        analysis = analyze_discovery_result(
            combined.discovery,
            top_k=top_k,
            transport=transport,
            timeout_seconds=timeout_seconds,
            max_body_bytes=max_body_bytes,
            enable_access=enable_access,
        )
        return replace(
            analysis,
            warnings=(
                *analysis.warnings,
                *_combined_handoff_warnings(combined),
            ),
            crawl_result=combined.static_crawl,
            combined_result=combined,
        )

    if elide_sensitive_forms:
        active_crawler = _combined_static_crawler(
            crawler=crawler,
            crawler_transport=crawler_transport,
        )
    else:
        active_crawler = crawler
        if active_crawler is None:
            active_crawler = (
                StaticCrawler(transport=crawler_transport)
                if crawler_transport is not None
                else StaticCrawler()
            )
    crawl_result = active_crawler.crawl(root_url, crawl_policy)
    if type(crawl_result) is not StaticCrawlResult:
        raise PipelineError("Static discovery must return StaticCrawlResult")
    try:
        crawl_result = replace(crawl_result)
    except (TypeError, ValueError) as exc:
        raise PipelineError("Static discovery result failed revalidation") from exc
    if on_crawl_validated is not None:
        on_crawl_validated(crawl_result)
    analysis = analyze_discovery_result(
        crawl_result.discovery,
        top_k=top_k,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        enable_access=enable_access,
    )
    return replace(analysis, crawl_result=crawl_result)


def _combined_static_crawler(
    *,
    crawler: StaticCrawler | None,
    crawler_transport: StaticCrawlerTransport | None,
) -> StaticCrawler:
    """Bind pre-canonical sensitive-form elision only for combined mode."""

    if crawler is not None:
        if type(crawler) is not StaticCrawler:
            raise TypeError("crawler must be a StaticCrawler")
        return replace(
            crawler,
            extractor=extract_static_html_with_sensitive_form_elision,
        )
    if crawler_transport is None:
        return StaticCrawler(
            extractor=extract_static_html_with_sensitive_form_elision,
        )
    return StaticCrawler(
        transport=crawler_transport,
        extractor=extract_static_html_with_sensitive_form_elision,
    )


def _combined_handoff_warnings(
    combined: CombinedDiscoveryResult,
) -> tuple[str, ...]:
    ready = sum(
        item.status == ProbeReadyStatus.READY
        for item in combined.discovery.probe_readiness
    )
    not_ready = sum(
        item.status == ProbeReadyStatus.NOT_READY
        for item in combined.discovery.probe_readiness
    )
    warnings = [
        "discovery NATIVE_COMBINED: "
        f"READY contexts={ready}; NOT_READY contexts={not_ready}"
    ]
    if combined.completion == DynamicCrawlCompletion.DEGRADED:
        warnings.append(
            "discovery DYNAMIC_INCOMPLETE: validated partial Dynamic "
            "discovery was retained"
        )
    return tuple(warnings)


def _analyze_contexts(
    contexts: Sequence[
        tuple[InputPoint, RequestTemplate, InputPointRequestContext]
    ],
    *,
    top_k: int,
    transport: RequestTransport | None,
    timeout_seconds: float,
    max_body_bytes: int,
    initial_warnings: Sequence[str],
    adapter_result: LegacyAdapterResult | None = None,
    discovery_result: CanonicalDiscoveryResult | None = None,
    allowed_methods: frozenset[HttpMethod] | None = None,
    enable_access: bool = False,
) -> AnalysisResult:
    active_transport = transport if transport is not None else UrlLibTransport()
    executor = RequestExecutor(
        transport=active_transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    planner = ProbePlanner()
    collector_label = _collector_label(discovery_result)
    runs: dict[str, list[_ProbeRun]] = {}
    warnings = list(initial_warnings)
    access_scoring_results: list[AccessScoringResult] = []
    access_probe_observations: list[AccessProbeObservation] = []
    credential_strip_planned_templates: set[str] = set()
    started = monotonic()

    for input_point, request_template, context in sorted(
        contexts,
        key=lambda item: item[2].id,
    ):
        # ASP.NET Web Forms state-management values can be very large and are
        # maintained by the framework rather than by application business
        # logic. Retain them in discovery, but do not spend baseline/probe,
        # scoring, or LLM-verification work on them for the current SQLi/XSS
        # scope.
        if _is_framework_state_input(input_point):
            warnings.append(
                f"input point {input_point.id} skipped: "
                f"framework state parameter {input_point.name!r}"
            )
            continue

        if (
            allowed_methods is not None
            and request_template.method not in allowed_methods
        ):
            warnings.append(
                f"input point {input_point.id} context {context.id} skipped: "
                f"{collector_label} analysis does not support HTTP method "
                f"{request_template.method.value}"
            )
            continue
        _require_loopback_request(request_template.url)
        try:
            probe_plan = planner.plan(input_point, request_template, context)
        except ProbePlanningError as exc:
            warnings.append(
                f"input point {input_point.id} context {context.id} skipped: {exc}"
            )
            continue

        execution = executor.execute_plan(probe_plan)
        feature_vector = extract_minimal_features(
            input_point,
            probe_plan,
            execution.response_pair,
            execution.baseline_response,
            execution.probe_response,
        )
        runs.setdefault(input_point.id or "", []).append(
            _ProbeRun(
                feature_vector=feature_vector,
                probe_plan=probe_plan,
                baseline_response=execution.baseline_response,
                probe_response=execution.probe_response,
            )
        )

        # BAC (opt-in): re-send the same GET with credentials stripped (once
        # per template) or a numeric identifier substituted. These are extra
        # network requests beyond the injection baseline/probe, so they run
        # only when access checking is explicitly enabled -- keeping the
        # request budget explicit. Non-destructive, GET-only, scored in the
        # separate access family (ADR-014/ADR-035).
        if enable_access and request_template.method == HttpMethod.GET:
            template_id = request_template.id or ""
            if template_id not in credential_strip_planned_templates:
                credential_strip_planned_templates.add(template_id)
                credential_plan = plan_credential_strip(request_template)
                if credential_plan is not None:
                    _run_access_plan(
                        credential_plan,
                        transport=active_transport,
                        timeout_seconds=timeout_seconds,
                        max_body_bytes=max_body_bytes,
                        access_scoring_results=access_scoring_results,
                        access_probe_observations=access_probe_observations,
                    )
            identifier_plan = plan_identifier_substitution(
                input_point, request_template
            )
            if identifier_plan is not None:
                _run_access_plan(
                    identifier_plan,
                    transport=active_transport,
                    timeout_seconds=timeout_seconds,
                    max_body_bytes=max_body_bytes,
                    access_scoring_results=access_scoring_results,
                    access_probe_observations=access_probe_observations,
                )

    scoring_results: list[ScoringResult] = []
    feature_vectors: list[FeatureVector] = []
    probe_observations: list[ProbeObservation] = []
    for input_point_id, input_point_runs in sorted(runs.items()):
        combined = combine_input_point_features(
            [run.feature_vector for run in input_point_runs]
        )
        feature_vectors.append(combined)
        probe_observations.extend(
            ProbeObservation(
                feature_vector_id=combined.id or "",
                input_point_id=input_point_id,
                probe_plan=run.probe_plan,
                baseline_response=run.baseline_response,
                probe_response=run.probe_response,
            )
            for run in input_point_runs
        )
        scoring_results.extend(generate_candidates(combined))

    elapsed_seconds = monotonic() - started
    selection = select_top_k(scoring_results, k=top_k)
    return AnalysisResult(
        adapter_result=adapter_result,
        scoring_results=tuple(scoring_results),
        selection=selection,
        warnings=tuple(warnings),
        probe_observations=tuple(probe_observations),
        elapsed_seconds=elapsed_seconds,
        discovery_result=discovery_result,
        feature_vectors=tuple(feature_vectors),
        access_scoring_results=tuple(access_scoring_results),
        access_probe_observations=tuple(access_probe_observations),
    )


def _collector_label(discovery_result: CanonicalDiscoveryResult | None) -> str:
    """Name the collector that produced the skipped context, not a guess."""

    if discovery_result is None:
        return "legacy adapter"
    return discovery_result.discovery_metadata.collector_kind.value


def _run_access_plan(
    plan: AccessProbePlan,
    *,
    transport: RequestTransport,
    timeout_seconds: float,
    max_body_bytes: int,
    access_scoring_results: list[AccessScoringResult],
    access_probe_observations: list[AccessProbeObservation],
) -> None:
    _require_loopback_request(plan.reference_request.url)
    _require_loopback_request(plan.comparison_request.url)
    execution: AccessProbeExecutionResult = execute_access_plan(
        plan,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    features = extract_access_features(
        plan,
        execution.reference_response,
        execution.comparison_response,
    )
    result = score_access_plan(plan, features)
    access_scoring_results.append(result)
    access_probe_observations.append(
        AccessProbeObservation(
            candidate_id=result.candidate.id or "",
            access_probe_plan=plan,
            reference_response=execution.reference_response,
            comparison_response=execution.comparison_response,
            features=features,
        )
    )


def _require_loopback_request(url: str) -> None:
    try:
        require_loopback_http_url(url)
    except LoopbackSafetyError as exc:
        raise PipelineError(
            "CLI analysis permits only localhost or loopback IP request templates"
        ) from exc
