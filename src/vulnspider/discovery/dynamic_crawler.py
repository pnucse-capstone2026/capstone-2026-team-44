"""Bounded deterministic same-authority Native Dynamic crawler."""

from __future__ import annotations

import copyreg
from dataclasses import dataclass, field, replace
from enum import StrEnum
from heapq import heappop, heappush
from math import isfinite
import os
from pathlib import Path
import pickle
import signal
import subprocess
import sys
import tempfile
from time import monotonic
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlsplit

from vulnspider.discovery.contracts import (
    BACStaticHint,
    CanonicalDiscoveryResult,
    CollectorKind,
    CrawlStatistics,
    DiscoveryMetadata,
    DiscoveryProvenance,
    DiscoverySafetyInvariant,
    DiscoveryWarning,
    ProbeReadiness,
    ScopeMetadata,
    scope_id_for_root,
)
from vulnspider.discovery.dynamic_browser import (
    BrowserAuditSummary,
    DynamicBrowser,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicBrowserPolicy,
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    DynamicRequestAuthority,
    NetworkDiscoveryCollection,
    PlaywrightDynamicBrowser,
)
from vulnspider.discovery.network_canonicalization import (
    canonicalize_network_discovery,
)
from vulnspider.discovery.navigation_safety import (
    authentication_state_change_token,
    automatic_navigation_within_root_path,
)
from vulnspider.discovery.rendered_dom import (
    RenderedDomExtractionResult,
    RenderedDomPolicy,
    extract_rendered_dom,
)
from vulnspider.discovery.static_crawler import (
    StaticCrawlerError,
    canonicalize_crawl_url,
    same_origin_crawl_url,
)
from vulnspider.domain import (
    Endpoint,
    InputPoint,
    InputPointRequestContext,
    RequestTemplate,
    stable_fingerprint,
)


DYNAMIC_CRAWLER_VERSION = "native-dynamic-crawler/1.2"
DYNAMIC_SCOPE_POLICY_VERSION = "same-origin-v1"
_REQUIRED_SAFETY_INVARIANT = (
    DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION
)
_DYNAMIC_WORKER_ENV = "VULNSPIDER_DYNAMIC_CRAWL_WORKER"


def _restore_mapping_proxy(value: dict[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(value)


def _reduce_mapping_proxy(
    value: Mapping[str, Any],
) -> tuple[Callable[[dict[str, Any]], Mapping[str, Any]], tuple[dict[str, Any]]]:
    return _restore_mapping_proxy, (dict(value),)


copyreg.pickle(type(MappingProxyType({})), _reduce_mapping_proxy)


_REDIRECT_PATH_HINTS = frozenset({
    "/redirect",
    "/redir",
    "/out",
    "/go",
    "/forward",
})
_REDIRECT_PARAMETER_NAMES = frozenset({
    "to",
    "url",
    "target",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "continue",
})


def _http_origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized HTTP(S) origin, or None for an invalid URL."""

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return None
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, host, port)


def _external_redirect_target(
    root_url: str,
    candidate_url: str,
) -> str | None:
    """Detect a same-origin redirector that points at another HTTP(S) origin.

    The redirector URL itself remains part of discovery. This helper is only
    used to prevent the dynamic crawler from navigating through the redirector
    to a cross-origin destination.
    """

    root_origin = _http_origin(root_url)
    if root_origin is None:
        return None
    try:
        parsed = urlsplit(candidate_url)
    except (TypeError, ValueError):
        return None

    path = (parsed.path.rstrip("/") or "/").lower()
    if path not in _REDIRECT_PATH_HINTS:
        return None

    for raw_name, raw_value in parse_qsl(parsed.query, keep_blank_values=True):
        if raw_name.strip().lower() not in _REDIRECT_PARAMETER_NAMES:
            continue
        value = raw_value.strip()
        if not value:
            continue
        target_origin = _http_origin(value)
        if target_origin is None:
            continue
        if target_origin != root_origin:
            return value
    return None


class DynamicCrawlerError(ValueError):
    """Raised when Dynamic crawl input or output violates its boundary."""


class DynamicCrawlCompletion(StrEnum):
    COMPLETE = "COMPLETE"
    DEGRADED = "DEGRADED"


class DynamicCrawlTerminationReason(StrEnum):
    FRONTIER_EXHAUSTED = "FRONTIER_EXHAUSTED"
    COMPLETED_WITH_FAILURES = "COMPLETED_WITH_FAILURES"
    PAGE_BUDGET_EXHAUSTED = "PAGE_BUDGET_EXHAUSTED"
    DEPTH_BUDGET_EXHAUSTED = "DEPTH_BUDGET_EXHAUSTED"
    NAVIGATION_BUDGET_EXHAUSTED = "NAVIGATION_BUDGET_EXHAUSTED"
    ELAPSED_BUDGET_EXHAUSTED = "ELAPSED_BUDGET_EXHAUSTED"
    OPERATIONAL_FAILURE = "OPERATIONAL_FAILURE"


@dataclass(frozen=True, slots=True)
class DynamicCrawlPolicy:
    """Reviewed Milestone 4 bounds for one managed browser crawl."""

    max_pages: int = 5
    max_depth: int = 1
    max_navigation_attempts: int = 8
    max_route_actions: int = 3
    max_elapsed_seconds: float = 15.0
    navigation_timeout_seconds: float = 3.0
    max_redirects_per_navigation: int = 3
    request_decision_budget: int = 50
    rendered_dom_policy: RenderedDomPolicy = field(default_factory=RenderedDomPolicy)

    def __post_init__(self) -> None:
        for name in (
            "max_pages",
            "max_navigation_attempts",
            "max_route_actions",
            "max_redirects_per_navigation",
            "request_decision_budget",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise DynamicCrawlerError(f"{name} must be a positive integer")
        if type(self.max_depth) is not int or self.max_depth < 0:
            raise DynamicCrawlerError("max_depth must be a non-negative integer")
        for name in ("max_elapsed_seconds", "navigation_timeout_seconds"):
            value = getattr(self, name)
            if (
                type(value) not in {int, float}
                or isinstance(value, bool)
                or not isfinite(value)
                or value <= 0
            ):
                raise DynamicCrawlerError(f"{name} must be finite and positive")
            object.__setattr__(self, name, float(value))
        if type(self.rendered_dom_policy) is not RenderedDomPolicy:
            raise DynamicCrawlerError(
                "rendered_dom_policy must be a canonical RenderedDomPolicy"
            )

    def to_dict(self) -> dict[str, int | float | str]:
        return {
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "max_navigation_attempts": self.max_navigation_attempts,
            "max_route_actions": self.max_route_actions,
            "max_elapsed_seconds": self.max_elapsed_seconds,
            "navigation_timeout_seconds": self.navigation_timeout_seconds,
            "max_redirects_per_navigation": self.max_redirects_per_navigation,
            "request_decision_budget": self.request_decision_budget,
            "rendered_dom_policy_fingerprint": self.rendered_dom_policy.fingerprint,
        }


@dataclass(frozen=True, slots=True)
class DynamicPageResult:
    """One successful rendered main-frame page owned by the crawl result."""

    requested_url: str
    page_url: str
    parent_url: str | None
    depth: int
    component: RenderedDomExtractionResult

    def __post_init__(self) -> None:
        try:
            requested = canonicalize_crawl_url(self.requested_url)
            page = canonicalize_crawl_url(self.page_url)
            parent = (
                None
                if self.parent_url is None
                else canonicalize_crawl_url(self.parent_url)
            )
        except StaticCrawlerError as exc:
            raise DynamicCrawlerError("Dynamic page URLs must be canonical") from exc
        if requested != self.requested_url or page != self.page_url:
            raise DynamicCrawlerError("Dynamic page URLs must already be canonical")
        if parent != self.parent_url:
            raise DynamicCrawlerError("Dynamic page parent URL must be canonical")
        if type(self.depth) is not int or self.depth < 0:
            raise DynamicCrawlerError("Dynamic page depth must be non-negative")
        if type(self.component) is not RenderedDomExtractionResult:
            raise TypeError("component must be RenderedDomExtractionResult")
        if self.component.source_url != self.page_url:
            raise DynamicCrawlerError("Dynamic page component source mismatch")
        self.component.discovery.validate()
        if (
            self.component.discovery.discovery_metadata.collector_kind
            != CollectorKind.NATIVE_DYNAMIC
        ):
            raise DynamicCrawlerError("Dynamic page component has wrong collector")
        if _REQUIRED_SAFETY_INVARIANT not in self.component.discovery.safety_invariants:
            raise DynamicCrawlerError("Dynamic page component lacks safety invariant")

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "page_url": self.page_url,
            "parent_url": self.parent_url,
            "depth": self.depth,
            "component": self.component.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class DynamicCrawlResult:
    """Validated Dynamic-only crawl handoff for later Milestone 5 orchestration."""

    root_url: str
    visited_urls: tuple[str, ...]
    pages: tuple[DynamicPageResult, ...]
    completion: DynamicCrawlCompletion
    termination_reason: DynamicCrawlTerminationReason
    navigation_attempts: int
    route_actions_attempted: int
    discovery: CanonicalDiscoveryResult
    browser_audit: BrowserAuditSummary

    def __post_init__(self) -> None:
        try:
            canonical_root = canonicalize_crawl_url(self.root_url)
        except StaticCrawlerError as exc:
            raise DynamicCrawlerError("Dynamic root URL must be canonical") from exc
        if canonical_root != self.root_url:
            raise DynamicCrawlerError("Dynamic root URL must already be canonical")
        if type(self.visited_urls) is not tuple or any(
            type(item) is not str for item in self.visited_urls
        ):
            raise TypeError("visited_urls must be a tuple of strings")
        if len(self.visited_urls) != len(set(self.visited_urls)):
            raise DynamicCrawlerError("visited_urls must be unique")
        for item in self.visited_urls:
            try:
                canonical_visited = canonicalize_crawl_url(item)
            except StaticCrawlerError as exc:
                raise DynamicCrawlerError("visited URL must be canonical") from exc
            if canonical_visited != item:
                raise DynamicCrawlerError("visited URL must already be canonical")
            if not same_origin_crawl_url(self.root_url, item):
                raise DynamicCrawlerError("visited URL escaped Dynamic origin")
        if self.visited_urls and self.visited_urls[0] != self.root_url:
            raise DynamicCrawlerError("Dynamic root must be the first visited URL")
        if type(self.pages) is not tuple or any(
            type(item) is not DynamicPageResult for item in self.pages
        ):
            raise TypeError("pages must be a tuple of DynamicPageResult")
        page_urls = tuple(item.page_url for item in self.pages)
        if len(page_urls) != len(set(page_urls)):
            raise DynamicCrawlerError("rendered page URLs must be unique")
        requested_page_urls = tuple(item.requested_url for item in self.pages)
        if len(requested_page_urls) != len(set(requested_page_urls)):
            raise DynamicCrawlerError("rendered requested URLs must be unique")
        completion = DynamicCrawlCompletion(self.completion)
        termination = DynamicCrawlTerminationReason(self.termination_reason)
        if type(self.navigation_attempts) is not int or self.navigation_attempts < 0:
            raise DynamicCrawlerError("navigation_attempts must be non-negative")
        if (
            type(self.route_actions_attempted) is not int
            or self.route_actions_attempted < 0
        ):
            raise DynamicCrawlerError("route_actions_attempted must be non-negative")
        if type(self.browser_audit) is not BrowserAuditSummary:
            raise TypeError("browser_audit must be BrowserAuditSummary")
        self.discovery.validate()
        if self.discovery.discovery_metadata.collector_kind != CollectorKind.NATIVE_DYNAMIC:
            raise DynamicCrawlerError("Dynamic aggregate has wrong collector")
        if _REQUIRED_SAFETY_INVARIANT not in self.discovery.safety_invariants:
            raise DynamicCrawlerError("Dynamic aggregate lacks safety invariant")
        if self.discovery.crawl_statistics.pages_processed != len(self.pages):
            raise DynamicCrawlerError("Dynamic page statistics do not match pages")
        if self.discovery.crawl_statistics.requests_attempted != self.navigation_attempts:
            raise DynamicCrawlerError("Dynamic navigation statistics do not match")
        if completion == DynamicCrawlCompletion.COMPLETE and termination != (
            DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED
        ):
            raise DynamicCrawlerError("complete Dynamic result has non-final termination")
        if completion == DynamicCrawlCompletion.DEGRADED and termination == (
            DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED
        ):
            raise DynamicCrawlerError("degraded Dynamic result lacks a failure reason")

        visited_positions = {
            url: index for index, url in enumerate(self.visited_urls)
        }
        retained_pages: dict[str, DynamicPageResult] = {}
        previous_visit_position = -1
        previous_order_key: tuple[int, str] | None = None
        for page_result in self.pages:
            if page_result.requested_url not in visited_positions:
                raise DynamicCrawlerError("Dynamic page was not visited")
            visit_position = visited_positions[page_result.requested_url]
            if visit_position <= previous_visit_position:
                raise DynamicCrawlerError("Dynamic pages do not follow visit order")
            previous_visit_position = visit_position
            order_key = (page_result.depth, page_result.requested_url)
            if previous_order_key is not None and order_key < previous_order_key:
                raise DynamicCrawlerError("Dynamic page ordering is not deterministic")
            previous_order_key = order_key
            for url in (
                page_result.requested_url,
                page_result.page_url,
                page_result.parent_url,
            ):
                if url is not None and not same_origin_crawl_url(self.root_url, url):
                    raise DynamicCrawlerError("Dynamic page topology escaped origin")
            if page_result.depth > self.discovery.crawl_statistics.depth_budget:
                raise DynamicCrawlerError("Dynamic page exceeds depth budget")
            if page_result.depth == 0:
                if (
                    page_result.parent_url is not None
                    or page_result.requested_url != self.root_url
                    or retained_pages
                ):
                    raise DynamicCrawlerError("Dynamic root page topology is invalid")
            else:
                parent = retained_pages.get(page_result.parent_url or "")
                if parent is None or page_result.depth != parent.depth + 1:
                    raise DynamicCrawlerError("Dynamic child page topology is invalid")
            component = page_result.component.discovery
            if component.crawl_statistics.max_depth_reached != page_result.depth:
                raise DynamicCrawlerError("Dynamic page depth ownership mismatch")
            for provenance in component.crawl_provenance:
                if (
                    provenance.source_url != page_result.page_url
                    or provenance.parent_url != page_result.parent_url
                    or provenance.depth != page_result.depth
                ):
                    raise DynamicCrawlerError("Dynamic page provenance mismatch")
            if page_result.component.discovery.discovery_metadata != (
                self.discovery.discovery_metadata
            ):
                raise DynamicCrawlerError("Dynamic page metadata ownership mismatch")
            if page_result.component.discovery.scope_metadata != self.discovery.scope_metadata:
                raise DynamicCrawlerError("Dynamic page scope ownership mismatch")
            retained_pages[page_result.page_url] = page_result
        object.__setattr__(self, "completion", completion)
        object.__setattr__(self, "termination_reason", termination)

    @property
    def warnings(self) -> tuple[DiscoveryWarning, ...]:
        return self.discovery.warnings

    def to_dict(self) -> dict[str, Any]:
        audit = self.browser_audit
        return {
            "root_url": self.root_url,
            "visited_urls": list(self.visited_urls),
            "pages": [item.to_dict() for item in self.pages],
            "completion": self.completion.value,
            "termination_reason": self.termination_reason.value,
            "navigation_attempts": self.navigation_attempts,
            "route_actions_attempted": self.route_actions_attempted,
            "discovery": self.discovery.to_dict(),
            "browser_audit": {
                "main_frame_navigation_allowed_count": (
                    audit.main_frame_navigation_allowed_count
                ),
                "main_frame_navigation_blocked_count": (
                    audit.main_frame_navigation_blocked_count
                ),
                "redirect_attempt_count": audit.redirect_attempt_count,
                "redirect_allowed_count": audit.redirect_allowed_count,
                "redirect_block_count": audit.redirect_block_count,
                "redirect_followed_count": audit.redirect_followed_count,
                "http_allowed_count": audit.http_allowed_count,
                "http_blocked_count": audit.http_blocked_count,
                "websocket_attempt_count": audit.websocket_attempt_count,
                "websocket_blocked_count": audit.websocket_blocked_count,
                "websocket_connected_count": audit.websocket_connected_count,
                "cleanup_error_codes": list(audit.cleanup_error_codes),
                "cleanup_complete": audit.cleanup_complete,
                "network_observations": [
                    {
                        "method": observation.method,
                        "resource_type": observation.resource_type,
                        "scheme": observation.scheme,
                        "host": observation.host,
                        "effective_port": observation.effective_port,
                        "path_fingerprint": observation.path_fingerprint,
                        "path_segment_count": observation.path_segment_count,
                        "query_parameter_names": list(
                            observation.query_parameter_names
                        ),
                        "scope": observation.scope.value,
                        "occurrence_count": observation.occurrence_count,
                    }
                    for observation in audit.network_observations
                ],
                "network_observation_overflow_count": (
                    audit.network_observation_overflow_count
                ),
            },
        }


@dataclass(slots=True)
class _CrawlState:
    root_url: str
    policy: DynamicCrawlPolicy
    authority: DynamicRequestAuthority
    metadata: DiscoveryMetadata
    scope: ScopeMetadata
    started: float
    queue: list[tuple[int, str, str]]
    scheduled: set[str]
    attempted: set[str] = field(default_factory=set)
    visited_urls: list[str] = field(default_factory=list)
    pages: list[DynamicPageResult] = field(default_factory=list)
    page_urls: set[str] = field(default_factory=set)
    warnings: dict[str, DiscoveryWarning] = field(default_factory=dict)
    skipped: int = 0
    explicit_navigation_calls: int = 0
    route_actions_attempted: int = 0
    operational_failure: bool = False
    depth_budget_exhausted: bool = False
    stop_reason: DynamicCrawlTerminationReason | None = None
    last_failure_code: str | None = None
    integrity_error: Exception | None = None

    def warn(
        self,
        code: str,
        message: str,
        details: Mapping[str, Any] | None = None,
        *,
        skipped: bool = True,
    ) -> None:
        warning = DiscoveryWarning(
            code=code,
            message=message,
            details=details or {},
        )
        self.warnings.setdefault(warning.id or "", warning)
        if skipped:
            self.skipped += 1


@dataclass(frozen=True, slots=True)
class DynamicCrawler:
    browser: DynamicBrowser = field(default_factory=PlaywrightDynamicBrowser)
    clock: Callable[[], float] = monotonic

    def crawl(
        self,
        root_url: str,
        policy: DynamicCrawlPolicy,
        authority: DynamicRequestAuthority,
    ) -> DynamicCrawlResult:
        if type(policy) is not DynamicCrawlPolicy:
            raise DynamicCrawlerError("policy must be DynamicCrawlPolicy")
        if type(authority) is not DynamicRequestAuthority:
            raise DynamicCrawlerError("authority must be DynamicRequestAuthority")
        if (
            type(self.browser) is PlaywrightDynamicBrowser
            and os.environ.get(_DYNAMIC_WORKER_ENV) != "1"
        ):
            return self._crawl_supervised(root_url, policy, authority)
        return self._crawl_in_process(root_url, policy, authority)

    def _crawl_supervised(
        self,
        root_url: str,
        policy: DynamicCrawlPolicy,
        authority: DynamicRequestAuthority,
    ) -> DynamicCrawlResult:
        with tempfile.TemporaryDirectory(
            prefix="vulnspider-dynamic-worker-"
        ) as temp_dir:
            input_path = Path(temp_dir) / "input.pickle"
            output_path = Path(temp_dir) / "output.pickle"
            input_path.write_bytes(
                pickle.dumps((root_url, policy, authority), protocol=5)
            )
            environment = dict(os.environ)
            environment[_DYNAMIC_WORKER_ENV] = "1"
            parent_cwd = Path.cwd()
            python_path_entries = [
                Path(item) if Path(item).is_absolute() else parent_cwd / item
                for item in environment.get("PYTHONPATH", "").split(os.pathsep)
                if item
            ]
            source_root = Path(__file__).resolve().parents[2]
            if source_root not in python_path_entries:
                python_path_entries.insert(0, source_root)
            environment["PYTHONPATH"] = os.pathsep.join(
                str(item.resolve()) for item in python_path_entries
            )
            command = (
                sys.executable,
                "-B",
                "-c",
                (
                    "from vulnspider.discovery.dynamic_crawler import "
                    "_dynamic_worker_main; _dynamic_worker_main()"
                ),
                str(input_path),
                str(output_path),
            )
            process_options: dict[str, Any] = {
                "env": environment,
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "cwd": temp_dir,
            }
            if os.name == "nt":
                process_options["creationflags"] = (
                    subprocess.CREATE_NEW_PROCESS_GROUP
                    | subprocess.CREATE_NO_WINDOW
                )
            else:
                process_options["start_new_session"] = True
            process = subprocess.Popen(command, **process_options)
            try:
                process.wait(timeout=policy.max_elapsed_seconds)
            except subprocess.TimeoutExpired:
                _terminate_worker_tree(process)
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.OPERATION_TIMEOUT,
                    "Dynamic crawl exceeded its hard lifecycle deadline.",
                ) from None
            if process.returncode != 0 or not output_path.is_file():
                raise DynamicCrawlerError(
                    "Dynamic crawl worker did not produce a validated result"
                )
            outcome, value = pickle.loads(output_path.read_bytes())
            if outcome == "error":
                if not isinstance(value, Exception):
                    raise DynamicCrawlerError(
                        "Dynamic crawl worker returned an invalid failure"
                    )
                raise value
            if outcome != "ok" or type(value) is not DynamicCrawlResult:
                raise DynamicCrawlerError(
                    "Dynamic crawl worker returned an invalid result"
                )
            return value

    def _crawl_in_process(
        self,
        root_url: str,
        policy: DynamicCrawlPolicy,
        authority: DynamicRequestAuthority,
    ) -> DynamicCrawlResult:
        try:
            canonical_root = canonicalize_crawl_url(root_url)
        except StaticCrawlerError as exc:
            raise DynamicCrawlerError("root_url must be absolute canonical HTTP(S)") from exc
        if canonical_root != authority.root_url:
            raise DynamicCrawlerError("root_url must match immutable request authority")

        metadata = DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_DYNAMIC,
            collector_version=DYNAMIC_CRAWLER_VERSION,
            configuration_fingerprint=stable_fingerprint(
                "native-dynamic-crawl-policy",
                policy.to_dict(),
                stable_fingerprint(
                    "dynamic-request-authority",
                    authority.root_url,
                    authority.navigation_urls,
                    tuple(
                        (item.kind.value, item.url)
                        for item in authority.resource_grants
                    ),
                    authority.allow_rendered_navigation,
                    authority.allow_passive_same_origin_resources,
                ),
            ),
        )
        scope_ref = (
            "scope-decision:dynamic-authority:"
            + stable_fingerprint(
                "dynamic-authority-scope",
                authority.root_url,
                authority.navigation_urls,
            )[:16]
        )
        scope = ScopeMetadata(
            target_scope_id=scope_id_for_root(
                canonical_root,
                policy_version=DYNAMIC_SCOPE_POLICY_VERSION,
            ),
            root_url=canonical_root,
            scope_policy_version=DYNAMIC_SCOPE_POLICY_VERSION,
            scope_decision_refs=(scope_ref,),
        )
        state = _CrawlState(
            root_url=canonical_root,
            policy=policy,
            authority=authority,
            metadata=metadata,
            scope=scope,
            started=self.clock(),
            queue=[(0, canonical_root, "")],
            scheduled={canonical_root},
        )
        browser_policy = DynamicBrowserPolicy(
            navigation_timeout_seconds=policy.navigation_timeout_seconds,
            request_decision_budget=policy.request_decision_budget,
            navigation_request_budget=policy.max_navigation_attempts,
            max_redirects_per_navigation=policy.max_redirects_per_navigation,
            deadline_monotonic=state.started + policy.max_elapsed_seconds,
        )

        def crawl_operation(session: Any) -> None:
            try:
                self._crawl_session(state, session)
            except DynamicBrowserError:
                raise
            except Exception as exc:  # Preserve canonical/integrity failures.
                state.integrity_error = exc

        try:
            run = self.browser.run(
                authority,
                crawl_operation,
                policy=browser_policy,
            )
        except DynamicBrowserError as exc:
            if exc.audit is None:
                raise
            audit = exc.audit
            network_discovery = (
                exc.network_discovery or NetworkDiscoveryCollection()
            )
            if state.last_failure_code != exc.code.value:
                self._record_browser_failure(state, exc)
        else:
            audit = run.audit
            network_discovery = run.network_discovery

        if state.integrity_error is not None:
            raise state.integrity_error

        elapsed_seconds = max(0.0, self.clock() - state.started)
        if elapsed_seconds >= policy.max_elapsed_seconds and state.stop_reason is None:
            state.warn(
                "DYNAMIC_ELAPSED_BUDGET_EXHAUSTED",
                "Dynamic elapsed-time budget was exhausted.",
                {"max_elapsed_seconds": policy.max_elapsed_seconds},
            )
            state.stop_reason = DynamicCrawlTerminationReason.ELAPSED_BUDGET_EXHAUSTED
            state.operational_failure = True
        if not audit.cleanup_complete:
            state.warn(
                "DYNAMIC_CLEANUP_INCOMPLETE",
                "Managed browser cleanup did not complete.",
                {"cleanup_error_count": len(audit.cleanup_error_codes)},
            )
            state.operational_failure = True
            if state.stop_reason is None:
                state.stop_reason = DynamicCrawlTerminationReason.OPERATIONAL_FAILURE

        discovery = _build_dynamic_discovery(
            state,
            audit=audit,
            network_discovery=network_discovery,
            elapsed_ms=elapsed_seconds * 1000.0,
        )
        termination = self._termination_reason(state)
        completion = (
            DynamicCrawlCompletion.DEGRADED
            if state.operational_failure
            or termination
            not in {DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED}
            else DynamicCrawlCompletion.COMPLETE
        )
        return DynamicCrawlResult(
            root_url=canonical_root,
            visited_urls=tuple(state.visited_urls),
            pages=tuple(state.pages),
            completion=completion,
            termination_reason=termination,
            navigation_attempts=audit.main_frame_navigation_allowed_count,
            route_actions_attempted=state.route_actions_attempted,
            discovery=discovery,
            browser_audit=audit,
        )

    def _crawl_session(self, state: _CrawlState, session: Any) -> None:
        while state.queue:
            if len(state.pages) >= state.policy.max_pages:
                state.warn(
                    "DYNAMIC_PAGE_BUDGET_EXHAUSTED",
                    "Rendered page budget was exhausted before the next navigation.",
                    {"max_pages": state.policy.max_pages},
                )
                state.stop_reason = DynamicCrawlTerminationReason.PAGE_BUDGET_EXHAUSTED
                return
            remaining = self._remaining_seconds(state)
            if remaining <= 0:
                state.warn(
                    "DYNAMIC_ELAPSED_BUDGET_EXHAUSTED",
                    "Dynamic elapsed-time budget was exhausted.",
                    {"max_elapsed_seconds": state.policy.max_elapsed_seconds},
                )
                state.stop_reason = (
                    DynamicCrawlTerminationReason.ELAPSED_BUDGET_EXHAUSTED
                )
                state.operational_failure = True
                return
            if state.explicit_navigation_calls >= state.policy.max_navigation_attempts:
                state.warn(
                    "DYNAMIC_NAVIGATION_BUDGET_EXHAUSTED",
                    "Main-frame navigation budget was exhausted.",
                    {"max_navigation_attempts": state.policy.max_navigation_attempts},
                )
                state.stop_reason = (
                    DynamicCrawlTerminationReason.NAVIGATION_BUDGET_EXHAUSTED
                )
                state.operational_failure = True
                return

            depth, requested_url, parent_url = heappop(state.queue)
            if requested_url in state.attempted:
                continue
            state.attempted.add(requested_url)
            state.visited_urls.append(requested_url)
            state.explicit_navigation_calls += 1
            rendered_navigation = (
                bool(parent_url)
                and not state.authority.allows_navigation(requested_url)
                and state.authority.allows_rendered_navigation(requested_url)
            )
            try:
                navigation_options = {
                    "timeout_seconds": min(
                        state.policy.navigation_timeout_seconds,
                        remaining,
                    )
                }
                if rendered_navigation:
                    navigation_options["rendered_navigation"] = True
                final_raw = session.navigate(requested_url, **navigation_options)
            except DynamicBrowserError as exc:
                if exc.code == DynamicBrowserErrorCode.REDIRECT_DUPLICATE:
                    state.warn(
                        "DYNAMIC_REDIRECT_DUPLICATE",
                        "Redirect target was already dispatched in this crawl.",
                        {"url_fingerprint": _url_fingerprint(requested_url)},
                    )
                    continue
                self._record_browser_failure(state, exc, requested_url=requested_url)
                return

            try:
                final_url = canonicalize_crawl_url(final_raw)
            except StaticCrawlerError as exc:
                raise DynamicCrawlerError(
                    "browser returned a non-canonical navigation URL"
                ) from exc
            if not same_origin_crawl_url(state.root_url, final_url):
                raise DynamicCrawlerError("browser escaped exact same-origin scope")
            if not (
                state.authority.allows_navigation(final_url)
                or (rendered_navigation and final_url == requested_url)
            ):
                raise DynamicCrawlerError("browser returned an unauthorized final URL")

            status_getter = getattr(session, "navigation_status_code", None)
            status_code = status_getter() if callable(status_getter) else None
            if type(status_code) is int and status_code >= 400:
                state.warn(
                    "DYNAMIC_HTTP_ERROR",
                    "HTTP error page was isolated from rendered extraction.",
                    {
                        "status_code": status_code,
                        "url_fingerprint": _url_fingerprint(final_url),
                    },
                )
                state.operational_failure = True
                continue
            if final_url in state.page_urls:
                state.warn(
                    "DYNAMIC_REDIRECT_DUPLICATE",
                    "Redirect final URL was already represented by a rendered page.",
                    {"url_fingerprint": _url_fingerprint(final_url)},
                )
                continue

            state.scheduled.add(final_url)
            state.attempted.add(final_url)
            if self._remaining_seconds(state) <= 0:
                state.warn(
                    "DYNAMIC_ELAPSED_BUDGET_EXHAUSTED",
                    "Dynamic elapsed-time budget was exhausted before DOM capture.",
                    {"max_elapsed_seconds": state.policy.max_elapsed_seconds},
                )
                state.stop_reason = (
                    DynamicCrawlTerminationReason.ELAPSED_BUDGET_EXHAUSTED
                )
                state.operational_failure = True
                return
            try:
                snapshot = session.capture_rendered_dom(
                    state.policy.rendered_dom_policy,
                    timeout_seconds=self._remaining_seconds(state),
                )
            except DynamicBrowserError as exc:
                self._record_browser_failure(state, exc, requested_url=requested_url)
                if exc.code in {
                    DynamicBrowserErrorCode.DOM_STABILIZATION_TIMEOUT,
                    DynamicBrowserErrorCode.DOM_LIMIT_EXCEEDED,
                    DynamicBrowserErrorCode.DOM_SNAPSHOT_FAILED,
                }:
                    continue
                return

            if self._remaining_seconds(state) <= 0:
                state.warn(
                    "DYNAMIC_ELAPSED_BUDGET_EXHAUSTED",
                    "Dynamic elapsed-time budget expired during DOM capture.",
                    {"max_elapsed_seconds": state.policy.max_elapsed_seconds},
                )
                state.stop_reason = (
                    DynamicCrawlTerminationReason.ELAPSED_BUDGET_EXHAUSTED
                )
                state.operational_failure = True
                return

            extraction_authority: Any = state.authority
            if state.authority.allow_rendered_navigation:
                extraction_authority = _SimpleRenderedRequestAuthority(
                    state.authority
                )
            component = extract_rendered_dom(
                snapshot,
                extraction_authority,
                discovery_metadata=state.metadata,
                scope_metadata=state.scope,
                parent_url=parent_url or None,
                depth=depth,
            )
            if self._remaining_seconds(state) <= 0:
                state.warn(
                    "DYNAMIC_ELAPSED_BUDGET_EXHAUSTED",
                    "Dynamic elapsed-time budget expired during extraction.",
                    {"max_elapsed_seconds": state.policy.max_elapsed_seconds},
                )
                state.stop_reason = (
                    DynamicCrawlTerminationReason.ELAPSED_BUDGET_EXHAUSTED
                )
                state.operational_failure = True
                return
            page_result = DynamicPageResult(
                requested_url=requested_url,
                page_url=final_url,
                parent_url=parent_url or None,
                depth=depth,
                component=component,
            )
            state.pages.append(page_result)
            state.page_urls.add(final_url)
            self._schedule_links(state, page_result)

            remaining_actions = (
                state.policy.max_route_actions - state.route_actions_attempted
            )
            if remaining_actions > 0 and self._remaining_seconds(state) > 0:
                action_runner = getattr(session, "perform_safe_route_actions", None)
                if callable(action_runner):
                    try:
                        attempted = action_runner(remaining_actions)
                    except DynamicBrowserError as exc:
                        self._record_browser_failure(
                            state, exc, requested_url=requested_url
                        )
                        return
                    if type(attempted) is int and attempted > 0:
                        state.route_actions_attempted += min(
                            attempted, remaining_actions
                        )

    def _schedule_links(
        self,
        state: _CrawlState,
        page_result: DynamicPageResult,
    ) -> None:
        for link in page_result.component.navigable_links:
            try:
                candidate = canonicalize_crawl_url(link.crawl_url)
            except StaticCrawlerError:
                state.warn(
                    "DYNAMIC_LINK_CANDIDATE_INVALID",
                    "Rendered link could not be canonicalized for navigation.",
                    {"link_id": link.id},
                )
                continue
            if not same_origin_crawl_url(state.root_url, candidate):
                state.warn(
                    "DYNAMIC_OFF_AUTHORITY_LINK",
                    "Cross-authority rendered link was blocked before queueing.",
                    {
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "link_id": link.id,
                    },
                )
                continue

            external_redirect = _external_redirect_target(
                state.root_url,
                candidate,
            )
            if external_redirect is not None:
                state.warn(
                    "DYNAMIC_EXTERNAL_REDIRECT_SUPPRESSED",
                    "External redirect target was discovered but not navigated.",
                    {
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "external_target_fingerprint": _url_fingerprint(
                            external_redirect
                        ),
                        "link_id": link.id,
                        "reason": "CROSS_ORIGIN_REDIRECT_TARGET",
                    },
                )
                continue

            unsafe_token = authentication_state_change_token(candidate)
            if unsafe_token is not None:
                state.warn(
                    "DYNAMIC_UNSAFE_NAVIGATION_SUPPRESSED",
                    "Authentication state-changing navigation was suppressed.",
                    {
                        "action_token": unsafe_token,
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "link_id": link.id,
                        "reason": "AUTHENTICATION_STATE_CHANGE",
                    },
                )
                continue
            if (
                not state.authority.allows_navigation(candidate)
                and not automatic_navigation_within_root_path(
                    state.root_url,
                    candidate,
                )
            ):
                state.warn(
                    "DYNAMIC_OFF_PATH_SCOPE_LINK",
                    "Rendered link was outside the implicit root path scope.",
                    {
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "link_id": link.id,
                        "reason": "ROOT_PATH_SCOPE_MISMATCH",
                    },
                )
                continue
            if not (
                state.authority.allows_navigation(candidate)
                or state.authority.allows_rendered_navigation(candidate)
            ):
                state.warn(
                    "DYNAMIC_REQUEST_NOT_AUTHORIZED",
                    "Rendered link lacks exact caller navigation authority.",
                    {
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "link_id": link.id,
                    },
                )
                continue
            if candidate in state.scheduled or candidate in state.attempted:
                state.warn(
                    "DYNAMIC_DUPLICATE_URL",
                    "Duplicate canonical rendered URL was not queued again.",
                    {
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "link_id": link.id,
                    },
                )
                continue
            next_depth = page_result.depth + 1
            if next_depth > state.policy.max_depth:
                state.warn(
                    "DYNAMIC_DEPTH_BUDGET_EXHAUSTED",
                    "Rendered link exceeded the configured crawl depth.",
                    {
                        "depth": next_depth,
                        "max_depth": state.policy.max_depth,
                        "destination_fingerprint": _url_fingerprint(candidate),
                    },
                )
                state.depth_budget_exhausted = True
                continue
            state.scheduled.add(candidate)
            heappush(
                state.queue,
                (next_depth, candidate, page_result.page_url),
            )

    def _remaining_seconds(self, state: _CrawlState) -> float:
        return state.policy.max_elapsed_seconds - (self.clock() - state.started)

    @staticmethod
    def _record_browser_failure(
        state: _CrawlState,
        error: DynamicBrowserError,
        *,
        requested_url: str | None = None,
    ) -> None:
        code = error.code.value
        details: dict[str, Any] = {"error_code": code}
        if requested_url is not None:
            details["url_fingerprint"] = _url_fingerprint(requested_url)
        state.warn(
            "DYNAMIC_OPERATIONAL_FAILURE",
            "A bounded Dynamic browser operation failed safely.",
            details,
        )
        state.operational_failure = True
        state.last_failure_code = code
        if error.code == DynamicBrowserErrorCode.NAVIGATION_BUDGET_EXHAUSTED:
            state.stop_reason = (
                DynamicCrawlTerminationReason.NAVIGATION_BUDGET_EXHAUSTED
            )
        elif error.code in {
            DynamicBrowserErrorCode.NAVIGATION_TIMEOUT,
            DynamicBrowserErrorCode.NAVIGATION_FAILED,
            DynamicBrowserErrorCode.REDIRECT_BUDGET_EXHAUSTED,
        }:
            state.stop_reason = DynamicCrawlTerminationReason.OPERATIONAL_FAILURE

    @staticmethod
    def _termination_reason(state: _CrawlState) -> DynamicCrawlTerminationReason:
        if state.stop_reason is not None:
            return state.stop_reason
        if state.depth_budget_exhausted:
            return DynamicCrawlTerminationReason.DEPTH_BUDGET_EXHAUSTED
        if state.operational_failure:
            return DynamicCrawlTerminationReason.COMPLETED_WITH_FAILURES
        return DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED


@dataclass(frozen=True, slots=True)
class _SimpleRenderedRequestAuthority:
    """Extraction-only view; browser transport remains exact and ephemeral."""

    authority: DynamicRequestAuthority

    @property
    def root_url(self) -> str:
        return self.authority.root_url

    def allows_navigation(self, url: str) -> bool:
        return self.authority.allows_navigation(url) or (
            self.authority.allows_rendered_navigation(url)
            and automatic_navigation_within_root_path(self.root_url, url)
        )


def _url_fingerprint(url: str) -> str:
    return stable_fingerprint("dynamic-crawler-url", url)[:16]


def _build_dynamic_discovery(
    state: _CrawlState,
    *,
    audit: BrowserAuditSummary,
    network_discovery: NetworkDiscoveryCollection,
    elapsed_ms: float,
) -> CanonicalDiscoveryResult:
    endpoints: dict[str, Endpoint] = {}
    point_groups: dict[str, list[InputPoint]] = {}
    templates: dict[str, RequestTemplate] = {}
    contexts: dict[str, InputPointRequestContext] = {}
    readiness: dict[str, ProbeReadiness] = {}
    provenance: dict[str, DiscoveryProvenance] = {}
    hints: dict[str, BACStaticHint] = {}
    warnings = dict(state.warnings)
    links_discovered = 0
    forms_discovered = 0
    skipped = state.skipped

    network_components = canonicalize_network_discovery(
        network_discovery,
        discovery_metadata=state.metadata,
        scope_metadata=state.scope,
    )
    components = (
        *(page_result.component.discovery for page_result in state.pages),
        *network_components,
    )
    for component in components:
        component.validate()
        if component.discovery_metadata != state.metadata:
            raise DynamicCrawlerError("Dynamic page metadata changed during crawl")
        if component.scope_metadata != state.scope:
            raise DynamicCrawlerError("Dynamic page scope changed during crawl")
        for item in component.endpoints:
            endpoints.setdefault(item.id or "", item)
        for item in component.input_points:
            point_groups.setdefault(item.id or "", []).append(item)
        for item in component.request_templates:
            templates.setdefault(item.id or "", item)
        for item in component.input_point_request_contexts:
            current = contexts.get(item.id)
            if current is not None and current != item:
                raise DynamicCrawlerError("Dynamic request-context identity collision")
            contexts.setdefault(item.id, item)
        for item in component.probe_readiness:
            readiness.setdefault(item.id or "", item)
        for item in component.crawl_provenance:
            current_provenance = provenance.get(item.id or "")
            if current_provenance is not None and current_provenance != item:
                raise DynamicCrawlerError("Dynamic provenance identity collision")
            provenance.setdefault(item.id or "", item)
        for item in component.bac_static_hints:
            hints.setdefault(item.id or "", item)
        for item in component.warnings:
            warnings.setdefault(item.id or "", item)
        stats = component.crawl_statistics
        links_discovered += stats.links_discovered
        forms_discovered += stats.forms_discovered
        skipped += stats.skipped

    points = tuple(
        _merge_input_points(group)
        for _, group in sorted(point_groups.items())
    )
    statistics = CrawlStatistics(
        requests_attempted=audit.main_frame_navigation_allowed_count,
        pages_processed=len(state.pages),
        html_pages=len(state.pages),
        links_discovered=links_discovered,
        forms_discovered=forms_discovered,
        skipped=skipped,
        redirects_followed=audit.redirect_followed_count,
        max_depth_reached=max((item.depth for item in state.pages), default=0),
        request_budget=state.policy.max_navigation_attempts,
        page_budget=state.policy.max_pages,
        depth_budget=state.policy.max_depth,
        elapsed_ms=elapsed_ms,
        endpoint_count=len(endpoints),
        input_point_count=len(points),
        request_template_count=len(templates),
        request_context_count=len(contexts),
    )
    return CanonicalDiscoveryResult.create(
        discovery_metadata=state.metadata,
        scope_metadata=state.scope,
        crawl_statistics=statistics,
        endpoints=tuple(endpoints.values()),
        input_points=points,
        request_templates=tuple(templates.values()),
        input_point_request_contexts=tuple(contexts.values()),
        probe_readiness=tuple(readiness.values()),
        crawl_provenance=tuple(provenance.values()),
        bac_static_hints=tuple(hints.values()),
        warnings=tuple(warnings.values()),
        safety_invariants=(_REQUIRED_SAFETY_INVARIANT,),
    )


def _merge_input_points(points: list[InputPoint]) -> InputPoint:
    candidate = points[0]
    values = tuple(
        sorted(
            {
                value
                for point in points
                for value in (
                    point.baseline_values
                    or (
                        (point.baseline_value,)
                        if point.baseline_value is not None
                        else ()
                    )
                )
            }
        )
    )
    type_hints = tuple(
        sorted(
            {
                point.type_hint
                for point in points
                if point.type_hint is not None
            }
        )
    )
    source_pages = tuple(
        sorted(
            {
                point.source_page
                for point in points
                if point.source_page is not None
            }
        )
    )
    origin_kinds: set[str] = set()
    pair_indices: set[int] = set()
    control_indices: set[int] = set()
    raw_query_tokens: set[str] = set()
    hidden_values: set[bool] = set()
    for point in points:
        metadata = point.metadata
        origin_kinds.update(str(item) for item in metadata.get("origin_kinds", ()))
        pair_indices.update(int(item) for item in metadata.get("pair_indices", ()))
        control_indices.update(
            int(item) for item in metadata.get("control_indices", ())
        )
        raw_token = metadata.get("raw_query_token")
        if isinstance(raw_token, str):
            raw_query_tokens.add(raw_token)
        raw_query_tokens.update(
            str(item) for item in metadata.get("raw_query_tokens", ())
        )
        hidden = metadata.get("hidden")
        if isinstance(hidden, bool):
            hidden_values.add(hidden)

    merged_metadata = dict(candidate.metadata)
    if source_pages:
        merged_metadata["source_pages"] = source_pages
    if origin_kinds:
        merged_metadata["origin_kinds"] = tuple(sorted(origin_kinds))
    merged_metadata["pair_indices"] = tuple(sorted(pair_indices))
    merged_metadata["control_indices"] = tuple(sorted(control_indices))
    if len(raw_query_tokens) == 1:
        merged_metadata["raw_query_token"] = next(iter(raw_query_tokens))
        merged_metadata.pop("raw_query_tokens", None)
    elif raw_query_tokens:
        merged_metadata["raw_query_tokens"] = tuple(sorted(raw_query_tokens))
        merged_metadata.pop("raw_query_token", None)
    if hidden_values:
        merged_metadata["hidden"] = any(hidden_values)
        merged_metadata["visibility"] = (
            "mixed"
            if len(hidden_values) > 1
            else ("hidden" if True in hidden_values else "visible")
        )
    if len(type_hints) > 1:
        merged_metadata["type_hints"] = type_hints
    return replace(
        candidate,
        baseline_value=values[0] if len(values) == 1 else None,
        baseline_values=values,
        type_hint=type_hints[0] if len(type_hints) == 1 else None,
        source_page=source_pages[0] if source_pages else None,
        metadata=merged_metadata,
    )


def _terminate_worker_tree(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                (
                    "taskkill.exe",
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                ),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5.0,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        process.kill()
    finally:
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)


def _dynamic_worker_main() -> None:
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    root_url, policy, authority = pickle.loads(input_path.read_bytes())
    try:
        result = DynamicCrawler().crawl(root_url, policy, authority)
    except Exception as exc:  # Preserve the original typed failure across cleanup.
        outcome: tuple[str, Any] = ("error", exc)
    else:
        outcome = ("ok", result)
    output_path.write_bytes(pickle.dumps(outcome, protocol=5))
