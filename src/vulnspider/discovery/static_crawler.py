"""Bounded same-origin static crawler with explicit redirect control."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from heapq import heappop, heappush
from math import isfinite
from time import monotonic, sleep
from types import MappingProxyType
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

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
from vulnspider.discovery.html_extractor import (
    StaticExtractionResult,
    extract_static_html,
    extract_static_html_with_sensitive_form_elision,
)
from vulnspider.discovery.navigation_safety import (
    authentication_state_change_token,
)
from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputPoint,
    InputPointRequestContext,
    RequestTemplate,
    stable_fingerprint,
)

CRAWLER_VERSION = "native-static-crawler/1.1"
SCOPE_POLICY_VERSION = "same-origin-v1"

DEFAULT_MAX_PAGES = 10
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_REQUESTS = 20
DEFAULT_TIMEOUT_SECONDS = 3.0
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_DELAY_SECONDS = 0.0
DEFAULT_MAX_ELAPSED_SECONDS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 512_000

_HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class StaticCrawlerError(ValueError):
    """Raised when crawler configuration or the root target is invalid."""


class StaticCrawlerTransportError(RuntimeError):
    """One bounded transport attempt failed before receiving a response."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or not code:
            raise ValueError("transport error code must not be empty")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class CrawlPolicy:
    max_pages: int = DEFAULT_MAX_PAGES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_requests: int = DEFAULT_MAX_REQUESTS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    delay_seconds: float = DEFAULT_DELAY_SECONDS
    max_elapsed_seconds: float = DEFAULT_MAX_ELAPSED_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    session_cookies: tuple[tuple[str, str], ...] = ()
    """Operator-supplied session cookies sent on every crawl request.

    This is how a Broken Access Control scan is given an authenticated
    session: the operator logs in out-of-band and provides the resulting
    cookie(s), so the crawler reaches protected resources (they answer 200
    instead of 401/403 and are therefore discovered) and every produced
    ``RequestTemplate`` carries the credential -- the precondition for the
    access layer to plan a ``CREDENTIAL_STRIP`` comparison. Read-only GET only;
    VulnSpider never logs in or changes authentication state itself.
    """

    def __post_init__(self) -> None:
        positive_integers = {
            "max_pages": self.max_pages,
            "max_requests": self.max_requests,
            "max_response_bytes": self.max_response_bytes,
        }
        for name, value in positive_integers.items():
            if type(value) is not int or value <= 0:
                raise StaticCrawlerError(f"{name} must be a positive integer")
        non_negative_integers = {
            "max_depth": self.max_depth,
            "max_redirects": self.max_redirects,
        }
        for name, value in non_negative_integers.items():
            if type(value) is not int or value < 0:
                raise StaticCrawlerError(
                    f"{name} must be a non-negative integer"
                )
        positive_numbers = {
            "timeout_seconds": self.timeout_seconds,
            "max_elapsed_seconds": self.max_elapsed_seconds,
        }
        for name, value in positive_numbers.items():
            if type(value) not in {int, float}:
                raise StaticCrawlerError(f"{name} must be numeric")
            if not isfinite(value) or value <= 0:
                raise StaticCrawlerError(f"{name} must be finite and positive")
        if type(self.delay_seconds) not in {int, float}:
            raise StaticCrawlerError("delay_seconds must be numeric")
        if not isfinite(self.delay_seconds) or self.delay_seconds < 0:
            raise StaticCrawlerError(
                "delay_seconds must be finite and non-negative"
            )
        cookies = tuple(self.session_cookies)
        for pair in cookies:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not all(isinstance(part, str) and part for part in pair)
            ):
                raise StaticCrawlerError(
                    "session_cookies must be (name, value) string pairs"
                )
        object.__setattr__(self, "session_cookies", cookies)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "max_requests": self.max_requests,
            "timeout_seconds": self.timeout_seconds,
            "max_redirects": self.max_redirects,
            "delay_seconds": self.delay_seconds,
            "max_elapsed_seconds": self.max_elapsed_seconds,
            "max_response_bytes": self.max_response_bytes,
            # Only the cookie NAMES enter the configuration fingerprint; the
            # values are secrets and must never be serialized.
            "session_cookie_names": [name for name, _value in self.session_cookies],
        }


@dataclass(frozen=True, slots=True)
class StaticCrawlerRequest:
    url: str
    method: HttpMethod = HttpMethod.GET
    cookies: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        method = HttpMethod(self.method)
        if method != HttpMethod.GET:
            raise StaticCrawlerError("static crawler requests must use GET")
        object.__setattr__(self, "url", canonicalize_crawl_url(self.url))
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "cookies", tuple(self.cookies))


@dataclass(frozen=True, slots=True)
class StaticCrawlerResponse:
    status_code: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    content_type: str | None = None
    encoding: str | None = None
    redirect_location: str | None = None
    oversized: bool = False

    def __post_init__(self) -> None:
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be an HTTP status integer")
        if not isinstance(self.body, bytes):
            raise TypeError("body must be bytes")
        headers = {
            str(name): str(value)
            for name, value in self.headers.items()
        }
        if type(self.elapsed_ms) not in {int, float}:
            raise TypeError("elapsed_ms must be numeric")
        if not isfinite(self.elapsed_ms) or self.elapsed_ms < 0:
            raise ValueError("elapsed_ms must be finite and non-negative")
        content_type = self.content_type
        if content_type is None:
            content_type = _header_value(headers, "Content-Type")
        if content_type is not None:
            content_type = content_type.split(";", 1)[0].strip().lower() or None
        if self.encoding is not None and type(self.encoding) is not str:
            raise TypeError("encoding must be a string or None")
        if (
            self.redirect_location is not None
            and type(self.redirect_location) is not str
        ):
            raise TypeError("redirect_location must be a string or None")
        if type(self.oversized) is not bool:
            raise TypeError("oversized must be a bool")
        object.__setattr__(self, "body", bytes(self.body))
        object.__setattr__(self, "headers", MappingProxyType(headers))
        object.__setattr__(self, "content_type", content_type)


class StaticCrawlerTransport(Protocol):
    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        """Send one bounded GET request without following redirects."""


class StaticHtmlExtractor(Protocol):
    def __call__(
        self,
        html: str,
        source_url: str,
        *,
        discovery_metadata: DiscoveryMetadata,
        scope_metadata: ScopeMetadata,
        parent_url: str | None,
        depth: int,
        session_cookies: tuple[tuple[str, str], ...] = (),
    ) -> StaticExtractionResult:
        """Extract one already-fetched HTML document."""


def _extractor_safety_invariants(
    extractor: StaticHtmlExtractor,
) -> tuple[DiscoverySafetyInvariant, ...]:
    if extractor is extract_static_html_with_sensitive_form_elision:
        return (
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
        )
    return ()


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: object,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class UrlLibStaticCrawlerTransport:
    """Standard-library GET transport with bounded reads and no auto-redirect."""

    def __init__(self) -> None:
        self._opener = build_opener(_NoRedirectHandler)

    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        if not isinstance(request, StaticCrawlerRequest):
            raise TypeError("request must be a StaticCrawlerRequest")
        if request.method != HttpMethod.GET:
            raise StaticCrawlerError("static crawler transport accepts GET only")
        if type(timeout_seconds) not in {int, float}:
            raise StaticCrawlerError("timeout_seconds must be numeric")
        if not isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise StaticCrawlerError(
                "timeout_seconds must be finite and positive"
            )
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise StaticCrawlerError(
                "max_response_bytes must be a positive integer"
            )
        headers = {"User-Agent": "VulnSpider/0.2 static discovery"}
        if request.cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in request.cookies
            )
        url_request = Request(
            request.url,
            headers=headers,
            method=HttpMethod.GET.value,
        )
        started = monotonic()
        try:
            with self._opener.open(
                url_request,
                timeout=timeout_seconds,
            ) as response:
                body, oversized = _read_bounded(response, max_response_bytes)
                headers = dict(response.headers.items())
                return StaticCrawlerResponse(
                    status_code=response.status,
                    body=body,
                    headers=headers,
                    elapsed_ms=(monotonic() - started) * 1000.0,
                    content_type=response.headers.get_content_type(),
                    encoding=response.headers.get_content_charset(),
                    redirect_location=_header_value(headers, "Location"),
                    oversized=oversized,
                )
        except HTTPError as exc:
            try:
                try:
                    body, oversized = _read_bounded(exc, max_response_bytes)
                    headers = dict(exc.headers.items()) if exc.headers else {}
                    return StaticCrawlerResponse(
                        status_code=exc.code,
                        body=body,
                        headers=headers,
                        elapsed_ms=(monotonic() - started) * 1000.0,
                        content_type=(
                            exc.headers.get_content_type()
                            if exc.headers
                            else None
                        ),
                        encoding=(
                            exc.headers.get_content_charset()
                            if exc.headers
                            else None
                        ),
                        redirect_location=_header_value(headers, "Location"),
                        oversized=oversized,
                    )
                except TimeoutError as read_exc:
                    raise StaticCrawlerTransportError("timeout") from read_exc
                except OSError as read_exc:
                    raise StaticCrawlerTransportError(
                        f"transport-error:{type(read_exc).__name__}"
                    ) from read_exc
            finally:
                exc.close()
        except TimeoutError as exc:
            raise StaticCrawlerTransportError("timeout") from exc
        except URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, TimeoutError):
                raise StaticCrawlerTransportError("timeout") from exc
            reason_name = (
                type(reason).__name__
                if reason is not None
                else type(exc).__name__
            )
            raise StaticCrawlerTransportError(
                f"transport-error:{reason_name}"
            ) from exc
        except OSError as exc:
            raise StaticCrawlerTransportError(
                f"transport-error:{type(exc).__name__}"
            ) from exc
        except Exception as exc:
            raise StaticCrawlerTransportError(
                f"transport-error:{type(exc).__name__}"
            ) from exc


@dataclass(frozen=True, slots=True)
class StaticCrawlResult:
    root_url: str
    visited_urls: tuple[str, ...]
    processed_urls: tuple[str, ...]
    discovery: CanonicalDiscoveryResult

    def __post_init__(self) -> None:
        if type(self.visited_urls) is not tuple or any(
            type(item) is not str for item in self.visited_urls
        ):
            raise TypeError("visited_urls must be a tuple of strings")
        if type(self.processed_urls) is not tuple or any(
            type(item) is not str for item in self.processed_urls
        ):
            raise TypeError("processed_urls must be a tuple of strings")
        if len(self.visited_urls) != len(set(self.visited_urls)):
            raise ValueError("visited_urls must be unique")
        if len(self.processed_urls) != len(set(self.processed_urls)):
            raise ValueError("processed_urls must be unique")
        if any(item not in self.visited_urls for item in self.processed_urls):
            raise ValueError("processed_urls must be visited")
        if self.root_url != canonicalize_crawl_url(self.root_url):
            raise ValueError("root_url must be canonical")
        self.discovery.validate()

    @property
    def warnings(self) -> tuple[DiscoveryWarning, ...]:
        return self.discovery.warnings

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_url": self.root_url,
            "visited_urls": list(self.visited_urls),
            "processed_urls": list(self.processed_urls),
            "discovery": self.discovery.to_dict(),
        }


@dataclass(slots=True)
class _CrawlState:
    root_url: str
    policy: CrawlPolicy
    metadata: DiscoveryMetadata
    scope: ScopeMetadata
    started: float
    queue: list[tuple[int, str, str]]
    scheduled: set[str]
    extractor_safety_invariants: tuple[DiscoverySafetyInvariant, ...]
    requested: set[str] = field(default_factory=set)
    visited_urls: list[str] = field(default_factory=list)
    processed_urls: list[str] = field(default_factory=list)
    extractions: list[StaticExtractionResult] = field(default_factory=list)
    warnings: dict[str, DiscoveryWarning] = field(default_factory=dict)
    requests_attempted: int = 0
    redirects_followed: int = 0
    skipped: int = 0
    links_discovered: int = 0
    forms_discovered: int = 0
    max_depth_reached: int = 0
    last_request_at: float | None = None

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

    def add_extraction(self, extraction: StaticExtractionResult) -> None:
        self.extractions.append(extraction)
        self.processed_urls.append(extraction.source_url)
        stats = extraction.discovery.crawl_statistics
        self.links_discovered += stats.links_discovered
        self.forms_discovered += stats.forms_discovered
        self.skipped += stats.skipped
        for warning in extraction.discovery.warnings:
            self.warnings.setdefault(warning.id or "", warning)


@dataclass(frozen=True, slots=True)
class StaticCrawler:
    transport: StaticCrawlerTransport = field(
        default_factory=UrlLibStaticCrawlerTransport
    )
    extractor: StaticHtmlExtractor = extract_static_html
    clock: Callable[[], float] = monotonic
    sleeper: Callable[[float], None] = sleep

    def crawl(
        self,
        root_url: str,
        policy: CrawlPolicy | None = None,
    ) -> StaticCrawlResult:
        active_policy = policy or CrawlPolicy()
        if not isinstance(active_policy, CrawlPolicy):
            raise StaticCrawlerError("policy must be a CrawlPolicy")
        extractor_safety_invariants = _extractor_safety_invariants(self.extractor)
        canonical_root = canonicalize_crawl_url(root_url)
        metadata = DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_STATIC,
            collector_version=CRAWLER_VERSION,
            configuration_fingerprint=stable_fingerprint(
                "native-static-crawl-policy",
                active_policy.to_dict(),
                tuple(item.value for item in extractor_safety_invariants),
            ),
        )
        scope_ref = (
            "scope-decision:origin:"
            + stable_fingerprint("origin", _origin(canonical_root))[:16]
        )
        scope = ScopeMetadata(
            target_scope_id=scope_id_for_root(
                canonical_root,
                policy_version=SCOPE_POLICY_VERSION,
            ),
            root_url=canonical_root,
            scope_policy_version=SCOPE_POLICY_VERSION,
            scope_decision_refs=(scope_ref,),
        )
        state = _CrawlState(
            root_url=canonical_root,
            policy=active_policy,
            metadata=metadata,
            scope=scope,
            started=self.clock(),
            queue=[(0, canonical_root, "")],
            scheduled={canonical_root},
            extractor_safety_invariants=extractor_safety_invariants,
        )

        while state.queue:
            if len(state.extractions) >= active_policy.max_pages:
                state.warn(
                    "PAGE_BUDGET_EXHAUSTED",
                    "HTML page budget was exhausted before the next request",
                    {"max_pages": active_policy.max_pages},
                )
                break
            if self._elapsed_exhausted(state):
                break
            depth, url, parent_url = heappop(state.queue)
            if url in state.requested:
                continue
            fetched = self._fetch_redirect_chain(state, url, depth)
            if fetched is None:
                continue
            final_url, response = fetched
            if response.status_code >= 400:
                state.warn(
                    "HTTP_ERROR",
                    "HTTP error response was skipped",
                    {
                        "status_code": response.status_code,
                        "url_fingerprint": _url_fingerprint(final_url),
                    },
                )
                continue
            if response.oversized:
                state.warn(
                    "RESPONSE_BODY_TOO_LARGE",
                    "response exceeded the configured body limit",
                    {
                        "max_response_bytes": active_policy.max_response_bytes,
                        "url_fingerprint": _url_fingerprint(final_url),
                    },
                )
                continue
            if response.content_type not in _HTML_CONTENT_TYPES:
                state.warn(
                    "NON_HTML_RESPONSE",
                    "non-HTML response was not passed to the extractor",
                    {
                        "content_type": response.content_type or "",
                        "url_fingerprint": _url_fingerprint(final_url),
                    },
                )
                continue

            html = _decode_body(response.body, response.encoding)
            try:
                extraction = self.extractor(
                    html,
                    final_url,
                    discovery_metadata=metadata,
                    scope_metadata=scope,
                    parent_url=parent_url or None,
                    depth=depth,
                    session_cookies=active_policy.session_cookies,
                )
            except (TypeError, ValueError, UnicodeError) as exc:
                state.warn(
                    "HTML_EXTRACTION_ERROR",
                    "HTML response could not be safely extracted",
                    {
                        "error_type": type(exc).__name__,
                        "url_fingerprint": _url_fingerprint(final_url),
                    },
                )
                continue
            state.add_extraction(extraction)
            self._schedule_links(state, extraction, depth)

        discovery = _build_discovery_result(
            state,
            elapsed_ms=max(0.0, (self.clock() - state.started) * 1000.0),
        )
        return StaticCrawlResult(
            root_url=canonical_root,
            visited_urls=tuple(state.visited_urls),
            processed_urls=tuple(state.processed_urls),
            discovery=discovery,
        )

    def _fetch_redirect_chain(
        self,
        state: _CrawlState,
        url: str,
        depth: int,
    ) -> tuple[str, StaticCrawlerResponse] | None:
        current_url = url
        chain = {url}
        redirect_count = 0
        while True:
            attempts_before = state.requests_attempted
            response = self._send(state, current_url, depth)
            if redirect_count and state.requests_attempted > attempts_before:
                state.redirects_followed += 1
            if response is None:
                return None
            if response.status_code not in _REDIRECT_STATUSES:
                return current_url, response
            location = response.redirect_location
            if location is None or not location.strip():
                state.warn(
                    "REDIRECT_LOCATION_MISSING",
                    "redirect response without Location was skipped",
                    {"url_fingerprint": _url_fingerprint(current_url)},
                )
                return None
            if redirect_count >= state.policy.max_redirects:
                state.warn(
                    "REDIRECT_LIMIT_REACHED",
                    "redirect limit was reached before following Location",
                    {
                        "max_redirects": state.policy.max_redirects,
                        "url_fingerprint": _url_fingerprint(current_url),
                    },
                )
                return None
            try:
                destination = canonicalize_crawl_url(
                    location,
                    base_url=current_url,
                )
            except StaticCrawlerError:
                state.warn(
                    "REDIRECT_LOCATION_INVALID",
                    "malformed or unsupported redirect destination was skipped",
                    {
                        "location_fingerprint": _url_fingerprint(location),
                        "url_fingerprint": _url_fingerprint(current_url),
                    },
                )
                return None
            if not same_origin_crawl_url(state.root_url, destination):
                state.warn(
                    "OFF_SCOPE_REDIRECT",
                    "cross-origin redirect was blocked before transport",
                    {
                        "destination_fingerprint": _url_fingerprint(destination),
                        "url_fingerprint": _url_fingerprint(current_url),
                    },
                )
                return None
            if destination in chain:
                state.warn(
                    "REDIRECT_LOOP",
                    "redirect loop was blocked before another request",
                    {
                        "destination_fingerprint": _url_fingerprint(destination),
                    },
                )
                return None
            if destination in state.requested:
                state.warn(
                    "DUPLICATE_REDIRECT_TARGET",
                    "previously requested redirect destination was not fetched again",
                    {
                        "destination_fingerprint": _url_fingerprint(destination),
                    },
                )
                return None
            if state.requests_attempted >= state.policy.max_requests:
                state.warn(
                    "REQUEST_BUDGET_EXHAUSTED",
                    "request budget blocked the redirect destination",
                    {"max_requests": state.policy.max_requests},
                )
                return None
            if self._elapsed_exhausted(state):
                return None
            chain.add(destination)
            state.scheduled.add(destination)
            redirect_count += 1
            current_url = destination

    def _send(
        self,
        state: _CrawlState,
        url: str,
        depth: int,
    ) -> StaticCrawlerResponse | None:
        if state.requests_attempted >= state.policy.max_requests:
            state.warn(
                "REQUEST_BUDGET_EXHAUSTED",
                "request budget was exhausted before transport",
                {"max_requests": state.policy.max_requests},
            )
            return None
        if self._elapsed_exhausted(state):
            return None
        if state.last_request_at is not None and state.policy.delay_seconds:
            elapsed = self.clock() - state.started
            remaining = state.policy.max_elapsed_seconds - elapsed
            if state.policy.delay_seconds > remaining:
                state.warn(
                    "ELAPSED_BUDGET_EXHAUSTED",
                    "elapsed budget could not accommodate request delay",
                    {
                        "max_elapsed_seconds": (
                            state.policy.max_elapsed_seconds
                        )
                    },
                )
                return None
            self.sleeper(state.policy.delay_seconds)
            if self._elapsed_exhausted(state):
                return None

        request = StaticCrawlerRequest(url, cookies=state.policy.session_cookies)
        state.requested.add(request.url)
        state.visited_urls.append(request.url)
        state.requests_attempted += 1
        state.max_depth_reached = max(state.max_depth_reached, depth)
        state.last_request_at = self.clock()
        try:
            elapsed = self.clock() - state.started
            remaining = state.policy.max_elapsed_seconds - elapsed
            if remaining <= 0:
                state.warn(
                    "ELAPSED_BUDGET_EXHAUSTED",
                    "elapsed crawl budget was exhausted before transport",
                    {
                        "max_elapsed_seconds": (
                            state.policy.max_elapsed_seconds
                        )
                    },
                )
                return None
            response = self.transport.send(
                request,
                timeout_seconds=min(state.policy.timeout_seconds, remaining),
                max_response_bytes=state.policy.max_response_bytes,
            )
            if self.clock() - state.started >= state.policy.max_elapsed_seconds:
                state.warn(
                    "ELAPSED_BUDGET_EXHAUSTED",
                    "response completed after the elapsed crawl budget",
                    {
                        "max_elapsed_seconds": (
                            state.policy.max_elapsed_seconds
                        ),
                        "url_fingerprint": _url_fingerprint(request.url),
                    },
                )
                return None
            return response
        except StaticCrawlerTransportError as exc:
            if exc.code == "timeout":
                code = "TRANSPORT_TIMEOUT"
                message = "request timed out and crawl continued"
            else:
                code = "TRANSPORT_ERROR"
                message = "network error was recorded and crawl continued"
            state.warn(
                code,
                message,
                {
                    "error_code": exc.code,
                    "url_fingerprint": _url_fingerprint(request.url),
                },
            )
            return None

    def _schedule_links(
        self,
        state: _CrawlState,
        extraction: StaticExtractionResult,
        depth: int,
    ) -> None:
        for link in extraction.navigable_links:
            try:
                candidate = canonicalize_crawl_url(link.crawl_url)
            except StaticCrawlerError:
                state.warn(
                    "LINK_CANDIDATE_INVALID",
                    "extractor link could not be canonicalized for crawl",
                    {"link_id": link.id},
                )
                continue
            if not same_origin_crawl_url(state.root_url, candidate):
                state.warn(
                    "OFF_SCOPE_LINK",
                    "cross-origin link was blocked before queueing",
                    {
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "link_id": link.id,
                    },
                )
                continue
            unsafe_token = authentication_state_change_token(candidate)
            if unsafe_token is not None:
                state.warn(
                    "UNSAFE_NAVIGATION_SUPPRESSED",
                    "Authentication state-changing navigation was suppressed.",
                    {
                        "action_token": unsafe_token,
                        "destination_fingerprint": _url_fingerprint(candidate),
                        "link_id": link.id,
                        "reason": "AUTHENTICATION_STATE_CHANGE",
                    },
                )
                continue
            if candidate in state.scheduled or candidate in state.requested:
                state.warn(
                    "DUPLICATE_URL",
                    "duplicate canonical URL was not queued again",
                    {
                        "destination_fingerprint": _url_fingerprint(candidate),
                    },
                )
                continue
            next_depth = depth + 1
            if next_depth > state.policy.max_depth:
                state.warn(
                    "MAX_DEPTH_REACHED",
                    "link exceeded the configured crawl depth",
                    {
                        "depth": next_depth,
                        "max_depth": state.policy.max_depth,
                        "destination_fingerprint": _url_fingerprint(candidate),
                    },
                )
                continue
            state.scheduled.add(candidate)
            heappush(
                state.queue,
                (next_depth, candidate, extraction.source_url),
            )

    def _elapsed_exhausted(self, state: _CrawlState) -> bool:
        if self.clock() - state.started < state.policy.max_elapsed_seconds:
            return False
        state.warn(
            "ELAPSED_BUDGET_EXHAUSTED",
            "elapsed crawl budget was exhausted",
            {"max_elapsed_seconds": state.policy.max_elapsed_seconds},
        )
        return True


def canonicalize_crawl_url(
    raw_url: str,
    *,
    base_url: str | None = None,
) -> str:
    """Normalize one HTTP(S) crawl identity without rewriting path/query data."""

    if type(raw_url) is not str or not raw_url:
        raise StaticCrawlerError("URL must be a non-empty string")
    if any(
        character.isspace() or ord(character) < 32
        for character in raw_url
    ):
        raise StaticCrawlerError("URL must not contain whitespace or controls")
    candidate = raw_url
    if base_url is not None:
        canonical_base = canonicalize_crawl_url(base_url)
        try:
            candidate = urljoin(canonical_base, raw_url)
        except ValueError as exc:
            raise StaticCrawlerError("URL could not be resolved") from exc
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise StaticCrawlerError("malformed URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.netloc:
        raise StaticCrawlerError("URL must be absolute HTTP(S)")
    if parts.username is not None or parts.password is not None:
        raise StaticCrawlerError("URL user information is not supported")
    hostname = parts.hostname
    if hostname is None or not hostname:
        raise StaticCrawlerError("URL hostname must not be empty")
    hostname = hostname.lower()
    if any(
        character.isspace() or ord(character) < 32
        for character in hostname
    ):
        raise StaticCrawlerError("URL hostname is malformed")
    default_port = 80 if scheme == "http" else 443
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = (
        rendered_host
        if port is None or port == default_port
        else f"{rendered_host}:{port}"
    )
    return urlunsplit(
        (
            scheme,
            netloc,
            parts.path or "/",
            parts.query,
            "",
        )
    )


def _read_bounded(stream: Any, max_response_bytes: int) -> tuple[bytes, bool]:
    captured = stream.read(max_response_bytes + 1)
    return bytes(captured[:max_response_bytes]), len(captured) > max_response_bytes


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    normalized = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == normalized:
            return value
    return None


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower() if parts.hostname else ""
    port = parts.port or (80 if scheme == "http" else 443)
    return scheme, hostname, port


def same_origin_crawl_url(root_url: str, candidate_url: str) -> bool:
    """Return exact scheme/host/effective-port origin equality for crawl URLs."""

    canonical_root = canonicalize_crawl_url(root_url)
    canonical_candidate = canonicalize_crawl_url(candidate_url)
    return _origin(canonical_root) == _origin(canonical_candidate)


def _url_fingerprint(url: str) -> str:
    return stable_fingerprint("crawler-url", url)[:16]


def _decode_body(body: bytes, encoding: str | None) -> str:
    preferred = encoding or "utf-8"
    try:
        return body.decode(preferred, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _build_discovery_result(
    state: _CrawlState,
    *,
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
    safety_invariants = set(state.extractor_safety_invariants)

    for extraction in state.extractions:
        discovery = extraction.discovery
        for item in discovery.endpoints:
            endpoints.setdefault(item.id or "", item)
        for item in discovery.input_points:
            point_groups.setdefault(item.id or "", []).append(item)
        for item in discovery.request_templates:
            templates.setdefault(item.id or "", item)
        for item in discovery.input_point_request_contexts:
            contexts.setdefault(item.id, item)
        for item in discovery.probe_readiness:
            readiness.setdefault(item.id or "", item)
        for item in discovery.crawl_provenance:
            provenance.setdefault(item.id or "", item)
        for item in discovery.bac_static_hints:
            hints.setdefault(item.id or "", item)
        for item in discovery.warnings:
            warnings.setdefault(item.id or "", item)
        safety_invariants.update(discovery.safety_invariants)

    points = tuple(
        _merge_input_points(group)
        for _, group in sorted(point_groups.items())
    )
    statistics = CrawlStatistics(
        requests_attempted=state.requests_attempted,
        pages_processed=len(state.extractions),
        html_pages=len(state.extractions),
        links_discovered=state.links_discovered,
        forms_discovered=state.forms_discovered,
        skipped=state.skipped,
        redirects_followed=state.redirects_followed,
        max_depth_reached=state.max_depth_reached,
        request_budget=state.policy.max_requests,
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
        safety_invariants=tuple(
            sorted(safety_invariants, key=lambda item: item.value)
        ),
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
