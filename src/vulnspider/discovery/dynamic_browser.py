"""Optional browser capability preflight for Native Dynamic Discovery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from importlib import metadata
import json
from math import isfinite
import os
from pathlib import Path
import re
from threading import Lock
from time import monotonic
from typing import Any, Callable, Generic, Protocol, TypeVar
from urllib.parse import (
    parse_qsl,
    unquote_plus,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from vulnspider.discovery.rendered_dom import (
    RENDERED_DOM_CAPTURE_SCRIPT,
    RenderedDomError,
    RenderedDomErrorCode,
    RenderedDomPolicy,
    RenderedDomSnapshot,
    snapshot_from_browser_payload,
)
from vulnspider.discovery.post_replay_policy import (
    PostReplayDisposition,
    PostReplayPolicyDecision,
    PostReplayPolicyFeatures,
    PostReplayReasonCode,
    classify_post_replay,
)
from vulnspider.domain import (
    EphemeralRequestMaterial,
    normalize_parameter_name,
    stable_fingerprint,
)
from vulnspider.scope.loopback import (
    LoopbackSafetyError,
    require_loopback_http_url,
)
from vulnspider.sensitive import contains_credential_material, credential_field_name


PLAYWRIGHT_REQUIREMENT = "playwright>=1.48,<2"
_PLAYWRIGHT_DISTRIBUTION = "playwright"
_SUPPORTED_MAJOR = 1
_MINIMUM_MINOR = 48
_VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_HTTP_SCHEMES = frozenset({"http", "https"})
_RESOURCE_TYPES = frozenset({"script", "style", "fetch_xhr"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_DEFAULT_NAVIGATION_TIMEOUT_SECONDS = 3.0
_DEFAULT_REQUEST_DECISION_BUDGET = 50
_MAX_PASSIVE_URL_CHARACTERS = 8192
_MAX_PASSIVE_METHOD_CHARACTERS = 32
_MAX_PASSIVE_HOST_CHARACTERS = 253
_MAX_PASSIVE_QUERY_PARAMETER_NAMES = 64
_MAX_PASSIVE_QUERY_NAME_CHARACTERS = 128
_MAX_NETWORK_PATH_CHARACTERS = 2048
_MAX_NETWORK_QUERY_CHARACTERS = 4096
_MAX_NETWORK_QUERY_VALUE_CHARACTERS = 2048
_MAX_NETWORK_JSON_BODY_BYTES = 16384
_MAX_NETWORK_JSON_MEMBER_NAMES = 64
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_GRAPHQL_IGNORED_PREFIX = re.compile(
    r"(?:(?:[\s,\ufeff]+)|(?:#[^\r\n]*(?:\r\n?|\n|$)))*"
)

T = TypeVar("T")


class DynamicCapabilityCode(StrEnum):
    """Stable, secret-free failure codes for Dynamic browser preflight."""

    PLAYWRIGHT_PACKAGE_MISSING = "PLAYWRIGHT_PACKAGE_MISSING"
    PLAYWRIGHT_METADATA_FAILED = "PLAYWRIGHT_METADATA_FAILED"
    PLAYWRIGHT_IMPORT_FAILED = "PLAYWRIGHT_IMPORT_FAILED"
    PLAYWRIGHT_VERSION_UNSUPPORTED = "PLAYWRIGHT_VERSION_UNSUPPORTED"
    WEBSOCKET_GUARD_UNAVAILABLE = "WEBSOCKET_GUARD_UNAVAILABLE"
    PLAYWRIGHT_START_FAILED = "PLAYWRIGHT_START_FAILED"
    PLAYWRIGHT_RUNTIME_UNAVAILABLE = "PLAYWRIGHT_RUNTIME_UNAVAILABLE"
    CHROMIUM_EXECUTABLE_MISSING = "CHROMIUM_EXECUTABLE_MISSING"
    CHROMIUM_LAUNCH_FAILED = "CHROMIUM_LAUNCH_FAILED"
    PREFLIGHT_CLEANUP_FAILED = "PREFLIGHT_CLEANUP_FAILED"


class DynamicCapabilityError(RuntimeError):
    """Raised when the optional Dynamic browser runtime is not usable."""

    def __init__(
        self,
        code: DynamicCapabilityCode,
        message: str,
        *,
        setup_hint: str,
        cleanup_failed: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = DynamicCapabilityCode(code)
        self.setup_hint = setup_hint
        self.cleanup_failed = cleanup_failed

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        """Preserve the typed safe diagnostic across the crawl worker seam."""

        return (
            _restore_dynamic_capability_error,
            (self.code, str(self), self.setup_hint, self.cleanup_failed),
        )


def _restore_dynamic_capability_error(
    code: DynamicCapabilityCode,
    message: str,
    setup_hint: str,
    cleanup_failed: bool,
) -> DynamicCapabilityError:
    return DynamicCapabilityError(
        code,
        message,
        setup_hint=setup_hint,
        cleanup_failed=cleanup_failed,
    )


@dataclass(frozen=True, slots=True)
class DynamicBrowserCapability:
    """Successful, secret-free result of a strict Chromium preflight."""

    playwright_version: str
    browser_name: str
    websocket_guard_callable: bool
    headless_launch_verified: bool


class DynamicResourceKind(StrEnum):
    """Caller-owned exact resource authority categories."""

    SCRIPT = "script"
    STYLE = "style"
    FETCH_XHR = "fetch_xhr"


class DynamicNetworkDecisionKind(StrEnum):
    """Transport decision emitted before browser network dispatch."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class DynamicNetworkReason(StrEnum):
    """Stable network-policy decision reasons."""

    AUTHORIZED_NAVIGATION = "AUTHORIZED_NAVIGATION"
    AUTHORIZED_RESOURCE = "AUTHORIZED_RESOURCE"
    PASSIVE_SAME_ORIGIN_FETCH_XHR = "PASSIVE_SAME_ORIGIN_FETCH_XHR"
    REQUEST_DECISION_BUDGET_EXHAUSTED = "REQUEST_DECISION_BUDGET_EXHAUSTED"
    NAVIGATION_BUDGET_EXHAUSTED = "NAVIGATION_BUDGET_EXHAUSTED"
    REDIRECT_BUDGET_EXHAUSTED = "REDIRECT_BUDGET_EXHAUSTED"
    REDIRECT_DUPLICATE = "REDIRECT_DUPLICATE"
    INVALID_URL = "INVALID_URL"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    NON_GET_METHOD = "NON_GET_METHOD"
    NON_PRIMARY_PAGE = "NON_PRIMARY_PAGE"
    CHILD_FRAME_DOCUMENT = "CHILD_FRAME_DOCUMENT"
    REQUEST_NOT_AUTHORIZED = "REQUEST_NOT_AUTHORIZED"
    RESOURCE_KIND_NOT_AUTHORIZED = "RESOURCE_KIND_NOT_AUTHORIZED"
    EVENTSOURCE_DENIED = "EVENTSOURCE_DENIED"
    WEBSOCKET_DENIED = "WEBSOCKET_DENIED"


class PassiveNetworkScope(StrEnum):
    """Exact-origin classification for one passive request attempt."""

    SAME_SCOPE = "SAME_SCOPE"
    OFF_SCOPE = "OFF_SCOPE"


class NetworkDiscoveryDisposition(StrEnum):
    """Whether an allowed GET retains an executable value-bearing context."""

    SAFE = "SAFE"
    STRUCTURAL_ELIDED = "STRUCTURAL_ELIDED"


class NetworkDiscoveryElisionReason(StrEnum):
    """Stable reasons for discarding all request values before retention."""

    SENSITIVE_QUERY = "SENSITIVE_QUERY"
    CREDENTIAL_HEADER = "CREDENTIAL_HEADER"


class NetworkDiscoverySkipReason(StrEnum):
    """Bounded internal counters for allowed GETs that fail canonicalization."""

    INVALID_URL = "INVALID_URL"
    URL_TOO_LARGE = "URL_TOO_LARGE"
    PATH_TOO_LARGE = "PATH_TOO_LARGE"
    QUERY_TOO_LARGE = "QUERY_TOO_LARGE"
    QUERY_NAME_INVALID = "QUERY_NAME_INVALID"
    QUERY_VALUE_TOO_LARGE = "QUERY_VALUE_TOO_LARGE"


class PostJsonSkipReason(StrEnum):
    """Secret-free reasons a blocked POST JSON attempt was not retained."""

    HEADER_UNAVAILABLE = "HEADER_UNAVAILABLE"
    CONTENT_TYPE_UNSUPPORTED = "CONTENT_TYPE_UNSUPPORTED"
    BODY_UNAVAILABLE = "BODY_UNAVAILABLE"
    BODY_TOO_LARGE = "BODY_TOO_LARGE"
    BODY_ENCODING_INVALID = "BODY_ENCODING_INVALID"
    JSON_MALFORMED = "JSON_MALFORMED"
    JSON_TOP_LEVEL_NOT_OBJECT = "JSON_TOP_LEVEL_NOT_OBJECT"
    JSON_DUPLICATE_KEY = "JSON_DUPLICATE_KEY"
    JSON_MEMBER_LIMIT_EXCEEDED = "JSON_MEMBER_LIMIT_EXCEEDED"
    JSON_MEMBER_NAME_INVALID = "JSON_MEMBER_NAME_INVALID"
    SENSITIVE_REQUEST_ELIDED = "SENSITIVE_REQUEST_ELIDED"
    CANDIDATE_LIMIT_EXCEEDED = "CANDIDATE_LIMIT_EXCEEDED"


class ChildFrameDocumentKind(StrEnum):
    """Secret-free classification for one child-frame document lifecycle."""

    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    ABOUT_BLANK = "about_blank"
    BROWSER_ERROR = "browser_error"
    REPLACEMENT = "replacement"


class DynamicBrowserErrorCode(StrEnum):
    """Stable lifecycle error codes without provider diagnostics."""

    INVALID_AUTHORITY = "INVALID_AUTHORITY"
    PLAYWRIGHT_START_FAILED = "PLAYWRIGHT_START_FAILED"
    BROWSER_LAUNCH_FAILED = "BROWSER_LAUNCH_FAILED"
    CONTEXT_CREATE_FAILED = "CONTEXT_CREATE_FAILED"
    HTTP_GUARD_INSTALL_FAILED = "HTTP_GUARD_INSTALL_FAILED"
    HTTP_RESPONSE_DISPOSE_FAILED = "HTTP_RESPONSE_DISPOSE_FAILED"
    WEBSOCKET_GUARD_INSTALL_FAILED = "WEBSOCKET_GUARD_INSTALL_FAILED"
    PAGE_CREATE_FAILED = "PAGE_CREATE_FAILED"
    PASSIVE_OBSERVER_INSTALL_FAILED = "PASSIVE_OBSERVER_INSTALL_FAILED"
    PAGE_OBSERVER_INSTALL_FAILED = "PAGE_OBSERVER_INSTALL_FAILED"
    POPUP_OBSERVER_INSTALL_FAILED = "POPUP_OBSERVER_INSTALL_FAILED"
    REQUEST_DECISION_BUDGET_EXHAUSTED = "REQUEST_DECISION_BUDGET_EXHAUSTED"
    NAVIGATION_BUDGET_EXHAUSTED = "NAVIGATION_BUDGET_EXHAUSTED"
    REDIRECT_BUDGET_EXHAUSTED = "REDIRECT_BUDGET_EXHAUSTED"
    REDIRECT_DUPLICATE = "REDIRECT_DUPLICATE"
    NAVIGATION_NOT_AUTHORIZED = "NAVIGATION_NOT_AUTHORIZED"
    NAVIGATION_FAILED = "NAVIGATION_FAILED"
    NAVIGATION_TIMEOUT = "NAVIGATION_TIMEOUT"
    OPERATION_FAILED = "OPERATION_FAILED"
    OPERATION_TIMEOUT = "OPERATION_TIMEOUT"
    DOM_STABILIZATION_TIMEOUT = "DOM_STABILIZATION_TIMEOUT"
    DOM_LIMIT_EXCEEDED = "DOM_LIMIT_EXCEEDED"
    DOM_SNAPSHOT_FAILED = "DOM_SNAPSHOT_FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


@dataclass(frozen=True, slots=True)
class DynamicResourceGrant:
    """One exact same-origin resource grant."""

    kind: DynamicResourceKind
    url: str

    def __post_init__(self) -> None:
        try:
            kind = DynamicResourceKind(self.kind)
        except (TypeError, ValueError):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Dynamic resource grant uses an unsupported category.",
            ) from None
        object.__setattr__(self, "kind", kind)


@dataclass(frozen=True, slots=True)
class DynamicNetworkDecision:
    """One deterministic pre-transport authority decision."""

    decision: DynamicNetworkDecisionKind
    reason: DynamicNetworkReason
    canonical_url: str | None
    resource_kind: str


@dataclass(frozen=True, slots=True)
class BrowserAuditEvent:
    """Bounded, query-value-free browser transport evidence."""

    resource_kind: str
    decision: DynamicNetworkDecisionKind
    reason: DynamicNetworkReason
    scheme: str
    host: str
    port: int | None
    path: str
    query_name_count: int


@dataclass(frozen=True, slots=True)
class PassiveNetworkObservation:
    """Bounded, deterministic, secret-free fetch/XHR request attempt."""

    method: str
    resource_type: str
    scheme: str
    host: str
    effective_port: int
    path_fingerprint: str
    path_segment_count: int
    query_parameter_names: tuple[str, ...]
    scope: PassiveNetworkScope
    occurrence_count: int = 1

    def __post_init__(self) -> None:
        if type(self.method) is not str or not self.method:
            raise ValueError("passive network method must not be empty")
        if type(self.resource_type) is not str:
            raise TypeError("passive network resource type must be a string")
        if type(self.scheme) is not str or type(self.host) is not str:
            raise TypeError("passive network origin fields must be strings")
        try:
            query_parameter_names = tuple(sorted(self.query_parameter_names))
        except TypeError as exc:
            raise TypeError(
                "passive network query names must be an iterable of strings"
            ) from exc
        method = self.method.upper()
        resource_type = self.resource_type.lower()
        scheme = self.scheme.lower()
        host = self.host.lower()
        scope = PassiveNetworkScope(self.scope)
        if len(method) > _MAX_PASSIVE_METHOD_CHARACTERS:
            raise ValueError("passive network method is too long")
        if resource_type not in {"fetch", "xhr"}:
            raise ValueError("passive network resource type must be fetch or xhr")
        if scheme not in _HTTP_SCHEMES or not host:
            raise ValueError("passive network origin must be absolute HTTP(S)")
        if len(host) > _MAX_PASSIVE_HOST_CHARACTERS:
            raise ValueError("passive network host is too long")
        if (
            type(self.effective_port) is not int
            or not 1 <= self.effective_port <= 65535
        ):
            raise ValueError("passive network effective port is invalid")
        if (
            type(self.path_fingerprint) is not str
            or not self.path_fingerprint
            or any(character.isspace() for character in self.path_fingerprint)
        ):
            raise ValueError("passive network path fingerprint is invalid")
        if type(self.path_segment_count) is not int or self.path_segment_count < 0:
            raise ValueError("passive network path segment count is invalid")
        if any(type(name) is not str for name in query_parameter_names):
            raise TypeError("passive network query names must be strings")
        if len(query_parameter_names) > _MAX_PASSIVE_QUERY_PARAMETER_NAMES or any(
            len(name) > _MAX_PASSIVE_QUERY_NAME_CHARACTERS
            for name in query_parameter_names
        ):
            raise ValueError("passive network query names exceed safe bounds")
        if type(self.occurrence_count) is not int or self.occurrence_count <= 0:
            raise ValueError("passive network occurrence count must be positive")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "resource_type", resource_type)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "query_parameter_names", query_parameter_names)
        object.__setattr__(self, "scope", scope)


@dataclass(frozen=True, slots=True)
class NetworkDiscoveryCandidate:
    """Bounded internal projection of one already-authorized GET fetch/XHR."""

    resource_type: str
    source_url: str
    base_url: str
    query_parameter_names: tuple[str, ...]
    query_pairs: tuple[tuple[str, str], ...]
    disposition: NetworkDiscoveryDisposition
    elision_reasons: tuple[NetworkDiscoveryElisionReason, ...] = ()
    id: str = field(init=False)

    def __post_init__(self) -> None:
        resource_type = self.resource_type.strip().lower()
        disposition = NetworkDiscoveryDisposition(self.disposition)
        query_parameter_names = tuple(self.query_parameter_names)
        query_pairs = tuple(tuple(pair) for pair in self.query_pairs)
        reasons = tuple(
            sorted(
                (NetworkDiscoveryElisionReason(reason) for reason in self.elision_reasons),
                key=lambda item: item.value,
            )
        )
        if resource_type not in {"fetch", "xhr"}:
            raise ValueError("network discovery resource type must be fetch or xhr")
        if len(reasons) != len(set(reasons)):
            raise ValueError("network discovery elision reasons must be unique")
        if any(type(name) is not str or not name for name in query_parameter_names):
            raise ValueError("network discovery query names must not be empty")
        if any(
            len(name) > _MAX_PASSIVE_QUERY_NAME_CHARACTERS
            for name in query_parameter_names
        ):
            raise ValueError("network discovery query name is too long")
        if len(query_parameter_names) > _MAX_PASSIVE_QUERY_PARAMETER_NAMES:
            raise ValueError("network discovery has too many query names")
        if any(
            len(pair) != 2
            or type(pair[0]) is not str
            or type(pair[1]) is not str
            for pair in query_pairs
        ):
            raise TypeError("network discovery query pairs must contain strings")
        if any(
            len(value) > _MAX_NETWORK_QUERY_VALUE_CHARACTERS
            for _, value in query_pairs
        ):
            raise ValueError("network discovery query value is too long")
        if disposition == NetworkDiscoveryDisposition.SAFE:
            if reasons or tuple(name for name, _ in query_pairs) != query_parameter_names:
                raise ValueError("safe network discovery query structure is invalid")
            if contains_credential_material(query_pairs):
                raise ValueError("safe network discovery contains credential material")
        elif query_pairs or not reasons:
            raise ValueError("elided network discovery must retain names only")
        canonical_urls: dict[str, str] = {}
        for label, url in (("source", self.source_url), ("base", self.base_url)):
            try:
                canonical = _canonical_request_url(url)
            except DynamicBrowserError:
                raise ValueError(
                    f"network discovery {label} URL must be canonical"
                ) from None
            parts = urlsplit(canonical)
            if canonical != url or parts.query or parts.fragment:
                raise ValueError(
                    f"network discovery {label} URL must be query-free canonical"
                )
            if len(parts.path or "/") > _MAX_NETWORK_PATH_CHARACTERS:
                raise ValueError(f"network discovery {label} path is too long")
            canonical_urls[label] = canonical
        if _origin(canonical_urls["source"]) != _origin(canonical_urls["base"]):
            raise ValueError("network discovery candidate escaped source origin")
        encoded_query = urlencode(query_pairs)
        if len(encoded_query) > _MAX_NETWORK_QUERY_CHARACTERS:
            raise ValueError("network discovery encoded query is too long")
        if len(self.base_url) + len(encoded_query) + 1 > _MAX_PASSIVE_URL_CHARACTERS:
            raise ValueError("network discovery canonical URL is too long")
        fingerprint = stable_fingerprint(
            "network-discovery-candidate",
            resource_type,
            self.source_url,
            self.base_url,
            query_parameter_names,
            query_pairs,
            disposition.value,
            tuple(reason.value for reason in reasons),
        )
        object.__setattr__(self, "resource_type", resource_type)
        object.__setattr__(self, "query_parameter_names", query_parameter_names)
        object.__setattr__(self, "query_pairs", query_pairs)
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "elision_reasons", reasons)
        object.__setattr__(self, "id", f"netcand_{fingerprint[:24]}")

    @property
    def canonical_url(self) -> str | None:
        if self.disposition != NetworkDiscoveryDisposition.SAFE:
            return None
        parts = urlsplit(self.base_url)
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path or "/",
                urlencode(self.query_pairs),
                "",
            )
        )


@dataclass(frozen=True, slots=True)
class BlockedPostJsonCandidate:
    """Value-free structure from one eligible blocked POST JSON attempt."""

    resource_type: str
    source_url: str
    base_url: str
    member_names: tuple[str, ...]
    replay_policy: PostReplayPolicyDecision
    query_parameter_names: tuple[str, ...] = ()
    id: str = field(init=False)

    def __post_init__(self) -> None:
        resource_type = self.resource_type.strip().lower()
        if type(self.replay_policy) is not PostReplayPolicyDecision:
            raise TypeError("POST JSON candidate requires a replay policy decision")
        if resource_type not in {"fetch", "xhr"}:
            raise ValueError("POST JSON resource type must be fetch or xhr")
        if contains_credential_material(
            self.member_names
        ) or contains_credential_material(self.query_parameter_names):
            raise ValueError("POST JSON structure contains credential material")
        canonical_names = tuple(
            sorted(normalize_parameter_name(name) for name in self.member_names)
        )
        query_parameter_names = tuple(
            sorted(
                normalize_parameter_name(name)
                for name in self.query_parameter_names
            )
        )
        if contains_credential_material(
            canonical_names
        ) or contains_credential_material(query_parameter_names):
            raise ValueError("POST JSON structure contains credential material")
        if len(canonical_names) > _MAX_NETWORK_JSON_MEMBER_NAMES:
            raise ValueError("POST JSON has too many member names")
        if any(
            not name or len(name) > _MAX_PASSIVE_QUERY_NAME_CHARACTERS
            for name in canonical_names
        ):
            raise ValueError("POST JSON member name is invalid")
        if len(set(canonical_names)) != len(canonical_names):
            raise ValueError("POST JSON member names must be unique")
        if any(
            not name or len(name) > _MAX_PASSIVE_QUERY_NAME_CHARACTERS
            for name in query_parameter_names
        ):
            raise ValueError("POST JSON query name is invalid")
        if len(query_parameter_names) > _MAX_PASSIVE_QUERY_PARAMETER_NAMES:
            raise ValueError("POST JSON has too many query names")
        canonical_urls: dict[str, str] = {}
        for label, url in (("source", self.source_url), ("base", self.base_url)):
            try:
                canonical = _canonical_request_url(url)
            except DynamicBrowserError:
                raise ValueError(
                    f"POST JSON {label} URL must be canonical"
                ) from None
            parts = urlsplit(canonical)
            if canonical != url or parts.query or parts.fragment:
                raise ValueError(
                    f"POST JSON {label} URL must be query-free canonical"
                )
            if len(parts.path or "/") > _MAX_NETWORK_PATH_CHARACTERS:
                raise ValueError(f"POST JSON {label} path is too long")
            canonical_urls[label] = canonical
        if _origin(canonical_urls["source"]) != _origin(canonical_urls["base"]):
            raise ValueError("POST JSON candidate escaped source origin")
        fingerprint = stable_fingerprint(
            "blocked-post-json-candidate",
            "POST",
            resource_type,
            self.source_url,
            self.base_url,
            canonical_names,
            query_parameter_names,
        )
        object.__setattr__(self, "resource_type", resource_type)
        object.__setattr__(self, "member_names", canonical_names)
        object.__setattr__(self, "query_parameter_names", query_parameter_names)
        object.__setattr__(self, "replay_policy", self.replay_policy)
        object.__setattr__(self, "id", f"postjson_{fingerprint[:24]}")

    @property
    def canonical_url(self) -> str:
        parts = urlsplit(self.base_url)
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path or "/",
                urlencode(tuple((name, "") for name in self.query_parameter_names)),
                "",
            )
        )


@dataclass(frozen=True, slots=True)
class NetworkDiscoveryCollection:
    """Internal candidate set kept separate from passive browser audit evidence."""

    candidates: tuple[NetworkDiscoveryCandidate, ...] = ()
    skipped_counts: tuple[tuple[NetworkDiscoverySkipReason, int], ...] = ()
    overflow_count: int = 0
    post_json_candidates: tuple[BlockedPostJsonCandidate, ...] = ()
    post_json_replay_materials: tuple[
        tuple[str, EphemeralRequestMaterial], ...
    ] = field(default_factory=tuple, repr=False, compare=False)
    post_json_skipped_counts: tuple[tuple[str, PostJsonSkipReason, int], ...] = ()

    def __post_init__(self) -> None:
        raw_candidates = tuple(self.candidates)
        if any(type(item) is not NetworkDiscoveryCandidate for item in raw_candidates):
            raise TypeError("network discovery candidates must be canonical")
        candidates = tuple(sorted(raw_candidates, key=lambda item: item.id))
        if len({item.id for item in candidates}) != len(candidates):
            raise ValueError("network discovery candidates must be unique")
        counts = tuple(
            sorted(
                (
                    (NetworkDiscoverySkipReason(reason), count)
                    for reason, count in self.skipped_counts
                ),
                key=lambda item: item[0].value,
            )
        )
        if any(type(count) is not int or count <= 0 for _, count in counts):
            raise ValueError("network discovery skipped counts must be positive")
        if len({reason for reason, _ in counts}) != len(counts):
            raise ValueError("network discovery skipped reasons must be unique")
        if type(self.overflow_count) is not int or self.overflow_count < 0:
            raise ValueError("network discovery overflow count must be non-negative")
        raw_post_candidates = tuple(self.post_json_candidates)
        if any(
            type(item) is not BlockedPostJsonCandidate
            for item in raw_post_candidates
        ):
            raise TypeError("POST JSON candidates must be canonical")
        post_candidates = tuple(
            sorted(raw_post_candidates, key=lambda item: item.id)
        )
        if len({item.id for item in post_candidates}) != len(post_candidates):
            raise ValueError("POST JSON candidates must be unique")
        raw_replay_materials = tuple(self.post_json_replay_materials)
        if any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not EphemeralRequestMaterial
            for item in raw_replay_materials
        ):
            raise TypeError("POST JSON replay material must be explicit and transient")
        replay_materials = tuple(sorted(raw_replay_materials, key=lambda item: item[0]))
        if len({candidate_id for candidate_id, _ in replay_materials}) != len(
            replay_materials
        ):
            raise ValueError("POST JSON replay material ownership must be unique")
        post_candidates_by_id = {item.id: item for item in post_candidates}
        for candidate_id, material in replay_materials:
            candidate = post_candidates_by_id.get(candidate_id)
            if candidate is None:
                raise ValueError("POST JSON replay material has no structural owner")
            if (
                candidate.replay_policy.disposition
                != PostReplayDisposition.SAFE_FOR_PROBE
            ):
                raise ValueError("non-safe POST JSON candidate cannot retain replay material")
            if tuple(
                sorted(normalize_parameter_name(name) for name, _ in material.json_body)
            ) != candidate.member_names:
                raise ValueError("POST JSON replay body does not match structural names")
            if tuple(
                sorted(normalize_parameter_name(name) for name, _ in material.query)
            ) != candidate.query_parameter_names:
                raise ValueError("POST JSON replay query does not match structural names")
        post_counts = tuple(
            sorted(
                (
                    (source_url, PostJsonSkipReason(reason), count)
                    for source_url, reason, count in self.post_json_skipped_counts
                ),
                key=lambda item: (item[0], item[1].value),
            )
        )
        if any(
            type(source_url) is not str
            or not source_url
            or type(count) is not int
            or count <= 0
            for source_url, _, count in post_counts
        ):
            raise ValueError("POST JSON skipped counts must be positive and sourced")
        if len({(source, reason) for source, reason, _ in post_counts}) != len(
            post_counts
        ):
            raise ValueError("POST JSON skipped count keys must be unique")
        for source_url, _, _ in post_counts:
            try:
                canonical_source = _canonical_request_url(source_url)
            except DynamicBrowserError:
                raise ValueError(
                    "POST JSON skipped source must be canonical"
                ) from None
            source_parts = urlsplit(canonical_source)
            if (
                canonical_source != source_url
                or source_parts.query
                or source_parts.fragment
                or len(source_parts.path or "/") > _MAX_NETWORK_PATH_CHARACTERS
            ):
                raise ValueError("POST JSON skipped source must be query-free")
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "skipped_counts", counts)
        object.__setattr__(self, "post_json_candidates", post_candidates)
        object.__setattr__(self, "post_json_replay_materials", replay_materials)
        object.__setattr__(self, "post_json_skipped_counts", post_counts)


@dataclass(frozen=True, slots=True)
class BrowserAuditSummary:
    """Immutable minimal lifecycle and transport audit."""

    playwright_started: int
    playwright_stopped: int
    browsers_launched: int
    browsers_closed: int
    contexts_created: int
    contexts_closed: int
    pages_created: int
    pages_closed: int
    popup_attempt_count: int
    http_allowed_count: int
    http_blocked_count: int
    main_frame_navigation_allowed_count: int
    main_frame_navigation_blocked_count: int
    eventsource_attempt_count: int
    eventsource_blocked_count: int
    eventsource_allowed_count: int
    websocket_attempt_count: int
    websocket_blocked_count: int
    websocket_connected_count: int
    child_frame_attach_attempt_count: int
    child_frame_document_request_count: int
    child_frame_document_blocked_count: int
    child_frame_commit_count: int
    child_frame_authorized_commit_count: int
    child_frame_unauthorized_commit_count: int
    child_frame_internal_commit_count: int
    child_frame_about_blank_commit_count: int
    child_frame_browser_error_commit_count: int
    child_frame_replacement_commit_count: int
    child_frame_completion_count: int
    child_frame_authorized_completion_count: int
    child_frame_unauthorized_completion_count: int
    child_frame_internal_completion_count: int
    child_frame_about_blank_completion_count: int
    child_frame_browser_error_completion_count: int
    child_frame_replacement_completion_count: int
    child_frame_commit_kinds: tuple[ChildFrameDocumentKind, ...]
    child_frame_completion_kinds: tuple[ChildFrameDocumentKind, ...]
    child_frame_commit_overflow_count: int
    child_frame_completion_overflow_count: int
    child_frame_detach_count: int
    redirect_attempt_count: int
    redirect_allowed_count: int
    redirect_block_count: int
    redirect_followed_count: int
    request_decision_overflow_count: int
    cleanup_error_codes: tuple[str, ...]
    cleanup_complete: bool
    events: tuple[BrowserAuditEvent, ...]
    network_observations: tuple[PassiveNetworkObservation, ...] = field(
        default_factory=tuple
    )
    network_observation_overflow_count: int = 0


class DynamicBrowserError(RuntimeError):
    """Typed lifecycle failure with retained secret-free cleanup evidence."""

    def __init__(
        self,
        code: DynamicBrowserErrorCode,
        message: str,
        *,
        cleanup_error_codes: tuple[str, ...] = (),
        audit: BrowserAuditSummary | None = None,
        network_discovery: NetworkDiscoveryCollection | None = None,
    ) -> None:
        super().__init__(message)
        self.code = DynamicBrowserErrorCode(code)
        self.cleanup_error_codes = tuple(cleanup_error_codes)
        self.audit = audit
        self.network_discovery = network_discovery

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        """Preserve typed browser failures across the supervised worker seam."""

        return (
            _restore_dynamic_browser_error,
            (
                self.code,
                str(self),
                self.cleanup_error_codes,
                self.audit,
                self.network_discovery,
            ),
        )


def _restore_dynamic_browser_error(
    code: DynamicBrowserErrorCode,
    message: str,
    cleanup_error_codes: tuple[str, ...],
    audit: BrowserAuditSummary | None,
    network_discovery: NetworkDiscoveryCollection | None,
) -> DynamicBrowserError:
    return DynamicBrowserError(
        code,
        message,
        cleanup_error_codes=cleanup_error_codes,
        audit=audit,
        network_discovery=network_discovery,
    )


@dataclass(frozen=True, slots=True)
class DynamicBrowserPolicy:
    """Bounds owned by this lifecycle seam."""

    navigation_timeout_seconds: float = _DEFAULT_NAVIGATION_TIMEOUT_SECONDS
    request_decision_budget: int = _DEFAULT_REQUEST_DECISION_BUDGET
    navigation_request_budget: int = 8
    max_redirects_per_navigation: int = 3
    deadline_monotonic: float | None = None

    def __post_init__(self) -> None:
        if (
            type(self.navigation_timeout_seconds) not in {int, float}
            or isinstance(self.navigation_timeout_seconds, bool)
            or self.navigation_timeout_seconds <= 0
        ):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Navigation timeout must be a positive number.",
            )
        for name in (
            "request_decision_budget",
            "navigation_request_budget",
            "max_redirects_per_navigation",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.INVALID_AUTHORITY,
                    f"{name} must be a positive integer.",
                )
        object.__setattr__(
            self,
            "navigation_timeout_seconds",
            float(self.navigation_timeout_seconds),
        )
        if self.deadline_monotonic is not None:
            if (
                type(self.deadline_monotonic) not in {int, float}
                or isinstance(self.deadline_monotonic, bool)
                or not isfinite(self.deadline_monotonic)
                or self.deadline_monotonic <= 0
            ):
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.INVALID_AUTHORITY,
                    "Browser deadline must be finite and positive.",
                )
            object.__setattr__(
                self,
                "deadline_monotonic",
                float(self.deadline_monotonic),
            )


@dataclass(frozen=True, slots=True)
class DynamicRequestAuthority:
    """Immutable exact caller authority for one loopback browser session."""

    root_url: str
    navigation_urls: tuple[str, ...] = ()
    resource_grants: tuple[DynamicResourceGrant, ...] = ()
    allow_rendered_navigation: bool = False
    allow_passive_same_origin_resources: bool = False
    allow_passive_same_origin_fetch_xhr: bool = False

    def __post_init__(self) -> None:
        root_url = _canonical_authority_url(self.root_url)
        try:
            require_loopback_http_url(root_url)
        except LoopbackSafetyError:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Dynamic browser root must use an explicit loopback authority.",
            ) from None
        try:
            navigation_inputs = tuple(self.navigation_urls)
            grant_inputs = tuple(self.resource_grants)
        except TypeError:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Dynamic request authority collections must be iterable.",
            ) from None
        for name in (
            "allow_rendered_navigation",
            "allow_passive_same_origin_resources",
            "allow_passive_same_origin_fetch_xhr",
        ):
            if type(getattr(self, name)) is not bool:
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.INVALID_AUTHORITY,
                    f"{name} must be a boolean.",
                )

        navigation_urls = {root_url}
        for url in navigation_inputs:
            canonical = _canonical_authority_url(url)
            _require_same_origin(root_url, canonical)
            navigation_urls.add(canonical)

        resource_grants: set[tuple[DynamicResourceKind, str]] = set()
        for grant in grant_inputs:
            if type(grant) is not DynamicResourceGrant:
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.INVALID_AUTHORITY,
                    "Resource authority requires canonical DynamicResourceGrant.",
                )
            canonical = _canonical_authority_url(grant.url)
            _require_same_origin(root_url, canonical)
            resource_grants.add((grant.kind, canonical))

        object.__setattr__(self, "root_url", root_url)
        object.__setattr__(self, "navigation_urls", tuple(sorted(navigation_urls)))
        object.__setattr__(
            self,
            "resource_grants",
            tuple(
                DynamicResourceGrant(kind=kind, url=url)
                for kind, url in sorted(
                    resource_grants,
                    key=lambda item: (item[0].value, item[1]),
                )
            ),
        )

    def allows_navigation(self, url: str) -> bool:
        try:
            canonical = _canonical_request_url(url)
        except DynamicBrowserError:
            return False
        return canonical in self.navigation_urls

    def allows_rendered_navigation(self, url: str) -> bool:
        """Allow an explicitly enabled same-origin rendered/SPA URL.

        URL fragments are browser-local state and are never transmitted in an
        HTTP request. Angular/hash-router URLs such as ``/#/search`` therefore
        authorize against the same URL with only the fragment removed.
        """

        if not self.allow_rendered_navigation or type(url) is not str:
            return False
        try:
            parts = urlsplit(url)
            transport_url = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, parts.query, "")
            )
            canonical = _canonical_request_url(transport_url)
        except (DynamicBrowserError, ValueError):
            return False
        return _origin(self.root_url) == _origin(canonical)

    def decide_http(
        self,
        *,
        method: str,
        url: str,
        resource_type: str,
        is_primary_page: bool,
        is_main_frame: bool,
    ) -> DynamicNetworkDecision:
        normalized_kind = resource_type.strip().lower()
        try:
            canonical = _canonical_request_url(url)
        except DynamicBrowserError:
            reason = (
                DynamicNetworkReason.UNSUPPORTED_SCHEME
                if _safe_scheme(url) not in _HTTP_SCHEMES
                else DynamicNetworkReason.INVALID_URL
            )
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                reason,
                None,
                normalized_kind,
            )
        normalized_method = method.upper()
        is_balanced_fetch_xhr_method = (
            self.allow_passive_same_origin_fetch_xhr
            and normalized_method in {"GET", "HEAD"}
            and normalized_kind in {"fetch", "xhr"}
        )
        if normalized_method != "GET" and not is_balanced_fetch_xhr_method:
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.NON_GET_METHOD,
                canonical,
                normalized_kind,
            )
        if not is_primary_page:
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.NON_PRIMARY_PAGE,
                canonical,
                normalized_kind,
            )
        if normalized_kind == "document":
            if not is_main_frame:
                return DynamicNetworkDecision(
                    DynamicNetworkDecisionKind.BLOCK,
                    DynamicNetworkReason.CHILD_FRAME_DOCUMENT,
                    canonical,
                    normalized_kind,
                )
            if canonical in self.navigation_urls:
                return DynamicNetworkDecision(
                    DynamicNetworkDecisionKind.ALLOW,
                    DynamicNetworkReason.AUTHORIZED_NAVIGATION,
                    canonical,
                    normalized_kind,
                )
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
                canonical,
                normalized_kind,
            )
        if normalized_kind == "eventsource":
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.EVENTSOURCE_DENIED,
                canonical,
                normalized_kind,
            )
        grant_kind = _grant_kind_for_resource_type(normalized_kind)
        if grant_kind is None:
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.RESOURCE_KIND_NOT_AUTHORIZED,
                canonical,
                normalized_kind,
            )
        if any(
            grant.kind == grant_kind and grant.url == canonical
            for grant in self.resource_grants
        ):
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.ALLOW,
                DynamicNetworkReason.AUTHORIZED_RESOURCE,
                canonical,
                normalized_kind,
            )
        if (
            self.allow_passive_same_origin_resources
            and grant_kind
            in {DynamicResourceKind.SCRIPT, DynamicResourceKind.STYLE}
            and _origin(self.root_url) == _origin(canonical)
        ):
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.ALLOW,
                DynamicNetworkReason.AUTHORIZED_RESOURCE,
                canonical,
                normalized_kind,
            )
        if (
            is_balanced_fetch_xhr_method
            and grant_kind == DynamicResourceKind.FETCH_XHR
            and _origin(self.root_url) == _origin(canonical)
        ):
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.ALLOW,
                DynamicNetworkReason.PASSIVE_SAME_ORIGIN_FETCH_XHR,
                canonical,
                normalized_kind,
            )
        return DynamicNetworkDecision(
            DynamicNetworkDecisionKind.BLOCK,
            DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
            canonical,
            normalized_kind,
        )


class DynamicBrowserSession(Protocol):
    """Limited caller seam over one guarded primary page."""

    def navigate(
        self,
        url: str | None = None,
        *,
        timeout_seconds: float | None = None,
        rendered_navigation: bool = False,
    ) -> str:
        """Navigate to exact authority or one crawler-observed anchor URL."""

    def navigation_status_code(self) -> int | None:
        """Return the last direct navigation HTTP status when available."""

    def wait_for_selector(self, selector: str) -> None:
        """Wait within the configured operation timeout."""

    def text_content(self, selector: str) -> str | None:
        """Read one selected DOM text value."""

    def capture_rendered_dom(
        self,
        policy: RenderedDomPolicy | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> RenderedDomSnapshot:
        """Capture one bounded, sensitive-form-free main-frame snapshot."""

    def perform_safe_route_actions(
        self,
        max_actions: int,
        *,
        marker: str = "vulnspider-probe",
    ) -> int:
        """Exercise bounded search/filter UI controls without credential forms."""

    def close_page(self) -> None:
        """Close the owned primary page once through managed lifecycle cleanup."""


class DynamicBrowser(Protocol):
    """Synchronous managed browser boundary."""

    def run(
        self,
        authority: DynamicRequestAuthority,
        operation: Callable[[DynamicBrowserSession], T],
        *,
        policy: DynamicBrowserPolicy | None = None,
    ) -> "DynamicBrowserRunResult[T]":
        """Run one guarded operation and close all owned resources."""


@dataclass(frozen=True, slots=True)
class DynamicBrowserRunResult(Generic[T]):
    """Caller result plus final immutable cleanup/network audit."""

    value: T
    audit: BrowserAuditSummary
    network_discovery: NetworkDiscoveryCollection = field(
        default_factory=NetworkDiscoveryCollection
    )


def _load_playwright_sync_api() -> tuple[type[Any], Callable[[], Any]]:
    # This is intentionally the only production Playwright import. Keeping it
    # inside the explicit preflight preserves Static and legacy importability.
    from playwright.sync_api import BrowserContext, sync_playwright

    return BrowserContext, sync_playwright


def _parse_supported_version(version: str) -> tuple[int, int, int] | None:
    match = _VERSION_PATTERN.fullmatch(version)
    if match is None:
        return None
    parsed = tuple(int(part) for part in match.groups())
    if parsed[0] != _SUPPORTED_MAJOR or parsed[1] < _MINIMUM_MINOR:
        return None
    return parsed


def _error(
    code: DynamicCapabilityCode,
    message: str,
    setup_hint: str,
    *,
    cleanup_failed: bool = False,
) -> DynamicCapabilityError:
    return DynamicCapabilityError(
        code,
        message,
        setup_hint=setup_hint,
        cleanup_failed=cleanup_failed,
    )


def preflight_dynamic_browser(
    *,
    timeout_seconds: float | None = None,
) -> DynamicBrowserCapability:
    """Verify the optional Playwright package, WebSocket guard, and Chromium."""

    deadline = (
        None if timeout_seconds is None else monotonic() + float(timeout_seconds)
    )
    package_hint = "Install the optional runtime with: pip install -e .[dynamic]"
    browser_hint = "Install the matching browser with: playwright install chromium"
    try:
        version = metadata.version(_PLAYWRIGHT_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_PACKAGE_MISSING,
            "The optional Playwright package is not installed.",
            package_hint,
        ) from None
    except Exception:  # noqa: BLE001 - metadata diagnostics stay private.
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_METADATA_FAILED,
            "Playwright package metadata could not be read.",
            package_hint,
        ) from None
    if type(version) is not str or _parse_supported_version(version) is None:
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_VERSION_UNSUPPORTED,
            f"Playwright does not satisfy {PLAYWRIGHT_REQUIREMENT}.",
            package_hint,
        )

    try:
        browser_context_type, sync_playwright = _load_playwright_sync_api()
    except Exception:  # noqa: BLE001 - import diagnostics stay private.
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_IMPORT_FAILED,
            "The installed Playwright synchronous API is unavailable.",
            package_hint,
        ) from None
    if not callable(getattr(browser_context_type, "route_web_socket", None)):
        raise _error(
            DynamicCapabilityCode.WEBSOCKET_GUARD_UNAVAILABLE,
            "The required context-wide WebSocket guard is unavailable.",
            package_hint,
        )

    playwright: Any | None = None
    chromium: Any | None = None
    browser: Any | None = None
    capability: DynamicBrowserCapability | None = None
    failure: DynamicCapabilityError | None = None
    try:
        try:
            playwright = sync_playwright().start()
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            failure = _error(
                DynamicCapabilityCode.PLAYWRIGHT_START_FAILED,
                "The Playwright runtime could not start.",
                package_hint,
            )
        if failure is None:
            try:
                chromium = playwright.chromium
                executable_path = getattr(chromium, "executable_path", None)
                executable_exists = (
                    type(executable_path) is str
                    and bool(executable_path)
                    and Path(executable_path).is_file()
                )
            except Exception:  # noqa: BLE001 - provider diagnostics stay private.
                failure = _error(
                    DynamicCapabilityCode.PLAYWRIGHT_RUNTIME_UNAVAILABLE,
                    "The Playwright Chromium runtime is unavailable.",
                    browser_hint,
                )
            if failure is None and not executable_exists:
                failure = _error(
                    DynamicCapabilityCode.CHROMIUM_EXECUTABLE_MISSING,
                    "The matching Playwright Chromium executable is unavailable.",
                    browser_hint,
                )
        if failure is None:
            try:
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError
                browser = chromium.launch(
                    **_browser_launch_options(timeout_seconds=remaining)
                )
            except Exception:  # noqa: BLE001 - provider diagnostics stay private.
                failure = _error(
                    DynamicCapabilityCode.CHROMIUM_LAUNCH_FAILED,
                    "Headless Chromium could not launch.",
                    browser_hint,
                )
        if failure is None:
            capability = DynamicBrowserCapability(
                playwright_version=version,
                browser_name="chromium",
                websocket_guard_callable=True,
                headless_launch_verified=True,
            )
    finally:
        cleanup_failed = False
        if browser is not None:
            try:
                browser.close()
            except Exception:  # noqa: BLE001 - emit only a stable safe code.
                cleanup_failed = True
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:  # noqa: BLE001 - emit only a stable safe code.
                cleanup_failed = True
        if cleanup_failed:
            if failure is None:
                failure = _error(
                    DynamicCapabilityCode.PREFLIGHT_CLEANUP_FAILED,
                    "Dynamic browser preflight cleanup did not complete.",
                    "Retry preflight in a clean local process.",
                    cleanup_failed=True,
                )
            else:
                failure = _error(
                    failure.code,
                    str(failure),
                    failure.setup_hint,
                    cleanup_failed=True,
                )

    if failure is not None:
        raise failure from None
    if capability is None:
        raise _error(
            DynamicCapabilityCode.CHROMIUM_LAUNCH_FAILED,
            "Dynamic browser preflight did not produce a result.",
            browser_hint,
        )
    return capability


def _load_managed_playwright_sync_api() -> tuple[Callable[[], Any], type[Exception]]:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    return sync_playwright, PlaywrightTimeoutError


def _browser_launch_options(
    *,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    browser_environment = dict(os.environ)
    browser_environment["CHROME_LOG_FILE"] = os.devnull
    options: dict[str, Any] = {
        "headless": True,
        "env": browser_environment,
        "args": [f"--log-file={os.devnull}"],
    }
    if timeout_seconds is not None:
        options["timeout"] = max(1.0, timeout_seconds * 1000.0)
    return options


def _remaining_deadline_seconds(
    policy: DynamicBrowserPolicy,
) -> float | None:
    deadline = policy.deadline_monotonic
    if deadline is None:
        return None
    return max(0.0, deadline - monotonic())


def _deadline_expired(policy: DynamicBrowserPolicy) -> bool:
    remaining = _remaining_deadline_seconds(policy)
    return remaining is not None and remaining <= 0


def _canonical_authority_url(url: str) -> str:
    if type(url) is not str or not url or url != url.strip():
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority requires an absolute HTTP(S) URL.",
        )
    if any(character in url for character in "\r\n\t"):
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority contains invalid URL characters.",
        )
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority contains a malformed URL.",
        ) from None
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower() if parts.hostname else ""
    if (
        scheme not in _HTTP_SCHEMES
        or not hostname
        or (port is not None and port <= 0)
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority requires a credential-free HTTP(S) URL.",
        )
    effective_port = _DEFAULT_PORTS[scheme] if port is None else port
    host_text = f"[{hostname}]" if ":" in hostname else hostname
    netloc = (
        host_text
        if effective_port == _DEFAULT_PORTS[scheme]
        else f"{host_text}:{effective_port}"
    )
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _canonical_request_url(url: str) -> str:
    try:
        return _canonical_authority_url(url)
    except DynamicBrowserError as exc:
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Browser request URL is invalid or unsupported.",
        ) from None


def _require_same_origin(root_url: str, candidate_url: str) -> None:
    if _origin(root_url) != _origin(candidate_url):
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority cannot cross the root origin.",
        )


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower() if parts.hostname else ""
    port = parts.port
    return scheme, hostname, _DEFAULT_PORTS[scheme] if port is None else port


def _safe_scheme(url: str) -> str:
    if type(url) is not str:
        return ""
    try:
        return urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def _grant_kind_for_resource_type(
    resource_type: str,
) -> DynamicResourceKind | None:
    if resource_type == "script":
        return DynamicResourceKind.SCRIPT
    if resource_type == "stylesheet":
        return DynamicResourceKind.STYLE
    if resource_type in {"fetch", "xhr"}:
        return DynamicResourceKind.FETCH_XHR
    return None


def _safe_audit_event(
    *,
    url: str,
    resource_kind: str,
    decision: DynamicNetworkDecisionKind,
    reason: DynamicNetworkReason,
) -> BrowserAuditEvent:
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname.lower() if parts.hostname else ""
        parsed_port = parts.port
        port = _DEFAULT_PORTS.get(scheme) if parsed_port is None else parsed_port
        path = parts.path or "/"
        query_name_count = len(parse_qsl(parts.query, keep_blank_values=True))
    except (TypeError, ValueError):
        scheme = ""
        host = ""
        port = None
        path = ""
        query_name_count = 0
    return BrowserAuditEvent(
        resource_kind=resource_kind,
        decision=decision,
        reason=reason,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query_name_count=query_name_count,
    )


def _passive_network_observation_key(
    observation: PassiveNetworkObservation,
) -> tuple[object, ...]:
    return (
        observation.method,
        observation.resource_type,
        observation.scheme,
        observation.host,
        observation.effective_port,
        observation.path_fingerprint,
        observation.path_segment_count,
        observation.query_parameter_names,
        observation.scope.value,
    )


def _query_parameter_names(raw_query: str) -> tuple[str, ...]:
    names: list[str] = []
    for token in raw_query.split("&") if raw_query else ():
        raw_name = token.partition("=")[0]
        name = unquote_plus(raw_name)
        if len(name) > _MAX_PASSIVE_QUERY_NAME_CHARACTERS:
            raise ValueError("passive network query name is too long")
        names.append(name)
        if len(names) > _MAX_PASSIVE_QUERY_PARAMETER_NAMES:
            raise ValueError("too many passive network query names")
    return tuple(sorted(names))


def _safe_passive_network_observation(
    *,
    method: str,
    url: str,
    resource_type: str,
    root_origin: tuple[str, str, int],
) -> PassiveNetworkObservation | None:
    if (
        type(method) is not str
        or type(url) is not str
        or type(resource_type) is not str
        or not method
        or len(method) > _MAX_PASSIVE_METHOD_CHARACTERS
        or len(url) > _MAX_PASSIVE_URL_CHARACTERS
    ):
        return None
    normalized_resource_type = resource_type.strip().lower()
    if normalized_resource_type not in {"fetch", "xhr"}:
        return None
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname.lower() if parts.hostname else ""
        parsed_port = parts.port
        effective_port = (
            _DEFAULT_PORTS[scheme] if parsed_port is None else parsed_port
        )
        if effective_port <= 0:
            return None
        if len(host) > _MAX_PASSIVE_HOST_CHARACTERS:
            return None
        query_parameter_names = _query_parameter_names(parts.query)
    except (KeyError, TypeError, ValueError):
        return None
    if scheme not in _HTTP_SCHEMES or not host:
        return None
    path = parts.path or "/"
    return PassiveNetworkObservation(
        method=method.upper(),
        resource_type=normalized_resource_type,
        scheme=scheme,
        host=host,
        effective_port=effective_port,
        path_fingerprint=stable_fingerprint("passive-network-path", path)[:24],
        path_segment_count=sum(1 for segment in path.split("/") if segment),
        query_parameter_names=query_parameter_names,
        scope=(
            PassiveNetworkScope.SAME_SCOPE
            if (scheme, host, effective_port) == root_origin
            else PassiveNetworkScope.OFF_SCOPE
        ),
    )


def _safe_network_discovery_candidate(
    *,
    method: str,
    url: str,
    resource_type: str,
    source_url: str,
    root_origin: tuple[str, str, int],
    credential_header_present: bool,
) -> tuple[NetworkDiscoveryCandidate | None, NetworkDiscoverySkipReason | None]:
    """Project one allowed GET without retaining an unsafe request value."""

    if (
        type(method) is not str
        or type(url) is not str
        or type(resource_type) is not str
        or method.upper() != "GET"
        or resource_type.strip().lower() not in {"fetch", "xhr"}
    ):
        return None, None
    if len(url) > _MAX_PASSIVE_URL_CHARACTERS:
        return None, NetworkDiscoverySkipReason.URL_TOO_LARGE
    if (
        not url
        or url != url.strip()
        or any(character in url for character in "\r\n\t")
    ):
        return None, NetworkDiscoverySkipReason.INVALID_URL
    try:
        canonical = _canonical_request_url(url)
        parts = urlsplit(canonical)
    except (DynamicBrowserError, TypeError, ValueError):
        return None, NetworkDiscoverySkipReason.INVALID_URL
    if _origin(canonical) != root_origin:
        return None, None
    path = parts.path or "/"
    if len(path) > _MAX_NETWORK_PATH_CHARACTERS:
        return None, NetworkDiscoverySkipReason.PATH_TOO_LARGE
    if len(parts.query) > _MAX_NETWORK_QUERY_CHARACTERS:
        return None, NetworkDiscoverySkipReason.QUERY_TOO_LARGE
    if _invalid_percent_encoding(parts.query):
        return None, NetworkDiscoverySkipReason.INVALID_URL
    try:
        query_pairs = tuple(parse_qsl(parts.query, keep_blank_values=True))
    except (TypeError, ValueError):
        return None, NetworkDiscoverySkipReason.INVALID_URL
    if len(query_pairs) > _MAX_PASSIVE_QUERY_PARAMETER_NAMES:
        return None, NetworkDiscoverySkipReason.QUERY_TOO_LARGE
    if any(
        not name.strip() or len(name) > _MAX_PASSIVE_QUERY_NAME_CHARACTERS
        for name, _ in query_pairs
    ):
        return None, NetworkDiscoverySkipReason.QUERY_NAME_INVALID
    if any(len(value) > _MAX_NETWORK_QUERY_VALUE_CHARACTERS for _, value in query_pairs):
        return None, NetworkDiscoverySkipReason.QUERY_VALUE_TOO_LARGE
    try:
        canonical_source = _query_free_network_url(source_url, root_origin=root_origin)
    except ValueError:
        return None, NetworkDiscoverySkipReason.INVALID_URL
    base_url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    sensitive_query = contains_credential_material(query_pairs)
    reasons: list[NetworkDiscoveryElisionReason] = []
    if sensitive_query:
        reasons.append(NetworkDiscoveryElisionReason.SENSITIVE_QUERY)
    if credential_header_present:
        reasons.append(NetworkDiscoveryElisionReason.CREDENTIAL_HEADER)
    disposition = (
        NetworkDiscoveryDisposition.STRUCTURAL_ELIDED
        if reasons
        else NetworkDiscoveryDisposition.SAFE
    )
    return (
        NetworkDiscoveryCandidate(
            resource_type=resource_type,
            source_url=canonical_source,
            base_url=base_url,
            query_parameter_names=tuple(name for name, _ in query_pairs),
            query_pairs=(
                ()
                if disposition == NetworkDiscoveryDisposition.STRUCTURAL_ELIDED
                else query_pairs
            ),
            disposition=disposition,
            elision_reasons=tuple(reasons),
        ),
        None,
    )


class _JsonObjectPairs(tuple[tuple[str, object], ...]):
    """Marker that distinguishes JSON objects from arrays during parsing."""


class _DuplicateJsonKey(ValueError):
    pass


def _json_object_pairs(pairs: list[tuple[str, object]]) -> _JsonObjectPairs:
    names = tuple(name for name, _ in pairs)
    if len(names) != len(set(names)):
        raise _DuplicateJsonKey
    return _JsonObjectPairs(pairs)


def _reject_json_constant(_value: str) -> object:
    raise ValueError


def _application_json_content_type(value: str) -> bool:
    parts = tuple(part.strip() for part in value.split(";"))
    if not parts or parts[0].lower() != "application/json":
        return False
    parameters = parts[1:]
    if len(parameters) > 1:
        return False
    if not parameters:
        return True
    name, separator, charset = parameters[0].partition("=")
    normalized_charset = charset.strip().strip('"').lower()
    return (
        separator == "="
        and name.strip().lower() == "charset"
        and normalized_charset in {"utf-8", "utf8"}
    )


def _graphql_semantics_present(parsed: _JsonObjectPairs) -> bool:
    """Project only whether a top-level GraphQL document was observed."""

    for name, value in parsed:
        if normalize_parameter_name(name) != "query" or type(value) is not str:
            continue
        ignored_prefix = _GRAPHQL_IGNORED_PREFIX.match(value)
        document = value[ignored_prefix.end() :] if ignored_prefix else value
        if document.startswith("{") or re.match(
            r"(?:query|mutation|subscription|fragment)\b",
            document,
            flags=re.IGNORECASE,
        ):
            return True
    return False


def _safe_blocked_post_json_candidate(
    *,
    method: str,
    url: str,
    resource_type: str,
    source_url: str,
    root_origin: tuple[str, str, int],
    content_type: str | None,
    credential_header_present: bool,
    body: bytes | None,
) -> tuple[
    BlockedPostJsonCandidate | None,
    EphemeralRequestMaterial | None,
    PostJsonSkipReason | None,
]:
    """Split one blocked POST into value-free structure and replay-only material."""

    if (
        type(method) is not str
        or type(url) is not str
        or type(resource_type) is not str
        or method != "POST"
        or resource_type.strip().lower() not in {"fetch", "xhr"}
    ):
        return None, None, None
    if (
        len(url) > _MAX_PASSIVE_URL_CHARACTERS
        or not url
        or url != url.strip()
        or any(character in url for character in "\r\n\t")
    ):
        return None, None, None
    try:
        canonical = _canonical_request_url(url)
        parts = urlsplit(canonical)
    except (DynamicBrowserError, TypeError, ValueError):
        return None, None, None
    if _origin(canonical) != root_origin:
        return None, None, None
    path = parts.path or "/"
    if (
        len(path) > _MAX_NETWORK_PATH_CHARACTERS
        or len(parts.query) > _MAX_NETWORK_QUERY_CHARACTERS
        or _invalid_percent_encoding(parts.query)
    ):
        return None, None, None
    try:
        query_pairs = tuple(parse_qsl(parts.query, keep_blank_values=True))
        canonical_source = _query_free_network_url(
            source_url,
            root_origin=root_origin,
        )
    except (TypeError, ValueError):
        return None, None, None
    if type(content_type) is not str or not _application_json_content_type(
        content_type
    ):
        return None, None, PostJsonSkipReason.CONTENT_TYPE_UNSUPPORTED
    if type(body) is not bytes:
        return None, None, PostJsonSkipReason.BODY_UNAVAILABLE
    if len(body) > _MAX_NETWORK_JSON_BODY_BYTES:
        return None, None, PostJsonSkipReason.BODY_TOO_LARGE
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, None, PostJsonSkipReason.BODY_ENCODING_INVALID
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_json_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKey:
        return None, None, PostJsonSkipReason.JSON_DUPLICATE_KEY
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return None, None, PostJsonSkipReason.JSON_MALFORMED
    if type(parsed) is not _JsonObjectPairs:
        return None, None, PostJsonSkipReason.JSON_TOP_LEVEL_NOT_OBJECT
    if len(parsed) > _MAX_NETWORK_JSON_MEMBER_NAMES:
        return None, None, PostJsonSkipReason.JSON_MEMBER_LIMIT_EXCEEDED
    raw_member_names = tuple(name for name, _ in parsed)
    member_names = _redact_secret_shaped_parameter_names(
        raw_member_names,
        placeholder_kind="json_member",
    )
    if any(
        not name or len(name) > _MAX_PASSIVE_QUERY_NAME_CHARACTERS
        for name in member_names
    ):
        return None, None, PostJsonSkipReason.JSON_MEMBER_NAME_INVALID
    if len(set(member_names)) != len(member_names):
        return None, None, PostJsonSkipReason.JSON_DUPLICATE_KEY
    try:
        member_pairs = tuple(
            sorted(
                (
                    normalize_parameter_name(name),
                    json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
                )
                for name, value in parsed
            )
        )
    except (TypeError, ValueError, RecursionError):
        return None, None, PostJsonSkipReason.JSON_MALFORMED
    base_url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    try:
        replay_policy = classify_post_replay(
            PostReplayPolicyFeatures(
                method="POST",
                path=path,
                member_names=raw_member_names,
                query_parameter_names=tuple(name for name, _ in query_pairs),
                resource_type=resource_type,
                exact_authorized_loopback_origin=True,
                content_type="application/json",
                charset="utf-8",
                top_level_json_object=True,
                scalar_top_level_values=all(
                    value is None or type(value) in {str, int, float, bool}
                    for _, value in parsed
                ),
                reconstruction_complete=True,
                graphql_semantics_present=_graphql_semantics_present(parsed),
                credential_material_present=(
                    contains_credential_material(parsed)
                    or contains_credential_material(raw_member_names)
                    or contains_credential_material(query_pairs)
                ),
                credential_header_present=credential_header_present,
            )
        )
    except Exception:  # noqa: BLE001 - fail closed with a stable policy reason.
        replay_policy = PostReplayPolicyDecision(
            disposition=PostReplayDisposition.STRUCTURAL_ONLY,
            reason_code=PostReplayReasonCode.POLICY_ASSESSMENT_FAILED,
        )
    candidate = BlockedPostJsonCandidate(
        resource_type=resource_type,
        source_url=canonical_source,
        base_url=base_url,
        member_names=member_names,
        query_parameter_names=_redact_secret_shaped_parameter_names(
            tuple(name for name, _ in query_pairs),
            placeholder_kind="query_parameter",
        ),
        replay_policy=replay_policy,
    )
    replay_url = urlunsplit(
        (parts.scheme, parts.netloc, path, urlencode(query_pairs), "")
    )
    replay_material = None
    if replay_policy.disposition == PostReplayDisposition.SAFE_FOR_PROBE:
        replay_material = EphemeralRequestMaterial(
            url=replay_url,
            query=query_pairs,
            json_body=member_pairs,
        )
    return candidate, replay_material, None


def _redact_secret_shaped_parameter_names(
    names: tuple[str, ...],
    *,
    placeholder_kind: str,
) -> tuple[str, ...]:
    """Keep bounded structure without persisting a credential used as a name."""

    retained = [
        normalize_parameter_name(name)
        for name in names
        if not contains_credential_material(name)
    ]
    used = set(retained)
    redacted_count = sum(contains_credential_material(name) for name in names)
    placeholder_index = 1
    while redacted_count:
        placeholder = (
            f"__vulnspider_redacted_{placeholder_kind}_{placeholder_index:04d}__"
        )
        placeholder_index += 1
        if placeholder in used:
            continue
        used.add(placeholder)
        retained.append(placeholder)
        redacted_count -= 1
    return tuple(sorted(retained))


def _invalid_percent_encoding(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if index + 2 >= len(value) or any(
            character not in "0123456789abcdefABCDEF"
            for character in value[index + 1 : index + 3]
        ):
            return True
        index += 3
    return False


def _query_free_network_url(
    url: str,
    *,
    root_origin: tuple[str, str, int],
) -> str:
    canonical = _canonical_request_url(url)
    if _origin(canonical) != root_origin:
        raise ValueError("network discovery source escaped root origin")
    parts = urlsplit(canonical)
    if len(parts.path or "/") > _MAX_NETWORK_PATH_CHARACTERS:
        raise ValueError("network discovery source path is too large")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _request_has_credential_headers(request: Any) -> bool:
    """Inspect provider header names transiently and fail closed on ambiguity."""

    try:
        provider = getattr(request, "all_headers", None)
        headers = provider() if callable(provider) else getattr(request, "headers")
    except Exception:  # noqa: BLE001 - no header value or diagnostic may escape.
        return True
    if not isinstance(headers, Mapping):
        return True
    return any(credential_field_name(name) for name in headers)


def _request_json_header_projection(
    request: Any,
) -> tuple[str | None, bool, bool]:
    """Read only the JSON media type and credential-header presence."""

    try:
        provider = getattr(request, "all_headers", None)
        headers = provider() if callable(provider) else getattr(request, "headers")
    except Exception:  # noqa: BLE001 - provider data and diagnostics stay private.
        return None, True, False
    if not isinstance(headers, Mapping):
        return None, True, False
    content_types: list[str] = []
    credential_header_present = contains_credential_material(headers)
    for name, value in headers.items():
        if type(name) is not str or type(value) is not str:
            return None, True, False
        if credential_field_name(name):
            credential_header_present = True
        if name.strip().lower() == "content-type":
            content_types.append(value)
    if len(content_types) != 1:
        return None, credential_header_present, True
    return content_types[0], credential_header_present, True


def _request_post_data_buffer(request: Any) -> bytes | None:
    """Read a provider POST body transiently without retaining diagnostics."""

    try:
        value = getattr(request, "post_data_buffer")
        value = value() if callable(value) else value
    except Exception:  # noqa: BLE001 - body and diagnostics must not escape.
        return None
    if type(value) is not bytes:
        return None
    return value


def _post_policy_precedence(
    decision: PostReplayPolicyDecision,
) -> tuple[int, str]:
    rank = {
        PostReplayDisposition.SAFE_FOR_PROBE: 0,
        PostReplayDisposition.STRUCTURAL_ONLY: 1,
        PostReplayDisposition.BLOCKED_SENSITIVE: 2,
    }
    return rank[decision.disposition], decision.reason_code.value


class _NetworkDiscoveryRecorder:
    def __init__(self, *, candidate_limit: int) -> None:
        self._candidate_limit = candidate_limit
        self._lock = Lock()
        self._candidates: dict[str, NetworkDiscoveryCandidate] = {}
        self._post_json_candidates: dict[str, BlockedPostJsonCandidate] = {}
        self._post_json_replay_materials: dict[
            str, EphemeralRequestMaterial
        ] = {}
        self._skipped_counts: dict[NetworkDiscoverySkipReason, int] = {}
        self._post_json_skipped_counts: dict[
            tuple[str, PostJsonSkipReason], int
        ] = {}
        self._overflow_count = 0

    def record_allowed_get(
        self,
        *,
        method: str,
        url: str,
        resource_type: str,
        source_url: str,
        root_origin: tuple[str, str, int],
        credential_header_present: bool,
    ) -> None:
        candidate, skip_reason = _safe_network_discovery_candidate(
            method=method,
            url=url,
            resource_type=resource_type,
            source_url=source_url,
            root_origin=root_origin,
            credential_header_present=credential_header_present,
        )
        with self._lock:
            if skip_reason is not None:
                self._skipped_counts[skip_reason] = (
                    self._skipped_counts.get(skip_reason, 0) + 1
                )
                return
            if candidate is None or candidate.id in self._candidates:
                return
            if len(self._candidates) >= self._candidate_limit:
                self._overflow_count += 1
                return
            self._candidates[candidate.id] = candidate

    def record_blocked_post_json(
        self,
        *,
        method: str,
        url: str,
        resource_type: str,
        source_url: str,
        root_origin: tuple[str, str, int],
        content_type: str | None,
        credential_header_present: bool,
        headers_available: bool,
        body: bytes | None,
    ) -> None:
        try:
            canonical_source = _query_free_network_url(
                source_url,
                root_origin=root_origin,
            )
        except (DynamicBrowserError, ValueError):
            return
        if not headers_available:
            candidate = None
            replay_material = None
            skip_reason = PostJsonSkipReason.HEADER_UNAVAILABLE
        else:
            candidate, replay_material, skip_reason = _safe_blocked_post_json_candidate(
                method=method,
                url=url,
                resource_type=resource_type,
                source_url=canonical_source,
                root_origin=root_origin,
                content_type=content_type,
                credential_header_present=credential_header_present,
                body=body,
            )
        with self._lock:
            if skip_reason is not None:
                key = (canonical_source, skip_reason)
                self._post_json_skipped_counts[key] = (
                    self._post_json_skipped_counts.get(key, 0) + 1
                )
                return
            if candidate is None:
                return
            current = self._post_json_candidates.get(candidate.id)
            if current is not None:
                chosen = max(
                    (current, candidate),
                    key=lambda item: _post_policy_precedence(item.replay_policy),
                )
                self._post_json_candidates[candidate.id] = chosen
                if (
                    chosen.replay_policy.disposition
                    != PostReplayDisposition.SAFE_FOR_PROBE
                ):
                    self._post_json_replay_materials.pop(candidate.id, None)
                elif candidate is chosen and replay_material is not None:
                    self._post_json_replay_materials[candidate.id] = replay_material
                return
            if len(self._post_json_candidates) >= self._candidate_limit:
                overflow_reason = PostJsonSkipReason.CANDIDATE_LIMIT_EXCEEDED
                overflow_sources = {
                    canonical_source,
                    *(item.source_url for item in self._post_json_candidates.values()),
                    *(
                        source
                        for source, reason in self._post_json_skipped_counts
                        if reason == overflow_reason
                    ),
                }
                for key in tuple(self._post_json_skipped_counts):
                    if key[1] == overflow_reason:
                        del self._post_json_skipped_counts[key]
                self._post_json_skipped_counts[
                    (min(overflow_sources), overflow_reason)
                ] = 1
                largest_id = max(self._post_json_candidates)
                if candidate.id >= largest_id:
                    return
                del self._post_json_candidates[largest_id]
                self._post_json_replay_materials.pop(largest_id, None)
            self._post_json_candidates[candidate.id] = candidate
            if replay_material is not None:
                self._post_json_replay_materials[candidate.id] = replay_material

    def snapshot(self) -> NetworkDiscoveryCollection:
        with self._lock:
            return NetworkDiscoveryCollection(
                candidates=tuple(self._candidates.values()),
                skipped_counts=tuple(self._skipped_counts.items()),
                overflow_count=self._overflow_count,
                post_json_candidates=tuple(self._post_json_candidates.values()),
                post_json_replay_materials=tuple(
                    self._post_json_replay_materials.items()
                ),
                post_json_skipped_counts=tuple(
                    (source, reason, count)
                    for (source, reason), count in (
                        self._post_json_skipped_counts.items()
                    )
                ),
            )


class _AuditRecorder:
    def __init__(self, *, event_limit: int) -> None:
        self._event_limit = event_limit
        self._lock = Lock()
        self.playwright_started = 0
        self.playwright_stopped = 0
        self.browsers_launched = 0
        self.browsers_closed = 0
        self.contexts_created = 0
        self.contexts_closed = 0
        self.pages_created = 0
        self.pages_closed = 0
        self.popup_attempt_count = 0
        self.http_allowed_count = 0
        self.http_blocked_count = 0
        self.main_frame_navigation_allowed_count = 0
        self.main_frame_navigation_blocked_count = 0
        self.eventsource_attempt_count = 0
        self.eventsource_blocked_count = 0
        self.eventsource_allowed_count = 0
        self.websocket_attempt_count = 0
        self.websocket_blocked_count = 0
        self.websocket_connected_count = 0
        self.child_frame_attach_attempt_count = 0
        self.child_frame_document_request_count = 0
        self.child_frame_document_blocked_count = 0
        self.child_frame_commit_count = 0
        self.child_frame_authorized_commit_count = 0
        self.child_frame_unauthorized_commit_count = 0
        self.child_frame_internal_commit_count = 0
        self.child_frame_about_blank_commit_count = 0
        self.child_frame_browser_error_commit_count = 0
        self.child_frame_replacement_commit_count = 0
        self.child_frame_completion_count = 0
        self.child_frame_authorized_completion_count = 0
        self.child_frame_unauthorized_completion_count = 0
        self.child_frame_internal_completion_count = 0
        self.child_frame_about_blank_completion_count = 0
        self.child_frame_browser_error_completion_count = 0
        self.child_frame_replacement_completion_count = 0
        self.child_frame_commit_overflow_count = 0
        self.child_frame_completion_overflow_count = 0
        self.child_frame_detach_count = 0
        self.redirect_attempt_count = 0
        self.redirect_allowed_count = 0
        self.redirect_block_count = 0
        self.redirect_followed_count = 0
        self.request_decision_overflow_count = 0
        self.network_observation_overflow_count = 0
        self._events: list[BrowserAuditEvent] = []
        self._child_frame_commit_kinds: list[ChildFrameDocumentKind] = []
        self._child_frame_completion_kinds: list[ChildFrameDocumentKind] = []
        self._network_observations: dict[
            tuple[object, ...], tuple[PassiveNetworkObservation, int]
        ] = {}

    def record_http(
        self,
        decision: DynamicNetworkDecision,
        *,
        url: str,
        is_child_frame_document: bool,
        is_redirect: bool,
    ) -> None:
        with self._lock:
            if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                self.http_allowed_count += 1
            else:
                self.http_blocked_count += 1
            if decision.resource_kind == "eventsource":
                self.eventsource_attempt_count += 1
                if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                    self.eventsource_allowed_count += 1
                else:
                    self.eventsource_blocked_count += 1
            if is_child_frame_document:
                self.child_frame_document_request_count += 1
                if decision.decision == DynamicNetworkDecisionKind.BLOCK:
                    self.child_frame_document_blocked_count += 1
            if is_redirect:
                self.redirect_attempt_count += 1
                if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                    self.redirect_allowed_count += 1
                else:
                    self.redirect_block_count += 1
            self._append_event(
                _safe_audit_event(
                    url=url,
                    resource_kind=decision.resource_kind,
                    decision=decision.decision,
                    reason=decision.reason,
                )
            )

    def record_popup(self) -> None:
        with self._lock:
            self.popup_attempt_count += 1

    def record_main_frame_navigation(
        self,
        decision: DynamicNetworkDecision,
    ) -> None:
        with self._lock:
            if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                self.main_frame_navigation_allowed_count += 1
            else:
                self.main_frame_navigation_blocked_count += 1

    def record_redirect_followed(self) -> None:
        with self._lock:
            self.redirect_followed_count += 1

    def record_child_frame_attach(self) -> None:
        with self._lock:
            self.child_frame_attach_attempt_count += 1

    def record_child_frame_commit(
        self,
        classification: ChildFrameDocumentKind,
    ) -> None:
        with self._lock:
            classification = ChildFrameDocumentKind(classification)
            self.child_frame_commit_count += 1
            if classification == ChildFrameDocumentKind.AUTHORIZED:
                self.child_frame_authorized_commit_count += 1
            elif classification == ChildFrameDocumentKind.UNAUTHORIZED:
                self.child_frame_unauthorized_commit_count += 1
            else:
                self.child_frame_internal_commit_count += 1
                if classification == ChildFrameDocumentKind.ABOUT_BLANK:
                    self.child_frame_about_blank_commit_count += 1
                elif classification == ChildFrameDocumentKind.BROWSER_ERROR:
                    self.child_frame_browser_error_commit_count += 1
                else:
                    self.child_frame_replacement_commit_count += 1
            if len(self._child_frame_commit_kinds) < self._event_limit:
                self._child_frame_commit_kinds.append(classification)
            else:
                self.child_frame_commit_overflow_count += 1

    def record_child_frame_detach(self) -> None:
        with self._lock:
            self.child_frame_detach_count += 1

    def record_child_frame_completion(
        self,
        classification: ChildFrameDocumentKind,
    ) -> None:
        with self._lock:
            classification = ChildFrameDocumentKind(classification)
            self.child_frame_completion_count += 1
            if classification == ChildFrameDocumentKind.AUTHORIZED:
                self.child_frame_authorized_completion_count += 1
            elif classification == ChildFrameDocumentKind.UNAUTHORIZED:
                self.child_frame_unauthorized_completion_count += 1
            else:
                self.child_frame_internal_completion_count += 1
                if classification == ChildFrameDocumentKind.ABOUT_BLANK:
                    self.child_frame_about_blank_completion_count += 1
                elif classification == ChildFrameDocumentKind.BROWSER_ERROR:
                    self.child_frame_browser_error_completion_count += 1
                else:
                    self.child_frame_replacement_completion_count += 1
            if len(self._child_frame_completion_kinds) < self._event_limit:
                self._child_frame_completion_kinds.append(classification)
            else:
                self.child_frame_completion_overflow_count += 1

    def record_websocket(
        self,
        *,
        url: str,
        reason: DynamicNetworkReason,
    ) -> None:
        with self._lock:
            self.websocket_attempt_count += 1
            self.websocket_blocked_count += 1
            self._append_event(
                _safe_audit_event(
                    url=url,
                    resource_kind="websocket",
                    decision=DynamicNetworkDecisionKind.BLOCK,
                    reason=reason,
                )
            )

    def record_network_observation(
        self,
        observation: PassiveNetworkObservation,
    ) -> None:
        key = _passive_network_observation_key(observation)
        with self._lock:
            current = self._network_observations.get(key)
            if current is not None:
                self._network_observations[key] = (current[0], current[1] + 1)
                return
            if len(self._network_observations) >= self._event_limit:
                self.network_observation_overflow_count += 1
                return
            self._network_observations[key] = (observation, 1)

    def _append_event(self, event: BrowserAuditEvent) -> None:
        if len(self._events) < self._event_limit:
            self._events.append(event)
        else:
            self.request_decision_overflow_count += 1

    def snapshot(self, cleanup_error_codes: tuple[str, ...]) -> BrowserAuditSummary:
        with self._lock:
            cleanup_complete = (
                not cleanup_error_codes
                and self.playwright_started == self.playwright_stopped
                and self.browsers_launched == self.browsers_closed
                and self.contexts_created == self.contexts_closed
                and self.pages_created == self.pages_closed
            )
            return BrowserAuditSummary(
                playwright_started=self.playwright_started,
                playwright_stopped=self.playwright_stopped,
                browsers_launched=self.browsers_launched,
                browsers_closed=self.browsers_closed,
                contexts_created=self.contexts_created,
                contexts_closed=self.contexts_closed,
                pages_created=self.pages_created,
                pages_closed=self.pages_closed,
                popup_attempt_count=self.popup_attempt_count,
                http_allowed_count=self.http_allowed_count,
                http_blocked_count=self.http_blocked_count,
                main_frame_navigation_allowed_count=(
                    self.main_frame_navigation_allowed_count
                ),
                main_frame_navigation_blocked_count=(
                    self.main_frame_navigation_blocked_count
                ),
                eventsource_attempt_count=self.eventsource_attempt_count,
                eventsource_blocked_count=self.eventsource_blocked_count,
                eventsource_allowed_count=self.eventsource_allowed_count,
                websocket_attempt_count=self.websocket_attempt_count,
                websocket_blocked_count=self.websocket_blocked_count,
                websocket_connected_count=self.websocket_connected_count,
                child_frame_attach_attempt_count=(
                    self.child_frame_attach_attempt_count
                ),
                child_frame_document_request_count=(
                    self.child_frame_document_request_count
                ),
                child_frame_document_blocked_count=(
                    self.child_frame_document_blocked_count
                ),
                child_frame_commit_count=self.child_frame_commit_count,
                child_frame_authorized_commit_count=(
                    self.child_frame_authorized_commit_count
                ),
                child_frame_unauthorized_commit_count=(
                    self.child_frame_unauthorized_commit_count
                ),
                child_frame_internal_commit_count=(
                    self.child_frame_internal_commit_count
                ),
                child_frame_about_blank_commit_count=(
                    self.child_frame_about_blank_commit_count
                ),
                child_frame_browser_error_commit_count=(
                    self.child_frame_browser_error_commit_count
                ),
                child_frame_replacement_commit_count=(
                    self.child_frame_replacement_commit_count
                ),
                child_frame_completion_count=self.child_frame_completion_count,
                child_frame_authorized_completion_count=(
                    self.child_frame_authorized_completion_count
                ),
                child_frame_unauthorized_completion_count=(
                    self.child_frame_unauthorized_completion_count
                ),
                child_frame_internal_completion_count=(
                    self.child_frame_internal_completion_count
                ),
                child_frame_about_blank_completion_count=(
                    self.child_frame_about_blank_completion_count
                ),
                child_frame_browser_error_completion_count=(
                    self.child_frame_browser_error_completion_count
                ),
                child_frame_replacement_completion_count=(
                    self.child_frame_replacement_completion_count
                ),
                child_frame_commit_kinds=tuple(self._child_frame_commit_kinds),
                child_frame_completion_kinds=tuple(
                    self._child_frame_completion_kinds
                ),
                child_frame_commit_overflow_count=(
                    self.child_frame_commit_overflow_count
                ),
                child_frame_completion_overflow_count=(
                    self.child_frame_completion_overflow_count
                ),
                child_frame_detach_count=self.child_frame_detach_count,
                redirect_attempt_count=self.redirect_attempt_count,
                redirect_allowed_count=self.redirect_allowed_count,
                redirect_block_count=self.redirect_block_count,
                redirect_followed_count=self.redirect_followed_count,
                request_decision_overflow_count=(
                    self.request_decision_overflow_count
                ),
                cleanup_error_codes=cleanup_error_codes,
                cleanup_complete=cleanup_complete,
                events=tuple(self._events),
                network_observations=tuple(
                    PassiveNetworkObservation(
                        method=observation.method,
                        resource_type=observation.resource_type,
                        scheme=observation.scheme,
                        host=observation.host,
                        effective_port=observation.effective_port,
                        path_fingerprint=observation.path_fingerprint,
                        path_segment_count=observation.path_segment_count,
                        query_parameter_names=observation.query_parameter_names,
                        scope=observation.scope,
                        occurrence_count=occurrence_count,
                    )
                    for observation, occurrence_count in sorted(
                        self._network_observations.values(),
                        key=lambda item: _passive_network_observation_key(item[0]),
                    )
                ),
                network_observation_overflow_count=(
                    self.network_observation_overflow_count
                ),
            )


class _RouteGuard:
    def __init__(
        self,
        authority: DynamicRequestAuthority,
        policy: DynamicBrowserPolicy,
        audit: _AuditRecorder,
        stop_active_page: Callable[[], None],
        provider_timeout_error: type[Exception] = TimeoutError,
        network_discovery: _NetworkDiscoveryRecorder | None = None,
    ) -> None:
        self.authority = authority
        self.policy = policy
        self.audit = audit
        self.stop_active_page = stop_active_page
        self.provider_timeout_error = provider_timeout_error
        self.network_discovery = network_discovery or _NetworkDiscoveryRecorder(
            candidate_limit=policy.request_decision_budget
        )
        self._root_origin = _origin(authority.root_url)
        self.primary_page: Any | None = None
        self.decision_count = 0
        self._decision_lock = Lock()
        self._budget_exhausted = False
        self._navigation_budget_exhausted = False
        self._navigation_request_count = 0
        self._redirect_count = 0
        self._dispatched_main_frame_urls: set[str] = set()
        self._pending_redirect_target: str | None = None
        self._rendered_navigation_url: str | None = None
        self._redirect_duplicate = False
        self._request_failure: DynamicBrowserError | None = None

    def set_primary_page(self, page: Any) -> None:
        self.primary_page = page

    def begin_navigation(self, rendered_navigation_url: str | None = None) -> None:
        with self._decision_lock:
            self._redirect_count = 0
            self._pending_redirect_target = None
            self._redirect_duplicate = False
            self._rendered_navigation_url = rendered_navigation_url

    def handle_http(self, route: Any, request: Any) -> None:
        url = _safe_provider_text(request, "url")
        resource_type = _safe_provider_text(request, "resource_type")
        method = _safe_provider_text(request, "method")
        is_primary_page, is_main_frame = self._frame_state(request)
        is_child_frame_document = (
            resource_type.strip().lower() == "document" and not is_main_frame
        )
        within_budget, first_exhaustion, should_record = (
            self._reserve_transport_decision()
        )
        if not within_budget:
            decision = DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.REQUEST_DECISION_BUDGET_EXHAUSTED,
                None,
                resource_type,
            )
        else:
            decision = self.authority.decide_http(
                method=method,
                url=url,
                resource_type=resource_type,
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
            )
            if (
                is_primary_page
                and is_main_frame
                and resource_type.strip().lower() == "document"
                and decision.decision == DynamicNetworkDecisionKind.BLOCK
                and decision.reason == DynamicNetworkReason.REQUEST_NOT_AUTHORIZED
                and decision.canonical_url == self._rendered_navigation_url
            ):
                decision = DynamicNetworkDecision(
                    DynamicNetworkDecisionKind.ALLOW,
                    DynamicNetworkReason.AUTHORIZED_NAVIGATION,
                    decision.canonical_url,
                    resource_type.strip().lower(),
                )
        navigation_budget_first_exhaustion = False
        is_main_frame_document = (
            is_primary_page
            and is_main_frame
            and resource_type.strip().lower() == "document"
        )
        if (
            within_budget
            and is_main_frame_document
            and decision.decision == DynamicNetworkDecisionKind.ALLOW
        ):
            (
                navigation_within_budget,
                navigation_budget_first_exhaustion,
            ) = self._reserve_navigation_request()
            if not navigation_within_budget:
                decision = DynamicNetworkDecision(
                    DynamicNetworkDecisionKind.BLOCK,
                    DynamicNetworkReason.NAVIGATION_BUDGET_EXHAUSTED,
                    decision.canonical_url,
                    resource_type,
                )
        if (
            decision.decision == DynamicNetworkDecisionKind.ALLOW
            and method.upper() == "GET"
            and resource_type.strip().lower() in {"fetch", "xhr"}
            and is_primary_page
        ):
            self.network_discovery.record_allowed_get(
                method=method,
                url=url,
                resource_type=resource_type,
                source_url=self._network_source_url(),
                root_origin=self._root_origin,
                credential_header_present=_request_has_credential_headers(request),
            )
        if (
            within_budget
            and decision.decision == DynamicNetworkDecisionKind.BLOCK
            and decision.reason == DynamicNetworkReason.NON_GET_METHOD
            and decision.canonical_url is not None
            and _origin(decision.canonical_url) == self._root_origin
            and method == "POST"
            and resource_type.strip().lower() in {"fetch", "xhr"}
            and is_primary_page
        ):
            (
                content_type,
                credential_header_present,
                headers_available,
            ) = _request_json_header_projection(request)
            if (
                headers_available
                and type(content_type) is str
                and _application_json_content_type(content_type)
            ):
                body = _request_post_data_buffer(request)
                self.network_discovery.record_blocked_post_json(
                    method=method,
                    url=url,
                    resource_type=resource_type,
                    source_url=self._network_source_url(),
                    root_origin=self._root_origin,
                    content_type=content_type,
                    credential_header_present=credential_header_present,
                    headers_available=True,
                    body=body,
                )
        if should_record:
            self.audit.record_http(
                decision,
                url=url,
                is_child_frame_document=is_child_frame_document,
                is_redirect=False,
            )
        follows_redirect = False
        if is_main_frame_document:
            follows_redirect = self._take_pending_redirect_target(url, decision)
            self.audit.record_main_frame_navigation(decision)
            if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                self._record_dispatched_main_frame_url(decision.canonical_url)
        if decision.decision == DynamicNetworkDecisionKind.ALLOW:
            self._fulfill_allowed_http(
                route,
                decision,
                method=method,
                resource_type=resource_type,
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
                follows_redirect=follows_redirect,
            )
        else:
            if within_budget:
                self._set_navigation_failure(
                    is_primary_page=is_primary_page,
                    is_main_frame=is_main_frame,
                    is_document=resource_type.strip().lower() == "document",
                    reason=decision.reason,
                )
            self._abort_route(route)
        if first_exhaustion:
            self.stop_active_page()
        if navigation_budget_first_exhaustion:
            self.stop_active_page()

    def _network_source_url(self) -> str:
        raw_url = _safe_provider_text(self.primary_page, "url")
        for candidate in (raw_url, self.authority.root_url):
            try:
                return _query_free_network_url(
                    candidate,
                    root_origin=self._root_origin,
                )
            except (DynamicBrowserError, ValueError):
                continue
        return self.authority.root_url

    def _fulfill_allowed_http(
        self,
        route: Any,
        decision: DynamicNetworkDecision,
        *,
        method: str,
        resource_type: str,
        is_primary_page: bool,
        is_main_frame: bool,
        follows_redirect: bool = False,
    ) -> None:
        current_url = decision.canonical_url
        response: Any | None = None
        is_document_navigation = (
            is_primary_page
            and is_main_frame
            and resource_type.strip().lower() == "document"
        )
        try:
            while current_url is not None:
                timeout_ms = self._remaining_transport_timeout_ms()
                if timeout_ms <= 0:
                    self._set_navigation_failure(
                        is_primary_page=is_primary_page,
                        is_main_frame=is_main_frame,
                        is_document=is_document_navigation,
                        timeout=True,
                    )
                    self._abort_route(route)
                    return
                response = route.fetch(
                    url=current_url,
                    max_redirects=0,
                    timeout=timeout_ms,
                )
                if follows_redirect:
                    self.audit.record_redirect_followed()
                    follows_redirect = False
                redirect_url = _response_redirect_target(
                    response,
                    current_url=current_url,
                )
                if redirect_url is None:
                    route.fulfill(response=response)
                    return
                response_disposed = _dispose_api_response(response)
                response = None
                if not response_disposed:
                    self._set_response_dispose_failure()
                    self._abort_route(route)
                    return

                within_budget, first_exhaustion, should_record = (
                    self._reserve_transport_decision()
                )
                if within_budget:
                    redirect_decision = self.authority.decide_http(
                        method=method,
                        url=redirect_url,
                        resource_type=resource_type,
                        is_primary_page=is_primary_page,
                        is_main_frame=is_main_frame,
                    )
                    if (
                        redirect_decision.decision
                        == DynamicNetworkDecisionKind.ALLOW
                        and is_document_navigation
                        and self._was_main_frame_url_dispatched(
                            redirect_decision.canonical_url
                        )
                    ):
                        redirect_decision = DynamicNetworkDecision(
                            DynamicNetworkDecisionKind.BLOCK,
                            DynamicNetworkReason.REDIRECT_DUPLICATE,
                            redirect_decision.canonical_url,
                            resource_type,
                        )
                    elif (
                        redirect_decision.decision
                        == DynamicNetworkDecisionKind.ALLOW
                        and not self._reserve_redirect_hop()
                    ):
                        redirect_decision = DynamicNetworkDecision(
                            DynamicNetworkDecisionKind.BLOCK,
                            DynamicNetworkReason.REDIRECT_BUDGET_EXHAUSTED,
                            redirect_decision.canonical_url,
                            resource_type,
                        )
                else:
                    redirect_decision = DynamicNetworkDecision(
                        DynamicNetworkDecisionKind.BLOCK,
                        DynamicNetworkReason.REQUEST_DECISION_BUDGET_EXHAUSTED,
                        None,
                        resource_type,
                    )
                if should_record:
                    self.audit.record_http(
                        redirect_decision,
                        url=redirect_url,
                        is_child_frame_document=False,
                        is_redirect=True,
                    )
                if (
                    redirect_decision.decision
                    == DynamicNetworkDecisionKind.BLOCK
                ):
                    if (
                        is_document_navigation
                        and redirect_decision.reason
                        == DynamicNetworkReason.REDIRECT_DUPLICATE
                    ):
                        self._set_redirect_duplicate()
                        route.fulfill(
                            status=200,
                            content_type="text/html; charset=utf-8",
                            body="<!doctype html><title>duplicate redirect</title>",
                        )
                        return
                    if within_budget:
                        self._set_navigation_failure(
                            is_primary_page=is_primary_page,
                            is_main_frame=is_main_frame,
                            is_document=(
                                resource_type.strip().lower() == "document"
                            ),
                            reason=redirect_decision.reason,
                        )
                    self._abort_route(route)
                    if first_exhaustion:
                        self.stop_active_page()
                    return
                current_url = redirect_decision.canonical_url
                if is_document_navigation and current_url is not None:
                    self._set_pending_redirect_target(current_url)
                    route.fulfill(
                        status=200,
                        content_type="text/html; charset=utf-8",
                        body=_redirect_relocation_document(current_url),
                    )
                    return
        except self.provider_timeout_error:
            self._set_navigation_failure(
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
                is_document=resource_type.strip().lower() == "document",
                timeout=True,
            )
            self._abort_route(route)
        except Exception:  # noqa: BLE001 - provider details remain private.
            self._set_navigation_failure(
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
                is_document=resource_type.strip().lower() == "document",
            )
            self._abort_route(route)
        finally:
            if not _dispose_api_response(response):
                self._set_response_dispose_failure()

    def _set_navigation_failure(
        self,
        *,
        is_primary_page: bool,
        is_main_frame: bool,
        is_document: bool,
        timeout: bool = False,
        reason: DynamicNetworkReason | None = None,
    ) -> None:
        if not (is_primary_page and is_main_frame and is_document):
            return
        if timeout:
            code = DynamicBrowserErrorCode.NAVIGATION_TIMEOUT
            message = "Authorized browser navigation timed out."
        elif reason == DynamicNetworkReason.NAVIGATION_BUDGET_EXHAUSTED:
            code = DynamicBrowserErrorCode.NAVIGATION_BUDGET_EXHAUSTED
            message = "Main-frame navigation budget was exhausted."
        elif reason == DynamicNetworkReason.REDIRECT_BUDGET_EXHAUSTED:
            code = DynamicBrowserErrorCode.REDIRECT_BUDGET_EXHAUSTED
            message = "Per-navigation redirect budget was exhausted."
        else:
            code = DynamicBrowserErrorCode.NAVIGATION_FAILED
            message = "Authorized browser navigation failed."
        with self._decision_lock:
            if self._request_failure is None:
                self._request_failure = DynamicBrowserError(code, message)

    def _set_response_dispose_failure(self) -> None:
        with self._decision_lock:
            if self._request_failure is None:
                self._request_failure = DynamicBrowserError(
                    DynamicBrowserErrorCode.HTTP_RESPONSE_DISPOSE_FAILED,
                    "Intercepted browser response cleanup did not complete.",
                )

    @staticmethod
    def _abort_route(route: Any) -> None:
        try:
            route.abort(error_code="blockedbyclient")
        except Exception:  # noqa: BLE001 - the page may already be closing.
            return

    def handle_websocket(self, websocket_route: Any) -> None:
        url = _safe_provider_text(websocket_route, "url")
        within_budget, first_exhaustion, should_record = (
            self._reserve_transport_decision()
        )
        reason = (
            DynamicNetworkReason.WEBSOCKET_DENIED
            if within_budget
            else DynamicNetworkReason.REQUEST_DECISION_BUDGET_EXHAUSTED
        )
        if should_record:
            self.audit.record_websocket(url=url, reason=reason)
        # Routed WebSockets do not contact the server unless the handler calls
        # connect_to_server(). Returning here is therefore the synchronous,
        # pre-transport denial path and avoids creating any server connection.
        if first_exhaustion:
            self.stop_active_page()

    def _reserve_transport_decision(self) -> tuple[bool, bool, bool]:
        with self._decision_lock:
            if self._budget_exhausted:
                return False, False, False
            self.decision_count += 1
            within_budget = (
                self.decision_count <= self.policy.request_decision_budget
            )
            if not within_budget:
                self._budget_exhausted = True
            return within_budget, not within_budget, True

    def _reserve_navigation_request(self) -> tuple[bool, bool]:
        with self._decision_lock:
            if (
                self._navigation_request_count
                < self.policy.navigation_request_budget
            ):
                self._navigation_request_count += 1
                return True, False
            first_exhaustion = not self._navigation_budget_exhausted
            self._navigation_budget_exhausted = True
            return False, first_exhaustion

    def _reserve_redirect_hop(self) -> bool:
        with self._decision_lock:
            if self._redirect_count >= self.policy.max_redirects_per_navigation:
                return False
            self._redirect_count += 1
            return True

    def _remaining_transport_timeout_ms(self) -> float:
        timeout_seconds = self.policy.navigation_timeout_seconds
        deadline = self.policy.deadline_monotonic
        if deadline is not None:
            timeout_seconds = min(timeout_seconds, deadline - monotonic())
        return max(0.0, timeout_seconds * 1000.0)

    def _record_dispatched_main_frame_url(self, url: str | None) -> None:
        if url is None:
            return
        with self._decision_lock:
            self._dispatched_main_frame_urls.add(url)

    def _was_main_frame_url_dispatched(self, url: str | None) -> bool:
        if url is None:
            return False
        with self._decision_lock:
            return url in self._dispatched_main_frame_urls

    def _set_pending_redirect_target(self, url: str) -> None:
        with self._decision_lock:
            self._pending_redirect_target = url

    def _take_pending_redirect_target(
        self,
        raw_url: str,
        decision: DynamicNetworkDecision,
    ) -> bool:
        try:
            canonical_url = _canonical_request_url(raw_url)
        except DynamicBrowserError:
            canonical_url = None
        with self._decision_lock:
            if (
                self._pending_redirect_target is not None
                and canonical_url == self._pending_redirect_target
            ):
                followed = decision.decision == DynamicNetworkDecisionKind.ALLOW
                self._pending_redirect_target = None
                return followed
        return False

    def _set_redirect_duplicate(self) -> None:
        with self._decision_lock:
            self._redirect_duplicate = True
            self._pending_redirect_target = None

    def take_redirect_duplicate(self) -> bool:
        with self._decision_lock:
            duplicate = self._redirect_duplicate
            self._redirect_duplicate = False
            return duplicate

    def raise_if_budget_exhausted(self) -> None:
        with self._decision_lock:
            exhausted = self._budget_exhausted
        if exhausted:
            _raise_request_decision_budget_exhausted()

    def raise_if_failed(self) -> None:
        self.raise_if_budget_exhausted()
        with self._decision_lock:
            request_failure = self._request_failure
        if request_failure is not None:
            raise request_failure

    def _frame_state(self, request: Any) -> tuple[bool, bool]:
        try:
            frame = request.frame
            page = frame.page
            return page is self.primary_page, frame.parent_frame is None
        except Exception:  # noqa: BLE001 - fail closed on provider ambiguity.
            return False, False


def _safe_provider_text(provider: Any, attribute: str) -> str:
    try:
        value = getattr(provider, attribute)
        if callable(value):
            value = value()
    except Exception:  # noqa: BLE001 - fail closed without provider details.
        return ""
    return value if type(value) is str else ""


def _response_redirect_target(
    response: Any,
    *,
    current_url: str,
) -> str | None:
    try:
        status = response.status
        if callable(status):
            status = status()
        headers = response.headers
        if callable(headers):
            headers = headers()
    except Exception:  # noqa: BLE001 - fail closed without provider details.
        raise ValueError("redirect response metadata is unavailable") from None
    if type(status) is not int or not isinstance(headers, dict):
        raise ValueError("redirect response metadata is invalid")
    if status not in _REDIRECT_STATUS_CODES:
        return None
    location_values = tuple(
        value
        for key, value in headers.items()
        if type(key) is str and key.lower() == "location"
    )
    if not location_values:
        return None
    location = location_values[0]
    if type(location) is not str or not location:
        raise ValueError("redirect location is invalid")
    return urljoin(current_url, location)


def _redirect_relocation_document(url: str) -> str:
    encoded_url = (
        json.dumps(url, ensure_ascii=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    return (
        "<!doctype html><meta charset=\"utf-8\">"
        f"<script>window.location.replace({encoded_url});</script>"
    )


def _dispose_api_response(response: Any | None) -> bool:
    if response is None:
        return True
    try:
        response.dispose()
    except Exception:  # noqa: BLE001 - cleanup remains best effort and local.
        return False
    return True


def _raise_request_decision_budget_exhausted() -> None:
    raise DynamicBrowserError(
        DynamicBrowserErrorCode.REQUEST_DECISION_BUDGET_EXHAUSTED,
        "Browser transport decision budget was exhausted.",
    )


class _PageLifecycleObserver:
    def __init__(
        self,
        authority: DynamicRequestAuthority,
        audit: _AuditRecorder,
    ) -> None:
        self.authority = authority
        self.audit = audit

    def install(self, page: Any) -> None:
        page.on("frameattached", self.handle_frame_attached)
        page.on("framenavigated", self.handle_frame_navigated)
        page.on("framedetached", self.handle_frame_detached)
        page.on("requestfinished", self.handle_request_finished)

    def handle_frame_attached(self, frame: Any) -> None:
        if _is_child_frame(frame):
            self.audit.record_child_frame_attach()

    def handle_frame_navigated(self, frame: Any) -> None:
        if not _is_child_frame(frame):
            return
        url = _safe_provider_text(frame, "url")
        self.audit.record_child_frame_commit(
            _classify_child_frame_commit(url, self.authority)
        )

    def handle_frame_detached(self, frame: Any) -> None:
        if _is_child_frame(frame):
            self.audit.record_child_frame_detach()

    def handle_request_finished(self, request: Any) -> None:
        if _safe_provider_text(request, "resource_type").lower() != "document":
            return
        try:
            frame = request.frame
            if callable(frame):
                frame = frame()
        except Exception:  # noqa: BLE001 - ambiguous requests are not classified.
            return
        if _is_child_frame(frame):
            self.audit.record_child_frame_completion(
                _classify_child_frame_commit(
                    _safe_provider_text(frame, "url"),
                    self.authority,
                )
            )


class _PassiveNetworkObserver:
    """Read-only BrowserContext listener for safe fetch/XHR attempt evidence."""

    def __init__(
        self,
        authority: DynamicRequestAuthority,
        audit: _AuditRecorder,
    ) -> None:
        self._root_origin = _origin(authority.root_url)
        self._audit = audit

    def install(self, context: Any) -> None:
        context.on("request", self.handle_request)

    def handle_request(self, request: Any) -> None:
        try:
            observation = _safe_passive_network_observation(
                method=_safe_provider_text(request, "method"),
                url=_safe_provider_text(request, "url"),
                resource_type=_safe_provider_text(request, "resource_type"),
                root_origin=self._root_origin,
            )
            if observation is not None:
                self._audit.record_network_observation(observation)
        except Exception:  # noqa: BLE001 - passive observation cannot block Guard.
            return


def _is_child_frame(frame: Any) -> bool:
    try:
        parent = frame.parent_frame
        if callable(parent):
            parent = parent()
    except Exception:  # noqa: BLE001 - ambiguous frames are not classified.
        return False
    return parent is not None


def _classify_child_frame_commit(
    url: str,
    authority: DynamicRequestAuthority,
) -> ChildFrameDocumentKind:
    if url == "about:blank":
        return ChildFrameDocumentKind.ABOUT_BLANK
    scheme = _safe_scheme(url)
    if scheme in {"chrome-error", "edge-error"}:
        return ChildFrameDocumentKind.BROWSER_ERROR
    if scheme not in _HTTP_SCHEMES:
        return ChildFrameDocumentKind.REPLACEMENT
    if authority.allows_navigation(url):
        return ChildFrameDocumentKind.AUTHORIZED
    return ChildFrameDocumentKind.UNAUTHORIZED


@dataclass(slots=True)
class _ManagedResources:
    audit: _AuditRecorder
    playwright: Any | None = None
    browser: Any | None = None
    context: Any | None = None
    page: Any | None = None
    popup_pages: list[Any] = field(default_factory=list)
    _closed: bool = False
    _page_close_attempted: bool = False
    _page_cleanup_errors: tuple[str, ...] = ()
    _page_stop_requested: bool = False
    _cleanup_errors: tuple[str, ...] = ()

    def request_page_stop(self) -> None:
        self._page_stop_requested = True

    def add_popup_page(self, page: Any) -> None:
        self.popup_pages.append(page)
        self.audit.pages_created += 1
        self.audit.record_popup()

    def close_requested_page(self) -> tuple[str, ...]:
        if not self._page_stop_requested:
            return ()
        return self.close_page()

    def close_page(self) -> tuple[str, ...]:
        if self.page is None or self._page_close_attempted:
            return self._page_cleanup_errors
        self._page_close_attempted = True
        errors: list[str] = []
        self._close_one(
            self.page,
            "PAGE_CLOSE_FAILED",
            lambda: setattr(
                self.audit,
                "pages_closed",
                self.audit.pages_closed + 1,
            ),
            errors,
        )
        self._page_cleanup_errors = tuple(errors)
        return self._page_cleanup_errors

    def close(self) -> tuple[str, ...]:
        if self._closed:
            return self._cleanup_errors
        self._closed = True
        errors: list[str] = []
        for popup in reversed(self.popup_pages):
            self._close_one(
                popup,
                "POPUP_PAGE_CLOSE_FAILED",
                lambda: setattr(
                    self.audit,
                    "pages_closed",
                    self.audit.pages_closed + 1,
                ),
                errors,
            )
        self.close_page()
        errors.extend(self._page_cleanup_errors)
        self._close_one(
            self.context,
            "CONTEXT_CLOSE_FAILED",
            lambda: setattr(
                self.audit,
                "contexts_closed",
                self.audit.contexts_closed + 1,
            ),
            errors,
        )
        self._close_one(
            self.browser,
            "BROWSER_CLOSE_FAILED",
            lambda: setattr(
                self.audit,
                "browsers_closed",
                self.audit.browsers_closed + 1,
            ),
            errors,
        )
        self._close_one(
            self.playwright,
            "PLAYWRIGHT_STOP_FAILED",
            lambda: setattr(
                self.audit,
                "playwright_stopped",
                self.audit.playwright_stopped + 1,
            ),
            errors,
            method_name="stop",
        )
        self._cleanup_errors = tuple(errors)
        return self._cleanup_errors

    @staticmethod
    def _close_one(
        resource: Any | None,
        error_code: str,
        on_success: Callable[[], None],
        errors: list[str],
        *,
        method_name: str = "close",
    ) -> None:
        if resource is None:
            return
        try:
            getattr(resource, method_name)()
        except Exception:  # noqa: BLE001 - retain only stable cleanup code.
            errors.append(error_code)
        else:
            on_success()


class _PlaywrightDynamicSession:
    def __init__(
        self,
        *,
        page: Any,
        context: Any,
        authority: DynamicRequestAuthority,
        policy: DynamicBrowserPolicy,
        provider_timeout_error: type[Exception],
        guard: _RouteGuard,
        close_page: Callable[[], tuple[str, ...]],
    ) -> None:
        self._page = page
        self._context = context
        self._authority = authority
        self._policy = policy
        self._provider_timeout_error = provider_timeout_error
        self._guard = guard
        self._close_page = close_page
        self._last_navigation_status: int | None = None

    def navigate(
        self,
        url: str | None = None,
        *,
        timeout_seconds: float | None = None,
        rendered_navigation: bool = False,
    ) -> str:
        self._guard.raise_if_failed()
        target = self._authority.root_url if url is None else url
        if type(rendered_navigation) is not bool:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Rendered navigation marker must be a boolean.",
            )
        canonical = _canonical_request_url(target)
        exact_authority = self._authority.allows_navigation(canonical)
        rendered_authority = (
            rendered_navigation
            and self._authority.allows_rendered_navigation(canonical)
        )
        if not exact_authority and not rendered_authority:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.NAVIGATION_NOT_AUTHORIZED,
                "Navigation URL is not present in caller-owned authority.",
            )
        active_timeout = self._policy.navigation_timeout_seconds
        if timeout_seconds is not None:
            if (
                type(timeout_seconds) not in {int, float}
                or isinstance(timeout_seconds, bool)
                or timeout_seconds <= 0
            ):
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.OPERATION_FAILED,
                    "Navigation timeout override must be a positive number.",
                )
            active_timeout = min(active_timeout, float(timeout_seconds))
        self._last_navigation_status = None
        self._guard.begin_navigation(
            canonical if rendered_authority and not exact_authority else None
        )
        try:
            response = self._page.goto(
                canonical,
                wait_until="domcontentloaded",
                timeout=active_timeout * 1000,
            )
            self._guard.raise_if_failed()
            if self._guard.take_redirect_duplicate():
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.REDIRECT_DUPLICATE,
                    "Redirect target was already dispatched in this crawl.",
                )
            try:
                raw_status = None if response is None else response.status
            except Exception:  # noqa: BLE001 - status ambiguity remains private.
                raw_status = None
            if type(raw_status) is int and 100 <= raw_status <= 599:
                self._last_navigation_status = raw_status
            return _safe_provider_text(self._page, "url")
        except self._provider_timeout_error:
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.NAVIGATION_TIMEOUT,
                "Authorized browser navigation timed out.",
            ) from None
        except DynamicBrowserError:
            raise
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.NAVIGATION_FAILED,
                "Authorized browser navigation failed.",
            ) from None

    def navigation_status_code(self) -> int | None:
        return self._last_navigation_status

    def wait_for_selector(self, selector: str) -> None:
        self._guard.raise_if_failed()
        if type(selector) is not str or not selector:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Selector must not be empty.",
            )
        try:
            self._page.wait_for_selector(
                selector,
                timeout=self._policy.navigation_timeout_seconds * 1000,
            )
            self._guard.raise_if_failed()
        except self._provider_timeout_error:
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_TIMEOUT,
                "Bounded browser operation timed out.",
            ) from None
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Bounded browser operation failed.",
            ) from None

    def text_content(self, selector: str) -> str | None:
        self._guard.raise_if_failed()
        if type(selector) is not str or not selector:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Selector must not be empty.",
            )
        try:
            value = self._page.text_content(selector)
            self._guard.raise_if_failed()
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Bounded browser operation failed.",
            ) from None
        return value if value is None or type(value) is str else str(value)

    def perform_safe_route_actions(
        self,
        max_actions: int,
        *,
        marker: str = "vulnspider-probe",
    ) -> int:
        self._guard.raise_if_failed()
        if type(max_actions) is not int or max_actions < 0:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Route action budget must be a non-negative integer.",
            )
        if type(marker) is not str or not marker or len(marker) > 128:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Route action marker must be a short non-empty string.",
            )
        if max_actions == 0:
            return 0
        script = r"""
        async ({maxActions, marker}) => {
          const tokens = ["search", "find", "filter", "query"];
          const text = (el) => [
            el.getAttribute("type"), el.getAttribute("name"),
            el.getAttribute("id"), el.getAttribute("placeholder"),
            el.getAttribute("aria-label"), el.getAttribute("role"),
            el.textContent
          ].filter(Boolean).join(" ").toLowerCase();
          const sensitive = (el) => {
            const form = el.closest("form");
            return !!(form && form.querySelector('input[type="password"]'));
          };
          const postForm = (el) => {
            const form = el.closest("form");
            if (!form) return false;
            const method = (form.getAttribute("method") || "get").trim().toLowerCase();
            return method !== "get";
          };
          const relevant = (el) => {
            const kind = (el.getAttribute("type") || "").toLowerCase();
            return kind === "search" || tokens.some((token) => text(el).includes(token));
          };
          let actions = 0;
          const inputs = Array.from(document.querySelectorAll(
            'input:not([disabled]):not([type="password"]), textarea:not([disabled])'
          ));
          for (const el of inputs) {
            if (actions >= maxActions) break;
            if (!relevant(el) || sensitive(el) || postForm(el)) continue;
            const rect = el.getBoundingClientRect();
            if (rect.width <= 0 || rect.height <= 0) continue;
            el.focus();
            const setter = Object.getOwnPropertyDescriptor(
              el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype,
              "value"
            )?.set;
            if (setter) setter.call(el, marker); else el.value = marker;
            el.dispatchEvent(new Event("input", {bubbles: true}));
            el.dispatchEvent(new Event("change", {bubbles: true}));
            el.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", code: "Enter", bubbles: true}));
            el.dispatchEvent(new KeyboardEvent("keyup", {key: "Enter", code: "Enter", bubbles: true}));
            actions += 1;
            await new Promise((resolve) => setTimeout(resolve, 200));
          }
          if (actions < maxActions) {
            const buttons = Array.from(document.querySelectorAll(
              'button:not([disabled]), [role="button"]'
            ));
            for (const el of buttons) {
              if (actions >= maxActions) break;
              if (!relevant(el) || sensitive(el) || postForm(el)) continue;
              const rect = el.getBoundingClientRect();
              if (rect.width <= 0 || rect.height <= 0) continue;
              el.click();
              actions += 1;
              await new Promise((resolve) => setTimeout(resolve, 200));
            }
          }
          return actions;
        }
        """
        try:
            value = self._page.evaluate(
                script,
                {"maxActions": max_actions, "marker": marker},
            )
            self._page.wait_for_timeout(250)
            self._guard.raise_if_failed()
        except self._provider_timeout_error:
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_TIMEOUT,
                "Bounded SPA route action timed out.",
            ) from None
        except DynamicBrowserError:
            raise
        except Exception:
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Bounded SPA route action failed.",
            ) from None
        return value if type(value) is int and value >= 0 else 0

    def capture_rendered_dom(
        self,
        policy: RenderedDomPolicy | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> RenderedDomSnapshot:
        self._guard.raise_if_failed()
        active_policy = policy or RenderedDomPolicy()
        if type(active_policy) is not RenderedDomPolicy:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.DOM_SNAPSHOT_FAILED,
                "Rendered DOM capture requires a canonical policy.",
            )
        active_timeout_ms = float(active_policy.stabilization_timeout_ms)
        if timeout_seconds is not None:
            if (
                type(timeout_seconds) not in {int, float}
                or isinstance(timeout_seconds, bool)
                or timeout_seconds <= 0
            ):
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.DOM_SNAPSHOT_FAILED,
                    "Rendered DOM timeout override must be positive.",
                )
            active_timeout_ms = min(
                active_timeout_ms,
                float(timeout_seconds) * 1000.0,
            )
        cdp_session: Any | None = None
        try:
            cdp_session = self._context.new_cdp_session(self._page)
            frame_tree = cdp_session.send("Page.getFrameTree")
            frame_id = frame_tree["frameTree"]["frame"]["id"]
            isolated_world = cdp_session.send(
                "Page.createIsolatedWorld",
                {
                    "frameId": frame_id,
                    "worldName": "vulnspider-rendered-dom",
                    "grantUniveralAccess": False,
                },
            )
            execution_context_id = isolated_world["executionContextId"]
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            if cdp_session is not None:
                try:
                    cdp_session.detach()
                except Exception:  # noqa: BLE001 - no diagnostics are retained.
                    pass
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.DOM_SNAPSHOT_FAILED,
                "Rendered DOM isolated world could not be created.",
            ) from None
        try:
            expression = "(" + RENDERED_DOM_CAPTURE_SCRIPT + ")(" + json.dumps(
                active_policy.to_browser_payload(),
                sort_keys=True,
                separators=(",", ":"),
            ) + ")"
            evaluated = cdp_session.send(
                "Runtime.evaluate",
                {
                    "expression": expression,
                    "contextId": execution_context_id,
                    "awaitPromise": True,
                    "returnByValue": True,
                    "timeout": active_timeout_ms,
                    "disableBreaks": True,
                },
            )
            if "exceptionDetails" in evaluated:
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.DOM_SNAPSHOT_FAILED,
                    "Rendered DOM isolated capture failed safely.",
                )
            payload = evaluated["result"]["value"]
            self._guard.raise_if_failed()
        except DynamicBrowserError:
            raise
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.DOM_STABILIZATION_TIMEOUT,
                "Rendered DOM did not stabilize within the hard timeout.",
            ) from None
        finally:
            if cdp_session is not None:
                try:
                    cdp_session.detach()
                except Exception:  # noqa: BLE001 - no provider text is retained.
                    pass
        try:
            return snapshot_from_browser_payload(payload, active_policy)
        except RenderedDomError as exc:
            error_codes = {
                RenderedDomErrorCode.DOM_STABILIZATION_TIMEOUT: (
                    DynamicBrowserErrorCode.DOM_STABILIZATION_TIMEOUT
                ),
                RenderedDomErrorCode.DOM_LIMIT_EXCEEDED: (
                    DynamicBrowserErrorCode.DOM_LIMIT_EXCEEDED
                ),
                RenderedDomErrorCode.DOM_SNAPSHOT_FAILED: (
                    DynamicBrowserErrorCode.DOM_SNAPSHOT_FAILED
                ),
            }
            raise DynamicBrowserError(error_codes[exc.code], str(exc)) from None

    def close_page(self) -> None:
        self._guard.raise_if_failed()
        cleanup_error_codes = self._close_page()
        if cleanup_error_codes:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.CLEANUP_FAILED,
                "Managed primary page cleanup did not complete.",
                cleanup_error_codes=cleanup_error_codes,
            )


class PlaywrightDynamicBrowser:
    """Concrete synchronous adapter with strict pre-page transport guards."""

    def run(
        self,
        authority: DynamicRequestAuthority,
        operation: Callable[[DynamicBrowserSession], T],
        *,
        policy: DynamicBrowserPolicy | None = None,
    ) -> DynamicBrowserRunResult[T]:
        if type(authority) is not DynamicRequestAuthority:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Managed browser requires canonical DynamicRequestAuthority.",
            )
        if not callable(operation):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Managed browser operation must be callable.",
            )
        active_policy = policy or DynamicBrowserPolicy()
        if type(active_policy) is not DynamicBrowserPolicy:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Managed browser requires canonical DynamicBrowserPolicy.",
            )

        audit = _AuditRecorder(
            event_limit=active_policy.request_decision_budget,
        )
        network_discovery = _NetworkDiscoveryRecorder(
            candidate_limit=active_policy.request_decision_budget,
        )
        preflight_timeout = _remaining_deadline_seconds(active_policy)
        if preflight_timeout is None:
            preflight_dynamic_browser()
        else:
            preflight_dynamic_browser(timeout_seconds=preflight_timeout)
        resources = _ManagedResources(audit)
        primary_error: DynamicBrowserError | None = None
        value: T | None = None
        value_set = False

        def expire_if_needed() -> None:
            nonlocal primary_error
            if primary_error is None and _deadline_expired(active_policy):
                primary_error = DynamicBrowserError(
                    DynamicBrowserErrorCode.OPERATION_TIMEOUT,
                    "Managed browser lifecycle exceeded its crawl deadline.",
                )

        expire_if_needed()
        try:
            try:
                sync_playwright, provider_timeout_error = (
                    _load_managed_playwright_sync_api()
                )
                resources.playwright = sync_playwright().start()
                audit.playwright_started += 1
            except Exception:  # noqa: BLE001 - provider diagnostics stay private.
                primary_error = DynamicBrowserError(
                    DynamicBrowserErrorCode.PLAYWRIGHT_START_FAILED,
                    "Managed Playwright runtime could not start.",
                )
            expire_if_needed()
            if primary_error is None:
                try:
                    resources.browser = resources.playwright.chromium.launch(
                        **_browser_launch_options(
                            timeout_seconds=_remaining_deadline_seconds(
                                active_policy
                            )
                        )
                    )
                    audit.browsers_launched += 1
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.BROWSER_LAUNCH_FAILED,
                        "Managed headless Chromium could not launch.",
                    )
            expire_if_needed()
            if primary_error is None:
                try:
                    resources.context = resources.browser.new_context(
                        accept_downloads=False,
                        service_workers="block",
                    )
                    audit.contexts_created += 1
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.CONTEXT_CREATE_FAILED,
                        "Isolated browser context could not be created.",
                    )
            expire_if_needed()
            guard = _RouteGuard(
                authority,
                active_policy,
                audit,
                resources.request_page_stop,
                provider_timeout_error,
                network_discovery,
            )
            page_observer = _PageLifecycleObserver(authority, audit)
            passive_observer = _PassiveNetworkObserver(authority, audit)
            if primary_error is None:
                try:
                    resources.context.route("**/*", guard.handle_http)
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.HTTP_GUARD_INSTALL_FAILED,
                        "HTTP(S) request guard could not be installed.",
                    )
            expire_if_needed()
            if primary_error is None:
                try:
                    resources.context.route_web_socket(
                        "**/*",
                        guard.handle_websocket,
                    )
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.WEBSOCKET_GUARD_INSTALL_FAILED,
                        "WebSocket request guard could not be installed.",
                    )
            expire_if_needed()
            if primary_error is None:
                try:
                    passive_observer.install(resources.context)
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.PASSIVE_OBSERVER_INSTALL_FAILED,
                        "Passive browser request observer could not be installed.",
                    )
            expire_if_needed()
            if primary_error is None:
                try:
                    resources.page = resources.context.new_page()
                    audit.pages_created += 1
                    guard.set_primary_page(resources.page)
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.PAGE_CREATE_FAILED,
                        "Guarded primary page could not be created.",
                    )
            expire_if_needed()
            if primary_error is None:
                try:
                    page_observer.install(resources.page)
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.PAGE_OBSERVER_INSTALL_FAILED,
                        "Browser lifecycle observers could not be installed.",
                    )
            expire_if_needed()
            if primary_error is None:
                try:
                    resources.context.on(
                        "page",
                        lambda popup: resources.add_popup_page(popup),
                    )
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.POPUP_OBSERVER_INSTALL_FAILED,
                        "Popup lifecycle observer could not be installed.",
                    )
            expire_if_needed()
            if primary_error is None:
                session = _PlaywrightDynamicSession(
                    page=resources.page,
                    context=resources.context,
                    authority=authority,
                    policy=active_policy,
                    provider_timeout_error=provider_timeout_error,
                    guard=guard,
                    close_page=resources.close_page,
                )
                try:
                    value = operation(session)
                    guard.raise_if_failed()
                    value_set = True
                except DynamicBrowserError as exc:
                    primary_error = exc
                except (provider_timeout_error, TimeoutError):
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.OPERATION_TIMEOUT,
                        "Managed browser operation timed out.",
                    )
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.OPERATION_FAILED,
                        "Managed browser operation failed.",
                    )
                expire_if_needed()
        finally:
            resources.close_requested_page()
            cleanup_error_codes = resources.close()
            if primary_error is None:
                try:
                    guard.raise_if_failed()
                except DynamicBrowserError as exc:
                    primary_error = exc
            expire_if_needed()

        summary = audit.snapshot(cleanup_error_codes)
        network_summary = network_discovery.snapshot()
        if primary_error is not None:
            raise DynamicBrowserError(
                primary_error.code,
                str(primary_error),
                cleanup_error_codes=cleanup_error_codes,
                audit=summary,
                network_discovery=network_summary,
            ) from None
        if cleanup_error_codes:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.CLEANUP_FAILED,
                "Managed browser cleanup did not complete.",
                cleanup_error_codes=cleanup_error_codes,
                audit=summary,
                network_discovery=network_summary,
            )
        if not value_set:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Managed browser operation did not produce a result.",
                audit=summary,
                network_discovery=network_summary,
            )
        return DynamicBrowserRunResult(
            value=value,
            audit=summary,
            network_discovery=network_summary,
        )
