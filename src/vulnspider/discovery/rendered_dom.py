"""Pure bounded rendered-DOM snapshot validation and canonical extraction."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from html.parser import HTMLParser
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from vulnspider.discovery.contracts import (
    CanonicalDiscoveryResult,
    CollectorKind,
    DiscoveryMetadata,
    DiscoverySafetyInvariant,
    DiscoveryWarning,
    ScopeMetadata,
    scope_id_for_root,
)
from vulnspider.discovery.html_extractor import (
    NavigableLink,
    SCOPE_POLICY_VERSION,
    SensitiveFormElisionPolicy,
    extract_static_html,
)
from vulnspider.domain import stable_fingerprint

RENDERED_DOM_VERSION = "native-rendered-dom/1.0"
_MINIMUM_OBSERVATION_MS = 250
_POLL_INTERVAL_MS = 50
_STABLE_POLL_COUNT = 4
_STABLE_SPAN_MS = 150
_MAX_STABILIZATION_TIMEOUT_MS = 1000
_MAX_NODES = 1000
_MAX_ACTIONABLE_ELEMENTS = 100
_MAX_ANCHORS = 100
_MAX_FORMS = 100
_MAX_CONTROLS = 100
_MAX_ATTRIBUTES_PER_ELEMENT = 16
_MAX_ATTRIBUTE_LENGTH = 4096
_MAX_TEXT_LENGTH = 4096
_MAX_SERIALIZED_BYTES = 512_000

_PROJECTED_ATTRIBUTES = {
    "html": frozenset(),
    "body": frozenset(),
    "a": frozenset({"href"}),
    "form": frozenset({"action", "method"}),
    "input": frozenset(
        {"type", "name", "value", "disabled", "checked"}
    ),
    "select": frozenset({"name", "disabled", "multiple"}),
    "option": frozenset({"value", "selected"}),
    "textarea": frozenset({"name", "disabled"}),
}
_PROJECTED_VOID_TAGS = frozenset({"input"})
_PROJECTED_CONTROL_TAGS = frozenset({"input", "select", "textarea"})


class _ProjectedHtmlLimitError(ValueError):
    """Internal signal for a valid projection exceeding active policy."""


class _ProjectedHtmlValidator(HTMLParser):
    """Validate the minimal browser projection again on the host boundary."""

    def __init__(
        self,
        *,
        max_attributes_per_element: int = _MAX_ATTRIBUTES_PER_ELEMENT,
        max_attribute_length: int = _MAX_ATTRIBUTE_LENGTH,
        max_text_length: int = _MAX_TEXT_LENGTH,
    ) -> None:
        super().__init__(convert_charrefs=True)
        self.max_attributes_per_element = max_attributes_per_element
        self.max_attribute_length = max_attribute_length
        self.max_text_length = max_text_length
        self.stack: list[str] = []
        self.anchor_count = 0
        self.form_count = 0
        self.control_count = 0
        self.html_count = 0
        self.body_count = 0
        self.textarea_text_length = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized = tag.lower()
        allowed = _PROJECTED_ATTRIBUTES.get(normalized)
        if allowed is None:
            raise ValueError("rendered projection contains an unsupported tag")
        names = tuple(name.lower() for name, _ in attrs)
        if len(names) > self.max_attributes_per_element or any(
            value is not None and len(value) > self.max_attribute_length
            for _, value in attrs
        ):
            raise _ProjectedHtmlLimitError(
                "rendered projection attributes exceed active policy"
            )
        if len(names) != len(set(names)) or any(
            name not in allowed for name in names
        ):
            raise ValueError("rendered projection attributes are not allowed")
        attributes = {name.lower(): value for name, value in attrs}
        if normalized == "input" and (
            (attributes.get("type") or "text").strip().lower()
            == "password"
        ):
            raise ValueError("rendered projection contains a password control")
        if normalized == "html":
            self.html_count += 1
        elif normalized == "body":
            self.body_count += 1
        elif normalized == "a":
            self.anchor_count += 1
        elif normalized == "form":
            self.form_count += 1
        elif normalized in _PROJECTED_CONTROL_TAGS:
            if "form" not in self.stack:
                raise ValueError("rendered projection control has no form owner")
            self.control_count += 1
        if normalized == "textarea":
            self.textarea_text_length = 0
        if normalized not in _PROJECTED_VOID_TAGS:
            self.stack.append(normalized)

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if not self.stack or self.stack[-1] != normalized:
            raise ValueError("rendered projection nesting is malformed")
        self.stack.pop()

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        raise ValueError("rendered projection uses unsupported empty-element syntax")

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1] == "textarea":
            self.textarea_text_length += len(data)
            if self.textarea_text_length > self.max_text_length:
                raise _ProjectedHtmlLimitError(
                    "rendered projection text exceeds active policy"
                )
            return
        if data:
            raise ValueError("rendered projection contains unsupported text")

    def handle_comment(self, data: str) -> None:
        raise ValueError("rendered projection contains an unsupported comment")

    def handle_decl(self, decl: str) -> None:
        raise ValueError("rendered projection contains an unsupported declaration")

    def finish(self) -> None:
        self.close()
        if self.stack or self.html_count != 1 or self.body_count != 1:
            raise ValueError("rendered projection wrapper is malformed")


class RenderedDomErrorCode(StrEnum):
    """Stable, secret-free rendered-DOM failure codes."""

    DOM_STABILIZATION_TIMEOUT = "DOM_STABILIZATION_TIMEOUT"
    DOM_LIMIT_EXCEEDED = "DOM_LIMIT_EXCEEDED"
    DOM_SNAPSHOT_FAILED = "DOM_SNAPSHOT_FAILED"


class RenderedDomError(RuntimeError):
    """Raised when a rendered snapshot cannot be produced safely."""

    def __init__(self, code: RenderedDomErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = RenderedDomErrorCode(code)

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        """Preserve the typed error across the supervised crawl worker seam."""

        return (_restore_rendered_dom_error, (self.code, str(self)))


def _restore_rendered_dom_error(
    code: RenderedDomErrorCode,
    message: str,
) -> RenderedDomError:
    return RenderedDomError(code, message)


@dataclass(frozen=True, slots=True)
class RenderedDomPolicy:
    """Deterministic stabilization and serialization bounds for one page."""

    minimum_observation_ms: int = _MINIMUM_OBSERVATION_MS
    poll_interval_ms: int = _POLL_INTERVAL_MS
    stable_poll_count: int = _STABLE_POLL_COUNT
    stable_span_ms: int = _STABLE_SPAN_MS
    stabilization_timeout_ms: int = _MAX_STABILIZATION_TIMEOUT_MS
    max_nodes: int = _MAX_NODES
    max_actionable_elements: int = _MAX_ACTIONABLE_ELEMENTS
    max_anchors: int = _MAX_ANCHORS
    max_forms: int = _MAX_FORMS
    max_controls: int = _MAX_CONTROLS
    max_attributes_per_element: int = _MAX_ATTRIBUTES_PER_ELEMENT
    max_attribute_length: int = _MAX_ATTRIBUTE_LENGTH
    max_text_length: int = _MAX_TEXT_LENGTH
    max_serialized_bytes: int = _MAX_SERIALIZED_BYTES

    def __post_init__(self) -> None:
        values = (
            self.minimum_observation_ms,
            self.poll_interval_ms,
            self.stable_poll_count,
            self.stable_span_ms,
            self.stabilization_timeout_ms,
            self.max_nodes,
            self.max_actionable_elements,
            self.max_anchors,
            self.max_forms,
            self.max_controls,
            self.max_attributes_per_element,
            self.max_attribute_length,
            self.max_text_length,
            self.max_serialized_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("rendered DOM policy bounds must be positive integers")
        if self.minimum_observation_ms > self.stabilization_timeout_ms:
            raise ValueError("minimum observation must fit stabilization timeout")
        if self.stable_span_ms > self.stabilization_timeout_ms:
            raise ValueError("stable span must fit stabilization timeout")
        if (
            self.minimum_observation_ms < _MINIMUM_OBSERVATION_MS
            or self.poll_interval_ms != _POLL_INTERVAL_MS
            or self.stable_poll_count < _STABLE_POLL_COUNT
            or self.stable_span_ms < _STABLE_SPAN_MS
            or self.stabilization_timeout_ms != _MAX_STABILIZATION_TIMEOUT_MS
        ):
            raise ValueError("rendered DOM stabilization safety bounds are fixed")
        ceilings = (
            (self.max_nodes, _MAX_NODES),
            (self.max_actionable_elements, _MAX_ACTIONABLE_ELEMENTS),
            (self.max_anchors, _MAX_ANCHORS),
            (self.max_forms, _MAX_FORMS),
            (self.max_controls, _MAX_CONTROLS),
            (self.max_attributes_per_element, _MAX_ATTRIBUTES_PER_ELEMENT),
            (self.max_attribute_length, _MAX_ATTRIBUTE_LENGTH),
            (self.max_text_length, _MAX_TEXT_LENGTH),
            (self.max_serialized_bytes, _MAX_SERIALIZED_BYTES),
        )
        if any(value > ceiling for value, ceiling in ceilings):
            raise ValueError("rendered DOM extraction ceilings cannot be raised")

    @property
    def fingerprint(self) -> str:
        return stable_fingerprint(
            "rendered-dom-policy",
            RENDERED_DOM_VERSION,
            self.minimum_observation_ms,
            self.poll_interval_ms,
            self.stable_poll_count,
            self.stable_span_ms,
            self.stabilization_timeout_ms,
            self.max_nodes,
            self.max_actionable_elements,
            self.max_anchors,
            self.max_forms,
            self.max_controls,
            self.max_attributes_per_element,
            self.max_attribute_length,
            self.max_text_length,
            self.max_serialized_bytes,
        )

    def to_browser_payload(self) -> dict[str, int]:
        return {
            "minimumObservationMs": self.minimum_observation_ms,
            "pollIntervalMs": self.poll_interval_ms,
            "stablePollCount": self.stable_poll_count,
            "stableSpanMs": self.stable_span_ms,
            "stabilizationTimeoutMs": self.stabilization_timeout_ms,
            "maxNodes": self.max_nodes,
            "maxActionableElements": self.max_actionable_elements,
            "maxAnchors": self.max_anchors,
            "maxForms": self.max_forms,
            "maxControls": self.max_controls,
            "maxAttributesPerElement": self.max_attributes_per_element,
            "maxAttributeLength": self.max_attribute_length,
            "maxTextLength": self.max_text_length,
            "maxSerializedBytes": self.max_serialized_bytes,
        }


@dataclass(frozen=True, slots=True)
class RenderedDomSnapshot:
    """One bounded, sensitive-form-free main-frame extraction snapshot."""

    page_url: str
    sanitized_html: str = field(repr=False)
    sensitive_form_occurrences: tuple[int, ...]
    node_count: int
    anchor_count: int
    form_count: int
    control_count: int
    serialized_bytes: int
    capture_policy_fingerprint: str
    fingerprint: str = field(init=False)

    @property
    def sensitive_form_count(self) -> int:
        return len(self.sensitive_form_occurrences)

    def __post_init__(self) -> None:
        if type(self.page_url) is not str:
            raise TypeError("rendered page URL must be a string")
        parts = urlsplit(self.page_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError("rendered page URL must be absolute HTTP(S)")
        if type(self.sanitized_html) is not str:
            raise TypeError("sanitized rendered HTML must be a string")
        counts = (
            self.node_count,
            self.anchor_count,
            self.form_count,
            self.control_count,
            self.serialized_bytes,
        )
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("rendered DOM snapshot counts must be non-negative")
        try:
            occurrences = tuple(self.sensitive_form_occurrences)
        except TypeError:
            raise ValueError(
                "sensitive form occurrences must be an integer tuple"
            ) from None
        if (
            any(type(value) is not int or value < 0 for value in occurrences)
            or occurrences != tuple(sorted(set(occurrences)))
            or any(
                value >= self.form_count + len(occurrences)
                for value in occurrences
            )
        ):
            raise ValueError("sensitive form occurrences are not canonical")
        object.__setattr__(self, "sensitive_form_occurrences", occurrences)
        if self.serialized_bytes != len(self.sanitized_html.encode("utf-8")):
            raise ValueError("rendered DOM serialized byte count does not match")
        validator = _ProjectedHtmlValidator()
        validator.feed(self.sanitized_html)
        validator.finish()
        if (
            validator.anchor_count != self.anchor_count
            or validator.form_count != self.form_count
            or validator.control_count != self.control_count
        ):
            raise ValueError("rendered DOM projection counts do not match")
        if (
            self.node_count > _MAX_NODES
            or self.anchor_count > _MAX_ANCHORS
            or self.form_count + self.sensitive_form_count > _MAX_FORMS
            or self.control_count > _MAX_CONTROLS
            or self.serialized_bytes > _MAX_SERIALIZED_BYTES
            or self.anchor_count
            + self.form_count
            + self.sensitive_form_count
            + self.control_count
            > _MAX_ACTIONABLE_ELEMENTS
        ):
            raise ValueError("rendered DOM snapshot exceeds absolute bounds")
        if (
            type(self.capture_policy_fingerprint) is not str
            or not self.capture_policy_fingerprint
        ):
            raise ValueError("capture policy fingerprint must not be empty")
        fingerprint = stable_fingerprint(
            "rendered-dom-snapshot",
            self.page_url,
            self.sanitized_html,
            self.sensitive_form_occurrences,
            self.node_count,
            self.anchor_count,
            self.form_count,
            self.control_count,
            self.serialized_bytes,
            self.capture_policy_fingerprint,
        )
        object.__setattr__(self, "fingerprint", fingerprint)

    def to_dict(self) -> dict[str, Any]:
        return {
            "page_url": self.page_url,
            "sanitized_html": self.sanitized_html,
            "sensitive_form_count": self.sensitive_form_count,
            "sensitive_form_occurrences": list(
                self.sensitive_form_occurrences
            ),
            "node_count": self.node_count,
            "anchor_count": self.anchor_count,
            "form_count": self.form_count,
            "control_count": self.control_count,
            "serialized_bytes": self.serialized_bytes,
            "capture_policy_fingerprint": self.capture_policy_fingerprint,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True, slots=True)
class RenderedDomExtractionResult:
    """Canonical Native Dynamic component derived from one rendered snapshot."""

    source_url: str
    snapshot_fingerprint: str
    navigable_links: tuple[NavigableLink, ...]
    discovery: CanonicalDiscoveryResult

    def __post_init__(self) -> None:
        if type(self.navigable_links) is not tuple or any(
            type(item) is not NavigableLink for item in self.navigable_links
        ):
            raise TypeError("navigable_links must be a tuple of NavigableLink")
        if type(self.snapshot_fingerprint) is not str or not self.snapshot_fingerprint:
            raise ValueError("snapshot fingerprint must not be empty")
        if any(item.source_url != self.source_url for item in self.navigable_links):
            raise ValueError("navigable link source ownership mismatch")
        ordered = tuple(
            sorted(
                self.navigable_links,
                key=lambda item: (
                    item.crawl_url,
                    item.raw_href,
                    item.resolved_url,
                    item.occurrence_index,
                    item.id,
                ),
            )
        )
        if self.navigable_links != ordered:
            raise ValueError("navigable_links ordering is not canonical")
        self.discovery.validate()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "navigable_links": [item.to_dict() for item in self.navigable_links],
            "discovery": self.discovery.to_dict(),
        }


class RenderedRequestAuthority(Protocol):
    """Minimal exact request-authority seam used by pure extraction."""

    root_url: str

    def allows_navigation(self, url: str) -> bool:
        """Return whether an exact rendered request URL is caller-authorized."""


def snapshot_from_browser_payload(
    payload: object,
    policy: RenderedDomPolicy,
) -> RenderedDomSnapshot:
    """Validate one untrusted browser payload without retaining diagnostics."""

    if type(policy) is not RenderedDomPolicy:
        raise TypeError("policy must be a RenderedDomPolicy")
    if not isinstance(payload, Mapping):
        raise RenderedDomError(
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
            "Rendered DOM capture returned an invalid result.",
        )
    if payload.get("ok") is not True:
        raw_code = payload.get("code")
        try:
            code = RenderedDomErrorCode(raw_code)
        except (TypeError, ValueError):
            code = RenderedDomErrorCode.DOM_SNAPSHOT_FAILED
        messages = {
            RenderedDomErrorCode.DOM_STABILIZATION_TIMEOUT: (
                "Rendered DOM did not stabilize within the hard timeout."
            ),
            RenderedDomErrorCode.DOM_LIMIT_EXCEEDED: (
                "Rendered DOM exceeded a configured extraction bound."
            ),
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED: (
                "Rendered DOM capture failed safely."
            ),
        }
        raise RenderedDomError(code, messages[code])

    try:
        snapshot = RenderedDomSnapshot(
            page_url=_payload_string(payload, "pageUrl"),
            sanitized_html=_payload_string(payload, "sanitizedHtml"),
            sensitive_form_occurrences=_payload_int_tuple(
                payload,
                "sensitiveFormOccurrences",
            ),
            node_count=_payload_int(payload, "nodeCount"),
            anchor_count=_payload_int(payload, "anchorCount"),
            form_count=_payload_int(payload, "formCount"),
            control_count=_payload_int(payload, "controlCount"),
            serialized_bytes=_payload_int(payload, "serializedBytes"),
            capture_policy_fingerprint=policy.fingerprint,
        )
    except (TypeError, ValueError):
        raise RenderedDomError(
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
            "Rendered DOM capture returned an invalid result.",
        ) from None
    if (
        snapshot.node_count > policy.max_nodes
        or snapshot.anchor_count > policy.max_anchors
        or snapshot.form_count + snapshot.sensitive_form_count > policy.max_forms
        or snapshot.control_count > policy.max_controls
        or snapshot.serialized_bytes > policy.max_serialized_bytes
        or snapshot.anchor_count
        + snapshot.form_count
        + snapshot.sensitive_form_count
        + snapshot.control_count
        > policy.max_actionable_elements
    ):
        raise RenderedDomError(
            RenderedDomErrorCode.DOM_LIMIT_EXCEEDED,
            "Rendered DOM exceeded a configured extraction bound.",
        )
    try:
        validator = _ProjectedHtmlValidator(
            max_attributes_per_element=policy.max_attributes_per_element,
            max_attribute_length=policy.max_attribute_length,
            max_text_length=policy.max_text_length,
        )
        validator.feed(snapshot.sanitized_html)
        validator.finish()
    except _ProjectedHtmlLimitError:
        raise RenderedDomError(
            RenderedDomErrorCode.DOM_LIMIT_EXCEEDED,
            "Rendered DOM exceeded a configured extraction bound.",
        ) from None
    except ValueError:
        raise RenderedDomError(
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
            "Rendered DOM capture returned an invalid result.",
        ) from None
    return snapshot


def extract_rendered_dom(
    snapshot: RenderedDomSnapshot,
    authority: RenderedRequestAuthority,
    *,
    discovery_metadata: DiscoveryMetadata | None = None,
    scope_metadata: ScopeMetadata | None = None,
    parent_url: str | None = None,
    depth: int = 0,
) -> RenderedDomExtractionResult:
    """Convert one sanitized snapshot into a Native Dynamic component."""

    if type(snapshot) is not RenderedDomSnapshot:
        raise TypeError("snapshot must be a RenderedDomSnapshot")
    root_url = getattr(authority, "root_url", None)
    allows_navigation = getattr(authority, "allows_navigation", None)
    allows_rendered_navigation = getattr(
        authority,
        "allows_rendered_navigation",
        None,
    )
    if type(root_url) is not str or not callable(allows_navigation):
        raise TypeError("authority must provide exact rendered request authority")

    def source_request_authorized(url: str) -> bool:
        """Authorize exact URLs first, then explicitly enabled SPA URLs."""

        try:
            if allows_navigation(url) is True:
                return True
        except Exception:  # noqa: BLE001 - authority ambiguity fails closed.
            return False
        if not callable(allows_rendered_navigation):
            return False
        try:
            return allows_rendered_navigation(url) is True
        except Exception:  # noqa: BLE001 - authority ambiguity fails closed.
            return False

    if not source_request_authorized(snapshot.page_url):
        raise RenderedDomError(
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
            "Rendered DOM source page is not caller-authorized.",
        )

    if discovery_metadata is None:
        metadata = DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_DYNAMIC,
            collector_version=RENDERED_DOM_VERSION,
            configuration_fingerprint=stable_fingerprint(
                "native-rendered-dom-policy",
                RENDERED_DOM_VERSION,
                snapshot.capture_policy_fingerprint,
            ),
        )
    else:
        if type(discovery_metadata) is not DiscoveryMetadata:
            raise TypeError("discovery_metadata must be DiscoveryMetadata")
        if discovery_metadata.collector_kind != CollectorKind.NATIVE_DYNAMIC:
            raise ValueError("rendered DOM metadata must be Native Dynamic")
        metadata = discovery_metadata
    if scope_metadata is None:
        scope = ScopeMetadata(
            target_scope_id=scope_id_for_root(
                root_url,
                policy_version=SCOPE_POLICY_VERSION,
            ),
            root_url=root_url,
            scope_policy_version=SCOPE_POLICY_VERSION,
        )
    else:
        if type(scope_metadata) is not ScopeMetadata:
            raise TypeError("scope_metadata must be ScopeMetadata")
        if scope_metadata.root_url != root_url:
            raise ValueError("rendered DOM scope root must match request authority")
        scope = scope_metadata
    extracted = extract_static_html(
        snapshot.sanitized_html,
        snapshot.page_url,
        discovery_metadata=metadata,
        scope_metadata=scope,
        sensitive_form_policy=SensitiveFormElisionPolicy(),
        request_authorizer=source_request_authorized,
        parent_url=parent_url,
        depth=depth,
        safety_invariants=(
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
        ),
    )
    if any(
        warning.code == "SENSITIVE_FORM_ELIDED"
        for warning in extracted.discovery.warnings
    ):
        raise RenderedDomError(
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
            "Rendered DOM snapshot violated pre-canonical form elision.",
        )
    dynamic_warnings = tuple(
        DiscoveryWarning(
            code="SENSITIVE_FORM_ELIDED",
            message="sensitive form was elided before canonical construction",
            details={
                "form_occurrence_index": occurrence,
                "producer_kind": CollectorKind.NATIVE_DYNAMIC.value,
                "source_page_fingerprint": stable_fingerprint(
                    "rendered-source-page",
                    snapshot.page_url,
                )[:16],
            },
        )
        for occurrence in snapshot.sensitive_form_occurrences
    )
    base = extracted.discovery
    discovery = CanonicalDiscoveryResult.create(
        discovery_metadata=base.discovery_metadata,
        scope_metadata=base.scope_metadata,
        crawl_statistics=replace(
            base.crawl_statistics,
            forms_discovered=(
                snapshot.form_count + snapshot.sensitive_form_count
            ),
            skipped=base.crawl_statistics.skipped + len(dynamic_warnings),
        ),
        endpoints=base.endpoints,
        input_points=base.input_points,
        request_templates=base.request_templates,
        input_point_request_contexts=base.input_point_request_contexts,
        probe_readiness=base.probe_readiness,
        crawl_provenance=base.crawl_provenance,
        bac_static_hints=base.bac_static_hints,
        warnings=base.warnings + dynamic_warnings,
        safety_invariants=base.safety_invariants,
    )
    return RenderedDomExtractionResult(
        source_url=extracted.source_url,
        snapshot_fingerprint=snapshot.fingerprint,
        navigable_links=extracted.navigable_links,
        discovery=discovery,
    )


def _payload_string(payload: Mapping[object, object], key: str) -> str:
    value = payload.get(key)
    if type(value) is not str:
        raise TypeError(f"{key} must be a string")
    return value


def _payload_int(payload: Mapping[object, object], key: str) -> int:
    value = payload.get(key)
    if type(value) is not int or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def _payload_int_tuple(
    payload: Mapping[object, object],
    key: str,
) -> tuple[int, ...]:
    value = payload.get(key)
    if type(value) is not list or any(
        type(item) is not int or item < 0 for item in value
    ):
        raise ValueError(f"{key} must be a list of non-negative integers")
    return tuple(value)


# Executed only by the guarded browser adapter. The projection deliberately
# classifies every form by structural input type before reading any live value.
RENDERED_DOM_CAPTURE_SCRIPT = r"""
async (config) => {
  const timeoutCode = "DOM_STABILIZATION_TIMEOUT";
  const limitCode = "DOM_LIMIT_EXCEEDED";
  const failureCode = "DOM_SNAPSHOT_FAILED";
  const delay = (milliseconds) => new Promise(
    (resolve) => setTimeout(resolve, milliseconds)
  );
  const fail = (code) => ({ok: false, code});
  const normalizedInputType = (element) => {
    const raw = element.getAttribute("type");
    const normalized = (raw === null ? "text" : raw).trim().toLowerCase();
    return normalized || "text";
  };
  const relevantControl = (element) => (
    element.tagName === "INPUT" ||
    element.tagName === "SELECT" ||
    element.tagName === "TEXTAREA"
  );
  const stringWithinLimit = (value, maximum) => (
    typeof value === "string" && value.length <= maximum
  );
  const attributeCount = (attributes) => attributes.reduce(
    (count, value) => count + (value === null ? 0 : 1),
    0
  );
  const withoutQueryValues = (value) => {
    if (value === null) {
      return null;
    }
    const queryIndex = value.indexOf("?");
    if (queryIndex < 0) {
      return value;
    }
    const fragmentIndex = value.indexOf("#", queryIndex);
    return value.slice(0, queryIndex) + (
      fragmentIndex < 0 ? "" : value.slice(fragmentIndex)
    );
  };
  const inspect = () => {
    const nodeCount = document.querySelectorAll("*").length;
    if (nodeCount > config.maxNodes) {
      return fail(limitCode);
    }
    const forms = Array.from(document.querySelectorAll("form"));
    if (forms.length > config.maxForms) {
      return fail(limitCode);
    }
    const sensitiveForms = new Set();
    for (const form of forms) {
      const sensitive = Array.from(form.querySelectorAll("input")).some(
        (element) => normalizedInputType(element) === "password"
      );
      if (sensitive) {
        sensitiveForms.add(form);
      }
    }
    const anchors = Array.from(document.querySelectorAll("a")).filter(
      (anchor) => !sensitiveForms.has(anchor.closest("form"))
    );
    const safeForms = forms.filter((form) => !sensitiveForms.has(form));
    const controls = safeForms.flatMap((form) => (
      Array.from(form.querySelectorAll("input, select, textarea"))
    ));
    const actionableCount = anchors.length + forms.length + controls.length;
    if (
      anchors.length > config.maxAnchors ||
      controls.length > config.maxControls ||
      actionableCount > config.maxActionableElements
    ) {
      return fail(limitCode);
    }

    const structural = [];
    for (const anchor of anchors) {
      const href = anchor.getAttribute("href");
      if (
        anchor.attributes.length > config.maxAttributesPerElement ||
        attributeCount([href]) > config.maxAttributesPerElement ||
        (href !== null && !stringWithinLimit(href, config.maxAttributeLength))
      ) {
        return fail(limitCode);
      }
      structural.push(["a", href]);
    }
    for (const form of forms) {
      if (sensitiveForms.has(form)) {
        structural.push(["sensitive-form"]);
        continue;
      }
      const action = form.getAttribute("action");
      const method = form.getAttribute("method");
      if (
        form.attributes.length > config.maxAttributesPerElement ||
        attributeCount([action, method]) > config.maxAttributesPerElement ||
        [action, method].some((value) => (
          value !== null && !stringWithinLimit(value, config.maxAttributeLength)
        ))
      ) {
        return fail(limitCode);
      }
      const formStructure = [
        "form",
        withoutQueryValues(action),
        method,
      ];
      for (const control of Array.from(
        form.querySelectorAll("input, select, textarea")
      ).filter(relevantControl)) {
        const name = control.getAttribute("name");
        const type = control.tagName === "INPUT"
          ? normalizedInputType(control)
          : control.tagName.toLowerCase();
        const attributes = [name, type, control.disabled ? "disabled" : null];
        if (control.tagName === "SELECT" && control.multiple) {
          attributes.push("multiple");
        }
        if (
          control.attributes.length > config.maxAttributesPerElement ||
          attributeCount(attributes) > config.maxAttributesPerElement ||
          attributes.some((value) => (
            value !== null && !stringWithinLimit(
              value,
              config.maxAttributeLength
            )
          ))
        ) {
          return fail(limitCode);
        }
        const options = control.tagName === "SELECT"
          ? Array.from(control.options)
          : [];
        if (options.some(
          (option) => option.attributes.length > config.maxAttributesPerElement
        )) {
          return fail(limitCode);
        }
        const optionStructure = options.map((option) => [
          option.disabled,
          option.parentElement !== null && option.parentElement.disabled,
        ]);
        formStructure.push([
          control.tagName.toLowerCase(),
          ...attributes,
          optionStructure,
        ]);
      }
      structural.push(formStructure);
    }
    return {
      ok: true,
      key: JSON.stringify(structural),
      nodeCount,
      anchors,
      forms,
      safeForms,
      sensitiveForms,
      controls,
    };
  };

  const escapeAttribute = (value) => value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  const escapeText = (value) => value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  const serialize = (state) => {
    const pieces = ["<html><body>"];
    const pushAttribute = (attributes, name, value) => {
      if (value === null) {
        return true;
      }
      if (!stringWithinLimit(value, config.maxAttributeLength)) {
        return false;
      }
      attributes.push(`${name}="${escapeAttribute(value)}"`);
      return attributes.length <= config.maxAttributesPerElement;
    };
    for (const anchor of state.anchors) {
      if (anchor.attributes.length > config.maxAttributesPerElement) {
        return fail(limitCode);
      }
      const attributes = [];
      if (!pushAttribute(attributes, "href", anchor.getAttribute("href"))) {
        return fail(limitCode);
      }
      pieces.push(`<a${attributes.length ? " " + attributes.join(" ") : ""}></a>`);
    }
    for (const form of state.safeForms) {
      if (form.attributes.length > config.maxAttributesPerElement) {
        return fail(limitCode);
      }
      const formAttributes = [];
      if (
        !pushAttribute(formAttributes, "action", form.getAttribute("action")) ||
        !pushAttribute(formAttributes, "method", form.getAttribute("method"))
      ) {
        return fail(limitCode);
      }
      pieces.push(
        `<form${formAttributes.length ? " " + formAttributes.join(" ") : ""}>`
      );
      for (const control of Array.from(
        form.querySelectorAll("input, select, textarea")
      ).filter(relevantControl)) {
        if (control.attributes.length > config.maxAttributesPerElement) {
          return fail(limitCode);
        }
        const name = control.getAttribute("name");
        const disabled = control.disabled;
        if (control.tagName === "INPUT") {
          const type = normalizedInputType(control);
          if (type === "password") {
            return fail(failureCode);
          }
          const attributes = [];
          if (
            !pushAttribute(attributes, "type", type) ||
            !pushAttribute(attributes, "name", name)
          ) {
            return fail(limitCode);
          }
          if (disabled) {
            attributes.push("disabled=\"\"");
          } else if (name !== null && name.trim() !== "") {
            if (type === "checkbox" || type === "radio") {
              if (control.checked) {
                attributes.push("checked=\"\"");
                if (!pushAttribute(attributes, "value", control.value)) {
                  return fail(limitCode);
                }
              }
            } else if (type !== "file") {
              if (!pushAttribute(attributes, "value", control.value)) {
                return fail(limitCode);
              }
            }
          }
          if (attributes.length > config.maxAttributesPerElement) {
            return fail(limitCode);
          }
          pieces.push(`<input ${attributes.join(" ")}>`);
          continue;
        }
        if (control.tagName === "SELECT") {
          const attributes = [];
          if (!pushAttribute(attributes, "name", name)) {
            return fail(limitCode);
          }
          if (disabled) {
            attributes.push("disabled=\"\"");
          }
          if (control.multiple) {
            attributes.push("multiple=\"\"");
          }
          if (attributes.length > config.maxAttributesPerElement) {
            return fail(limitCode);
          }
          pieces.push(`<select${attributes.length ? " " + attributes.join(" ") : ""}>`);
          if (!disabled && name !== null && name.trim() !== "") {
            for (const option of Array.from(control.selectedOptions)) {
              if (option.attributes.length > config.maxAttributesPerElement) {
                return fail(limitCode);
              }
              const parentDisabled = (
                option.parentElement !== null && option.parentElement.disabled
              );
              if (option.disabled || parentDisabled) {
                continue;
              }
              const optionAttributes = ["selected=\"\""];
              if (!pushAttribute(optionAttributes, "value", option.value)) {
                return fail(limitCode);
              }
              pieces.push(`<option ${optionAttributes.join(" ")}></option>`);
            }
          }
          pieces.push("</select>");
          continue;
        }
        const attributes = [];
        if (!pushAttribute(attributes, "name", name)) {
          return fail(limitCode);
        }
        if (disabled) {
          attributes.push("disabled=\"\"");
        }
        let text = "";
        if (!disabled && name !== null && name.trim() !== "") {
          text = control.value;
          if (!stringWithinLimit(text, config.maxTextLength)) {
            return fail(limitCode);
          }
        }
        if (attributes.length > config.maxAttributesPerElement) {
          return fail(limitCode);
        }
        pieces.push(
          `<textarea${attributes.length ? " " + attributes.join(" ") : ""}>` +
          `${escapeText(text)}</textarea>`
        );
      }
      pieces.push("</form>");
    }
    pieces.push("</body></html>");
    const sanitizedHtml = pieces.join("");
    const serializedBytes = new TextEncoder().encode(sanitizedHtml).length;
    if (serializedBytes > config.maxSerializedBytes) {
      return fail(limitCode);
    }
    return {
      ok: true,
      pageUrl: window.location.href,
      sanitizedHtml,
      sensitiveFormOccurrences: state.forms.flatMap(
        (form, index) => state.sensitiveForms.has(form) ? [index] : []
      ),
      nodeCount: state.nodeCount,
      anchorCount: state.anchors.length,
      formCount: state.safeForms.length,
      controlCount: state.controls.length,
      serializedBytes,
    };
  };

  try {
    const started = performance.now();
    let previousKey = null;
    let stablePolls = 0;
    let stableSince = started;
    while (true) {
      const state = inspect();
      if (!state.ok) {
        return state;
      }
      const currentKey = JSON.stringify([window.location.href, state.key]);
      const now = performance.now();
      if (currentKey === previousKey) {
        stablePolls += 1;
      } else {
        previousKey = currentKey;
        stablePolls = 1;
        stableSince = now;
      }
      const elapsed = now - started;
      if (
        elapsed >= config.minimumObservationMs &&
        stablePolls >= config.stablePollCount &&
        now - stableSince >= config.stableSpanMs
      ) {
        return serialize(state);
      }
      if (elapsed >= config.stabilizationTimeoutMs) {
        return fail(timeoutCode);
      }
      await delay(config.pollIntervalMs);
    }
  } catch (_) {
    return fail(failureCode);
  }
}
"""
