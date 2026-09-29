"""Pure static HTML extraction into canonical discovery records."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from html.parser import HTMLParser
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from vulnspider.discovery.contracts import (
    CanonicalDiscoveryResult,
    CollectorKind,
    CrawlStatistics,
    DiscoveryContractError,
    DiscoveryMetadata,
    DiscoveryProvenance,
    DiscoverySafetyInvariant,
    DiscoverySubjectKind,
    DiscoveryWarning,
    NonProbeReadyReason,
    ProbeReadiness,
    ProbeReadyStatus,
    ScopeMetadata,
    discovery_run_id_for,
    scope_id_for_root,
)
from vulnspider.discovery.navigation_safety import (
    authentication_state_change_token,
    automatic_navigation_within_root_path,
)
from vulnspider.discovery.post_replay_policy import (
    PostReplayDisposition,
    PostReplayPolicyDecision,
    PostReplayReasonCode,
)
from vulnspider.domain import (
    Endpoint,
    EphemeralRequestMaterial,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    RequestContextCompleteness,
    RequestTemplate,
    stable_fingerprint,
)

EXTRACTOR_VERSION = "native-static-html/1.1"
SCOPE_POLICY_VERSION = "same-origin-v1"

_NON_DATA_INPUT_TYPES = frozenset({"button", "image", "reset", "submit"})
# control_types marker for the fixed submit-gate parameter: it rides on the
# request but is never turned into an injectable InputPoint.
_SUBMIT_GATE_TYPE = "submit-gate"
_CHECKABLE_INPUT_TYPES = frozenset({"checkbox", "radio"})


@dataclass(frozen=True, slots=True)
class SensitiveFormElisionPolicy:
    """Opt into pre-canonical elision of structurally sensitive forms."""


@dataclass(frozen=True, slots=True)
class NavigableLink:
    """One HTTP(S) anchor observation, separate from later scope enforcement."""

    source_url: str
    raw_href: str
    resolved_url: str
    crawl_url: str
    raw_query: str
    occurrence_index: int
    id: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.raw_href:
            raise ValueError("raw_href must not be empty")
        if self.occurrence_index < 0:
            raise ValueError("occurrence_index must be non-negative")
        fingerprint = stable_fingerprint(
            "navigable-link",
            self.source_url,
            self.raw_href,
            self.resolved_url,
            self.crawl_url,
            self.occurrence_index,
        )
        object.__setattr__(self, "id", f"link_{fingerprint[:16]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_url": self.source_url,
            "raw_href": self.raw_href,
            "resolved_url": self.resolved_url,
            "crawl_url": self.crawl_url,
            "raw_query": self.raw_query,
            "occurrence_index": self.occurrence_index,
        }


@dataclass(frozen=True, slots=True)
class StaticExtractionResult:
    """Immutable output from one HTML document with no transport behavior."""

    source_url: str
    navigable_links: tuple[NavigableLink, ...]
    discovery: CanonicalDiscoveryResult

    def __post_init__(self) -> None:
        if type(self.navigable_links) is not tuple or any(
            type(item) is not NavigableLink for item in self.navigable_links
        ):
            raise TypeError("navigable_links must be a tuple of NavigableLink")
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
        if any(item.source_url != self.source_url for item in self.navigable_links):
            raise ValueError("navigable link source ownership mismatch")
        self.discovery.validate()

    @property
    def warnings(self) -> tuple[DiscoveryWarning, ...]:
        return self.discovery.warnings

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "navigable_links": [
                item.to_dict() for item in self.navigable_links
            ],
            "discovery": self.discovery.to_dict(),
        }


@dataclass(slots=True)
class _RawControl:
    name: str
    type_hint: str
    values: tuple[str, ...]
    hidden: bool
    control_index: int


@dataclass(slots=True)
class _RawOption:
    raw_value: str | None
    selected: bool
    disabled: bool
    text_parts: list[str] = field(default_factory=list)

    def value(self) -> str:
        if self.raw_value is not None:
            return self.raw_value
        return " ".join("".join(self.text_parts).split())


@dataclass(slots=True)
class _ActiveTextarea:
    name: str | None
    disabled: bool
    control_index: int
    text_parts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _ActiveSelect:
    name: str | None
    disabled: bool
    multiple: bool
    control_index: int
    options: list[_RawOption] = field(default_factory=list)
    option: _RawOption | None = None


@dataclass(slots=True)
class _RawForm:
    occurrence_index: int
    raw_method: str | None
    raw_action: str | None
    sensitive: bool = False
    controls: list[_RawControl] = field(default_factory=list)
    malformed_reasons: set[str] = field(default_factory=set)
    closed: bool = False
    submit_gate: tuple[str, str] | None = None
    """First named submit control ``(name, value)`` a browser would activate.

    A browser submitting a form sends the activated submit control's
    ``name=value`` alongside the data fields, and many handlers gate on it
    (``if (isset($_GET['Submit']))`` -- DVWA's SQLi page is exactly this). It is
    carried as a fixed request parameter but never becomes an injectable
    InputPoint. Only the first named submit is kept, because a browser sends
    exactly one. Unnamed submits send nothing and are ignored.
    """


@dataclass(slots=True)
class _PointState:
    candidate: InputPoint
    baseline_values: set[str] = field(default_factory=set)
    type_hints: set[str] = field(default_factory=set)
    raw_query_tokens: set[str] = field(default_factory=set)
    origin_kinds: set[str] = field(default_factory=set)
    pair_indices: set[int] = field(default_factory=set)
    control_indices: set[int] = field(default_factory=set)
    hidden: bool = False


class _SensitiveFormClassifier(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.form_count = 0
        self.form_occurrence: int | None = None
        self.sensitive_form_occurrences: set[int] = set()

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "form":
            self.form_occurrence = self.form_count
            self.form_count += 1
            return
        if (
            tag == "input"
            and self.form_occurrence is not None
            and _normalized_input_type(attrs) == "password"
        ):
            self.sensitive_form_occurrences.add(self.form_occurrence)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        if tag == "form":
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.form_occurrence = None

    def finish(self) -> None:
        self.close()
        self.form_occurrence = None


class _StaticHtmlParser(HTMLParser):
    def __init__(
        self,
        *,
        sensitive_form_occurrences: frozenset[int] = frozenset(),
    ) -> None:
        super().__init__(convert_charrefs=True)
        self.raw_links: list[str | None] = []
        self.forms: list[_RawForm] = []
        self.warnings: list[tuple[str, str, dict[str, Any]]] = []
        self.form: _RawForm | None = None
        self.textarea: _ActiveTextarea | None = None
        self.select: _ActiveSelect | None = None
        self._control_index = 0
        self._form_occurrence_count = 0
        self._sensitive_form_occurrences = sensitive_form_occurrences

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if (
            self.form is not None
            and self.form.sensitive
            and tag in {"button", "input", "option", "select", "textarea"}
        ):
            return
        attributes = _attribute_map(attrs)
        if tag == "a":
            self.raw_links.append(attributes.get("href"))
            return
        if tag == "form":
            self._start_form(attributes)
            return
        if tag == "input":
            self._add_input(attributes)
            return
        if tag == "textarea":
            self._start_textarea(attributes)
            return
        if tag == "select":
            self._start_select(attributes)
            return
        if tag == "option":
            self._start_option(attributes)
            return
        if tag == "button" and self.form is not None:
            # A <button> defaults to type=submit; one with type=button/reset
            # does not submit. A named submitting button gates the handler just
            # like <input type=submit>, so carry it as a fixed parameter.
            button_type = (attributes.get("type") or "submit").strip().lower()
            button_name = _non_empty_attribute(attributes, "name")
            if button_type == "submit" and button_name is not None:
                self._record_submit_gate(
                    button_name, attributes.get("value") or ""
                )
            self._warn_control(
                "FORM_CONTROL_NON_DATA",
                "button control is not an injectable successful control",
                attributes,
            )

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        if tag in {"form", "option", "select", "textarea"}:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "option":
            self._finish_option()
        elif tag == "select":
            self._finish_select()
        elif tag == "textarea":
            self._finish_textarea()
        elif tag == "form":
            self._finish_form(closed=True)

    def handle_data(self, data: str) -> None:
        if self.select is not None and self.select.option is not None:
            self.select.option.text_parts.append(data)
        elif self.textarea is not None:
            self.textarea.text_parts.append(data)

    def finish(self) -> None:
        self.close()
        if self.select is not None:
            if self.form is not None:
                self.form.malformed_reasons.add("unclosed-select")
            self._finish_select()
        if self.textarea is not None:
            if self.form is not None:
                self.form.malformed_reasons.add("unclosed-textarea")
            self._finish_textarea()
        if self.form is not None:
            self.form.malformed_reasons.add("unclosed-form")
            self._finish_form(closed=False)

    def _start_form(self, attributes: Mapping[str, str | None]) -> None:
        if self.form is not None:
            self.form.malformed_reasons.add("nested-form")
            self._finish_form(closed=False)
            nested_reason = {"nested-form"}
        else:
            nested_reason = set()
        occurrence_index = self._form_occurrence_count
        self._form_occurrence_count += 1
        self.form = _RawForm(
            occurrence_index=occurrence_index,
            raw_method=attributes.get("method"),
            raw_action=attributes.get("action"),
            sensitive=occurrence_index in self._sensitive_form_occurrences,
            malformed_reasons=nested_reason,
        )
        self._control_index = 0

    def _finish_form(self, *, closed: bool) -> None:
        if self.form is None:
            self.warnings.append(
                (
                    "FORM_END_WITHOUT_START",
                    "form end tag had no active form",
                    {},
                )
            )
            return
        if self.select is not None:
            self.form.malformed_reasons.add("unclosed-select")
            self._finish_select()
        if self.textarea is not None:
            self.form.malformed_reasons.add("unclosed-textarea")
            self._finish_textarea()
        self.form.closed = closed and not self.form.malformed_reasons
        self.forms.append(self.form)
        self.form = None
        self._control_index = 0

    def _add_input(self, attributes: Mapping[str, str | None]) -> None:
        if self.form is None:
            self._warn_control(
                "FORM_CONTROL_OUTSIDE_FORM",
                "input outside a form was not bound to a request context",
                attributes,
            )
            return
        control_index = self._next_control_index()
        if "disabled" in attributes:
            self._warn_control(
                "FORM_CONTROL_DISABLED",
                "disabled form control was skipped",
                attributes,
            )
            return
        name = _non_empty_attribute(attributes, "name")
        if name is None:
            self._warn_control(
                "FORM_CONTROL_NAME_MISSING",
                "form control without a name was skipped",
                attributes,
            )
            return
        type_hint = (attributes.get("type") or "text").strip().lower() or "text"
        if type_hint == "file":
            self._warn_control(
                "FORM_CONTROL_FILE_UNSUPPORTED",
                "file input was recorded as unsupported and not transmitted",
                attributes,
            )
            return
        if type_hint in _NON_DATA_INPUT_TYPES:
            if type_hint == "submit":
                # A named submit button gates the handler; carry it as a fixed
                # request parameter (never an injectable input point).
                self._record_submit_gate(name, attributes.get("value") or "")
            self._warn_control(
                "FORM_CONTROL_NON_DATA",
                "non-data form control was skipped",
                attributes,
            )
            return
        if type_hint in _CHECKABLE_INPUT_TYPES and "checked" not in attributes:
            self._warn_control(
                "FORM_CONTROL_UNCHECKED",
                "unchecked checkbox or radio control was skipped",
                attributes,
            )
            return
        if type_hint in _CHECKABLE_INPUT_TYPES:
            value = (
                attributes["value"]
                if "value" in attributes and attributes["value"] is not None
                else "on"
            )
        else:
            value = attributes.get("value") or ""
        self.form.controls.append(
            _RawControl(
                name=name,
                type_hint=type_hint,
                values=(value,),
                hidden=type_hint == "hidden",
                control_index=control_index,
            )
        )

    def _start_textarea(self, attributes: Mapping[str, str | None]) -> None:
        if self.form is None:
            self._warn_control(
                "FORM_CONTROL_OUTSIDE_FORM",
                "textarea outside a form was not bound to a request context",
                attributes,
            )
            return
        if self.textarea is not None:
            self.form.malformed_reasons.add("nested-textarea")
            self._finish_textarea()
        self.textarea = _ActiveTextarea(
            name=_non_empty_attribute(attributes, "name"),
            disabled="disabled" in attributes,
            control_index=self._next_control_index(),
        )

    def _finish_textarea(self) -> None:
        if self.textarea is None:
            return
        active = self.textarea
        self.textarea = None
        if self.form is None:
            return
        if active.disabled:
            self.warnings.append(
                (
                    "FORM_CONTROL_DISABLED",
                    "disabled textarea was skipped",
                    {"control_type": "textarea"},
                )
            )
            return
        if active.name is None:
            self.warnings.append(
                (
                    "FORM_CONTROL_NAME_MISSING",
                    "textarea without a name was skipped",
                    {"control_type": "textarea"},
                )
            )
            return
        self.form.controls.append(
            _RawControl(
                name=active.name,
                type_hint="textarea",
                values=("".join(active.text_parts),),
                hidden=False,
                control_index=active.control_index,
            )
        )

    def _start_select(self, attributes: Mapping[str, str | None]) -> None:
        if self.form is None:
            self._warn_control(
                "FORM_CONTROL_OUTSIDE_FORM",
                "select outside a form was not bound to a request context",
                attributes,
            )
            return
        if self.select is not None:
            self.form.malformed_reasons.add("nested-select")
            self._finish_select()
        self.select = _ActiveSelect(
            name=_non_empty_attribute(attributes, "name"),
            disabled="disabled" in attributes,
            multiple="multiple" in attributes,
            control_index=self._next_control_index(),
        )

    def _start_option(self, attributes: Mapping[str, str | None]) -> None:
        if self.select is None:
            return
        self._finish_option()
        self.select.option = _RawOption(
            raw_value=(
                attributes.get("value") if "value" in attributes else None
            ),
            selected="selected" in attributes,
            disabled="disabled" in attributes,
        )

    def _finish_option(self) -> None:
        if self.select is None or self.select.option is None:
            return
        self.select.options.append(self.select.option)
        self.select.option = None

    def _finish_select(self) -> None:
        if self.select is None:
            return
        self._finish_option()
        active = self.select
        self.select = None
        if self.form is None:
            return
        if active.disabled:
            self.warnings.append(
                (
                    "FORM_CONTROL_DISABLED",
                    "disabled select was skipped",
                    {"control_type": "select"},
                )
            )
            return
        if active.name is None:
            self.warnings.append(
                (
                    "FORM_CONTROL_NAME_MISSING",
                    "select without a name was skipped",
                    {"control_type": "select"},
                )
            )
            return
        enabled = [item for item in active.options if not item.disabled]
        if not enabled:
            self.warnings.append(
                (
                    "FORM_SELECT_OPTION_MISSING",
                    "select without an enabled option was skipped",
                    {"control_type": "select", "name": active.name},
                )
            )
            return
        if active.multiple:
            chosen = [item for item in enabled if item.selected]
        else:
            chosen = [next((item for item in enabled if item.selected), enabled[0])]
        if not chosen:
            self.warnings.append(
                (
                    "FORM_SELECT_SELECTION_MISSING",
                    "multiple select without a selected option was skipped",
                    {"control_type": "select", "name": active.name},
                )
            )
            return
        self.form.controls.append(
            _RawControl(
                name=active.name,
                type_hint="select",
                values=tuple(item.value() for item in chosen),
                hidden=False,
                control_index=active.control_index,
            )
        )

    def _next_control_index(self) -> int:
        current = self._control_index
        self._control_index += 1
        return current

    def _record_submit_gate(self, name: str, value: str) -> None:
        """Remember the first named submit control of the current form."""

        if self.form is None or self.form.submit_gate is not None:
            return
        self.form.submit_gate = (name, value)

    def _warn_control(
        self,
        code: str,
        message: str,
        attributes: Mapping[str, str | None],
    ) -> None:
        details: dict[str, Any] = {}
        name = _non_empty_attribute(attributes, "name")
        type_hint = _non_empty_attribute(attributes, "type")
        if name is not None:
            details["name"] = name
        if type_hint is not None:
            details["control_type"] = type_hint.lower()
        self.warnings.append((code, message, details))


class CanonicalDiscoveryBuilder:
    def __init__(
        self,
        *,
        source_url: str,
        metadata: DiscoveryMetadata,
        scope: ScopeMetadata,
        parent_url: str | None,
        depth: int,
        request_authorizer: Callable[[str], bool] | None,
        discovered_by: str | None = None,
        session_cookies: Mapping[str, str] | None = None,
    ) -> None:
        self.source_url = source_url
        self.metadata = metadata
        self.scope = scope
        self.parent_url = parent_url
        self.depth = depth
        self.request_authorizer = request_authorizer
        self.session_cookies = dict(session_cookies or {})
        self.native_metadata_key = (
            "native_dynamic"
            if metadata.collector_kind == CollectorKind.NATIVE_DYNAMIC
            else "native_static"
        )
        self.discovered_by = discovered_by or (
            "native_dynamic_rendered_dom"
            if metadata.collector_kind == CollectorKind.NATIVE_DYNAMIC
            else "native_static_html"
        )
        self.run_id = discovery_run_id_for(metadata, scope)
        self.endpoints: dict[str, Endpoint] = {}
        self.point_states: dict[str, _PointState] = {}
        self.templates: dict[str, RequestTemplate] = {}
        self.contexts: dict[str, InputPointRequestContext] = {}
        self.readiness: dict[str, ProbeReadiness] = {}
        self.warnings: dict[str, DiscoveryWarning] = {}
        self.skipped_observations = 0
        self.observations: dict[
            tuple[DiscoverySubjectKind, str],
            set[str],
        ] = {}

    def add_warning(
        self,
        code: str,
        message: str,
        details: Mapping[str, Any] | None = None,
        *,
        skipped: bool = True,
    ) -> None:
        if skipped:
            self.skipped_observations += 1
        warning = DiscoveryWarning(
            code=code,
            message=message,
            details=details or {},
        )
        self.warnings.setdefault(warning.id or "", warning)

    def add_url_surface(
        self,
        url: str,
        *,
        observation_key: str,
        query_origin_kind: str = "query",
    ) -> None:
        endpoint = self._add_endpoint(
            url,
            method=HttpMethod.GET,
            observation_key=observation_key,
        )
        occurrences = _query_occurrences(urlsplit(url).query)
        if not occurrences:
            return
        self._add_template_with_points(
            endpoint=endpoint,
            url=url,
            method=HttpMethod.GET,
            query_occurrences=occurrences,
            form_controls=(),
            context_key=(
                "native-query:"
                + stable_fingerprint("native-query", url)[:16]
            ),
            provenance=(("query", "raw-url"),),
            metadata={
                "context_kind": "query",
                "raw_query": urlsplit(url).query,
                "source_page": self.source_url,
            },
            observation_key=f"query:{observation_key}",
            ready=True,
            not_ready_reasons=(),
            query_origin_kind=query_origin_kind,
        )

    def add_structural_query_surface(
        self,
        url: str,
        *,
        query_parameter_names: Sequence[str],
        observation_key: str,
        not_ready_reasons: Sequence[NonProbeReadyReason],
        query_origin_kind: str,
    ) -> None:
        """Add value-free query structure with no executable request context."""

        endpoint = self._add_endpoint(
            url,
            method=HttpMethod.GET,
            observation_key=observation_key,
        )
        canonical_names = tuple(
            _canonical_input_name(name) for name in query_parameter_names
        )
        counts = Counter(name for name in canonical_names if name)
        seen: dict[str, int] = {}
        for pair_index, canonical_name in enumerate(canonical_names):
            if not canonical_name:
                self.add_warning(
                    "QUERY_PARAMETER_NAME_MISSING",
                    "query occurrence without a name was not made injectable",
                    {"pair_index": pair_index},
                )
                continue
            occurrence_index = (
                seen.get(canonical_name, 0) if counts[canonical_name] > 1 else None
            )
            seen[canonical_name] = seen.get(canonical_name, 0) + 1
            point = InputPoint(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                location=InputLocation.QUERY,
                name=canonical_name,
                occurrence_index=occurrence_index,
                baseline_value=None,
                type_hint="query",
                source_page=self.source_url,
                metadata={
                    self.native_metadata_key: True,
                    "hidden": False,
                    "visibility": "visible",
                    "value_state": "elided",
                },
            )
            self._remember_point(
                point,
                raw_query_token=None,
                origin_kind=query_origin_kind,
                pair_index=pair_index,
                control_index=-1,
                hidden=False,
            )
            status = ProbeReadiness(
                input_point_id=point.id or "",
                request_context_id=None,
                status=ProbeReadyStatus.NOT_READY,
                reasons=tuple(not_ready_reasons),
            )
            self.readiness.setdefault(status.id or "", status)
            self._observe(
                DiscoverySubjectKind.INPUT_POINT,
                point.id or "",
                f"input:{observation_key}:query:{pair_index}",
            )

    def add_structural_json_body_surface(
        self,
        url: str,
        *,
        member_names: Sequence[str],
        observation_key: str,
        not_ready_reasons: Sequence[NonProbeReadyReason],
        origin_kind: str,
        ephemeral_material: EphemeralRequestMaterial | None = None,
        replay_policy: PostReplayPolicyDecision,
    ) -> None:
        """Add persistent JSON structure and an optional replay-only sidecar."""

        endpoint = self._add_endpoint(
            url,
            method=HttpMethod.POST,
            observation_key=observation_key,
        )
        canonical_names = tuple(
            canonical_name
            for name in member_names
            if (canonical_name := _canonical_input_name(name))
        )
        if type(replay_policy) is not PostReplayPolicyDecision:
            raise TypeError("POST JSON surface requires a replay policy decision")
        if (
            replay_policy.disposition == PostReplayDisposition.SAFE_FOR_PROBE
            and ephemeral_material is None
        ):
            replay_policy = PostReplayPolicyDecision(
                disposition=PostReplayDisposition.STRUCTURAL_ONLY,
                reason_code=PostReplayReasonCode.RECONSTRUCTION_INCOMPLETE,
            )
        ready = replay_policy.disposition == PostReplayDisposition.SAFE_FOR_PROBE
        if not ready:
            ephemeral_material = None
        policy_not_ready_reasons: tuple[NonProbeReadyReason, ...] = ()
        if not ready:
            if (
                replay_policy.reason_code
                == PostReplayReasonCode.POLICY_ASSESSMENT_FAILED
            ):
                policy_not_ready_reasons = (
                    NonProbeReadyReason.POST_POLICY_ASSESSMENT_FAILED,
                )
            elif (
                replay_policy.disposition
                == PostReplayDisposition.BLOCKED_SENSITIVE
            ):
                policy_not_ready_reasons = (
                    NonProbeReadyReason.POST_POLICY_BLOCKED_SENSITIVE,
                )
            else:
                policy_not_ready_reasons = (
                    NonProbeReadyReason.POST_POLICY_STRUCTURAL_ONLY,
                )
        effective_not_ready_reasons = tuple(
            sorted(
                set(not_ready_reasons).union(policy_not_ready_reasons),
                key=lambda item: item.value,
            )
        )
        if ephemeral_material is not None:
            if tuple(
                sorted(
                    _canonical_input_name(name)
                    for name, _ in ephemeral_material.json_body
                )
            ) != tuple(sorted(canonical_names)):
                raise DiscoveryContractError(
                    "JSON replay material does not align with structural names"
                )
        structural_pairs = tuple((name, "null") for name in canonical_names)
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url=url,
            query=tuple(parse_qsl(urlsplit(url).query, keep_blank_values=True)),
            json_body=structural_pairs,
            completeness=(
                RequestContextCompleteness.COMPLETE
                if ready
                else RequestContextCompleteness.UNKNOWN
            ),
            context_key=f"json:{observation_key}",
            provenance=(("json_body", "browser-request-body"),),
            metadata={
                "context_kind": "json_body",
                "content_type": "application/json",
                "source_page": self.source_url,
                "reconstruction_status": "complete" if ready else "policy_withheld",
                "json_value_encoding": "canonical-json-text",
                "replay_material_state": "ephemeral" if ready else "withheld_by_policy",
                "post_replay_disposition": replay_policy.disposition.value,
                "post_replay_reason": replay_policy.reason_code.value,
                "non_probe_ready_reasons": tuple(
                    item.value for item in effective_not_ready_reasons
                ),
            },
            ephemeral_material=ephemeral_material,
        )
        stored_template = self.templates.setdefault(template.id or "", template)
        self._observe(
            DiscoverySubjectKind.REQUEST_TEMPLATE,
            stored_template.id or "",
            f"template:{observation_key}",
        )
        for member_index, canonical_name in enumerate(canonical_names):
            point = InputPoint(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                location=InputLocation.JSON_BODY,
                name=canonical_name,
                occurrence_index=None,
                baseline_value=None,
                type_hint="json",
                source_page=self.source_url,
                metadata={
                    self.native_metadata_key: True,
                    "hidden": False,
                    "visibility": "network_observed" if ready else "structural_only",
                    "value_state": "ephemeral" if ready else "elided",
                    "post_replay_disposition": replay_policy.disposition.value,
                    "post_replay_reason": replay_policy.reason_code.value,
                },
            )
            self._remember_point(
                point,
                raw_query_token=None,
                origin_kind=origin_kind,
                pair_index=member_index,
                control_index=-1,
                hidden=False,
            )
            self._bind(
                point,
                stored_template,
                observation_key=f"{observation_key}:json:{member_index}",
                ready=ready,
                not_ready_reasons=effective_not_ready_reasons,
            )

    def add_form(
        self,
        form: _RawForm,
        *,
        boundary_key: str,
    ) -> None:
        method, method_provenance = _form_method(form.raw_method)
        if method is None:
            self.add_warning(
                "FORM_METHOD_UNSUPPORTED",
                "form method is not supported by the canonical request model",
                {"method": (form.raw_method or "").strip().upper()},
            )
            return
        try:
            action_url, _ = _resolve_http_url(
                form.raw_action or "",
                base_url=self.source_url,
                default_to_base=True,
            )
        except ValueError:
            self.add_warning(
                "FORM_ACTION_MALFORMED",
                "malformed form action was skipped",
                {
                    "action_fingerprint": _redacted_url_fingerprint(
                        form.raw_action or ""
                    )
                },
            )
            return
        if not _same_http_origin(self.scope.root_url, action_url):
            self.add_warning(
                "OFF_SCOPE_FORM_ACTION",
                "Cross-origin form action was excluded from request construction.",
                {
                    "action_fingerprint": _redacted_url_fingerprint(action_url),
                    "reason": "EXACT_ORIGIN_MISMATCH",
                },
            )
            return
        action_provenance = (
            "explicit"
            if form.raw_action is not None and form.raw_action.strip()
            else "html_default_current_document"
        )
        complete = form.closed and not form.malformed_reasons
        boundary_status = "stable" if complete else "unavailable"
        controls_status = "complete" if complete else "partial"
        not_ready_reasons = (
            ()
            if complete
            else (
                NonProbeReadyReason.FORM_BOUNDARY_UNAVAILABLE,
                NonProbeReadyReason.REQUEST_CONTEXT_PARTIAL,
            )
        )
        expanded_controls = tuple(
            (control, value)
            for control in form.controls
            for value in control.values
        )
        pairs = tuple(
            (control.name, value) for control, value in expanded_controls
        )
        provenance: list[tuple[str, str]] = [
            ("form_method", method_provenance),
            ("form_action", action_provenance),
            ("form_boundary", boundary_status),
            ("form_controls", controls_status),
            ("form_method_raw", form.raw_method or ""),
            ("form_action_raw", form.raw_action or ""),
            ("form_action_resolved", action_url),
        ]
        metadata: dict[str, Any] = {
            "context_kind": "form",
            "source_page": self.source_url,
            "form_method_provenance": method_provenance,
            "form_action_provenance": action_provenance,
            "form_boundary_status": boundary_status,
            "form_boundary_key": boundary_key,
            "form_grouping_policy": "native_stable_form_boundary",
            "hidden_input_policy": (
                "native_all_successful_controls_preserved"
                if complete
                else "native_form_boundary_incomplete"
            ),
            "reconstruction_status": "complete" if complete else "partial",
            "non_probe_ready_reasons": tuple(
                item.value for item in not_ready_reasons
            ),
        }
        if form.malformed_reasons:
            metadata["malformed_reasons"] = tuple(
                sorted(form.malformed_reasons)
            )
            self.add_warning(
                "FORM_BOUNDARY_MALFORMED",
                "malformed form boundary was preserved as non-probe-ready",
                {"reasons": tuple(sorted(form.malformed_reasons))},
                skipped=False,
            )

        # The activated submit button's name=value rides on the request as a
        # fixed parameter (a browser sends it), gating handlers like DVWA's, but
        # is never made an injectable input point.
        gate_pairs = (form.submit_gate,) if form.submit_gate is not None else ()
        gate_control_types = (
            ((_SUBMIT_GATE_TYPE, False, -1),)
            if form.submit_gate is not None
            else ()
        )

        observation_key = f"form:{boundary_key}"
        if method == HttpMethod.GET:
            encoded_query = urlencode(pairs + gate_pairs)
            parts = urlsplit(action_url)
            request_url = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, encoded_query, "")
            )
            query_occurrences = _query_occurrences(encoded_query)
            provenance.append(("query", "raw-url"))
            endpoint = self._add_endpoint(
                request_url,
                method=method,
                observation_key=observation_key,
            )
            self._add_template_with_points(
                endpoint=endpoint,
                url=request_url,
                method=method,
                query_occurrences=query_occurrences,
                form_controls=(),
                control_types=tuple(
                    (
                        control.type_hint,
                        control.hidden,
                        control.control_index,
                    )
                    for control, _ in expanded_controls
                )
                + gate_control_types,
                context_key=boundary_key,
                provenance=tuple(provenance),
                metadata=metadata,
                observation_key=observation_key,
                ready=complete,
                not_ready_reasons=not_ready_reasons,
            )
            return

        endpoint = self._add_endpoint(
            action_url,
            method=method,
            observation_key=observation_key,
        )
        action_query = _query_occurrences(urlsplit(action_url).query)
        if action_query:
            provenance.append(("query", "raw-url"))
        gate_controls = (
            (
                (
                    _RawControl(
                        name=form.submit_gate[0],
                        type_hint=_SUBMIT_GATE_TYPE,
                        values=(form.submit_gate[1],),
                        hidden=False,
                        control_index=-1,
                    ),
                    form.submit_gate[1],
                ),
            )
            if form.submit_gate is not None
            else ()
        )
        self._add_template_with_points(
            endpoint=endpoint,
            url=action_url,
            method=method,
            query_occurrences=action_query,
            form_controls=expanded_controls + gate_controls,
            context_key=boundary_key,
            provenance=tuple(provenance),
            metadata=metadata,
            observation_key=observation_key,
            ready=complete,
            not_ready_reasons=not_ready_reasons,
        )

    def build(
        self,
        *,
        link_count: int,
        form_count: int,
        safety_invariants: Sequence[DiscoverySafetyInvariant] = (),
        pages_processed: int = 1,
        html_pages: int = 1,
    ) -> CanonicalDiscoveryResult:
        points = self._finalize_points()
        provenance: list[DiscoveryProvenance] = []
        for (kind, subject_id), observation_keys in sorted(
            self.observations.items(),
            key=lambda item: (item[0][0].value, item[0][1]),
        ):
            for key in sorted(observation_keys):
                provenance.append(
                    DiscoveryProvenance(
                        discovery_run_id=self.run_id,
                        subject_kind=kind,
                        subject_id=subject_id,
                        collector_kind=self.metadata.collector_kind,
                        source_url=self.source_url,
                        parent_url=self.parent_url,
                        depth=self.depth,
                        collector_observation_key=key,
                    )
                )
        statistics = CrawlStatistics(
            pages_processed=pages_processed,
            html_pages=html_pages,
            links_discovered=link_count,
            forms_discovered=form_count,
            skipped=self.skipped_observations,
            max_depth_reached=self.depth,
            page_budget=1,
            depth_budget=self.depth,
            endpoint_count=len(self.endpoints),
            input_point_count=len(points),
            request_template_count=len(self.templates),
            request_context_count=len(self.contexts),
        )
        return CanonicalDiscoveryResult.create(
            discovery_metadata=self.metadata,
            scope_metadata=self.scope,
            crawl_statistics=statistics,
            endpoints=tuple(self.endpoints.values()),
            input_points=points,
            request_templates=tuple(self.templates.values()),
            input_point_request_contexts=tuple(self.contexts.values()),
            probe_readiness=tuple(self.readiness.values()),
            crawl_provenance=tuple(provenance),
            warnings=tuple(self.warnings.values()),
            safety_invariants=safety_invariants,
        )

    def _add_endpoint(
        self,
        url: str,
        *,
        method: HttpMethod,
        observation_key: str,
    ) -> Endpoint:
        parts = urlsplit(url)
        endpoint = Endpoint(
            method=method,
            scheme=parts.scheme,
            host=parts.netloc,
            path=parts.path or "/",
            discovered_by=self.discovered_by,
        )
        stored = self.endpoints.setdefault(endpoint.id or "", endpoint)
        self._observe(
            DiscoverySubjectKind.ENDPOINT,
            stored.id or "",
            f"endpoint:{observation_key}",
        )
        return stored

    def _add_template_with_points(
        self,
        *,
        endpoint: Endpoint,
        url: str,
        method: HttpMethod,
        query_occurrences: tuple[tuple[str, str, str], ...],
        form_controls: tuple[tuple[_RawControl, str], ...],
        context_key: str,
        provenance: tuple[tuple[str, str], ...],
        metadata: Mapping[str, Any],
        observation_key: str,
        ready: bool,
        not_ready_reasons: Sequence[NonProbeReadyReason],
        control_types: tuple[tuple[str, bool, int], ...] = (),
        query_origin_kind: str | None = None,
    ) -> None:
        context_complete = ready
        effective_reasons = tuple(not_ready_reasons)
        if self.request_authorizer is not None:
            try:
                authorized = self.request_authorizer(url) is True
            except Exception:  # noqa: BLE001 - authority ambiguity fails closed.
                authorized = False
            if not authorized:
                ready = False
                effective_reasons = tuple(
                    sorted(
                        set(effective_reasons)
                        | {NonProbeReadyReason.REQUEST_NOT_AUTHORIZED},
                        key=lambda item: item.value,
                    )
                )
                metadata = {
                    **metadata,
                    "non_probe_ready_reasons": tuple(
                        item.value for item in effective_reasons
                    ),
                }
        query_pairs = tuple(
            (name, value) for name, value, _ in query_occurrences
        )
        form_pairs = tuple(
            (control.name, value) for control, value in form_controls
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=method,
            url=url,
            query=query_pairs,
            form=form_pairs,
            cookies=self.session_cookies,
            completeness=(
                RequestContextCompleteness.COMPLETE
                if context_complete
                else RequestContextCompleteness.PARTIAL
            ),
            context_key=context_key,
            provenance=provenance,
            metadata=metadata,
        )
        stored_template = self.templates.setdefault(
            template.id or "",
            template,
        )
        self._observe(
            DiscoverySubjectKind.REQUEST_TEMPLATE,
            stored_template.id or "",
            f"template:{observation_key}",
        )

        query_counts = Counter(
            canonical_name
            for name, _, _ in query_occurrences
            if (canonical_name := _canonical_input_name(name))
        )
        query_seen: dict[str, int] = {}
        for pair_index, (name, value, raw_token) in enumerate(query_occurrences):
            canonical_name = _canonical_input_name(name)
            if not canonical_name:
                self.add_warning(
                    "QUERY_PARAMETER_NAME_MISSING",
                    "query occurrence without a name was not made injectable",
                    {"pair_index": pair_index},
                )
                continue
            if pair_index < len(control_types):
                type_hint, hidden, control_index = control_types[pair_index]
            else:
                type_hint, hidden, control_index = ("query", False, -1)
            if type_hint == _SUBMIT_GATE_TYPE:
                # Fixed submit parameter: carried on the request template's
                # query above, but not an injectable input point.
                continue
            occurrence_index = (
                query_seen.get(canonical_name, 0)
                if query_counts[canonical_name] > 1
                else None
            )
            query_seen[canonical_name] = query_seen.get(canonical_name, 0) + 1
            point = InputPoint(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                location=InputLocation.QUERY,
                name=canonical_name,
                occurrence_index=occurrence_index,
                baseline_value=value,
                type_hint=type_hint,
                source_page=self.source_url,
                metadata={
                    self.native_metadata_key: True,
                    "hidden": hidden,
                    "visibility": "hidden" if hidden else "visible",
                },
            )
            self._remember_point(
                point,
                raw_query_token=raw_token,
                origin_kind=(
                    query_origin_kind
                    or (
                        "form"
                        if metadata.get("context_kind") == "form"
                        else "query"
                    )
                ),
                pair_index=pair_index,
                control_index=control_index,
                hidden=hidden,
            )
            self._bind(
                point,
                stored_template,
                observation_key=f"{observation_key}:query:{pair_index}",
                ready=ready,
                not_ready_reasons=effective_reasons,
            )

        form_counts = Counter(
            _canonical_input_name(control.name)
            for control, _ in form_controls
        )
        form_seen: dict[str, int] = {}
        for pair_index, (control, value) in enumerate(form_controls):
            if control.type_hint == _SUBMIT_GATE_TYPE:
                # Fixed submit parameter: carried on the request template's form
                # body above, but not an injectable input point.
                continue
            canonical_name = _canonical_input_name(control.name)
            occurrence_index = (
                form_seen.get(canonical_name, 0)
                if form_counts[canonical_name] > 1
                else None
            )
            form_seen[canonical_name] = form_seen.get(canonical_name, 0) + 1
            point = InputPoint(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                location=InputLocation.FORM,
                name=canonical_name,
                occurrence_index=occurrence_index,
                baseline_value=value,
                type_hint=control.type_hint,
                source_page=self.source_url,
                metadata={
                    self.native_metadata_key: True,
                    "hidden": control.hidden,
                    "visibility": "hidden" if control.hidden else "visible",
                },
            )
            self._remember_point(
                point,
                raw_query_token=None,
                origin_kind="form",
                pair_index=pair_index,
                control_index=control.control_index,
                hidden=control.hidden,
            )
            self._bind(
                point,
                stored_template,
                observation_key=f"{observation_key}:form:{pair_index}",
                ready=ready,
                not_ready_reasons=effective_reasons,
            )

    def _remember_point(
        self,
        point: InputPoint,
        *,
        raw_query_token: str | None,
        origin_kind: str,
        pair_index: int,
        control_index: int,
        hidden: bool,
    ) -> None:
        key = point.id or ""
        state = self.point_states.get(key)
        if state is None:
            state = _PointState(candidate=point)
            self.point_states[key] = state
        if point.baseline_value is not None:
            state.baseline_values.add(point.baseline_value)
        if point.type_hint is not None:
            state.type_hints.add(point.type_hint)
        if raw_query_token is not None:
            state.raw_query_tokens.add(raw_query_token)
        state.origin_kinds.add(origin_kind)
        state.pair_indices.add(pair_index)
        if control_index >= 0:
            state.control_indices.add(control_index)
        state.hidden = state.hidden or hidden

    def _bind(
        self,
        point: InputPoint,
        template: RequestTemplate,
        *,
        observation_key: str,
        ready: bool,
        not_ready_reasons: Sequence[NonProbeReadyReason],
    ) -> None:
        context = InputPointRequestContext.from_objects(point, template)
        stored_context = self.contexts.setdefault(context.id, context)
        status = ProbeReadiness(
            input_point_id=point.id or "",
            request_context_id=stored_context.id,
            status=(
                ProbeReadyStatus.READY
                if ready
                else ProbeReadyStatus.NOT_READY
            ),
            reasons=tuple(not_ready_reasons),
        )
        self.readiness.setdefault(status.id or "", status)
        self._observe(
            DiscoverySubjectKind.INPUT_POINT,
            point.id or "",
            f"input:{observation_key}",
        )
        self._observe(
            DiscoverySubjectKind.REQUEST_CONTEXT,
            stored_context.id,
            f"context:{observation_key}",
        )

    def _observe(
        self,
        kind: DiscoverySubjectKind,
        subject_id: str,
        observation_key: str,
    ) -> None:
        self.observations.setdefault((kind, subject_id), set()).add(
            observation_key
        )

    def _finalize_points(self) -> tuple[InputPoint, ...]:
        points: list[InputPoint] = []
        for key in sorted(self.point_states):
            state = self.point_states[key]
            values = tuple(sorted(state.baseline_values))
            baseline_value = values[0] if len(values) == 1 else None
            type_hints = tuple(sorted(state.type_hints))
            metadata: dict[str, Any] = {
                self.native_metadata_key: True,
                "hidden": state.hidden,
                "visibility": "hidden" if state.hidden else "visible",
                "origin_kinds": tuple(sorted(state.origin_kinds)),
                "pair_indices": tuple(sorted(state.pair_indices)),
                "control_indices": tuple(sorted(state.control_indices)),
            }
            raw_tokens = tuple(sorted(state.raw_query_tokens))
            if len(raw_tokens) == 1:
                metadata["raw_query_token"] = raw_tokens[0]
            elif raw_tokens:
                metadata["raw_query_tokens"] = raw_tokens
            points.append(
                replace(
                    state.candidate,
                    baseline_value=baseline_value,
                    baseline_values=values,
                    type_hint=type_hints[0] if len(type_hints) == 1 else None,
                    metadata=metadata,
                )
            )
        return tuple(points)


def extract_static_html(
    html: str,
    source_url: str,
    *,
    discovery_metadata: DiscoveryMetadata | None = None,
    scope_metadata: ScopeMetadata | None = None,
    parent_url: str | None = None,
    depth: int = 0,
    sensitive_form_policy: SensitiveFormElisionPolicy | None = None,
    request_authorizer: Callable[[str], bool] | None = None,
    safety_invariants: Sequence[DiscoverySafetyInvariant] = (),
    session_cookies: Mapping[str, str] | tuple[tuple[str, str], ...] = (),
) -> StaticExtractionResult:
    """Extract one HTML string without fetching, submitting, or executing it.

    ``session_cookies`` are attached to every produced ``RequestTemplate`` so a
    downstream access-control check can strip them. They are the operator's
    authenticated session; extraction still never fetches or submits anything.
    """

    if type(html) is not str:
        raise TypeError("html must be a string")
    if type(source_url) is not str:
        raise TypeError("source_url must be a string")
    if type(depth) is not int or depth < 0:
        raise ValueError("depth must be a non-negative integer")
    if sensitive_form_policy is not None and (
        type(sensitive_form_policy) is not SensitiveFormElisionPolicy
    ):
        raise TypeError(
            "sensitive_form_policy must be a SensitiveFormElisionPolicy or None"
        )
    if request_authorizer is not None and not callable(request_authorizer):
        raise TypeError("request_authorizer must be callable or None")
    _, canonical_source = _resolve_http_url(source_url, base_url=None)
    canonical_parent = None
    if parent_url is not None:
        if type(parent_url) is not str:
            raise TypeError("parent_url must be a string")
        _, canonical_parent = _resolve_http_url(parent_url, base_url=None)

    metadata = discovery_metadata or DiscoveryMetadata(
        collector_kind=CollectorKind.NATIVE_STATIC,
        collector_version=EXTRACTOR_VERSION,
        configuration_fingerprint=stable_fingerprint(
            "native-static-html-policy",
            EXTRACTOR_VERSION,
        ),
    )
    metadata.validate()
    if metadata.collector_kind not in {
        CollectorKind.NATIVE_STATIC,
        CollectorKind.NATIVE_DYNAMIC,
    }:
        raise DiscoveryContractError(
            "HTML extractor requires Native Static or Native Dynamic metadata"
        )
    if (
        metadata.collector_kind == CollectorKind.NATIVE_DYNAMIC
        and sensitive_form_policy is None
    ):
        raise DiscoveryContractError(
            "Native Dynamic HTML extraction requires sensitive-form elision"
        )
    scope = scope_metadata or ScopeMetadata(
        target_scope_id=scope_id_for_root(
            canonical_source,
            policy_version=SCOPE_POLICY_VERSION,
        ),
        root_url=canonical_source,
        scope_policy_version=SCOPE_POLICY_VERSION,
    )
    scope.validate()

    sensitive_form_occurrences: frozenset[int] = frozenset()
    classified_form_count: int | None = None
    if sensitive_form_policy is not None:
        classifier = _SensitiveFormClassifier()
        classifier.feed(html)
        classifier.finish()
        sensitive_form_occurrences = frozenset(
            classifier.sensitive_form_occurrences
        )
        classified_form_count = classifier.form_count

    parser = _StaticHtmlParser(
        sensitive_form_occurrences=sensitive_form_occurrences
    )
    parser.feed(html)
    parser.finish()
    if (
        classified_form_count is not None
        and classified_form_count != len(parser.forms)
    ):
        raise ValueError(
            "sensitive form classification did not align with canonical parsing"
        )

    builder = CanonicalDiscoveryBuilder(
        source_url=canonical_source,
        metadata=metadata,
        scope=scope,
        parent_url=canonical_parent,
        depth=depth,
        request_authorizer=request_authorizer,
        session_cookies=dict(session_cookies),
    )
    builder.add_url_surface(
        canonical_source,
        observation_key=(
            "document:"
            + stable_fingerprint("source-document", canonical_source)[:16]
        ),
    )
    for code, message, details in parser.warnings:
        builder.add_warning(code, message, details)

    valid_links: list[tuple[str, str, str]] = []
    for raw_href in parser.raw_links:
        if raw_href is None:
            builder.add_warning(
                "LINK_HREF_MISSING",
                "anchor without href was skipped",
            )
            continue
        if not raw_href.strip():
            builder.add_warning(
                "LINK_HREF_EMPTY",
                "anchor with empty href was skipped",
            )
            continue
        try:
            raw_parts = urlsplit(raw_href)
        except ValueError:
            builder.add_warning(
                "LINK_URL_MALFORMED",
                "malformed anchor URL was skipped",
                {"href_fingerprint": _redacted_url_fingerprint(raw_href)},
            )
            continue
        if raw_parts.scheme and raw_parts.scheme.lower() not in {"http", "https"}:
            builder.add_warning(
                "LINK_SCHEME_UNSUPPORTED",
                "non-HTTP anchor was skipped",
                {
                    "href_fingerprint": _redacted_url_fingerprint(raw_href),
                    "scheme": raw_parts.scheme.lower(),
                },
            )
            continue
        try:
            resolved_url, crawl_url = _resolve_http_url(
                raw_href,
                base_url=canonical_source,
            )
        except ValueError:
            builder.add_warning(
                "LINK_URL_MALFORMED",
                "malformed anchor URL was skipped",
                {"href_fingerprint": _redacted_url_fingerprint(raw_href)},
            )
            continue
        valid_links.append((raw_href, resolved_url, crawl_url))

    link_seen: Counter[tuple[str, str, str]] = Counter()
    links: list[NavigableLink] = []
    for raw_href, resolved_url, crawl_url in valid_links:
        key = (raw_href, resolved_url, crawl_url)
        occurrence_index = link_seen[key]
        link_seen[key] += 1
        link = NavigableLink(
            source_url=canonical_source,
            raw_href=raw_href,
            resolved_url=resolved_url,
            crawl_url=crawl_url,
            raw_query=urlsplit(crawl_url).query,
            occurrence_index=occurrence_index,
        )
        if not _same_http_origin(scope.root_url, crawl_url):
            builder.add_warning(
                "OFF_SCOPE_LINK",
                "Cross-origin link was excluded from request construction.",
                {
                    "destination_fingerprint": stable_fingerprint(
                        "crawler-url", crawl_url
                    )[:16],
                    "link_id": link.id,
                    "reason": "EXACT_ORIGIN_MISMATCH",
                },
            )
            continue
        unsafe_token = authentication_state_change_token(crawl_url)
        if unsafe_token is not None:
            builder.add_warning(
                "UNSAFE_NAVIGATION_SUPPRESSED",
                "Authentication state-changing navigation was suppressed.",
                {
                    "action_token": unsafe_token,
                    "destination_fingerprint": stable_fingerprint(
                        "crawler-url", crawl_url
                    )[:16],
                    "link_id": link.id,
                    "reason": "AUTHENTICATION_STATE_CHANGE",
                },
            )
            continue
        if not automatic_navigation_within_root_path(
            scope.root_url,
            crawl_url,
        ):
            try:
                path_scope_granted = (
                    request_authorizer is not None
                    and request_authorizer(crawl_url) is True
                )
            except Exception:  # noqa: BLE001 - scope ambiguity fails closed.
                path_scope_granted = False
            if not path_scope_granted:
                builder.add_warning(
                    "OFF_PATH_SCOPE_LINK",
                    "Link was outside the implicit root path scope.",
                    {
                        "destination_fingerprint": stable_fingerprint(
                            "crawler-url", crawl_url
                        )[:16],
                        "link_id": link.id,
                        "reason": "ROOT_PATH_SCOPE_MISMATCH",
                    },
                )
                continue
        links.append(link)
        builder.add_url_surface(
            crawl_url,
            observation_key=f"link:{link.id}",
        )

    form_seen: Counter[str] = Counter()
    for raw_form in parser.forms:
        if raw_form.sensitive:
            builder.add_warning(
                "SENSITIVE_FORM_ELIDED",
                "sensitive form was elided before canonical construction",
                {
                    "depth": depth,
                    "form_occurrence_index": raw_form.occurrence_index,
                    "producer_kind": metadata.collector_kind.value,
                },
            )
            continue
        signature = _form_signature(raw_form)
        duplicate_index = form_seen[signature]
        form_seen[signature] += 1
        boundary_key = (
            f"native-form:{signature[:16]}:occurrence={duplicate_index}"
        )
        builder.add_form(raw_form, boundary_key=boundary_key)

    try:
        active_invariants = {
            DiscoverySafetyInvariant(item) for item in safety_invariants
        }
    except (TypeError, ValueError):
        raise DiscoveryContractError(
            "safety_invariants must contain canonical values"
        ) from None
    if sensitive_form_policy is not None:
        active_invariants.add(
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION
        )
    discovery = builder.build(
        link_count=len(valid_links),
        form_count=len(parser.forms),
        safety_invariants=tuple(
            sorted(active_invariants, key=lambda item: item.value)
        ),
    )
    ordered_links = tuple(
        sorted(
            links,
            key=lambda item: (
                item.crawl_url,
                item.raw_href,
                item.resolved_url,
                item.occurrence_index,
                item.id,
            ),
        )
    )
    return StaticExtractionResult(
        source_url=canonical_source,
        navigable_links=ordered_links,
        discovery=discovery,
    )


def extract_static_html_with_sensitive_form_elision(
    html: str,
    source_url: str,
    *,
    discovery_metadata: DiscoveryMetadata,
    scope_metadata: ScopeMetadata,
    parent_url: str | None,
    depth: int,
    session_cookies: tuple[tuple[str, str], ...] = (),
) -> StaticExtractionResult:
    """Extract Static HTML with the merge-required elision policy bound."""

    return extract_static_html(
        html,
        source_url,
        discovery_metadata=discovery_metadata,
        scope_metadata=scope_metadata,
        parent_url=parent_url,
        depth=depth,
        sensitive_form_policy=SensitiveFormElisionPolicy(),
        session_cookies=session_cookies,
    )


def _attribute_map(
    attrs: Sequence[tuple[str, str | None]],
) -> dict[str, str | None]:
    return {name.lower(): value for name, value in attrs}


def _normalized_input_type(
    attrs: Sequence[tuple[str, str | None]],
) -> str:
    raw_type: str | None = None
    for name, value in attrs:
        if name.lower() == "type":
            raw_type = value
    return (raw_type or "text").strip().lower() or "text"


def _non_empty_attribute(
    attributes: Mapping[str, str | None],
    name: str,
) -> str | None:
    value = attributes.get(name)
    if value is None or not value.strip():
        return None
    return value


def _resolve_http_url(
    raw_url: str,
    *,
    base_url: str | None,
    default_to_base: bool = False,
) -> tuple[str, str]:
    candidate = raw_url
    if default_to_base and not raw_url.strip():
        if base_url is None:
            raise ValueError("default URL requires a base URL")
        candidate = base_url
    elif base_url is not None:
        candidate = urljoin(base_url, raw_url)
    try:
        parts = urlsplit(candidate)
        _ = parts.port
    except ValueError as exc:
        raise ValueError("malformed HTTP URL") from exc
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise ValueError("URL must be absolute HTTP(S)")
    if parts.hostname is None:
        raise ValueError("URL hostname must not be empty")
    if any(character.isspace() or ord(character) < 32 for character in candidate):
        raise ValueError("URL must not contain whitespace or control characters")
    resolved_url = urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc,
            parts.path or "/",
            parts.query,
            parts.fragment,
        )
    )
    crawl_url = urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc,
            parts.path or "/",
            parts.query,
            "",
        )
    )
    return resolved_url, crawl_url


def _same_http_origin(root_url: str, candidate_url: str) -> bool:
    """Compare exact scheme, normalized host, and effective port."""

    return _http_origin(root_url) == _http_origin(candidate_url)


def _http_origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname.casefold() if parts.hostname is not None else ""
    effective_port = parts.port or (80 if scheme == "http" else 443)
    return scheme, host, effective_port


def _query_occurrences(raw_query: str) -> tuple[tuple[str, str, str], ...]:
    if not raw_query:
        return ()
    occurrences: list[tuple[str, str, str]] = []
    for raw_token in raw_query.split("&"):
        if raw_token == "":
            continue
        parsed = parse_qsl(raw_token, keep_blank_values=True)
        if len(parsed) != 1:
            continue
        name, value = parsed[0]
        occurrences.append((name, value, raw_token))
    return tuple(occurrences)


def _canonical_input_name(name: str) -> str:
    return name.strip().lower()


def _redacted_url_fingerprint(raw_url: str) -> str:
    return stable_fingerprint("redacted-url", raw_url)[:16]


def _form_method(raw_method: str | None) -> tuple[HttpMethod | None, str]:
    if raw_method is None or not raw_method.strip():
        return HttpMethod.GET, "html_default_get"
    normalized = raw_method.strip().upper()
    if normalized == HttpMethod.GET.value:
        return HttpMethod.GET, "explicit"
    if normalized == HttpMethod.POST.value:
        return HttpMethod.POST, "explicit"
    return None, "unsupported"


def _form_signature(form: _RawForm) -> str:
    controls = tuple(
        (
            item.name,
            item.type_hint,
            item.values,
            item.hidden,
            item.control_index,
        )
        for item in form.controls
    )
    return stable_fingerprint(
        "native-form-boundary",
        form.raw_method,
        form.raw_action,
        controls,
        tuple(sorted(form.malformed_reasons)),
        form.closed,
    )
