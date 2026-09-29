"""Deterministic, value-free policy for observed POST replay eligibility."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import re
from urllib.parse import unquote

from vulnspider.domain import normalize_parameter_name
from vulnspider.sensitive import credential_field_name


_READ_ONLY_ENDPOINT_TOKENS = frozenset(
    {"autocomplete", "filter", "find", "lookup", "query", "search"}
)
_READ_ONLY_MEMBER_NAMES = frozenset(
    {"category", "filter", "keyword", "page", "q", "query", "search", "sort"}
)
_DIRECT_STATE_CHANGE_TOKENS = frozenset(
    {
        "checkout",
        "create",
        "delete",
        "logout",
        "mutate",
        "mutation",
        "purchase",
        "remove",
        "transfer",
        "update",
        "upload",
        "write",
    }
)
_MUTATION_CONTEXT_TOKENS = frozenset(
    {"account", "admin", "cart", "order", "orders", "password", "profile"}
)
_MUTATION_ACTION_TOKENS = frozenset(
    {
        "add",
        "approve",
        "assign",
        "cancel",
        "change",
        "clear",
        "close",
        "grant",
        "mutate",
        "mutation",
        "place",
        "promote",
        "reset",
        "revoke",
        "set",
        "submit",
    }
).union(_DIRECT_STATE_CHANGE_TOKENS)
_SEMANTIC_TOKEN = re.compile(r"[a-z0-9]+")
_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9a-fA-F]{2})")


class PostReplayDisposition(StrEnum):
    """The independent Gate 1C-B POST replay policy outcome."""

    SAFE_FOR_PROBE = "SAFE_FOR_PROBE"
    STRUCTURAL_ONLY = "STRUCTURAL_ONLY"
    BLOCKED_SENSITIVE = "BLOCKED_SENSITIVE"


class PostReplayReasonCode(StrEnum):
    """Stable primary reasons for one POST replay policy outcome."""

    MULTIPLE_READ_ONLY_SIGNALS = "MULTIPLE_READ_ONLY_SIGNALS"
    READ_ONLY_EVIDENCE_INSUFFICIENT = "READ_ONLY_EVIDENCE_INSUFFICIENT"
    SENSITIVE_FIELD_NAME = "SENSITIVE_FIELD_NAME"
    SENSITIVE_VALUE_MATERIAL = "SENSITIVE_VALUE_MATERIAL"
    SENSITIVE_HEADER = "SENSITIVE_HEADER"
    SENSITIVE_COOKIE = "SENSITIVE_COOKIE"
    METHOD_UNSUPPORTED = "METHOD_UNSUPPORTED"
    ORIGIN_NOT_AUTHORIZED = "ORIGIN_NOT_AUTHORIZED"
    PROVENANCE_UNSUPPORTED = "PROVENANCE_UNSUPPORTED"
    CONTENT_TYPE_UNSUPPORTED = "CONTENT_TYPE_UNSUPPORTED"
    CHARSET_UNSUPPORTED = "CHARSET_UNSUPPORTED"
    GRAPHQL_UNSUPPORTED = "GRAPHQL_UNSUPPORTED"
    JSON_TOP_LEVEL_NOT_OBJECT = "JSON_TOP_LEVEL_NOT_OBJECT"
    NO_INJECTABLE_TOP_LEVEL_MEMBER = "NO_INJECTABLE_TOP_LEVEL_MEMBER"
    NESTED_JSON_UNSUPPORTED = "NESTED_JSON_UNSUPPORTED"
    RECONSTRUCTION_INCOMPLETE = "RECONSTRUCTION_INCOMPLETE"
    STATE_CHANGING_SEMANTICS = "STATE_CHANGING_SEMANTICS"
    POLICY_ASSESSMENT_FAILED = "POLICY_ASSESSMENT_FAILED"


@dataclass(frozen=True, slots=True)
class PostReplayPolicyFeatures:
    """Normalized structural features; no request value or raw payload is retained."""

    method: str
    path: str
    member_names: tuple[str, ...]
    resource_type: str
    exact_authorized_loopback_origin: bool
    content_type: str
    charset: str
    top_level_json_object: bool
    scalar_top_level_values: bool
    reconstruction_complete: bool
    action_intent: str | None = None
    query_parameter_names: tuple[str, ...] = field(default_factory=tuple)
    header_names: tuple[str, ...] = field(default_factory=tuple)
    cookie_names: tuple[str, ...] = field(default_factory=tuple)
    graphql_semantics_present: bool = False
    credential_material_present: bool = False
    credential_header_present: bool = False
    credential_cookie_present: bool = False

    def __post_init__(self) -> None:
        method = _required_text(self.method, label="method").upper()
        path = _required_text(self.path, label="path")
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("POST replay path must be an absolute query-free path")
        if _INVALID_PERCENT_ENCODING.search(path):
            raise ValueError("POST replay path has invalid percent encoding")
        try:
            unquote(path, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("POST replay path is not valid UTF-8") from None
        resource_type = _required_text(
            self.resource_type,
            label="resource_type",
        ).lower()
        content_type = _required_text(
            self.content_type,
            label="content_type",
        ).lower()
        charset = _required_text(self.charset, label="charset").lower()
        if charset == "utf8":
            charset = "utf-8"
        action_intent = self.action_intent
        if action_intent is not None:
            action_intent = _camel_separated(
                _required_text(
                    action_intent,
                    label="action_intent",
                )
            ).lower()
        for label, value in (
            ("exact_authorized_loopback_origin", self.exact_authorized_loopback_origin),
            ("top_level_json_object", self.top_level_json_object),
            ("scalar_top_level_values", self.scalar_top_level_values),
            ("reconstruction_complete", self.reconstruction_complete),
            ("graphql_semantics_present", self.graphql_semantics_present),
            ("credential_material_present", self.credential_material_present),
            ("credential_header_present", self.credential_header_present),
            ("credential_cookie_present", self.credential_cookie_present),
        ):
            if type(value) is not bool:
                raise TypeError(f"{label} must be a bool")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "member_names", _canonical_names(self.member_names))
        object.__setattr__(self, "resource_type", resource_type)
        object.__setattr__(self, "content_type", content_type)
        object.__setattr__(self, "charset", charset)
        object.__setattr__(self, "action_intent", action_intent)
        object.__setattr__(
            self,
            "query_parameter_names",
            _canonical_names(self.query_parameter_names),
        )
        object.__setattr__(self, "header_names", _canonical_names(self.header_names))
        object.__setattr__(self, "cookie_names", _canonical_names(self.cookie_names))


@dataclass(frozen=True, slots=True)
class PostReplayPolicyDecision:
    """Deterministic disposition and its stable primary reason."""

    disposition: PostReplayDisposition
    reason_code: PostReplayReasonCode

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "disposition",
            PostReplayDisposition(self.disposition),
        )
        object.__setattr__(
            self,
            "reason_code",
            PostReplayReasonCode(self.reason_code),
        )


def classify_post_replay(
    features: PostReplayPolicyFeatures,
) -> PostReplayPolicyDecision:
    """Classify one value-free POST observation without changing execution state."""

    if type(features) is not PostReplayPolicyFeatures:
        raise TypeError("features must be PostReplayPolicyFeatures")

    field_names = (*features.member_names, *features.query_parameter_names)
    if any(credential_field_name(name) for name in field_names):
        return _decision(
            PostReplayDisposition.BLOCKED_SENSITIVE,
            PostReplayReasonCode.SENSITIVE_FIELD_NAME,
        )
    if features.credential_material_present:
        return _decision(
            PostReplayDisposition.BLOCKED_SENSITIVE,
            PostReplayReasonCode.SENSITIVE_VALUE_MATERIAL,
        )
    if features.credential_header_present or any(
        credential_field_name(name) for name in features.header_names
    ):
        return _decision(
            PostReplayDisposition.BLOCKED_SENSITIVE,
            PostReplayReasonCode.SENSITIVE_HEADER,
        )
    if features.credential_cookie_present or any(
        credential_field_name(name) for name in features.cookie_names
    ):
        return _decision(
            PostReplayDisposition.BLOCKED_SENSITIVE,
            PostReplayReasonCode.SENSITIVE_COOKIE,
        )

    structural_reason = _structural_reason(features)
    if structural_reason is not None:
        return _decision(
            PostReplayDisposition.STRUCTURAL_ONLY,
            structural_reason,
        )
    if _has_state_changing_semantics(features):
        return _decision(
            PostReplayDisposition.STRUCTURAL_ONLY,
            PostReplayReasonCode.STATE_CHANGING_SEMANTICS,
        )
    if _read_only_signal_count(features) < 2:
        return _decision(
            PostReplayDisposition.STRUCTURAL_ONLY,
            PostReplayReasonCode.READ_ONLY_EVIDENCE_INSUFFICIENT,
        )
    return _decision(
        PostReplayDisposition.SAFE_FOR_PROBE,
        PostReplayReasonCode.MULTIPLE_READ_ONLY_SIGNALS,
    )


def _structural_reason(
    features: PostReplayPolicyFeatures,
) -> PostReplayReasonCode | None:
    checks = (
        (features.method != "POST", PostReplayReasonCode.METHOD_UNSUPPORTED),
        (
            not features.exact_authorized_loopback_origin,
            PostReplayReasonCode.ORIGIN_NOT_AUTHORIZED,
        ),
        (
            features.resource_type not in {"fetch", "xhr"},
            PostReplayReasonCode.PROVENANCE_UNSUPPORTED,
        ),
        (
            features.content_type != "application/json",
            PostReplayReasonCode.CONTENT_TYPE_UNSUPPORTED,
        ),
        (features.charset != "utf-8", PostReplayReasonCode.CHARSET_UNSUPPORTED),
        (
            features.graphql_semantics_present
            or "graphql" in _path_semantic_tokens(features.path),
            PostReplayReasonCode.GRAPHQL_UNSUPPORTED,
        ),
        (
            not features.top_level_json_object,
            PostReplayReasonCode.JSON_TOP_LEVEL_NOT_OBJECT,
        ),
        (
            not features.member_names,
            PostReplayReasonCode.NO_INJECTABLE_TOP_LEVEL_MEMBER,
        ),
        (
            not features.scalar_top_level_values,
            PostReplayReasonCode.NESTED_JSON_UNSUPPORTED,
        ),
        (
            not features.reconstruction_complete,
            PostReplayReasonCode.RECONSTRUCTION_INCOMPLETE,
        ),
    )
    return next((reason for failed, reason in checks if failed), None)


def _read_only_signal_count(features: PostReplayPolicyFeatures) -> int:
    path_signal = bool(
        _path_semantic_tokens(features.path).intersection(_READ_ONLY_ENDPOINT_TOKENS)
    )
    action_signal = bool(
        _semantic_tokens(features.action_intent).intersection(
            _READ_ONLY_ENDPOINT_TOKENS
        )
    )
    member_signal = bool(
        set(features.member_names).intersection(_READ_ONLY_MEMBER_NAMES)
    )
    return sum((path_signal, action_signal, member_signal))


def _has_state_changing_semantics(features: PostReplayPolicyFeatures) -> bool:
    tokens = _path_semantic_tokens(features.path)
    tokens.update(_semantic_tokens(features.action_intent))
    names = (*features.member_names, *features.query_parameter_names)
    for name in names:
        tokens.update(_semantic_tokens(name))
    if tokens.intersection(_DIRECT_STATE_CHANGE_TOKENS):
        return True
    if (
        tokens.intersection(_MUTATION_CONTEXT_TOKENS)
        and tokens.intersection(_MUTATION_ACTION_TOKENS)
    ):
        return True
    return any(_has_concatenated_mutation_semantics(name) for name in names)


def _has_concatenated_mutation_semantics(value: str) -> bool:
    compact = "".join(_SEMANTIC_TOKEN.findall(value.lower()))
    return any(
        compact in {f"{context}{action}", f"{action}{context}"}
        for context in _MUTATION_CONTEXT_TOKENS
        for action in _MUTATION_ACTION_TOKENS
    )


def _semantic_tokens(value: str | None) -> set[str]:
    if value is None:
        return set()
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return set(_SEMANTIC_TOKEN.findall(separated.lower()))


def _path_semantic_tokens(path: str) -> set[str]:
    return _semantic_tokens(unquote(path, encoding="utf-8", errors="strict"))


def _required_text(value: object, *, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{label} must not contain surrounding whitespace")
    return value


def _canonical_names(values: tuple[str, ...]) -> tuple[str, ...]:
    if type(values) is not tuple or any(type(value) is not str for value in values):
        raise TypeError("policy names must be a tuple of strings")
    normalized = tuple(
        sorted(
            normalize_parameter_name(_camel_separated(value))
            for value in values
        )
    )
    if any(not value for value in normalized):
        raise ValueError("policy names must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ValueError("policy names must be unique after normalization")
    return normalized


def _camel_separated(value: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)


def _decision(
    disposition: PostReplayDisposition,
    reason_code: PostReplayReasonCode,
) -> PostReplayPolicyDecision:
    return PostReplayPolicyDecision(
        disposition=disposition,
        reason_code=reason_code,
    )
