"""Shared bounded credential-name and credential-material policy."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
import json
import re


_BASE64URL_SEGMENT = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_AUTHORIZATION_VALUE = re.compile(r"(?:bearer|basic)\s+\S+", re.IGNORECASE)
_API_CREDENTIAL_VALUES = (
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
)
_CREDENTIAL_FIELD_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "bearer",
        "bearer_token",
        "client_secret",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "csrf",
        "csrf_token",
        "id_token",
        "jsessionid",
        "jwt",
        "oauth_token",
        "passwd",
        "password",
        "password_confirm",
        "password_confirmation",
        "phpsessid",
        "private_key",
        "proxy_authorization",
        "pwd",
        "refresh_token",
        "secret",
        "secret_key",
        "session",
        "session_id",
        "session_key",
        "session_token",
        "sid",
        "token",
        "x_api_key",
        "x_csrf_token",
        "x_xsrf_token",
        "xsrf",
        "xsrf_token",
    }
)
_NESTED_CREDENTIAL_FIELD_SUFFIXES = _CREDENTIAL_FIELD_NAMES.difference(
    {"bearer", "cookie", "cookies", "secret", "session", "token"}
)


def credential_field_name(value: object) -> bool:
    """Return whether a field name is credential-bearing under Contract v1."""

    if not isinstance(value, str):
        return False
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    normalized = re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")
    return normalized in _CREDENTIAL_FIELD_NAMES or any(
        normalized.endswith(f"_{item}")
        for item in _NESTED_CREDENTIAL_FIELD_SUFFIXES
    )


def contains_credential_material(
    value: object,
    *,
    field_name: object = None,
    depth: int = 0,
) -> bool:
    """Detect bounded credential material without changing the shared policy."""

    if depth > 20:
        return True
    if credential_field_name(field_name) and _has_material(value):
        return True
    if isinstance(value, str):
        stripped = value.strip()
        return (
            _is_structured_jwt(stripped)
            or _AUTHORIZATION_VALUE.fullmatch(stripped) is not None
            or any(pattern.fullmatch(stripped) for pattern in _API_CREDENTIAL_VALUES)
        )
    if isinstance(value, Mapping):
        return any(
            contains_credential_material(
                item,
                field_name=key,
                depth=depth + 1,
            )
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for item in value:
            if (
                isinstance(item, Sequence)
                and not isinstance(item, str | bytes)
                and len(item) == 2
                and isinstance(item[0], str)
            ):
                if contains_credential_material(
                    item[1],
                    field_name=item[0],
                    depth=depth + 1,
                ):
                    return True
            elif contains_credential_material(item, depth=depth + 1):
                return True
    return False


def _has_material(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping | Sequence) and not isinstance(value, str | bytes):
        return len(value) > 0
    return True


def _is_structured_jwt(value: str) -> bool:
    if not value or len(value) > 8192:
        return False
    segments = value.split(".")
    if len(segments) != 3 or any(
        not segment
        or len(segment) > 4096
        or _BASE64URL_SEGMENT.fullmatch(segment) is None
        for segment in segments[:2]
    ):
        return False
    signature = segments[2]
    if len(signature) > 4096 or (
        signature and _BASE64URL_SEGMENT.fullmatch(signature) is None
    ):
        return False
    header = _base64url_json(segments[0])
    payload = _base64url_json(segments[1])
    return (
        isinstance(header, Mapping)
        and isinstance(header.get("alg"), str)
        and bool(header["alg"])
        and isinstance(payload, Mapping)
        and (bool(signature) or header["alg"].lower() == "none")
    )


def _base64url_json(segment: str) -> object:
    try:
        padding = "=" * (-len(segment) % 4)
        decoded = base64.b64decode(
            (segment + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        if len(decoded) > 4096:
            return None
        return json.loads(decoded.decode("utf-8"))
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ):
        return None
