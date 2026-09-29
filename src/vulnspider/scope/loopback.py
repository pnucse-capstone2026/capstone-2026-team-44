"""Shared validation for explicit loopback HTTP request authorities."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlsplit


class LoopbackSafetyError(ValueError):
    """Raised when an HTTP URL is not an explicit loopback target."""


def require_loopback_http_url(url: str) -> None:
    """Reject malformed, credential-bearing, or non-loopback HTTP URLs."""

    if type(url) is not str or not url or url != url.strip():
        raise LoopbackSafetyError(
            "request URL must be an absolute loopback HTTP(S) URL"
        )
    if any(character.isspace() or ord(character) < 32 for character in url):
        raise LoopbackSafetyError("request URL contains invalid characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise LoopbackSafetyError("request URL authority is malformed") from exc
    hostname = parts.hostname
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.netloc
        or hostname is None
        or parts.username is not None
        or parts.password is not None
        or (port is not None and port <= 0)
    ):
        raise LoopbackSafetyError(
            "request URL must use a credential-free loopback HTTP(S) authority"
        )
    if hostname.casefold() == "localhost":
        return
    try:
        address = ip_address(hostname)
    except ValueError as exc:
        raise LoopbackSafetyError(
            "request URL host must be localhost or a loopback IP"
        ) from exc
    if not address.is_loopback:
        raise LoopbackSafetyError(
            "request URL host must be localhost or a loopback IP"
        )
