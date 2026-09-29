"""Conservative classification for passive navigation candidates."""

from __future__ import annotations

from urllib.parse import parse_qsl, unquote, urlsplit


_AUTHENTICATION_TERMINATION_TOKENS = frozenset(
    {
        "logoff",
        "logout",
        "signout",
    }
)
_PAGE_EXTENSIONS = (
    ".aspx",
    ".html",
    ".jspx",
    ".php",
    ".asp",
    ".cgi",
    ".htm",
    ".jsp",
)
_ACTION_QUERY_NAMES = frozenset({"action", "cmd", "do", "operation", "task"})


def authentication_state_change_token(url: str) -> str | None:
    """Return a clear authentication-termination token in a URL path.

    Matching is segment based rather than substring based so documentation paths
    such as ``/docs/logout-behavior`` remain navigable. Only explicit action query
    names are considered; unrelated query and fragment values remain ignored.
    """

    if type(url) is not str or not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    for raw_segment in parts.path.split("/"):
        segment = unquote(raw_segment, errors="replace").casefold()
        if ";" in segment:
            segment = segment.split(";", 1)[0]
        for extension in _PAGE_EXTENSIONS:
            if segment.endswith(extension):
                segment = segment[: -len(extension)]
                break
        if segment in _AUTHENTICATION_TERMINATION_TOKENS:
            return segment
    for raw_name, raw_value in parse_qsl(
        parts.query,
        keep_blank_values=True,
        strict_parsing=False,
    ):
        name = raw_name.casefold()
        value = raw_value.casefold()
        if name in _AUTHENTICATION_TERMINATION_TOKENS:
            return name
        if name in _ACTION_QUERY_NAMES:
            for extension in _PAGE_EXTENSIONS:
                if value.endswith(extension):
                    value = value[: -len(extension)]
                    break
            if value in _AUTHENTICATION_TERMINATION_TOKENS:
                return value
    return None


def automatic_navigation_within_root_path(
    root_url: str,
    candidate_url: str,
) -> bool:
    """Keep implicit navigation inside a directory-shaped root path.

    File-shaped roots retain origin-wide behavior. Exact caller grants remain a
    separate authority decision for directory-shaped roots.
    """

    try:
        root_path = _normalized_scope_path(urlsplit(root_url).path or "/")
        candidate_path = _normalized_scope_path(
            urlsplit(candidate_url).path or "/"
        )
    except ValueError:
        return False
    if root_path is None or candidate_path is None:
        return False
    if not root_path.endswith("/"):
        return True
    prefix = root_path
    return (
        candidate_path.rstrip("/") == root_path.rstrip("/")
        or candidate_path.startswith(prefix)
    )


def _normalized_scope_path(path: str) -> str | None:
    decoded_segments: list[str] = []
    for raw_segment in path.split("/"):
        segment = raw_segment
        for _ in range(len(raw_segment) + 1):
            decoded = unquote(segment, errors="replace")
            if decoded == segment:
                break
            segment = decoded
        else:
            return None
        if segment in {".", ".."} or "/" in segment or "\\" in segment:
            return None
        decoded_segments.append(segment)
    return "/".join(decoded_segments) or "/"
