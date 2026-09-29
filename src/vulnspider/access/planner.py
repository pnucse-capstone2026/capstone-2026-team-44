"""Deterministic planning for Broken Access Control (BAC) probe requests.

Mirrors ``observation/planner.py``'s discipline (baseline preserved, exactly
one aspect changed, deterministic identity) but plans a subject/resource
comparison instead of an InputPoint value perturbation. Both check kinds are
GET-only and non-destructive.

Unlike ``observation/planner.py``, query reconstruction here always uses
structured ``urlencode`` rather than preserving the exact original raw-query
byte formatting. That byte-for-bit preservation matters for injection markers
(the marker text itself is the signal); for an access comparison the signal is
the response, not the request's exact encoding, so this simplification is
accepted for v1.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlencode, urlsplit, urlunsplit

from vulnspider.domain import (
    AccessCheckKind,
    AccessProbePlan,
    AccessSubjectContext,
    HttpMethod,
    InputLocation,
    InputPoint,
    ParamPairs,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
)

_AUTHORIZATION_HEADER = "authorization"
_COOKIE_HEADER = "cookie"
_NUMERIC_IDENTIFIER_PATTERN = re.compile(r"^\d+$")


def _is_probe_ready(request_template: RequestTemplate) -> bool:
    if request_template.completeness != RequestContextCompleteness.COMPLETE:
        return False
    metadata = request_template.metadata
    if metadata.get("non_probe_ready_reasons"):
        return False
    if metadata.get("reconstruction_status") in {"ambiguous", "partial"}:
        return False
    if metadata.get("form_boundary_status") == "unavailable":
        return False
    return True


def _has_header(headers: Mapping[str, str], name: str) -> bool:
    normalized = name.lower()
    return any(header_name.lower() == normalized for header_name in headers)


def _strip_headers(headers: Mapping[str, str], *names: str) -> dict[str, str]:
    blocked = {name.lower() for name in names}
    return {
        name: value for name, value in headers.items() if name.lower() not in blocked
    }


def _request_instance(request_template: RequestTemplate) -> RequestInstance:
    return RequestInstance(
        method=request_template.method,
        url=request_template.url,
        headers=request_template.headers,
        query=request_template.query,
        form=request_template.form,
        cookies=request_template.cookies,
    )


def plan_credential_strip(request_template: RequestTemplate) -> AccessProbePlan | None:
    """Plan a CREDENTIAL_STRIP check, or return ``None`` if not eligible.

    Eligible only for a probe-ready GET ``RequestTemplate`` that carries
    cookies or an ``Authorization`` header -- i.e. the crawler actually used
    some credential to reach this resource, so removing it is a meaningful
    comparison. If the reference request itself carried no credentials there
    is nothing to strip and no comparison to make.
    """

    if not _is_probe_ready(request_template):
        return None
    if request_template.method != HttpMethod.GET:
        return None
    has_cookies = bool(request_template.cookies)
    has_auth_header = _has_header(request_template.headers, _AUTHORIZATION_HEADER)
    if not has_cookies and not has_auth_header:
        return None

    reference_request = _request_instance(request_template)
    comparison_request = RequestInstance(
        method=request_template.method,
        url=request_template.url,
        headers=_strip_headers(
            request_template.headers, _AUTHORIZATION_HEADER, _COOKIE_HEADER
        ),
        query=request_template.query,
        form=request_template.form,
        cookies={},
    )
    return AccessProbePlan(
        endpoint_id=request_template.endpoint_id,
        endpoint_fingerprint=request_template.endpoint_fingerprint,
        request_template_id=request_template.id or "",
        check_kind=AccessCheckKind.CREDENTIAL_STRIP,
        reference_request=reference_request,
        comparison_request=comparison_request,
        reference_subject=AccessSubjectContext.ORIGINAL,
        comparison_subject=AccessSubjectContext.ANONYMOUS,
        changed_aspect="credentials",
        input_point_id=None,
    )


def plan_identifier_substitution(
    input_point: InputPoint,
    request_template: RequestTemplate,
) -> AccessProbePlan | None:
    """Plan an IDENTIFIER_SUBSTITUTION check, or return ``None`` if not eligible.

    Eligible only for a probe-ready GET ``RequestTemplate`` and a
    ``QUERY``/``FORM`` InputPoint whose baseline value is purely numeric
    digits. The substituted value is ``baseline + 1``: deterministic, bounded,
    and non-destructive for a read-only GET. Non-numeric identifiers (UUIDs,
    opaque tokens) are never substituted -- inventing a "plausible" alternate
    value for those would not be a principled probe, so those InputPoints are
    simply not planned.
    """

    if not _is_probe_ready(request_template):
        return None
    if request_template.method != HttpMethod.GET:
        return None
    if input_point.location not in (InputLocation.QUERY, InputLocation.FORM):
        return None
    baseline_value = input_point.baseline_value
    if baseline_value is None or not _NUMERIC_IDENTIFIER_PATTERN.match(baseline_value):
        return None

    substituted_value = str(int(baseline_value) + 1)

    pairs = (
        request_template.query
        if input_point.location == InputLocation.QUERY
        else request_template.form
    )
    target = _target_pair_index(input_point, pairs)
    if target is None:
        return None
    pair_index, matched_value = target
    if matched_value != baseline_value:
        return None

    reference_request = _request_instance(request_template)
    comparison_query = request_template.query
    comparison_form = request_template.form
    comparison_url = request_template.url
    if input_point.location == InputLocation.QUERY:
        comparison_query = _replace_pair_value(
            request_template.query, pair_index, substituted_value
        )
        comparison_url = _rebuild_query_url(request_template.url, comparison_query)
    else:
        comparison_form = _replace_pair_value(
            request_template.form, pair_index, substituted_value
        )

    comparison_request = RequestInstance(
        method=request_template.method,
        url=comparison_url,
        headers=request_template.headers,
        query=comparison_query,
        form=comparison_form,
        cookies=request_template.cookies,
    )
    return AccessProbePlan(
        endpoint_id=request_template.endpoint_id,
        endpoint_fingerprint=request_template.endpoint_fingerprint,
        request_template_id=request_template.id or "",
        check_kind=AccessCheckKind.IDENTIFIER_SUBSTITUTION,
        reference_request=reference_request,
        comparison_request=comparison_request,
        reference_subject=AccessSubjectContext.ORIGINAL,
        comparison_subject=AccessSubjectContext.ORIGINAL,
        changed_aspect=_changed_field(input_point),
        input_point_id=input_point.id,
    )


def _target_pair_index(
    input_point: InputPoint,
    pairs: ParamPairs,
) -> tuple[int, str] | None:
    matches = [
        (index, value)
        for index, (name, value) in enumerate(pairs)
        if name.strip().lower() == input_point.name
    ]
    if not matches:
        return None
    if input_point.occurrence_index is None:
        if len(matches) != 1:
            return None
        return matches[0]
    if input_point.occurrence_index >= len(matches):
        return None
    return matches[input_point.occurrence_index]


def _replace_pair_value(pairs: ParamPairs, pair_index: int, value: str) -> ParamPairs:
    return tuple(
        (name, value if index == pair_index else pair_value)
        for index, (name, pair_value) in enumerate(pairs)
    )


def _rebuild_query_url(url: str, query: ParamPairs) -> str:
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def _changed_field(input_point: InputPoint) -> str:
    location = input_point.location.value.lower()
    if input_point.occurrence_index is None:
        return f"{location}.{input_point.name}"
    return f"{location}.{input_point.name}[{input_point.occurrence_index}]"


class AccessProbePlanner:
    """Thin object wrapper over the module-level planning functions."""

    def plan_credential_strip(
        self, request_template: RequestTemplate
    ) -> AccessProbePlan | None:
        return plan_credential_strip(request_template)

    def plan_identifier_substitution(
        self,
        input_point: InputPoint,
        request_template: RequestTemplate,
    ) -> AccessProbePlan | None:
        return plan_identifier_substitution(input_point, request_template)
