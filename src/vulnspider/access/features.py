"""Feature extraction for one executed Broken Access Control (BAC) probe pair.

Same ``value``/``observed``/``source``/``extractor_version``/``details``
shape as ``vulnspider.features.extraction`` (docs/FEATURE_SCHEMA.md), but the
signal direction is inverted from the injection features: here a *high*
value means the comparison request was **not** denied something it should
have been denied, not that an injected value caused an observable change.
"""

from __future__ import annotations

import re

from vulnspider.domain import AccessProbePlan, FeatureObservation, ResponseSnapshot

ACCESS_FEATURE_SCHEMA_VERSION = "access-feature-v0.2"
ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION = "access-differential-v2"

ACCESS_UNAUTHORIZED_SUCCESS = "access_unauthorized_success"
ACCESS_BODY_SIZE_SIMILARITY_RATIO = "access_body_size_similarity_ratio"

_REFERENCE_NOT_ELIGIBLE_REASON = "reference-request-did-not-succeed"
_REFERENCE_DENIED_REASON = "reference-response-is-an-access-denial-page"
_EXECUTION_ERROR_REASON = "execution-error"

# Application-level access-denial phrases. Many apps return an "access denied"
# or "please log in" page with **HTTP 200**, not 401/403 (DVWA's BAC page is
# exactly this). A purely status-based signal reads that 200 as a successful
# unauthorized access and reports a false positive, so the body is checked for
# a denial before the comparison is counted as a success. Bounded, case-
# insensitive substrings only -- no attempt to parse the page.
_DENIAL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"access denied",
        r"permission denied",
        r"\bunauthori[sz]ed\b",
        r"\bforbidden\b",
        r"not authori[sz]ed",
        r"authentication (?:is )?required",
        r"login required",
        r"please (?:log|sign) ?in",
        r"you must (?:log|sign) ?in",
        r"session (?:has )?expired",
        r"no user_id cookie",
        r"접근(?:이)? *(?:거부|금지)",
        r"권한(?:이)? *없",
        r"로그인(?:이)? *(?:필요|요구)",
        r"인증(?:이)? *(?:필요|요구)",
    )
)

# Only scan the head of the body: a denial notice is near the top, and this
# bounds the work on a large page.
_DENIAL_SCAN_LIMIT = 4096


def _is_access_denial(response: ResponseSnapshot) -> bool:
    """Whether a 2xx response is actually an application-level denial page."""

    text = response.decoded_text
    if not text:
        return False
    head = text[:_DENIAL_SCAN_LIMIT]
    return any(pattern.search(head) for pattern in _DENIAL_PATTERNS)


def _is_success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def extract_access_features(
    access_probe_plan: AccessProbePlan,
    reference_response: ResponseSnapshot,
    comparison_response: ResponseSnapshot,
) -> dict[str, FeatureObservation]:
    """Extract the two BAC features for one reference/comparison response pair.

    Both features require the reference request to have actually succeeded
    (2xx, no transport error): if the reference itself was not served, there
    is nothing to check the comparison request against, and both features are
    reported ``observed=False`` rather than guessed (AGENTS.md rule 9).
    """

    if reference_response.execution_error is not None:
        return _missing_features(
            details={
                "reason": _EXECUTION_ERROR_REASON,
                "reference_execution_error": reference_response.execution_error,
            }
        )
    if not _is_success_status(reference_response.status_code):
        return _missing_features(
            details={
                "reason": _REFERENCE_NOT_ELIGIBLE_REASON,
                "reference_status_code": reference_response.status_code,
            }
        )
    if _is_access_denial(reference_response):
        # The reference itself is an "access denied" / "please log in" page
        # served with 200. There is no protected resource being returned, so
        # there is nothing for the comparison to succeed *at* -- comparing two
        # denial pages is not a Broken Access Control observation. Report the
        # features unobserved rather than manufacturing a signal (this is what
        # removes the DVWA anonymous-BAC false positive; run the scan with an
        # authenticated --cookie so the reference is real protected content).
        return _missing_features(
            details={
                "reason": _REFERENCE_DENIED_REASON,
                "reference_status_code": reference_response.status_code,
            }
        )

    features = {
        ACCESS_UNAUTHORIZED_SUCCESS: _unauthorized_success(
            reference_response, comparison_response
        ),
    }
    if comparison_response.execution_error is not None:
        features[ACCESS_BODY_SIZE_SIMILARITY_RATIO] = FeatureObservation.missing(
            ACCESS_BODY_SIZE_SIMILARITY_RATIO,
            source="access_response_diff",
            extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
            details={
                "reason": _EXECUTION_ERROR_REASON,
                "comparison_execution_error": comparison_response.execution_error,
            },
        )
    else:
        features[ACCESS_BODY_SIZE_SIMILARITY_RATIO] = _body_size_similarity_ratio(
            reference_response, comparison_response
        )
    return features


def _unauthorized_success(
    reference_response: ResponseSnapshot,
    comparison_response: ResponseSnapshot,
) -> FeatureObservation:
    # "Success" means the comparison request received the protected resource,
    # not merely a 2xx status. An application-level denial returned as 200 (an
    # "access denied" / "please log in" page) is a *denial*, so it does not
    # count -- this is the primary fix for the status-only false positive.
    comparison_denied = _is_access_denial(comparison_response)
    comparison_succeeded = (
        comparison_response.execution_error is None
        and _is_success_status(comparison_response.status_code)
        and not comparison_denied
    )
    value = 1.0 if comparison_succeeded else 0.0
    return FeatureObservation(
        name=ACCESS_UNAUTHORIZED_SUCCESS,
        value=value,
        observed=True,
        source="access_response_diff",
        extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "reference_status_code": reference_response.status_code,
            "comparison_status_code": comparison_response.status_code,
            "comparison_execution_error": comparison_response.execution_error,
            "comparison_access_denied_page": comparison_denied,
        },
    )


def _body_size_similarity_ratio(
    reference_response: ResponseSnapshot,
    comparison_response: ResponseSnapshot,
) -> FeatureObservation:
    reference_length = reference_response.body_length_bytes
    comparison_length = comparison_response.body_length_bytes
    raw_diff_ratio = abs(comparison_length - reference_length) / max(reference_length, 1)
    value = 1.0 - min(raw_diff_ratio, 1.0)
    return FeatureObservation(
        name=ACCESS_BODY_SIZE_SIMILARITY_RATIO,
        value=value,
        observed=True,
        source="access_response_diff",
        extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "reference_length": reference_length,
            "comparison_length": comparison_length,
            "raw_diff_ratio": raw_diff_ratio,
            "formula": "1 - min(abs(comparison-reference)/max(reference,1), 1.0)",
        },
    )


def _missing_features(*, details: dict[str, object]) -> dict[str, FeatureObservation]:
    return {
        ACCESS_UNAUTHORIZED_SUCCESS: FeatureObservation.missing(
            ACCESS_UNAUTHORIZED_SUCCESS,
            source="access_response_diff",
            extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
        ACCESS_BODY_SIZE_SIMILARITY_RATIO: FeatureObservation.missing(
            ACCESS_BODY_SIZE_SIMILARITY_RATIO,
            source="access_response_diff",
            extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
    }
