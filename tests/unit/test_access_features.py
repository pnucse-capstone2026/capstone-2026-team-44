"""BAC feature extraction: the access-denial gate (ADR-038)."""

from __future__ import annotations

import unittest
from typing import cast

from vulnspider.access.features import (
    ACCESS_UNAUTHORIZED_SUCCESS,
    extract_access_features,
)
from vulnspider.domain import AccessProbePlan, ResponseSnapshot

_PLAN = cast(AccessProbePlan, None)  # extract_access_features ignores the plan


def _response(text: str, *, status: int = 200, role: str = "baseline") -> ResponseSnapshot:
    body = text.encode("utf-8")
    return ResponseSnapshot(
        request_id="req",
        status_code=status,
        elapsed_ms=1.0,
        body_bytes_hash="h",
        body_length_bytes=len(body),
        headers={},
        decoded_text=text,
        encoding="utf-8",
        request_role=role,
    )


class AccessDenialGateTests(unittest.TestCase):
    def test_a_leaked_record_is_unauthorized_success(self) -> None:
        # Reference and comparison both return real (different) records: the
        # comparison succeeded at retrieving a protected resource -> IDOR.
        features = extract_access_features(
            _PLAN,
            _response("<table><tr><td>Alice</td></tr></table>"),
            _response("<table><tr><td>Bob</td></tr></table>"),
        )
        self.assertEqual(features[ACCESS_UNAUTHORIZED_SUCCESS].value, 1.0)

    def test_a_200_denial_comparison_is_not_a_success(self) -> None:
        # The comparison is HTTP 200 but is an "access denied" page: it did not
        # actually receive the resource, so it must not count as success.
        features = extract_access_features(
            _PLAN,
            _response("<table><tr><td>Alice</td></tr></table>"),
            _response("<p>Access denied. No user_id cookie found.</p>"),
        )
        self.assertEqual(features[ACCESS_UNAUTHORIZED_SUCCESS].value, 0.0)

    def test_a_denied_reference_makes_the_observation_inconclusive(self) -> None:
        # The reference itself is a 200 denial page (anonymous scan): there is
        # no protected resource to compare against, so both features are
        # reported unobserved rather than manufacturing a signal (this removes
        # the DVWA anonymous-BAC false positive).
        features = extract_access_features(
            _PLAN,
            _response("<p>Access denied. Please log in.</p>"),
            _response("<p>Access denied. Please log in.</p>"),
        )
        self.assertFalse(features[ACCESS_UNAUTHORIZED_SUCCESS].observed)

    def test_korean_denial_is_recognized(self) -> None:
        features = extract_access_features(
            _PLAN,
            _response("<table><tr><td>홍길동</td></tr></table>"),
            _response("<p>접근이 거부되었습니다. 권한이 없습니다.</p>"),
        )
        self.assertEqual(features[ACCESS_UNAUTHORIZED_SUCCESS].value, 0.0)


if __name__ == "__main__":
    unittest.main()
