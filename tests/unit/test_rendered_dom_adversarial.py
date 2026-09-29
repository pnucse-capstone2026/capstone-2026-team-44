from __future__ import annotations

import unittest

from vulnspider.discovery import (
    CollectorKind,
    DiscoveryContractError,
    DiscoveryMetadata,
    RenderedDomError,
    RenderedDomErrorCode,
    RenderedDomPolicy,
    extract_static_html,
)
from vulnspider.discovery.rendered_dom import snapshot_from_browser_payload


def valid_payload(html: str = "<html><body></body></html>") -> dict[str, object]:
    return {
        "ok": True,
        "pageUrl": "http://127.0.0.1:8765/rendered",
        "sanitizedHtml": html,
        "sensitiveFormOccurrences": [],
        "nodeCount": 2,
        "anchorCount": 0,
        "formCount": 0,
        "controlCount": 0,
        "serializedBytes": len(html.encode("utf-8")),
    }


class RenderedDomAdversarialTests(unittest.TestCase):
    def test_native_dynamic_metadata_cannot_bypass_sensitive_form_policy(
        self,
    ) -> None:
        metadata = DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_DYNAMIC,
            collector_version="adversarial",
            configuration_fingerprint="adversarial",
        )
        html = (
            '<form action="/login">'
            '<input type="password" name="pw" value="FALLBACK_SENTINEL">'
            "</form>"
        )
        with self.assertRaisesRegex(
            DiscoveryContractError,
            "requires sensitive-form elision",
        ):
            extract_static_html(
                html,
                "http://127.0.0.1/",
                discovery_metadata=metadata,
            )

    def test_timeout_and_unknown_browser_failures_are_stable_and_secret_free(
        self,
    ) -> None:
        secret = "provider-secret-value"
        for payload, expected in (
            (
                {
                    "ok": False,
                    "code": "DOM_STABILIZATION_TIMEOUT",
                    "diagnostic": secret,
                },
                RenderedDomErrorCode.DOM_STABILIZATION_TIMEOUT,
            ),
            (
                {"ok": False, "code": "UNKNOWN", "diagnostic": secret},
                RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
            ),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(RenderedDomError) as raised:
                    snapshot_from_browser_payload(payload, RenderedDomPolicy())
                self.assertEqual(raised.exception.code, expected)
                self.assertNotIn(secret, str(raised.exception))

    def test_every_snapshot_bound_is_rechecked_outside_browser(self) -> None:
        policy = RenderedDomPolicy(
            max_nodes=5,
            max_actionable_elements=4,
            max_anchors=3,
            max_forms=3,
            max_controls=3,
            max_serialized_bytes=100,
        )
        cases = (
            ("<html><body></body></html>", {"nodeCount": 6}),
            (
                "<html><body>" + "<a></a>" * 4 + "</body></html>",
                {"anchorCount": 4},
            ),
            (
                "<html><body>" + "<form></form>" * 4 + "</body></html>",
                {"formCount": 4},
            ),
            (
                (
                    "<html><body><form>"
                    + '<input name="q">' * 4
                    + "</form></body></html>"
                ),
                {"formCount": 1, "controlCount": 4},
            ),
            (
                (
                    "<html><body><a></a><a></a><form>"
                    '<input name="a"><input name="b">'
                    "</form></body></html>"
                ),
                {"anchorCount": 2, "formCount": 1, "controlCount": 2},
            ),
        )
        for html, override in cases:
            with self.subTest(override=override):
                payload = valid_payload(html) | override
                with self.assertRaises(RenderedDomError) as raised:
                    snapshot_from_browser_payload(payload, policy)
                self.assertEqual(
                    raised.exception.code,
                    RenderedDomErrorCode.DOM_LIMIT_EXCEEDED,
                )

    def test_utf8_byte_limit_and_reported_length_cannot_be_bypassed(self) -> None:
        html = (
            "<html><body><form><textarea name=\"q\">"
            "한글</textarea></form></body></html>"
        )
        policy = RenderedDomPolicy(max_serialized_bytes=60)
        payload = valid_payload(html)
        payload["formCount"] = 1
        payload["controlCount"] = 1
        self.assertGreater(len(html.encode("utf-8")), len(html))
        with self.assertRaises(RenderedDomError) as raised:
            snapshot_from_browser_payload(payload, policy)
        self.assertEqual(
            raised.exception.code,
            RenderedDomErrorCode.DOM_LIMIT_EXCEEDED,
        )

        payload = valid_payload()
        payload["serializedBytes"] = 1
        with self.assertRaises(RenderedDomError) as malformed:
            snapshot_from_browser_payload(payload, RenderedDomPolicy())
        self.assertEqual(
            malformed.exception.code,
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
        )

    def test_bool_and_provider_shaped_values_are_not_accepted_as_counts(self) -> None:
        for value in (True, "2", 2.0, None):
            with self.subTest(value=value):
                payload = valid_payload()
                payload["nodeCount"] = value
                with self.assertRaises(RenderedDomError) as raised:
                    snapshot_from_browser_payload(payload, RenderedDomPolicy())
                self.assertEqual(
                    raised.exception.code,
                    RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
                )

    def test_projection_counts_and_allowed_tags_are_host_validated(self) -> None:
        payload = valid_payload()
        payload["anchorCount"] = 1
        with self.assertRaises(RenderedDomError) as counts:
            snapshot_from_browser_payload(payload, RenderedDomPolicy())
        self.assertEqual(
            counts.exception.code,
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
        )

        payload = valid_payload("<html><body><script></script></body></html>")
        with self.assertRaises(RenderedDomError) as tag:
            snapshot_from_browser_payload(payload, RenderedDomPolicy())
        self.assertEqual(
            tag.exception.code,
            RenderedDomErrorCode.DOM_SNAPSHOT_FAILED,
        )

    def test_active_attribute_and_text_limits_are_host_rechecked(self) -> None:
        cases = (
            (
                '<html><body><a href="/long-value"></a></body></html>',
                {"anchorCount": 1},
                RenderedDomPolicy(max_attribute_length=5),
            ),
            (
                (
                    "<html><body><form>"
                    '<input type="text" name="q" value="v">'
                    "</form></body></html>"
                ),
                {"formCount": 1, "controlCount": 1},
                RenderedDomPolicy(max_attributes_per_element=2),
            ),
            (
                (
                    "<html><body><form><textarea name=\"q\">"
                    "too-long</textarea></form></body></html>"
                ),
                {"formCount": 1, "controlCount": 1},
                RenderedDomPolicy(max_text_length=3),
            ),
        )
        for html, counts, policy in cases:
            with self.subTest(policy=policy):
                payload = valid_payload(html) | counts
                with self.assertRaises(RenderedDomError) as raised:
                    snapshot_from_browser_payload(payload, policy)
                self.assertEqual(
                    raised.exception.code,
                    RenderedDomErrorCode.DOM_LIMIT_EXCEEDED,
                )


if __name__ == "__main__":
    unittest.main()
