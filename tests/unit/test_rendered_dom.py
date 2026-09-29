from __future__ import annotations

from dataclasses import dataclass
import json
import unittest

from vulnspider.discovery import (
    CollectorKind,
    DiscoverySafetyInvariant,
    DynamicRequestAuthority,
    NonProbeReadyReason,
    ProbeReadyStatus,
    RenderedDomError,
    RenderedDomErrorCode,
    RenderedDomPolicy,
    RenderedDomSnapshot,
    extract_rendered_dom,
)
from vulnspider.domain import InputLocation, RequestContextCompleteness


SOURCE_URL = "http://127.0.0.1:8765/rendered?seed=one&seed=two&blank="


def snapshot(
    html: str,
    *,
    sensitive_form_count: int = 0,
) -> RenderedDomSnapshot:
    policy = RenderedDomPolicy()
    safe_form_count = html.count("<form")
    return RenderedDomSnapshot(
        page_url=SOURCE_URL,
        sanitized_html=html,
        sensitive_form_occurrences=tuple(
            range(safe_form_count, safe_form_count + sensitive_form_count)
        ),
        node_count=12,
        anchor_count=html.count("<a"),
        form_count=safe_form_count,
        control_count=(
            html.count("<input")
            + html.count("<select")
            + html.count("<textarea")
        ),
        serialized_bytes=len(html.encode("utf-8")),
        capture_policy_fingerprint=policy.fingerprint,
    )


@dataclass(frozen=True)
class _Authority:
    root_url: str
    allowed: frozenset[str]

    def allows_navigation(self, url: str) -> bool:
        return url in self.allowed


class RenderedDomExtractionTests(unittest.TestCase):
    def test_extracts_dynamic_links_forms_and_repeated_raw_query_occurrences(
        self,
    ) -> None:
        html = (
            "<html><body>"
            '<a href="/next?a=1&a=2&blank="></a>'
            '<form action="/submit" method="post">'
            '<input type="hidden" name="csrf" value="token">'
            '<input type="text" name="query" value="live-value">'
            '<textarea name="note">rendered note</textarea>'
            "</form></body></html>"
        )
        authority = _Authority(
            root_url="http://127.0.0.1:8765/",
            allowed=frozenset(
                {
                    SOURCE_URL,
                    "http://127.0.0.1:8765/next?a=1&a=2&blank=",
                    "http://127.0.0.1:8765/submit",
                }
            ),
        )

        result = extract_rendered_dom(snapshot(html), authority)

        discovery = result.discovery
        self.assertEqual(
            discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_DYNAMIC,
        )
        self.assertTrue(
            all(
                item.collector_kind == CollectorKind.NATIVE_DYNAMIC
                for item in discovery.crawl_provenance
            )
        )
        self.assertTrue(
            all(
                endpoint.discovered_by == "native_dynamic_rendered_dom"
                for endpoint in discovery.endpoints
            )
        )
        self.assertTrue(
            all(point.metadata.get("native_dynamic") is True for point in discovery.input_points)
        )
        names = [point.name for point in discovery.input_points]
        self.assertEqual(names.count("a"), 2)
        self.assertIn("blank", names)
        self.assertIn("csrf", names)
        self.assertIn("query", names)
        self.assertIn("note", names)
        repeated = [point for point in discovery.input_points if point.name == "a"]
        self.assertEqual(
            sorted(point.occurrence_index for point in repeated),
            [0, 1],
        )
        link_template = next(
            item
            for item in discovery.request_templates
            if "/next?" in item.url
        )
        self.assertEqual(
            link_template.url,
            "http://127.0.0.1:8765/next?a=1&a=2&blank=",
        )
        self.assertEqual(
            link_template.query,
            (("a", "1"), ("a", "2"), ("blank", "")),
        )
        form_template = next(
            item for item in discovery.request_templates if item.form
        )
        self.assertEqual(
            form_template.form,
            (
                ("csrf", "token"),
                ("query", "live-value"),
                ("note", "rendered note"),
            ),
        )
        self.assertTrue(
            all(item.status == ProbeReadyStatus.READY for item in discovery.probe_readiness)
        )
        discovery.validate()

    def test_unauthorized_request_surface_remains_visible_but_not_ready(self) -> None:
        html = '<html><body><a href="/not-authorized?x=1"></a></body></html>'
        authority = _Authority(
            root_url="http://127.0.0.1:8765/",
            allowed=frozenset({SOURCE_URL}),
        )

        discovery = extract_rendered_dom(snapshot(html), authority).discovery

        point = next(item for item in discovery.input_points if item.name == "x")
        readiness = next(
            item for item in discovery.probe_readiness if item.input_point_id == point.id
        )
        context = next(
            item
            for item in discovery.input_point_request_contexts
            if item.id == readiness.request_context_id
        )
        template = next(
            item
            for item in discovery.request_templates
            if item.id == context.request_template_id
        )
        self.assertEqual(readiness.status, ProbeReadyStatus.NOT_READY)
        self.assertEqual(
            readiness.reasons,
            (NonProbeReadyReason.REQUEST_NOT_AUTHORIZED,),
        )
        self.assertEqual(template.completeness, RequestContextCompleteness.COMPLETE)
        self.assertEqual(point.location, InputLocation.QUERY)
        discovery.validate()

    def test_sensitive_elision_warning_is_subject_free_and_value_free(self) -> None:
        sentinel = "NEVER_SERIALIZE_PASSWORD_6f0f"
        html = (
            "<html><body>"
            '<form action="/safe" method="get">'
            '<input type="text" name="q" value="ok">'
            "</form></body></html>"
        )
        authority = _Authority(
            root_url="http://127.0.0.1:8765/",
            allowed=frozenset(
                {SOURCE_URL, "http://127.0.0.1:8765/safe?q=ok"}
            ),
        )

        result = extract_rendered_dom(
            snapshot(html, sensitive_form_count=1),
            authority,
        )

        warnings = [
            item
            for item in result.discovery.warnings
            if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(result.discovery.crawl_statistics.forms_discovered, 2)
        self.assertEqual(result.discovery.crawl_statistics.skipped, 1)
        self.assertIsNone(warnings[0].subject_id)
        self.assertIsNone(warnings[0].provenance_id)
        self.assertEqual(
            warnings[0].details["producer_kind"],
            CollectorKind.NATIVE_DYNAMIC.value,
        )
        self.assertIn(
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
            result.discovery.safety_invariants,
        )
        self.assertNotIn(sentinel, json.dumps(result.to_dict(), sort_keys=True))

    def test_same_snapshot_produces_identical_canonical_serialization(self) -> None:
        html = (
            "<html><body>"
            '<a href="/same?x=1&x=2"></a>'
            '<form><input name="blank" value=""></form>'
            "</body></html>"
        )
        request_url = SOURCE_URL.split("?", 1)[0] + "?blank="
        authority = _Authority(
            root_url="http://127.0.0.1:8765/",
            allowed=frozenset(
                {
                    SOURCE_URL,
                    "http://127.0.0.1:8765/same?x=1&x=2",
                    request_url,
                }
            ),
        )
        first_snapshot = snapshot(html)
        second_snapshot = snapshot(html)

        first = extract_rendered_dom(first_snapshot, authority)
        second = extract_rendered_dom(second_snapshot, authority)

        self.assertEqual(first_snapshot.fingerprint, second_snapshot.fingerprint)
        self.assertEqual(first.to_dict(), second.to_dict())


class RenderedDomSnapshotTests(unittest.TestCase):
    def test_policy_and_authority_types_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integers"):
            RenderedDomPolicy(max_nodes=0)
        with self.assertRaisesRegex(ValueError, "stabilization safety"):
            RenderedDomPolicy(minimum_observation_ms=249)
        with self.assertRaisesRegex(ValueError, "stabilization safety"):
            RenderedDomPolicy(stabilization_timeout_ms=999)
        with self.assertRaisesRegex(ValueError, "ceilings cannot be raised"):
            RenderedDomPolicy(max_nodes=1001)
        with self.assertRaises(TypeError):
            extract_rendered_dom(snapshot("<html><body></body></html>"), object())

    def test_dynamic_request_authority_satisfies_extraction_protocol(self) -> None:
        authority = DynamicRequestAuthority(root_url=SOURCE_URL)
        result = extract_rendered_dom(
            snapshot("<html><body></body></html>"),
            authority,
        )
        self.assertEqual(
            result.discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_DYNAMIC,
        )

    def test_snapshot_repr_does_not_emit_serialized_html(self) -> None:
        rendered = snapshot("<html><body></body></html>")
        self.assertNotIn("<html>", repr(rendered))

    def test_precanonical_password_form_violation_is_rejected(self) -> None:
        html = (
            "<html><body><form>"
            '<input type="password" name="secret" value="sentinel">'
            "</form></body></html>"
        )
        authority = _Authority(
            root_url="http://127.0.0.1:8765/",
            allowed=frozenset({SOURCE_URL}),
        )
        with self.assertRaisesRegex(ValueError, "password control") as raised:
            snapshot(html)
        self.assertNotIn("sentinel", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
