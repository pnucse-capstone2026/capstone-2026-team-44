from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from tests.integration.dynamic_loopback_site import DynamicLoopbackSite
from vulnspider.discovery import (
    CollectorKind,
    DiscoveryMergePolicy,
    DiscoverySafetyInvariant,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicRequestAuthority,
    PlaywrightDynamicBrowser,
    RenderedDomPolicy,
    SensitiveFormElisionPolicy,
    extract_rendered_dom,
    extract_static_html,
    merge_discovery_results,
    preflight_dynamic_browser,
)


class RenderedDomLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._original_cwd = Path.cwd()
        cls._browser_workdir = tempfile.TemporaryDirectory(
            prefix="vulnspider-rendered-dom-"
        )
        os.chdir(cls._browser_workdir.name)
        try:
            preflight_dynamic_browser()
        except Exception:
            os.chdir(cls._original_cwd)
            cls._browser_workdir.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._original_cwd)
        cls._browser_workdir.cleanup()

    def test_rendered_basic_extracts_live_main_frame_surfaces(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = self._basic_authority(site, site.rendered_basic_url)

            run = self._capture(
                site.rendered_basic_url,
                authority,
                marker="#rendered-js-marker",
            )

            snapshot, extracted = run.value
            self.assertEqual(snapshot.anchor_count, 2)
            self.assertEqual(snapshot.form_count, 2)
            self.assertEqual(snapshot.sensitive_form_count, 0)
            self.assertNotIn("iframe-only", snapshot.sanitized_html)
            self.assertNotIn("initial", snapshot.sanitized_html)
            self.assertIn("rendered-value", snapshot.sanitized_html)
            self.assertIn("rendered note", snapshot.sanitized_html)
            self.assertNotIn("name=\"ignored\" value", snapshot.sanitized_html)
            self.assertNotIn("name=\"disabled\" value", snapshot.sanitized_html)
            self.assertNotIn("unnamed", snapshot.sanitized_html)

            discovery = extracted.discovery
            self.assertEqual(
                discovery.discovery_metadata.collector_kind,
                CollectorKind.NATIVE_DYNAMIC,
            )
            values = {
                point.name: point.baseline_value
                for point in discovery.input_points
                if point.occurrence_index is None
            }
            self.assertEqual(values["query"], "rendered-value")
            self.assertEqual(values["choice"], "yes")
            self.assertEqual(values["role"], "admin")
            self.assertEqual(values["note"], "rendered note")
            self.assertEqual(values["static"], "source")
            self.assertNotIn("ignored", values)
            self.assertNotIn("disabled", values)
            alpha = [
                point
                for point in discovery.input_points
                if point.name == "alpha"
            ]
            self.assertEqual(
                sorted(point.occurrence_index for point in alpha),
                [0, 1],
            )
            self.assertEqual(
                next(
                    item
                    for item in discovery.request_templates
                    if "/rendered-target?" in item.url
                ).url,
                site.root_url + "rendered-target?alpha=1&alpha=2&blank=",
            )
            self.assertTrue(
                all(
                    item.source_url == site.rendered_basic_url
                    for item in discovery.crawl_provenance
                )
            )
            discovery.validate()
            self._assert_balanced_cleanup(run.audit)
            self.assertEqual(site.sentinel_requests, ())
            self.assertFalse(
                any(item.method == "POST" for item in site.primary_requests)
            )

    def test_rendered_sensitive_elision_is_precanonical_and_secret_free(
        self,
    ) -> None:
        sentinel = "SENSITIVE_SENTINEL_92bd"
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.rendered_sensitive_url,
                navigation_urls=(
                    site.root_url + "rendered-safe?ok=1",
                    site.root_url + "rendered-safe-form",
                ),
            )

            run = self._capture(site.rendered_sensitive_url, authority)

            snapshot, extracted = run.value
            warnings = [
                item
                for item in extracted.discovery.warnings
                if item.code == "SENSITIVE_FORM_ELIDED"
            ]
            self.assertEqual(snapshot.sensitive_form_count, 1)
            self.assertEqual(snapshot.sensitive_form_occurrences, (1,))
            self.assertEqual(snapshot.form_count, 1)
            self.assertEqual(len(warnings), 1)
            self.assertEqual(warnings[0].details["form_occurrence_index"], 1)
            self.assertEqual(
                extracted.discovery.crawl_statistics.forms_discovered,
                2,
            )
            self.assertEqual(extracted.discovery.crawl_statistics.skipped, 1)
            self.assertIsNone(warnings[0].subject_id)
            self.assertIsNone(warnings[0].provenance_id)
            self.assertIn(
                DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
                extracted.discovery.safety_invariants,
            )
            serialized = json.dumps(
                {
                    "snapshot": snapshot.to_dict(),
                    "canonical": extracted.to_dict(),
                    "audit": repr(run.audit),
                },
                sort_keys=True,
            )
            self.assertNotIn(sentinel, serialized)
            self.assertNotIn("inside-sensitive", serialized)
            self.assertFalse(
                any(point.name == "password" for point in extracted.discovery.input_points)
            )
            safe_collision = [
                point
                for point in extracted.discovery.input_points
                if point.name == "ok"
            ]
            self.assertEqual(len(safe_collision), 1)
            self.assertEqual(safe_collision[0].baseline_value, "1")
            self._assert_balanced_cleanup(run.audit)

            poisoned_authority = DynamicRequestAuthority(
                root_url=site.rendered_poisoned_url,
                navigation_urls=(
                    site.root_url + "rendered-poison-safe?ok=1",
                ),
            )
            poisoned = self._capture(
                site.rendered_poisoned_url,
                poisoned_authority,
            )
            poisoned_snapshot, poisoned_result = poisoned.value
            poisoned_serialized = json.dumps(
                {
                    "snapshot": poisoned_snapshot.to_dict(),
                    "canonical": poisoned_result.to_dict(),
                    "audit": repr(poisoned.audit),
                },
                sort_keys=True,
            )
            self.assertEqual(poisoned_snapshot.sensitive_form_occurrences, (0,))
            self.assertEqual(poisoned_snapshot.form_count, 0)
            self.assertNotIn("POISON_SENTINEL_31ac", poisoned_serialized)
            self.assertNotIn("poisoned-sensitive", poisoned_serialized)
            self._assert_balanced_cleanup(poisoned.audit)

            associated_authority = DynamicRequestAuthority(
                root_url=site.rendered_associated_password_url,
                navigation_urls=(site.root_url + "associated-safe",),
            )
            associated = self._capture(
                site.rendered_associated_password_url,
                associated_authority,
            )
            associated_snapshot, associated_result = associated.value
            associated_serialized = json.dumps(
                {
                    "snapshot": associated_snapshot.to_dict(),
                    "canonical": associated_result.to_dict(),
                    "audit": repr(associated.audit),
                },
                sort_keys=True,
            )
            self.assertEqual(
                associated_snapshot.sensitive_form_occurrences,
                (0,),
            )
            self.assertEqual(associated_snapshot.form_count, 1)
            self.assertNotIn("ASSOCIATED_SENTINEL_8b5e", associated_serialized)
            self.assertNotIn("physical-sensitive", associated_serialized)
            self.assertTrue(
                any(
                    endpoint.path == "/associated-safe"
                    for endpoint in associated_result.discovery.endpoints
                )
            )
            self._assert_balanced_cleanup(associated.audit)
            self.assertEqual(site.sentinel_requests, ())

    def test_rendered_deterministic_across_two_fresh_browser_runs(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = self._basic_authority(
                site,
                site.rendered_deterministic_url,
            )

            first = self._capture(
                site.rendered_deterministic_url,
                authority,
                marker="#rendered-js-marker",
            )
            second = self._capture(
                site.rendered_deterministic_url,
                authority,
                marker="#rendered-js-marker",
            )

            self.assertEqual(
                first.value[0].to_dict(),
                second.value[0].to_dict(),
            )
            self.assertEqual(
                first.value[1].to_dict(),
                second.value[1].to_dict(),
            )
            self._assert_balanced_cleanup(first.audit)
            self._assert_balanced_cleanup(second.audit)
            self.assertEqual(site.sentinel_requests, ())

    def test_rendered_bounded_node_and_utf8_size_limits_fail_closed(self) -> None:
        with DynamicLoopbackSite() as site:
            cases = (
                (
                    site.rendered_large_url,
                    RenderedDomPolicy(max_nodes=10),
                ),
                (
                    site.rendered_basic_url,
                    RenderedDomPolicy(max_serialized_bytes=100),
                ),
                (
                    site.rendered_attribute_large_url,
                    RenderedDomPolicy(),
                ),
                (
                    site.rendered_text_large_url,
                    RenderedDomPolicy(),
                ),
            )
            for url, policy in cases:
                with self.subTest(policy=policy):
                    authority = self._basic_authority(site, url)
                    with self.assertRaises(DynamicBrowserError) as raised:
                        self._capture(url, authority, policy=policy)
                    error = raised.exception
                    self.assertEqual(
                        error.code,
                        DynamicBrowserErrorCode.DOM_LIMIT_EXCEEDED,
                    )
                    self.assertIsNotNone(error.audit)
                    self._assert_balanced_cleanup(error.audit)
                    self.assertEqual(error.cleanup_error_codes, ())
            self.assertEqual(site.sentinel_requests, ())

    def test_rendered_timeout_has_stable_error_and_complete_cleanup(self) -> None:
        site = DynamicLoopbackSite()
        with self.assertRaises(DynamicBrowserError) as raised:
            with site:
                authority = DynamicRequestAuthority(
                    root_url=site.rendered_noisy_url,
                )
                self._capture(
                    site.rendered_noisy_url,
                    authority,
                    policy=RenderedDomPolicy(),
                )

        error = raised.exception
        self.assertEqual(
            error.code,
            DynamicBrowserErrorCode.DOM_STABILIZATION_TIMEOUT,
        )
        self.assertIsNotNone(error.audit)
        self._assert_balanced_cleanup(error.audit)
        self.assertEqual(error.cleanup_error_codes, ())
        self.assertTrue(site.cleanup_complete)
        self.assertEqual(site.server_threads_alive, (False, False))

    def test_rendered_merge_is_compatible_with_static_component(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = self._basic_authority(site, site.rendered_basic_url)
            dynamic = self._capture(
                site.rendered_basic_url,
                authority,
            ).value[1].discovery
            static = extract_static_html(
                (
                    "<html><body>"
                    '<a href="/static-only?s=1"></a>'
                    '<a href="/rendered-target?alpha=1&alpha=2&blank="></a>'
                    "</body></html>"
                ),
                site.rendered_basic_url,
                sensitive_form_policy=SensitiveFormElisionPolicy(),
            ).discovery

            combined = merge_discovery_results(
                static,
                dynamic,
                DiscoveryMergePolicy(),
            )

            self.assertEqual(
                combined.discovery_metadata.collector_kind,
                CollectorKind.NATIVE_COMBINED,
            )
            self.assertEqual(
                {
                    item.collector_kind
                    for item in combined.crawl_provenance
                },
                {CollectorKind.NATIVE_STATIC, CollectorKind.NATIVE_DYNAMIC},
            )
            self.assertTrue(
                any(point.name == "s" for point in combined.input_points)
            )
            self.assertTrue(
                any(point.name == "query" for point in combined.input_points)
            )
            self.assertEqual(
                sum(
                    endpoint.path == "/rendered-target"
                    for endpoint in combined.endpoints
                ),
                1,
            )
            self.assertEqual(
                sum(point.name == "alpha" for point in combined.input_points),
                2,
            )
            combined.validate()
            self.assertEqual(site.sentinel_requests, ())

    @staticmethod
    def _basic_authority(
        site: DynamicLoopbackSite,
        page_url: str,
    ) -> DynamicRequestAuthority:
        return DynamicRequestAuthority(
            root_url=page_url,
            navigation_urls=(
                site.root_url + "rendered-static?s=1",
                site.root_url + "rendered-static-search?static=source",
                site.root_url + "rendered-target?alpha=1&alpha=2&blank=",
                (
                    site.root_url
                    + "rendered-search?csrf=token&query=rendered-value"
                    + "&choice=yes&role=admin&note=rendered+note"
                ),
            ),
        )

    @staticmethod
    def _capture(
        page_url: str,
        authority: DynamicRequestAuthority,
        *,
        policy: RenderedDomPolicy | None = None,
        marker: str | None = None,
    ):
        def operation(session):
            session.navigate(page_url)
            if marker is not None:
                session.wait_for_selector(marker)
            captured = session.capture_rendered_dom(policy)
            return captured, extract_rendered_dom(captured, authority)

        return PlaywrightDynamicBrowser().run(authority, operation)

    @staticmethod
    def _assert_balanced_cleanup(audit) -> None:
        assert audit is not None
        if not audit.cleanup_complete:
            raise AssertionError("browser cleanup did not complete")
        if audit.cleanup_error_codes:
            raise AssertionError("browser cleanup emitted stable errors")
        pairs = (
            (audit.playwright_started, audit.playwright_stopped),
            (audit.browsers_launched, audit.browsers_closed),
            (audit.contexts_created, audit.contexts_closed),
            (audit.pages_created, audit.pages_closed),
        )
        if any(created != closed for created, closed in pairs):
            raise AssertionError("browser lifecycle counters are unbalanced")


if __name__ == "__main__":
    unittest.main()
