from __future__ import annotations

from dataclasses import fields, replace
import unittest

from vulnspider.discovery import (
    BrowserAuditSummary,
    CollectorKind,
    CombinedDiscoveryResult,
    DiscoveryContractError,
    DiscoveryMergePolicy,
    DiscoveryMetadata,
    DiscoverySafetyInvariant,
    DynamicCrawlCompletion,
    DynamicCrawlerError,
    DynamicCrawlResult,
    DynamicCrawlTerminationReason,
    DynamicIntegrityError,
    DynamicPageResult,
    DynamicRequestAuthority,
    NativeDiscoveryOrchestrator,
    RenderedDomExtractionResult,
    SensitiveFormElisionPolicy,
    StaticCrawlResult,
    extract_static_html,
    merge_discovery_results,
)
from vulnspider.domain import stable_fingerprint


ROOT_URL = "http://127.0.0.1:8080/"
HTML = '<html><body><a href="/surface?q=1">surface</a></body></html>'


def _static_result(
    *,
    safe: bool = True,
    html: str = HTML,
    root_url: str = ROOT_URL,
) -> StaticCrawlResult:
    extraction = extract_static_html(
        html,
        root_url,
        discovery_metadata=DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_STATIC,
            collector_version="combined-test-static/1",
            configuration_fingerprint=stable_fingerprint(
                "combined-test-static",
                safe,
            ),
        ),
        sensitive_form_policy=(SensitiveFormElisionPolicy() if safe else None),
    )
    return StaticCrawlResult(
        root_url=root_url,
        visited_urls=(root_url,),
        processed_urls=(root_url,),
        discovery=extraction.discovery,
    )


def _empty_audit() -> BrowserAuditSummary:
    tuple_fields = {
        "child_frame_commit_kinds",
        "child_frame_completion_kinds",
        "cleanup_error_codes",
        "events",
        "network_observations",
    }
    values = {
        item.name: (
            ()
            if item.name in tuple_fields
            else (True if item.name == "cleanup_complete" else 0)
        )
        for item in fields(BrowserAuditSummary)
    }
    return BrowserAuditSummary(**values)


def _dynamic_result(
    *,
    completion: DynamicCrawlCompletion = DynamicCrawlCompletion.COMPLETE,
    html: str = HTML,
    root_url: str = ROOT_URL,
) -> DynamicCrawlResult:
    extraction = extract_static_html(
        html,
        root_url,
        discovery_metadata=DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_DYNAMIC,
            collector_version="combined-test-dynamic/1",
            configuration_fingerprint=stable_fingerprint("combined-test-dynamic"),
        ),
        sensitive_form_policy=SensitiveFormElisionPolicy(),
    )
    rendered = RenderedDomExtractionResult(
        source_url=root_url,
        snapshot_fingerprint=stable_fingerprint("combined-test-snapshot"),
        navigable_links=extraction.navigable_links,
        discovery=extraction.discovery,
    )
    page = DynamicPageResult(
        requested_url=root_url,
        page_url=root_url,
        parent_url=None,
        depth=0,
        component=rendered,
    )
    termination = (
        DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED
        if completion == DynamicCrawlCompletion.COMPLETE
        else DynamicCrawlTerminationReason.COMPLETED_WITH_FAILURES
    )
    return DynamicCrawlResult(
        root_url=root_url,
        visited_urls=(root_url,),
        pages=(page,),
        completion=completion,
        termination_reason=termination,
        navigation_attempts=0,
        route_actions_attempted=0,
        discovery=extraction.discovery,
        browser_audit=_empty_audit(),
    )


class _Producer:
    def __init__(self, log: list[str], name: str, outcome) -> None:
        self.log = log
        self.name = name
        self.outcome = outcome

    def crawl(self, *args, **kwargs):
        self.log.append(self.name)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class CombinedDiscoveryOrchestrationTests(unittest.TestCase):
    def test_off_path_link_cannot_be_promoted_by_combined_merge(self) -> None:
        root = "http://127.0.0.1:8080/area/"
        off_path = "http://127.0.0.1:8080/outside?csrf=OFFPATH_SECRET"
        html = (
            '<a href="/area/local?id=1">local</a>'
            f'<a href="{off_path}">outside</a>'
        )
        static_result = _static_result(html=html, root_url=root)
        dynamic_result = _dynamic_result(html=html, root_url=root)
        combined = NativeDiscoveryOrchestrator(
            static_crawler=_Producer([], "static", static_result),
            dynamic_crawler=_Producer([], "dynamic", dynamic_result),
        ).discover(root, authority=DynamicRequestAuthority(root))

        for discovery in (
            static_result.discovery,
            dynamic_result.discovery,
            combined.discovery,
        ):
            self.assertNotIn(
                off_path,
                {template.url for template in discovery.request_templates},
            )
            self.assertFalse(
                any(
                    endpoint.path == "/outside"
                    for endpoint in discovery.endpoints
                )
            )
            self.assertFalse(
                any(point.name == "csrf" for point in discovery.input_points)
            )
            self.assertFalse(
                any(
                    point.name == "csrf"
                    for point, _template, _context in discovery.ready_contexts()
                )
            )
            self.assertNotIn("OFFPATH_SECRET", repr(discovery.to_dict()))

    def test_off_scope_link_cannot_be_promoted_by_combined_merge(self) -> None:
        html = (
            '<a href="/local?id=1">local</a>'
            '<a href="https://www.youtube.com/watch?v=test">external</a>'
        )
        static_result = _static_result(html=html)
        dynamic_result = _dynamic_result(html=html)
        orchestrator = NativeDiscoveryOrchestrator(
            static_crawler=_Producer([], "static", static_result),
            dynamic_crawler=_Producer([], "dynamic", dynamic_result),
        )

        combined = orchestrator.discover(
            ROOT_URL,
            authority=DynamicRequestAuthority(ROOT_URL),
        )

        for discovery in (
            static_result.discovery,
            dynamic_result.discovery,
            combined.discovery,
        ):
            self.assertFalse(
                any(
                    "www.youtube.com" in template.url
                    for template in discovery.request_templates
                )
            )
            self.assertFalse(
                any(
                    endpoint.host == "www.youtube.com"
                    for endpoint in discovery.endpoints
                )
            )
            self.assertTrue(
                all(
                    "www.youtube.com" not in template.url
                    for _point, template, _context in discovery.ready_contexts()
                )
            )
        self.assertIn(
            "OFF_SCOPE_LINK",
            {warning.code for warning in combined.discovery.warnings},
        )

    def test_runs_static_then_dynamic_and_exposes_degraded_completion(self) -> None:
        log: list[str] = []
        orchestrator = NativeDiscoveryOrchestrator(
            static_crawler=_Producer(log, "static", _static_result()),
            dynamic_crawler=_Producer(
                log,
                "dynamic",
                _dynamic_result(completion=DynamicCrawlCompletion.DEGRADED),
            ),
        )

        result = orchestrator.discover(
            ROOT_URL,
            authority=DynamicRequestAuthority(ROOT_URL),
        )

        self.assertEqual(log, ["static", "dynamic"])
        self.assertTrue(result.degraded)
        self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
        self.assertEqual(
            result.to_dict()["completion"],
            DynamicCrawlCompletion.DEGRADED.value,
        )
        self.assertEqual(
            result.discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_COMBINED,
        )

    def test_producer_failures_are_strict_and_do_not_merge(self) -> None:
        log: list[str] = []
        static_failure = NativeDiscoveryOrchestrator(
            static_crawler=_Producer(log, "static", RuntimeError("static failed")),
            dynamic_crawler=_Producer(log, "dynamic", _dynamic_result()),
        )
        with self.assertRaisesRegex(RuntimeError, "static failed"):
            static_failure.discover(
                ROOT_URL,
                authority=DynamicRequestAuthority(ROOT_URL),
            )
        self.assertEqual(log, ["static"])

        log.clear()
        dynamic_failure = NativeDiscoveryOrchestrator(
            static_crawler=_Producer(log, "static", _static_result()),
            dynamic_crawler=_Producer(log, "dynamic", RuntimeError("dynamic failed")),
        )
        with self.assertRaisesRegex(RuntimeError, "dynamic failed"):
            dynamic_failure.discover(
                ROOT_URL,
                authority=DynamicRequestAuthority(ROOT_URL),
            )
        self.assertEqual(log, ["static", "dynamic"])

    def test_missing_safety_invariant_is_not_a_fallback(self) -> None:
        static_result = _static_result(safe=False)
        dynamic_result = _dynamic_result()
        static_before = static_result.to_dict()
        dynamic_before = dynamic_result.to_dict()
        orchestrator = NativeDiscoveryOrchestrator(
            static_crawler=_Producer([], "static", static_result),
            dynamic_crawler=_Producer([], "dynamic", dynamic_result),
        )

        with self.assertRaisesRegex(
            DynamicIntegrityError,
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION.value,
        ):
            orchestrator.discover(
                ROOT_URL,
                authority=DynamicRequestAuthority(ROOT_URL),
            )

        self.assertEqual(static_result.to_dict(), static_before)
        self.assertEqual(dynamic_result.to_dict(), dynamic_before)

    def test_invalid_component_stops_before_dynamic(self) -> None:
        invalid_static = _static_result()
        invalid_statistics = replace(
            invalid_static.discovery.crawl_statistics,
            endpoint_count=(
                invalid_static.discovery.crawl_statistics.endpoint_count + 1
            ),
        )
        object.__setattr__(
            invalid_static.discovery,
            "crawl_statistics",
            invalid_statistics,
        )
        log: list[str] = []
        orchestrator = NativeDiscoveryOrchestrator(
            static_crawler=_Producer(log, "static", invalid_static),
            dynamic_crawler=_Producer(log, "dynamic", _dynamic_result()),
        )

        with self.assertRaises(DiscoveryContractError):
            orchestrator.discover(
                ROOT_URL,
                authority=DynamicRequestAuthority(ROOT_URL),
            )
        self.assertEqual(log, ["static"])

    def test_mutated_dynamic_wrapper_cannot_masquerade_as_complete(self) -> None:
        dynamic_result = _dynamic_result(
            completion=DynamicCrawlCompletion.DEGRADED
        )
        object.__setattr__(
            dynamic_result,
            "completion",
            DynamicCrawlCompletion.COMPLETE,
        )
        log: list[str] = []
        orchestrator = NativeDiscoveryOrchestrator(
            static_crawler=_Producer(log, "static", _static_result()),
            dynamic_crawler=_Producer(log, "dynamic", dynamic_result),
        )

        with self.assertRaisesRegex(
            DynamicCrawlerError,
            "complete Dynamic result has non-final termination",
        ):
            orchestrator.discover(
                ROOT_URL,
                authority=DynamicRequestAuthority(ROOT_URL),
            )
        self.assertEqual(log, ["static", "dynamic"])

    def test_combined_result_must_match_retained_producers(self) -> None:
        static_result = _static_result()
        dynamic_result = _dynamic_result()
        empty_html = "<html><body></body></html>"
        unrelated = merge_discovery_results(
            _static_result(html=empty_html).discovery,
            _dynamic_result(html=empty_html).discovery,
            DiscoveryMergePolicy(),
        )

        with self.assertRaisesRegex(
            DynamicIntegrityError,
            "does not match its producer components",
        ):
            CombinedDiscoveryResult(
                root_url=ROOT_URL,
                static_crawl=static_result,
                dynamic_crawl=dynamic_result,
                discovery=unrelated,
            )


if __name__ == "__main__":
    unittest.main()
