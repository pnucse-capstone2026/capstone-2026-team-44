from __future__ import annotations

from dataclasses import dataclass, field, replace
import pickle
import unittest

import vulnspider.discovery.dynamic_browser as browser_module
from vulnspider.discovery import (
    CollectorKind,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicBrowserPolicy,
    DynamicBrowserRunResult,
    DynamicCrawlCompletion,
    DynamicCrawler,
    DynamicCrawlPolicy,
    DynamicCrawlTerminationReason,
    DynamicNetworkDecision,
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    DynamicRequestAuthority,
    NetworkDiscoveryCollection,
    PassiveNetworkObservation,
    PassiveNetworkScope,
    RenderedDomPolicy,
    RenderedDomSnapshot,
)


def rendered_snapshot(
    url: str,
    body: str = "",
    *,
    sensitive_occurrences: tuple[int, ...] = (),
) -> RenderedDomSnapshot:
    html = f"<html><body>{body}</body></html>"
    return RenderedDomSnapshot(
        page_url=url,
        sanitized_html=html,
        sensitive_form_occurrences=sensitive_occurrences,
        node_count=max(1, body.count("<")),
        anchor_count=body.count("<a "),
        form_count=body.count("<form"),
        control_count=(
            body.count("<input")
            + body.count("<select")
            + body.count("<textarea")
        ),
        serialized_bytes=len(html.encode("utf-8")),
        capture_policy_fingerprint=RenderedDomPolicy().fingerprint,
    )


def _allow(url: str) -> DynamicNetworkDecision:
    return DynamicNetworkDecision(
        DynamicNetworkDecisionKind.ALLOW,
        DynamicNetworkReason.AUTHORIZED_NAVIGATION,
        url,
        "document",
    )


@dataclass
class FakeDynamicSession:
    snapshots: dict[str, RenderedDomSnapshot]
    recorder: browser_module._AuditRecorder
    statuses: dict[str, int] = field(default_factory=dict)
    redirects: dict[str, str] = field(default_factory=dict)
    errors: dict[str, DynamicBrowserErrorCode] = field(default_factory=dict)
    current_url: str | None = None
    current_status: int | None = None
    navigation_calls: list[str] = field(default_factory=list)
    rendered_navigation_calls: list[str] = field(default_factory=list)

    def navigate(
        self,
        url: str | None = None,
        *,
        timeout_seconds: float | None = None,
        rendered_navigation: bool = False,
    ) -> str:
        if url is None:
            raise AssertionError("crawler must pass an explicit URL")
        if timeout_seconds is None or timeout_seconds <= 0:
            raise AssertionError("crawler must pass a bounded timeout")
        self.navigation_calls.append(url)
        if rendered_navigation:
            self.rendered_navigation_calls.append(url)
        self.recorder.record_http(
            _allow(url),
            url=url,
            is_child_frame_document=False,
            is_redirect=False,
        )
        self.recorder.record_main_frame_navigation(_allow(url))
        code = self.errors.get(url)
        if code is not None:
            raise DynamicBrowserError(code, "fake bounded failure")
        final_url = self.redirects.get(url, url)
        if final_url != url:
            self.recorder.record_http(
                _allow(final_url),
                url=final_url,
                is_child_frame_document=False,
                is_redirect=True,
            )
            self.recorder.record_http(
                _allow(final_url),
                url=final_url,
                is_child_frame_document=False,
                is_redirect=False,
            )
            self.recorder.record_main_frame_navigation(_allow(final_url))
            self.recorder.record_redirect_followed()
        self.current_url = final_url
        self.current_status = self.statuses.get(final_url, 200)
        return final_url

    def navigation_status_code(self) -> int | None:
        return self.current_status

    def capture_rendered_dom(
        self,
        policy: RenderedDomPolicy | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> RenderedDomSnapshot:
        if type(policy) is not RenderedDomPolicy:
            raise AssertionError("crawler must pass its rendered DOM policy")
        if self.current_url is None:
            raise AssertionError("navigation must precede capture")
        if timeout_seconds is None or timeout_seconds <= 0:
            raise AssertionError("crawler must bound rendered DOM capture")
        return self.snapshots[self.current_url]


@dataclass
class FakeDynamicBrowser:
    snapshots: dict[str, RenderedDomSnapshot]
    statuses: dict[str, int] = field(default_factory=dict)
    redirects: dict[str, str] = field(default_factory=dict)
    errors: dict[str, DynamicBrowserErrorCode] = field(default_factory=dict)
    network_discovery: NetworkDiscoveryCollection = field(
        default_factory=NetworkDiscoveryCollection
    )
    session: FakeDynamicSession | None = None

    def run(self, authority, operation, *, policy=None):
        if type(policy) is not DynamicBrowserPolicy:
            raise AssertionError("crawler must pass a browser policy")
        recorder = browser_module._AuditRecorder(
            event_limit=policy.request_decision_budget
        )
        session = FakeDynamicSession(
            snapshots=self.snapshots,
            recorder=recorder,
            statuses=self.statuses,
            redirects=self.redirects,
            errors=self.errors,
        )
        self.session = session
        try:
            value = operation(session)
        except DynamicBrowserError as exc:
            audit = recorder.snapshot(())
            raise DynamicBrowserError(
                exc.code,
                str(exc),
                audit=audit,
                network_discovery=self.network_discovery,
            ) from None
        return DynamicBrowserRunResult(
            value=value,
            audit=recorder.snapshot(()),
            network_discovery=self.network_discovery,
        )


class DynamicCrawlerTests(unittest.TestCase):
    def test_implicit_navigation_stays_within_directory_root_path(self) -> None:
        root = "http://127.0.0.1:8080/vulnerabilities/sqli/"
        child = "http://127.0.0.1:8080/vulnerabilities/sqli/help"
        sibling = "http://127.0.0.1:8080/about.php?csrf=OFFPATH_SECRET"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/about.php?csrf=OFFPATH_SECRET"></a>'
                    '<a href="/vulnerabilities/sqli/help"></a>',
                ),
                child: rendered_snapshot(child),
            }
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            DynamicRequestAuthority(root, allow_rendered_navigation=True),
        )

        assert browser.session is not None
        self.assertEqual(browser.session.navigation_calls, [root, child])
        self.assertNotIn(sibling, result.visited_urls)
        self.assertEqual(result.completion, DynamicCrawlCompletion.COMPLETE)
        warnings = [
            warning
            for warning in result.discovery.warnings
            if warning.code == "OFF_PATH_SCOPE_LINK"
        ]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(
            warnings[0].details["reason"],
            "ROOT_PATH_SCOPE_MISMATCH",
        )
        self.assertNotIn(sibling, repr(warnings[0].details))
        serialized = repr(result.to_dict())
        self.assertNotIn("OFFPATH_SECRET", serialized)
        self.assertNotIn(
            sibling,
            {template.url for template in result.discovery.request_templates},
        )
        self.assertFalse(
            any(endpoint.path == "/about.php" for endpoint in result.discovery.endpoints)
        )
        self.assertFalse(
            any(
                point.name == "csrf" for point in result.discovery.input_points
            )
        )
        self.assertIn(
            "OFF_PATH_SCOPE_LINK",
            {warning.code for warning in result.discovery.warnings},
        )

    def test_exact_grant_can_extend_directory_root_path_scope(self) -> None:
        root = "http://127.0.0.1:8080/vulnerabilities/sqli/"
        granted = "http://127.0.0.1:8080/about.php?x=1"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(root, '<a href="/about.php?x=1"></a>'),
                granted: rendered_snapshot(granted),
            }
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            DynamicRequestAuthority(
                root,
                navigation_urls=(granted,),
                allow_rendered_navigation=True,
            ),
        )

        assert browser.session is not None
        self.assertEqual(browser.session.navigation_calls, [root, granted])
        self.assertEqual(result.completion, DynamicCrawlCompletion.COMPLETE)
        self.assertIn(
            granted,
            {template.url for template in result.discovery.request_templates},
        )
        self.assertTrue(
            any(
                point.name == "x" for point in result.discovery.input_points
            )
        )
        self.assertTrue(
            any(
                point.name == "x"
                for point, _template, _context in result.discovery.ready_contexts()
            )
        )
        self.assertNotIn(
            "DYNAMIC_OFF_PATH_SCOPE_LINK",
            {warning.code for warning in result.discovery.warnings},
        )

    def test_authentication_state_change_link_is_never_navigated(self) -> None:
        root = "http://127.0.0.1:8080/start"
        profile = "http://127.0.0.1:8080/account/profile"
        logout = "http://127.0.0.1:8080/logout.php"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/logout.php"></a>'
                    '<a href="/account/profile"></a>',
                ),
                profile: rendered_snapshot(profile),
            }
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            DynamicRequestAuthority(root, allow_rendered_navigation=True),
        )

        assert browser.session is not None
        self.assertEqual(browser.session.navigation_calls, [root, profile])
        self.assertNotIn(logout, result.visited_urls)
        self.assertEqual(result.completion, DynamicCrawlCompletion.COMPLETE)
        warnings = [
            warning
            for warning in result.discovery.warnings
            if warning.code == "UNSAFE_NAVIGATION_SUPPRESSED"
        ]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].details["action_token"], "logout")
        self.assertEqual(
            warnings[0].details["reason"],
            "AUTHENTICATION_STATE_CHANGE",
        )
        self.assertNotIn(logout, repr(warnings[0].details))

    def test_allowed_network_candidate_enters_dynamic_canonical_discovery(self) -> None:
        root = "http://127.0.0.1:8080/start"
        candidate, reason = browser_module._safe_network_discovery_candidate(
            method="GET",
            url=(
                "http://127.0.0.1:8080/api/search"
                "?keyword=phone&page=1&tag=a&tag=b"
            ),
            resource_type="fetch",
            source_url=root,
            root_origin=("http", "127.0.0.1", 8080),
            credential_header_present=False,
        )
        self.assertIsNone(reason)
        assert candidate is not None
        snapshots = {root: rendered_snapshot(root)}
        static_dynamic = DynamicCrawler(
            browser=FakeDynamicBrowser(snapshots),
            clock=lambda: 0.0,
        ).crawl(root, DynamicCrawlPolicy(), DynamicRequestAuthority(root))
        observed = DynamicCrawler(
            browser=FakeDynamicBrowser(
                snapshots,
                network_discovery=NetworkDiscoveryCollection(
                    candidates=(candidate,)
                ),
            ),
            clock=lambda: 0.0,
        ).crawl(root, DynamicCrawlPolicy(), DynamicRequestAuthority(root))

        endpoint = next(
            item for item in observed.discovery.endpoints if item.path == "/api/search"
        )
        self.assertEqual(
            {item.name for item in observed.discovery.input_points if item.endpoint_id == endpoint.id},
            {"keyword", "page", "tag"},
        )
        self.assertEqual(len(observed.discovery.ready_contexts()), 4)
        self.assertNotEqual(
            observed.discovery.to_dict()["discovery_snapshot_id"],
            static_dynamic.discovery.to_dict()["discovery_snapshot_id"],
        )
        self.assertNotIn("network_discovery", observed.to_dict()["browser_audit"])

    def test_post_replay_material_survives_worker_handoff_but_not_artifact(self) -> None:
        root = "http://127.0.0.1:8080/start"
        sentinel = "POST_WORKER_HANDOFF_SENTINEL_1C_A"
        candidate, replay_material, reason = (
            browser_module._safe_blocked_post_json_candidate(
                method="POST",
                url="http://127.0.0.1:8080/api/search",
                resource_type="fetch",
                source_url=root,
                root_origin=("http", "127.0.0.1", 8080),
                content_type="application/json",
                credential_header_present=False,
                body=(f'{{"keyword":"{sentinel}","page":1}}').encode(),
            )
        )
        self.assertIsNone(reason)
        assert candidate is not None
        assert replay_material is not None
        result = DynamicCrawler(
            browser=FakeDynamicBrowser(
                {root: rendered_snapshot(root)},
                network_discovery=NetworkDiscoveryCollection(
                    post_json_candidates=(candidate,),
                    post_json_replay_materials=((candidate.id, replay_material),),
                ),
            ),
            clock=lambda: 0.0,
        ).crawl(root, DynamicCrawlPolicy(), DynamicRequestAuthority(root))

        self.assertNotIn(sentinel, repr(result))
        self.assertNotIn(sentinel, repr(result.to_dict()))
        self.assertEqual(len(result.discovery.ready_contexts()), 2)
        restored = pickle.loads(pickle.dumps(result, protocol=5))
        self.assertNotIn(sentinel, repr(restored.to_dict()))
        self.assertIn(
            sentinel,
            repr(restored.discovery.request_templates[0].execution_json_body),
        )

    def test_transport_policy_bit_does_not_change_canonical_snapshot(self) -> None:
        root = "http://127.0.0.1:8080/start"
        snapshots = {root: rendered_snapshot(root)}

        strict_result = DynamicCrawler(
            browser=FakeDynamicBrowser(snapshots),
            clock=lambda: 0.0,
        ).crawl(root, DynamicCrawlPolicy(), DynamicRequestAuthority(root))
        balanced_result = DynamicCrawler(
            browser=FakeDynamicBrowser(snapshots),
            clock=lambda: 0.0,
        ).crawl(
            root,
            DynamicCrawlPolicy(),
            DynamicRequestAuthority(
                root,
                allow_passive_same_origin_fetch_xhr=True,
            ),
        )

        self.assertEqual(
            balanced_result.discovery.to_dict(),
            strict_result.discovery.to_dict(),
        )

    def test_passive_observation_serializes_only_under_audit_and_not_snapshot(
        self,
    ) -> None:
        root = "http://127.0.0.1:8080/start"
        browser = FakeDynamicBrowser({root: rendered_snapshot(root)})
        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            DynamicRequestAuthority(root),
        )
        observation = browser_module._safe_passive_network_observation(
            method="post",
            url=(
                "http://127.0.0.1:8080/private/raw-path-secret"
                "?parameter_name=QUERY_VALUE_SECRET"
            ),
            resource_type="fetch",
            root_origin=("http", "127.0.0.1", 8080),
        )
        assert observation is not None
        audit = replace(
            result.browser_audit,
            network_observations=(observation,),
            network_observation_overflow_count=3,
        )
        observed_result = replace(result, browser_audit=audit)

        payload = observed_result.to_dict()
        audit_payload = payload["browser_audit"]
        self.assertEqual(
            audit_payload["network_observations"],
            [
                {
                    "method": "POST",
                    "resource_type": "fetch",
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "effective_port": 8080,
                    "path_fingerprint": observation.path_fingerprint,
                    "path_segment_count": 2,
                    "query_parameter_names": ["parameter_name"],
                    "scope": "SAME_SCOPE",
                    "occurrence_count": 1,
                }
            ],
        )
        self.assertEqual(audit_payload["network_observation_overflow_count"], 3)
        self.assertNotIn("network_observations", payload["discovery"])
        self.assertEqual(
            payload["discovery"]["discovery_snapshot_id"],
            result.discovery.to_dict()["discovery_snapshot_id"],
        )
        serialized = repr(payload)
        self.assertNotIn("raw-path-secret", serialized)
        self.assertNotIn("QUERY_VALUE_SECRET", serialized)
        restored = pickle.loads(pickle.dumps(observed_result, protocol=5))
        self.assertEqual(restored.browser_audit, audit)
        self.assertEqual(
            restored.discovery.to_dict()["discovery_snapshot_id"],
            result.discovery.to_dict()["discovery_snapshot_id"],
        )

    def test_passive_observation_model_rejects_raw_resource_categories(self) -> None:
        with self.assertRaises(ValueError):
            PassiveNetworkObservation(
                method="GET",
                resource_type="script",
                scheme="http",
                host="127.0.0.1",
                effective_port=80,
                path_fingerprint="safe-fingerprint",
                path_segment_count=1,
                query_parameter_names=(),
                scope=PassiveNetworkScope.SAME_SCOPE,
            )
        with self.assertRaises(ValueError):
            PassiveNetworkObservation(
                method="GET",
                resource_type="fetch",
                scheme="http",
                host="127.0.0.1",
                effective_port=80,
                path_fingerprint="safe-fingerprint",
                path_segment_count=1,
                query_parameter_names=("q" * 129,),
                scope=PassiveNetworkScope.SAME_SCOPE,
            )

    def test_simple_authority_navigates_only_rendered_same_origin_anchors(
        self,
    ) -> None:
        root = "http://127.0.0.1:8080/start"
        page_a = "http://127.0.0.1:8080/page-a?from_start=one"
        page_b = "http://127.0.0.1:8080/page-b?from_a=two"
        snapshots = {
            root: rendered_snapshot(
                root,
                (
                    '<a href="/page-a?from_start=one#first"></a>'
                    '<a href="/page-a?from_start=one#duplicate"></a>'
                    '<a href="http://127.0.0.1:8081/out"></a>'
                ),
            ),
            page_a: rendered_snapshot(
                page_a,
                (
                    '<a href="/page-b?from_a=two#first"></a>'
                    '<a href="/page-b?from_a=two#duplicate"></a>'
                ),
            ),
            page_b: rendered_snapshot(
                page_b,
                (
                    '<a href="/start#cycle"></a>'
                    '<form action="/search" method="get">'
                    '<input name="from_b" value="three">'
                    "</form>"
                ),
            ),
        }
        browser = FakeDynamicBrowser(snapshots)
        authority = DynamicRequestAuthority(
            root,
            allow_rendered_navigation=True,
            allow_passive_same_origin_resources=True,
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(max_depth=2),
            authority,
        )

        self.assertEqual(result.visited_urls, (root, page_a, page_b))
        self.assertEqual([page.depth for page in result.pages], [0, 1, 2])
        self.assertEqual(
            [page.parent_url for page in result.pages],
            [None, root, page_a],
        )
        self.assertEqual(
            browser.session.navigation_calls,
            [root, page_a, page_b],
        )
        self.assertEqual(
            browser.session.rendered_navigation_calls,
            [page_a, page_b],
        )
        self.assertEqual(
            {point.name for point in result.discovery.input_points},
            {"from_a", "from_b", "from_start"},
        )
        self.assertNotIn(root + "#cycle", result.visited_urls)
        self.assertIn(
            "OFF_SCOPE_LINK",
            {warning.code for warning in result.discovery.warnings},
        )
        self.assertIn(
            "DYNAMIC_DUPLICATE_URL",
            {warning.code for warning in result.discovery.warnings},
        )

        rerun_browser = FakeDynamicBrowser(snapshots)
        rerun = DynamicCrawler(browser=rerun_browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(max_depth=2),
            authority,
        )
        self.assertEqual(rerun.visited_urls, result.visited_urls)
        self.assertEqual(rerun.pages, result.pages)
        self.assertEqual(rerun.discovery.endpoints, result.discovery.endpoints)
        self.assertEqual(rerun.discovery.input_points, result.discovery.input_points)

    def test_deterministic_bfs_uses_exact_authority_and_page_provenance(self) -> None:
        root = "http://127.0.0.1/start"
        page_a = "http://127.0.0.1/page-a"
        page_b = "http://127.0.0.1/page-b"
        page_c = "http://127.0.0.1/page-c?x=1"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    (
                        '<a href="/page-b"></a>'
                        '<a href="/page-a#one"></a>'
                        '<a href="/page-a#two"></a>'
                        '<a href="http://127.0.0.1:9/out"></a>'
                        '<a href="/not-authorized"></a>'
                    ),
                ),
                page_a: rendered_snapshot(
                    page_a,
                    '<a href="/page-c?x=1"></a><a href="/start"></a>',
                ),
                page_b: rendered_snapshot(page_b),
                page_c: rendered_snapshot(
                    page_c,
                    '<form action="/safe" method="get"><input name="q" value="1"></form>',
                ),
            }
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(page_b, page_a, page_c),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(max_depth=2),
            authority,
        )

        self.assertEqual(result.visited_urls, (root, page_a, page_b, page_c))
        self.assertEqual([item.depth for item in result.pages], [0, 1, 1, 2])
        self.assertEqual(
            [item.parent_url for item in result.pages],
            [None, root, root, page_a],
        )
        self.assertEqual(result.completion, DynamicCrawlCompletion.COMPLETE)
        self.assertEqual(
            result.termination_reason,
            DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED,
        )
        self.assertEqual(
            result.discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_DYNAMIC,
        )
        self.assertEqual(result.navigation_attempts, 4)
        self.assertEqual(result.route_actions_attempted, 0)
        self.assertTrue(result.browser_audit.cleanup_complete)
        self.assertTrue(
            all(
                provenance.depth
                == next(
                    page.depth
                    for page in result.pages
                    if page.page_url == provenance.source_url
                )
                for provenance in result.discovery.crawl_provenance
            )
        )
        self.assertEqual(browser.session.navigation_calls, list(result.visited_urls))

    def test_same_authority_redirect_uses_final_page_once(self) -> None:
        root = "http://127.0.0.1/start"
        redirect = "http://127.0.0.1/a-redirect"
        final = "http://127.0.0.1/z-final"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/a-redirect"></a><a href="/z-final"></a>',
                ),
                final: rendered_snapshot(final),
            },
            redirects={redirect: final},
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(redirect, final),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        self.assertEqual([item.page_url for item in result.pages], [root, final])
        self.assertEqual(len({item.page_url for item in result.pages}), 2)
        self.assertEqual(result.discovery.crawl_statistics.redirects_followed, 1)
        self.assertEqual(result.navigation_attempts, 3)
        result.discovery.validate()

    def test_http_error_isolated_while_later_page_is_retained(self) -> None:
        root = "http://127.0.0.1/start"
        error = "http://127.0.0.1/a-error"
        good = "http://127.0.0.1/b-good"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/a-error"></a><a href="/b-good"></a>',
                ),
                error: rendered_snapshot(error),
                good: rendered_snapshot(
                    good,
                    '<form action="/safe" method="get"><input name="live" value="yes"></form>',
                ),
            },
            statuses={error: 500},
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(error, good),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        self.assertEqual([item.page_url for item in result.pages], [root, good])
        self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
        self.assertEqual(
            result.termination_reason,
            DynamicCrawlTerminationReason.COMPLETED_WITH_FAILURES,
        )
        self.assertIn("DYNAMIC_HTTP_ERROR", {item.code for item in result.warnings})
        self.assertTrue(any(point.name == "live" for point in result.discovery.input_points))

    def test_sensitive_occurrence_stays_page_local_and_secret_free(self) -> None:
        root = "http://127.0.0.1/start"
        sensitive = "http://127.0.0.1/sensitive"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(root, '<a href="/sensitive"></a>'),
                sensitive: rendered_snapshot(
                    sensitive,
                    '<form action="/safe" method="get"><input name="safe" value="1"></form>',
                    sensitive_occurrences=(1,),
                ),
            }
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(sensitive,),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        warnings = [
            item for item in result.warnings if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].details["form_occurrence_index"], 1)
        self.assertNotIn("password", repr(result.to_dict()).lower())
        self.assertTrue(any(point.name == "safe" for point in result.discovery.input_points))


if __name__ == "__main__":
    unittest.main()
