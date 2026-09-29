from __future__ import annotations

from collections import Counter
import json
import os
import pickle
import socket
import tempfile
import unittest
from http.client import HTTPConnection
from pathlib import Path
from urllib.request import urlopen

from tests.integration.dynamic_loopback_site import (
    NETWORK_API_KEY_SENTINEL,
    NETWORK_JWT_SENTINEL,
    DynamicLoopbackSite,
)
from vulnspider.discovery import (
    ChildFrameDocumentKind,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicBrowserPolicy,
    DynamicCapabilityError,
    DynamicCrawler,
    DynamicCrawlPolicy,
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    DynamicRequestAuthority,
    DynamicResourceGrant,
    DynamicResourceKind,
    ProbeReadyStatus,
    PassiveNetworkScope,
    PlaywrightDynamicBrowser,
    preflight_dynamic_browser,
)
from vulnspider.domain import HttpMethod, InputLocation


class DynamicLoopbackHarnessTests(unittest.TestCase):
    def test_binds_ephemeral_loopback_port_records_requests_and_closes(self) -> None:
        site = DynamicLoopbackSite()
        with site:
            primary_port = site.primary_port
            sentinel_port = site.sentinel_port
            self.assertGreater(primary_port, 0)
            self.assertGreater(sentinel_port, 0)
            self.assertNotEqual(primary_port, sentinel_port)
            self.assertTrue(all(site.server_threads_alive))
            with urlopen(site.root_url, timeout=1.0) as response:
                body = response.read().decode("utf-8")
            self.assertIn("initial-marker", body)
            self.assertEqual(
                [(item.method, item.path) for item in site.primary_requests],
                [("GET", "/")],
            )
            self.assertEqual(site.sentinel_requests, ())

        self.assertTrue(site.cleanup_complete)
        self.assertEqual(site.server_threads_alive, (False, False))
        for port in (primary_port, sentinel_port):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            finally:
                probe.close()

    def test_test_exception_still_closes_both_servers(self) -> None:
        site = DynamicLoopbackSite()
        with self.assertRaisesRegex(RuntimeError, "test failure"):
            with site:
                raise RuntimeError("test failure")
        self.assertTrue(site.cleanup_complete)
        self.assertEqual(site.server_threads_alive, (False, False))

    def test_extended_routes_are_observable_without_reaching_sentinel(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            page_expectations = (
                (site.eventsource_url, "EventSource"),
                (site.websocket_url, "WebSocket"),
                (site.fetch_xhr_url, "XMLHttpRequest"),
                (site.unsafe_get_url, "state-change"),
                (site.autosubmit_url, "requestSubmit"),
                (site.page_close_url, "page-close-marker"),
                (site.iframe_url, "frame-child"),
                (site.popup_url, "window.open"),
                (site.location_same_url, "location.replace"),
                (site.location_cross_url, "location.replace"),
                (site.redirect_target_url, "redirect-marker"),
                (site.location_target_url, "location-marker"),
            )
            for url, marker in page_expectations:
                with urlopen(url, timeout=1.0) as response:
                    body = response.read().decode("utf-8")
                self.assertIn(marker, body)

            def redirect_response(path: str) -> tuple[int, str | None]:
                connection = HTTPConnection(
                    "127.0.0.1",
                    site.primary_port,
                    timeout=1.0,
                )
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    response.read()
                    return response.status, response.getheader("Location")
                finally:
                    connection.close()

            self.assertEqual(
                redirect_response("/redirect-same"),
                (302, "/redirect/final"),
            )
            self.assertEqual(
                redirect_response("/redirect-cross"),
                (302, "/redirect/intermediate"),
            )
            self.assertEqual(
                redirect_response("/redirect/intermediate"),
                (302, f"{site.sentinel_origin}/redirect-target"),
            )
            self.assertEqual(site.sentinel_requests, ())
            self.assertEqual(
                [item.path for item in site.primary_requests],
                [
                    "/eventsource",
                    "/websocket",
                    "/fetch-xhr",
                    "/unsafe-get",
                    "/autosubmit",
                    "/page-close",
                    "/iframe",
                    "/popup",
                    "/location-same",
                    "/location-cross",
                    "/redirect/final",
                    "/location-target",
                    "/redirect-same",
                    "/redirect-cross",
                    "/redirect/intermediate",
                ],
            )

        self.assertTrue(site.cleanup_complete)
        self.assertEqual(site.server_threads_alive, (False, False))


class DynamicBrowserLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._original_cwd = Path.cwd()
        cls._browser_workdir = tempfile.TemporaryDirectory(
            prefix="vulnspider-browser-"
        )
        os.chdir(cls._browser_workdir.name)
        try:
            preflight_dynamic_browser()
        except DynamicCapabilityError as exc:
            os.chdir(cls._original_cwd)
            cls._browser_workdir.cleanup()
            raise unittest.SkipTest(
                f"real Chromium unavailable: {exc.code.value}"
            ) from None

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._original_cwd)
        cls._browser_workdir.cleanup()

    def test_real_chromium_executes_javascript_and_blocks_external_transports(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.root_url,
                resource_grants=(
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        site.allowed_script_url,
                    ),
                ),
            )

            def operation(session):
                navigated_url = session.navigate()
                session.wait_for_selector("#dynamic-marker")
                return navigated_url, session.text_content("#dynamic-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, (site.root_url, "javascript-executed"))
            primary_paths = [item.path for item in site.primary_requests]
            self.assertIn("/", primary_paths)
            self.assertIn("/allowed.js", primary_paths)
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        self.assertEqual(audit.playwright_started, 1)
        self.assertEqual(audit.playwright_stopped, 1)
        self.assertEqual(audit.browsers_launched, 1)
        self.assertEqual(audit.browsers_closed, 1)
        self.assertEqual(audit.contexts_created, 1)
        self.assertEqual(audit.contexts_closed, 1)
        self.assertEqual(audit.pages_created, 1)
        self.assertEqual(audit.pages_closed, 1)
        self.assertGreaterEqual(audit.http_allowed_count, 2)
        self.assertGreaterEqual(audit.http_blocked_count, 1)
        self.assertEqual(audit.websocket_attempt_count, 1)
        self.assertEqual(audit.websocket_blocked_count, 1)
        self.assertEqual(audit.websocket_connected_count, 0)
        self.assertTrue(
            any(
                event.decision == DynamicNetworkDecisionKind.BLOCK
                and event.reason == DynamicNetworkReason.REQUEST_NOT_AUTHORIZED
                and event.path == "/blocked.js"
                for event in audit.events
            )
        )
        self.assertTrue(
            any(
                event.reason == DynamicNetworkReason.WEBSOCKET_DENIED
                and event.path == "/socket"
                for event in audit.events
            )
        )

    def test_real_eventsource_attempts_are_blocked(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.eventsource_url)

            def operation(session):
                session.navigate()
                session.wait_for_selector("#eventsource-marker")
                return session.text_content("#eventsource-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, "both-blocked")
            primary_paths = [item.path for item in site.primary_requests]
            self.assertIn("/eventsource", primary_paths)
            self.assertNotIn("/event-stream", primary_paths)
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        self.assertEqual(audit.eventsource_attempt_count, 2)
        self.assertEqual(audit.eventsource_blocked_count, 2)
        self.assertEqual(audit.eventsource_allowed_count, 0)
        self.assertEqual(
            sum(
                event.reason == DynamicNetworkReason.EVENTSOURCE_DENIED
                for event in audit.events
            ),
            2,
        )

    def test_real_same_and_cross_authority_websockets_are_denied(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.websocket_url)

            def operation(session):
                session.navigate()
                session.wait_for_selector("#websocket-marker")
                return session.text_content("#websocket-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, "constructors-attempted")
            self.assertEqual(
                [item.path for item in site.primary_requests],
                ["/websocket"],
            )
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        self.assertEqual(audit.websocket_attempt_count, 2)
        self.assertEqual(audit.websocket_blocked_count, 2)
        self.assertEqual(audit.websocket_connected_count, 0)
        self.assertEqual(
            {
                event.path
                for event in audit.events
                if event.reason == DynamicNetworkReason.WEBSOCKET_DENIED
            },
            {"/same-socket", "/cross-socket"},
        )

    def test_real_fetch_and_xhr_are_blocked_before_transport(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.fetch_xhr_url)

            def operation(session):
                session.navigate()
                session.wait_for_selector("#fetch-xhr-marker")
                return session.text_content("#fetch-xhr-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, "both-blocked")
            self.assertEqual(
                [item.path for item in site.primary_requests],
                ["/fetch-xhr"],
            )
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        blocked = {
            (event.resource_kind, event.path): event.reason
            for event in audit.events
            if event.decision == DynamicNetworkDecisionKind.BLOCK
        }
        self.assertEqual(
            blocked[("fetch", "/fetch-target")],
            DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
        )
        self.assertEqual(
            blocked[("xhr", "/xhr-target")],
            DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
        )

    def test_real_balanced_fetch_xhr_allows_only_natural_same_origin_get_head(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.balanced_fetch_xhr_url,
                resource_grants=(
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        site.balanced_fetch_xhr_script_url,
                    ),
                    DynamicResourceGrant(
                        DynamicResourceKind.STYLE,
                        site.balanced_fetch_xhr_style_url,
                    ),
                ),
                allow_passive_same_origin_fetch_xhr=True,
            )

            result = DynamicCrawler().crawl(
                site.balanced_fetch_xhr_url,
                DynamicCrawlPolicy(
                    max_pages=1,
                    max_depth=0,
                    max_navigation_attempts=1,
                    request_decision_budget=30,
                ),
                authority,
            )

            request_counts = Counter(
                (item.method, item.path) for item in site.primary_requests
            )
            self.assertEqual(
                request_counts,
                Counter(
                    {
                        ("GET", "/balanced-fetch-xhr"): 1,
                        ("GET", "/balanced-fetch-xhr.js"): 1,
                        ("GET", "/balanced-fetch-xhr.css"): 1,
                        ("GET", "/balanced/get-fetch"): 1,
                        ("GET", "/balanced/get-xhr"): 1,
                        ("HEAD", "/balanced/head-fetch"): 1,
                        ("GET", "/balanced/redirect-same"): 1,
                        ("GET", "/balanced/redirect-final"): 1,
                        ("GET", "/balanced/redirect-cross"): 1,
                    }
                ),
            )
            self.assertEqual(
                request_counts[("POST", "/balanced/post-fetch")],
                0,
            )
            self.assertEqual(site.sentinel_requests, ())

        observations = result.browser_audit.network_observations
        self.assertEqual(len(observations), 7)
        self.assertEqual(
            {
                (item.method, item.resource_type, item.scope)
                for item in observations
            },
            {
                ("GET", "fetch", PassiveNetworkScope.SAME_SCOPE),
                ("GET", "xhr", PassiveNetworkScope.SAME_SCOPE),
                ("HEAD", "fetch", PassiveNetworkScope.SAME_SCOPE),
                ("POST", "fetch", PassiveNetworkScope.SAME_SCOPE),
                ("GET", "fetch", PassiveNetworkScope.OFF_SCOPE),
            },
        )
        self.assertTrue(all(item.occurrence_count == 1 for item in observations))
        self.assertFalse(
            {"script", "stylesheet"}
            & {item.resource_type for item in observations}
        )
        self.assertIn(
            DynamicNetworkReason.PASSIVE_SAME_ORIGIN_FETCH_XHR,
            {
                event.reason
                for event in result.browser_audit.events
                if event.decision == DynamicNetworkDecisionKind.ALLOW
            },
        )
        self.assertIn(
            DynamicNetworkReason.NON_GET_METHOD,
            {
                event.reason
                for event in result.browser_audit.events
                if event.decision == DynamicNetworkDecisionKind.BLOCK
            },
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        for secret in (
            "GET_FETCH_VALUE_SECRET",
            "GET_XHR_VALUE_SECRET",
            "HEAD_VALUE_SECRET",
            "POST_QUERY_VALUE_SECRET",
            "AUTHORIZATION_VALUE_SECRET",
            "POST_BODY_VALUE_SECRET",
            "OFF_SCOPE_VALUE_SECRET",
        ):
            self.assertNotIn(secret, serialized)
        endpoints = {item.path: item for item in result.discovery.endpoints}
        self.assertTrue(
            {"/balanced/get-fetch", "/balanced/get-xhr"} <= set(endpoints)
        )
        self.assertNotIn("/balanced/head-fetch", endpoints)
        self.assertNotIn("/balanced/post-fetch", endpoints)
        sensitive_ids = {
            endpoints["/balanced/get-fetch"].id,
            endpoints["/balanced/get-xhr"].id,
        }
        sensitive_points = tuple(
            item
            for item in result.discovery.input_points
            if item.endpoint_id in sensitive_ids
        )
        self.assertEqual(
            {item.name for item in sensitive_points},
            {"api_key", "session"},
        )
        self.assertTrue(
            all(item.baseline_value is None for item in sensitive_points)
        )
        readiness = {
            item.input_point_id: item for item in result.discovery.probe_readiness
        }
        self.assertTrue(
            all(
                readiness[item.id or ""].status.value == "NOT_READY"
                for item in sensitive_points
            )
        )
        self.assertFalse(
            {
                item.id
                for item in result.discovery.request_templates
                if item.endpoint_id in sensitive_ids
            }
        )
        self.assertTrue(result.browser_audit.cleanup_complete)

    def test_real_observed_get_api_canonicalization_is_transport_free(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.network_canonicalization_url,
                resource_grants=(
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        site.network_canonicalization_script_url,
                    ),
                    DynamicResourceGrant(
                        DynamicResourceKind.STYLE,
                        site.network_canonicalization_style_url,
                    ),
                ),
                allow_passive_same_origin_fetch_xhr=True,
            )

            result = DynamicCrawler().crawl(
                site.network_canonicalization_url,
                DynamicCrawlPolicy(
                    max_pages=1,
                    max_depth=0,
                    max_navigation_attempts=1,
                    request_decision_budget=20,
                ),
                authority,
            )

            request_counts = Counter(
                (item.method, item.path) for item in site.primary_requests
            )
            self.assertEqual(
                request_counts,
                Counter(
                    {
                        ("GET", "/network-canonicalization"): 1,
                        ("GET", "/network-canonicalization.js"): 1,
                        ("GET", "/network-canonicalization.css"): 1,
                        ("GET", "/api/search"): 1,
                        ("GET", "/api/filter"): 1,
                        ("GET", "/api/private"): 1,
                        ("HEAD", "/api/head"): 1,
                    }
                ),
            )
            self.assertEqual(request_counts[("POST", "/api/post")], 0)
            self.assertEqual(site.sentinel_requests, ())

        endpoints = {item.path: item for item in result.discovery.endpoints}
        self.assertIn("/api/search", endpoints)
        self.assertIn("/api/filter", endpoints)
        self.assertIn("/api/private", endpoints)
        for excluded in ("/api/head", "/api/post", "/api/off-scope"):
            self.assertNotIn(excluded, endpoints)
        api_endpoint_ids = {
            endpoints["/api/search"].id,
            endpoints["/api/filter"].id,
        }
        api_points = tuple(
            item
            for item in result.discovery.input_points
            if item.endpoint_id in api_endpoint_ids
        )
        self.assertEqual(
            sorted((item.name, item.occurrence_index) for item in api_points),
            [
                ("category", None),
                ("keyword", None),
                ("page", None),
                ("tag", 0),
                ("tag", 1),
            ],
        )
        self.assertEqual(len(result.discovery.ready_contexts()), 5)
        self.assertEqual(len(result.discovery.request_templates), 2)
        self.assertEqual(len(result.discovery.input_point_request_contexts), 5)
        private_endpoint = endpoints["/api/private"]
        private_points = tuple(
            item
            for item in result.discovery.input_points
            if item.endpoint_id == private_endpoint.id
        )
        self.assertEqual(
            [(item.name, item.baseline_value) for item in private_points],
            [("page", None)],
        )
        readiness = {
            item.input_point_id: item for item in result.discovery.probe_readiness
        }
        self.assertEqual(readiness[private_points[0].id or ""].status.value, "NOT_READY")
        self.assertFalse(
            any(
                item.endpoint_id == private_endpoint.id
                for item in result.discovery.request_templates
            )
        )
        warning = next(
            item
            for item in result.discovery.warnings
            if item.code == "NETWORK_GET_VALUES_ELIDED"
        )
        self.assertEqual(warning.details["elided_candidate_count"], 1)
        self.assertEqual(warning.details["structural_candidate_count"], 1)
        self.assertEqual(
            {
                item.discovered_by
                for item in endpoints.values()
                if item.id in api_endpoint_ids
            },
            {"native_dynamic_network"},
        )
        self.assertEqual(
            {
                origin
                for point in api_points
                for origin in point.metadata["origin_kinds"]
            },
            {"network_fetch", "network_xhr"},
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        for secret in (
            "HEAD_CANONICALIZATION_SECRET",
            "POST_CANONICALIZATION_SECRET",
            "POST_AUTHORIZATION_SECRET",
            "GET_AUTHORIZATION_CANONICALIZATION_SECRET",
            "POST_BODY_CANONICALIZATION_SECRET",
            "OFF_SCOPE_CANONICALIZATION_SECRET",
        ):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("network_discovery", result.to_dict()["browser_audit"])
        self.assertTrue(result.browser_audit.cleanup_complete)

    def test_real_blocked_post_json_is_classified_without_browser_transport(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.observed_post_json_url,
                allow_passive_same_origin_fetch_xhr=True,
            )
            result = DynamicCrawler().crawl(
                site.observed_post_json_url,
                DynamicCrawlPolicy(
                    max_pages=1,
                    max_depth=0,
                    max_navigation_attempts=1,
                    request_decision_budget=20,
                ),
                authority,
            )
            request_counts = Counter(
                (item.method, item.path) for item in site.primary_requests
            )
            self.assertEqual(
                request_counts,
                Counter({("GET", "/observed-post-json"): 1}),
            )
            self.assertFalse(any(method == "POST" for method, _ in request_counts))
            self.assertEqual(site.sentinel_requests, ())

        endpoints = tuple(
            item for item in result.discovery.endpoints if item.path == "/api/search"
        )
        self.assertEqual(len(endpoints), 1)
        endpoint = endpoints[0]
        self.assertEqual(endpoint.method, HttpMethod.POST)
        points = tuple(
            item
            for item in result.discovery.input_points
            if item.endpoint_id == endpoint.id
        )
        self.assertEqual(
            {(item.name, item.location) for item in points},
            {
                ("keyword", InputLocation.JSON_BODY),
                ("page", InputLocation.JSON_BODY),
            },
        )
        readiness = {
            item.input_point_id: item for item in result.discovery.probe_readiness
        }
        self.assertTrue(
            all(
                readiness[item.id or ""].status == ProbeReadyStatus.READY
                and readiness[item.id or ""].request_context_id is not None
                for item in points
            )
        )
        search_templates = tuple(
            template
            for template in result.discovery.request_templates
            if template.endpoint_id == endpoint.id
        )
        self.assertEqual(len(search_templates), 1)
        template = search_templates[0]
        self.assertEqual(
            template.metadata["post_replay_disposition"],
            "SAFE_FOR_PROBE",
        )
        self.assertIsNotNone(template.ephemeral_material)
        self.assertEqual(
            sum(
                context.input_point_id in {point.id for point in points}
                for context in result.discovery.input_point_request_contexts
            ),
            2,
        )

        serialized = json.dumps(result.to_dict(), sort_keys=True)
        pickled = pickle.dumps(result, protocol=5)
        for secret in (
            "phone",
            "POST_AUTHORIZATION_VALUE_SENTINEL",
            "POST_PASSWORD_VALUE_SENTINEL",
            "POST_API_KEY_VALUE_SENTINEL",
            "POST_TOKEN_VALUE_SENTINEL",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        ):
            self.assertNotIn(secret, serialized)
        for secret in (
            "POST_AUTHORIZATION_VALUE_SENTINEL",
            "POST_PASSWORD_VALUE_SENTINEL",
            "POST_API_KEY_VALUE_SENTINEL",
            "POST_TOKEN_VALUE_SENTINEL",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        ):
            self.assertNotIn(secret.encode(), pickled)
        canonical_paths = {
            item.path for item in result.discovery.endpoints
        }
        self.assertIn("/api/secret", canonical_paths)
        secret_endpoint = next(
            item
            for item in result.discovery.endpoints
            if item.path == "/api/secret"
        )
        secret_template = next(
            item
            for item in result.discovery.request_templates
            if item.endpoint_id == secret_endpoint.id
        )
        self.assertEqual(
            secret_template.metadata["post_replay_disposition"],
            "BLOCKED_SENSITIVE",
        )
        self.assertIsNone(secret_template.ephemeral_material)
        for rejected in (
            "/api/malformed",
            "/api/array",
            "/api/duplicate",
            "/api/oversized",
            "/api/off-scope-post",
        ):
            self.assertNotIn(rejected, canonical_paths)
        warning = next(
            item
            for item in result.discovery.warnings
            if item.code == "NETWORK_POST_JSON_SKIPPED"
        )
        self.assertEqual(warning.details["skipped_attempt_count"], 4)
        self.assertTrue(result.browser_audit.cleanup_complete)

    def test_real_passive_network_observation_is_bounded_and_never_replays(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.network_observation_url,
                resource_grants=(
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        site.network_observation_script_url,
                    ),
                    DynamicResourceGrant(
                        DynamicResourceKind.STYLE,
                        site.network_observation_style_url,
                    ),
                    DynamicResourceGrant(
                        DynamicResourceKind.FETCH_XHR,
                        site.network_observation_fetch_url,
                    ),
                    DynamicResourceGrant(
                        DynamicResourceKind.FETCH_XHR,
                        site.network_observation_xhr_url,
                    ),
                ),
            )

            result = DynamicCrawler().crawl(
                site.network_observation_url,
                DynamicCrawlPolicy(
                    max_pages=1,
                    max_depth=0,
                    max_navigation_attempts=1,
                    request_decision_budget=20,
                ),
                authority,
            )

            request_counts = Counter(
                (item.method, item.path) for item in site.primary_requests
            )
            self.assertEqual(
                request_counts,
                Counter(
                    {
                        ("GET", "/network-observation"): 1,
                        ("GET", "/network-observation.js"): 1,
                        ("GET", "/network-observation.css"): 1,
                        ("GET", "/network-observation/get-fetch"): 1,
                        ("GET", "/network-observation/get-xhr"): 1,
                    }
                ),
            )
            self.assertEqual(
                request_counts[("POST", "/network-observation/post-fetch")],
                0,
            )
            self.assertEqual(site.sentinel_requests, ())

        observations = result.browser_audit.network_observations
        self.assertEqual(len(observations), 4)
        self.assertEqual(
            {
                (item.method, item.resource_type, item.scope)
                for item in observations
            },
            {
                ("GET", "fetch", PassiveNetworkScope.SAME_SCOPE),
                ("GET", "xhr", PassiveNetworkScope.SAME_SCOPE),
                ("POST", "fetch", PassiveNetworkScope.SAME_SCOPE),
                ("GET", "fetch", PassiveNetworkScope.OFF_SCOPE),
            },
        )
        self.assertEqual(
            {
                item.query_parameter_names for item in observations
            },
            {
                ("alpha", "repeat", "repeat"),
                ("beta",),
                ("post_name",),
                ("outside",),
            },
        )
        self.assertTrue(all(item.path_segment_count >= 2 for item in observations))
        self.assertTrue(all(item.occurrence_count == 1 for item in observations))
        self.assertEqual(
            result.browser_audit.network_observation_overflow_count,
            0,
        )
        self.assertTrue(
            any(
                event.resource_kind == "script"
                and event.decision == DynamicNetworkDecisionKind.ALLOW
                for event in result.browser_audit.events
            )
        )
        self.assertTrue(
            any(
                event.resource_kind == "stylesheet"
                and event.decision == DynamicNetworkDecisionKind.ALLOW
                for event in result.browser_audit.events
            )
        )
        self.assertNotIn(
            "script",
            {item.resource_type for item in observations},
        )
        self.assertNotIn(
            "stylesheet",
            {item.resource_type for item in observations},
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        for secret in (
            NETWORK_API_KEY_SENTINEL,
            NETWORK_JWT_SENTINEL,
            "POST_QUERY_VALUE_SECRET",
            "OFF_SCOPE_QUERY_SECRET",
            "AUTHORIZATION_SECRET",
            "POST_BODY_PASSWORD_SECRET",
        ):
            self.assertNotIn(secret, serialized)
        endpoints = {item.path: item for item in result.discovery.endpoints}
        network_paths = {
            "/network-observation/get-fetch",
            "/network-observation/get-xhr",
        }
        self.assertTrue(network_paths <= set(endpoints))
        network_endpoint_ids = {endpoints[path].id for path in network_paths}
        network_points = tuple(
            item
            for item in result.discovery.input_points
            if item.endpoint_id in network_endpoint_ids
        )
        self.assertEqual(
            sorted((item.name, item.occurrence_index) for item in network_points),
            [("alpha", None), ("beta", None), ("repeat", 0), ("repeat", 1)],
        )
        self.assertTrue(all(item.baseline_value is None for item in network_points))
        self.assertFalse(
            any(
                item.endpoint_id in network_endpoint_ids
                for item in result.discovery.request_templates
            )
        )
        warning = next(
            item
            for item in result.discovery.warnings
            if item.code == "NETWORK_GET_VALUES_ELIDED"
        )
        self.assertEqual(warning.details["elided_candidate_count"], 2)
        self.assertEqual(warning.details["structural_candidate_count"], 2)
        self.assertEqual(warning.details["audit_only_candidate_count"], 0)
        self.assertTrue(result.browser_audit.cleanup_complete)

    def test_real_unauthorized_same_origin_get_is_blocked(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.unsafe_get_url)
            with self.assertRaises(DynamicBrowserError) as raised:
                PlaywrightDynamicBrowser().run(
                    authority,
                    lambda session: session.navigate(),
                )

            self.assertEqual(
                [item.path for item in site.primary_requests],
                ["/unsafe-get"],
            )
            self.assertEqual(site.sentinel_requests, ())

        error = raised.exception
        self.assertEqual(error.code, DynamicBrowserErrorCode.NAVIGATION_FAILED)
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertTrue(
            any(
                event.resource_kind == "document"
                and event.reason == DynamicNetworkReason.REQUEST_NOT_AUTHORIZED
                and event.path == "/state-change"
                for event in error.audit.events
            )
        )

    def test_real_autosubmit_post_is_blocked_before_transport(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.autosubmit_url)
            with self.assertRaises(DynamicBrowserError) as raised:
                PlaywrightDynamicBrowser().run(
                    authority,
                    lambda session: session.navigate(),
                )

            self.assertEqual(
                [(item.method, item.path) for item in site.primary_requests],
                [("GET", "/autosubmit")],
            )
            self.assertEqual(site.sentinel_requests, ())

        error = raised.exception
        self.assertEqual(error.code, DynamicBrowserErrorCode.NAVIGATION_FAILED)
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertTrue(
            any(
                event.resource_kind == "document"
                and event.reason == DynamicNetworkReason.NON_GET_METHOD
                and event.path == "/submit-target"
                for event in error.audit.events
            )
        )

    def test_real_dom_driven_page_close_is_idempotently_cleaned(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.page_close_url)

            def operation(session):
                session.navigate()
                session.wait_for_selector("#page-close-marker")
                value = session.text_content("#page-close-marker")
                session.close_page()
                return value

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, "ready-to-close")
            self.assertEqual(
                [item.path for item in site.primary_requests],
                ["/page-close"],
            )
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        self.assertEqual(audit.pages_created, 1)
        self.assertEqual(audit.pages_closed, 1)
        self.assertEqual(audit.contexts_closed, 1)
        self.assertEqual(audit.browsers_closed, 1)
        self.assertEqual(audit.playwright_stopped, 1)

    def test_real_child_frames_are_blocked_and_detached(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.iframe_url)

            def operation(session):
                session.navigate()
                session.wait_for_selector("#iframe-marker")
                return session.text_content("#iframe-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, "children-blocked")
            primary_paths = [item.path for item in site.primary_requests]
            self.assertIn("/iframe", primary_paths)
            self.assertNotIn("/frame-child", primary_paths)
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        self.assertEqual(audit.child_frame_attach_attempt_count, 4)
        self.assertEqual(audit.child_frame_document_request_count, 2)
        self.assertEqual(audit.child_frame_document_blocked_count, 2)
        self.assertEqual(audit.child_frame_authorized_commit_count, 0)
        self.assertEqual(audit.child_frame_unauthorized_commit_count, 0)
        self.assertEqual(
            audit.child_frame_commit_count,
            audit.child_frame_internal_commit_count,
        )
        self.assertGreaterEqual(audit.child_frame_about_blank_commit_count, 1)
        self.assertGreaterEqual(audit.child_frame_browser_error_commit_count, 1)
        self.assertGreaterEqual(audit.child_frame_replacement_commit_count, 1)
        self.assertIn(
            ChildFrameDocumentKind.ABOUT_BLANK,
            audit.child_frame_commit_kinds,
        )
        self.assertIn(
            ChildFrameDocumentKind.BROWSER_ERROR,
            audit.child_frame_commit_kinds,
        )
        self.assertIn(
            ChildFrameDocumentKind.REPLACEMENT,
            audit.child_frame_commit_kinds,
        )
        self.assertEqual(audit.child_frame_commit_overflow_count, 0)
        self.assertEqual(audit.child_frame_completion_count, 0)
        self.assertEqual(audit.child_frame_detach_count, 4)
        self.assertEqual(
            sum(
                event.reason == DynamicNetworkReason.CHILD_FRAME_DOCUMENT
                for event in audit.events
            ),
            2,
        )

    def test_real_popup_is_guarded_and_cleaned(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.popup_url)

            def operation(session):
                session.navigate()
                session.wait_for_selector("#popup-marker")
                return session.text_content("#popup-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, "popup-attempted")
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        self.assertEqual(audit.popup_attempt_count, 1)
        self.assertEqual(audit.pages_created, 2)
        self.assertEqual(audit.pages_closed, 2)
        self.assertTrue(
            any(
                event.reason == DynamicNetworkReason.NON_PRIMARY_PAGE
                and event.path == "/popup-target"
                for event in audit.events
            )
        )

    def test_real_same_authority_http_redirect_completes(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.redirect_same_url,
                navigation_urls=(site.redirect_target_url,),
                resource_grants=(
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        site.redirect_relative_script_url,
                    ),
                ),
            )

            def operation(session):
                navigated_url = session.navigate()
                session.wait_for_selector("#redirect-marker")
                session.wait_for_selector("#redirect-relative-marker")
                return (
                    navigated_url,
                    session.text_content("#redirect-marker"),
                    session.text_content("#redirect-relative-marker"),
                )

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(
                result.value,
                (
                    site.redirect_target_url,
                    "same-authority",
                    "target-relative",
                ),
            )
            self.assertEqual(
                [item.path for item in site.primary_requests],
                [
                    "/redirect-same",
                    "/redirect/final",
                    "/redirect/relative.js",
                ],
            )
            self.assertEqual(site.sentinel_requests, ())

        self.assertTrue(result.audit.cleanup_complete)
        self.assertEqual(result.audit.redirect_attempt_count, 1)
        self.assertEqual(result.audit.redirect_allowed_count, 1)
        self.assertEqual(result.audit.redirect_block_count, 0)

    def test_real_cross_authority_http_redirect_is_blocked(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.redirect_cross_url,
                navigation_urls=(site.redirect_cross_intermediate_url,),
            )
            with self.assertRaises(DynamicBrowserError) as raised:
                PlaywrightDynamicBrowser().run(
                    authority,
                    lambda session: session.navigate(),
                )

            self.assertEqual(
                [item.path for item in site.primary_requests],
                ["/redirect-cross", "/redirect/intermediate"],
            )
            self.assertEqual(site.sentinel_requests, ())

        error = raised.exception
        self.assertEqual(error.code, DynamicBrowserErrorCode.NAVIGATION_FAILED)
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertEqual(error.audit.redirect_attempt_count, 2)
        self.assertEqual(error.audit.redirect_allowed_count, 1)
        self.assertEqual(error.audit.redirect_block_count, 1)
        self.assertTrue(
            any(
                event.reason == DynamicNetworkReason.REQUEST_NOT_AUTHORIZED
                and event.path == "/redirect-target"
                for event in error.audit.events
            )
        )

    def test_real_same_authority_js_location_completes(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.location_same_url,
                navigation_urls=(site.location_target_url,),
            )

            def operation(session):
                navigated_url = session.navigate()
                session.wait_for_selector("#location-marker")
                return navigated_url, session.text_content("#location-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(
                result.value,
                (site.location_target_url, "same-authority"),
            )
            self.assertEqual(
                [item.path for item in site.primary_requests],
                ["/location-same", "/location-target"],
            )
            self.assertEqual(site.sentinel_requests, ())

        self.assertTrue(result.audit.cleanup_complete)

    def test_real_cross_authority_js_location_is_blocked(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.location_cross_url)
            with self.assertRaises(DynamicBrowserError) as raised:
                PlaywrightDynamicBrowser().run(
                    authority,
                    lambda session: session.navigate(),
                )

            self.assertEqual(
                [item.path for item in site.primary_requests],
                ["/location-cross"],
            )
            self.assertEqual(site.sentinel_requests, ())

        error = raised.exception
        self.assertEqual(error.code, DynamicBrowserErrorCode.NAVIGATION_FAILED)
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertTrue(
            any(
                event.reason == DynamicNetworkReason.REQUEST_NOT_AUTHORIZED
                and event.path == "/location-target"
                for event in error.audit.events
            )
        )

    def test_real_navigation_timeout_preserves_error_and_cleanup_audit(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.slow_url)
            try:
                with self.assertRaises(DynamicBrowserError) as raised:
                    PlaywrightDynamicBrowser().run(
                        authority,
                        lambda session: session.navigate(),
                        policy=DynamicBrowserPolicy(
                            navigation_timeout_seconds=0.1,
                            request_decision_budget=10,
                        ),
                    )
            finally:
                site.release_slow.set()

            self.assertTrue(site.slow_started.wait(timeout=1.0))
            self.assertIn(
                "/slow",
                [item.path for item in site.primary_requests],
            )

        error = raised.exception
        self.assertEqual(
            error.code,
            DynamicBrowserErrorCode.NAVIGATION_TIMEOUT,
        )
        self.assertEqual(error.cleanup_error_codes, ())
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertEqual(error.audit.pages_closed, 1)
        self.assertEqual(error.audit.contexts_closed, 1)
        self.assertEqual(error.audit.browsers_closed, 1)
        self.assertEqual(error.audit.playwright_stopped, 1)

    def test_real_shared_transport_budget_stops_websocket_flood(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.websocket_budget_url,
            )
            with self.assertRaises(DynamicBrowserError) as raised:
                PlaywrightDynamicBrowser().run(
                    authority,
                    lambda session: session.navigate(),
                    policy=DynamicBrowserPolicy(
                        navigation_timeout_seconds=1.0,
                        request_decision_budget=2,
                    ),
                )

            self.assertIn(
                "/websocket-budget",
                [item.path for item in site.primary_requests],
            )
            self.assertEqual(site.sentinel_requests, ())

        error = raised.exception
        self.assertEqual(
            error.code,
            DynamicBrowserErrorCode.REQUEST_DECISION_BUDGET_EXHAUSTED,
        )
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertEqual(error.audit.pages_created, 1)
        self.assertEqual(error.audit.pages_closed, 1)
        self.assertGreaterEqual(error.audit.websocket_attempt_count, 2)
        self.assertEqual(
            error.audit.websocket_blocked_count,
            error.audit.websocket_attempt_count,
        )
        self.assertEqual(error.audit.websocket_connected_count, 0)
        self.assertEqual(error.audit.request_decision_overflow_count, 1)
        processed_decisions = (
            error.audit.http_allowed_count
            + error.audit.http_blocked_count
            + error.audit.websocket_attempt_count
        )
        self.assertLessEqual(processed_decisions, 3)


if __name__ == "__main__":
    unittest.main()
