from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vulnspider.discovery.dynamic_browser as dynamic_browser_module
from vulnspider.discovery import (
    ChildFrameDocumentKind,
    DynamicBrowserCapability,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicBrowserPolicy,
    DynamicCapabilityCode,
    DynamicCapabilityError,
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    DynamicRequestAuthority,
    DynamicResourceGrant,
    DynamicResourceKind,
    PassiveNetworkScope,
    PlaywrightDynamicBrowser,
    preflight_dynamic_browser,
)


class FakeBrowserContext:
    def route_web_socket(self) -> None:
        pass


class FakeBrowser:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


@dataclass
class FakeChromium:
    executable_path: str
    launch_error: Exception | None = None
    browser: FakeBrowser | None = None

    def __post_init__(self) -> None:
        self.launch_calls: list[dict[str, object]] = []

    def launch(self, **kwargs: object) -> FakeBrowser:
        self.launch_calls.append(kwargs)
        if self.launch_error is not None:
            raise self.launch_error
        if self.browser is None:
            self.browser = FakeBrowser()
        return self.browser


@dataclass
class FakePlaywright:
    chromium: FakeChromium
    stop_error: Exception | None = None

    def __post_init__(self) -> None:
        self.stop_calls = 0

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error


@dataclass
class FakePlaywrightManager:
    playwright: FakePlaywright | None = None
    start_error: Exception | None = None

    def start(self) -> FakePlaywright:
        if self.start_error is not None:
            raise self.start_error
        if self.playwright is None:
            raise AssertionError("test must provide a fake Playwright runtime")
        return self.playwright


class BrokenChromiumPlaywright:
    def __init__(self, *, stop_error: Exception | None = None) -> None:
        self.stop_calls = 0
        self.stop_error = stop_error

    @property
    def chromium(self) -> object:
        raise RuntimeError("PROVIDER_SECRET_PATH")

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error


def fake_loader(
    manager: FakePlaywrightManager,
    *,
    context_type: type[object] = FakeBrowserContext,
) -> tuple[type[object], object]:
    return context_type, lambda: manager


class DynamicBrowserPreflightTests(unittest.TestCase):
    def test_reports_missing_optional_package_without_importing_playwright(
        self,
    ) -> None:
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                side_effect=metadata.PackageNotFoundError,
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api"
            ) as loader,
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_PACKAGE_MISSING,
        )
        self.assertFalse(raised.exception.cleanup_failed)
        loader.assert_not_called()

    def test_redacts_package_metadata_failure(self) -> None:
        with patch(
            "vulnspider.discovery.dynamic_browser.metadata.version",
            side_effect=RuntimeError("PROVIDER_SECRET_PATH"),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_METADATA_FAILED,
        )
        self.assertNotIn("PROVIDER_SECRET_PATH", str(raised.exception))

    def test_redacts_provider_import_failure(self) -> None:
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.61.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                side_effect=RuntimeError("PROVIDER_SECRET_PATH"),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_IMPORT_FAILED,
        )
        self.assertNotIn("PROVIDER_SECRET_PATH", str(raised.exception))

    def test_rejects_unsupported_or_non_release_versions(self) -> None:
        for version in ("1.47.2", "2.0.0", "1.48.0rc1", "invalid"):
            with self.subTest(version=version):
                with patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value=version,
                ):
                    with self.assertRaises(DynamicCapabilityError) as raised:
                        preflight_dynamic_browser()
                self.assertEqual(
                    raised.exception.code,
                    DynamicCapabilityCode.PLAYWRIGHT_VERSION_UNSUPPORTED,
                )

    def test_requires_callable_context_wide_websocket_guard(self) -> None:
        class MissingGuard:
            pass

        manager = FakePlaywrightManager()
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.48.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                return_value=fake_loader(
                    manager,
                    context_type=MissingGuard,
                ),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.WEBSOCKET_GUARD_UNAVAILABLE,
        )

    def test_reports_missing_chromium_and_stops_playwright(self) -> None:
        chromium = FakeChromium("Z:/missing/playwright/chromium.exe")
        playwright = FakePlaywright(chromium)
        manager = FakePlaywrightManager(playwright)
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.48.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                return_value=fake_loader(manager),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.CHROMIUM_EXECUTABLE_MISSING,
        )
        self.assertEqual(chromium.launch_calls, [])
        self.assertEqual(playwright.stop_calls, 1)

    def test_redacts_chromium_property_failure_and_preserves_cleanup_state(
        self,
    ) -> None:
        playwright = BrokenChromiumPlaywright(
            stop_error=RuntimeError("CLEANUP_SECRET_PATH")
        )
        manager = FakePlaywrightManager(playwright)  # type: ignore[arg-type]
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.61.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                return_value=fake_loader(manager),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_RUNTIME_UNAVAILABLE,
        )
        self.assertTrue(raised.exception.cleanup_failed)
        self.assertNotIn("PROVIDER_SECRET_PATH", str(raised.exception))
        self.assertNotIn("CLEANUP_SECRET_PATH", str(raised.exception))
        self.assertEqual(playwright.stop_calls, 1)

    def test_verifies_headless_launch_and_closes_every_created_resource(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chromium.exe"
            executable.touch()
            browser = FakeBrowser()
            chromium = FakeChromium(str(executable), browser=browser)
            playwright = FakePlaywright(chromium)
            manager = FakePlaywrightManager(playwright)
            with (
                patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value="1.61.0",
                ),
                patch(
                    "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                    return_value=fake_loader(manager),
                ),
            ):
                result = preflight_dynamic_browser()

        self.assertEqual(result.playwright_version, "1.61.0")
        self.assertEqual(result.browser_name, "chromium")
        self.assertTrue(result.websocket_guard_callable)
        self.assertTrue(result.headless_launch_verified)
        self.assertEqual(chromium.launch_calls[0]["headless"], True)
        self.assertEqual(
            chromium.launch_calls[0]["env"]["CHROME_LOG_FILE"],
            os.devnull,
        )
        self.assertEqual(browser.close_calls, 1)
        self.assertEqual(playwright.stop_calls, 1)

    def test_launch_failure_still_stops_playwright(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chromium.exe"
            executable.touch()
            chromium = FakeChromium(
                str(executable),
                launch_error=RuntimeError("provider path and details"),
            )
            playwright = FakePlaywright(chromium)
            manager = FakePlaywrightManager(playwright)
            with (
                patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value="1.61.0",
                ),
                patch(
                    "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                    return_value=fake_loader(manager),
                ),
            ):
                with self.assertRaises(DynamicCapabilityError) as raised:
                    preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.CHROMIUM_LAUNCH_FAILED,
        )
        self.assertNotIn("provider path", str(raised.exception))
        self.assertEqual(playwright.stop_calls, 1)

    def test_cleanup_failure_is_never_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chromium.exe"
            executable.touch()
            browser = FakeBrowser(close_error=RuntimeError("private detail"))
            chromium = FakeChromium(str(executable), browser=browser)
            playwright = FakePlaywright(chromium)
            manager = FakePlaywrightManager(playwright)
            with (
                patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value="1.61.0",
                ),
                patch(
                    "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                    return_value=fake_loader(manager),
                ),
            ):
                with self.assertRaises(DynamicCapabilityError) as raised:
                    preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PREFLIGHT_CLEANUP_FAILED,
        )
        self.assertTrue(raised.exception.cleanup_failed)
        self.assertNotIn("private detail", str(raised.exception))
        self.assertEqual(browser.close_calls, 1)
        self.assertEqual(playwright.stop_calls, 1)


class ManagedProviderTimeoutError(Exception):
    pass


class ManagedFakePage:
    def __init__(
        self,
        events: list[str],
        *,
        close_error: Exception | None = None,
    ) -> None:
        self.events = events
        self.close_error = close_error
        self.url = "about:blank"
        self.handlers: dict[str, object] = {}

    def on(self, event: str, handler: object) -> None:
        self.handlers[event] = handler

    def goto(self, url: str, **kwargs: object) -> None:
        self.events.append("navigate")
        self.url = url

    def wait_for_selector(self, selector: str, **kwargs: object) -> None:
        self.events.append("wait_for_selector")

    def text_content(self, selector: str) -> str:
        self.events.append("text_content")
        return "marker"

    def close(self) -> None:
        self.events.append("page_close")
        if self.close_error is not None:
            raise self.close_error


class ManagedFakeContext:
    def __init__(
        self,
        events: list[str],
        page: ManagedFakePage,
        *,
        fail_at: str | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.events = events
        self.page = page
        self.fail_at = fail_at
        self.close_error = close_error
        self.http_handler: object | None = None
        self.websocket_handler: object | None = None
        self.handlers: dict[str, object] = {}

    def on(self, event: str, handler: object) -> None:
        if event == "request":
            self.events.append("passive_observer")
            if self.fail_at == "passive_observer":
                raise RuntimeError("provider passive observer detail")
        self.handlers[event] = handler

    def route(self, pattern: str, handler: object) -> None:
        self.events.append("http_guard")
        if self.fail_at == "http_guard":
            raise RuntimeError("provider http guard detail")
        self.http_handler = handler

    def route_web_socket(self, pattern: str, handler: object) -> None:
        self.events.append("websocket_guard")
        if self.fail_at == "websocket_guard":
            raise RuntimeError("provider websocket guard detail")
        self.websocket_handler = handler

    def new_page(self) -> ManagedFakePage:
        self.events.append("page_create")
        if self.fail_at == "page":
            raise RuntimeError("provider page detail")
        return self.page

    def close(self) -> None:
        self.events.append("context_close")
        if self.close_error is not None:
            raise self.close_error


class ManagedFakeBrowser:
    def __init__(
        self,
        events: list[str],
        context: ManagedFakeContext,
        *,
        fail_at: str | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.events = events
        self.context = context
        self.fail_at = fail_at
        self.close_error = close_error
        self.context_options: list[dict[str, object]] = []

    def new_context(self, **kwargs: object) -> ManagedFakeContext:
        self.events.append("context_create")
        self.context_options.append(kwargs)
        if self.fail_at == "context":
            raise RuntimeError("provider context detail")
        return self.context

    def close(self) -> None:
        self.events.append("browser_close")
        if self.close_error is not None:
            raise self.close_error


class ManagedFakeChromium:
    def __init__(
        self,
        events: list[str],
        browser: ManagedFakeBrowser,
        *,
        fail_at: str | None = None,
    ) -> None:
        self.events = events
        self.browser = browser
        self.fail_at = fail_at
        self.launch_options: list[dict[str, object]] = []

    def launch(self, **kwargs: object) -> ManagedFakeBrowser:
        self.events.append("browser_launch")
        self.launch_options.append(kwargs)
        if self.fail_at == "browser":
            raise RuntimeError("provider launch detail")
        return self.browser


class ManagedFakePlaywright:
    def __init__(
        self,
        events: list[str],
        chromium: ManagedFakeChromium,
        *,
        stop_error: Exception | None = None,
    ) -> None:
        self.events = events
        self.chromium = chromium
        self.stop_error = stop_error

    def stop(self) -> None:
        self.events.append("playwright_stop")
        if self.stop_error is not None:
            raise self.stop_error


class ManagedFakeManager:
    def __init__(
        self,
        events: list[str],
        playwright: ManagedFakePlaywright,
        *,
        fail_at: str | None = None,
    ) -> None:
        self.events = events
        self.playwright = playwright
        self.fail_at = fail_at

    def start(self) -> ManagedFakePlaywright:
        self.events.append("playwright_start")
        if self.fail_at == "playwright":
            raise RuntimeError("provider start detail")
        return self.playwright


@dataclass
class ManagedProviderFixture:
    events: list[str]
    manager: ManagedFakeManager
    chromium: ManagedFakeChromium
    browser: ManagedFakeBrowser
    context: ManagedFakeContext
    page: ManagedFakePage


def managed_provider(
    *,
    fail_at: str | None = None,
    close_failures: frozenset[str] = frozenset(),
) -> ManagedProviderFixture:
    events: list[str] = []
    page = ManagedFakePage(
        events,
        close_error=(
            RuntimeError("page cleanup private")
            if "page" in close_failures
            else None
        ),
    )
    context = ManagedFakeContext(
        events,
        page,
        fail_at=fail_at,
        close_error=(
            RuntimeError("context cleanup private")
            if "context" in close_failures
            else None
        ),
    )
    browser = ManagedFakeBrowser(
        events,
        context,
        fail_at=fail_at,
        close_error=(
            RuntimeError("browser cleanup private")
            if "browser" in close_failures
            else None
        ),
    )
    chromium = ManagedFakeChromium(
        events,
        browser,
        fail_at=fail_at,
    )
    playwright = ManagedFakePlaywright(
        events,
        chromium,
        stop_error=(
            RuntimeError("playwright cleanup private")
            if "playwright" in close_failures
            else None
        ),
    )
    manager = ManagedFakeManager(
        events,
        playwright,
        fail_at=fail_at,
    )
    return ManagedProviderFixture(
        events=events,
        manager=manager,
        chromium=chromium,
        browser=browser,
        context=context,
        page=page,
    )


def capability() -> DynamicBrowserCapability:
    return DynamicBrowserCapability(
        playwright_version="1.61.0",
        browser_name="chromium",
        websocket_guard_callable=True,
        headless_launch_verified=True,
    )


class DynamicRequestAuthorityTests(unittest.TestCase):
    def test_canonicalizes_authority_and_allows_only_exact_grants(self) -> None:
        authority = DynamicRequestAuthority(
            root_url="HTTP://127.0.0.1:80",
            navigation_urls=("http://127.0.0.1/path?x=1",),
            resource_grants=(
                DynamicResourceGrant(
                    DynamicResourceKind.SCRIPT,
                    "http://127.0.0.1/app.js",
                ),
                DynamicResourceGrant(
                    DynamicResourceKind.FETCH_XHR,
                    "http://127.0.0.1/data",
                ),
            ),
        )

        self.assertEqual(authority.root_url, "http://127.0.0.1/")
        self.assertEqual(
            authority.navigation_urls,
            ("http://127.0.0.1/", "http://127.0.0.1/path?x=1"),
        )
        root = authority.decide_http(
            method="GET",
            url="http://127.0.0.1/",
            resource_type="document",
            is_primary_page=True,
            is_main_frame=True,
        )
        script = authority.decide_http(
            method="GET",
            url="http://127.0.0.1/app.js",
            resource_type="script",
            is_primary_page=True,
            is_main_frame=True,
        )
        fetch_xhr_decisions = tuple(
            authority.decide_http(
                method="GET",
                url="http://127.0.0.1/data",
                resource_type=resource_type,
                is_primary_page=True,
                is_main_frame=True,
            )
            for resource_type in ("fetch", "xhr")
        )

        self.assertEqual(root.decision, DynamicNetworkDecisionKind.ALLOW)
        self.assertEqual(
            root.reason,
            DynamicNetworkReason.AUTHORIZED_NAVIGATION,
        )
        self.assertEqual(script.decision, DynamicNetworkDecisionKind.ALLOW)
        self.assertTrue(
            all(
                decision.decision == DynamicNetworkDecisionKind.ALLOW
                and decision.reason == DynamicNetworkReason.AUTHORIZED_RESOURCE
                for decision in fetch_xhr_decisions
            )
        )
        whitespace_method = authority.decide_http(
            method=" GET ",
            url="http://127.0.0.1/data",
            resource_type="fetch",
            is_primary_page=True,
            is_main_frame=True,
        )
        self.assertEqual(
            whitespace_method.decision,
            DynamicNetworkDecisionKind.BLOCK,
        )
        self.assertEqual(
            whitespace_method.reason,
            DynamicNetworkReason.NON_GET_METHOD,
        )

    def test_simple_mode_allows_only_observed_navigation_and_passive_resources(
        self,
    ) -> None:
        root = "http://127.0.0.1:8080/"
        authority = DynamicRequestAuthority(
            root,
            allow_rendered_navigation=True,
            allow_passive_same_origin_resources=True,
        )

        self.assertTrue(
            authority.allows_rendered_navigation(
                "http://127.0.0.1:8080/rendered?x=1"
            )
        )
        self.assertFalse(
            authority.allows_rendered_navigation(
                "http://127.0.0.1:8081/rendered?x=1"
            )
        )
        document = authority.decide_http(
            method="GET",
            url="http://127.0.0.1:8080/rendered?x=1",
            resource_type="document",
            is_primary_page=True,
            is_main_frame=True,
        )
        decisions = {
            resource_type: authority.decide_http(
                method="GET",
                url=f"http://127.0.0.1:8080/{resource_type}",
                resource_type=resource_type,
                is_primary_page=True,
                is_main_frame=True,
            )
            for resource_type in ("script", "stylesheet", "fetch", "xhr")
        }
        cross_script = authority.decide_http(
            method="GET",
            url="http://127.0.0.1:8081/app.js",
            resource_type="script",
            is_primary_page=True,
            is_main_frame=True,
        )

        self.assertEqual(document.decision, DynamicNetworkDecisionKind.BLOCK)
        self.assertEqual(
            decisions["script"].decision,
            DynamicNetworkDecisionKind.ALLOW,
        )
        self.assertEqual(
            decisions["stylesheet"].decision,
            DynamicNetworkDecisionKind.ALLOW,
        )
        self.assertEqual(decisions["fetch"].decision, DynamicNetworkDecisionKind.BLOCK)
        self.assertEqual(decisions["xhr"].decision, DynamicNetworkDecisionKind.BLOCK)
        self.assertEqual(cross_script.decision, DynamicNetworkDecisionKind.BLOCK)

    def test_balanced_fetch_xhr_allows_only_same_origin_get_and_head(self) -> None:
        root = "http://127.0.0.1:8080/"
        strict = DynamicRequestAuthority(root)
        balanced = DynamicRequestAuthority(
            root,
            allow_passive_same_origin_fetch_xhr=True,
        )

        strict_fetch = strict.decide_http(
            method="GET",
            url=root + "api",
            resource_type="fetch",
            is_primary_page=True,
            is_main_frame=True,
        )
        self.assertFalse(strict.allow_passive_same_origin_fetch_xhr)
        self.assertEqual(strict_fetch.decision, DynamicNetworkDecisionKind.BLOCK)

        for method in ("GET", "HEAD"):
            for resource_type in ("fetch", "xhr"):
                with self.subTest(method=method, resource_type=resource_type):
                    decision = balanced.decide_http(
                        method=method,
                        url=root + "api",
                        resource_type=resource_type,
                        is_primary_page=True,
                        is_main_frame=True,
                    )
                    self.assertEqual(
                        decision.decision,
                        DynamicNetworkDecisionKind.ALLOW,
                    )
                    self.assertEqual(
                        decision.reason,
                        DynamicNetworkReason.PASSIVE_SAME_ORIGIN_FETCH_XHR,
                    )

        blocked_cases = (
            ("POST", root + "api", "fetch", True),
            ("PUT", root + "api", "xhr", True),
            ("PATCH", root + "api", "fetch", True),
            ("DELETE", root + "api", "xhr", True),
            ("GET", "http://127.0.0.1:8081/api", "fetch", True),
            ("GET", "http://localhost:8080/api", "xhr", True),
            ("GET", "https://127.0.0.1:8080/api", "fetch", True),
            ("GET", "http://127.0.0.1.evil.test:8080/api", "xhr", True),
            ("GET", root + "api", "fetch", False),
            ("HEAD", root + "script.js", "script", True),
            (" HEAD ", root + "api", "fetch", True),
            ("GET", "http://127.0.0.1:0/api", "fetch", True),
        )
        for method, url, resource_type, is_primary_page in blocked_cases:
            with self.subTest(
                method=method,
                url=url,
                resource_type=resource_type,
                is_primary_page=is_primary_page,
            ):
                decision = balanced.decide_http(
                    method=method,
                    url=url,
                    resource_type=resource_type,
                    is_primary_page=is_primary_page,
                    is_main_frame=True,
                )
                self.assertEqual(
                    decision.decision,
                    DynamicNetworkDecisionKind.BLOCK,
                )

    def test_balanced_fetch_xhr_flag_requires_boolean(self) -> None:
        with self.assertRaises(DynamicBrowserError):
            DynamicRequestAuthority(
                "http://127.0.0.1/",
                allow_passive_same_origin_fetch_xhr=1,  # type: ignore[arg-type]
            )

    def test_blocks_cross_origin_redirect_methods_frames_and_internal_urls(
        self,
    ) -> None:
        authority = DynamicRequestAuthority(root_url="http://127.0.0.1:8080/")
        cases = (
            (
                dict(
                    method="GET",
                    url="http://127.0.0.1:8081/",
                    resource_type="document",
                    is_primary_page=True,
                    is_main_frame=True,
                ),
                DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
            ),
            (
                dict(
                    method="POST",
                    url="http://127.0.0.1:8080/",
                    resource_type="document",
                    is_primary_page=True,
                    is_main_frame=True,
                ),
                DynamicNetworkReason.NON_GET_METHOD,
            ),
            (
                dict(
                    method="GET",
                    url="http://127.0.0.1:8080/",
                    resource_type="document",
                    is_primary_page=True,
                    is_main_frame=False,
                ),
                DynamicNetworkReason.CHILD_FRAME_DOCUMENT,
            ),
            (
                dict(
                    method="GET",
                    url="data:text/plain,blocked",
                    resource_type="document",
                    is_primary_page=True,
                    is_main_frame=True,
                ),
                DynamicNetworkReason.UNSUPPORTED_SCHEME,
            ),
        )
        for values, reason in cases:
            with self.subTest(reason=reason):
                decision = authority.decide_http(**values)
                self.assertEqual(
                    decision.decision,
                    DynamicNetworkDecisionKind.BLOCK,
                )
                self.assertEqual(decision.reason, reason)

    def test_rejects_external_userinfo_fragment_and_cross_origin_grants(
        self,
    ) -> None:
        factories = (
            lambda: DynamicRequestAuthority("https://example.com/"),
            lambda: DynamicRequestAuthority("http://user@127.0.0.1/"),
            lambda: DynamicRequestAuthority("http://127.0.0.1/#fragment"),
            lambda: DynamicRequestAuthority("http://127.0.0.1:0/"),
            lambda: DynamicRequestAuthority(
                "http://127.0.0.1:8080/",
                resource_grants=(
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        "http://localhost:8080/app.js",
                    ),
                ),
            ),
        )
        for factory in factories:
            with self.subTest(factory=factory):
                with self.assertRaises(DynamicBrowserError) as raised:
                    factory()
                self.assertEqual(
                    raised.exception.code,
                    DynamicBrowserErrorCode.INVALID_AUTHORITY,
                )


class PassiveNetworkObservationTests(unittest.TestCase):
    class TrapRequest:
        def __init__(self, method: str, url: str, resource_type: str) -> None:
            self._values = {
                "method": method,
                "url": url,
                "resource_type": resource_type,
            }
            self.accesses: list[str] = []

        def __getattr__(self, name: str) -> object:
            if name in self._values:
                self.accesses.append(name)
                return self._values[name]
            if name in {
                "headers",
                "all_headers",
                "cookies",
                "post_data",
                "response",
                "fetch",
                "continue_",
                "fulfill",
                "abort",
            }:
                raise AssertionError(f"passive observer accessed forbidden API: {name}")
            raise AttributeError(name)

    def test_observer_is_read_only_filters_resources_and_projects_secrets(self) -> None:
        authority = DynamicRequestAuthority("http://127.0.0.1/root")
        audit = dynamic_browser_module._AuditRecorder(event_limit=20)
        observer = dynamic_browser_module._PassiveNetworkObserver(authority, audit)
        requests = [
            self.TrapRequest(
                "get",
                (
                    "http://127.0.0.1:80/raw-path-secret/nested"
                    "?alpha=QUERY_VALUE_SECRET&repeat=one&repeat=two"
                ),
                "fetch",
            ),
            self.TrapRequest(
                "post",
                "http://127.0.0.1:8081/post-target?form_name=BODY_SECRET",
                "xhr",
            ),
            self.TrapRequest(
                "GET",
                "http://127.0.0.1.example/suffix-target?token=JWT_SECRET",
                "fetch",
            ),
        ]
        excluded = [
            self.TrapRequest(
                "GET",
                f"http://127.0.0.1/{resource_type}",
                resource_type,
            )
            for resource_type in (
                "document",
                "script",
                "stylesheet",
                "image",
                "font",
                "media",
                "eventsource",
                "websocket",
            )
        ]

        for request in (*requests, *excluded):
            observer.handle_request(request)

        observations = audit.snapshot(()).network_observations
        self.assertEqual(len(observations), 3)
        same_scope = next(
            item for item in observations if item.scope == PassiveNetworkScope.SAME_SCOPE
        )
        self.assertEqual(same_scope.method, "GET")
        self.assertEqual(same_scope.resource_type, "fetch")
        self.assertEqual(same_scope.effective_port, 80)
        self.assertEqual(same_scope.path_segment_count, 2)
        self.assertEqual(
            same_scope.query_parameter_names,
            ("alpha", "repeat", "repeat"),
        )
        self.assertEqual(
            same_scope.path_fingerprint,
            dynamic_browser_module.stable_fingerprint(
                "passive-network-path",
                "/raw-path-secret/nested",
            )[:24],
        )
        self.assertEqual(
            sum(item.scope == PassiveNetworkScope.OFF_SCOPE for item in observations),
            2,
        )
        serialized = repr(observations)
        for secret in (
            "raw-path-secret",
            "QUERY_VALUE_SECRET",
            "BODY_SECRET",
            "JWT_SECRET",
            "Bearer",
            "password",
        ):
            self.assertNotIn(secret, serialized)
        for request in (*requests, *excluded):
            self.assertEqual(request.accesses, ["method", "url", "resource_type"])

    def test_observation_deduplicates_sorts_bounds_and_does_not_consume_guard(self) -> None:
        authority = DynamicRequestAuthority("http://127.0.0.1:8080/")
        policy = DynamicBrowserPolicy(request_decision_budget=2)
        audit = dynamic_browser_module._AuditRecorder(
            event_limit=policy.request_decision_budget
        )
        guard = dynamic_browser_module._RouteGuard(
            authority,
            policy,
            audit,
            lambda: None,
        )
        observer = dynamic_browser_module._PassiveNetworkObserver(authority, audit)
        first = self.TrapRequest(
            "GET",
            "http://127.0.0.1:8080/z?b=2&a=1",
            "fetch",
        )
        second = self.TrapRequest(
            "GET",
            "http://127.0.0.1:8080/a?x=1",
            "xhr",
        )
        overflow = self.TrapRequest(
            "POST",
            "http://127.0.0.1:8080/overflow?y=1",
            "fetch",
        )

        for request in (first, first, second, overflow, overflow):
            observer.handle_request(request)

        summary = audit.snapshot(())
        self.assertEqual(guard.decision_count, 0)
        self.assertEqual(summary.http_allowed_count, 0)
        self.assertEqual(summary.http_blocked_count, 0)
        self.assertEqual(summary.websocket_attempt_count, 0)
        self.assertEqual(summary.redirect_attempt_count, 0)
        self.assertEqual(len(summary.network_observations), 2)
        self.assertEqual(
            sorted(item.occurrence_count for item in summary.network_observations),
            [1, 2],
        )
        self.assertEqual(summary.network_observation_overflow_count, 2)
        self.assertEqual(
            summary.network_observations,
            tuple(
                sorted(
                    summary.network_observations,
                    key=dynamic_browser_module._passive_network_observation_key,
                )
            ),
        )

    def test_malformed_or_oversized_observation_is_safely_discarded(self) -> None:
        authority = DynamicRequestAuthority("http://127.0.0.1/")
        audit = dynamic_browser_module._AuditRecorder(event_limit=5)
        observer = dynamic_browser_module._PassiveNetworkObserver(authority, audit)
        requests = (
            self.TrapRequest("GET", "http://127.0.0.1:invalid/path", "fetch"),
            self.TrapRequest("G" * 33, "http://127.0.0.1/path", "xhr"),
            self.TrapRequest(
                "GET",
                "http://127.0.0.1/path?" + "&".join(f"q{i}=x" for i in range(65)),
                "fetch",
            ),
            self.TrapRequest(
                "GET",
                "http://127.0.0.1/" + "x" * 8192,
                "fetch",
            ),
        )

        for request in requests:
            observer.handle_request(request)

        summary = audit.snapshot(())
        self.assertEqual(summary.network_observations, ())
        self.assertEqual(summary.network_observation_overflow_count, 0)


class ManagedDynamicBrowserTests(unittest.TestCase):
    def run_with_provider(
        self,
        provider: ManagedProviderFixture,
        operation,
    ):
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.preflight_dynamic_browser",
                side_effect=lambda: (
                    provider.events.append("preflight") or capability()
                ),
            ),
            patch(
                "vulnspider.discovery.dynamic_browser."
                "_load_managed_playwright_sync_api",
                return_value=(
                    lambda: provider.manager,
                    ManagedProviderTimeoutError,
                ),
            ),
        ):
            return PlaywrightDynamicBrowser().run(
                DynamicRequestAuthority("http://127.0.0.1/"),
                operation,
            )

    def test_normal_lifecycle_installs_guards_before_page_and_cleans_reverse(
        self,
    ) -> None:
        provider = managed_provider()

        result = self.run_with_provider(
            provider,
            lambda _: provider.events.append("operation") or "ok",
        )

        self.assertEqual(result.value, "ok")
        self.assertEqual(
            provider.events,
            [
                "preflight",
                "playwright_start",
                "browser_launch",
                "context_create",
                "http_guard",
                "websocket_guard",
                "passive_observer",
                "page_create",
                "operation",
                "page_close",
                "context_close",
                "browser_close",
                "playwright_stop",
            ],
        )
        self.assertEqual(
            provider.browser.context_options,
            [{"accept_downloads": False, "service_workers": "block"}],
        )
        self.assertTrue(result.audit.cleanup_complete)

    def test_http_and_websocket_share_one_atomic_transport_budget(self) -> None:
        class Route:
            def __init__(self) -> None:
                self.fulfilled = 0
                self.aborted = 0

            def fetch(self, **kwargs: object) -> object:
                return SimpleNamespace(
                    status=200,
                    headers={},
                    dispose=lambda: None,
                )

            def fulfill(self, **kwargs: object) -> None:
                self.fulfilled += 1

            def abort(self, *, error_code: str) -> None:
                self.aborted += 1

        class WebSocketRoute:
            url = "ws://127.0.0.1/socket"

            def connect_to_server(self) -> None:
                raise AssertionError("WebSocket transport must remain denied")

            def close(self) -> None:
                raise AssertionError("synchronous route close must not be used")

        page = object()
        request = SimpleNamespace(
            url="http://127.0.0.1/",
            resource_type="document",
            method="GET",
            frame=SimpleNamespace(page=page, parent_frame=None),
        )
        audit = dynamic_browser_module._AuditRecorder(event_limit=2)
        stop_calls: list[str] = []
        guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority("http://127.0.0.1/"),
            DynamicBrowserPolicy(request_decision_budget=2),
            audit,
            lambda: stop_calls.append("stop"),
        )
        guard.set_primary_page(page)
        route = Route()

        guard.handle_http(route, request)
        guard.handle_websocket(WebSocketRoute())
        guard.handle_websocket(WebSocketRoute())
        guard.handle_websocket(WebSocketRoute())

        summary = audit.snapshot(())
        self.assertEqual(route.fulfilled, 1)
        self.assertEqual(route.aborted, 0)
        self.assertEqual(guard.decision_count, 3)
        self.assertEqual(stop_calls, ["stop"])
        with self.assertRaises(DynamicBrowserError) as raised:
            guard.raise_if_budget_exhausted()
        self.assertEqual(
            raised.exception.code,
            DynamicBrowserErrorCode.REQUEST_DECISION_BUDGET_EXHAUSTED,
        )
        self.assertEqual(summary.http_allowed_count, 1)
        self.assertEqual(summary.websocket_attempt_count, 2)
        self.assertEqual(summary.websocket_blocked_count, 2)
        self.assertEqual(summary.websocket_connected_count, 0)
        self.assertEqual(summary.request_decision_overflow_count, 1)

    def test_child_frame_lifecycle_classification_is_bounded_and_subtyped(
        self,
    ) -> None:
        authority = DynamicRequestAuthority("http://127.0.0.1/")
        cases = (
            ("http://127.0.0.1/", ChildFrameDocumentKind.AUTHORIZED),
            ("http://127.0.0.1/blocked", ChildFrameDocumentKind.UNAUTHORIZED),
            ("about:blank", ChildFrameDocumentKind.ABOUT_BLANK),
            (
                "chrome-error://chromewebdata/",
                ChildFrameDocumentKind.BROWSER_ERROR,
            ),
            ("about:srcdoc", ChildFrameDocumentKind.REPLACEMENT),
        )
        audit = dynamic_browser_module._AuditRecorder(event_limit=2)

        for url, expected in cases:
            classification = dynamic_browser_module._classify_child_frame_commit(
                url,
                authority,
            )
            self.assertEqual(classification, expected)
            audit.record_child_frame_commit(classification)
            audit.record_child_frame_completion(classification)

        summary = audit.snapshot(())
        self.assertEqual(summary.child_frame_commit_count, 5)
        self.assertEqual(summary.child_frame_completion_count, 5)
        self.assertEqual(summary.child_frame_authorized_commit_count, 1)
        self.assertEqual(summary.child_frame_unauthorized_commit_count, 1)
        self.assertEqual(summary.child_frame_internal_commit_count, 3)
        self.assertEqual(summary.child_frame_about_blank_commit_count, 1)
        self.assertEqual(summary.child_frame_browser_error_commit_count, 1)
        self.assertEqual(summary.child_frame_replacement_commit_count, 1)
        self.assertEqual(summary.child_frame_authorized_completion_count, 1)
        self.assertEqual(summary.child_frame_unauthorized_completion_count, 1)
        self.assertEqual(summary.child_frame_internal_completion_count, 3)
        self.assertEqual(summary.child_frame_about_blank_completion_count, 1)
        self.assertEqual(summary.child_frame_browser_error_completion_count, 1)
        self.assertEqual(summary.child_frame_replacement_completion_count, 1)
        self.assertEqual(
            summary.child_frame_commit_kinds,
            (
                ChildFrameDocumentKind.AUTHORIZED,
                ChildFrameDocumentKind.UNAUTHORIZED,
            ),
        )
        self.assertEqual(summary.child_frame_commit_overflow_count, 3)
        self.assertEqual(summary.child_frame_completion_overflow_count, 3)

    def test_http_redirect_hops_are_authorized_before_transport(self) -> None:
        class Response:
            def __init__(
                self,
                status: int,
                location: str | None = None,
                *,
                dispose_error: bool = False,
            ) -> None:
                self.status = status
                self.headers = {} if location is None else {"location": location}
                self.disposed = False
                self.dispose_error = dispose_error

            def dispose(self) -> None:
                if self.dispose_error:
                    raise RuntimeError("provider cleanup detail")
                self.disposed = True

        class Route:
            def __init__(self, responses: list[Response]) -> None:
                self.responses = responses
                self.fetch_urls: list[str] = []
                self.fulfilled = 0
                self.aborted = 0

            def fetch(self, *, url: str, **kwargs: object) -> Response:
                self.fetch_urls.append(url)
                return self.responses.pop(0)

            def fulfill(self, **kwargs: object) -> None:
                self.fulfilled += 1

            def abort(self, *, error_code: str) -> None:
                self.aborted += 1

        page = object()
        root_url = "http://127.0.0.1/redirect"
        target_url = "http://127.0.0.1/target"
        request = SimpleNamespace(
            url=root_url,
            resource_type="document",
            method="GET",
            frame=SimpleNamespace(page=page, parent_frame=None),
        )
        audit = dynamic_browser_module._AuditRecorder(event_limit=10)
        guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority(
                root_url,
                navigation_urls=(target_url,),
            ),
            DynamicBrowserPolicy(request_decision_budget=10),
            audit,
            lambda: None,
        )
        guard.set_primary_page(page)
        allowed_route = Route(
            [Response(302, "/target")]
        )

        guard.handle_http(allowed_route, request)

        self.assertEqual(allowed_route.fetch_urls, [root_url])
        self.assertEqual(allowed_route.fulfilled, 1)
        target_route = Route([Response(200)])
        guard.handle_http(
            target_route,
            SimpleNamespace(
                url=target_url,
                resource_type="document",
                method="GET",
                frame=SimpleNamespace(page=page, parent_frame=None),
            ),
        )
        self.assertEqual(target_route.fetch_urls, [target_url])
        self.assertEqual(target_route.fulfilled, 1)
        self.assertEqual(allowed_route.aborted, 0)
        allowed_summary = audit.snapshot(())
        self.assertEqual(allowed_summary.redirect_attempt_count, 1)
        self.assertEqual(allowed_summary.redirect_allowed_count, 1)
        self.assertEqual(allowed_summary.redirect_block_count, 0)
        self.assertEqual(allowed_summary.redirect_followed_count, 1)
        guard.raise_if_failed()

        budget_audit = dynamic_browser_module._AuditRecorder(event_limit=10)
        budget_guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority(root_url, navigation_urls=(target_url,)),
            DynamicBrowserPolicy(
                request_decision_budget=10,
                navigation_request_budget=1,
            ),
            budget_audit,
            lambda: None,
        )
        budget_guard.set_primary_page(page)
        budget_root_route = Route([Response(302, "/target")])
        budget_guard.handle_http(budget_root_route, request)
        budget_target_route = Route([Response(200)])
        budget_guard.handle_http(
            budget_target_route,
            SimpleNamespace(
                url=target_url,
                resource_type="document",
                method="GET",
                frame=SimpleNamespace(page=page, parent_frame=None),
            ),
        )
        budget_summary = budget_audit.snapshot(())
        self.assertEqual(budget_target_route.fetch_urls, [])
        self.assertEqual(budget_summary.redirect_allowed_count, 1)
        self.assertEqual(budget_summary.redirect_followed_count, 0)

        blocked_audit = dynamic_browser_module._AuditRecorder(event_limit=10)
        blocked_guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority(root_url),
            DynamicBrowserPolicy(request_decision_budget=10),
            blocked_audit,
            lambda: None,
        )
        blocked_guard.set_primary_page(page)
        blocked_route = Route(
            [Response(302, "http://127.0.0.1:8080/external")]
        )

        blocked_guard.handle_http(blocked_route, request)

        self.assertEqual(blocked_route.fetch_urls, [root_url])
        self.assertEqual(blocked_route.fulfilled, 0)
        self.assertEqual(blocked_route.aborted, 1)
        blocked_summary = blocked_audit.snapshot(())
        self.assertEqual(blocked_summary.redirect_attempt_count, 1)
        self.assertEqual(blocked_summary.redirect_allowed_count, 0)
        self.assertEqual(blocked_summary.redirect_block_count, 1)
        self.assertEqual(blocked_summary.redirect_followed_count, 0)
        with self.assertRaises(DynamicBrowserError) as raised:
            blocked_guard.raise_if_failed()
        self.assertEqual(
            raised.exception.code,
            DynamicBrowserErrorCode.NAVIGATION_FAILED,
        )

        cleanup_guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority(root_url),
            DynamicBrowserPolicy(request_decision_budget=10),
            dynamic_browser_module._AuditRecorder(event_limit=10),
            lambda: None,
        )
        cleanup_guard.set_primary_page(page)
        cleanup_route = Route([Response(200, dispose_error=True)])

        cleanup_guard.handle_http(cleanup_route, request)

        self.assertEqual(cleanup_route.fulfilled, 1)
        with self.assertRaises(DynamicBrowserError) as cleanup_raised:
            cleanup_guard.raise_if_failed()
        self.assertEqual(
            cleanup_raised.exception.code,
            DynamicBrowserErrorCode.HTTP_RESPONSE_DISPOSE_FAILED,
        )

        script_url = "http://127.0.0.1/app.js"
        script_target_url = "http://127.0.0.1/app-v2.js"
        script_audit = dynamic_browser_module._AuditRecorder(event_limit=10)
        script_guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority(
                root_url,
                resource_grants=(
                    DynamicResourceGrant(DynamicResourceKind.SCRIPT, script_url),
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        script_target_url,
                    ),
                ),
            ),
            DynamicBrowserPolicy(request_decision_budget=10),
            script_audit,
            lambda: None,
        )
        script_guard.set_primary_page(page)
        script_route = Route(
            [Response(302, "/app-v2.js"), Response(200)]
        )
        script_guard.handle_http(
            script_route,
            SimpleNamespace(
                url=script_url,
                resource_type="script",
                method="GET",
                frame=SimpleNamespace(page=page, parent_frame=None),
            ),
        )
        script_summary = script_audit.snapshot(())
        self.assertEqual(script_route.fetch_urls, [script_url, script_target_url])
        self.assertEqual(script_summary.redirect_allowed_count, 1)
        self.assertEqual(script_summary.redirect_followed_count, 0)
        self.assertEqual(script_summary.main_frame_navigation_allowed_count, 0)

        balanced_audit = dynamic_browser_module._AuditRecorder(event_limit=10)
        balanced_guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority(
                root_url,
                allow_passive_same_origin_fetch_xhr=True,
            ),
            DynamicBrowserPolicy(request_decision_budget=10),
            balanced_audit,
            lambda: None,
        )
        balanced_guard.set_primary_page(page)
        balanced_route = Route([Response(302, "/api-v2"), Response(200)])
        balanced_guard.handle_http(
            balanced_route,
            SimpleNamespace(
                url="http://127.0.0.1/api",
                resource_type="fetch",
                method="HEAD",
                frame=SimpleNamespace(page=page, parent_frame=None),
            ),
        )
        balanced_summary = balanced_audit.snapshot(())
        self.assertEqual(
            balanced_route.fetch_urls,
            ["http://127.0.0.1/api", "http://127.0.0.1/api-v2"],
        )
        self.assertEqual(balanced_route.fulfilled, 1)
        self.assertEqual(balanced_route.aborted, 0)
        self.assertEqual(balanced_summary.redirect_allowed_count, 1)
        self.assertEqual(balanced_summary.http_allowed_count, 2)
        self.assertEqual(balanced_summary.http_blocked_count, 0)
        self.assertEqual(balanced_summary.request_decision_overflow_count, 0)

        off_scope_audit = dynamic_browser_module._AuditRecorder(event_limit=10)
        off_scope_guard = dynamic_browser_module._RouteGuard(
            DynamicRequestAuthority(
                root_url,
                allow_passive_same_origin_fetch_xhr=True,
            ),
            DynamicBrowserPolicy(request_decision_budget=10),
            off_scope_audit,
            lambda: None,
        )
        off_scope_guard.set_primary_page(page)
        off_scope_route = Route(
            [Response(302, "http://127.0.0.1:8080/api-v2")]
        )
        off_scope_guard.handle_http(
            off_scope_route,
            SimpleNamespace(
                url="http://127.0.0.1/api",
                resource_type="xhr",
                method="GET",
                frame=SimpleNamespace(page=page, parent_frame=None),
            ),
        )
        off_scope_summary = off_scope_audit.snapshot(())
        self.assertEqual(off_scope_route.fetch_urls, ["http://127.0.0.1/api"])
        self.assertEqual(off_scope_route.fulfilled, 0)
        self.assertEqual(off_scope_route.aborted, 1)
        self.assertEqual(off_scope_summary.redirect_block_count, 1)
        self.assertEqual(off_scope_summary.http_allowed_count, 1)
        self.assertEqual(off_scope_summary.http_blocked_count, 1)
        self.assertEqual(off_scope_summary.request_decision_overflow_count, 0)

    def test_preflight_failure_starts_no_provider_resource(self) -> None:
        provider = managed_provider()
        failure = DynamicCapabilityError(
            DynamicCapabilityCode.CHROMIUM_LAUNCH_FAILED,
            "preflight failed",
            setup_hint="safe hint",
        )
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.preflight_dynamic_browser",
                side_effect=failure,
            ),
            patch(
                "vulnspider.discovery.dynamic_browser."
                "_load_managed_playwright_sync_api"
            ) as loader,
        ):
            with self.assertRaises(DynamicCapabilityError):
                PlaywrightDynamicBrowser().run(
                    DynamicRequestAuthority("http://127.0.0.1/"),
                    lambda _: None,
                )
        self.assertEqual(provider.events, [])
        loader.assert_not_called()

    def test_each_partial_initialization_failure_cleans_created_resources(
        self,
    ) -> None:
        cases = (
            ("playwright", DynamicBrowserErrorCode.PLAYWRIGHT_START_FAILED, []),
            (
                "browser",
                DynamicBrowserErrorCode.BROWSER_LAUNCH_FAILED,
                ["playwright_stop"],
            ),
            (
                "context",
                DynamicBrowserErrorCode.CONTEXT_CREATE_FAILED,
                ["browser_close", "playwright_stop"],
            ),
            (
                "http_guard",
                DynamicBrowserErrorCode.HTTP_GUARD_INSTALL_FAILED,
                ["context_close", "browser_close", "playwright_stop"],
            ),
            (
                "websocket_guard",
                DynamicBrowserErrorCode.WEBSOCKET_GUARD_INSTALL_FAILED,
                ["context_close", "browser_close", "playwright_stop"],
            ),
            (
                "passive_observer",
                DynamicBrowserErrorCode.PASSIVE_OBSERVER_INSTALL_FAILED,
                ["context_close", "browser_close", "playwright_stop"],
            ),
            (
                "page",
                DynamicBrowserErrorCode.PAGE_CREATE_FAILED,
                ["context_close", "browser_close", "playwright_stop"],
            ),
        )
        for fail_at, code, cleanup_tail in cases:
            with self.subTest(fail_at=fail_at):
                provider = managed_provider(fail_at=fail_at)
                with self.assertRaises(DynamicBrowserError) as raised:
                    self.run_with_provider(provider, lambda _: None)
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(
                    provider.events[-len(cleanup_tail) :] if cleanup_tail else [],
                    cleanup_tail,
                )
                if fail_at in {
                    "http_guard",
                    "websocket_guard",
                    "passive_observer",
                }:
                    self.assertNotIn("page_create", provider.events)

    def test_operation_exception_and_timeout_preserve_typed_primary_error(
        self,
    ) -> None:
        cases = (
            (
                RuntimeError("provider operation private"),
                DynamicBrowserErrorCode.OPERATION_FAILED,
            ),
            (
                ManagedProviderTimeoutError("provider timeout private"),
                DynamicBrowserErrorCode.OPERATION_TIMEOUT,
            ),
        )
        for error, code in cases:
            with self.subTest(code=code):
                provider = managed_provider()

                def operation(_):
                    raise error

                with self.assertRaises(DynamicBrowserError) as raised:
                    self.run_with_provider(provider, operation)
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn("private", str(raised.exception))
                self.assertTrue(raised.exception.audit.cleanup_complete)

    def test_cleanup_failures_do_not_stop_later_cleanup_or_replace_primary(
        self,
    ) -> None:
        provider = managed_provider(
            close_failures=frozenset({"page", "browser"}),
        )

        def operation(_):
            raise RuntimeError("operation private")

        with self.assertRaises(DynamicBrowserError) as raised:
            self.run_with_provider(provider, operation)

        error = raised.exception
        self.assertEqual(error.code, DynamicBrowserErrorCode.OPERATION_FAILED)
        self.assertEqual(
            error.cleanup_error_codes,
            ("PAGE_CLOSE_FAILED", "BROWSER_CLOSE_FAILED"),
        )
        self.assertIn("context_close", provider.events)
        self.assertIn("playwright_stop", provider.events)
        self.assertNotIn("private", str(error))
        self.assertFalse(error.audit.cleanup_complete)

    def test_cleanup_failure_without_primary_is_not_reported_as_success(
        self,
    ) -> None:
        provider = managed_provider(
            close_failures=frozenset({"context"}),
        )
        with self.assertRaises(DynamicBrowserError) as raised:
            self.run_with_provider(provider, lambda _: "ok")
        self.assertEqual(
            raised.exception.code,
            DynamicBrowserErrorCode.CLEANUP_FAILED,
        )
        self.assertEqual(
            raised.exception.cleanup_error_codes,
            ("CONTEXT_CLOSE_FAILED",),
        )

    def test_managed_resource_close_is_idempotent(self) -> None:
        provider = managed_provider()
        audit = dynamic_browser_module._AuditRecorder(event_limit=5)
        resources = dynamic_browser_module._ManagedResources(
            audit,
            playwright=provider.manager.playwright,
            browser=provider.browser,
            context=provider.context,
            page=provider.page,
        )

        first = resources.close()
        second = resources.close()

        self.assertEqual(first, ())
        self.assertEqual(second, ())
        self.assertEqual(provider.events.count("page_close"), 1)
        self.assertEqual(provider.events.count("context_close"), 1)
        self.assertEqual(provider.events.count("browser_close"), 1)
        self.assertEqual(provider.events.count("playwright_stop"), 1)

    def test_session_page_close_uses_managed_idempotent_cleanup(self) -> None:
        provider = managed_provider()

        def operation(session):
            session.close_page()
            session.close_page()
            return "closed"

        result = self.run_with_provider(provider, operation)

        self.assertEqual(result.value, "closed")
        self.assertEqual(provider.events.count("page_close"), 1)
        self.assertEqual(provider.events.count("context_close"), 1)
        self.assertEqual(provider.events.count("browser_close"), 1)
        self.assertEqual(provider.events.count("playwright_stop"), 1)
        self.assertEqual(result.audit.pages_created, 1)
        self.assertEqual(result.audit.pages_closed, 1)
        self.assertTrue(result.audit.cleanup_complete)

    def test_limited_session_navigation_and_dom_read_methods(self) -> None:
        provider = managed_provider()

        def operation(session):
            url = session.navigate()
            session.wait_for_selector("#marker")
            return url, session.text_content("#marker")

        result = self.run_with_provider(provider, operation)

        self.assertEqual(result.value, ("http://127.0.0.1/", "marker"))
        self.assertIn("navigate", provider.events)
        self.assertIn("wait_for_selector", provider.events)
        self.assertIn("text_content", provider.events)

    def test_unauthorized_navigation_is_blocked_before_page_goto(self) -> None:
        provider = managed_provider()
        with self.assertRaises(DynamicBrowserError) as raised:
            self.run_with_provider(
                provider,
                lambda session: session.navigate("http://127.0.0.1:8080/"),
            )
        self.assertEqual(
            raised.exception.code,
            DynamicBrowserErrorCode.NAVIGATION_NOT_AUTHORIZED,
        )
        self.assertNotIn("navigate", provider.events)


if __name__ == "__main__":
    unittest.main()
