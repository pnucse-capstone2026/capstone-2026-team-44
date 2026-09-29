from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import vulnspider.discovery.html_extractor as extractor_module
from vulnspider.discovery import (
    NonProbeReadyReason,
    ProbeReadyStatus,
    SensitiveFormElisionPolicy,
    extract_static_html,
)
from vulnspider.domain import HttpMethod, InputLocation


SOURCE_URL = "http://example.test/root/index.html"
SENSITIVE_FORM_POLICY = SensitiveFormElisionPolicy()


class StaticHtmlExtractorAdversarialTests(unittest.TestCase):
    def test_off_scope_links_never_become_executable_request_objects(self) -> None:
        source_url = "http://localhost:4280/root"
        external_urls = {
            "https://www.youtube.com/watch?v=test",
            "http://localhost:8080/other?port=1",
            "https://localhost/secure?scheme=1",
            "http://127.0.0.1:4280/ip?host=1",
        }
        result = extract_static_html(
            """
            <a href="/local?id=1">Local</a>
            <a href="https://www.youtube.com/watch?v=test">YouTube</a>
            <a href="http://localhost:8080/other?port=1">Port</a>
            <a href="https://localhost/secure?scheme=1">Scheme</a>
            <a href="http://127.0.0.1:4280/ip?host=1">Host</a>
            <form action="https://outside.test/submit" method="get">
              <input name="external_form" value="never">
            </form>
            """,
            source_url,
        )

        self.assertIn(
            "http://localhost:4280/local?id=1",
            {template.url for template in result.discovery.request_templates},
        )
        self.assertTrue(
            external_urls.isdisjoint(
                template.url for template in result.discovery.request_templates
            )
        )
        self.assertNotIn(
            "external_form",
            {point.name for point in result.discovery.input_points},
        )
        external_hosts = {"www.youtube.com", "localhost:8080", "127.0.0.1:4280"}
        self.assertTrue(
            external_hosts.isdisjoint(
                endpoint.host for endpoint in result.discovery.endpoints
            )
        )
        self.assertTrue(
            all(
                template.url.startswith("http://localhost:4280/")
                for template in result.discovery.request_templates
            )
        )
        self.assertEqual(
            {warning.code for warning in result.discovery.warnings}
            & {"OFF_SCOPE_LINK", "OFF_SCOPE_FORM_ACTION"},
            {"OFF_SCOPE_LINK", "OFF_SCOPE_FORM_ACTION"},
        )
        self.assertTrue(
            external_urls.isdisjoint(
                link.crawl_url for link in result.navigable_links
            )
        )
        result.discovery.validate()

    def test_suppressed_link_query_values_are_never_serialized(self) -> None:
        sentinel = "CSRF_SECRET_123"
        result = extract_static_html(
            f"""
            <a href="/account?action=logout&amp;csrf={sentinel}">Logout</a>
            <a href="https://outside.test/path?csrf={sentinel}">Outside</a>
            <a href="/safe?q=ok">Safe</a>
            """,
            SOURCE_URL,
        )

        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(sentinel, serialized)
        self.assertEqual(
            {link.crawl_url for link in result.navigable_links},
            {"http://example.test/safe?q=ok"},
        )
        self.assertEqual(
            {template.url for template in result.discovery.request_templates},
            {"http://example.test/safe?q=ok"},
        )
        self.assertEqual(
            {warning.code for warning in result.discovery.warnings}
            & {"OFF_SCOPE_LINK", "UNSAFE_NAVIGATION_SUPPRESSED"},
            {"OFF_SCOPE_LINK", "UNSAFE_NAVIGATION_SUPPRESSED"},
        )

    def test_preserves_raw_query_tokens_and_repeated_occurrences(self) -> None:
        raw_query = (
            "tag=a&tag=a&q=&flag&q=%2Fadmin%2Fusers&"
            "encoded%20key=v&double=%252F"
        )
        result = extract_static_html(
            f"""
            <a href="/search?{raw_query}#one">one</a>
            <a href="/search?{raw_query}#two">two</a>
            """,
            SOURCE_URL,
        )
        search_links = [
            item
            for item in result.navigable_links
            if item.crawl_url.startswith("http://example.test/search?")
        ]
        self.assertEqual(len(search_links), 2)
        self.assertEqual(search_links[0].crawl_url, search_links[1].crawl_url)
        self.assertNotIn("#", search_links[0].crawl_url)

        template = next(
            item
            for item in result.discovery.request_templates
            if item.url.startswith("http://example.test/search?")
        )
        self.assertEqual(template.url.split("?", 1)[1], raw_query)
        self.assertEqual(
            template.query,
            (
                ("tag", "a"),
                ("tag", "a"),
                ("q", ""),
                ("flag", ""),
                ("q", "/admin/users"),
                ("encoded key", "v"),
                ("double", "%2F"),
            ),
        )
        tag_points = sorted(
            (
                item
                for item in result.discovery.input_points
                if item.name == "tag"
            ),
            key=lambda item: item.occurrence_index or 0,
        )
        self.assertEqual([item.occurrence_index for item in tag_points], [0, 1])
        self.assertNotEqual(tag_points[0].id, tag_points[1].id)
        self.assertEqual(
            [item.baseline_value for item in tag_points],
            ["a", "a"],
        )
        q_points = sorted(
            (item for item in result.discovery.input_points if item.name == "q"),
            key=lambda item: item.occurrence_index or 0,
        )
        self.assertEqual(
            [item.metadata["raw_query_token"] for item in q_points],
            ["q=", "q=%2Fadmin%2Fusers"],
        )
        flag = next(
            item for item in result.discovery.input_points if item.name == "flag"
        )
        self.assertEqual(flag.baseline_value, "")
        self.assertEqual(flag.metadata["raw_query_token"], "flag")

    def test_canonical_equivalent_names_share_occurrence_identity(self) -> None:
        result = extract_static_html(
            """
            <a href="/search?A=1&a=2&%20=ignored">query</a>
            <form method="post" action="/submit">
              <input name="A" value="1">
              <input name="a" value="2">
            </form>
            """,
            SOURCE_URL,
        )
        query_points = sorted(
            (
                item
                for item in result.discovery.input_points
                if item.location == InputLocation.QUERY and item.name == "a"
            ),
            key=lambda item: item.occurrence_index or 0,
        )
        form_points = sorted(
            (
                item
                for item in result.discovery.input_points
                if item.location == InputLocation.FORM and item.name == "a"
            ),
            key=lambda item: item.occurrence_index or 0,
        )
        self.assertEqual(
            [item.occurrence_index for item in query_points],
            [0, 1],
        )
        self.assertEqual(
            [item.occurrence_index for item in form_points],
            [0, 1],
        )
        self.assertEqual(
            [item.baseline_value for item in query_points],
            ["1", "2"],
        )
        self.assertEqual(
            [item.baseline_value for item in form_points],
            ["1", "2"],
        )
        self.assertIn(
            "QUERY_PARAMETER_NAME_MISSING",
            {item.code for item in result.warnings},
        )
        result.discovery.validate()

    def test_invalid_links_become_structured_warnings(self) -> None:
        sensitive_href = "javascript:send('never-in-link-warning')"
        result = extract_static_html(
            f"""
            <a href="">empty</a>
            <a>missing</a>
            <a href="{sensitive_href}">js</a>
            <a href="mailto:a@example.test">mail</a>
            <a href="data:text/plain,hello">data</a>
            <a href="tel:+12025550123">tel</a>
            <a href="http://[::1">broken</a>
            <a href="https://outside.test/path?q=1">external metadata</a>
            """,
            SOURCE_URL,
        )
        codes = [item.code for item in result.warnings]
        self.assertIn("LINK_HREF_EMPTY", codes)
        self.assertIn("LINK_HREF_MISSING", codes)
        self.assertEqual(codes.count("LINK_SCHEME_UNSUPPORTED"), 4)
        self.assertIn("LINK_URL_MALFORMED", codes)
        self.assertNotIn(
            "https://outside.test/path?q=1",
            {item.crawl_url for item in result.navigable_links},
        )
        self.assertIn("OFF_SCOPE_LINK", codes)
        warning_payload = json.dumps(
            [
                (item.code, item.message, dict(item.details))
                for item in result.warnings
            ],
            sort_keys=True,
        )
        self.assertNotIn(sensitive_href, warning_payload)
        self.assertIn("href_fingerprint", warning_payload)

    def test_form_successful_control_rules_are_deterministic(self) -> None:
        secret = "never-in-warning"
        result = extract_static_html(
            f"""
            <form method="pOsT" action="../submit">
              <input type="hidden" name="token" value="x">
              <input type="hidden" name="token" value="x">
              <input disabled name="disabled" value="no">
              <input value="missing-name">
              <input type="password" name="password" value="{secret}">
              <input type="checkbox" name="checked" checked>
              <input type="checkbox" name="unchecked" value="no">
              <input type="radio" name="choice" value="a" checked>
              <input type="radio" name="choice" value="b">
              <input type="file" name="upload">
              <input type="submit" name="submitter" value="send">
              <select name="roles" multiple>
                <option value="reader" selected>Reader</option>
                <option selected>writer</option>
                <option value="disabled" selected disabled>Disabled</option>
              </select>
              <select name="empty"></select>
            </form>
            <input name="outside" value="ignored">
            """,
            SOURCE_URL,
        )
        template = next(
            item
            for item in result.discovery.request_templates
            if item.method == HttpMethod.POST
        )
        self.assertEqual(
            template.form,
            (
                ("token", "x"),
                ("token", "x"),
                ("password", secret),
                ("checked", "on"),
                ("choice", "a"),
                ("roles", "reader"),
                ("roles", "writer"),
                # The named submit control rides on the request body as a fixed
                # gate parameter (a browser sends it), but is never an input
                # point -- asserted below.
                ("submitter", "send"),
            ),
        )
        self.assertNotIn(
            "submitter",
            {item.name for item in result.discovery.input_points},
        )
        token_points = sorted(
            (item for item in result.discovery.input_points if item.name == "token"),
            key=lambda item: item.occurrence_index or 0,
        )
        self.assertEqual([item.occurrence_index for item in token_points], [0, 1])
        self.assertNotEqual(token_points[0].id, token_points[1].id)
        role_points = [
            item for item in result.discovery.input_points if item.name == "roles"
        ]
        self.assertEqual(len(role_points), 2)
        self.assertTrue(
            all(item.location == InputLocation.FORM for item in token_points)
        )
        warning_text = json.dumps(
            [
                (item.code, item.message, dict(item.details))
                for item in result.warnings
            ],
            sort_keys=True,
        )
        self.assertNotIn(secret, warning_text)
        self.assertIn("FORM_CONTROL_DISABLED", warning_text)
        self.assertIn("FORM_CONTROL_NAME_MISSING", warning_text)
        self.assertIn("FORM_CONTROL_UNCHECKED", warning_text)
        self.assertIn("FORM_CONTROL_FILE_UNSUPPORTED", warning_text)
        self.assertIn("FORM_CONTROL_OUTSIDE_FORM", warning_text)
        self.assertIn("FORM_SELECT_OPTION_MISSING", warning_text)

    def test_missing_form_defaults_and_malformed_forms_fail_closed(self) -> None:
        result = extract_static_html(
            """
            <form action="">
              <input name="q" value="">
            </form>
            <form action="/outer">
              <input name="outer" value="1">
              <form method="post" action="/nested">
                <input name="nested" value="2">
              </form>
            <form method="post" action="/unclosed">
              <input name="tail" value="3">
            """,
            SOURCE_URL,
        )
        complete = next(
            item
            for item in result.discovery.request_templates
            if item.metadata.get("form_action_provenance")
            == "html_default_current_document"
        )
        self.assertEqual(complete.method, HttpMethod.GET)
        self.assertEqual(
            complete.url,
            "http://example.test/root/index.html?q=",
        )
        incomplete_template_ids = {
            item.id
            for item in result.discovery.request_templates
            if item.metadata.get("form_boundary_status") == "unavailable"
        }
        self.assertGreaterEqual(len(incomplete_template_ids), 2)
        contexts = {
            item.id: item for item in result.discovery.input_point_request_contexts
        }
        readiness = [
            item
            for item in result.discovery.probe_readiness
            if item.request_context_id
            and contexts[item.request_context_id].request_template_id
            in incomplete_template_ids
        ]
        self.assertTrue(readiness)
        self.assertTrue(
            all(item.status == ProbeReadyStatus.NOT_READY for item in readiness)
        )
        self.assertTrue(
            all(
                NonProbeReadyReason.FORM_BOUNDARY_UNAVAILABLE in item.reasons
                for item in readiness
            )
        )

    def test_malformed_form_action_is_skipped_without_stopping_document(self) -> None:
        sensitive_action = "http://[::1?token=never-in-action-warning"
        result = extract_static_html(
            f"""
            <form action="{sensitive_action}">
              <input name="bad" value="1">
            </form>
            <a href="/still-found?q=ok">ok</a>
            """,
            SOURCE_URL,
        )
        self.assertIn(
            "http://example.test/still-found?q=ok",
            {item.crawl_url for item in result.navigable_links},
        )
        self.assertIn(
            "FORM_ACTION_MALFORMED",
            {item.code for item in result.warnings},
        )
        self.assertNotIn(
            "bad",
            {item.name for item in result.discovery.input_points},
        )
        warning_payload = json.dumps(
            [
                (item.code, item.message, dict(item.details))
                for item in result.warnings
            ],
            sort_keys=True,
        )
        self.assertNotIn(sensitive_action, warning_payload)
        self.assertIn("action_fingerprint", warning_payload)

    def test_skipped_statistics_count_duplicate_observations(self) -> None:
        result = extract_static_html(
            """
            <form method="post" action="/submit">
              <input disabled name="same" value="one">
              <input disabled name="same" value="two">
            </form>
            """,
            SOURCE_URL,
        )
        warnings = [
            item
            for item in result.warnings
            if item.code == "FORM_CONTROL_DISABLED"
        ]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(result.discovery.crawl_statistics.skipped, 2)

    def test_safe_anchor_password_form_collision_is_elided_pre_canonical(
        self,
    ) -> None:
        password_sentinel = "PW_SENTINEL"
        html = f"""
        <a href="/search?q=safe">safe</a>
        <form method="get" action="/search">
          <input type="password" name="q" value="{password_sentinel}">
        </form>
        """

        first = extract_static_html(
            html,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )
        second = extract_static_html(
            html,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )

        q_points = [
            item
            for item in first.discovery.input_points
            if item.name == "q"
        ]
        self.assertEqual(len(q_points), 1)
        q_point = q_points[0]
        self.assertEqual(q_point.baseline_values, ("safe",))
        self.assertEqual(q_point.type_hint, "query")
        self.assertEqual(q_point.metadata["raw_query_token"], "q=safe")
        self.assertEqual(q_point.metadata["origin_kinds"], ("query",))
        self.assertEqual(
            [
                item
                for item in first.discovery.request_templates
                if item.metadata.get("context_kind") == "form"
            ],
            [],
        )
        self.assertEqual(
            len(first.discovery.input_point_request_contexts),
            1,
        )
        warnings = [
            item
            for item in first.warnings
            if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(warnings), 1)
        serialized = json.dumps(first.to_dict(), sort_keys=True)
        self.assertFalse(password_sentinel in serialized)
        self.assertFalse(password_sentinel in repr(first))
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        first.discovery.validate()

    def test_repeated_sensitive_forms_have_deterministic_warnings(self) -> None:
        html = """
        <form method="post" action="/first">
          <input type="password" name="first" value="FIRST_SENTINEL">
        </form>
        <form method="get" action="/second">
          <input type=" PaSsWoRd " name="second" value="SECOND_SENTINEL">
        </form>
        """

        first = extract_static_html(
            html,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )
        second = extract_static_html(
            html,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )

        first_warnings = [
            item
            for item in first.warnings
            if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        second_warnings = [
            item
            for item in second.warnings
            if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(first_warnings), 2)
        self.assertEqual(
            sorted(
                item.details["form_occurrence_index"]
                for item in first_warnings
            ),
            [0, 1],
        )
        self.assertEqual(first_warnings, second_warnings)
        self.assertEqual(first, second)
        self.assertNotIn(
            "/first",
            {item.path for item in first.discovery.endpoints},
        )
        self.assertNotIn(
            "/second",
            {item.path for item in first.discovery.endpoints},
        )
        warning_text = json.dumps(
            first.discovery.to_dict()["warnings"],
            sort_keys=True,
        )
        self.assertFalse("FIRST_SENTINEL" in warning_text)
        self.assertFalse("SECOND_SENTINEL" in warning_text)

    def test_input_permutation_has_canonical_output_order(self) -> None:
        first_html = """
        <a href="/b?q=2">b</a>
        <a href="/a?q=1">a</a>
        <form method="post" action="/z"><input name="z" value="1"></form>
        <form method="post" action="/y"><input name="y" value="2"></form>
        """
        second_html = """
        <form method="post" action="/y"><input name="y" value="2"></form>
        <a href="/a?q=1">a</a>
        <form method="post" action="/z"><input name="z" value="1"></form>
        <a href="/b?q=2">b</a>
        """
        first = extract_static_html(first_html, SOURCE_URL)
        second = extract_static_html(second_html, SOURCE_URL)
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_identity_is_stable_across_python_hash_seeds(self) -> None:
        html = (
            '<a href="/search?tag=a&tag=a&q=">q</a>'
            '<form method="post" action="/submit">'
            '<input name="x" value="1"></form>'
        )
        script = (
            "import json;"
            "from vulnspider.discovery import extract_static_html;"
            f"result=extract_static_html({html!r},{SOURCE_URL!r});"
            "print(json.dumps(result.to_dict(),sort_keys=True,separators=(',',':')))"
        )
        project_root = Path(__file__).resolve().parents[2]
        outputs: list[str] = []
        for seed in ("1", "777"):
            env = os.environ.copy()
            env["PYTHONHASHSEED"] = seed
            env["PYTHONPATH"] = str(project_root / "src")
            completed = subprocess.run(
                [sys.executable, "-B", "-c", script],
                cwd=project_root,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_module_has_no_network_transport_dependency(self) -> None:
        source = inspect.getsource(extractor_module)
        for forbidden in (
            "http.client",
            "requests",
            "socket",
            "urllib.request",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
