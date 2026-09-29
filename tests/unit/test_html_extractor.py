from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import unittest

from vulnspider.discovery import (
    CollectorKind,
    DiscoverySafetyInvariant,
    ProbeReadyStatus,
    SensitiveFormElisionPolicy,
    StaticExtractionResult,
    extract_static_html,
)
from vulnspider.domain import (
    HttpMethod,
    InputLocation,
    RequestContextCompleteness,
    validate_input_point_request_context,
)


SOURCE_URL = "http://example.test/app/index.html"
SENSITIVE_FORM_POLICY = SensitiveFormElisionPolicy()


class StaticHtmlExtractorTests(unittest.TestCase):
    def test_extracts_links_queries_and_forms_into_canonical_contract(self) -> None:
        html = """
        <html><body>
          <a href="../items?id=7">item</a>
          <form action="/search">
            <input name="q" value="books">
            <input type="hidden" name="token" value="abc">
            <textarea name="bio">hello world</textarea>
            <select name="category">
              <option value="a">A</option>
              <option value="b" selected>B</option>
            </select>
          </form>
          <form method="POST" action="submit">
            <input type="email" name="email" value="a@example.test">
            <input type="password" name="password" value="correct horse">
            <input type="checkbox" name="remember" value="yes" checked>
          </form>
        </body></html>
        """

        result = extract_static_html(html, SOURCE_URL)

        self.assertIsInstance(result, StaticExtractionResult)
        self.assertEqual(
            tuple(link.crawl_url for link in result.navigable_links),
            ("http://example.test/items?id=7",),
        )
        self.assertEqual(
            result.discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_STATIC,
        )
        result.discovery.validate()

        form_templates = [
            item
            for item in result.discovery.request_templates
            if item.metadata.get("context_kind") == "form"
        ]
        self.assertEqual(len(form_templates), 2)
        get_form = next(item for item in form_templates if item.method == HttpMethod.GET)
        post_form = next(
            item for item in form_templates if item.method == HttpMethod.POST
        )
        self.assertEqual(
            get_form.query,
            (
                ("q", "books"),
                ("token", "abc"),
                ("bio", "hello world"),
                ("category", "b"),
            ),
        )
        self.assertEqual(get_form.form, ())
        self.assertEqual(
            get_form.url,
            (
                "http://example.test/search?q=books&token=abc&"
                "bio=hello+world&category=b"
            ),
        )
        self.assertEqual(
            dict(get_form.provenance)["form_method"],
            "html_default_get",
        )
        self.assertEqual(
            post_form.form,
            (
                ("email", "a@example.test"),
                ("password", "correct horse"),
                ("remember", "yes"),
            ),
        )
        self.assertEqual(post_form.url, "http://example.test/app/submit")
        self.assertEqual(
            post_form.completeness,
            RequestContextCompleteness.COMPLETE,
        )

        hidden = next(
            point
            for point in result.discovery.input_points
            if point.name == "token"
        )
        self.assertEqual(hidden.location, InputLocation.QUERY)
        self.assertEqual(hidden.type_hint, "hidden")
        self.assertTrue(hidden.metadata["hidden"])
        self.assertTrue(
            all(
                item.status == ProbeReadyStatus.READY
                for item in result.discovery.probe_readiness
            )
        )
        self.assertEqual(
            len(result.discovery.ready_contexts()),
            len(result.discovery.input_point_request_contexts),
        )

        points = {item.id: item for item in result.discovery.input_points}
        templates = {
            item.id: item for item in result.discovery.request_templates
        }
        for context in result.discovery.input_point_request_contexts:
            validate_input_point_request_context(
                points[context.input_point_id],
                templates[context.request_template_id],
            )

    def test_select_uses_first_option_and_preserves_textarea_blank(self) -> None:
        result = extract_static_html(
            """
            <form method="post" action="/profile">
              <textarea name="note"></textarea>
              <select name="theme">
                <option>light</option>
                <option value="dark">Dark</option>
              </select>
            </form>
            """,
            SOURCE_URL,
        )
        template = next(
            item
            for item in result.discovery.request_templates
            if item.metadata.get("context_kind") == "form"
        )
        self.assertEqual(template.form, (("note", ""), ("theme", "light")))

    def test_result_is_immutable_and_deterministic(self) -> None:
        html = """
        <a href="/b?q=2">b</a>
        <a href="/a?q=1">a</a>
        <form method="post" action="/submit">
          <input name="q" value="">
        </form>
        """
        first = extract_static_html(html, SOURCE_URL)
        second = extract_static_html(html, SOURCE_URL)
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first.to_dict(), sort_keys=True),
            json.dumps(second.to_dict(), sort_keys=True),
        )
        with self.assertRaises(FrozenInstanceError):
            first.source_url = "http://changed.test/"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            first.discovery.input_points[0].metadata["changed"] = True  # type: ignore[index]

    def test_password_value_never_appears_in_warning_payloads(self) -> None:
        secret = "do-not-log-this"
        result = extract_static_html(
            f"""
            <form method="post" action="/login">
              <input type="password" name="password" value="{secret}">
              <input disabled name="ignored" value="{secret}">
            </form>
            """,
            SOURCE_URL,
        )
        warning_payload = json.dumps(
            [
                {
                    "code": item.code,
                    "message": item.message,
                    "details": dict(item.details),
                }
                for item in result.warnings
            ],
            sort_keys=True,
        )
        self.assertNotIn(secret, warning_payload)

    def test_sensitive_form_elision_policy_is_opt_in(self) -> None:
        html = """
        <form method="post" action="/login">
          <input type="password" name="password" value="current-static-value">
        </form>
        """

        result = extract_static_html(html, SOURCE_URL)
        marked = extract_static_html(
            html,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )

        template = next(
            item
            for item in result.discovery.request_templates
            if item.method == HttpMethod.POST
        )
        self.assertEqual(
            template.form,
            (("password", "current-static-value"),),
        )
        self.assertNotIn(
            "SENSITIVE_FORM_ELIDED",
            {item.code for item in result.warnings},
        )
        invariant = (
            DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION
        )
        self.assertEqual(result.discovery.safety_invariants, ())
        self.assertNotIn("safety_invariants", result.discovery.to_dict())
        self.assertEqual(marked.discovery.safety_invariants, (invariant,))
        self.assertEqual(
            marked.discovery.to_dict()["safety_invariants"],
            [invariant.value],
        )

    def test_elides_password_get_form_before_canonical_construction(self) -> None:
        result = extract_static_html(
            """
            <form method="get" action="/password-only-get">
              <input type="password" name="password" value="not-canonical">
            </form>
            """,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )

        self.assertNotIn(
            "/password-only-get",
            {item.path for item in result.discovery.endpoints},
        )
        self.assertEqual(result.discovery.input_points, ())
        self.assertEqual(result.discovery.request_templates, ())
        self.assertEqual(result.discovery.input_point_request_contexts, ())
        self.assertEqual(result.discovery.probe_readiness, ())
        self.assertEqual(
            [item.code for item in result.warnings],
            ["SENSITIVE_FORM_ELIDED"],
        )
        result.discovery.validate()

    def test_elides_password_post_form_with_secret_free_warning(self) -> None:
        password_sentinel = "PW_SENTINEL"
        result = extract_static_html(
            f"""
            <form method="post" action="/password-only-post">
              <input type="password" name="password" value="{password_sentinel}">
            </form>
            """,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )

        self.assertNotIn(
            "/password-only-post",
            {item.path for item in result.discovery.endpoints},
        )
        self.assertEqual(result.discovery.input_points, ())
        self.assertEqual(result.discovery.request_templates, ())
        self.assertEqual(result.discovery.input_point_request_contexts, ())
        warnings = [
            item
            for item in result.warnings
            if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(warnings), 1)
        warning_text = json.dumps(
            result.discovery.to_dict()["warnings"],
            sort_keys=True,
        )
        self.assertFalse(password_sentinel in warning_text)
        self.assertFalse(password_sentinel in repr(warnings))

    def test_elides_only_sensitive_form_on_mixed_page(self) -> None:
        result = extract_static_html(
            """
            <form method="post" action="/login">
              <input type="password" name="password" value="not-canonical">
              <input type="hidden" name="csrf" value="also-not-canonical">
            </form>
            <form method="get" action="/search">
              <input name="q" value="books">
            </form>
            """,
            SOURCE_URL,
            sensitive_form_policy=SENSITIVE_FORM_POLICY,
        )

        self.assertNotIn(
            "/login",
            {item.path for item in result.discovery.endpoints},
        )
        self.assertIn(
            "/search",
            {item.path for item in result.discovery.endpoints},
        )
        self.assertEqual(
            {item.name for item in result.discovery.input_points},
            {"q"},
        )
        self.assertEqual(
            {
                item.code
                for item in result.warnings
                if item.code == "SENSITIVE_FORM_ELIDED"
            },
            {"SENSITIVE_FORM_ELIDED"},
        )
        result.discovery.validate()


class SubmitGateTests(unittest.TestCase):
    """A named submit control gates the handler, so it rides on the request."""

    def _templates(self, html: str):
        result = extract_static_html(html, SOURCE_URL)
        result.discovery.validate()
        return result.discovery

    def test_named_get_submit_rides_on_query_but_is_not_an_input_point(self) -> None:
        discovery = self._templates(
            '<form action="/sqli/" method="get">'
            '<input type="text" name="id" value="1">'
            '<input type="submit" name="Submit" value="Submit"></form>'
        )
        # id is the only injectable input point; Submit is not.
        self.assertEqual(
            {point.name for point in discovery.input_points}, {"id"}
        )
        template = next(iter(discovery.request_templates))
        self.assertIn(("id", "1"), template.query)
        self.assertIn(("Submit", "Submit"), template.query)

    def test_unnamed_submit_sends_nothing(self) -> None:
        discovery = self._templates(
            '<form action="/xss/" method="get">'
            '<input type="text" name="name" value="x">'
            '<input type="submit" value="Submit"></form>'
        )
        self.assertEqual(
            {point.name for point in discovery.input_points}, {"name"}
        )
        template = next(iter(discovery.request_templates))
        self.assertEqual(list(template.query), [("name", "x")])

    def test_named_button_rides_on_a_post_body_but_is_not_injectable(self) -> None:
        discovery = self._templates(
            '<form action="/save" method="post">'
            '<input type="text" name="q" value="1">'
            '<button name="do" value="save">Save</button></form>'
        )
        self.assertEqual({point.name for point in discovery.input_points}, {"q"})
        template = next(iter(discovery.request_templates))
        self.assertIn(("do", "save"), template.form)

    def test_only_the_first_named_submit_is_carried(self) -> None:
        discovery = self._templates(
            '<form action="/multi/" method="get">'
            '<input type="text" name="id" value="1">'
            '<input type="submit" name="save" value="Save">'
            '<input type="submit" name="delete" value="Delete"></form>'
        )
        template = next(iter(discovery.request_templates))
        names = [name for name, _ in template.query]
        self.assertIn("save", names)
        self.assertNotIn("delete", names)


if __name__ == "__main__":
    unittest.main()
