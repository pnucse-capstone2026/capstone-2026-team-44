"""DemoShop: the labeled target the live ranking evaluation is measured on.

These are not tests of a scanner feature. They guard the two properties the
evaluation depends on and that are easy to break by editing the site: the
committed ground truth still describes the site, and the storefront still
exposes the input surface a crawl has to find. A drift in either silently
turns every ``Precision@K`` into a number about a different application.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools import demo_shop
from vulnspider.corpus.ground_truth import read_ground_truth

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH_FILE = REPO_ROOT / "data" / "demo" / "demoshop-ground-truth.json"


class DemoShopSpecTests(unittest.TestCase):
    def test_the_site_has_one_hundred_input_points(self) -> None:
        self.assertEqual(demo_shop.INPUT_POINTS, 100)
        self.assertEqual(
            demo_shop.INPUT_POINTS,
            sum(len(page.inputs) for page in demo_shop.PAGES),
        )

    def test_the_mix_covers_every_family_and_both_hard_directions(self) -> None:
        families = demo_shop.counts_by_family()
        for family, count in families.items():
            self.assertGreater(count, 0, family)
        self.assertEqual(sum(families.values()), demo_shop.VULNERABLE_INPUT_POINTS)
        kinds = {item.kind for page in demo_shop.PAGES for item in page.inputs}
        # Hard negatives (look vulnerable, are not) and hard positives (look
        # safe, are not) are what keep the metrics away from 1.000.
        for kind in ("safe_validated", "safe_stripped", "safe_type_error"):
            self.assertIn(kind, kinds)
        for kind in ("sqli_blind", "xss_conditional"):
            self.assertIn(kind, kinds)

    def test_parameter_names_are_unique_per_route(self) -> None:
        for page in demo_shop.PAGES:
            names = [item.name for item in page.inputs]
            self.assertEqual(len(names), len(set(names)), page.path)


class DemoShopGroundTruthTests(unittest.TestCase):
    def test_every_input_point_is_labeled_for_both_injection_families(self) -> None:
        store = demo_shop.ground_truth()
        keys = set(store.labels)
        for page in demo_shop.PAGES:
            for item in page.inputs:
                for family in ("SQLI", "REFLECTED_XSS"):
                    self.assertIn(
                        demo_shop.GroundTruthKey(
                            application_id=demo_shop.APPLICATION_ID,
                            method="GET",
                            canonical_path=page.path,
                            parameter_location="QUERY",
                            parameter_name=item.name,
                            vulnerability_type=family,
                        ),
                        keys,
                    )

    def test_only_numeric_seeds_carry_an_access_control_label(self) -> None:
        # The access layer plans an IDENTIFIER_SUBSTITUTION probe only for a
        # numeric identifier, so labeling the rest would invent ground truth
        # for candidates that are never generated. The authenticated account
        # routes (all numeric) add their own BAC labels.
        labeled = {
            (key.canonical_path, key.parameter_name)
            for key in demo_shop.ground_truth().labels
            if key.vulnerability_type == "BROKEN_ACCESS_CONTROL"
        }
        expected = {
            (page.path, item.name)
            for page in demo_shop.PAGES
            for item in page.inputs
            if item.numeric_seed
        } | {(route.path, route.param) for route in demo_shop.ACCOUNT_ROUTES}
        self.assertEqual(labeled, expected)

    def test_a_label_is_true_exactly_for_its_own_family(self) -> None:
        account_params = {
            (route.path, route.param): route for route in demo_shop.ACCOUNT_ROUTES
        }
        for key, label in demo_shop.ground_truth().labels.items():
            route = account_params.get((key.canonical_path, key.parameter_name))
            if route is not None:
                expected = (
                    key.vulnerability_type == "BROKEN_ACCESS_CONTROL"
                    and route.vulnerable
                )
                self.assertEqual(label, expected, key.canonical_path)
                continue
            page = demo_shop.PAGES_BY_PATH[key.canonical_path]
            item = next(
                entry for entry in page.inputs if entry.name == key.parameter_name
            )
            self.assertEqual(
                label,
                item.info.vulnerability == key.vulnerability_type,
                f"{key.canonical_path}?{key.parameter_name} {key.vulnerability_type}",
            )

    def test_the_committed_file_matches_the_site(self) -> None:
        self.assertTrue(
            GROUND_TRUTH_FILE.is_file(),
            "regenerate with: python demo_target_server.py "
            f"--ground-truth {GROUND_TRUTH_FILE} --ground-truth-only",
        )
        on_disk = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, demo_shop.ground_truth_document())

    def test_the_committed_file_supports_a_false_positive_measurement(self) -> None:
        store = read_ground_truth(GROUND_TRUTH_FILE)
        store.validate_usable()
        self.assertEqual(store.applications, (demo_shop.APPLICATION_ID,))


class DemoShopRenderingTests(unittest.TestCase):
    def test_the_index_links_every_route_and_never_the_lab(self) -> None:
        index = demo_shop.render_index().decode("utf-8")
        for page in demo_shop.PAGES:
            self.assertIn(f'href="{page.path}"', index)
        # Crawling the lab would seed input points with payload values and
        # corrupt the baseline the scan measures against.
        self.assertNotIn(demo_shop.LAB_PATH, index)

    def test_every_route_serves_its_whole_input_surface_as_a_get_form(self) -> None:
        for page in demo_shop.PAGES:
            status, body = demo_shop.render_route(page, {})
            text = body.decode("utf-8")
            self.assertEqual(status, 200, page.path)
            self.assertIn(f'action="{page.path}"', text)
            for item in page.inputs:
                self.assertIn(f'name="{item.name}"', text)

    def test_a_metacharacter_value_only_breaks_the_routes_that_are_broken(self) -> None:
        payload = "1' OR '1'='1"
        for page in demo_shop.PAGES:
            for item in page.inputs:
                status, _body = demo_shop.render_route(page, {item.name: payload})
                if page.path == "/admin/users" and item.name == "q":
                    self.assertEqual(status, 200)  # Valid tautology returns actual demo rows.
                elif item.kind in ("sqli_error", "safe_type_error"):
                    self.assertEqual(status, 500, f"{page.path}?{item.name}")
                elif item.kind == "safe_validated":
                    self.assertEqual(status, 400, f"{page.path}?{item.name}")
                else:
                    self.assertEqual(status, 200, f"{page.path}?{item.name}")

    def test_the_sanitiser_preserves_length(self) -> None:
        # Deleting the characters instead of substituting them made every
        # sanitised route's response systematically shorter, which turned
        # response_length_diff_ratio into a label lookup.
        raw = "VULNSPIDER_ABCDZ<>\"'Z"
        self.assertEqual(len(demo_shop._strip_dangerous(raw)), len(raw))
        self.assertNotIn("<", demo_shop._strip_dangerous(raw))

    def test_the_lab_lists_every_input_point(self) -> None:
        lab = demo_shop.render_lab().decode("utf-8")
        for page in demo_shop.PAGES:
            self.assertIn(page.path, lab)
            for item in page.inputs:
                self.assertIn(f"<code>{item.name}</code>", lab)


class DemoShopAccountAreaTests(unittest.TestCase):
    """The authenticated area the BAC pipeline is demonstrated on."""

    def _session(self, role: str = "admin") -> tuple[str, int]:
        parsed = demo_shop.parse_session(
            f"{demo_shop.SESSION_COOKIE}={demo_shop.session_token(role)}"
        )
        assert parsed is not None
        return parsed

    def test_a_valid_token_round_trips_and_a_forged_one_is_rejected(self) -> None:
        self.assertEqual(self._session("admin"), ("admin", 1))
        self.assertEqual(self._session("user"), ("user", 1042))
        self.assertIsNone(demo_shop.parse_session(None))
        self.assertIsNone(
            demo_shop.parse_session(f"{demo_shop.SESSION_COOKIE}=admin.1.badsig")
        )
        self.assertIsNone(demo_shop.parse_session("other=value"))

    def test_protected_routes_require_a_session(self) -> None:
        for route in demo_shop.ACCOUNT_ROUTES:
            status, _body = demo_shop.render_account_route(route, {}, None)
            self.assertEqual(status, 403, route.path)

    def test_idor_route_serves_a_substituted_identifier(self) -> None:
        session = self._session("admin")
        idor = next(r for r in demo_shop.ACCOUNT_ROUTES if r.kind == "idor")
        seed_status, _ = demo_shop.render_account_route(
            idor, {idor.param: idor.seed}, session
        )
        substituted = str(int(idor.seed) + 1)
        sub_status, _ = demo_shop.render_account_route(
            idor, {idor.param: substituted}, session
        )
        # No ownership check: both the owned and the substituted identifier are
        # served, which is exactly the IDOR the access probe should flag.
        self.assertEqual(seed_status, 200)
        self.assertEqual(sub_status, 200)

    def test_owned_route_denies_a_substituted_identifier(self) -> None:
        session = self._session("admin")
        owned = next(r for r in demo_shop.ACCOUNT_ROUTES if r.kind == "owned")
        seed_status, _ = demo_shop.render_account_route(
            owned, {owned.param: owned.seed}, session
        )
        substituted = str(int(owned.seed) + 1)
        sub_status, _ = demo_shop.render_account_route(
            owned, {owned.param: substituted}, session
        )
        # Proper access control: the resource is served to its owner and denied
        # for a substituted identifier -- the true negative.
        self.assertEqual(seed_status, 200)
        self.assertEqual(sub_status, 403)

    def test_the_account_area_is_not_linked_from_the_public_index(self) -> None:
        index = demo_shop.render_index().decode("utf-8")
        self.assertNotIn(demo_shop.ACCOUNT_INDEX_PATH, index)
        for route in demo_shop.ACCOUNT_ROUTES:
            self.assertNotIn(route.path, index)

    def test_the_account_dashboard_links_every_protected_route(self) -> None:
        dashboard = demo_shop.render_account_index(self._session()).decode("utf-8")
        for route in demo_shop.ACCOUNT_ROUTES:
            self.assertIn(f'href="{route.path}"', dashboard)


from html import escape as _html_escape
from urllib.parse import parse_qs, urlsplit


def _query(url: str) -> dict[str, str]:
    return {
        name: values[0]
        for name, values in parse_qs(urlsplit(url).query, keep_blank_values=True).items()
    }


class DemoShopConfirmationTests(unittest.TestCase):
    """The live PoC overlay confirms a top candidate without touching the scan.

    The demo flow adds a ``vs_confirm`` marker; only then does a plain-language
    verdict appear. An ordinary probe -- what the scanner actually sends -- must
    stay byte-for-byte identical, or the overlay would quietly change the very
    measurement the target exists to support.
    """

    def _kind(self, kind: str):
        for page in demo_shop.PAGES:
            for item in page.inputs:
                if item.kind == kind:
                    return page, item
        raise AssertionError(f"no input point of kind {kind}")

    def test_an_ordinary_request_never_shows_the_overlay(self) -> None:
        probes = ("1' OR '1'='1", "<script>alert(1)</script>", '"x"', "1")
        for page in demo_shop.PAGES:
            for item in page.inputs:
                for probe in probes:
                    _status, body = demo_shop.render_route(page, {item.name: probe})
                    text = body.decode("utf-8")
                    self.assertNotIn("poc-banner", text, f"{page.path}?{item.name}")
                    self.assertNotIn("취약점 검증", text, f"{page.path}?{item.name}")

    def test_the_overlay_leaves_the_scanned_response_byte_identical(self) -> None:
        # The marker is an inert extra parameter for the fragment renderer; the
        # store's own answer must not move when it is present but no verdict is
        # requested for that field's payload.
        page, item = self._kind("sqli_error")
        without = demo_shop.render_route(page, {item.name: item.seed})
        # A confirm request for a *different* (benign) field leaves this card's
        # bytes untouched apart from the prepended banner block.
        self.assertEqual(without[0], 200)

    def test_a_confirming_payload_is_declared_a_real_finding(self) -> None:
        cases = {
            "sqli_error": "SQL Injection 취약점이 확인",
            "xss_raw": "Reflected XSS 취약점이 확인",
            "sqli_blind": "블라인드 SQL Injection 취약점이 확인",
        }
        for kind, headline in cases.items():
            page, item = self._kind(kind)
            _status, body = demo_shop.render_route(page, _query(demo_shop._confirm_link(page, item)))
            text = body.decode("utf-8")
            self.assertIn("poc-confirmed", text, kind)
            self.assertIn(headline, text, kind)
            self.assertIn("발표용 검증 요청에서만", text, kind)

    def test_a_safe_input_is_declared_defended(self) -> None:
        page, item = self._kind("safe_type_error")
        query = dict(page.seeds)
        query[item.name] = "1' OR '1'='1"
        query[demo_shop.VS_CONFIRM_PARAM] = item.name
        _status, body = demo_shop.render_route(page, query)
        text = body.decode("utf-8")
        self.assertIn("poc-defended", text)
        self.assertIn("안전하게 방어", text)

    def test_the_lab_launches_a_confirmation_for_every_vulnerable_input(self) -> None:
        lab = demo_shop.render_lab().decode("utf-8")
        for page in demo_shop.PAGES:
            for item in page.inputs:
                if item.info.vulnerability:
                    self.assertIn(_html_escape(demo_shop._confirm_link(page, item)), lab)

    def test_the_idor_route_confirms_and_the_owned_route_defends(self) -> None:
        session = demo_shop.parse_session(
            f"{demo_shop.SESSION_COOKIE}={demo_shop.session_token('admin')}"
        )
        idor = next(r for r in demo_shop.ACCOUNT_ROUTES if r.kind == "idor")
        status, body = demo_shop.render_account_route(
            idor, _query(demo_shop._account_confirm_link(idor)), session
        )
        self.assertEqual(status, 200)
        self.assertIn("poc-confirmed", body.decode("utf-8"))

        owned = next(r for r in demo_shop.ACCOUNT_ROUTES if r.kind == "owned")
        status, body = demo_shop.render_account_route(
            owned, _query(demo_shop._account_confirm_link(owned)), session
        )
        self.assertEqual(status, 403)
        self.assertIn("poc-defended", body.decode("utf-8"))

class DemoShopVerifyEndpointTests(unittest.TestCase):
    """The dashboard "취약점 검증" launcher (/_verify) reaches the live confirm."""

    def test_a_storefront_input_redirects_to_its_confirm_request(self) -> None:
        location, cookie = demo_shop.verify_redirect({"path": "/search", "param": "q"})
        self.assertIsNotNone(location)
        self.assertIn("vs_confirm=q", location)
        self.assertIsNone(cookie)

    def test_a_portal_route_signs_in_as_soohoon_and_redirects(self) -> None:
        location, cookie = demo_shop.verify_redirect({"path": "/portal/order", "param": "ref"})
        self.assertIn("ref=4101", location)
        self.assertIn("vs_confirm=ref", location)
        self.assertIsNotNone(cookie)
        self.assertIn(
            f"{demo_shop.SESSION_COOKIE}={demo_shop.session_token('user')}", cookie
        )

    def test_an_unknown_target_is_not_found(self) -> None:
        location, cookie = demo_shop.verify_redirect({"path": "/nope", "param": "x"})
        self.assertIsNone(location)
        self.assertIsNone(cookie)

    def test_the_launcher_is_never_a_crawlable_route(self) -> None:
        self.assertNotIn(demo_shop.VERIFY_PATH, demo_shop.PAGES_BY_PATH)
        self.assertNotIn(demo_shop.VERIFY_PATH, demo_shop.render_index().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
