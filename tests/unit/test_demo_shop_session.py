"""Browser-facing demo login and the same-session order ownership example."""

from __future__ import annotations

import unittest
from html.parser import HTMLParser
from http.client import HTTPConnection
from http.cookies import SimpleCookie
from threading import Thread
from urllib.parse import urlencode

from tools import demo_shop


class LoginControls(HTMLParser):
    def __init__(self, body: str) -> None:
        super().__init__()
        self.forms: list[dict[str, str | None]] = []
        self.named_controls: list[str] = []
        self.links: list[str] = []
        self.in_form = False
        self.feed(body)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self.forms.append(values)
            self.in_form = True
        if self.in_form and tag in ("input", "select", "textarea", "button") and values.get("name"):
            self.named_controls.append(values["name"] or "")
        if tag == "a" and values.get("href"):
            self.links.append(values["href"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.in_form = False


class DemoShopSessionHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = demo_shop.build_server(0)
        cls.worker = Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)

    def _request(
        self, method: str, path: str, cookie: str | None = None
    ) -> tuple[int, dict[str, str], str]:
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Cookie": cookie} if cookie is not None else {}
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            return (
                response.status,
                {name.lower(): value for name, value in response.getheaders()},
                response.read().decode("utf-8"),
            )
        finally:
            connection.close()

    def _login(self, path: str = "/login", *, destination: str = "/portal/") -> str:
        status, headers, _body = self._request("POST", path)
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("location"), destination)
        jar: SimpleCookie = SimpleCookie()
        jar.load(headers["set-cookie"])
        morsel = jar[demo_shop.SESSION_COOKIE]
        self.assertEqual(morsel.value, demo_shop.session_token("user"))
        self.assertEqual(morsel["path"], "/")
        self.assertTrue(morsel["httponly"])
        self.assertEqual(morsel["samesite"].lower(), "lax")
        return f"{demo_shop.SESSION_COOKIE}={morsel.value}"

    def test_my_page_opens_a_single_explicit_profile_login(self) -> None:
        status, _headers, home = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn('href="/login">마이페이지</a>', home)
        status, headers, body = self._request("GET", "/login")
        self.assertEqual(status, 200)
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn("location", headers)
        controls = LoginControls(body)
        self.assertEqual(len(controls.forms), 1)
        self.assertEqual(controls.forms[0].get("action"), "/login")
        self.assertEqual(controls.forms[0].get("method", "").lower(), "post")
        self.assertEqual(controls.named_controls, [])
        self.assertIn("한수훈으로 로그인", body)
        for text in ("로그인 후 이동", "다음 단계", "로그인 링크 받기", "--cookie"):
            self.assertNotIn(text, body)
        self.assertFalse(any("?as=" in link for link in controls.links))
        self.assertNotIn(demo_shop.ACCOUNT_INDEX_PATH, controls.links)

    def test_login_sets_a_user_cookie_and_ignores_redirect_or_role_overrides(self) -> None:
        cookie = self._login("/login?as=admin&return_to=https%3A%2F%2Fexample.invalid&next=%2Fcart")
        self.assertEqual(demo_shop.parse_session(cookie), ("user", 1042))
        status, headers, body = self._request("GET", "/portal/", cookie)
        self.assertEqual(status, 200)
        self.assertNotIn("set-cookie", headers)
        for value in ("한수훈", "1042", "4100"):
            self.assertIn(value, body)
        for route in demo_shop.ACCOUNT_ROUTES:
            self.assertIn(route.path, LoginControls(body).links)
        status, headers, _body = self._request("GET", "/login", cookie)
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("location"), "/portal/")
        self.assertNotIn("set-cookie", headers)

    def test_one_session_can_read_its_own_and_another_members_order(self) -> None:
        cookie = self._login()
        for ref, owner, uid in (("4100", "한수훈", "1042"), ("4101", "전상현", "1043")):
            with self.subTest(ref=ref):
                status, headers, body = self._request("GET", f"/portal/order?ref={ref}", cookie)
                self.assertEqual(status, 200)
                self.assertNotIn("set-cookie", headers)
                for label, value in (("주문번호", ref), ("주문자", owner), ("소유자 uid", uid)):
                    self.assertIn(f"<th>{label}</th><td>{value}</td>", body)
                self.assertIn("<strong>한수훈</strong> 님 · 회원번호 1042", body)
        status, _headers, body = self._request("GET", "/portal/", cookie)
        self.assertEqual(status, 200)
        self.assertIn("한수훈", body)

    def test_ownership_notice_compares_session_uid_without_confirm_marker(self) -> None:
        cookie = self._login()
        for path, other in (("/portal/order", "4101"), ("/portal/message", "9999")):
            route = next(route for route in demo_shop.ACCOUNT_ROUTES if route.path == path)
            for value in (route.seed, other):
                status, _, body = self._request("GET", route.path + "?" + urlencode({route.param: value}), cookie)
                self.assertEqual(status, 200)
                self.assertEqual('class="ownership-mismatch"' in body, value != route.seed)
                if value != route.seed:
                    self.assertIn("현재 사용자: 한수훈 (회원번호 1042)", body)
                    self.assertIn("조회된 소유자: <mark>", body)

    def test_member_ids_search_and_manual_sql_injection(self) -> None:
        names = ("한수훈", "전상현", "이석현")
        for index, name in enumerate(names):
            status, _, body = self._request("GET", "/admin/users?" + urlencode({"id": str(1042 + index), "q": "soohoon"}))
            self.assertEqual(status, 200)
            self.assertIn(f"<td>{name}</td>", body)
            for other in set(names) - {name}:
                self.assertNotIn(f"<td>{other}</td>", body)
            self.assertNotIn("<h3>이메일 또는 이름</h3>", body)
        for identifier in ("1043", "1044", "9999"):
            status, _, body = self._request("GET", "/admin/users?" + urlencode({"id": identifier, "vs_confirm": "id"}))
            self.assertEqual(status, 200)
            self.assertEqual("인증 없이 회원 정보가 조회되었습니다" in body, identifier != "9999")
            self.assertNotIn("소유자:", body)
        for marker in ({}, {"vs_confirm": "q"}):
            status, _, body = self._request("GET", "/admin/users?" + urlencode({"q": "1' OR '1'='1", **marker}))
            self.assertEqual(status, 200)
            self.assertIn("member-breach", body)  # the bypass is shown as a breach
            self.assertIn("$2b$12$", body)  # and leaks password hashes
            for name in names:
                self.assertIn(f"<td>{name}</td>", body)
        for query in ({"id": "9999"}, {"q": "nobody"}, {"q": "1' OR '1'='2"}):
            status, _, body = self._request("GET", "/admin/users?" + urlencode(query))
            self.assertEqual(status, 200)
            self.assertIn("일치하는 계정이 없습니다", body)
        for term in ("전상현", "sanghyun"):
            status, _, body = self._request("GET", "/admin/users?" + urlencode({"q": term}))
            self.assertEqual(status, 200)
            self.assertIn("검색 결과 1건", body)
            self.assertIn("<td>전상현</td>", body)
            self.assertNotIn("member-breach", body)  # a scoped result never leaks
            self.assertNotIn("$2b$12$", body)
        for term in ("'", "'; DROP TABLE members; --"):
            status, _, body = self._request("GET", "/admin/users?" + urlencode({"q": term, "vs_confirm": "q"}))
            self.assertEqual(status, 500)
            self.assertNotIn("유출된 회원 정보", body)
        status, _, body = self._request("GET", "/admin/users")
        self.assertEqual(status, 200)
        self.assertIn("<td>한수훈</td>", body)

    def test_missing_or_forged_cookies_cannot_open_protected_resources(self) -> None:
        paths = [demo_shop.ACCOUNT_INDEX_PATH] + [route.path for route in demo_shop.ACCOUNT_ROUTES]
        for cookie in (None, f"{demo_shop.SESSION_COOKIE}=user.1042.invalid"):
            for path in paths:
                with self.subTest(cookie=cookie, path=path):
                    status, headers, _body = self._request("GET", path, cookie)
                    self.assertEqual(status, 403)
                    self.assertNotIn("set-cookie", headers)

    def test_card_still_checks_ownership_with_the_default_profile(self) -> None:
        cookie = self._login()
        for card_id, expected in (("5001", 200), ("5002", 403)):
            with self.subTest(card_id=card_id):
                status, _headers, _body = self._request("GET", f"/portal/card?card_id={card_id}", cookie)
                self.assertEqual(status, expected)

    def test_logout_requires_post_and_clears_the_browser_cookie(self) -> None:
        cookie = self._login()
        _status, headers, _body = self._request("GET", "/logout", cookie)
        self.assertNotIn("set-cookie", headers)
        status, _headers, _body = self._request("GET", "/portal/", cookie)
        self.assertEqual(status, 200)
        status, headers, _body = self._request("POST", "/logout", cookie)
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("location"), "/login")
        jar: SimpleCookie = SimpleCookie()
        jar.load(headers["set-cookie"])
        morsel = jar[demo_shop.SESSION_COOKIE]
        self.assertEqual(morsel.value, "")
        self.assertEqual(morsel["max-age"], "0")
        self.assertEqual(morsel["path"], "/")
        status, _headers, _body = self._request("GET", "/portal/")
        self.assertEqual(status, 403)
        status, headers, body = self._request("GET", "/login")
        self.assertEqual(status, 200)
        self.assertNotIn("set-cookie", headers)
        self.assertIn("한수훈으로 로그인", body)

    def test_explicit_legacy_role_login_is_still_available(self) -> None:
        for role in ("admin", "user"):
            with self.subTest(role=role):
                status, headers, _body = self._request("GET", f"/login?as={role}")
                self.assertEqual(status, 200)
                jar: SimpleCookie = SimpleCookie()
                jar.load(headers["set-cookie"])
                self.assertEqual(jar[demo_shop.SESSION_COOKIE].value, demo_shop.session_token(role))
        status, headers, _body = self._request("GET", "/login?as=unknown")
        self.assertEqual(status, 400)
        self.assertNotIn("set-cookie", headers)

    def test_public_login_fixture_never_authenticates_get_probes(self) -> None:
        path = "/account/login?username=soohoon&return_to=%2Fportal%2F&next=%2Fcart"
        status, headers, body = self._request("GET", path)
        self.assertEqual(status, 200)
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn("location", headers)
        self.assertCountEqual(LoginControls(body).named_controls, ["username", "return_to", "next"])

    def test_unknown_post_routes_do_not_issue_a_session(self) -> None:
        status, headers, _body = self._request("POST", "/orders")
        self.assertEqual(status, 405)
        self.assertNotIn("set-cookie", headers)

    def test_shopper_order_links_open_login_without_issuing_a_session(self) -> None:
        _status, _headers, home = self._request("GET", "/")
        for label in ("주문조회", "주문 및 배송 조회"):
            self.assertIn(f'href="/login/orders">{label}</a>', home)
        # The public injection fixture stays discoverable in the directory.
        self.assertIn('href="/orders"', home)
        for cookie in (None, f"{demo_shop.SESSION_COOKIE}=user.1042.invalid"):
            for path in ("/login/orders", "/login/orders?as=admin&next=//example.invalid"):
                with self.subTest(cookie=cookie, path=path):
                    status, headers, body = self._request("GET", path, cookie)
                    self.assertEqual(status, 200)
                    self.assertNotIn("set-cookie", headers)
                    self.assertNotIn("location", headers)
                    controls = LoginControls(body)
                    self.assertEqual(len(controls.forms), 1)
                    self.assertEqual(controls.forms[0].get("action"), "/login/orders")
                    self.assertEqual(controls.forms[0].get("method"), "post")
                    self.assertEqual(controls.named_controls, [])
                    self.assertFalse(any(link.startswith("/portal") for link in controls.links))

    def test_order_login_goes_directly_to_the_same_session_order_lookup(self) -> None:
        cookie = self._login(
            "/login/orders?as=admin&return_to=https%3A%2F%2Fexample.invalid",
            destination="/portal/order",
        )
        self.assertEqual(demo_shop.parse_session(cookie), ("user", 1042))
        status, headers, _body = self._request("GET", "/login/orders", cookie)
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("location"), "/portal/order")
        self.assertNotIn("set-cookie", headers)
        for ref, owner, product, price in (
            ("4100", "한수훈", "데일리 스웨이드 스니커즈", "89,000원"),
            ("4101", "전상현", "무선 오버이어 헤드폰", "149,000원"),
        ):
            status, _headers, body = self._request("GET", f"/portal/order?ref={ref}", cookie)
            self.assertEqual(status, 200)
            self.assertIn(f"<th>주문자</th><td>{owner}</td>", body)
            self.assertIn("<strong>한수훈</strong> 님 · 회원번호 1042", body)
            self.assertIn(product, body)
            self.assertIn(price, body)

    def test_legacy_order_forms_forward_numbers_to_the_protected_order_endpoint(self) -> None:
        cookie = self._login()
        cases = (
            ("/orders", "4100", "한수훈"),
            ("/orders?order_id=4100", "4100", "한수훈"),
            ("/orders?order_id=4101", "4101", "전상현"),
            ("/orders?order_id=20240517", "4100", "한수훈"),
            ("/orders?order_id=20240518&status=all", "4101", "전상현"),
        )
        for path, ref, owner in cases:
            with self.subTest(path=path):
                status, headers, _body = self._request("GET", path, cookie)
                self.assertEqual(status, 303)
                self.assertEqual(headers.get("location"), f"/portal/order?ref={ref}")
                self.assertNotIn("set-cookie", headers)
                status, _headers, body = self._request("GET", headers["location"], cookie)
                self.assertEqual(status, 200)
                self.assertIn(f"<th>주문번호</th><td>{ref}</td>", body)
                self.assertIn(f"<th>주문자</th><td>{owner}</td>", body)
        unusual = '//example.invalid/<b>?ref=1&next=2\r\nX-Injected: yes'
        status, headers, _body = self._request("GET", "/orders?" + urlencode({"order_id": unusual}), cookie)
        self.assertEqual(status, 303)
        self.assertEqual(headers["location"], "/portal/order?" + urlencode({"ref": unusual}))
        self.assertNotIn("x-injected", headers)

    def test_anonymous_order_fixture_keeps_its_inputs_and_sql_error_behavior(self) -> None:
        for cookie in (None, f"{demo_shop.SESSION_COOKIE}=user.1042.invalid"):
            for value, expected in (("20240517", 200), ("4101", 200), ("1'", 500)):
                with self.subTest(cookie=cookie, value=value):
                    status, headers, body = self._request("GET", "/orders?" + urlencode({"order_id": value}), cookie)
                    self.assertEqual(status, expected)
                    self.assertNotIn("location", headers)
                    self.assertNotIn("set-cookie", headers)
                    controls = LoginControls(body)
                    self.assertCountEqual(controls.named_controls, ["order_id", "status", "from_date", "to_date"])
                    self.assertIn("/login/orders", controls.links)
                    self.assertNotIn('class="record member-record"', body)

    def test_order_login_rejects_upload_framing_without_waiting_for_a_body(self) -> None:
        for headers in ({"Content-Length": "64"}, {"Transfer-Encoding": "chunked"}):
            connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
            try:
                connection.request("POST", "/login/orders", headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                self.assertIsNone(response.getheader("Set-Cookie"))
                self.assertIsNone(response.getheader("Location"))
                response.read()
            finally:
                connection.close()
