"""DemoShop -- a realistic, fully labeled loopback storefront.

The old ``demo_target_server.py`` served fifteen bare routes whose parameter
names were the whole story: ``/search?q=`` reflected, ``/product?id=`` blew up
with a SQL error. It proved the CLI ran end-to-end, but it could not support an
evaluation. Thirty-seven input points, almost all trivially separable, make
``Precision@K`` land on ``1.000`` and say nothing.

This module replaces it with an online store: catalog, cart, checkout, orders,
seller console, support desk, admin. **100 query input points** across 32
routes, 40 of them genuinely vulnerable and 60 safe, and -- because the site is
authored here -- every one of them carries a known label. That is what makes
``Precision@K`` / ``Recall@K`` / ``MAP@K`` computable against a live scan
(``vulnspider.evaluation.live``).

Separability is the point of the mix
------------------------------------
A target that any ranking gets right measures nothing, so the safe input points
are chosen to be *hard*, and two vulnerable kinds are chosen to be *missable*:

* ``safe_validated`` answers a non-alphanumeric value with a plain 400. It
  fires ``status_code_changed`` exactly as error-based SQLi does, with no SQL
  signature behind it -- the single biggest false-positive source, and exactly
  what focused verification is supposed to demote (``INCONCLUSIVE_ERROR``).
* ``safe_dynamic`` varies its row count with the value, so
  ``response_length_diff_ratio`` moves on a page with nothing wrong with it.
* ``safe_escaped`` reflects the probe marker HTML-encoded. It is separable only
  because ``safe_html_encoding_detected`` exists (feature-v0.2).
* ``safe_stripped`` deletes the sentinel characters instead of encoding them,
  so that feature goes *unobserved* and the prior cannot tell it from a real
  raw reflection. It sits in the same score band as the XSS true positives and
  is separated only by focused verification, which never confirms it.
* ``xss_conditional`` is reflected raw only when a *second* parameter holds a
  particular value. A probe changes one input point at a time, so the default
  request never sees the reflection: a true positive the current observation
  model structurally misses.
* ``sqli_blind`` emits no SQL error at all; only the row count moves.
* ``safe_type_error`` binds its value as a parameter -- nothing is injectable --
  and still leaks a genuine driver cast error. It fires ``sql_error_pattern``
  like error-based SQLi, and *reproduces* it under every variant payload, so
  focused verification confirms it too. It is in the corpus precisely because
  the honest number is not 1.000.

Every route also carries a per-route block of constant filler, so page sizes
differ across routes and ``response_length_diff_ratio`` is not a label lookup
(same reasoning as ``tools/corpus_target_site.py``).

Why every parameter is a GET form control
-----------------------------------------
Each route renders a filter/search form holding *all* of its parameters, and
the storefront links to routes without a query string. The static crawler turns
a GET form's controls into ``QUERY`` input points on the action path, so one
crawled page yields that route's whole input surface. Including the storefront
and the parameter-free member login entries, 35 pages expose 100 input points.

The response echoes **every** parameter present, not just the first. A probe
changes exactly one parameter and leaves the rest at their seeds, so every
input point has to be observable on its own for the differential to mean
anything.

The lab
-------
``/_lab`` is the answer to "why is this input point worth ranking?": every
input point with its verdict, the reason, the signal VulnSpider observes, and
two links -- the normal request and the attack request -- so the difference is
visible in a browser. It is deliberately **not linked from the storefront**,
because crawling it would seed input points with payload values and corrupt the
baseline the scan measures against.

Run standalone:

    python demo_target_server.py            # http://127.0.0.1:8899
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zlib
from contextlib import closing
from dataclasses import dataclass
from html import escape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from tools import demo_shop_storefront as storefront

from vulnspider.corpus.ground_truth import (
    GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthKey,
    GroundTruthStore,
    ground_truth_from_entries,
)

APPLICATION_ID = "demoshop"
HOST = "127.0.0.1"
PORT = 8899
LAB_PATH = "/_lab"
LAB_GROUND_TRUTH_PATH = "/_lab/ground-truth.json"
# Marker the human demo flow adds to a request to turn on the PoC verdict.
VS_CONFIRM_PARAM = "vs_confirm"
# The dashboard's "취약점 검증" links land here; it redirects to the live
# confirm request for that input point. Not linked from any crawled page.
VERIFY_PATH = "/_verify"

SQLI = "SQLI"
REFLECTED_XSS = "REFLECTED_XSS"
BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"

# Characters that break out of the string literal in the routes that build
# their SQL by concatenation. The probe sentinel (Z<>"'Z) carries two of them,
# so a probe trips these routes while an ordinary catalogue value does not.
_SQL_METACHARS = frozenset({"'", '"', ";", "`", "\\"})

# What a strict server-side validator accepts: the shapes a real form allows.
_VALIDATION_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " _-.,@:/+"
)

# One phrasing per SQL dialect, picked per route so the target is not one
# vendor's error string repeated. ``sql_error_pattern`` matches all six.
_SQL_ERRORS = (
    "You have an error in your SQL syntax near '{value}'",
    "SQLSTATE[42000]: syntax error at or near '{value}'",
    "PostgreSQL: unterminated quoted string at or near '{value}'",
    "ORA-00933: SQL command not properly ended near '{value}'",
    "Microsoft SQL Server: Unclosed quotation mark after '{value}'",
    "SQLite error: near '{value}': syntax error",
)


@dataclass(frozen=True, slots=True)
class KindInfo:
    """What one behaviour is, and what a scanner can see of it.

    ``vulnerability`` is the ground truth: the family this behaviour is a true
    positive for, or ``""`` when the input point is safe. Everything else is
    lab copy -- it explains the verdict to a human and is never read by the
    scanner.
    """

    vulnerability: str
    verdict: str
    difficulty: str
    reason: str
    signal: str
    payload: str


KINDS: dict[str, KindInfo] = {
    "xss_raw": KindInfo(
        vulnerability=REFLECTED_XSS,
        verdict="취약",
        difficulty="탐지 쉬움",
        reason="입력값이 이스케이프 없이 본문에 그대로 출력된다.",
        signal="marker_reflected=1, safe_html_encoding_detected=0",
        payload="<script>alert('DemoShop XSS')</script>",
    ),
    "xss_attr": KindInfo(
        vulnerability=REFLECTED_XSS,
        verdict="취약",
        difficulty="탐지 쉬움",
        reason="입력값이 HTML 속성값 안에 따옴표 처리 없이 삽입된다.",
        signal="marker_reflected=1, safe_html_encoding_detected=0",
        payload='"><script>alert(\'DemoShop XSS\')</script>',
    ),
    "xss_js": KindInfo(
        vulnerability=REFLECTED_XSS,
        verdict="취약",
        difficulty="탐지 쉬움",
        reason="입력값이 <script> 안의 문자열 리터럴에 그대로 들어간다.",
        signal="marker_reflected=1, safe_html_encoding_detected=0",
        payload="';alert('DemoShop XSS');//",
    ),
    "xss_conditional": KindInfo(
        vulnerability=REFLECTED_XSS,
        verdict="취약",
        difficulty="탐지 어려움 (미탐 유발)",
        reason=(
            "다른 파라미터가 특정 값일 때만 이스케이프 없이 출력된다. "
            "그 조건에서는 실제로 취약하다."
        ),
        signal=(
            "기본 요청에서는 반사가 일어나지 않아 marker_reflected=0 → 미탐. "
            "한 번에 한 입력점만 바꾸는 차분 관측의 구조적 한계다"
        ),
        payload="<script>alert('DemoShop XSS')</script>",
    ),
    "sqli_error": KindInfo(
        vulnerability=SQLI,
        verdict="취약",
        difficulty="탐지 쉬움",
        reason="입력값을 질의 문자열에 이어붙여 SQL 오류 메시지가 그대로 노출된다.",
        signal="sql_error_pattern=1, status_code_changed=1",
        payload="1' OR '1'='1",
    ),
    "sqli_blind": KindInfo(
        vulnerability=SQLI,
        verdict="취약",
        difficulty="탐지 어려움",
        reason="오류는 숨기지만 조건의 참/거짓에 따라 조회되는 행 수가 달라진다.",
        signal="response_length_diff_ratio만 움직인다 (sql_error_pattern=0)",
        payload="1' AND '1'='2",
    ),
    "bac": KindInfo(
        vulnerability=BROKEN_ACCESS_CONTROL,
        verdict="취약",
        difficulty="접근제어 파이프라인 (--access-control)",
        reason="인가 확인 없이 식별자만 바꾸면 남의 자원이 그대로 조회된다.",
        signal="주입 신호 없음. 식별자 치환 재요청의 응답 비교로만 드러난다",
        payload="",
    ),
    "safe_escaped": KindInfo(
        vulnerability="",
        verdict="안전",
        difficulty="반사는 되지만 안전",
        reason="출력할 때 HTML 엔티티로 이스케이프한다.",
        signal="marker_reflected=1 이지만 safe_html_encoding_detected=1 로 감점",
        payload="<script>alert('blocked')</script>",
    ),
    "safe_type_error": KindInfo(
        vulnerability="",
        verdict="안전",
        difficulty="오탐 유발 (hard negative)",
        reason=(
            "값은 바인딩 파라미터로 넘어가 주입이 불가능하지만, 정수 캐스팅에 "
            "실패하면 드라이버의 DB 오류 메시지가 그대로 화면에 노출된다. "
            "정보 노출이지 SQL 주입은 아니다."
        ),
        signal=(
            "sql_error_pattern=1, status_code_changed=1 → 오류 기반 SQLi와 "
            "구별되지 않는다. 재검증에서도 같은 오류가 재현되므로 "
            "focused verification도 걸러내지 못한다"
        ),
        payload="1' OR '1'='1",
    ),
    "safe_stripped": KindInfo(
        vulnerability="",
        verdict="안전",
        difficulty="오탐 유발 (hard negative)",
        reason=(
            "출력 전에 <, >, 따옴표를 마침표로 치환한다. 남는 문자로는 "
            "스크립트를 만들 수 없어 실제로는 취약하지 않다."
        ),
        signal=(
            "marker_reflected=1 인데 sentinel이 사라져 "
            "safe_html_encoding_detected가 미관측 → 사전 점수만으로는 "
            "진짜 반사형 XSS와 구분되지 않는다"
        ),
        payload="<script>alert('blocked')</script>",
    ),
    "safe_validated": KindInfo(
        vulnerability="",
        verdict="안전",
        difficulty="오탐 유발 (hard negative)",
        reason="허용 문자 집합을 벗어난 값은 400으로 거절한다. 주입은 일어나지 않는다.",
        signal="status_code_changed=1 이지만 sql_error_pattern=0 → 검증 단계에서 강등",
        payload="1' OR '1'='1",
    ),
    "safe_dynamic": KindInfo(
        vulnerability="",
        verdict="안전",
        difficulty="오탐 유발 (hard negative)",
        reason="값에 따라 보여주는 결과 개수만 달라지고 질의에는 값이 들어가지 않는다.",
        signal="response_length_diff_ratio만 움직인다 → blind SQLi와 구분되지 않는다",
        payload="99",
    ),
    "safe_param": KindInfo(
        vulnerability="",
        verdict="안전",
        difficulty="신호 없음",
        reason="파라미터 바인딩으로 조회하고 값 자체는 출력하지 않는다.",
        signal="관측되는 신호 없음",
        payload="<script>alert('blocked')</script>",
    ),
    "safe_allowlist": KindInfo(
        vulnerability="",
        verdict="안전",
        difficulty="신호 없음",
        reason="허용 목록에 없는 값은 기본값으로 대체한다.",
        signal="관측되는 신호 없음",
        payload="<script>alert('blocked')</script>",
    ),
}


@dataclass(frozen=True, slots=True)
class InputSpec:
    """One query parameter: the store's form control and the scanner's unit."""

    name: str
    kind: str
    seed: str
    label: str
    control: str = "text"
    options: tuple[str, ...] = ()
    condition: tuple[str, str] | None = None
    """``(parameter, value)`` this input point is only rendered under.

    Only ``xss_conditional`` uses it: the reflection happens under a state the
    default request does not carry, which is what makes it missable.
    """

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown behaviour kind: {self.kind!r}")
        if self.control == "select" and self.seed not in self.options:
            raise ValueError(f"{self.name}: seed must be one of its options")
        if (self.kind == "xss_conditional") != (self.condition is not None):
            raise ValueError(f"{self.name}: xss_conditional requires a condition")

    @property
    def info(self) -> KindInfo:
        return KINDS[self.kind]

    @property
    def numeric_seed(self) -> bool:
        """Whether the access layer could plan an identifier substitution."""

        return self.seed.isdigit()


@dataclass(frozen=True, slots=True)
class PageSpec:
    """One storefront route and the input surface it exposes."""

    path: str
    title: str
    section: str
    blurb: str
    inputs: tuple[InputSpec, ...]
    listing: str = "plain"

    @property
    def seeds(self) -> dict[str, str]:
        return {item.name: item.seed for item in self.inputs}


def _text(name: str, kind: str, seed: str, label: str) -> InputSpec:
    return InputSpec(name=name, kind=kind, seed=seed, label=label)


def _choice(name: str, kind: str, options: tuple[str, ...], label: str) -> InputSpec:
    return InputSpec(
        name=name,
        kind=kind,
        seed=options[0],
        label=label,
        control="select",
        options=options,
    )


def _area(name: str, kind: str, seed: str, label: str) -> InputSpec:
    return InputSpec(name=name, kind=kind, seed=seed, label=label, control="textarea")


def _hidden(name: str, kind: str, seed: str, label: str) -> InputSpec:
    return InputSpec(name=name, kind=kind, seed=seed, label=label, control="hidden")


PAGES: tuple[PageSpec, ...] = (
    PageSpec(
        path="/search",
        title="통합 검색",
        section="쇼핑",
        blurb="상품명·브랜드·카테고리를 한 번에 검색합니다.",
        listing="products",
        inputs=(
            _text("q", "xss_raw", "sneakers", "검색어"),
            _choice(
                "category",
                "safe_allowlist",
                ("all", "shoes", "bags", "tech", "home"),
                "카테고리",
            ),
            _choice(
                "sort",
                "safe_allowlist",
                ("relevance", "price_asc", "price_desc", "newest"),
                "정렬",
            ),
            _text("min_price", "safe_type_error", "0", "최소 가격"),
            _text("max_price", "safe_validated", "500000", "최대 가격"),
        ),
    ),
    PageSpec(
        path="/catalog",
        title="카탈로그",
        section="쇼핑",
        blurb="카테고리별 상품 목록입니다.",
        listing="products",
        inputs=(
            _choice(
                "category",
                "safe_allowlist",
                ("shoes", "bags", "tech", "home"),
                "카테고리",
            ),
            _text("brand", "sqli_error", "northpeak", "브랜드"),
            _text("color", "safe_stripped", "black", "색상"),
            _choice("size", "safe_allowlist", ("all", "s", "m", "l"), "사이즈"),
            _text("sort", "sqli_blind", "newest", "정렬 기준"),
            _text("page", "safe_dynamic", "1", "페이지"),
        ),
    ),
    PageSpec(
        path="/product",
        title="상품 상세",
        section="쇼핑",
        blurb="선택한 상품의 상세 정보입니다.",
        listing="product",
        inputs=(
            _text("id", "sqli_error", "101", "상품 번호"),
            _text("variant", "xss_attr", "black-270", "선택한 옵션"),
            _choice("tab", "safe_allowlist", ("detail", "spec", "ship"), "탭"),
            _text("qty", "safe_type_error", "1", "수량"),
        ),
    ),
    PageSpec(
        path="/product/reviews",
        title="상품 리뷰",
        section="쇼핑",
        blurb="구매자가 남긴 리뷰입니다.",
        listing="reviews",
        inputs=(
            _text("product_id", "sqli_blind", "101", "상품 번호"),
            _choice("sort", "safe_allowlist", ("recent", "rating", "helpful"), "정렬"),
            _text("rating", "safe_validated", "5", "평점 필터"),
            _text("page", "safe_dynamic", "1", "페이지"),
        ),
    ),
    PageSpec(
        path="/product/qna",
        title="상품 문의",
        section="쇼핑",
        blurb="상품에 대한 질문과 판매자 답변입니다.",
        listing="reviews",
        inputs=(
            _text("product_id", "safe_stripped", "101", "상품 번호"),
            _text("q", "xss_raw", "배송", "문의 검색"),
            _choice("answered", "safe_allowlist", ("all", "yes", "no"), "답변 여부"),
        ),
    ),
    PageSpec(
        path="/review/new",
        title="리뷰 작성",
        section="쇼핑",
        blurb="구매한 상품에 리뷰를 남깁니다. 작성 전 미리보기가 표시됩니다.",
        inputs=(
            _text("product_id", "safe_param", "101", "상품 번호"),
            _text("title", "xss_raw", "가볍고 좋아요", "리뷰 제목"),
            _area("body", "safe_escaped", "발이 편합니다.", "리뷰 본문"),
            _text("rating", "safe_validated", "5", "평점"),
            _text("nickname", "xss_attr", "runner99", "표시 이름"),
        ),
    ),
    PageSpec(
        path="/cart",
        title="장바구니",
        section="주문",
        blurb="담아둔 상품을 확인하고 쿠폰을 적용합니다.",
        listing="orders",
        inputs=(
            _text("item_id", "safe_stripped", "5521", "장바구니 항목"),
            _text("qty", "safe_validated", "2", "수량"),
            _text("coupon", "sqli_error", "WELCOME10", "쿠폰 코드"),
            _text("note", "safe_stripped", "부재시 경비실", "배송 메모"),
        ),
    ),
    PageSpec(
        path="/checkout",
        title="주문서",
        section="주문",
        blurb="결제 전 주문 내용을 확인합니다.",
        listing="orders",
        inputs=(
            _text("order_ref", "xss_js", "ORD-20240517", "주문 참조번호"),
            _choice("shipping", "safe_allowlist", ("standard", "express"), "배송"),
            _choice("payment", "safe_allowlist", ("card", "transfer", "point"), "결제"),
            _area("message", "safe_stripped", "문 앞에 놓아주세요", "요청사항"),
            _text("zipcode", "safe_validated", "06236", "우편번호"),
        ),
    ),
    PageSpec(
        path="/orders",
        title="주문 내역",
        section="주문",
        blurb="기간별 주문 내역을 조회합니다.",
        listing="orders",
        inputs=(
            _text("order_id", "sqli_error", "20240517", "주문번호"),
            _choice("status", "safe_allowlist", ("all", "paid", "shipped"), "상태"),
            _text("from_date", "safe_validated", "2024-01-01", "시작일"),
            _text("to_date", "safe_validated", "2024-12-31", "종료일"),
        ),
    ),
    PageSpec(
        path="/order/track",
        title="배송 조회",
        section="주문",
        blurb="운송장 번호로 배송 상태를 조회합니다.",
        listing="orders",
        inputs=(
            _text("tracking_no", "sqli_blind", "884120553", "운송장 번호"),
            _choice("carrier", "safe_allowlist", ("cj", "post", "logen"), "택배사"),
        ),
    ),
    PageSpec(
        path="/order/invoice",
        title="거래명세서",
        section="주문",
        blurb="주문 건의 거래명세서를 확인합니다.",
        inputs=(
            _text("order_id", "bac", "20240517", "주문번호"),
            _choice("format", "safe_allowlist", ("html", "pdf"), "형식"),
        ),
    ),
    PageSpec(
        path="/account/login",
        title="로그인",
        section="내 계정",
        blurb="가입한 아이디로 로그인 링크를 받습니다.",
        inputs=(
            _text("username", "xss_raw", "soohoon", "아이디"),
            _text("return_to", "xss_attr", "/account/profile", "로그인 후 이동"),
            _text("next", "safe_stripped", "/cart", "다음 단계"),
        ),
    ),
    PageSpec(
        path="/account/profile",
        title="내 프로필",
        section="내 계정",
        blurb="공개 프로필에 표시되는 정보입니다.",
        inputs=(
            _text("uid", "bac", "1042", "회원 번호"),
            _text("nickname", "xss_raw", "soohoon", "닉네임"),
            InputSpec(
                name="bio",
                kind="xss_conditional",
                seed="러닝을 좋아합니다",
                label="소개글",
                control="textarea",
                condition=("view", "private"),
            ),
            _choice("view", "safe_allowlist", ("public", "private"), "공개 범위"),
        ),
    ),
    PageSpec(
        path="/account/address",
        title="배송지 관리",
        section="내 계정",
        blurb="등록된 배송지를 확인하고 수정합니다.",
        inputs=(
            _text("address_id", "bac", "77", "배송지 번호"),
            _text("zipcode", "safe_validated", "46241", "우편번호"),
            _text("city", "xss_attr", "부산", "도시"),
            _text("street", "safe_escaped", "부산대학로63번길 2", "상세 주소"),
        ),
    ),
    PageSpec(
        path="/account/wishlist",
        title="위시리스트",
        section="내 계정",
        blurb="찜한 상품 목록입니다.",
        listing="products",
        inputs=(
            _text("uid", "bac", "1042", "회원 번호"),
            _choice("sort", "safe_allowlist", ("recent", "price"), "정렬"),
            _text("page", "safe_dynamic", "1", "페이지"),
        ),
    ),
    PageSpec(
        path="/account/points",
        title="적립금",
        section="내 계정",
        blurb="적립금 사용 내역입니다.",
        listing="orders",
        inputs=(
            _text("uid", "safe_stripped", "1042", "회원 번호"),
            _choice("period", "safe_allowlist", ("30d", "90d", "1y"), "기간"),
        ),
    ),
    PageSpec(
        path="/support/ticket",
        title="문의 내역",
        section="고객센터",
        blurb="접수한 1:1 문의를 확인합니다.",
        listing="reviews",
        inputs=(
            _text("ticket_id", "bac", "8813", "문의 번호"),
            _text("subject", "xss_raw", "환불 문의", "제목"),
            _area("message", "safe_stripped", "언제 처리되나요?", "내용"),
            _choice(
                "category",
                "safe_allowlist",
                ("refund", "delivery", "etc"),
                "유형",
            ),
        ),
    ),
    PageSpec(
        path="/support/faq",
        title="자주 묻는 질문",
        section="고객센터",
        blurb="키워드로 FAQ를 검색합니다.",
        listing="articles",
        inputs=(
            _text("q", "safe_escaped", "교환", "검색어"),
            _choice("topic", "safe_allowlist", ("all", "order", "refund"), "주제"),
        ),
    ),
    PageSpec(
        path="/support/chat",
        title="상담 대기실",
        section="고객센터",
        blurb="상담원 연결 전 대기 화면입니다.",
        inputs=(
            _text("room", "safe_param", "r-4471", "상담방"),
            _text("nickname", "xss_js", "soohoon", "표시 이름"),
        ),
    ),
    PageSpec(
        path="/seller/dashboard",
        title="판매자 대시보드",
        section="판매자",
        blurb="판매 지표를 요약합니다.",
        listing="orders",
        inputs=(
            _text("seller_id", "sqli_error", "northpeak", "판매자 코드"),
            _choice("range", "safe_allowlist", ("7d", "30d", "90d"), "기간"),
            _choice("metric", "safe_allowlist", ("sales", "views", "returns"), "지표"),
        ),
    ),
    PageSpec(
        path="/seller/product/edit",
        title="상품 수정",
        section="판매자",
        blurb="등록한 상품 정보를 수정합니다.",
        inputs=(
            _text("product_id", "sqli_error", "101", "상품 번호"),
            _text("title", "xss_attr", "노스피크 러닝화", "상품명"),
            _text("price", "safe_validated", "39000", "판매가"),
            _text("stock", "safe_type_error", "12", "재고"),
        ),
    ),
    PageSpec(
        path="/seller/settlement",
        title="정산 내역",
        section="판매자",
        blurb="월별 정산 내역입니다.",
        listing="orders",
        inputs=(
            _text("seller_id", "bac", "24", "판매자 번호"),
            _text("month", "safe_validated", "2024-05", "정산 월"),
        ),
    ),
    PageSpec(
        path="/promo/coupon",
        title="쿠폰함",
        section="이벤트",
        blurb="발급받은 쿠폰을 확인합니다.",
        inputs=(
            _text("code", "sqli_blind", "SPRING24", "쿠폰 코드"),
            _text("campaign", "xss_raw", "봄맞이", "캠페인"),
        ),
    ),
    PageSpec(
        path="/promo/event",
        title="이벤트",
        section="이벤트",
        blurb="진행 중인 이벤트 안내입니다.",
        listing="articles",
        inputs=(
            _text("event_id", "safe_param", "31", "이벤트 번호"),
            _text("banner", "xss_attr", "spring-sale", "배너 코드"),
            _hidden("utm_source", "safe_stripped", "newsletter", "유입 경로"),
        ),
    ),
    PageSpec(
        path="/newsletter",
        title="뉴스레터",
        section="이벤트",
        blurb="신상품 소식을 메일로 받습니다.",
        inputs=(
            _text("email", "safe_validated", "soohoon@demoshop.test", "이메일"),
            _hidden("source", "safe_escaped", "footer", "유입 경로"),
        ),
    ),
    PageSpec(
        path="/blog/post",
        title="스타일 매거진",
        section="매거진",
        blurb="에디터가 쓴 스타일 가이드입니다.",
        listing="articles",
        inputs=(
            _text("slug", "safe_stripped", "spring-running", "글 주소"),
            _area("comment", "xss_raw", "잘 읽었습니다", "댓글"),
            _choice("sort", "safe_allowlist", ("recent", "popular"), "댓글 정렬"),
        ),
    ),
    PageSpec(
        path="/blog/search",
        title="매거진 검색",
        section="매거진",
        blurb="매거진 글을 검색합니다.",
        listing="articles",
        inputs=(_text("q", "sqli_blind", "러닝", "검색어"),),
    ),
    PageSpec(
        path="/compare",
        title="상품 비교",
        section="쇼핑",
        blurb="선택한 상품을 나란히 비교합니다.",
        listing="products",
        inputs=(
            _text("ids", "sqli_error", "101,104", "비교할 상품 번호"),
            _choice("sort", "safe_allowlist", ("price", "rating"), "정렬"),
        ),
    ),
    PageSpec(
        path="/store/locator",
        title="매장 찾기",
        section="고객센터",
        blurb="가까운 오프라인 매장을 찾습니다.",
        listing="articles",
        inputs=(
            _text("zip", "safe_validated", "06236", "우편번호"),
            _text("city", "xss_attr", "서울", "도시"),
            _text("radius", "safe_dynamic", "10", "반경(km)"),
        ),
    ),
    PageSpec(
        path="/api/suggest",
        title="검색어 추천",
        section="쇼핑",
        blurb="검색창 자동완성이 호출하는 내부 엔드포인트입니다.",
        inputs=(
            _text("term", "xss_raw", "sne", "입력 중인 검색어"),
            _text("limit", "safe_validated", "10", "개수"),
        ),
    ),
    PageSpec(
        path="/admin/users",
        title="아이디·비밀번호 찾기",
        section="내 계정",
        blurb="가입한 이메일이나 이름으로 계정을 찾습니다.",
        listing="orders",
        inputs=(
            _text("id", "bac", "1042", "회원 번호"),
            _choice("role", "safe_allowlist", ("member", "seller", "admin"), "역할"),
            _text("q", "sqli_error", "soohoon", "이메일 또는 이름"),
        ),
    ),
    PageSpec(
        path="/admin/orders",
        title="주문 관리",
        section="관리자",
        blurb="운영자용 주문 조회 화면입니다.",
        listing="orders",
        inputs=(
            _text("id", "bac", "20240517", "주문번호"),
            _choice("status", "safe_allowlist", ("all", "paid", "refund"), "상태"),
        ),
    ),
)

PAGES_BY_PATH: dict[str, PageSpec] = {page.path: page for page in PAGES}
INPUT_POINT_NUMBERS = {
    key: number
    for number, key in enumerate(
        ((page.path, item.name) for page in PAGES for item in page.inputs), start=1
    )
}

INPUT_POINTS = sum(len(page.inputs) for page in PAGES)
VULNERABLE_INPUT_POINTS = sum(
    1 for page in PAGES for item in page.inputs if item.info.vulnerability
)


def counts_by_family() -> dict[str, int]:
    """Vulnerable input points per ground truth family."""

    totals = {SQLI: 0, REFLECTED_XSS: 0, BROKEN_ACCESS_CONTROL: 0}
    for page in PAGES:
        for item in page.inputs:
            family = item.info.vulnerability
            if family:
                totals[family] += 1
    return totals


# ---------------------------------------------------------------------------
# Authenticated area: a small logged-in account section whose Broken Access
# Control the pipeline can genuinely evaluate.
# ---------------------------------------------------------------------------
#
# The public storefront above is intentionally unauthenticated (100 input
# points, injection evaluation). BAC is different: it needs a *session*. The two
# access features only mean anything when the reference request is an
# authenticated 2xx, and a proper access-control check can only return 403 to a
# request it can attribute to a user. So the account area lives behind a login,
# is reachable only with a session cookie, and is scanned separately
# (``analyze --url .../portal/ --cookie demoshop_session=... --access-control``).
#
# The public header links only to a parameter-free login screen. Its explicit
# POST action is never followed by the crawler; protected resources stay out of
# the anonymous injection scan. The BAC scan targets the portal directly.

LOGIN_PATH = "/login"
ORDER_LOGIN_PATH = "/login/orders"
ACCOUNT_INDEX_PATH = "/portal/"
SESSION_COOKIE = "demoshop_session"
DEMO_MEMBER = "한수훈"

# role -> user id. The scan logs in out-of-band as one of these and passes the
# resulting cookie with --cookie; DemoShop never creates accounts.
_USERS: dict[str, int] = {"admin": 1, "user": 1042}
# Not a real secret -- a fixed key so the token is deterministic and DemoShop can
# reject a forged or absent cookie (an unauthenticated request must get 403).
_SESSION_KEY = "demoshop-fixed-demo-key"


def _sign(role: str, uid: int) -> str:
    digest = hashlib.sha256(f"{role}.{uid}.{_SESSION_KEY}".encode()).hexdigest()
    return digest[:12]


def session_token(role: str) -> str:
    """The ``demoshop_session`` cookie value a login as ``role`` would set."""

    uid = _USERS[role]
    return f"{role}.{uid}.{_sign(role, uid)}"


def parse_session(cookie_header: str | None) -> tuple[str, int] | None:
    """Return ``(role, uid)`` for a valid session cookie, else ``None``."""

    if not cookie_header:
        return None
    jar: SimpleCookie = SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:  # noqa: BLE001 - a malformed cookie is simply no session
        return None
    morsel = jar.get(SESSION_COOKIE)
    if morsel is None:
        return None
    parts = morsel.value.split(".")
    if len(parts) != 3:
        return None
    role, raw_uid, signature = parts
    if role not in _USERS or not raw_uid.isdigit():
        return None
    uid = int(raw_uid)
    if _sign(role, uid) != signature:
        return None
    return role, uid


@dataclass(frozen=True, slots=True)
class AccountRoute:
    """One protected account resource keyed by a numeric identifier."""

    path: str
    title: str
    param: str
    seed: str
    kind: str  # "idor" (vulnerable) or "owned" (safe, ownership-checked)
    reason: str
    signal: str

    def __post_init__(self) -> None:
        if self.kind not in ("idor", "owned"):
            raise ValueError(f"unknown account route kind: {self.kind!r}")
        if not self.seed.isdigit():
            raise ValueError(f"{self.path}: account route seed must be numeric")

    @property
    def vulnerable(self) -> bool:
        return self.kind == "idor"


ACCOUNT_ROUTES: tuple[AccountRoute, ...] = (
    AccountRoute(
        path="/portal/order",
        title="주문 상세",
        param="ref",
        seed="4100",
        kind="idor",
        reason=(
            "로그인은 확인하지만 주문이 로그인 사용자의 것인지(소유권)는 "
            "확인하지 않는다. ref를 남의 번호로 바꾸면 그 주문이 그대로 조회된다."
        ),
        signal=(
            "식별자 치환(ref+1) 재요청이 200으로 다른 주문을 반환 → "
            "access_unauthorized_success=1.0"
        ),
    ),
    AccountRoute(
        path="/portal/message",
        title="쪽지함",
        param="thread",
        seed="880",
        kind="idor",
        reason=(
            "쪽지 스레드도 소유권 확인이 없다. thread 번호만 바꾸면 남의 쪽지를 "
            "읽을 수 있다."
        ),
        signal=(
            "식별자 치환(thread+1) 재요청이 200으로 다른 스레드를 반환 → "
            "access_unauthorized_success=1.0"
        ),
    ),
    AccountRoute(
        path="/portal/card",
        title="결제 수단",
        param="card_id",
        seed="5001",
        kind="owned",
        reason=(
            "결제 수단은 소유권을 확인한다. 로그인 사용자의 것이 아닌 card_id는 "
            "403으로 거절한다. 접근제어가 제대로 걸려 있다."
        ),
        signal=(
            "식별자 치환(card_id+1)·쿠키 제거 재요청이 403 → "
            "access_unauthorized_success=0.0 (안전)"
        ),
    ),
)

ACCOUNT_ROUTES_BY_PATH: dict[str, AccountRoute] = {
    route.path: route for route in ACCOUNT_ROUTES
}

ACCOUNT_VULNERABLE_INPUT_POINTS = sum(1 for r in ACCOUNT_ROUTES if r.vulnerable)


def account_ground_truth_entries() -> list[tuple[GroundTruthKey, bool]]:
    """Ground truth for the authenticated account routes.

    Each route's numeric parameter is a candidate for all three families:
    injection (both False -- the value is a bound record lookup, never
    reflected or concatenated) and BROKEN_ACCESS_CONTROL (True for the IDOR
    routes, False for the ownership-checked one).
    """

    entries: list[tuple[GroundTruthKey, bool]] = []
    for route in ACCOUNT_ROUTES:
        for family in (SQLI, REFLECTED_XSS, BROKEN_ACCESS_CONTROL):
            entries.append(
                (
                    GroundTruthKey(
                        application_id=APPLICATION_ID,
                        method="GET",
                        canonical_path=route.path,
                        parameter_location="QUERY",
                        parameter_name=route.param,
                        vulnerability_type=family,
                    ),
                    family == BROKEN_ACCESS_CONTROL and route.vulnerable,
                )
            )
    return entries


def ground_truth_entries() -> tuple[tuple[GroundTruthKey, bool], ...]:
    """Label every candidate the pipeline can generate for this site.

    Both injection families are labeled for every input point, because
    ``generate_candidates`` produces a SQLi *and* a Reflected XSS candidate for
    every FeatureVector. ``BROKEN_ACCESS_CONTROL`` is labeled only where the
    seed is a bare number, since that is the precondition for the access layer
    to plan an ``IDENTIFIER_SUBSTITUTION`` probe -- labeling the rest would
    invent ground truth for candidates that are never generated. The
    authenticated account routes (scanned separately with a session cookie) add
    their own BAC labels.
    """

    entries: list[tuple[GroundTruthKey, bool]] = []
    for page in PAGES:
        for item in page.inputs:
            families = [SQLI, REFLECTED_XSS]
            if item.numeric_seed:
                families.append(BROKEN_ACCESS_CONTROL)
            for family in families:
                entries.append(
                    (
                        GroundTruthKey(
                            application_id=APPLICATION_ID,
                            method="GET",
                            canonical_path=page.path,
                            parameter_location="QUERY",
                            parameter_name=item.name,
                            vulnerability_type=family,
                        ),
                        item.info.vulnerability == family,
                    )
                )
    entries.extend(account_ground_truth_entries())
    return tuple(entries)


def ground_truth() -> GroundTruthStore:
    """The site's labels as the evaluation protocol's store."""

    return ground_truth_from_entries(ground_truth_entries())


def ground_truth_document() -> dict[str, object]:
    """The labels in the JSON shape ``read_ground_truth`` accepts."""

    return {
        "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
        "application_id": APPLICATION_ID,
        "entries": [
            {**key.as_mapping(), "vulnerable": label}
            for key, label in ground_truth_entries()
        ],
    }


# ---------------------------------------------------------------------------
# Behaviour: what one parameter does to the response
# ---------------------------------------------------------------------------


def _echo_repeats(page: PageSpec, item: InputSpec) -> int:
    """How many times a reflecting route echoes its value: 1, 2, or 3.

    Real pages repeat a filter value -- breadcrumb, heading, result caption --
    and how often has nothing to do with whether the echo is escaped. Making it
    a per-route constant is what stops ``reflection_count_norm`` from becoming a
    label lookup: some safe reflections outrank some dangerous ones on the
    pre-verification prior, which is exactly the confusion focused verification
    has to resolve.
    """

    return 1 + zlib.crc32(f"{page.path}:{item.name}".encode("utf-8")) % 3


def _strip_dangerous(value: str) -> str:
    """Replace the characters an XSS payload needs, rather than encoding them.

    Substituting one ASCII byte per removed character, instead of deleting it,
    keeps the sanitised echo exactly as long as a raw one. Deleting them made
    ``response_length_diff_ratio`` systematically smaller on every sanitised
    route, which quietly turned one feature into a label lookup and let the
    prior separate these hard negatives for the wrong reason.
    """

    return "".join("." if char in "<>\"'" else char for char in value)


def _has_sql_metachar(value: str) -> bool:
    """Whether concatenating this value would break the surrounding literal."""

    return any(char in _SQL_METACHARS for char in value) or "--" in value


def _validation_ok(value: str) -> bool:
    return all(char in _VALIDATION_ALLOWED for char in value)


def _stable_count(value: str, *, base: int, spread: int) -> int:
    """A value-dependent row count that is reproducible across runs."""

    return base + zlib.crc32(value.encode("utf-8")) % spread


def _rows(items: list[str], *, css: str = "rows") -> str:
    return f'<ul class="{css}">' + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def _result_rows(label: str, count: int) -> str:
    return _rows(
        [
            f'{escape(label)} <span class="sku">#{1000 + index}</span> '
            f'<span class="price">{29000 + index * 1500:,}원</span>'
            for index in range(count)
        ]
    )


def _card(title: str, body: str, *, tone: str = "") -> str:
    css = f"card {tone}".strip()
    return f'<section class="{css}"><h3>{escape(title)}</h3>{body}</section>'


def _chrome(page: PageSpec) -> str:
    """Constant, route-specific filler.

    Page size has to vary from route to route for reasons that have nothing to
    do with a vulnerability, or ``response_length_diff_ratio`` degenerates into
    a label lookup. This block is identical on every response for a route, so
    it moves the ratio's denominator without ever creating a baseline/probe
    difference.
    """

    count = 3 + zlib.crc32(page.path.encode("utf-8")) % 7
    products = storefront.PRODUCTS
    picks = "".join(
        f'<li><a href="/product#item-{product.id}">'
        f'<img src="{product.image}" alt="{escape(product.name)}" '
        f'loading="lazy" width="1024" height="1024">'
        f'<b>{escape(product.name)}</b><em>{product.price:,}원</em></a></li>'
        for product in (products[index % len(products)] for index in range(count))
    )
    return (
        '<section class="picks"><h3>함께 본 상품</h3>'
        f'<ul class="grid">{picks}</ul></section>'
    )


def _sql_error(page: PageSpec, value: str) -> str:
    phrasing = _SQL_ERRORS[zlib.crc32(page.path.encode("utf-8")) % len(_SQL_ERRORS)]
    return phrasing.format(value=escape(value))


_IDOR_ORDER_PATHS = ("/order/invoice", "/admin/orders")


def _order_leak(order_id: str) -> str:
    """The order history an IDOR on an order route leaks -- another member's."""

    items = (
        ("무선 오버이어 헤드폰", 149000, "2024-05-18", "배송완료"),
        ("데일리 스웨이드 스니커즈", 89000, "2024-05-12", "배송완료"),
        ("에센셜 캔버스 토트", 59000, "2024-04-30", "구매확정"),
    )
    numbers = (escape(order_id), "20240512", "20240430")
    rows = "".join(
        f"<tr><td>{num}</td><td>{escape(name)}</td>"
        f"<td>{price:,}원</td><td>{escape(date)}</td><td>{escape(status)}</td></tr>"
        for num, (name, price, date, status) in zip(numbers, items)
    )
    return (
        '<p class="hint">소유권 확인 없이 다른 회원 <mark>전상현</mark> 님의 '
        "주문 명세가 조회되었습니다.</p>"
        '<table class="record"><tr>'
        "<th>주문번호</th><th>상품</th><th>결제금액</th><th>주문일</th><th>상태</th>"
        f"</tr>{rows}</table>"
    )


def _fragment(
    page: PageSpec,
    item: InputSpec,
    value: str,
    query: dict[str, str],
) -> tuple[int, str]:
    """Render one parameter's contribution, and the status it forces.

    Every present parameter is rendered, not just the first: a probe changes
    exactly one input point and leaves the rest at their seeds, so each one has
    to be independently observable for the differential to mean anything.
    """

    kind = item.kind
    repeats = _echo_repeats(page, item)
    if kind == "xss_raw":
        return 200, _card(
            item.label,
            "".join(
                f'<p class="echo">입력하신 <b>{value}</b> 기준으로 표시합니다.</p>'
                for _ in range(repeats)
            )
            + _result_rows("검색 결과", 4),
        )
    if kind == "xss_attr":
        return 200, _card(
            item.label,
            "".join(
                f'<input class="echo" type="text" name="{item.name}_view{index}" '
                f'value="{value}" readonly>'
                for index in range(repeats)
            ),
        )
    if kind == "xss_js":
        return 200, _card(
            item.label,
            "".join(
                f"<script>var demoshopLabel{index} = '" + value + "';</script>"
                for index in range(repeats)
            )
            + f'<p class="echo">화면 표시명: <span id="{item.name}_view"></span></p>',
        )
    if kind == "xss_conditional":
        assert item.condition is not None
        gate_name, gate_value = item.condition
        if query.get(gate_name, "") == gate_value:
            return 200, _card(
                item.label,
                f'<p class="echo">{value}</p>'
                f'<p class="hint">{escape(gate_name)}={escape(gate_value)} '
                "상태에서만 원문 그대로 표시됩니다.</p>",
            )
        return 200, _card(
            item.label,
            f'<p class="muted">{escape(gate_name)}={escape(gate_value)} '
            "일 때만 표시되는 항목입니다.</p>",
        )
    if kind == "sqli_error":
        if _has_sql_metachar(value):
            return 500, _card(
                item.label,
                f'<p class="error">Database error: {_sql_error(page, value)}</p>',
                tone="danger",
            )
        return 200, _card(
            item.label,
            _result_rows(f"{item.label} = {escape(value)}", 5),
        )
    if kind == "sqli_blind":
        rows = 1 if _has_sql_metachar(value) else 7
        return 200, _card(item.label, _result_rows("조회 결과", rows))
    if kind == "bac":
        if page.path in _IDOR_ORDER_PATHS:
            return 200, _card(item.label, _order_leak(value))
        return 200, _card(
            item.label,
            '<table class="record">'
            f"<tr><th>식별자</th><td>{escape(value)}</td></tr>"
            "<tr><th>이름</th><td>한수훈</td></tr>"
            "<tr><th>연락처</th><td>010-3071-4426</td></tr>"
            "<tr><th>이메일</th><td>tngns4426@pusan.ac.kr</td></tr>"
            "<tr><th>주소</th><td>부산광역시 금정구 부산대학로63번길 2</td></tr>"
            "<tr><th>결제수단</th><td>신한카드 ****-4426</td></tr>"
            "</table>"
            '<p class="hint">로그인 여부와 무관하게 조회됩니다.</p>',
        )
    if kind == "safe_escaped":
        return 200, _card(
            item.label,
            "".join(
                f'<p class="echo">{escape(value)}</p>' for _ in range(repeats)
            ),
        )
    if kind == "safe_type_error":
        # Bound as a parameter, so nothing is injectable -- but the driver
        # still reports a real cast failure, and the page leaks it.
        if not value.isdigit():
            return 500, _card(
                item.label,
                '<p class="error">SQLSTATE[22P02]: invalid input syntax for '
                f"type integer: &quot;{escape(value)}&quot;</p>",
                tone="danger",
            )
        return 200, _card(item.label, _result_rows("조회 결과", 4))
    if kind == "safe_stripped":
        cleaned = _strip_dangerous(value)
        return 200, _card(
            item.label,
            "".join(f'<p class="echo">{cleaned}</p>' for _ in range(repeats))
            + '<p class="hint">특수문자는 저장 전에 마침표로 치환됩니다.</p>',
        )
    if kind == "safe_validated":
        if not _validation_ok(value):
            return 400, _card(
                item.label,
                f'<p class="warn">입력값이 올바르지 않습니다. '
                f"{escape(item.label)} 형식을 확인해 주세요.</p>",
                tone="warn",
            )
        return 200, _card(item.label, f'<p class="echo">{escape(value)}</p>')
    if kind == "safe_dynamic":
        rows = _stable_count(value, base=2, spread=6)
        return 200, _card(item.label, _result_rows("표시 항목", rows))
    if kind == "safe_param":
        return 200, _card(
            item.label,
            '<p class="muted">준비된 항목을 불러왔습니다.</p>' + _result_rows("항목", 3),
        )
    if kind == "safe_allowlist":
        chosen = value if value in item.options else item.options[0]
        return 200, _card(
            item.label,
            f'<p class="echo">{escape(chosen)}</p>',
        )
    raise ValueError(f"unhandled behaviour kind: {kind!r}")


# ---------------------------------------------------------------------------
# Storefront rendering
# ---------------------------------------------------------------------------

_STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.6 "Malgun Gothic", system-ui, sans-serif;
       background: #f4f5f7; color: #16181d; }
a { color: #1b4dd1; text-decoration: none; }
a:hover { text-decoration: underline; }
header.top { background: #16181d; color: #fff; padding: 14px 24px;
             display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
header.top .brand { font-size: 20px; font-weight: 700; color: #fff; }
header.top nav a { color: #d6d9e0; font-size: 14px; }
main { max-width: 1080px; margin: 0 auto; padding: 24px; }
h1 { font-size: 24px; margin: 0 0 4px; }
p.blurb { color: #5b6070; margin: 0 0 20px; }
form.filters { background: #fff; border: 1px solid #dfe2e8; border-radius: 10px;
               padding: 16px; display: grid; gap: 12px;
               grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
form.filters label { display: block; font-size: 13px; color: #5b6070; }
form.filters input, form.filters select, form.filters textarea {
    width: 100%; padding: 8px; border: 1px solid #cfd4dd; border-radius: 6px;
    font: inherit; }
form.filters .actions { grid-column: 1 / -1; }
form.filters button { background: #1b4dd1; color: #fff; border: 0;
                      border-radius: 6px; padding: 9px 18px; font: inherit;
                      cursor: pointer; }
.results { display: grid; gap: 14px; margin: 20px 0;
           grid-template-columns: repeat(auto-fit, minmax(310px, 1fr)); }
.card { background: #fff; border: 1px solid #dfe2e8; border-radius: 10px;
        padding: 14px 16px; }
.card h3 { margin: 0 0 8px; font-size: 14px; color: #5b6070;
           text-transform: none; }
.card.danger { border-color: #e0b4b4; background: #fff6f6; }
.card.warn { border-color: #e6d3a3; background: #fffdf3; }
.echo { margin: 0; word-break: break-all; }
.muted, .hint { color: #7a8092; font-size: 13px; }
.error { color: #a11; font-family: Consolas, monospace; font-size: 13px; }
.warn { color: #8a6d1f; }
ul.rows { list-style: none; margin: 8px 0 0; padding: 0; }
ul.rows li { padding: 6px 0; border-top: 1px solid #eef0f4; font-size: 14px; }
.sku { color: #9aa0b0; font-size: 12px; }
.price { float: right; font-weight: 600; }
.picks { margin: 26px 0; }
.picks h3 { font-size: 15px; }
ul.grid { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px;
          grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
ul.grid li { background: #fff; border: 1px solid #dfe2e8; border-radius: 10px;
             padding: 10px; font-size: 13px; }
ul.grid .thumb { display: block; height: 62px; border-radius: 6px;
                 background: linear-gradient(135deg, #dfe4ee, #c9d1e3);
                 margin-bottom: 8px; }
ul.grid em { display: block; font-style: normal; font-weight: 600;
             margin-top: 4px; }
table.record { border-collapse: collapse; width: 100%; font-size: 14px; }
table.record th { text-align: left; color: #7a8092; font-weight: 500;
                  padding: 5px 10px 5px 0; white-space: nowrap; }
.sections { display: grid; gap: 18px;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.sections section { background: #fff; border: 1px solid #dfe2e8;
                    border-radius: 10px; padding: 16px; }
.sections h2 { font-size: 15px; margin: 0 0 10px; }
.sections ul { margin: 0; padding-left: 18px; }
.sections li { padding: 3px 0; }
footer.bottom { color: #7a8092; font-size: 13px; padding: 24px;
                text-align: center; }
table.lab { width: 100%; border-collapse: collapse; background: #fff;
            font-size: 13px; }
table.lab th, table.lab td { border: 1px solid #e3e6ec; padding: 7px 9px;
                             text-align: left; vertical-align: top; }
table.lab th { background: #f0f2f6; font-weight: 600; }
table.lab code { font-family: Consolas, monospace; }
.badge { display: inline-block; border-radius: 999px; padding: 2px 9px;
         font-size: 12px; font-weight: 600; white-space: nowrap; }
.badge.vuln { background: #fde8e8; color: #a11; }
.badge.safe { background: #e7f3e9; color: #1d6b34; }
.summary { display: grid; gap: 12px; margin: 0 0 22px;
           grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); }
.summary div { background: #fff; border: 1px solid #dfe2e8; border-radius: 10px;
               padding: 14px; }
.summary b { display: block; font-size: 26px; }
pre.cmd { background: #16181d; color: #e6e9f0; padding: 14px; border-radius: 8px;
          overflow-x: auto; font-size: 13px; }
"""

_POC_STYLE = (
    "<style>"
    """
/* Live vulnerability confirmation (Proof of Concept) -- styled to sit inside
   DemoShop's editorial storefront: flat cards, hairline borders, the shop's
   own palette (var(--ink)/--line/--sand/--paper) and a restrained warm accent
   for a confirmed finding, instead of a loud stand-alone alert. */
.poc-banner { display: flex; gap: 15px; align-items: flex-start; margin: 0 0 30px;
    padding: 20px 24px; border: 1px solid var(--line); border-left: 3px solid var(--muted);
    border-radius: 2px; background: var(--paper); }
.poc-banner .poc-icon { flex-shrink: 0; width: 26px; height: 26px; margin-top: 2px;
    color: var(--muted); }
.poc-banner .poc-icon svg { width: 100%; height: 100%; display: block; }
.poc-banner .poc-body { min-width: 0; }
.poc-eyebrow { font-size: 10px; font-weight: 700; letter-spacing: 1.7px;
    text-transform: uppercase; color: var(--muted); }
.poc-banner h2 { font-size: 22px; margin: 8px 0 13px; color: var(--ink);
    letter-spacing: -.035em; font-weight: 700; }
.poc-what { margin: 0 0 12px; font-size: 14px; color: #4c4f47; }
.poc-what b { color: var(--ink); }
.poc-what code, .poc-foot code { background: var(--sand); color: var(--ink); padding: 2px 7px;
    border-radius: 3px; border: 1px solid var(--line); font-family: Consolas, monospace;
    font-size: 12.5px; word-break: break-all; }
.poc-proof { margin: 0; font-size: 15px; line-height: 1.85; color: #3a3d36; }
.poc-evidence { margin-top: 18px; }
.poc-evidence-cap { font-size: 10px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--muted); margin-bottom: 7px; }
.poc-code { margin: 0; padding: 13px 15px; border-radius: 2px; background: var(--sand);
    border: 1px solid var(--line); color: var(--ink);
    font: 13px/1.7 Consolas, monospace; white-space: pre-wrap;
    word-break: break-all; overflow-x: auto; }
.poc-rows { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; font-size: 15px; }
.poc-rows span { background: var(--sand); border: 1px solid var(--line); border-radius: 2px;
    padding: 9px 14px; font-weight: 600; font-variant-numeric: tabular-nums; }
.poc-rows b { display: block; font-size: 10px; letter-spacing: .5px; text-transform: uppercase;
    color: var(--muted); font-weight: 700; margin-bottom: 3px; }
.poc-rows .hot { background: #fbf1ec; border-color: #e6c6b8; color: #8a2f16; }
.poc-rows .poc-arrow { background: none; border: 0; padding: 0; color: #b9bcb2; font-size: 20px; }
.poc-foot { margin: 17px 0 0; font-size: 11.5px; line-height: 1.7; color: var(--muted); }
/* State accents: warm terracotta for a confirmed finding (echoes the shop
   accent), sage for a defended route, amber for pending. */
.poc-confirmed { border-left-color: #b1442a; }
.poc-confirmed .poc-icon { color: #b1442a; }
.poc-confirmed h2 { color: #97381f; }
.poc-defended { border-left-color: #5c6a4c; }
.poc-defended .poc-icon { color: #5c6a4c; }
.poc-defended h2 { color: #46543a; }
.poc-pending { border-left-color: #9c7b2b; }
.poc-pending .poc-icon { color: #9c7b2b; }
.poc-pending h2 { color: #7c611f; }
.poc-cta { display: inline-block; font-weight: 600; color: #97381f;
    border: 1px solid #e0c3b7; background: #fbf2ee; border-radius: 3px;
    padding: 2px 9px; white-space: nowrap; }
.poc-cta:hover { text-decoration: none; background: #f6e7df; }
.poc-cta-row { margin-top: 7px; }
.poc-cta-row small { color: var(--muted); font-size: 11px; }
/* SQL injection impact: the built query, then the dumped table. */
.poc-sql { margin-top: 4px; }
.poc-sql-query { margin: 0 0 12px; padding: 12px 14px; border-radius: 2px;
    background: var(--sand); border: 1px solid var(--line); color: var(--ink);
    font: 13px/1.65 Consolas, monospace; white-space: pre-wrap; word-break: break-all; }
.poc-sql-query mark { background: #f4dcd1; color: #8a2f16; border-radius: 2px;
    padding: 0 3px; font-weight: 700; }
.poc-sql-note { font-size: 14px; line-height: 1.75; color: #4c4f47; margin: 0 0 14px; }
.poc-sql-note code { background: var(--sand); border: 1px solid var(--line); padding: 2px 6px;
    border-radius: 3px; font-family: Consolas, monospace; }
.poc-leak { border: 1px solid var(--line); border-radius: 2px; overflow: hidden; }
.poc-leak-head { background: #fbf2ee; color: #97381f; font-weight: 700; font-size: 13px;
    padding: 10px 14px; letter-spacing: .2px; border-bottom: 1px solid #ecdfd8; }
.poc-leak-wrap { overflow-x: auto; }
.poc-leak-table { width: 100%; border-collapse: collapse; font-size: 12.5px;
    background: var(--paper); white-space: nowrap; }
.poc-leak-table th { background: var(--sand); color: #6b4a3f; text-align: left;
    padding: 9px 12px; font-weight: 600; border-bottom: 1px solid var(--line); }
.poc-leak-table td { padding: 9px 12px; border-top: 1px solid var(--line); }
.poc-leak-table td.hash { font-family: Consolas, monospace; color: #a8452b; }
/* Inline highlight used inside the leaked-record cards (e.g. the IDOR order). */
.route-results mark, .poc-banner mark { background: #f4dcd1; color: #8a2f16;
    border-radius: 2px; padding: 0 3px; }
@media (max-width: 600px) { .poc-banner { padding: 16px 18px; } }
"""
    "</style>"
)


def _nav() -> str:
    sections: dict[str, str] = {}
    for page in PAGES:
        sections.setdefault(page.section, page.path)
    links = "".join(
        f'<a href="{path}">{escape(section)}</a>'
        for section, path in sections.items()
    )
    return f'<nav>{links}</nav>'


def _input_of(path: str, name: str) -> str:
    """Tag a storefront control with the canonical input point it feeds.

    Presentation only. The tag is static text (display number, label, name)
    that shop.css shows in reveal mode, so an audience can see that the header
    search box or a category tab ends up as one of the numbered parameters.
    """

    item = next(item for item in PAGES_BY_PATH[path].inputs if item.name == name)
    number = INPUT_POINT_NUMBERS[(path, name)]
    return (
        f'<span class="input-of" aria-hidden="true">⊙ #{number:03d} '
        f"{escape(item.label)} <code>{escape(name)}</code></span>"
    )


def _layout(title: str, body: str, *, input_count: int = 0, head_extra: str = "") -> bytes:
    # Reveal mode is a viewer preference kept in localStorage; restoring the
    # class before first paint avoids a flash of unmarked controls.
    count = f"<b data-reveal-count>{input_count}</b>" if input_count else ""
    toggle = (
        '<button class="reveal-toggle" type="button" data-reveal-toggle '
        'aria-pressed="false"><span aria-hidden="true">⊙</span>'
        f'<span data-reveal-label>입력점 표시</span>{count}</button>'
    )
    return (
        "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)} · DemoShop</title>"
        f'<style>{_STYLE}</style>{head_extra}<link rel="stylesheet" href="/assets/shop.css">'
        "<script>try{if(localStorage.getItem('demoshop-reveal-inputs')==='1')"
        "document.documentElement.classList.add('reveal-inputs')}catch(e){}</script>"
        f'<script src="{storefront.PRODUCTS_SCRIPT}" defer></script>'
        '<script src="/assets/shop.js" defer></script></head><body>'
        f"{storefront.header(_input_of)}<main>{body}</main>{toggle}"
        f"{storefront.footer()}</body></html>"
    ).encode("utf-8")


def _control(
    item: InputSpec,
    value: str,
    *,
    number: int | None = None,
    path: str = "",
    chips: tuple[tuple[str, str], ...] = (),
) -> str:
    # A filter form keeps what was submitted, so the value is echoed here too --
    # HTML-escaped, as a form control must be. For a route that sanitises on
    # input, the control shows the *sanitised* value: showing the raw one would
    # put an entity-encoded copy of the probe sentinel on the page and make the
    # route look defended by encoding, which is not what it does.
    if item.kind == "safe_stripped":
        value = _strip_dangerous(value)
    field_id = f' id="input-point-{number:03d}"' if number is not None else ''
    if item.control == "hidden":
        field = f'<input type="hidden"{field_id} name="{item.name}" value="{escape(value)}">'
    elif item.control == "select":
        options = "".join(
            f'<option value="{escape(option)}"'
            f'{" selected" if option == value else ""}>{escape(option)}</option>'
            for option in item.options
        )
        field = f'<select{field_id} name="{item.name}">{options}</select>'
    elif item.control == "textarea":
        field = f'<textarea{field_id} name="{item.name}" rows="2">{escape(value)}</textarea>'
    else:
        field = f'<input type="text"{field_id} name="{item.name}" value="{escape(value)}">'
    if number is None:
        return field if item.control == "hidden" else f"<label>{escape(item.label)}{field}</label>"
    label = escape(item.label)
    tooltip = (
        f'<span class="input-tooltip" role="tooltip" id="input-hint-{number:03d}">'
        f'<strong>입력점 #{number:03d}</strong><span>{label} · {escape(item.name)}</span>'
        + (f'<small>GET {escape(path)}?{escape(item.name)}=…</small>' if path else '')
        + ('<small>페이지에 포함된 숨김 입력</small>' if item.control == 'hidden' else '')
        + '</span>'
    )
    caption = (
        f'<span>{label}</span>' if item.control == 'hidden'
        else f'<label for="input-point-{number:03d}">{label}</label>'
    )
    return (
        f'<div class="input-point-field" data-input-point="{number:03d}">'
        f'<div class="field-caption">{caption}'
        f'<button class="input-marker" type="button" aria-label="입력점 {number:03d} 안내" '
        f'aria-describedby="input-hint-{number:03d}"><span aria-hidden="true">⊙</span>'
        f'<span class="marker-number" aria-hidden="true">{number:03d}</span></button>'
        f'{tooltip}</div>{field}'
        + ('<span class="hidden-input-note">숨김 입력</span>' if item.control == 'hidden' else '')
        + _chips(chips)
        + '</div>'
    )


def _chips(chips: tuple[tuple[str, str], ...]) -> str:
    # Quick picks are unnamed type=button controls: they set the text input's
    # value and submit, so the crawl still sees one control with its seed.
    if not chips:
        return ""
    return '<span class="chips">' + "".join(
        f'<button type="button" class="chip" data-chip="{escape(value)}">{escape(label)}</button>'
        for value, label in chips
    ) + "</span>"


def _filter_form(page: PageSpec, query: dict[str, str]) -> str:
    controls = "".join(
        _control(
            item,
            query.get(item.name, item.seed),
            number=INPUT_POINT_NUMBERS[(page.path, item.name)],
            path=page.path,
            chips=storefront.chips(page.path, item.name),
        )
        for item in page.inputs
    )
    submit = escape(storefront.route_copy(page.path).submit)
    return (
        f'<form class="filters" id="input-points" method="get" action="{page.path}">'
        f'{controls}<div class="actions"><button type="submit">{submit}</button></div>'
        "</form>"
    )


# ---------------------------------------------------------------------------
# Live vulnerability confirmation (Proof of Concept)
#
# A demo-only overlay: when the human demo flow adds the ``vs_confirm`` marker
# to a request, the route renders a plain-language verdict that a non-expert can
# read at a glance -- "this input point really is a SQL Injection", with the
# concrete evidence highlighted. The marker is added only by the lab launch
# links (which the crawler never reaches), so an ordinary probe -- and the whole
# scan -- sees a byte-for-byte unchanged response and is never affected.
# ---------------------------------------------------------------------------


def _confirm_link(page: PageSpec, item: InputSpec) -> str:
    """The lab launch URL that fires the PoC confirmation for one input point."""

    overrides = {item.name: item.info.payload}
    if item.kind == "bac":
        overrides[item.name] = str(int(item.seed) + 1)
    if item.condition is not None:
        overrides[item.condition[0]] = item.condition[1]
    overrides[VS_CONFIRM_PARAM] = item.name
    return _link(page, overrides)


def _account_confirm_link(route: AccountRoute) -> str:
    """The lab launch URL that fires the PoC confirmation for a portal route."""

    substituted = str(int(route.seed) + 1)
    return f"{route.path}?{urlencode({route.param: substituted, VS_CONFIRM_PARAM: route.param})}"


def verify_redirect(query: dict[str, str]) -> tuple[str | None, str | None]:
    """Resolve a dashboard "취약점 검증" click to a live confirm request.

    Returns ``(location, set_cookie)``. A storefront input point redirects to
    its confirm URL; a portal (BAC) route additionally issues the ``soohoon``
    session so the redirect lands logged in and shows another member's order.
    """

    path = query.get("path", "")
    param = query.get("param", "")
    page = PAGES_BY_PATH.get(path)
    if page is not None:
        item = next((it for it in page.inputs if it.name == param), None)
        if item is None:
            item = next((it for it in page.inputs if it.info.vulnerability), None)
        if item is not None:
            return _confirm_link(page, item), None
    route = ACCOUNT_ROUTES_BY_PATH.get(path)
    if route is not None:
        cookie = (
            f"{SESSION_COOKIE}={session_token('user')}; Path=/; HttpOnly; SameSite=Lax"
        )
        return _account_confirm_link(route), cookie
    return None, None


def _poc_source(caption: str, snippet: str) -> str:
    return (
        f'<div class="poc-evidence-cap">{escape(caption)}</div>'
        f'<pre class="poc-code">{escape(snippet)}</pre>'
    )


def _poc_rows(a_label: str, a: int, b_label: str, b: int) -> str:
    return (
        '<div class="poc-rows">'
        f'<span><b>{escape(a_label)}</b>{a}행 조회</span>'
        '<span class="poc-arrow" aria-hidden="true">→</span>'
        f'<span class="hot"><b>{escape(b_label)}</b>{b}행 조회</span></div>'
    )



# Shared demo customer fixtures; IDs are 1042, 1043, and 1044 respectively.
_LEAKED_MEMBERS = (
    ("한수훈", "tngns4426@pusan.ac.kr", "010-3071-4426", "신한 ****-4426", "$2b$12$Qk8s0…e3P/uZ2r"),
    ("전상현", "sanghyun.jeon@demoshop.test", "010-1234-5678", "국민 ****-1043", "$2b$12$V1cD9…9mA2Rf0k"),
    ("이석현", "seokhyun.lee@demoshop.test", "010-2345-6789", "우리 ****-1044", "$2b$12$7HdLq…kQ8Xy1Zt"),
)


def _member_secret(member_id: int, column: int) -> str:
    index = member_id - 1042
    if 0 <= index < len(_LEAKED_MEMBERS):
        return _LEAKED_MEMBERS[index][column]
    return "-"


def _member_results(query: dict[str, str]) -> tuple[int, str, int]:
    """Intentionally injectable, read-only search over three ephemeral demo rows."""
    value = query.get("q", "soohoon")
    identifier = query.get("id", "1042")
    # Default search is neutral so changing only the ID actually selects a member.
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE members (id INTEGER, username TEXT, name TEXT, email TEXT, phone TEXT)")
        db.executemany("INSERT INTO members VALUES (?, ?, ?, ?, ?)", [
            (1042 + index, username, row[0], row[1], row[2])
            for index, (username, row) in enumerate(zip(("soohoon", "sanghyun", "seokhyun"), _LEAKED_MEMBERS))
        ])
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16384)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
        db.execute("PRAGMA query_only = ON")
        db.set_progress_handler(lambda: 1, 10000)
        try:
            if value in ("", "soohoon"):
                rows = db.execute("SELECT id, name, email, phone FROM members WHERE id = ?", (identifier,)).fetchall()
            else:
                # Deliberate local teaching flaw. execute rejects multiple statements;
                # query_only and the instruction budget bound this disposable fixture.
                rows = db.execute(
                    "SELECT DISTINCT id, name, email, phone FROM ("
                    "SELECT id, name, email, phone, username AS term FROM members UNION ALL "
                    "SELECT id, name, email, phone, name AS term FROM members) WHERE term = '"
                    + value + "'"
                ).fetchall()
        except sqlite3.Error as exc:
            return 500, _card("계정 찾기", f'<p class="error">Database error: SQLite error: {escape(str(exc))}</p>', tone="danger"), 0
    # A member search matches at most one member. More than one row means
    # the filter was subverted -- render that as the breach it is, with the
    # private fields (card, password hash) a lookup must never return.
    if len(rows) > 1:
        leaked = "".join(
            "<tr>"
            f"<td>{escape(str(rid))}</td><td>{escape(str(name))}</td>"
            f"<td>{escape(str(email))}</td><td>{escape(str(phone))}</td>"
            f"<td>{escape(_member_secret(rid, 3))}</td>"
            f'<td class="hash">{escape(_member_secret(rid, 4))}</td></tr>'
            for rid, name, email, phone in rows
        )
        breach = (
            '<div class="member-breach"><div class="breach-head">'
            "\u26a0\ufe0f SQL Injection · 전체 계정 정보가 유출되었습니다</div>"
            '<div class="member-results-wrap"><table class="record breach-table"><tr>'
            "<th>회원번호</th><th>이름</th><th>이메일</th><th>연락처</th>"
            "<th>결제 카드</th><th>비밀번호 해시</th></tr>" + leaked + "</table></div></div>"
        )
        return 200, breach, len(rows)
    if rows:
        listing = "".join(
            f"<tr><td>{escape(str(rid))}</td><td>{escape(str(name))}</td></tr>"
            for rid, name, _email, _phone in rows
        )
        card_body = (
            f"<p>검색 결과 {len(rows)}건 · 계정의 공개 이름만 표시합니다.</p>"
            '<table class="record"><tr><th>회원번호</th><th>표시 이름</th></tr>'
            + listing + "</table>"
        )
    else:
        card_body = '<p class="muted">일치하는 계정이 없습니다.</p>'
    return 200, _card("계정 찾기", card_body, tone="member-results"), len(rows)


def _ownership_notice(session: tuple[str, int], holder: str, owner_uid: int) -> str:
    if session[1] == owner_uid:
        return ""
    name = DEMO_MEMBER if session[0] == "user" else session[0]
    return ('<aside class="ownership-mismatch" role="status"><strong>다른 사용자의 정보가 조회되었습니다</strong>'
            f'<p>현재 사용자: {escape(name)} (회원번호 {session[1]}) → '
            f'조회된 소유자: <mark>{escape(holder)} (회원번호 {owner_uid})</mark></p></aside>')


def _sqli_leak_panel(item: InputSpec, value: str) -> str:
    """Show the impact of the injection: the built query and the dumped table."""

    rows = "".join(
        f"<tr><td>{escape(name)}</td><td>{escape(email)}</td><td>{escape(phone)}</td>"
        f'<td>{escape(card)}</td><td class="hash">{escape(pw)}</td></tr>'
        for name, email, phone, card, pw in _LEAKED_MEMBERS
    )
    return (
        '<div class="poc-sql">'
        '<div class="poc-evidence-cap">서버가 실행한 질의</div>'
        '<pre class="poc-sql-query">SELECT * FROM members\n'
        f"WHERE {escape(item.name)} = '<mark>{escape(value)}</mark>'</pre>"
        "<p class=\"poc-sql-note\"><code>' OR '1'='1'</code> 은 조건을 <b>항상 참</b>으로 "
        "만들어 필터를 무력화합니다. 한 건이 아니라 <b>회원 테이블 전체</b>가 그대로 "
        "반환됩니다.</p>"
        '<div class="poc-leak"><div class="poc-leak-head">'
        "\U0001f513 유출된 회원 정보 · 전체 3건</div>"
        '<div class="poc-leak-wrap"><table class="poc-leak-table">'
        "<tr><th>이름</th><th>이메일</th><th>연락처</th><th>결제 카드</th>"
        "<th>비밀번호 해시</th></tr>"
        f"{rows}</table></div></div></div>"
    )


def _poc_banner(tone: str, heading: str, label: str, value: str,
                proof: str, evidence: str = "") -> str:
    _svg = (
        '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" '
        'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{}</svg>'
    )
    icons = {
        "confirmed": _svg.format('<path d="M4 10.5l3.6 3.6L16 5.4"/>'),
        "defended": _svg.format(
            '<path d="M10 2.4 4 4.7v4.4c0 3.7 3 6.5 6 7.9 3-1.4 6-4.2 6-7.9V4.7z"/>'
            '<path d="M7.6 9.8 9.4 11.6 12.7 8"/>'
        ),
        "pending": _svg.format('<circle cx="10" cy="10" r="7"/><path d="M10 6v4.2l2.8 1.8"/>'),
    }
    tags = {"confirmed": "취약점 확인됨", "defended": "방어 확인됨", "pending": "재현 대기"}
    return (
        f'<aside class="poc-banner poc-{tone}" role="status" tabindex="-1">'
        f'<div class="poc-icon" aria-hidden="true">{icons[tone]}</div>'
        '<div class="poc-body">'
        f'<div class="poc-eyebrow">취약점 검증 · Proof of Concept · {escape(tags[tone])}</div>'
        f'<h2>{escape(heading)}</h2>'
        f'<p class="poc-what"><b>{escape(label)}</b> 입력점에 '
        f'<code>{escape(value)}</code> 값을 전송했습니다.</p>'
        f'<p class="poc-proof">{escape(proof)}</p>'
        + (f'<div class="poc-evidence">{evidence}</div>' if evidence else "")
        + '<p class="poc-foot">이 확인 화면은 발표용 검증 요청에서만 나타나며, '
        '스캐너가 관측하는 일반 응답에는 포함되지 않습니다.</p>'
        '</div></aside>'
    )


_SAFE_REASONS = {
    "safe_escaped": (
        "입력한 스크립트가 화면에 되비쳐 나오긴 하지만, 출력할 때 <, >, 따옴표를 HTML 엔티티로 "
        "이스케이프합니다. 그래서 브라우저가 이를 코드가 아니라 화면에 보이는 '글자'로만 표시합니다. "
        "실행되지 않으므로 취약점이 아닙니다."
    ),
    "safe_type_error": (
        "500 오류가 보이지만 이것은 SQL 주입이 아닙니다. 값은 바인딩 파라미터로 안전하게 전달된 뒤 "
        "정수 변환에 실패했을 뿐이고, 그때 드라이버가 낸 캐스팅 오류 메시지가 노출된 것입니다. "
        "질의문에 값이 끼어들지 않으므로 주입은 불가능합니다(정보 노출일 뿐, 오탐을 유발하는 함정입니다)."
    ),
    "safe_stripped": (
        "출력하기 전에 <, >, 따옴표를 마침표(.)로 치환합니다. 남는 문자만으로는 스크립트를 만들 수 "
        "없으므로 실제로는 취약하지 않습니다."
    ),
    "safe_validated": (
        "허용된 문자 집합을 벗어난 값은 400으로 거절되어 질의나 화면에 도달하지 못합니다. "
        "입력 검증이 주입을 차단합니다."
    ),
    "safe_dynamic": (
        "값에 따라 보여주는 결과 개수만 달라질 뿐, 값 자체는 질의문에 들어가지 않습니다. "
        "블라인드 SQL Injection처럼 보이지만 실제로는 주입이 아닙니다."
    ),
    "safe_param": (
        "파라미터 바인딩으로만 조회하고 값 자체는 화면에 출력하지 않습니다. 관측되는 주입 신호가 없습니다."
    ),
    "safe_allowlist": (
        "허용 목록에 없는 값은 기본값으로 대체되므로 입력이 그대로 반영되지 않습니다."
    ),
}


def _confirmation(page: PageSpec, item: InputSpec, value: str,
                  query: dict[str, str]) -> str:
    """A beginner-friendly PoC verdict for one input point under a demo payload."""

    kind = item.kind
    label = item.label

    if kind in ("xss_raw", "xss_conditional"):
        if kind == "xss_conditional":
            assert item.condition is not None
            gate_name, gate_value = item.condition
            if query.get(gate_name, "") != gate_value:
                return _poc_banner(
                    "pending", "아직 페이로드가 반영되지 않았습니다", label, value,
                    f"이 입력점은 다른 조건({gate_name}={gate_value})이 함께 충족될 때만 원문이 "
                    "그대로 출력됩니다. 그 조건을 같이 보내면 취약점이 드러납니다.",
                )
        if "<" in value or ">" in value:
            return _poc_banner(
                "confirmed", "Reflected XSS 취약점이 확인되었습니다", label, value,
                "입력한 HTML/스크립트가 이스케이프 없이 페이지 본문에 그대로 삽입되어, 브라우저가 이를 "
                "실제 코드로 실행했습니다. 화면에 경고창(alert)이 떴다면 공격자가 넣은 스크립트가 실행된 "
                "것입니다. 반사형 XSS 취약점이 맞습니다.",
                _poc_source("페이지 소스에 삽입된 형태", f"<b>{value}</b>"),
            )
        return _poc_banner(
            "pending", "아직 페이로드가 반영되지 않았습니다", label, value,
            "HTML 특수문자(< 또는 >)가 포함된 값을 보내야 반사형 XSS가 드러납니다.",
        )
    if kind == "xss_attr":
        if '"' in value:
            return _poc_banner(
                "confirmed", "Reflected XSS 취약점이 확인되었습니다", label, value,
                "입력값이 HTML 속성값(value=\"…\") 안에 따옴표 처리 없이 들어가, 큰따옴표로 속성을 "
                "빠져나와 새로운 <script> 태그를 심을 수 있었습니다. 경고창이 떴다면 실행된 것입니다.",
                _poc_source("속성에 삽입된 형태", f'<input value="{value}">'),
            )
        return _poc_banner(
            "pending", "아직 페이로드가 반영되지 않았습니다", label, value,
            "큰따옴표(\")가 포함된 값을 보내야 속성 탈출형 XSS가 드러납니다.",
        )
    if kind == "xss_js":
        if "'" in value:
            return _poc_banner(
                "confirmed", "Reflected XSS 취약점이 확인되었습니다", label, value,
                "입력값이 <script> 내부의 문자열 안에 그대로 들어가, 작은따옴표로 문자열을 끊고 임의의 "
                "자바스크립트를 실행할 수 있었습니다. 경고창이 떴다면 실행된 것입니다.",
                _poc_source("스크립트에 삽입된 형태", f"<script>var demoshopLabel0 = '{value}';</script>"),
            )
        return _poc_banner(
            "pending", "아직 페이로드가 반영되지 않았습니다", label, value,
            "작은따옴표(')가 포함된 값을 보내야 스크립트 문자열 탈출형 XSS가 드러납니다.",
        )
    if page.path == "/admin/users" and item.name == "q":
        status, _result, row_count = _member_results(query)
        if status == 500:
            return _poc_banner("pending", "SQL 오류가 관찰되었습니다", label, value,
                               "회원 조회에 실패했습니다. 아래 실제 응답을 확인하세요.")
        if row_count > 1:
            return _poc_banner("confirmed", "SQL Injection 취약점이 확인되었습니다", label, value,
                               f"검색 조건이 우회되어 전체 계정 {row_count}건의 이메일·비밀번호 해시까지 "
                               "유출되었습니다. 아래가 실제 조회 결과입니다.")
        return _poc_banner("pending", "회원 조회 결과를 확인하세요", label, value,
                           "아래 회원 목록은 입력한 검색 조건의 실제 결과입니다.")
    if kind == "sqli_error":
        if _has_sql_metachar(value):
            return _poc_banner(
                "confirmed", "SQL Injection 취약점이 확인되었습니다", label, value,
                "입력값이 SQL 질의문에 그대로 들어갑니다. 공격자가 항상 참이 되는 조건을 "
                "넣으면 필터가 무너져 회원 전체 정보가 유출됩니다. 서버가 낸 500 SQL 구문 "
                "오류는 입력이 질의에 섞였다는 결정적 증거입니다.",
                _sqli_leak_panel(item, value),
            )
        return _poc_banner(
            "pending", "아직 페이로드가 반영되지 않았습니다", label, value,
            "따옴표(') 같은 SQL 특수문자가 포함된 값을 보내야 SQL 오류가 드러납니다.",
        )
    if kind == "sqli_blind":
        if _has_sql_metachar(value):
            return _poc_banner(
                "confirmed", "블라인드 SQL Injection 취약점이 확인되었습니다", label, value,
                "오류는 없지만 참/거짓 조건에 따라 조회 행 수가 달라집니다(정상 7행 → 페이로드 1행). "
                "이 참·거짓 반응을 한 글자씩 이용하면 아래처럼 회원 정보를 통째로 빼낼 수 있는 "
                "블라인드 SQL Injection입니다.",
                _poc_rows("정상 요청", 7, "페이로드 요청", 1) + _sqli_leak_panel(item, value),
            )
        return _poc_banner(
            "pending", "아직 페이로드가 반영되지 않았습니다", label, value,
            "SQL 조건이 담긴 값을 보내야 결과 행 수의 변화가 드러납니다.",
        )
    if kind == "bac" and page.path == "/admin/users":
        status, _result, row_count = _member_results(query)
        if status != 200 or row_count == 0:
            return _poc_banner("pending", "조회된 회원 정보가 없습니다", label, value,
                               "입력한 조건으로 회원 정보를 반환하지 않았습니다.")
        return _poc_banner("confirmed", "인증 없이 회원 정보가 조회되었습니다", label, value,
                           f"로그인 검사 없이 {row_count}건의 회원 정보가 반환되었습니다. 아래 실제 회원 목록을 확인하세요.")
    if kind == "bac":
        victim = "전상현" if page.path in _IDOR_ORDER_PATHS else _fake_holder(value)
        return _poc_banner(
            "confirmed", "Broken Access Control 취약점이 확인되었습니다", label, value,
            "인가 확인 없이 식별자만 바꾸자 다른 사용자의 자원이 그대로 조회되었습니다. "
            "권한 없는 자원 접근(Broken Access Control)이 맞습니다.",
            _poc_source("인가 없이 열람된 자원", f"{item.label} {value} → 소유자 {victim}"),
        )

    reason = _SAFE_REASONS.get(kind)
    if reason is None:
        return ""
    attacky = _has_sql_metachar(value) or "<" in value or ">" in value
    if not attacky:
        return ""
    return _poc_banner(
        "defended", "이 입력점은 안전하게 방어되어 있습니다", label, value, reason,
    )


def _confirm_banner(page: PageSpec, query: dict[str, str]) -> str:
    """The PoC verdict for a storefront route, or an empty string otherwise."""

    target_name = query.get(VS_CONFIRM_PARAM)
    if not target_name:
        return ""
    item = next((it for it in page.inputs if it.name == target_name), None)
    if item is None:
        return ""
    return _confirmation(page, item, query.get(item.name, item.seed), query)


def _account_confirm_banner(route: AccountRoute, value: str,
                            query: dict[str, str]) -> str:
    """The PoC verdict for a portal route, or an empty string otherwise."""

    if VS_CONFIRM_PARAM not in query:
        return ""
    label = route.title
    if route.kind == "idor":
        if value == route.seed:
            return _poc_banner(
                "pending", "아직 페이로드가 반영되지 않았습니다", label, value,
                "식별자를 다른 사용자의 값으로 바꿔 요청하면 IDOR이 드러납니다.",
            )
        return _poc_banner(
            "confirmed", "Broken Access Control(IDOR) 취약점이 확인되었습니다", label, value,
            "로그인은 했지만 소유권 확인이 없어, 식별자만 다른 값으로 바꾸자 다른 사용자의 자원이 "
            "그대로 열렸습니다. 권한 없는 자원 접근 — Broken Access Control(IDOR)이 맞습니다.",
            _poc_source("인가 없이 조회된 남의 자원", f"{route.param}={value} 소유자 "
                        + ("전상현" if route.path == "/portal/order" else _fake_holder(value))),
        )
    if value != route.seed:
        return _poc_banner(
            "defended", "이 자원은 접근제어로 보호되어 있습니다", label, value,
            "소유권을 확인하기 때문에, 다른 사용자의 식별자로 바꾼 요청을 403으로 거부했습니다. "
            "접근제어가 올바르게 동작하는 안전한 라우트입니다.",
        )
    return ""


def render_route(page: PageSpec, query: dict[str, str]) -> tuple[int, bytes]:
    """Render one storefront route for the parameters it was given."""

    status = 200
    cards: list[str] = []
    if page.path == "/admin/users":
        status, members, _row_count = _member_results(query)
        cards.append(members)
    for item in page.inputs:
        if page.path == "/admin/users" and item.name in ("id", "q"):
            continue
        value = query.get(item.name, item.seed)
        item_status, html = _fragment(page, item, value, query)
        status = max(status, item_status)
        cards.append(html)
    banner = _confirm_banner(page, query)
    body = (
        banner
        + f'<a class="surface-jump" href="#input-points">⊙ 이 페이지의 입력점 {len(page.inputs)}개 보기</a>'
        + storefront.route_body(
            page.path,
            page.title,
            page.blurb,
            _filter_form(page, query),
            "".join(cards),
            _input_of,
        )
        + _chrome(page)
    )
    return status, _layout(page.title, body, input_count=len(page.inputs), head_extra=_POC_STYLE if banner else "")


def render_index() -> bytes:
    """The storefront home page: the crawl entry point.

    It links every route with a bare path. Each route's filter form then
    exposes that route's whole parameter set, so the crawler reaches all 100
    input points in one page per route.
    """

    sections: dict[str, list[PageSpec]] = {}
    for page in PAGES:
        sections.setdefault(page.section, []).append(page)
    blocks = "".join(
        f"<section><h2>{escape(section)}</h2><ul>"
        + "".join(
            f'<li><a href="{page.path}">{escape(page.title)}</a></li>'
            for page in pages
        )
        + "</ul></section>"
        for section, pages in sections.items()
    )
    body = storefront.home(blocks, _input_of)
    return _layout("홈", body)


# ---------------------------------------------------------------------------
# The lab: why each input point is (or is not) a vulnerability
# ---------------------------------------------------------------------------


def _link(page: PageSpec, overrides: dict[str, str]) -> str:
    query = dict(page.seeds)
    query.update(overrides)
    return f"{page.path}?{urlencode(query)}"


def _attack_link(page: PageSpec, item: InputSpec) -> str:
    """The request that demonstrates the behaviour, with the rest at defaults."""

    overrides = {item.name: item.info.payload}
    if item.kind == "bac":
        overrides[item.name] = str(int(item.seed) + 1)
    if item.condition is not None:
        overrides[item.condition[0]] = item.condition[1]
    return _link(page, overrides)


def render_lab() -> bytes:
    """The instructor view: the site's own answer key, with live examples."""

    families = counts_by_family()
    rows: list[str] = []
    for page in PAGES:
        rows.append(
            f'<tr><th colspan="7">{escape(page.title)} '
            f"<code>{escape(page.path)}</code></th></tr>"
        )
        for item in page.inputs:
            info = item.info
            vulnerable = bool(info.vulnerability)
            badge = "vuln" if vulnerable else "safe"
            verdict = (
                f"{info.verdict} · {info.vulnerability}"
                if vulnerable
                else info.verdict
            )
            rows.append(
                "<tr>"
                f"<td><code>{escape(item.name)}</code></td>"
                f'<td><span class="badge {badge}">{escape(verdict)}</span></td>'
                f"<td><code>{escape(item.kind)}</code></td>"
                f"<td>{escape(info.difficulty)}</td>"
                f"<td>{escape(info.reason)}</td>"
                f"<td>{escape(info.signal)}</td>"
                f'<td><a href="{escape(_link(page, {}))}">정상</a>'
                + (
                    f' · <a href="{escape(_attack_link(page, item))}">공격</a>'
                    if info.payload or item.kind == "bac"
                    else ""
                )
                + (
                    f' · <a class="poc-cta" href="{escape(_confirm_link(page, item))}">'
                    "🎯 취약점 검증</a>"
                    if vulnerable
                    else ""
                )
                + "</td></tr>"
            )
    body = (
        "<h1>DemoShop 입력점 지도</h1>"
        '<p class="blurb">이 사이트의 정답지입니다. 각 입력점이 왜 취약한지 / 왜 '
        "안전한지, 그리고 VulnSpider가 무엇을 관측하는지 보여줍니다. "
        "‘공격’ 링크는 같은 요청을 브라우저에서 그대로 재현하고, ‘🎯 취약점 검증’ 링크는 그 결과를 비전공자도 알아볼 수 있는 확인 화면과 함께 보여줍니다.</p>"
        '<div class="summary">'
        f"<div><b>{INPUT_POINTS}</b>전체 입력점</div>"
        f"<div><b>{VULNERABLE_INPUT_POINTS}</b>취약 입력점</div>"
        f"<div><b>{families[REFLECTED_XSS]}</b>Reflected XSS</div>"
        f"<div><b>{families[SQLI]}</b>SQL Injection</div>"
        f"<div><b>{families[BROKEN_ACCESS_CONTROL]}</b>Broken Access Control</div>"
        f"<div><b>{INPUT_POINTS - VULNERABLE_INPUT_POINTS}</b>안전 입력점</div>"
        "</div>"
        f'<p>정답 파일: <a href="{LAB_GROUND_TRUTH_PATH}">'
        f"{LAB_GROUND_TRUTH_PATH}</a> · 평가 실행:</p>"
        "<pre class=\"cmd\">PYTHONPATH=src python -m vulnspider analyze \\\n"
        f"  --url http://{HOST}:{PORT}/ --max-pages 60 --max-requests 250 \\\n"
        "  --top-k 20 --output analysis.json \\\n"
        "  --verify --verify-output verify.json \\\n"
        "  --verification-model data/corpus/verification-model.json \\\n"
        "  --ground-truth data/demo/demoshop-ground-truth.json \\\n"
        "  --eval-output evaluation.json</pre>"
        '<table class="lab"><thead><tr>'
        "<th>파라미터</th><th>판정</th><th>동작</th><th>난이도</th>"
        "<th>이유</th><th>VulnSpider가 보는 신호</th><th>재현</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        + _account_lab_section()
    )
    return _layout("입력점 지도", body, head_extra=_POC_STYLE)


def _account_lab_section() -> str:
    """The authenticated-area (Broken Access Control) answer key."""

    rows = []
    for route in ACCOUNT_ROUTES:
        badge = "vuln" if route.vulnerable else "safe"
        verdict = "취약 · IDOR" if route.vulnerable else "안전 · 접근제어"
        cta_label = "🎯 취약점 검증" if route.vulnerable else "🛡️ 방어 확인"
        cta = (
            f'<div class="poc-cta-row"><a class="poc-cta" '
            f'href="{escape(_account_confirm_link(route))}">{cta_label}</a> '
            "<small>(admin 로그인 후)</small></div>"
        )
        rows.append(
            "<tr>"
            f"<td><code>{escape(route.path)}?{escape(route.param)}</code>{cta}</td>"
            f'<td><span class="badge {badge}">{escape(verdict)}</span></td>'
            f"<td>{escape(route.reason)}</td>"
            f"<td>{escape(route.signal)}</td>"
            "</tr>"
        )
    token = session_token("admin")
    return (
        f'<h2 style="margin-top:32px">인증 영역 (Broken Access Control)</h2>'
        '<p class="blurb">로그인 세션이 있어야 접근되는 영역입니다. 쿠키 없이는 '
        "403이라 크롤되지 않으므로, 세션 쿠키를 주고 <b>따로</b> 스캔합니다. "
        "IDOR은 소유권 확인이 없어 식별자만 바꾸면 남의 자원이 열리고, 정상 "
        "라우트는 소유권을 확인해 403으로 막습니다.</p>"
        f'<p>로그인: <a href="{LOGIN_PATH}?as=admin">{LOGIN_PATH}?as=admin</a> '
        f'/ <a href="{LOGIN_PATH}?as=user">{LOGIN_PATH}?as=user</a> · '
        f'대시보드: <a href="{ACCOUNT_INDEX_PATH}">{ACCOUNT_INDEX_PATH}</a> '
        "(쿠키 필요) · BAC 평가 실행:</p>"
        "<pre class=\"cmd\">PYTHONPATH=src python -m vulnspider analyze \\\n"
        f"  --url http://{HOST}:{PORT}{ACCOUNT_INDEX_PATH} "
        "--access-control \\\n"
        f"  --cookie {SESSION_COOKIE}={token} \\\n"
        "  --max-pages 20 --max-requests 100 --top-k 10 \\\n"
        "  --output portal-analysis.json \\\n"
        "  --ground-truth data/demo/demoshop-ground-truth.json \\\n"
        "  --application-id demoshop --eval-output portal-eval.json</pre>"
        '<table class="lab"><thead><tr>'
        "<th>보호 자원</th><th>판정</th><th>이유</th>"
        "<th>VulnSpider가 보는 신호</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def _account_form(route: AccountRoute, value: str) -> str:
    label = "주문번호" if route.path == "/portal/order" else route.param
    return (
        f'<form class="filters" method="get" action="{route.path}">'
        f"<label>{escape(label)}"
        f'<input type="text" name="{route.param}" value="{escape(value)}"></label>'
        '<div class="actions"><button type="submit">조회</button></div></form>'
    )


def _fake_holder(identifier: str) -> str:
    names = ("전상현", "이석현")
    return names[zlib.crc32(identifier.encode("utf-8")) % len(names)]


def render_login(role: str) -> bytes:
    body = (
        "<h1>로그인됨</h1>"
        f'<p class="blurb"><b>{escape(role)}</b> 세션이 발급되었습니다. '
        "이 쿠키를 스캐너에 전달하면 인증 상태로 크롤합니다.</p>"
        '<pre class="cmd">--cookie '
        f'{SESSION_COOKIE}={escape(session_token(role))}</pre>'
        f'<p><a href="{ACCOUNT_INDEX_PATH}">내 계정으로 이동 →</a></p>'
    )
    return _layout("로그인", body)


def render_member_login(*, action: str = LOGIN_PATH) -> bytes:
    """Human login only; viewing this page never issues a session cookie."""

    body = (
        '<section class="member-login"><p class="eyebrow">MY DEMOSHOP</p>'
        '<h1>로그인</h1><p>로그인하고 내 주문과 회원 정보를 확인하세요.</p>'
        f'<div class="member-profile"><span class="member-avatar" aria-hidden="true">{escape(DEMO_MEMBER[0])}</span>'
        f'<div><strong>{DEMO_MEMBER}</strong><span>기본 프로필 · 일반 회원</span></div></div>'
        f'<form method="post" action="{escape(action)}">'
        f'<button class="button dark" type="submit">{DEMO_MEMBER}으로 로그인</button></form>'
        '<p class="member-note">시연용 계정으로 비밀번호 없이 이용할 수 있습니다.</p>'
        '</section>'
    )
    return _layout("로그인", body)


def _member_heading(session: tuple[str, int], title: str) -> str:
    role, uid = session
    name = DEMO_MEMBER if role == "user" else role
    return (
        '<div class="member-heading"><div><p class="eyebrow">MY DEMOSHOP</p>'
        f'<h1>{escape(title)}</h1><p><strong>{escape(name)}</strong> 님 · 회원번호 {uid}</p></div>'
        '<form method="post" action="/logout">'
        '<button class="button outline" type="submit">로그아웃</button></form></div>'
    )


def render_account_index(session: tuple[str, int]) -> bytes:
    body = (
        '<section class="member-page">' + _member_heading(session, "마이페이지")
        + '<section class="member-order"><div class="section-heading"><h2>내 주문</h2>'
        '<span>최근 주문 1건</span></div><div class="member-order-row">'
        '<img src="/assets/sneakers.png" alt="데일리 스웨이드 스니커즈" width="104" height="104">'
        '<div><p class="eyebrow">주문번호 4100 · 배송완료</p>'
        '<h3>데일리 스웨이드 스니커즈</h3><p>2024.05.17 · 89,000원 · 수량 1</p></div>'
        '<a class="button dark" href="/portal/order">주문 상세</a></div></section>'
        '<nav class="member-links" aria-label="내 계정 메뉴">'
        '<a href="/portal/message">쪽지함 <span>↗</span></a>'
        '<a href="/portal/card">결제 수단 <span>↗</span></a></nav></section>'
    )
    return _layout("마이페이지", body)


def _forbidden(message: str) -> tuple[int, bytes]:
    body = (
        '<h1>403</h1>'
        f'<p class="warn">{escape(message)}</p>'
        f'<p><a href="{LOGIN_PATH}">로그인</a></p>'
    )
    return 403, _layout("접근 거부", body)


def render_account_route(
    route: AccountRoute,
    query: dict[str, str],
    session: tuple[str, int] | None,
) -> tuple[int, bytes]:
    """Render one protected account resource with its access-control behaviour."""

    if session is None:
        return _forbidden("로그인이 필요합니다. 세션 쿠키가 없습니다.")
    _role, uid = session
    value = query.get(route.param, route.seed)
    banner = _account_confirm_banner(route, value, query)

    if route.path == "/portal/order":
        # Intentionally vulnerable fixture: authentication is enforced above,
        # but changing only ref returns another member's synthetic order.
        own = value == route.seed
        holder, owner_uid = (DEMO_MEMBER, 1042) if own else ("전상현", 1043)
        product = "데일리 스웨이드 스니커즈" if own else "무선 오버이어 헤드폰"
        price = "89,000" if own else "149,000"
        photo = "sneakers" if own else "headphones"
        date = "2024.05.17" if own else "2024.05.18"
        body = (
            '<section class="member-page">' + _member_heading(session, route.title)
            + f'<p><a class="text-link" href="{ACCOUNT_INDEX_PATH}">← 마이페이지</a></p>'
            + banner + _ownership_notice(session, holder, owner_uid)
            + '<section class="route-panel"><div class="panel-heading">'
            '<h2>주문 조회</h2><p>주문번호로 주문 내역을 확인하세요.</p></div>'
            + _account_form(route, value) + '</section>'
            '<section class="member-order"><div class="section-heading"><h2>주문 내역</h2>'
            '<span>배송완료</span></div><table class="record member-record">'
            f'<tr><th>주문번호</th><td>{escape(value)}</td></tr>'
            f'<tr><th>주문자</th><td>{holder}</td></tr>'
            f'<tr><th>소유자 uid</th><td>{owner_uid}</td></tr>'
            f'<tr><th>주문일</th><td>{date}</td></tr></table>'
            '<div class="member-order-row">'
            f'<img src="/assets/{photo}.png" alt="{product}" width="104" height="104">'
            f'<div><h3>{product}</h3><p>수량 1 · 배송완료</p></div>'
            f'<strong>{price}원</strong></div></section></section>'
        )
        return 200, _layout(route.title, body, head_extra=_POC_STYLE if banner else "")

    if route.kind == "owned":
        # Proper access control: the resource must belong to the session user.
        # Each user's own card is the seed value; any other identifier is
        # someone else's and is denied -- so a substituted id gets a 403
        # regardless of which role is logged in. This is the true negative the
        # BAC pipeline should score low.
        if value != route.seed:
            message = (
                f"{escape(route.param)}={escape(value)} 는 현재 사용자의 것이 "
                "아닙니다."
            )
            if not banner:
                return _forbidden(message)
            body = (
                banner + "<h1>403</h1>"
                f'<p class="warn">{message}</p>'
                f'<p><a href="{LOGIN_PATH}">로그인</a></p>'
            )
            return 403, _layout("접근 거부", body, head_extra=_POC_STYLE)
        card = _account_form(route, value) + _card(
            route.title,
            '<table class="record">'
            f"<tr><th>{escape(route.param)}</th><td>{escape(value)}</td></tr>"
            "<tr><th>카드</th><td>신한 ****-4426</td></tr>"
            f"<tr><th>소유자 uid</th><td>{uid}</td></tr></table>",
        )
        return 200, _layout(route.title, f"{banner}<h1>{escape(route.title)}</h1>{card}", head_extra=_POC_STYLE if banner else "")

    # IDOR: authenticated, but no ownership check -- any id is served.
    holder = DEMO_MEMBER if value == route.seed else _fake_holder(value)
    owner_uid = 1042 if value == route.seed else (1043 if holder == "전상현" else 1044)
    record = _ownership_notice(session, holder, owner_uid) + _account_form(route, value) + _card(
        route.title,
        '<table class="record">'
        f"<tr><th>{escape(route.param)}</th><td>{escape(value)}</td></tr>"
        f"<tr><th>소유자</th><td>{escape(holder)}</td></tr>"
        "<tr><th>내용</th><td>주문/쪽지 상세가 인가 확인 없이 표시됩니다.</td></tr>"
        "</table>"
        '<p class="hint">소유권을 확인하지 않으므로 남의 자원도 조회됩니다.</p>',
        tone="danger",
    )
    return 200, _layout(route.title, f"{banner}{_member_heading(session, route.title)}{record}", head_extra=_POC_STYLE if banner else "")


class DemoShopHandler(BaseHTTPRequestHandler):
    """Loopback fixture with member POST actions and a legacy GET role helper."""

    server_version = "DemoShop/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep the console readable while a scan runs

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if parts.path == storefront.PRODUCTS_SCRIPT:
            self._respond(
                200,
                storefront.products_script(),
                content_type="text/javascript; charset=utf-8",
            )
            return
        asset = storefront.ASSETS.get(parts.path)
        if asset is not None:
            asset_path, content_type = asset
            self._respond(200, asset_path.read_bytes(), content_type=content_type)
            return
        query = {
            name: values[0]
            for name, values in parse_qs(parts.query, keep_blank_values=True).items()
        }
        if parts.path == VERIFY_PATH:
            location, cookie = verify_redirect(query)
            if location is None:
                self._respond(404, _layout("취약점 검증",
                    "<h1>검증 대상 입력점을 찾을 수 없습니다</h1>"
                    '<p class="blurb">path·param 값을 확인하세요.</p>'))
            else:
                self._respond(303, b"", location=location, set_cookie=cookie)
            return
        if parts.path in ("/", "/index.html"):
            self._respond(200, render_index())
            return
        if parts.path == LAB_GROUND_TRUTH_PATH:
            self._respond(
                200,
                json.dumps(ground_truth_document(), ensure_ascii=False, indent=2)
                .encode("utf-8"),
                content_type="application/json; charset=utf-8",
            )
            return
        if parts.path == LAB_PATH:
            self._respond(200, render_lab())
            return
        session = parse_session(self.headers.get("Cookie"))
        if parts.path in (LOGIN_PATH, ORDER_LOGIN_PATH):
            destination = "/portal/order" if parts.path == ORDER_LOGIN_PATH else ACCOUNT_INDEX_PATH
            if "as" not in query or parts.path == ORDER_LOGIN_PATH:
                if session is not None:
                    self._respond(303, b"", location=destination)
                else:
                    self._respond(200, render_member_login(action=parts.path))
                return
            # Retain explicit role login for the existing scanner/lab runbook.
            role = query["as"]
            if role not in _USERS:
                self._respond(400, _layout("로그인", "<h1>알 수 없는 역할</h1>"))
                return
            self._respond(
                200,
                render_login(role),
                set_cookie=f"{SESSION_COOKIE}={session_token(role)}; Path=/; HttpOnly; SameSite=Lax",
            )
            return
        if parts.path == "/orders" and session is not None:
            # Old shopper bookmarks/forms hand off to the authoritative member
            # order endpoint. Anonymous /orders remains the public SQLi fixture.
            entered = query.get("order_id", "4100")
            ref = {"20240517": "4100", "20240518": "4101"}.get(entered, entered)
            self._respond(303, b"", location="/portal/order?" + urlencode({"ref": ref}))
            return
        if parts.path in (ACCOUNT_INDEX_PATH, "/portal"):
            if session is None:
                status, body = _forbidden("로그인이 필요합니다.")
                self._respond(status, body)
                return
            self._respond(200, render_account_index(session))
            return
        account_route = ACCOUNT_ROUTES_BY_PATH.get(parts.path)
        if account_route is not None:
            status, body = render_account_route(account_route, query, session)
            self._respond(status, body)
            return
        page = PAGES_BY_PATH.get(parts.path)
        if page is None:
            self._respond(404, _layout("찾을 수 없음", "<h1>404</h1>"))
            return
        status, body = render_route(page, query)
        self._respond(status, body)

    def do_POST(self) -> None:
        # Both forms have no named controls and no body to read. Reject body
        # uploads instead of introducing unbounded/blocking request-body I/O.
        path = urlsplit(self.path).path
        if path not in (LOGIN_PATH, ORDER_LOGIN_PATH, "/logout"):
            self._respond(405, b"Method Not Allowed")
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            self._respond(400, b"Empty form required")
            return
        if path in (LOGIN_PATH, ORDER_LOGIN_PATH):
            destination = "/portal/order" if path == ORDER_LOGIN_PATH else ACCOUNT_INDEX_PATH
            self._respond(
                303, b"", location=destination,
                set_cookie=f"{SESSION_COOKIE}={session_token('user')}; Path=/; HttpOnly; SameSite=Lax",
            )
        else:
            self._respond(
                303, b"", location=LOGIN_PATH,
                set_cookie=f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            )

    def _respond(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "text/html; charset=utf-8",
        set_cookie: str | None = None,
        location: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie is not None:
            self.send_header("Set-Cookie", set_cookie)
        if location is not None:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)


def build_server(port: int = PORT) -> ThreadingHTTPServer:
    """Bind the storefront to loopback only."""

    return ThreadingHTTPServer((HOST, port), DemoShopHandler)


def banner(port: int = PORT) -> str:
    families = counts_by_family()
    base = f"http://{HOST}:{port}"
    return (
        f"DemoShop  {base}/\n"
        f"  입력점 {INPUT_POINTS}개 "
        f"(취약 {VULNERABLE_INPUT_POINTS}: XSS {families[REFLECTED_XSS]}, "
        f"SQLi {families[SQLI]}, BAC {families[BROKEN_ACCESS_CONTROL]} / "
        f"안전 {INPUT_POINTS - VULNERABLE_INPUT_POINTS}), 라우트 {len(PAGES)}개\n"
        f"  입력점 지도(정답지)  {base}{LAB_PATH}\n"
        f"  정답 JSON            {base}{LAB_GROUND_TRUTH_PATH}\n"
        "  (지도는 상점에서 링크되지 않습니다: 크롤 대상은 상점 화면뿐입니다)\n"
        f"  인증 영역(BAC)       {base}{LOGIN_PATH}?as=admin → {base}{ACCOUNT_INDEX_PATH}\n"
        f"    로그인 후 세션 쿠키로 스캔: --cookie {SESSION_COOKIE}="
        f"{session_token('admin')}\n"
        f"    BAC 취약 {ACCOUNT_VULNERABLE_INPUT_POINTS} (IDOR) / 정상 "
        f"{len(ACCOUNT_ROUTES) - ACCOUNT_VULNERABLE_INPUT_POINTS}, "
        f"라우트 {len(ACCOUNT_ROUTES)}개 (쿠키 없이는 403)"
    )
