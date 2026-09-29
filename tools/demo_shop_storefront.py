"""Presentation-only storefront. Product selections never mutate server state.

Every canonical input point is rendered by ``demo_shop`` as a control of the
route's GET form. This module decides where that form sits on the page and
what the page shows around it -- a filter bar above the product grid, the
option panel of a product page, the order form of the checkout -- so the
audience uses the real input points, not a stand-in. Nothing here adds a
parameter, a named control or a link with a query string: the crawl surface
is the form ``demo_shop`` renders, and only that.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from html import escape
from pathlib import Path

InputTag = Callable[[str, str], str]
"""``(path, name) -> html`` naming the canonical input point a control feeds.

The storefront never knows the numbering itself; ``demo_shop`` passes the
renderer in so the tag stays in step with ``INPUT_POINT_NUMBERS``.
"""


def untagged(path: str, name: str) -> str:
    return ""


ASSET_ROOT = Path(__file__).with_name("demo_shop_assets")
ASSETS = {
    f"/assets/{name}": (ASSET_ROOT / name, content_type)
    for name, content_type in (
        ("shop.css", "text/css; charset=utf-8"),
        ("shop.js", "text/javascript; charset=utf-8"),
        ("sneakers.png", "image/png"),
        ("tote.png", "image/png"),
        ("headphones.png", "image/png"),
        ("lamp.png", "image/png"),
        # Colour variants: the product recoloured, background untouched
        # (tools/demo_shop_assets/make_variants.py).
        ("sneakers-black.jpg", "image/jpeg"),
        ("sneakers-white.jpg", "image/jpeg"),
        ("tote-navy.jpg", "image/jpeg"),
        ("tote-black.jpg", "image/jpeg"),
        ("headphones-silver.jpg", "image/jpeg"),
        ("headphones-blue.jpg", "image/jpeg"),
        ("lamp-sage.jpg", "image/jpeg"),
        ("lamp-cream.jpg", "image/jpeg"),
    )
}

CATEGORY_LABELS = {"shoes": "슈즈", "bags": "가방", "tech": "디지털", "home": "홈 & 리빙"}


@dataclass(frozen=True, slots=True)
class Product:
    """One catalog entry. Colour variants are recoloured copies of a photo."""

    id: str
    photo: str
    """Base photo (``sneakers`` …): the search haystack and the asset family."""
    brand: str
    brand_key: str
    name: str
    price: int
    category: str
    color: str
    color_label: str
    sizes: tuple[str, ...]
    rank: int
    """Recency: 1 is the newest, used by ``sort=newest`` / ``recent``."""
    badge: str = ""
    file: str = ""
    """Asset file name; defaults to the base photo's PNG."""
    blurb: str = ""
    variants: tuple[tuple[str, str], ...] = ()
    """``(value, label)`` options for the product page's ``variant`` input."""

    @property
    def image(self) -> str:
        return f"/assets/{self.file or self.photo + '.png'}"

    @property
    def haystack(self) -> str:
        return " ".join(
            (
                self.brand,
                self.brand_key,
                self.name,
                self.photo,
                self.category,
                CATEGORY_LABELS[self.category],
                self.color,
                self.color_label,
            )
        ).lower()


def _sizes(colour: str, label: str, sizes: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Colour-matched size options: a product only offers its own colour."""

    return tuple((f"{colour}-{size}", f"{label} {size.upper()}") for size in sizes)


_SHOE_SIZES = ("250", "260", "270", "280")
_BAG_SIZES = ("m", "l")
_HEADPHONES = (("graphite", "그래파이트"), ("silver", "실버"), ("blue", "블루"))
_MUSHROOM_LAMP = (("terracotta", "테라코타"), ("sage", "세이지"), ("cream", "크림"))

PRODUCTS: tuple[Product, ...] = (
    Product("101", "sneakers", "NORTHPEAK", "northpeak", "데일리 스웨이드 스니커즈", 89000, "shoes", "sand", "샌드", ("s", "m", "l"), 3, "BEST",
            blurb="부드러운 스웨이드와 편안한 쿠션. 어떤 옷에도 자연스럽게 어울리는 데일리 슈즈.", variants=_sizes("sand", "샌드", _SHOE_SIZES)),
    Product("102", "tote", "FORM & FIELD", "formfield", "에센셜 캔버스 토트", 59000, "bags", "oatmeal", "오트밀", ("m", "l"), 4, "NEW",
            blurb="탄탄한 캔버스와 부드러운 가죽 손잡이. 출근부터 주말 산책까지 가볍게 함께하세요.", variants=_sizes("oatmeal", "오트밀", _BAG_SIZES)),
    Product("103", "headphones", "STILL SOUND", "stillsound", "무선 오버이어 헤드폰", 149000, "tech", "graphite", "그래파이트", (), 5, "PICK",
            blurb="오롯이 나만의 리듬에 집중하는 시간. 포근한 이어 쿠션과 차분한 그래파이트 컬러.", variants=_HEADPHONES),
    Product("104", "lamp", "ROOM EDIT", "roomedit", "머쉬룸 테이블 램프", 69000, "home", "terracotta", "테라코타", (), 6, "NEW",
            blurb="둥근 실루엣과 따뜻한 테라코타 컬러. 좋아하는 공간에 은은한 빛을 더해보세요.", variants=_MUSHROOM_LAMP),
    Product("105", "sneakers", "NORTHPEAK", "northpeak", "데일리 스웨이드 스니커즈 블랙", 89000, "shoes", "black", "블랙", ("s", "m", "l"), 1, "NEW",
            file="sneakers-black.jpg", blurb="같은 편안함, 더 차분한 색. 어디에나 어울리는 블랙 스웨이드.", variants=_sizes("black", "블랙", _SHOE_SIZES)),
    Product("106", "sneakers", "NORTHPEAK", "northpeak", "코트 스니커즈 화이트", 129000, "shoes", "white", "화이트", ("m", "l"), 7,
            file="sneakers-white.jpg", blurb="깨끗한 화이트 어퍼에 검 솔. 어떤 하루에도 가장 먼저 손이 가는 한 켤레.", variants=_sizes("white", "화이트", _SHOE_SIZES)),
    Product("107", "tote", "FORM & FIELD", "formfield", "에센셜 캔버스 토트 네이비", 59000, "bags", "navy", "네이비", ("m", "l"), 8,
            file="tote-navy.jpg", blurb="깊은 네이비 캔버스. 노트북과 텀블러가 넉넉히 들어갑니다.", variants=_sizes("navy", "네이비", _BAG_SIZES)),
    Product("108", "tote", "FORM & FIELD", "formfield", "위켄드 토트 블랙", 79000, "bags", "black", "블랙", ("m", "l"), 2, "NEW",
            file="tote-black.jpg", blurb="1박 2일 짐이 들어가는 큰 사이즈. 블랙 캔버스와 가죽 손잡이.", variants=_sizes("black", "블랙", _BAG_SIZES)),
    Product("109", "headphones", "STILL SOUND", "stillsound", "무선 오버이어 헤드폰 실버", 149000, "tech", "silver", "실버", (), 9,
            file="headphones-silver.jpg", blurb="밝은 실버 마감. 같은 사운드, 다른 인상.", variants=_HEADPHONES),
    Product("110", "headphones", "STILL SOUND", "stillsound", "스튜디오 헤드폰 블루", 199000, "tech", "blue", "블루", (), 10, "PICK",
            file="headphones-blue.jpg", blurb="넓은 무대감의 스튜디오 튜닝. 깊은 블루 컬러.", variants=_HEADPHONES),
    Product("111", "lamp", "ROOM EDIT", "roomedit", "머쉬룸 테이블 램프 세이지", 69000, "home", "sage", "세이지", (), 11,
            file="lamp-sage.jpg", blurb="차분한 세이지 그린. 침실 협탁에 어울리는 은은한 빛.", variants=_MUSHROOM_LAMP),
    Product("112", "lamp", "ROOM EDIT", "roomedit", "머쉬룸 테이블 램프 크림", 69000, "home", "cream", "크림", (), 12,
            file="lamp-cream.jpg", blurb="부드러운 크림 컬러 파우더 코팅. 어떤 공간에도 조용히 스며드는 빛.", variants=_MUSHROOM_LAMP),
)
PRODUCTS_BY_ID = {product.id: product for product in PRODUCTS}
WISHLIST_IDS = ("105", "101", "108", "110", "104", "112")
"""The demo member's saved products, shown on /account/wishlist."""

LISTING_ROUTES = ("/search", "/catalog", "/account/wishlist", "/compare")


PRODUCTS_SCRIPT = "/assets/products.js"
"""The catalog for shop.js as its own script asset.

Keeping product data out of the page HTML means editing a name, price or
option never changes a route's response bytes -- and therefore never moves a
scan's response-size features or the ranking a dashboard is built from.
"""


def products_script() -> bytes:
    rows = [{**asdict(product), "image": product.image} for product in PRODUCTS]
    data = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    return f"window.DEMOSHOP_PRODUCTS = {data};\n".encode("utf-8")


@dataclass(frozen=True, slots=True)
class RouteCopy:
    """What the route's form is called on the page and what it submits."""

    panel: str
    submit: str
    results: str


_DEFAULT_COPY = RouteCopy("조회 조건", "조회하기", "조회 결과")
ROUTE_COPY: dict[str, RouteCopy] = {
    "/search": RouteCopy("검색 조건", "검색", "조건별 조회 응답"),
    "/catalog": RouteCopy("필터", "필터 적용", "조건별 조회 응답"),
    "/product": RouteCopy("옵션 선택", "옵션 적용", "옵션별 조회 응답"),
    "/product/reviews": RouteCopy("리뷰 보기", "리뷰 불러오기", "리뷰"),
    "/product/qna": RouteCopy("문의 검색", "검색", "문의 목록"),
    "/review/new": RouteCopy("리뷰 작성", "미리보기", "미리보기"),
    "/cart": RouteCopy("장바구니 옵션", "장바구니 갱신", "장바구니 조회 응답"),
    "/checkout": RouteCopy("배송 · 결제 정보", "주문 내용 확인", "주문 확인 응답"),
    "/orders": RouteCopy("조회 조건", "주문 조회", "주문 내역"),
    "/order/track": RouteCopy("운송장 조회", "배송 조회", "배송 현황"),
    "/order/invoice": RouteCopy("명세서 선택", "명세서 보기", "거래명세서"),
    "/account/login": RouteCopy("로그인", "로그인 링크 받기", "로그인 안내"),
    "/account/profile": RouteCopy("프로필 편집", "프로필 저장", "공개 프로필 미리보기"),
    "/account/address": RouteCopy("배송지 편집", "배송지 저장", "저장된 배송지"),
    "/account/wishlist": RouteCopy("정렬 · 페이지", "위시리스트 불러오기", "조건별 조회 응답"),
    "/account/points": RouteCopy("조회 조건", "적립금 조회", "적립금 내역"),
    "/support/ticket": RouteCopy("1:1 문의", "문의 보내기", "접수 결과"),
    "/support/faq": RouteCopy("FAQ 검색", "검색", "검색 결과"),
    "/support/chat": RouteCopy("상담 입장", "대기실 입장", "대기 현황"),
    "/seller/dashboard": RouteCopy("지표 선택", "현황 조회", "판매 현황"),
    "/seller/product/edit": RouteCopy("상품 정보", "변경 사항 저장", "저장 결과"),
    "/seller/settlement": RouteCopy("정산 조회", "정산 내역 조회", "정산 내역"),
    "/promo/coupon": RouteCopy("쿠폰 등록", "쿠폰 등록", "쿠폰함"),
    "/promo/event": RouteCopy("이벤트 참여", "참여하기", "참여 결과"),
    "/newsletter": RouteCopy("뉴스레터 구독", "구독하기", "구독 결과"),
    "/blog/post": RouteCopy("댓글 남기기", "댓글 등록", "댓글"),
    "/blog/search": RouteCopy("매거진 검색", "검색", "검색 결과"),
    "/compare": RouteCopy("비교 조건", "비교하기", "조건별 조회 응답"),
    "/store/locator": RouteCopy("매장 검색", "매장 찾기", "가까운 매장"),
    "/api/suggest": RouteCopy("자동완성 요청", "추천 받기", "추천 검색어"),
    "/admin/users": RouteCopy("계정 검색", "계정 찾기", "검색 결과"),
    "/admin/orders": RouteCopy("주문 검색", "주문 조회", "주문 목록"),
}


def route_copy(path: str) -> RouteCopy:
    return ROUTE_COPY.get(path, _DEFAULT_COPY)


CHIPS: dict[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("/search", "min_price"): (("0", "0원"), ("50000", "5만원"), ("100000", "10만원")),
    ("/search", "max_price"): (("100000", "10만원"), ("200000", "20만원"), ("500000", "50만원")),
    ("/catalog", "brand"): (("northpeak", "NORTHPEAK"), ("formfield", "FORM & FIELD"), ("stillsound", "STILL SOUND"), ("roomedit", "ROOM EDIT")),
    ("/catalog", "color"): (("black", "블랙"), ("white", "화이트"), ("sand", "샌드"), ("navy", "네이비")),
    ("/catalog", "sort"): (("newest", "최신순"), ("price_asc", "낮은 가격순"), ("price_desc", "높은 가격순")),
    # The product page's option chips are product-specific and rendered by
    # shop.js from the products script; this server-rendered set is a fixed
    # placeholder around the seed value so the crawled page never changes
    # when the catalog's options do.
    ("/product", "variant"): (("black-270", "블랙 270"), ("black-260", "블랙 260"), ("sand-270", "샌드 270"), ("sand-260", "샌드 260")),
    ("/product/reviews", "rating"): (("5", "★5"), ("4", "★4"), ("3", "★3")),
    ("/review/new", "rating"): (("5", "★5"), ("4", "★4"), ("3", "★3")),
    ("/cart", "coupon"): (("WELCOME10", "WELCOME10"), ("SPRING24", "SPRING24")),
    ("/compare", "ids"): (("101,104", "스니커즈 · 램프"), ("103,110", "헤드폰 둘"), ("101,105,106", "스니커즈 셋")),
    ("/store/locator", "radius"): (("5", "5km"), ("10", "10km"), ("20", "20km")),
    ("/api/suggest", "term"): (("sne", "sne"), ("토트", "토트"), ("램", "램")),
}
"""Quick picks that set a text input's value and submit the form.

They only exist for controls a real site would offer as a chooser; the
canonical control stays a text input with its seed, so the crawl baseline is
unchanged and the probe still types into the box.
"""


def chips(path: str, name: str) -> tuple[tuple[str, str], ...]:
    return CHIPS.get((path, name), ())


def _card(product: Product) -> str:
    badge = f'<span class="product-badge">{product.badge}</span>' if product.badge else ""
    return (
        f'<a class="product-card" href="/product#item-{product.id}" data-product="{product.id}" '
        f'data-category="{product.category}" data-brand="{product.brand_key}" data-color="{product.color}" '
        f'data-sizes="{" ".join(product.sizes)}" data-price="{product.price}" data-rank="{product.rank}" '
        f'data-search="{escape(product.haystack)}">'
        f'<div class="product-photo">{badge}<img src="{product.image}" alt="{escape(product.name)}" '
        f'loading="lazy" width="1024" height="1024"></div>'
        f'<p class="maker">{escape(product.brand)}</p><h3>{escape(product.name)}</h3>'
        f'<p class="price">{product.price:,}<small>원</small></p>'
        f'<p class="shipping">{escape(product.color_label)} · 무료배송</p></a>'
    )


def product_cards(input_of: InputTag = untagged, *, limit: int | None = None) -> str:
    cards = "".join(_card(product) for product in PRODUCTS[:limit])
    return (
        '<div class="product-grid" data-input-of="/product id">'
        + input_of("/product", "id")
        + cards
        + '</div>'
    )


def header(input_of: InputTag = untagged) -> str:
    # The search box is a bare control: no form and no name, so the crawl
    # surface stays the canonical /search form. shop.js turns Enter or the
    # magnifier into /search?q=..., which is that form's first input point.
    return '''<div class="announcement">좋은 취향의 시작, DemoShop &nbsp; · &nbsp; 전 상품 무료배송</div>
<header class="store-header"><div class="header-inner"><a class="wordmark" href="/">DemoShop<span>EVERYDAY, WELL CHOSEN.</span></a>
<div class="search-box" data-input-of="/search q"><input type="search" data-search-input placeholder="어떤 일상을 찾고 있나요?" aria-label="통합 검색" autocomplete="off"><a class="search-go" href="/search" data-search-go aria-label="검색"><b aria-hidden="true">⌕</b></a>''' + input_of("/search", "q") + '''</div>
<div class="header-actions"><a href="/login">마이페이지</a><a href="/login/orders">주문조회</a><a class="cart-link" href="/cart">장바구니 <span>1</span></a></div></div>
<nav class="store-nav" aria-label="쇼핑 메뉴"><a href="/catalog#category-all">전체 상품</a><a href="/catalog#category-shoes">슈즈</a><a href="/catalog#category-bags">가방</a><a href="/catalog#category-tech">디지털</a><a href="/catalog#category-home">홈 & 리빙</a><a class="nav-edit" href="/promo/event">이번 주의 혜택 ↗</a></nav></header>'''


def footer() -> str:
    return '''<footer class="store-footer"><div><a class="wordmark" href="/">DemoShop</a><p>당신의 매일을 조금 더 좋아지게.<br>쓸수록 좋아지는 물건을 소개합니다.</p></div>
<div><strong>고객센터</strong><a href="/support/ticket">1:1 문의</a><a href="/login/orders">주문 및 배송 조회</a><a href="/support/faq">교환 · 반품</a></div>
<div><strong>쇼핑 안내</strong><a href="/catalog#category-all">전체 상품 보기</a><a href="/product/reviews">상품 리뷰</a><a href="/account/profile">내 정보</a></div>
<p class="demo-disclosure">VulnSpider 시연용 가상 쇼핑몰입니다. 상품 사진은 AI 생성 이미지이며, 실제 결제·주문·배송은 이루어지지 않습니다.</p></footer>'''


def home(directory: str, input_of: InputTag = untagged) -> str:
    return '''<section class="hero"><div class="hero-copy"><p class="eyebrow">THE EVERYDAY EDIT / 2026</p><h1>일상에 오래 남을<br>좋은 취향.</h1><p>가볍게 나서는 아침부터 편안히 쉬는 저녁까지.<br>매일 손이 가는 물건들을 만나보세요.</p><a class="button dark" href="/catalog#category-all">컬렉션 둘러보기 <span>↗</span></a><div class="hero-note"><span>01 — 12</span><i></i><span>CURATED FOR YOU</span></div></div>
<a class="hero-visual" href="/product#item-101"><img src="/assets/sneakers.png" alt="따뜻한 샌드 컬러의 데일리 스웨이드 스니커즈" width="1024" height="1024"><span class="hero-sticker">LESS, BUT<br>BETTER.</span><span class="hero-caption">NORTHPEAK · DAILY SUEDE SNEAKERS <b>↗</b></span></a></section>
<div class="benefit-strip"><span><b>01</b> 오래 쓰는 디자인</span><span><b>02</b> 전 상품 무료배송</span><span><b>03</b> 매일 새로운 발견</span></div>
<section class="shop-section"><div class="section-heading"><div><p class="eyebrow">OUR FAVORITES</p><h2>지금, 가장 눈여겨볼 것들</h2></div><a href="/catalog#category-all">전체 상품 보기 ↗</a></div>''' + product_cards(input_of, limit=8) + '''</section>
<section class="editorial"><img src="/assets/lamp.png" alt="따뜻한 빛의 테라코타 테이블 램프" loading="lazy" width="1024" height="1024"><div><p class="eyebrow">A LITTLE CHANGE, A BETTER DAY</p><h2>작은 조명 하나로<br>달라지는 저녁의 분위기.</h2><p>오늘의 공간에 포근한 색과 빛을 더해보세요.</p><a class="text-link" href="/product#item-104">룸 에디트 만나보기 ↗</a></div></section>
<details class="service-directory"><summary>쇼핑 서비스 전체보기 <span>+</span></summary><div class="sections">''' + directory + '</div></details>'


def _breadcrumb(title: str) -> str:
    return f'<div class="breadcrumb"><a href="/">홈</a> / <span>{escape(title)}</span></div>'


def _panel(path: str, blurb: str, form: str) -> str:
    copy = route_copy(path)
    return (
        f'<section class="route-panel"><div class="panel-heading"><h2>{escape(copy.panel)}</h2>'
        f'<p>{escape(blurb)}</p></div>{form}</section>'
    )


def _results(path: str, results: str) -> str:
    copy = route_copy(path)
    return (
        '<section class="route-results" aria-live="polite"><div class="section-heading">'
        f'<div><p class="eyebrow">RESPONSE</p><h2>{escape(copy.results)}</h2></div>'
        '<p class="applied" data-applied></p></div>'
        f'<div class="results">{results}</div></section>'
    )


def _tabs(path: str, input_of: InputTag) -> str:
    return (
        f'<nav class="category-tabs" aria-label="상품 카테고리" data-input-of="{path} category">'
        + input_of(path, "category")
        + '<a href="#category-all" data-filter="all">전체</a><a href="#category-shoes" data-filter="shoes">슈즈</a>'
        '<a href="#category-bags" data-filter="bags">가방</a><a href="#category-tech" data-filter="tech">디지털</a>'
        '<a href="#category-home" data-filter="home">홈 & 리빙</a></nav>'
    )


PAGED_ROUTES = ("/catalog", "/account/wishlist")
"""Listing routes whose form has a canonical ``page`` input; only these page."""


def _pager(path: str, input_of: InputTag) -> str:
    # The pager navigates with the canonical `page` parameter (shop.js merges
    # it into the current query), so it is tagged as that input point.
    if path not in PAGED_ROUTES:
        return ""
    return (
        f'<div class="pager" data-pager data-input-of="{path} page" hidden>'
        + input_of(path, "page")
        + '<button type="button" data-page-step="-1" aria-label="이전 페이지">‹</button>'
        '<span data-pager-pages></span>'
        '<button type="button" data-page-step="1" aria-label="다음 페이지">›</button></div>'
    )


_EMPTY = '<p class="search-empty" data-search-empty hidden>일치하는 상품이 없습니다. 다른 조건을 입력해 보세요.</p>'


def _listing(path: str, title: str, blurb: str, form: str, input_of: InputTag) -> str:
    if path in ("/catalog", "/search"):
        heading = (
            '<div class="collection-title"><p class="eyebrow">THE COLLECTION</p><h1 data-search-heading>일상을 위한 좋은 선택</h1>'
            '<p data-search-note>취향에 맞는 물건을 천천히 골라보세요.</p></div>' + _tabs(path, input_of)
        )
    elif path == "/account/wishlist":
        heading = (
            '<div class="collection-title"><p class="eyebrow">MY WISHLIST</p><h1 data-search-heading>찜한 상품</h1>'
            f'<p data-search-note>{escape(blurb)}</p></div>'
        )
    else:
        heading = (
            '<div class="collection-title"><p class="eyebrow">COMPARE</p><h1 data-search-heading>상품 비교</h1>'
            f'<p data-search-note>{escape(blurb)}</p></div>'
        )
    filter_bar = f'<section class="filter-bar"><p class="filter-state" data-filter-state></p>{form}</section>'
    compare = '<div class="compare-table" data-compare hidden></div>' if path == "/compare" else ""
    return heading + filter_bar + product_cards(input_of) + _EMPTY + _pager(path, input_of) + compare


def _product_detail(form: str, input_of: InputTag) -> str:
    first = PRODUCTS[0]
    return (
        '<section class="product-detail"><div class="detail-photo">'
        f'<img data-product-image src="/assets/{first.photo}.png" alt="{escape(first.name)}" width="1024" height="1024"></div>'
        f'<div class="product-info"><p class="eyebrow" data-product-brand>{escape(first.brand)}</p><h1 data-product-name>{escape(first.name)}</h1>'
        f'<p class="product-description" data-product-description>{escape(first.blurb)}</p>'
        f'<p class="detail-price"><span data-product-price>{first.price:,}</span><small>원</small>'
        '<span class="variant-chip">선택 옵션 <b data-variant>black-270</b></span></p>'
        '<div class="delivery-info"><p><span>배송</span>무료배송 · 일반 배송</p><p><span>안내</span>사진과 상품 정보는 시연용입니다.</p></div>'
        f'<div class="option-panel">{form}</div>'
        '<div class="purchase-total"><span>총 상품 금액 <small data-qty-note></small></span><strong><span data-total>89,000</span>원</strong></div>'
        '<div class="purchase-actions"><a class="button outline" data-cart href="/cart#item-101-1">장바구니 담기</a>'
        '<a class="button dark" data-checkout href="/checkout#item-101-1">바로 구매</a></div>'
        '<p class="microcopy">결제 없이 구매 과정을 체험할 수 있습니다.</p></div></section>'
        '<section class="detail-tabs" data-input-of="/product tab">' + input_of("/product", "tab") +
        '<div class="tab-bar" role="tablist"><button type="button" role="tab" data-tab="detail">상세 설명</button>'
        '<button type="button" role="tab" data-tab="spec">제품 사양</button><button type="button" role="tab" data-tab="ship">배송 · 교환</button></div>'
        '<div class="tab-panel" data-tab-panel="detail"><h3>상세 설명</h3><p data-product-description>' + escape(first.blurb) + '</p>'
        '<p>매일 손이 가는 물건은 오래 봐도 질리지 않아야 합니다. 과한 장식 대신 좋은 소재와 편안한 형태에 집중했습니다.</p></div>'
        '<div class="tab-panel" data-tab-panel="spec" hidden><h3>제품 사양</h3><table class="spec"><tr><th>브랜드</th><td data-product-brand></td></tr>'
        '<tr><th>컬러</th><td data-product-color></td></tr><tr><th>사이즈</th><td data-product-sizes></td></tr>'
        '<tr><th>카테고리</th><td data-product-category></td></tr><tr><th>상품 번호</th><td data-product-id></td></tr></table></div>'
        '<div class="tab-panel" data-tab-panel="ship" hidden><h3>배송 · 교환</h3><p>전 상품 무료배송, 평일 오후 2시 이전 주문은 당일 출고됩니다.</p>'
        '<p>수령 후 7일 이내 교환·반품이 가능합니다. 시연용 안내이며 실제 배송은 이루어지지 않습니다.</p></div></section>'
    )


def _cart(form: str, input_of: InputTag) -> str:
    first = PRODUCTS[0]
    return (
        '<div class="collection-title"><p class="eyebrow">YOUR SELECTION</p><h1>장바구니</h1>'
        '<p>장바구니 <span aria-hidden="true">→</span> 주문 확인 <span aria-hidden="true">→</span> 시연 완료</p></div>'
        '<div class="cart-layout"><section class="cart-product">'
        f'<img data-product-image src="/assets/{first.photo}.png" alt="{escape(first.name)}" width="1024" height="1024">'
        f'<div><p class="eyebrow" data-product-brand>{escape(first.brand)}</p><h2 data-product-name>{escape(first.name)}</h2>'
        f'<p><span data-product-price>{first.price:,}</span>원 · 무료배송 · 항목 <b data-item-id>5521</b></p>'
        f'<div class="option-panel">{form}</div>'
        '<a class="text-link" href="/catalog#category-all">계속 쇼핑하기 ↗</a></div></section>'
        '<aside class="order-summary"><h2>주문 예상 금액</h2>'
        '<p><span>상품 금액 <small data-qty-note></small></span><span><span data-subtotal>89,000</span>원</span></p>'
        '<p><span>쿠폰 할인 <small data-coupon-note></small></span><span>-<span data-discount>0</span>원</span></p>'
        '<p><span>배송비</span><span>무료</span></p>'
        '<p class="memo"><span>배송 메모</span><span data-note-echo></span></p>'
        '<div class="purchase-total"><span>총 결제 금액</span><strong><span data-total>89,000</span>원</strong></div>'
        '<a class="button dark" data-checkout href="/checkout#item-101-1">주문하기 ↗</a>'
        '<p class="microcopy">시연용 · 실제 결제가 발생하지 않습니다.</p></aside></div>'
    )


def _checkout(form: str) -> str:
    first = PRODUCTS[0]
    return (
        '<div class="collection-title"><p class="eyebrow">YOUR SELECTION</p><h1>주문 / 결제</h1>'
        '<p>장바구니 <span aria-hidden="true">→</span> 주문 확인 <span aria-hidden="true">→</span> 시연 완료</p></div>'
        '<div class="cart-layout"><section class="cart-product">'
        f'<img data-product-image src="/assets/{first.photo}.png" alt="{escape(first.name)}" width="1024" height="1024">'
        f'<div><p class="eyebrow" data-product-brand>{escape(first.brand)}</p><h2 data-product-name>{escape(first.name)}</h2>'
        f'<p><span data-product-price>{first.price:,}</span>원 × <b data-quantity-echo>1</b>개</p>'
        f'<div class="option-panel">{form}</div></div></section>'
        '<aside class="order-summary"><h2>주문 예상 금액</h2>'
        '<p><span>상품 금액</span><span><span data-subtotal>89,000</span>원</span></p>'
        '<p><span>배송비 <small data-shipping-note></small></span><span><span data-shipping-fee>무료</span></span></p>'
        '<p><span>결제 수단</span><span data-payment-echo></span></p>'
        '<p class="memo"><span>요청사항</span><span data-message-echo></span></p>'
        '<p class="memo"><span>주문 참조</span><span data-order-ref></span></p>'
        '<div class="purchase-total"><span>총 결제 금액</span><strong><span data-total>89,000</span>원</strong></div>'
        '<button class="button dark" type="button" data-place-order>주문 시연 완료하기</button>'
        '<p class="microcopy">시연용 · 실제 결제가 발생하지 않습니다.</p></aside></div>'
        '<div class="order-success" data-order-success role="status" hidden><h2>주문 과정을 모두 체험했어요.</h2>'
        '<p>실제 주문이나 결제는 발생하지 않았습니다. 다른 상품도 둘러보세요.</p>'
        '<a class="button dark" href="/catalog#category-all">쇼핑 계속하기 ↗</a></div>'
    )


def route_body(
    path: str,
    title: str,
    blurb: str,
    form: str,
    results: str,
    input_of: InputTag = untagged,
) -> str:
    """Lay out one route: the canonical form where a real site would put it.

    ``form`` is the route's GET form as rendered by ``demo_shop`` (unchanged),
    ``results`` the server's per-parameter response cards.
    """

    crumb = _breadcrumb(title)
    if path == "/orders":
        crumb += (
            '<section class="member-order"><h2>내 주문 조회</h2>'
            '<p>로그인하면 주문자, 상품, 결제금액을 확인할 수 있습니다.</p>'
            '<a class="button dark" href="/login/orders">로그인하고 주문 조회</a></section>'
        )
    if path in LISTING_ROUTES:
        return crumb + _listing(path, title, blurb, form, input_of) + _results(path, results)
    if path == "/product":
        return crumb + _product_detail(form, input_of) + _results(path, results)
    if path == "/cart":
        return crumb + _cart(form, input_of) + _results(path, results)
    if path == "/checkout":
        return crumb + _checkout(form) + _results(path, results)
    return (
        crumb
        + f'<div class="collection-title"><p class="eyebrow">DEMOSHOP SERVICES</p><h1>{escape(title)}</h1></div>'
        + _panel(path, blurb, form)
        + _results(path, results)
    )
