# DemoShop input points as the storefront's own UI

## Goal
Every one of the 100 canonical input points is a visible control the audience
can use on the page (not a form tucked in a collapsed section), and the page
visibly reacts to the submitted values. The parameter surface, seeds, form
methods/actions, response behaviors and ground truth stay byte-for-byte the
evaluation surface they are today.

## Non-Goals
No new parameters, routes, links with query strings, vulnerability labels or
server-side state. No new image assets: product variants are CSS filters on
the four bundled photos.

## Context Read
- AGENTS.md, PLANS.md, demoshop-input-markers.md, demoshop-reveal-mode-and-search.md
- tools/demo_shop.py (`_control`, `_filter_form`, `render_route`, `_fragment`)
- tools/demo_shop_storefront.py, shop.css, shop.js, tests for the storefront

## Current State
Each route renders its canonical GET form inside `<details class="route-options">`
("선택한 조건과 상세 정보") with a generic "적용" button and the server's per
parameter response cards in a nested collapsed details. Only `q` and
`category` affect the visible product grid; the catalog has four products, so
brand/color/size/sort/page have nothing visible to act on.

## Proposed Changes
1. The canonical form becomes the page's primary panel: heading, route copy,
   contextual submit label, always open. Product routes render it as a filter
   bar above the grid; product/cart/checkout embed it in the product info,
   cart line and order form; every other route renders it as the service form.
2. The server's response cards render in a visible "조회 결과" panel below the
   form; error/warn cards are styled as banners.
3. Catalog grows to 12 products (4 photos × CSS colour variants) with brand,
   colour, sizes, price and recency attributes. shop.js filters, sorts and
   pages the grid from the URL query on /search, /catalog, /account/wishlist
   and /compare; a pager and sort chips set the canonical `page`/`sort` text
   inputs and submit the form.
4. Product page: `id` selects the product, `variant` is shown as the chosen
   option, `tab` switches detail/spec/ship panels, `qty` (the canonical text
   input) drives the total and the cart/checkout links. Cart: `qty`, `coupon`,
   `note` are reflected in the order summary. The presentation-only quantity
   selects are removed in favour of the canonical inputs.
5. A generic "적용된 조건" strip lists the submitted values on every route.
6. Reveal mode, markers, tooltips and the header search keep working.

## Interfaces / Data Changes
Presentation only. `storefront` gains route copy (submit label, results title,
chips), the product table and `route_body(...)`; `_control` gains `chips`.

## Safety / Scope Impact
Chips, pager and tab buttons are `type="button"` with no name. Product data
reaches the page as a JSON script block (never parsed for URLs). No link
carries a query string. Verified by the existing storefront contract tests and
a real scan after the change.

## Test Plan
- Storefront contract tests (unique markers, no named presentation controls,
  no query links, 100 inputs, ground truth) plus new checks: route copy for
  every path, chip buttons unnamed, 12 product cards, JSON block present
- Static checks; real scan: endpoints=33, input_points=100, 200 candidates
- Browser QA: catalog filter/sort/page, product tabs/qty/variant, cart
  coupon/qty, service form + results, reveal mode, 390px

## Acceptance Criteria
- [x] All 100 controls are visible page UI with a contextual submit action.
- [x] Catalog/search/product/cart visibly react to the parameters.
- [x] Crawl surface, seeds, forms, response behaviors and ground truth unchanged.
- [x] Tests, static checks and a real scan pass.

## Progress Log
- 2026-09-15: Plan written after the user asked that hidden-in-HTML inputs
  (sort, page, …) become real storefront controls.
- 2026-09-15: Implemented `route_body` layouts, the 12-product catalog with
  CSS tints, chips, pager, product tabs, cart/checkout summaries, the visible
  results section and the "적용된 조건" strip. Storefront tests extended
  (route copy for every path, unnamed buttons, 12 cards, JSON block, seeds
  match a product). 35 targeted tests, format/lint/type checks passed.
  Real scan: endpoints=33, input_points=100, 200 candidates. The no-verify
  ranking moved slightly (P@20 0.75→0.80) because every route's HTML grew,
  which shifts the response-size baseline; behaviors per parameter are
  unchanged, so `docs/results/demoshop` should be regenerated with the new
  target revision before quoting numbers.
  Browser QA: catalog seeds→1 product, page=2, bags sorted by price, `brand='`
  → red database-error banner; product `#item-110-2` → blue variant, tabs,
  qty validation; cart coupon/qty/note; checkout express fee; wishlist and
  compare; reveal on/off; 375px without horizontal overflow.

- 2026-09-15 (follow-up): the CSS `filter` tints coloured the whole photo,
  so the eight variants are now real assets produced by
  `tools/demo_shop_assets/make_variants.py` (GrabCut product mask, HLS
  recolour, background untouched; ~830 KB total). The pager is always shown on
  `/catalog` and `/account/wishlist` (the routes with a canonical `page`) and
  carries the `⊙ #011 페이지 page` tag; `/search` and `/compare` no longer
  page. Reveal outlines are 3px and extend to chips, pager and tab buttons.
- 2026-09-16: Olive sneakers redone — GrabCut mask extended by a floor-
  difference test (toe caps), smooth/dim/neutral floor dropped from the rim,
  Lab chroma pull instead of HLS colourise so texture survives, gum sole kept
  via a chroma-based soft weight closed vertically. `variant` chips are now
  per product (`Product.variants`, swapped by shop.js; the product page also
  re-applies `#item-` on hashchange for the "함께 본 상품" links).
- 2026-09-16: The olive colourway never looked like a product photo, so 106
  is now "코트 스니커즈 화이트": the upper is pulled to white in Lab (chroma
  removed, lightness lifted, grain kept) over the gum sole.
- 2026-09-16: GrabCut kept painting the floor shadow and leaving holes, so
  the matte now comes from `rembg` (U²-Net; ISNet for the tote). All eight
  variants regenerated: no floor or shadow tint, no holes, tote handle loops
  open, both sneakers keep the gum sole. The generator documents an isolated
  venv; rembg is not a DemoShop dependency.
- 2026-09-16: Options are colour-matched (shoes: own colour × 250–280,
  bags: own colour × M/L, headphones and lamps: the model's colours) and
  product data moved out of the HTML into `/assets/products.js`. Measured
  why: the ranking is deterministic for identical responses but a few KB of
  HTML shifts probabilities at the third decimal and swaps near-tied ranks
  (P@20 flips between 0.75 and 0.80 across today's storefront revisions and
  the 2026-08-30 results pack). With product data out of the page, catalog
  edits no longer touch the crawled bytes: two scans before/after a
  product-data edit were identical.

## Decision Log
- Decision: grid filters from the URL query, not from the form's default
  values. Reason: seeds are the crawler's baselines and must stay in the
  controls, but a bare landing page should show the whole catalog; the panel
  shows "적용 전/적용됨" so the state is explicit.
- Decision: colour variants as recoloured JPEG assets (product only), not
  CSS `filter`. Reason: a filter tints the background too and looked crude;
  GrabCut-masked recolouring keeps the studio backdrop and costs ~100 KB each.

## Open Questions
- None.
