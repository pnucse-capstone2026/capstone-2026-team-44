# DemoShop reveal mode and working header search

## Goal
Make the 100 canonical input points obvious during a demonstration without
changing what a crawl finds, and make the storefront's header search behave
like a real search instead of a static link.

## Non-Goals
No new input points, forms, routes, vulnerability labels, seeds, probe
behavior or scanner changes. No server-side search state.

## Context Read
- AGENTS.md, PLANS.md, docs/exec-plans/completed/demoshop-input-markers.md
- tools/demo_shop.py, tools/demo_shop_storefront.py, shop.css, shop.js
- discovery/html_extractor.py (controls outside a form are warned, not bound)
- discovery/static_crawler.py (`_merge_input_points`: a second form for the
  same parameter would merge baselines, so the search box must not be a form)

## Current State
Markers were subtle (22px ⊙ next to a label) and lived only inside each
route's "선택한 조건과 상세 정보" section, closed by default on product, cart
and checkout. The header search was `<a href="/search">`; category tabs,
product cards and quantity selectors were client-only fragments with no visible
link to the parameter they end up in.

## Proposed Changes
1. A fixed "⊙ 입력점 표시" pill toggles `html.reveal-inputs`, persisted in
   `localStorage`; an inline head script restores it before first paint.
2. In reveal mode: solid outline + number badge on every canonical control,
   the conditions section opens, hidden-input notes are outlined, and the
   tooltip also shows the request shape (`GET /search?q=…`).
3. Storefront controls that feed a canonical parameter carry
   `data-input-of="<path> <name>"` and a static `⊙ #NNN label name` tag
   rendered by `demo_shop._input_of` from `INPUT_POINT_NUMBERS`: header search
   → `/search q`, category tabs → `category` of the current route, product grid
   → `/product id`, quantity → `/product qty` and `/cart qty`.
4. Header search is a bare `<input type="search">` (no form, no name). Enter
   or the magnifier navigates to `/search?q=<term>`; the term prefills the box,
   filters the product grid on the client and updates the heading.

## Interfaces / Data Changes
Presentation only. `storefront.header/home/route_intro/product_cards` take an
`input_of` renderer; `_layout` takes `input_count`; `_control` takes `path`.

## Safety / Scope Impact
The crawl surface is unchanged: a real scan still finds 33 endpoints and 100
input points with 200 scored candidates and an identical no-verify ranking.
The only discovery difference is one more `FORM_CONTROL_OUTSIDE_FORM` warning
for the search box. Tags and tooltips contain static labels, names and the
request shape, never verdicts or ground truth.

## Test Plan
- Existing marker/storefront/ground-truth tests (25) and dashboard story tests
- Static format/lint/type checks
- Real scan against the modified target: endpoint and input-point counts
- Browser QA: reveal on/off, tags on search/tabs/grid/quantity, hidden input,
  product/cart form sync from `#item-` fragments, header search round trip,
  390px layout without horizontal overflow

## Acceptance Criteria
- [x] Reveal mode makes every canonical control and its feeding UI obvious.
- [x] Header search opens `/search?q=` and narrows the visible products.
- [x] Crawl surface, seeds, forms and ground truth unchanged (scan verified).
- [x] Tests and static checks pass.

## Progress Log
- 2026-09-15: Implemented reveal pill, tags, tooltip request shape, working
  search and cart qty sync. 32 targeted tests passed; format/lint/type checks
  passed; scan found endpoints=33, input_points=100, 200 candidates, same
  no-verify ranking as the previous run.

## Decision Log
- Decision: the search box is not a `<form>`. Reason: a second form for
  `/search q` merges into the same InputPoint with an extra baseline value and
  a template lacking the other four parameters, changing the evaluation surface.
- Decision: reveal mode is off by default and persisted. Reason: the storefront
  should first read as a real shop; the toggle is the demo beat.

## Open Questions
- None.
