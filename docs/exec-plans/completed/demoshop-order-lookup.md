# DemoShop member order lookup navigation

## Goal
Make the storefront 주문조회 menu display the authenticated member order lookup,
including the same-session 4100/4101 BAC demonstration.

## Non-Goals
Change the scanner, public 100-input fixture labels, session token format, or
actual purchase state.

## Context Read
- AGENTS.md, PLANS.md, CODE_REVIEW.md, docs/GIT_WORKFLOW.md
- README_START_HERE.md, docs/DECISION_LOG.md (ADR-037/043)
- docs/exec-plans/completed/demoshop-simple-login.md
- tools/demo_shop.py, tools/demo_shop_storefront.py, DemoShop tests

## Initial State
Header/footer 주문조회 links still open `/orders`, a public injection fixture
whose results are generic rows. Actual order records live at `/portal/order`.

## Implemented Changes
1. Added a parameter-free `/login/orders` entry: anonymous GET shows the existing
   one-button profile login; explicit POST logs in and redirects to the fixed
   `/portal/order` route. Signed-in GET goes straight there.
2. Pointed shopper order links to this entry. Kept `/orders` in the discovery
   directory with a member-order call to action for anonymous visitors.
3. Signed-in visits to legacy `/orders` now redirect to `/portal/order?ref=...`,
   carrying the entered order number with URL encoding. Map the old examples
   20240517/20240518 to 4100/4101. Anonymous fixture responses remain unchanged.

## Interfaces / Data Changes
Target-only GET/POST entry; no named inputs. The public evaluation fixture is
anonymous, and the existing authenticated portal owns member order records.

## Safety / Scope Impact
Fixed local destinations; no automatic authentication on GET. Keep loopback-only
binding, explicit POST login, missing/forged-session403 and safe-card403 behavior.
Authenticated `/orders` is a redirect alias, not a second BAC data endpoint.

## Test Plan
- Header/footer order entry, anonymous login and no cookies on GET.
- Explicit login to order lookup, same-session 4100/4101 records.
- Authenticated legacy order numbers/escaped query forwarding; anonymous fixture
  input contract and SQLi behavior; direct unauthenticated portal denied.
- Full unittest + format/lint/types/diff, independent Gate Review, browser QA.

## Acceptance Criteria
- [x] 주문조회 opens actual member order lookup before/after login.
- [x] Entered order numbers change displayed owner/product/amount.
- [x] Existing public 100-input labels remain compatible.
- [x] Checks, Gate Review and preview restart complete.

## Progress Log
- 2026-09-21: Reproduced route mismatch from source; design selected.
- 2026-09-21: Implemented and narrow tests 49 PASS; format, lint, types and
  diff checks PASS. Independent Gate Review: PASS, no findings.
- 2026-09-21: Started updated preview on 127.0.0.1:8900. Browser flow passed:
  home 주문조회 → login → own order4100 → other order4101; header re-entry while
  signed in returns to own order; legacy20240518 URL reaches order4101. No JS
  errors. Anonymous live crawl: 35 pages, 37 endpoints, exactly100 input points,
  no portal endpoint or session cookie.
- 2026-09-21: Full `python -B -m unittest discover -s tests`: 1,036 tests PASS
  in 234 seconds. `python tools/check_format.py`, `python tools/check_lint.py`,
  `python tools/check_types.py`, and `git diff --check` PASS. Gate Review PASS.
  Implementation and verification complete.

## Decision Log
- Reuse the protected order endpoint rather than duplicate its data renderer.
- Use a fixed path for login intent instead of arbitrary return URL parameters.

## Open Questions
- None.
