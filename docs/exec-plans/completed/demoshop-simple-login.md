# DemoShop simple member login

## Goal
Connect storefront My Page to a one-button login as `soohoon`, a real demo
session, and an understandable own-order / other-member-order BAC example.

## Non-Goals
- Production authentication, account creation, real orders or payments.
- Scanner login automation, scoring changes, or changes to frozen v0.1.
- Removal of the public 100-input evaluation fixtures or existing user edits.

## Context Read
- AGENTS.md, README_START_HERE.md, PLANS.md, CODE_REVIEW.md
- docs/ARCHITECTURE.md, docs/PROTOTYPE_V0_1.md, docs/PROTOTYPE_V0_2.md
- docs/TEAM_INTERFACES_V0_2.md, docs/GIT_WORKFLOW.md
- docs/EVALUATION_PROTOCOL.md, docs/DECISION_LOG.md (ADR-037)
- tools/demo_shop.py, tools/demo_shop_storefront.py, tests/unit/test_demo_shop*.py

## Initial State
The header links to the public `/account/login` injection fixture. Actual demo
sessions already exist at `/login?as=admin|user`, with protected `/portal/`
resources, but neither a simple shopper login nor a named order comparison.
Existing uncommitted changes rename the demo member and add public order leak
examples; preserve them.

## Implemented Changes
1. Added a GET login screen and explicit POST login/logout actions. Redirects use
   fixed local destinations; login issues the existing `user` role (uid 1042).
2. Added the member profile and own order to My Page. Preserved the lookup `ref`
   parameter; 4100 displays `soohoon` and 4101 displays `sanghyun` with order details.
3. Preserved the public fixture and legacy explicit role-login compatibility.
4. Documented the manual demo in README and ADR-043; added HTTP session tests.

## Interfaces / Data Changes
Only the loopback target UI/HTTP routes change. Existing session token format,
canonical input names, labels, and scanner contracts remain intact. Public
navigation additionally visits the parameter-free GET `/login` page.

## Safety / Scope Impact
Login/logout are explicit human POST actions which only set/clear a demo cookie.
GET `/login` does not authenticate. Anonymous protected resources still return
403; intentional IDOR and ownership-checked negative control stay in place.
No scanner transport, scope grants, payload execution or external requests change.

## Test Plan
- HTTP: anonymous login, fixed-user POST, cookie persistence, My Page, own/other
  orders, tampered cookie, logout, unknown POST, fixed redirects, legacy roles.
- Contracts: public 100 inputs/ground truth, IDOR 200 and safe-card 403.
- Browser: desktop/mobile flow and order-number edit.
- Full unittest, format, lint, types, diff check and independent Gate Review.

## Acceptance Criteria
- [x] My Page → one-button soohoon login → member profile / own order.
- [x] Same session can query 4101 and visibly show sanghyun's order.
- [x] Logout clears browser session; anonymous resources stay protected.
- [x] Public fixture contracts and existing local changes are preserved.
- [x] Required checks and independent review pass; docs match implementation.

## Progress Log
- 2026-09-21: Inspected the existing login, session and order lookup behavior.
- 2026-09-21: Implemented member login/logout and named order ownership display.
  Narrow suite: 44 tests PASS. Format, lint, type hints, and diff checks PASS.
  Two independent Gate Reviews both PASS;
  additional manual malformed/nonempty POST checks confirmed rejection.
- 2026-09-21: Live anonymous static crawl: 34 visited pages, 35 endpoints (new
  GET/empty POST login endpoints), exactly 100 input points, no portal endpoints
  and no session cookies. Committed ground truth remains unchanged.
- 2026-09-21: Browser QA on loopback preview port 8900 passed: My Page, login,
  persistent soohoon identity across 4100/4101 lookup, logout, anonymous403;
  desktop 1280 and mobile 390 layouts checked, no mobile horizontal overflow or
  JavaScript errors.
- 2026-09-21: Full verification complete: `python -B -m unittest discover -s
  tests` ran 1,031 tests in 245 seconds, all PASS. `python tools/check_format.py`,
  `python tools/check_lint.py`, `python tools/check_types.py`, and
  `git diff --check` PASS. Both independent Gate Reviews PASS. Plan completed.

## Decision Log
- Reuse existing authenticated portal and user role; preserve public evaluation
  fixture separately so a shopper login does not alter the labeled input model.
- Keep scanner token/role helpers compatible; expose no token on shopper screens.

## Open Questions
- None.
