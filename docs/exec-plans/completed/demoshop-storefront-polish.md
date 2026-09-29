# DemoShop storefront and report terminology

## Goal
Use the user-requested report labels and present DemoShop as a convincing
Korean lifestyle storefront with locally bundled product photography.

## Non-Goals
No real payments, accounts, persistent carts, changed scanner scope, scoring,
verification rules, canonical input schema, vulnerability labels or payloads.

## Context Read
- AGENTS.md, README_START_HERE.md, PLANS.md, CODE_REVIEW.md
- Previously read architecture/domain/feature/evaluation/Git documents
- tools/demo_shop.py, tests/unit/test_demo_shop.py
- reporting/dashboard_* and decision_html_report.py
- docs/exec-plans/active/demo-shop-and-live-evaluation.md
- imagegen SKILL.md

## Current State
Prior report redesign is present as uncommitted work. DemoShop still has plain
navigation lists, placeholder product blocks, and no product photography.

## Proposed Changes
1. Label the summary "상위 취약점 후보" and all headline scores "최종 신뢰도".
   Keep source explanations: an unverified candidate retains its calibrated prior.
2. Add a warm editorial storefront shell, home/catalog/product/cart/checkout
   presentation, existing-route navigation and bounded in-page interactions.
3. Bundle four ImageGen product photos. Serve only exact allowlisted local assets.
4. Preserve existing forms, seeds, probe fragments, HTTP outcomes and ground truth;
   validate the actual crawl and update docs about changed response-size baselines.

## Interfaces / Data Changes
Presentation labels only; no score/model/JSON changes. New demo presentation
module and exact static asset routes; no scanner transport changes.

## Safety / Scope Impact
Loopback binding and GET-only target behavior retained. Asset lookups use fixed
paths, never join request text to filesystem paths. Cart/checkout simulations
use URL fragments and DOM only; no storage, payment or order mutation.

## Test Plan
- Report labels with and without verification; unchanged numerical values
- Existing DemoShop ground-truth/form/status tests; static asset routing negatives
- Native crawl still finds 100 canonical input points
- Desktop/mobile shopping navigation and image load QA
- Narrow/full tests, format/lint/types/diff checks, independent Gate Review

## Acceptance Criteria
- [x] Report labels match request, with truthful provenance.
- [x] Home and shopping flow use local product images and responsive UI.
- [x] Existing labeled input surface and behavior are preserved.
- [x] Full checks and independent Gate Review pass.

## Progress Log
- 2026-09-13: Inspected current report/storefront and generated four product photos.
- Implemented the storefront shell, four product cards, product detail, quantity,
  cart/checkout simulation, category filtering and local asset allowlist.
- Narrow report/storefront tests passed (39 tests). A broader 61-test run found
  one obsolete chart-title assertion; updated it for the requested terminology
  and reran the affected test successfully.
- Static checks (format/lint/type hints/diff whitespace) passed.
- Real static analyze + verification completed: 33 endpoints, 100 input points,
  200 scored candidates, 12 selected; preview reports regenerated under build/.
- Browser QA: desktop home and tote quantity 2 -> cart -> checkout (118,000 won)
  -> simulated completion passed. Mobile 390px home/product had no horizontal
  overflow; Home & Living category displayed the lamp; local photos loaded.
- Full suite passed: 989 tests in 260.444 seconds. Initial independent review
  reached PASS WITH MINOR for category/query UI synchronization.
- Fixed that minor: accepted category query values and fragment selections stay
  aligned. Explicit all-category browsing omits only a category control without
  an existing all option; default search's all option stays enabled. Bare crawl
  forms retain their original active controls and options.
- Browser regression QA passed: home category -> all -> submit kept four products;
  home category -> submit kept only the lamp and category=home. Bare /search
  retained its visible, enabled category=all control. Final report overview
  displayed the new terminology and 33/100/200/12 counts.
- After the review fix, 39 affected tests passed, then 23 storefront tests passed
  after the search-default correction. All static checks passed again.
- Final independent Gate Review: APPROVE / PASS, with no remaining findings.

## Decision Log
- Report "final confidence" is a user-facing label for the currently available
  probability, not a new VerificationConfidence record. An unverified value is
  explicitly described as unchanged from the pre-verification probability.
- Preserve bare crawler links; client presentation choices use fragments.

## Open Questions
- None.
