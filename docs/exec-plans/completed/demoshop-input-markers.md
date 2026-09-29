# DemoShop input-point markers and publication

## Goal
Make the existing attack surface easy to identify during demonstrations and
publish the dashboard/storefront work on `feat/dashboard-improve`.

## Non-Goals
No new input points, vulnerability labels, score reconstruction, probe behavior,
external target scope or real shopping transactions.

## Context Read
- AGENTS.md, PLANS.md, CODE_REVIEW.md, docs/GIT_WORKFLOW.md
- Previous dashboard/storefront completed plans and ADR-041/042
- tools/demo_shop.py, storefront assets and related tests

## Current State
The redesigned storefront retains 100 canonical query input points across 32
routes; a real scan confirms 33 endpoints including the entry page. Existing
ground-truth and vulnerable/safe behavior tests pass. Forms are available through
the route's conditions/details area but their input identities are not visible.

## Proposed Changes
1. Assign stable display numbers 001–100 from the canonical PAGES/input order.
2. Add subtle hover/focus markers to actual canonical controls, including hidden
   input annotations, and a shortcut that reveals each route's input section.
3. Preserve names, seeds, form methods/actions and all _fragment behavior.
4. Test, independently review, commit and push the requested branch without
   tool attribution or contribution trailers.

## Interfaces / Data Changes
Demo presentation only. Display numbers are local to the authored target, not
scanner InputPoint IDs and not a new domain or JSON contract.

## Safety / Scope Impact
No scope changes. Marker controls are non-submitting buttons with no names.
Tooltips contain static canonical labels/names, never vulnerability verdicts or
ground truth. Generated scan artifacts remain ignored.

## Test Plan
- Exactly one unique marker per canonical point; unchanged names/defaults
- Keyboard/focus and hover tooltip behavior; hidden input annotation
- Real scan still discovers 100 input points
- Narrow/full tests, static checks and independent Gate Review
- Verify remote branch commit after push

## Acceptance Criteria
- [x] All canonical inputs have stable, accessible, unobtrusive markers.
- [x] Canonical input surface and probe behavior remain intact.
- [x] Tests, static checks and independent Gate Review pass.
- [x] Requested branch and reviewed changes are ready for authorized publication.

## Progress Log
- 2026-09-13: Reconfirmed the 100-point surface and renamed the working branch.
- Added numbered hover/focus markers, hidden-field annotations and a form
  shortcut that preserves the current product/quantity fragment.
- Narrow tests passed: 25 tests, including all 100 unique marker numbers and
  unchanged hidden input types. Static format/lint/type-hint checks passed.
- Real scan passed: 33 endpoints, 100 input points, 200 scored candidates.
- Browser QA passed: desktop marker focus, mobile 390px tooltips without
  horizontal overflow, selected lamp id=104 and qty=2 retained on reveal.
- Independent Gate Review: APPROVE / PASS with no findings.
- Full suite passed: 991 tests in 295.764 seconds.
- Compared canonical definitions with the prior committed target: PAGES,
  InputSpec, seed helpers, _fragment, ground-truth construction, loopback binding
  and authenticated route behavior were unchanged.
- Reviewed the staged source, bundled photos, tests and documentation. Publication
  is the final Git operation; the remote commit SHA is recorded in the delivery
  message rather than embedded recursively in this plan.

## Decision Log
- Marker identity uses authored order and is separate from scanner-generated IDs.
- Existing historical repository setup documentation is outside this change;
  new content and commit text do not include tool contribution attribution.

## Open Questions
- None.
