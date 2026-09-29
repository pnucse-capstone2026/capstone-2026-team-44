# Dashboard demonstration story

## Goal
Show the analysis journey, before/after confidence, and recognizable input names.

## Non-Goals
No scoring, selection, crawler, network, payload, or ground-truth changes.

## Context Read
- AGENTS.md, PLANS.md, CODE_REVIEW.md, docs/GIT_WORKFLOW.md
- docs/ARCHITECTURE.md, docs/TEAM_INTERFACES_V0_2.md, ADR-041/042
- Dashboard renderer, verification evidence, DemoShop numbered controls

## Current State
The overview has separate counts and an ownership map. Confidence comparisons
and source details require navigating into individual candidates.

## Proposed Changes
1. Connect authoritative counts in a numbered analysis journey, without implying
   a common denominator or that candidate counts are confirmed vulnerabilities.
2. Show the first three representatives with supplied prior/final values and
   verification signal explanations, including missing/unchanged results.
3. Read DemoShop captions/numbers from the candidate's existing baseline response
   and matching GET form. Fall back on canonical names for ambiguous/missing data.

## Interfaces / Data Changes
Private HTML presentation projections only. No public or JSON contract changes.
Source labels remain descriptive annotations, never identities or score inputs.

## Safety / Scope Impact
No new requests or dependencies. Escape response-derived captions. No target
imports or ground-truth access. Preserve offline HTML and existing CSP.

## Test Plan
- Counts, prior/final provenance, missing and weakened verification
- Exact baseline/input attribution; duplicate/wrong-form/escaped captions
- Existing dashboard/report tests, full checks, independent Gate Review
- Offline fixture preview; desktop/mobile browser and navigation checks

## Acceptance Criteria
- [x] Three prioritized improvements work with authoritative and missing data.
- [x] Narrow/full checks and independent Gate Review pass.
- [x] Updated preview opens and supports candidate navigation.

## Progress Log
- 2026-09-14: Inspected report contracts and existing DemoShop annotations.
- Added connected count stages and the first three representatives' prior/final
  comparison, with shared 0–100% scale and visible missing-verification state.
- Annotated map, table, comparison and detail from retained baseline captions;
  all 100 authored DemoShop numbers match in regression tests.
- Narrow tests: 17 passed. Full suite: 998 passed in 233.105 seconds.
  Format, lint, type-hint and diff checks passed.
- Independent Gate Review: PASS after fixing malformed form-action fallback;
  affected tests passed again. Final CSS aligns comparison headings and adds
  decorative stage connectors, hidden on mobile.
- Desktop 1280px and mobile 390px QA passed; document width 375px at 390px,
  source-caption detail navigation and overview return work.
- Automatic approval review rejected the server/start-and-scan command without
  a specific reason. No alternative scan was attempted. Browser QA instead uses
  a clearly labeled offline fixture at build/report-preview/story-preview.html;
  existing real scan artifacts remain unchanged. Fresh real-target regeneration
  has therefore not been verified in this change.

## Decision Log
- Use existing baseline HTML for display labels rather than duplicating DemoShop
  definitions in the scanner or changing discovery contracts.

## Open Questions
- None.
