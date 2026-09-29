# DemoShop member evidence demo

## Goal
Show cross-member BAC access clearly and make member lookup/SQLi reproducible directly in DemoShop.

## Non-Goals
Scanner, ranking, payload execution policy, and frozen v0.1 changes.

## Context Read
- AGENTS.md, README_START_HERE.md, docs/ARCHITECTURE.md
- PLANS.md, CODE_REVIEW.md, docs/GIT_WORKFLOW.md
- tools/demo_shop.py and DemoShop tests

## Current State
Member records are fixed display fragments; SQL member disclosure requires a confirmation overlay.

## Proposed Changes
1. Share three demo member records across lookup and disclosure.
2. Resolve IDs and evaluate member searches against an isolated in-memory fixture.
3. Highlight mismatched resource ownership and test normal/negative/manual demo paths.

## Interfaces / Data Changes
Demo fixture only; preserve canonical input names, seeds, and labels.

## Safety / Scope Impact
Loopback target only. No persistent database or new transport permissions.

## Test Plan
Narrow DemoShop HTTP tests, full unittest/static checks, independent Gate Review.

## Acceptance Criteria
- [x] Three requested names and consistent contact data.
- [x] Manual SQLi reveals members without vs_confirm; ID lookup resolves correctly.
- [x] Ownership mismatch is visually and textually explicit.
- [x] Full checks and Gate Review pass.

## Progress Log
- 2026-09-23: Inspected existing branch and fixture; unrelated untracked files preserved.

- 2026-09-23: Implemented three shared members, read-only ephemeral SQLite lookup,
  owner mismatch notice and full-width result table. Browser checked direct SQLi
  and order 4101 without confirmation markers.
- Verification: full unittest suite 1,048 passed; final affected DemoShop suite
  55 passed; format, lint, type-hint and diff whitespace checks passed.
- Independent Gate Review: PASS. Second focused safety review: PASS.
  SQLite bound failure cases were manually checked by the safety reviewer;
  dedicated persistent tests for every budget limit remain optional.

## Decision Log
- Keep all changes confined to demo behavior and presentation.

## Open Questions
- None.
