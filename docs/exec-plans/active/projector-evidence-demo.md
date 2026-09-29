# Projector dashboard and evidence explanation

## Goal
Finish the existing dashboard improvements for a bright lecture room and make
the recorded Baseline/Probe evidence understandable to non-specialists.

## Non-Goals
No new manual proof, success-message or payload execution feature. The user
explicitly excluded the former DemoShop proof walkthrough on 2026-09-21.
No scoring, selection, confidence, network or frozen v0.1 semantic changes.

## Context Read
- AGENTS.md, PLANS.md, CODE_REVIEW.md, docs/GIT_WORKFLOW.md
- README_START_HERE.md, architecture, v0.1/v0.2 and team interface documents
- Domain model, feature schema, evaluation protocol, ADR-041/042
- Dashboard renderer/assets/evidence, DemoShop routes, existing tests

## Current State
The resumed branch already contained larger typography, presentation and
comparison modules, plus the now-excluded proof implementation. Unrelated
results_pack.py changes, generated docs/results artifacts and local files are
preserved. New deliverables are generated separately under build/.

## Proposed Changes
1. Retain and finish high-contrast typography, projector mode, presentation
   story, status cards and confidence bars, with navigation in projector mode.
2. Compare bounded escaped excerpts from actual retained responses, distinguish
   input-point aggregate evidence from one response pair, and explain limits.
3. Remove only the unfinished proof code, assets, tests and dashboard links.
4. Generate a fresh DemoShop K=20 report, visually verify it, run all required
   checks and obtain independent Gate Review.

## Interfaces / Data Changes
Private presentation helpers and decision-html-v5 only. Existing authoritative
JSON, domain and scoring contracts remain unchanged. No dependencies added.

## Safety / Scope Impact
Report is offline, escaped and CSP constrained. It issues no target requests.
DemoShop retains its pre-existing fixture behavior. Fresh scans use existing
approved loopback CLI paths and bounds. No ground truth enters explanations.

## Test Plan
- Attribution, escaping, bounds, missing/error evidence, baseline-existing error
- Aggregate feature versus displayed pair and safe reflection explanations
- Offline routes, CSP, representative counts, no proof links
- Full unit suite, format, lint, types and diff checks; independent Gate Review
- Browser inspection of overview, projector navigation, story and details

## Acceptance Criteria
- [x] Projector-mode screens and truthful plain-language comparisons implemented.
- [x] New proof functionality excluded; original DemoShop behavior preserved.
- [x] Fresh local DemoShop K=20 report generated and delivered as a local file.
- [x] Required code checks and independent Gate Review pass; docs updated.
- [ ] Browser visual QA and confirmation that the report is visibly open.
  Blocked by the browser tool's file-URL policy; local file-panel open is queued.
  Keep this plan active until this remaining presentation check is completed.

## Progress Log
- 2026-09-20: Dashboard presentation improvements started.
- 2026-09-21: Removed unfinished
  proof integration; DemoShop (19) and storefront (10) tests passed. Removed
  report proof links and changed presentation step 3 to evidence interpretation.
  Added navigation that stays available while the sidebar is hidden.
- 2026-09-21: Corrected baseline-existing SQL errors, unchanged response labels,
  and aggregate evidence explanations. Aligned Baseline excerpts using bounded
  unique shared context near the Probe excerpt, with fallback for ambiguous or
  absent context. Excerpt selection does not produce features or scores.
- 2026-09-21: Full suite passed: 1013 tests in 241.031 seconds. After the final
  excerpt/accessibility corrections and three new regressions, all 42 relevant
  comparison/experience/story/HTML tests passed. Format, lint, type-hint and
  full git diff --check passed. DemoShop tests (19 + 10) passed separately.
- 2026-09-21: Independent initial Gate PASS WITH MINOR; fixed actual featured
  count and mobile arrow-only rotation. Final independent Gate PASS / APPROVE;
  reviewer independently ran 24 tests and git diff --check successfully.
- 2026-09-21: Fresh build/projector-final results pack completed public and BAC
  scenarios (2/2). Public report: 100 input points, 200 scored candidates,
  selected K=20, 20 detail screens; 145 local links resolve, IDs are unique,
  script CSP hash matches, and no proof actions remain. Final scan generated
  at 2026-09-20 20:40 UTC from the current working tree.
- 2026-09-21: Existing docs/results whitespace errors were normalized only at
  reported trailing spaces in demoshop-bac/dashboard.html and the two run.log
  files. Original bytes are backed up in build/preexisting-whitespace-backup.
  Existing data, prior scan content and results_pack.py changes are preserved.
- 2026-09-21: Browser tool rejected the local file URL under its URL security
  policy. No workaround attempted. Visual QA is unverified; the local file
  tool accepted the final dashboard path with status queued for this task.

## Decision Log
- User's amended scope supersedes the earlier proof plan completely.
- Preserve pre-existing generated results and runner changes; publish the new
  K=20 run under build/projector-final rather than relabeling an old scan.
- Show observations and limits, not a celebratory vulnerability verdict.

## Open Questions
- Actual rendered layout/projector readability still requires visual checking.
  No code defect remains from independent Gate Review.
