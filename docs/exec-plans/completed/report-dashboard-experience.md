# Report dashboard experience

## Goal
Give non-specialist graduation-project evaluators a Korean overview dashboard,
candidate navigation, and dedicated evidence/verification/remediation screens.

## Non-Goals
No scanner, scoring, selection, verification, network, JSON contract, or frozen
v0.1 renderer changes. No new dependencies or invented crawl links/evidence.

## Context Read
- AGENTS.md, README_START_HERE.md, PLANS.md, CODE_REVIEW.md
- docs/ARCHITECTURE.md, DOMAIN_MODEL.md, FEATURE_SCHEMA.md
- docs/PROTOTYPE_V0_1.md, PROTOTYPE_V0_2.md, TEAM_INTERFACES_V0_2.md
- docs/GIT_WORKFLOW.md, EVALUATION_PROTOCOL.md, DECISION_LOG.md
- reporting/decision_html_report.py, guidance.py, verification_detail_report.py
- verification/result.py, focused.py, access_verify.py; report tests

## Current State
The v0.2 renderer now presents separate overview, searchable list, detail and
reading-guide screens. Details preserve authoritative evidence and include
payload-level verification. Implementation, visual QA, independent Gate Review
and the final isolated full-suite run are complete and passing.

## Proposed Changes
1. Self-contained fragment-routed overview, searchable candidate list, detail
   screens, and methodology screen with responsive, accessible navigation.
2. Show endpoint-to-input/candidate relationships (not crawl navigation edges),
   truthful counts, readable feature explanations and actual payload records.
3. Preserve advanced evidence/provenance; explain missing/rejected/unexecuted
   evidence; show conditional defensive guidance and fix verification criteria.
4. Add reporting regressions, run browser QA/full checks and independent Gate Review.

## Interfaces / Data Changes
Presentation-only helpers; existing renderer arguments and JSON stay compatible.

## Safety / Scope Impact
Report is offline, escapes all dynamic content, uses only a fixed trusted script
for local navigation/filtering, and never requests the scanned target.

## Test Plan
- Existing decision, verification, frozen HTML and CLI regressions
- Fragment identity, candidate membership, escaping, missing data, statuses
- Desktop/mobile browser navigation, search, history, no external requests
- Full unittest/format/lint/type-hint suite and git diff --check

## Acceptance Criteria
- [x] Overview and candidate details are separate screens, usable offline.
- [x] Counts, scores, evidence and payload execution match producer objects.
- [x] Responsive keyboard-accessible navigation and browser QA pass.
- [x] Full checks pass; independent Gate Review PASS or PASS WITH MINOR.
- [x] Documentation matches implementation.

## Progress Log
- 2026-09-13: Inspected renderer/contracts; created isolated branch from the
  user's current checkpoint and planned presentation-only changes.
- 2026-09-13: Implemented dependency-free screen layout, fixed CSP-hashed
  navigation/filtering script, candidate ownership map, readable evidence,
  actual payload records and conditional remediation. Preserved candidate
  membership, confidence source, JSON and frozen v0.1 behavior.
- 2026-09-13: Added reporting tests for local unique routes, escaping/CSP,
  empty/missing data, real payload provenance, rejection, accepted-but-unexecuted
  payloads, execution errors and aggregate-only BAC verification. Final focused
  reporting/CLI/guidance checks: 48 passed. Format/lint/type-hint checks passed.
  All Python checks/scans used `PYTHONPATH=src`: the shell's default Python
  otherwise resolves a separate editable checkout, so it would not test this
  working tree. No environment installation was changed.
- 2026-09-13: Generated a real DemoShop report using loopback port 18991: 33
  endpoints, 100 input points, 200 scored candidates, 12 selected representatives.
  Browser QA through a report-only loopback preview on port 18992 verified map
  links, detailed payload/defense screens, list search/empty/reset/family filters,
  back navigation preserving filters, keyboard skip focus, 390px mobile and
  1280px desktop layout without document overflow, and an empty report. A
  script-omitted copy verified CSS-only direct detail and next-candidate routes.
  Browser error/warning log was empty. Preview artifacts stay ignored in
  `build/report-preview/`; original checked-in results were not overwritten.
- 2026-09-13: Independent Gate Review first returned PASS WITH MINOR for the
  skip link; corrected it to focus the current page heading. Final independent
  review returned PASS/APPROVE, with 20 targeted tests and diff whitespace checks
  passing. No blocking or minor findings remain.
- 2026-09-13: Initial full suite passed 984 tests. A subsequent 985-test run
  during live UI tooling failed two existing browser integration checks (100ms
  navigation timeout and process cleanup capturing newly created node_repl/node
  tool processes). With UI tooling stopped, both affected modules passed all
  14 tests. No unrelated test or crawler behavior was changed to accommodate
  the failures.
- 2026-09-13: Final full suite with UI tooling idle: **985 tests passed in
  264.125 seconds** (`python -B -m unittest discover -s tests`, with
  `PYTHONPATH=src`). `check_format.py`, `check_lint.py`, `check_types.py` and
  `git diff --check` passed. Final independent Gate result: **PASS**. Plan moved
  to completed. The generated dashboard is `build/report-preview/dashboard.html`.

## Decision Log
- Use fragment routes within one portable HTML file, preserving CLI output
  paths and avoiding companion asset publication failures.
- Preserve existing highest-type-per-subject display; disclose the distinction
  between selected candidate count and displayed representative count.

## Open Questions
- None.
