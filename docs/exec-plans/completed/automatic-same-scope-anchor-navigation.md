# Automatic Same-Scope Anchor Navigation

## Goal

Prove that `vulnspider -u URL` needs only the start URL to traverse a bounded,
deterministic multi-page chain of rendered GET anchors within the start URL's
exact scheme, host, and effective port, while preserving canonical discovery,
merge, and probe provenance.

## Non-Goals

- Redesigning the M4 crawler or its deterministic BFS frontier.
- Form submission, button/menu clicks, fetch/XHR/API discovery, History API or
  hash routing, or state-changing request replay.
- Feature, scoring, Top-K, LLM, Static-only, or legacy behavior changes.
- Push, PR, merge, stash, or generated-report changes.

## Context Read

- `AGENTS.md`
- `README_START_HERE.md`
- `docs/ARCHITECTURE.md`
- `docs/GIT_WORKFLOW.md`
- `docs/DECISION_LOG.md` ADR-019
- `PLANS.md`
- `CODE_REVIEW.md`
- M4 navigation sections of
  `docs/exec-plans/active/v0_2_native_dynamic_discovery_mvp.md`
- `src/vulnspider/cli.py`
- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/discovery/dynamic_crawler.py`
- `tests/integration/dynamic_loopback_site.py`
- `tests/integration/test_simple_cli_loopback.py`

## Current State

The M4 crawler already canonicalizes rendered anchors and schedules them on a
heap-backed `(depth, canonical URL, parent URL)` frontier. It removes fragments,
deduplicates scheduled/attempted URLs, prevents cycles, enforces all existing
budgets and the hard deadline, and rejects URLs outside the root's exact origin.
ADR-019 already enables this extraction-only capability for the simple `-u`
adapter while leaving advanced `analyze --dynamic` exact-grant-only. However,
the simple adapter inherited M4's advanced default maximum depth of one, so a
rendered anchor found on page A could not schedule page B.

The existing public CLI Chromium test follows one rendered anchor but does not
prove a second hop, a cycle back to start, or that multiple rendered pages
contribute canonical Endpoint/InputPoint records that survive combined merge
and probe execution.

## Proposed Changes

1. Give only the public simple adapter a bounded maximum link depth of two;
   preserve the shared `DynamicCrawlPolicy` default for advanced callers.
2. Extend the existing local simple-CLI fixture to expose page A, page B, a
   canonical cycle to the start page, and a different-port sentinel link.
3. Strengthen the focused crawler test to cover automatic two-hop rendered
   navigation, fragment deduplication, deterministic order, cycle prevention,
   and cross-scope rejection without explicit navigation grants.
4. Strengthen the real public CLI E2E to verify visited URLs/depth, canonical
   multi-page Endpoint/InputPoint merge, READY/NOT_READY context ownership,
   probe/response-pair provenance, zero cross-scope/state-changing transport,
   and a deterministic rerun.

## Interfaces / Data Changes

No canonical interface changes. The simple CLI's default Dynamic maximum depth
changes from one to two; the shared/advanced `DynamicCrawlPolicy` default stays
one. The existing `DynamicRequestAuthority` simple-mode capability remains
derived from its canonical root URL and the existing M4 frontier remains
authoritative.

## Safety / Scope Impact

The simple adapter can now reach one additional bounded anchor depth, but its
origin authority is not expanded. Only rendered GET anchors on the exact root
origin may be directly navigated. The sentinel uses a different effective port
and must receive zero requests. Existing page, navigation, browser
request-decision, elapsed-time, and hard-deadline bounds remain unchanged, and
the new simple depth bound is explicitly two.

## Test Plan

- Focused Dynamic crawler unit tests.
- Strict real-Chromium `bounded-navigation` Gate.
- Public `-u` multi-page loopback E2E, including deterministic rerun metrics.
- Full unittest regression, Native Static E2E, v0.1 smoke.
- Format, lint, type, and diff checks.
- Exactly one Independent Gate Review; at most one Critical/High correction
  loop followed by affected/full gate reruns.

## Acceptance Criteria

- [x] Start, page A, and page B are visited in deterministic BFS order.
- [x] The page-B link back to start is deduplicated and never revisited.
- [x] The different-port sentinel receives zero attempts and zero visits.
- [x] Multiple pages contribute canonical Endpoint/InputPoint records that
  merge into the combined result with valid contexts and provenance.
- [x] No form is submitted and no state-changing request occurs.
- [x] All ordered gates and exactly one Independent Gate Review pass.
- [x] The task diff contains only navigation files; JSON artifacts and
  `stash@{0}` are untouched.

## Progress Log

- 2026-08-08: Committed the separately reviewed DYNAMIC_INTEGRITY fix as
  `b57b2e4` after explicit staged-diff validation.
- 2026-08-08: Inspected the current CLI/authority/M4 frontier and confirmed its
  exact-scope anchor capability. The first focused test exposed the remaining
  root cause: the simple adapter inherited M4's depth-one advanced default and
  therefore could not schedule page B from page A.
- 2026-08-08: Set only the simple adapter's default maximum depth to two and
  added a local root-to-A-to-B cycle fixture with different-port sentinel,
  multi-page canonical merge/probe assertions, and deterministic unit rerun.
- 2026-08-08: Focused navigation passed 2/2; strict real-Chromium bounded
  navigation passed 7/7 with Playwright 1.62.0; public CLI multi-page E2E
  passed 1/1 and its separate two-run stable projection matched.
- 2026-08-08: Public CLI metrics were depth 2, 9 Endpoints, 5 InputPoints,
  READY 5 / NOT_READY 0, 5 ProbePlans, 5 baseline and 5 probe requests,
  5 ResponsePairs, and zero cross-scope attempts/visits or state-changing
  requests.
- 2026-08-08: Full unittest passed 443/443, Native Static E2E 1/1, v0.1 smoke
  7/7, and format/lint/type/diff checks passed.
- 2026-08-08: Exactly one Independent Gate Review returned `PASS WITH MINOR`
  with Critical/High/Medium 0. Its Low note records that the committed Chromium
  E2E runs once; deterministic rerun remains covered by the focused fake-browser
  regression and the separately executed public-CLI two-run gate.

## Decision Log

- Decision: Reuse the existing ADR-019 extraction-only rendered-navigation
  authority and M4 BFS, changing only the simple adapter's default maximum
  depth to two.
- Reason: The current production path already derives exact origin scope from
  the start URL and enforces all requested normalization and safety invariants;
  a narrow adapter policy override enables the required second hop without
  changing advanced caller behavior or adding another authority mechanism.

## Open Questions

- None.
