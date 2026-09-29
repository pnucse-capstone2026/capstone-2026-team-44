# Real Target Dynamic Integrity Fix

## Goal

Fix the production `DYNAMIC_INTEGRITY` failure for the unchanged loopback demo
target while preserving strict component and merge validation.

## Non-Goals

- Changing the demo fixture.
- Redesigning discovery topology, merge semantics, ProbePlanner,
  RequestExecutor, features, scoring, or Top-K.
- Suppressing or weakening the required sensitive-form safety invariant.
- Commit, push, PR, merge, or stash operations.

## Context Read

- `AGENTS.md`
- `README_START_HERE.md`
- `CODE_REVIEW.md`
- `demo_target_server.py`
- `src/vulnspider/discovery/static_crawler.py`
- `src/vulnspider/discovery/combined.py`
- `src/vulnspider/discovery/merge.py`
- `src/vulnspider/pipeline.py`
- relevant combined pipeline and merge tests

## Current State

The demo root returns a bounded 404 response. Static Discovery validates as an
empty canonical component with `HTTP_ERROR`, while Dynamic Discovery validates
as an empty component with `DYNAMIC_HTTP_ERROR`. All topology references are
valid. Static's configured sensitive-form extractor is never invoked because
there is no successful HTML page, so its run-level result loses the configured
`SENSITIVE_FORM_PRE_CANONICAL_ELISION` declaration. Strict merge correctly
rejects that unmarked component.

## Proposed Changes

1. Bind the existing sensitive-form elision policy to one canonical Static
   extractor and derive its run-level invariant from that extractor identity.
2. Seed Static aggregation with that evidence even when zero pages reach
   extraction, without accepting caller-asserted declarations.
3. Add a focused pipeline regression with a Static 404 and valid empty Dynamic
   component, proving strict merge and analysis complete without suppressing
   validation.

## Interfaces / Data Changes

The canonical sensitive-eliding extractor identity participates in the Static
crawler configuration fingerprint and seeds the matching run-level invariant.
The default non-eliding Static extractor continues to declare none.

## Safety / Scope Impact

No request policy, redirect behavior, scope decision, budget, payload, or probe
behavior changes. Merge continues to require the invariant from both producer
components. Only crawlers explicitly configured with the existing
pre-canonical elision extractor make the corresponding run-level declaration.

## Test Plan

- Focused combined pipeline regression for Static HTTP error plus empty Dynamic.
- Existing combined merge and static crawler unit suites.
- Exact manual demo server reproduction with the public CLI.
- Existing Final Gate, full unittest, format/lint/type/diff checks, and one
  independent Gate Review as required by `AGENTS.md`.

## Acceptance Criteria

- [x] Both real-target components validate independently and strict merge
  succeeds.
- [x] Public `vulnspider -u http://127.0.0.1:8899/` no longer fails merge
  integrity; the fixture's intentional root 404 produces the existing
  degraded-result policy (exit 4, crawl report only).
- [x] Focused and repository Gates pass without fixture or validation changes.
- [x] No unexpected worktree files are changed and `stash@{0}` is untouched.

## Progress Log

- 2026-08-08: Confirmed the correct branch and clean tracked worktree; preserved
  the two pre-existing untracked `static-only-*.json` files.
- 2026-08-08: Reproduced public CLI exit 3. Direct traceback identified
  `Static: missing SENSITIVE_FORM_PRE_CANONICAL_ELISION`.
- 2026-08-08: Independently validated both components and every requested
  topology reference. Both are empty and collision-free; only Static's
  run-level safety declaration is missing because the 404 bypasses extraction.
- 2026-08-08: Bound the run-level declaration to the canonical sensitive-form
  elision extractor and added Static-404 regression coverage. Focused tests,
  Final Gate, full unittest, Native Static E2E, v0.1 smoke, format, lint, types,
  and diff check pass.
- 2026-08-08: Re-ran the exact CLI command. Strict merge succeeds and writes a
  valid degraded crawl report; the unchanged fixture's root 404 then yields the
  expected `DYNAMIC_INCOMPLETE` exit 4 without an analysis report.

## Decision Log

- Decision: Carry the existing safety policy as explicit producer run metadata.
- Reason: Inferring it from observed pages loses the guarantee on empty/error
  crawls, while adding it unconditionally would falsely mark ordinary Static
  crawlers and weaken merge validation.
- Gate Review: One independent review blocked the first implementation because
  it accepted a caller-asserted invariant independently of its extractor. The
  declaration field was removed, the invariant was bound to the canonical
  eliding extractor, and an adversarial non-eliding 404 test was added.

## Open Questions

- None.
