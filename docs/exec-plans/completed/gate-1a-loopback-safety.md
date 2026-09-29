# Gate 1A Loopback Safety

## Goal

Restore the existing loopback-only boundary before Static crawl, Light Probe,
Injection Focused Verification, BAC Focused Verification, and Dynamic browser
authority execution.

## Non-Goals

- Change POST JSON structural discovery or READY/NOT_READY behavior.
- Disable Dynamic Discovery, rendered navigation, passive resources, or
  same-origin GET/HEAD fetch/XHR.
- Change CLI progress or dependency behavior.
- Revert PR #19 wholesale.

## Context Read

- `AGENTS.md`
- `README_START_HERE.md`
- `docs/ARCHITECTURE.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- Gate 1A read-only analysis and implementation request
- Relevant pipeline, Dynamic browser, focused verification, and safety tests

## Current State

At `7614b11`, three loopback checks were disabled by an early return or a
triple-quoted string. Static URL analysis reached its crawler before root
loopback validation, and BAC verification had no local execution guard.

## Proposed Changes

1. Add one strict shared loopback HTTP URL validator.
2. Restore pipeline and Dynamic authority validation with existing public
   error types.
3. Validate a Static root before crawler transport.
4. Validate Injection and BAC derived requests immediately before transport.
5. Add only the four missing negative transport-zero regressions.

## Interfaces / Data Changes

No public model, schema, CLI, or report contract changes. The new helper is an
internal policy utility.

## Safety / Scope Impact

Non-loopback, userinfo-bearing, and malformed authorities fail closed before
active execution. Existing exact-origin Dynamic request decisions and bounded
SPA discovery remain unchanged.

## Test Plan

- Four new negative transport-zero regression tests, first RED then GREEN.
- Existing Dynamic authority, cross-origin crawler/navigation, Injection, BAC,
  and CLI non-loopback tests.
- Real loopback rendered DOM, SPA navigation, GET/HEAD fetch/XHR, and
  cross-authority browser tests.
- `git diff --check`.
- Do not run the full 891-test suite in Gate 1A.

## Acceptance Criteria

- [x] Every new negative test is RED before the product patch.
- [x] Static, Light Probe, Injection verification, and BAC verification reject
  external targets with zero transport calls.
- [x] Dynamic authority rejects external/userinfo/malformed inputs.
- [x] Required POST-independent SPA controls remain green.
- [x] POST product code and tests remain unchanged.
- [x] `git diff --check` passes.

## Progress Log

- 2026-08-31: Confirmed clean branch `hotfix/integration-safety-regression` at
  `7614b11` and traced the disabled boundaries.
- 2026-08-31: Added four tests and reproduced four failures before product
  changes; all failures executed transport instead of rejecting.
- 2026-08-31: Added the shared validator and restored all active boundaries.
- 2026-08-31: Targeted safety and POST-independent SPA controls passed. One
  pre-existing POST expectation failure remains outside Gate 1A.

## Decision Log

- Decision: Use one internal strict URL validator and map its error into each
  boundary's existing public error type.
- Reason: This minimizes policy divergence without changing crawler or
  verification public APIs.
- Decision: Keep `StaticCrawler` generic and enforce loopback at
  `pipeline.analyze_url()`.
- Reason: The product entry boundary owns project authorization while crawler
  unit contracts remain reusable.

## Open Questions

- Gate 1C owns the known POST JSON structural-only regression.
- The environment's missing `tqdm` dependency remains outside Gate 1A.
