# Passive Browser Network Observation

## Goal

Record browser-originated fetch/XHR request attempts as bounded, deterministic,
secret-free browser audit evidence without issuing, replaying, or authorizing
any request.

## Non-Goals

- Request replay or new transport execution.
- Changes to HTTP/WebSocket guards, scope authority, or CLI options.
- Canonical Endpoint, InputPoint, RequestTemplate, request-context, readiness,
  provenance, warning, snapshot, probe, feature, scoring, selection, BAC, or LLM
  behavior.

## Context Read

- `AGENTS.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- `README_START_HERE.md`
- `docs/ARCHITECTURE.md`
- `docs/PROTOTYPE_V0_2.md`
- `docs/INTERFACE_CONTRACT_V1.md`
- `docs/DECISION_LOG.md`
- `docs/exec-plans/active/v0_2_native_dynamic_discovery_mvp.md`
- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/discovery/dynamic_crawler.py`
- Dynamic browser/crawler unit and loopback tests

## Current State

The managed browser creates a BrowserContext, installs context-wide HTTP and
WebSocket guards, then creates its primary Page. Fetch/XHR is blocked unless an
exact same-origin `fetch_xhr` grant exists. Guard audit events retain sanitized
transport decisions, but there is no separate passive request-attempt model.

## Proposed Changes

1. Add an immutable safe projection for fetch/XHR attempts and bounded audit
   aggregation.
2. Install a read-only BrowserContext request observer after both guards and
   before Page creation.
3. Serialize observations only under Dynamic crawl browser audit evidence.
4. Add unit, real Chromium loopback, and strict manifest coverage.

## Interfaces / Data Changes

`BrowserAuditSummary` gains `network_observations` and
`network_observation_overflow_count` with backward-compatible defaults.
`DynamicCrawlResult.to_dict()` serializes them under `browser_audit`. No
canonical discovery contract or snapshot input changes.

## Safety / Scope Impact

The observer reads only request method, URL, and resource type. It does not
call any routing, page-navigation, request, response, header, cookie, or body
API. Raw URLs, paths, query values, credentials, bodies, timestamps, and
provider objects are not retained. Exact scheme, host, and effective port
determine scope. The existing request-decision budget supplies only the
retention bound; observation does not consume the Guard budget.

## Test Plan

- Unit: lifecycle order, read-only traps, filtering, exact scope, secret-safe
  projection, duplicate aggregation, deterministic order, overflow, unchanged
  Guard counters, serialization, pickle, and snapshot independence.
- Integration: natural same-scope GET fetch/XHR each reaches the server once;
  POST and different-port attempts are observed but reach no target; script and
  style are excluded; all cleanup completes.
- Gate: register the Chromium case in the required browser-loopback manifest.
- Regression: focused suites, strict Gate, full unittest, format, lint, types,
  and diff check.

## Acceptance Criteria

- [x] Observer is installed after both guards and before Page creation.
- [x] Observer cannot execute or replay a request.
- [x] Only safe, bounded fetch/XHR projections are retained.
- [x] Existing Guard policy, counters, and canonical statistics are unchanged.
- [x] Canonical discovery and discovery snapshot are observation-independent.
- [x] Real Chromium proves GET delivery once and POST/off-scope delivery zero.
- [x] Independent Gate Review has no blocking finding.

## Progress Log

- 2026-08-13: Starting state and stash identity verified; 51 focused baseline
  tests passed with one expected capability skip in the ordinary unittest path.
- 2026-08-13: Added the passive projection, bounded deterministic aggregation,
  lifecycle installation, browser-audit serialization, and unit contracts; 75
  focused tests passed.
- 2026-08-13: The dedicated real-Chromium loopback case passed with same-scope
  GET fetch/XHR delivered once each, POST and different-port delivery at zero,
  and four natural fetch/XHR attempts retained without secret values.
- 2026-08-13: Strict browser-loopback passed 16/16 with no skips; the full
  regression passed 488/488 and format, lint, type-hint, and diff checks passed.
- 2026-08-13: Independent Gate Review returned PASS WITH MINOR with no Critical,
  High, or Medium findings. The sole Low records that pre-change hashes were not
  captured for the seven protected untracked JSON files.

## Decision Log

- Decision: Store NO-1 only in producer-owned Dynamic browser audit evidence.
- Reason: A secret-free attempt lacks the complete executable context required
  for canonicalization, and observation must not imply replay authority.
- Decision: Reuse `request_decision_budget` only as the unique-observation
  retention ceiling and independently count every unretained unique attempt.
- Reason: Audit memory remains bounded without consuming Guard decisions or
  changing existing transport and crawl statistics.

## Open Questions

- None for NO-1. Canonical promotion or request replay requires a separately
  reviewed future contract.
