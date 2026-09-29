# NO-3 Observed GET API Canonicalization

## Goal

Promote only naturally emitted, Authority-allowed, exact-origin primary-page GET
fetch/XHR requests into deterministic canonical Endpoint, QUERY InputPoint,
RequestTemplate, and valid request-context records without replaying transport or
retaining credentials.

## Non-Goals

- Canonicalizing HEAD, POST, PUT, PATCH, DELETE, JSON bodies, or PATH parameters.
- Authentication/session replay or storage of raw headers, cookies, tokens, or
  sensitive query values.
- Changing browser authority, redirects, budgets, navigation, scoring, Top-K, BAC,
  LLM, or Mutation behavior.
- Reconstructing canonical data from passive audit fingerprints or serialized audit
  JSON.

## Context Read

- `AGENTS.md`, `PLANS.md`, `CODE_REVIEW.md`, `README_START_HERE.md`
- `docs/ARCHITECTURE.md`, `docs/PROTOTYPE_V0_2.md`
- `docs/INTERFACE_CONTRACT_V1.md`, `docs/TEAM_INTERFACES_V0_2.md`
- `docs/DOMAIN_MODEL.md`, `docs/GIT_WORKFLOW.md`, `docs/DECISION_LOG.md`
- NO-1 and NO-2 completed execution plans
- Dynamic browser/crawler, canonical contracts/builders, merge, pipeline, handoff,
  and related unit/integration tests

## Current State

NO-1 retains bounded secret-free PassiveNetworkObservation audit projections. NO-2
allows naturally emitted primary-page exact-origin fetch/XHR GET and HEAD in simple
mode. Those observations are not canonical discovery objects and do not affect the
discovery snapshot. The Dynamic crawler currently aggregates only rendered-DOM
canonical components.

## Proposed Changes

1. Reuse the repository credential-name/material policy through a shared safe policy
   module.
2. Collect a separate bounded internal network-discovery candidate only at the
   already-authorized route decision. Preserve executable query values only when no
   sensitive query or credential-bearing header is present; otherwise retain path and
   ordered query-name structure only.
3. Canonicalize safe candidates through the existing canonical builder semantics and
   represent structural candidates as Endpoint/InputPoint plus NOT_READY status,
   without RequestTemplate/context.
4. Feed the network component into the existing Dynamic aggregation and Static-first
   merge paths, preserving DOM and NETWORK provenance under one stable identity.
5. Extend focused unit, real Chromium, strict Gate, and simple CLI E2E evidence.

## Interfaces / Data Changes

- Add immutable internal network-candidate/collection records to the managed browser
  boundary; they are not serialized under `browser_audit`.
- Add explicit canonical NOT_READY reason(s) only if the existing structural-only
  contract needs them; do not redesign Contract v1.
- Network-derived canonical objects remain ordinary CanonicalDiscoveryResult members
  and therefore participate in `discovery_snapshot_id` and the existing crawl/analysis
  content binding.

## Safety / Scope Impact

No authority is broadened and no request is created, replayed, retried, or redirected
by canonicalization. Candidate creation happens only after the existing Guard returns
ALLOW for a primary-page exact-origin GET fetch/XHR. Header values are inspected only
transiently for credential-bearing names and are never stored. Sensitive query values
are discarded before candidate construction; malformed, userinfo, and oversized URLs
fail closed.

## Test Plan

- Unit: safe fetch/XHR, repeated occurrences, deterministic order/dedup, DOM/network
  merge, HEAD/POST/off-scope/blocked negatives, malformed/userinfo/oversize bounds,
  secret non-retention, context binding, snapshot behavior, pickle, static-only
  invariance.
- Chromium: natural GET fetch and XHR arrive exactly once; HEAD remains audit-only;
  POST/off-scope remain blocked; no canonicalization replay; network provenance and
  cleanup hold.
- CLI E2E: crawl artifact carries network canonical objects/readiness, only READY
  contexts reach ProbePlanner, analysis references exact InputPoint/snapshot and
  baseline/probe plan identities.
- Regression/static: full unittest, strict browser-loopback gate, format, lint, types,
  and `git diff --check`.

## Acceptance Criteria

- [x] Safe exact-origin GET fetch/XHR produce canonical objects and validated contexts.
- [x] Sensitive/credential-bearing GET stores no raw credential or sensitive value and
  is NOT_READY or explicitly audit-only when Contract v1 cannot express it safely.
- [x] HEAD, non-GET, blocked, off-scope, malformed, userinfo, and oversized requests do
  not produce canonical objects.
- [x] Duplicate/event ordering is deterministic; DOM/network evidence merges without
  duplicate identity.
- [x] Canonical changes affect snapshots; audit-only occurrence changes do not.
- [x] Browser transport counts prove no canonicalization request/replay.
- [x] Crawl/analysis references and ProbePlan baseline/probe attribution validate.
- [x] Independent Gate Review reaches PASS or PASS WITH MINOR.

## Progress Log

- 2026-08-14: Verified remote `integration/v0.2` at `1b356f8` contains NO-1
  `12d4877` and NO-2 `6bd65ba`; created the required branch from that tip. Confirmed
  zero tracked changes, recorded seven protected JSON hashes and stash OID
  `4cb421fdc274504f1768ddc8cbee0b1d84dd8dbf`.
- 2026-08-14: Read the governing contracts and traced NO-1 observation, NO-2 Guard,
  Dynamic aggregation, canonical validation, merge, snapshot, and handoff paths.
- 2026-08-14: Added a separate bounded candidate at the post-ALLOW Guard seam,
  shared the existing Contract v1 credential policy, and canonicalized safe GETs
  through the existing builder/merge path. Sensitive or credential-bearing GETs
  now discard all values before candidate retention and become structural NOT_READY
  or explicitly counted audit-only records.
- 2026-08-14: Added unit, real-Chromium, strict manifest, and simple CLI E2E coverage.
  Focused tests passed (170); the Chromium-only canonicalization test, simple CLI
  E2E, and strict browser-loopback Gate passed (18/18 required, zero skipped).
- 2026-08-14: Full regression passed (505 tests). Format, lint, types, and
  `git diff --check` passed. Self-review added a fail-closed canonical scope check
  for directly constructed candidates before independent review.
- 2026-08-15: Independent review first returned APPROVE/PASS WITH MINOR for a
  missing full-CLI NOT_READY execution assertion. Added an allowed
  credential-header GET to the simple CLI fixture and proved one natural server
  arrival, value-free NOT_READY crawl ownership, zero planner execution, and zero
  credential serialization. Follow-up independent review returned APPROVE/PASS
  with no findings or test gaps.
- 2026-08-15: Re-ran the strict browser-loopback Gate (18/18 required, zero
  skipped/failures), the simple CLI E2E, focused checks, and the full 505-test
  regression on the final tree; all passed.

## Decision Log

- Decision: Capture candidates at the existing allowed route decision rather than
  from PassiveNetworkObservation or browser-audit JSON.
- Reason: Only the Guard has authoritative allow/scope/primary-page evidence and the
  original bounded URL needed for canonicalization; this preserves audit separation
  and prevents reconstruction or replay.
- Decision: Use structural-only Endpoint/InputPoint plus NOT_READY for sensitive or
  credential-bearing GET when Contract v1 validates that representation.
- Reason: It preserves useful names/provenance while ensuring no executable request
  context or secret value exists.
- Decision: When an elided request has no query names, emit no canonical object and
  record it in `audit_only_candidate_count` instead of inventing a readiness owner.
- Reason: Contract v1 readiness belongs to InputPoint; an Endpoint-only credential
  request cannot truthfully carry NOT_READY ownership.

## Open Questions

- None blocking.
