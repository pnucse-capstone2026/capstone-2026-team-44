# Interface Contract v1

## Goal

Freeze the current `integration/v0.2` cross-team boundaries as one documented,
versioned Interface Contract v1, backed by minimal validation/serialization
code and focused contract tests, so later BAC and mutation work can consume the
existing canonical artifacts without reconstructing identity or provenance.

## Non-Goals

- Network Observation, POST Probe expansion, login/session implementation, or
  BAC pipeline implementation.
- Payload mutation, `payload_verifier_v2`, LLM calls, Focused Verification, or
  changes to scoring weights, Top-K, feature schema, or Dynamic crawling.
- A new context-registry artifact, parallel DTO graph, or broad refactor.
- Commit, push, PR, merge, stash operations, or tracked JSON artifacts.

## Context Read

- `AGENTS.md`
- `README_START_HERE.md`
- `docs/ARCHITECTURE.md`
- `docs/PROTOTYPE_V0_1.md`
- `docs/PROTOTYPE_V0_2.md`
- `docs/TEAM_INTERFACES_V0_2.md`
- `docs/DOMAIN_MODEL.md`
- `docs/FEATURE_SCHEMA.md`
- `docs/DECISION_LOG.md`
- `PLANS.md` and `CODE_REVIEW.md`
- current domain, observation, features, scoring, selection, reporting, and
  pipeline modules and their tests

## Current State

The existing Feature extractor already consumes canonical `InputPoint`,
`ProbePlan`, `ResponsePair`, and role-owned `ResponseSnapshot` objects and
rejects cross-plan/missing provenance. `ScoringResult`, `SelectionOutcome`, and
the split crawl/analysis reports already preserve candidate, feature, probe,
response, and discovery identities.

The first Gate Review found that the initial adapter trusted duplicated report
score/evidence values, used configuration-bound run identity as content
identity, and incompletely rejected nested credential material. The hardened
boundary must reuse producer APIs and bind the two reports to exact canonical
discovery content without adding a third artifact.

## Proposed Changes

1. Document Interface Contract v1 and its compatibility, identity,
   provenance, sensitive-data, and artifact rules.
2. Add a small `vulnspider.handoff` module that validates the existing
   `vulnspider-crawl.json` plus `vulnspider-analysis.json` mappings and produces
   deterministic immutable `NormalizedCandidate` records for selected
   Injection candidates.
3. Reserve explicit handoff category/vulnerability discriminators for future
   BAC without constructing fabricated BAC data or implementing BAC behavior.
4. Add dedicated contract tests for existing Probe/Feature ownership,
   candidate validation/serialization, artifact identity resolution, missing
   references, and sensitive-context rejection.
5. Add deterministic canonical discovery snapshot binding to crawl output and
   the matching analysis reference.
6. Revalidate report FeatureVectors with existing scorers and the existing
   Top-K selector; reject raw credentials with a bounded nested detector.

## Interfaces / Data Changes

New additive public package: `vulnspider.handoff`, contract version `1.0`.
Existing feature, scoring, selection, and pipeline signatures remain unchanged.
Canonical discovery serialization adds `discovery_snapshot_id`, and the
analysis crawl reference adds the same required content binding. Existing
report/discovery version strings remain unchanged and are validated exactly.

The adapter output contains candidate/ranking fields, resolved endpoint and
input identities, complete score evidence, exact probe/response provenance,
and a safe Injection mutation context derived from the existing request
template/context records. It is derived handoff data, not a canonical artifact.

## Safety / Scope Impact

No network or payload execution changes. The adapter performs only in-memory
validation of already-loaded JSON mappings. It rejects raw cookie and
authorization material, unresolved identities, unsupported categories/types,
missing provenance, and fabricated unavailable evidence. A bounded structural
JWT/API credential detector scans nested mappings and parameter pairs without
classifying every ordinary string as secret. It never persists or logs raw
response bodies or credentials.

## Test Plan

- Focused Interface Contract v1 unit tests.
- Existing observation, scoring/selection, and split-reporting regressions.
- Full `unittest` regression.
- Existing format, lint, type-hint, and `git diff --check` checks.
- Final changed-file/status/diff review before reporting readiness.

## Acceptance Criteria

- [x] Contract A is fixed by code references, documentation, and tests.
- [x] Contract B exposes deterministic selected-candidate handoff records for
  SQLi and Reflected XSS and reserves, but does not implement, BAC.
- [x] Contract C joins only crawl and analysis artifacts and resolves exact
  InputPoint, Endpoint, RequestTemplate, request context, ProbePlan, and
  response provenance.
- [x] Missing or inconsistent identity fails explicitly.
- [x] Unobserved evidence remains unavailable rather than numeric zero.
- [x] Raw credential context is rejected and no third canonical artifact is
  introduced.
- [x] Existing behavior and complete regression remain unchanged.
- [x] Worktree contains only task changes plus the pre-existing untracked JSON.
- [x] Discovery content is deterministically bound to crawl and analysis by one
  recalculated snapshot ID.
- [x] Artifact scoring, evidence, summary, rank, and ordering are checked with
  existing authoritative scorer/selection APIs.
- [x] JWT, Bearer, API-key, cookie, authorization, and nested credentials fail
  closed before mutation context construction.

## Progress Log

- 2026-08-09: Confirmed `integration/v0.2` at `e630ce7`, pulled with
  `--ff-only`, and created `feat/interface-contract-v1` without touching the
  seven untracked JSON artifacts or stash.
- 2026-08-09: Inspected current contracts. Probe/Feature ownership is already
  strict; candidate selection and split artifacts already carry the required
  authoritative identities. Chose a minimal artifact-join adapter instead of
  changing upstream models or report schemas.
- 2026-08-09: Added the versioned handoff schema and two-artifact adapter,
  Contract v1 documentation, ADR-020, documentation pointers, and twelve
  focused contract tests. The focused suite and initial format/lint/type checks
  pass; regression validation remains in progress.
- 2026-08-09: Passed 98 relevant regression tests and the complete 455-test
  suite, including real Chromium integration tests. Final format, lint, type,
  tracked-diff whitespace, and new-file whitespace checks pass. The branch is
  ready for the requested independent Gate Review; no commit or remote action
  has been performed.
- 2026-08-09: Hardened the failed Gate Review findings with deterministic
  discovery snapshot binding, authoritative scorer/Top-K replay, exact evidence
  comparison, nested credential rejection, strict schema versions, and shared
  parameter-name normalization. Added adversarial contract regressions. The
  focused 37-test suite, 199 related regressions, complete 480-test suite, and
  explicit 44-test Chromium integration set pass, together with format, lint,
  type, and diff checks. Operational `elapsed_ms` telemetry is normalized out
  of the snapshot projection so identical discovery content remains
  deterministic. No commit, remote action, stash operation, or JSON-artifact
  modification was performed.

## Decision Log

- Decision: Treat `vulnspider-crawl.json` and `vulnspider-analysis.json` as the
  only canonical artifacts and make `NormalizedCandidate` derived handoff data.
- Reason: This preserves producer ownership and avoids a third registry that
  could drift from discovery or analysis truth.
- Decision: Keep Contract A production code unchanged.
- Reason: Existing factories and extractor validation already enforce exact
  ProbePlan/ResponsePair/ResponseSnapshot ownership; duplicating that logic in
  a wrapper would weaken rather than clarify the boundary.
- Decision: Bind reports by deterministic canonical discovery content rather
  than adding a run UUID or third registry.
- Reason: Equal canonical content remains reproducible while any relevant
  discovery change invalidates a stale analysis reference.
- Decision: Re-score reconstructed report FeatureVectors and re-run selection
  through existing public APIs.
- Reason: Scorer weights, maxima, evidence semantics, and Top-K ordering remain
  owned by their authoritative implementations rather than the handoff.

## Open Questions

- None for Contract v1. BAC subject/access-context fields and comparison policy
  remain future reviewed contract extensions.
