# Prompt 05D Top-K Reporting and CLI

## Goal

Complete the v0.1 pipeline from validated 05C scoring results through
cross-type-comparable deterministic Top-K selection, stable JSON reporting,
adapter-record CLI orchestration, and a network-free end-to-end smoke test.

## Non-Goals

Focused verification, confidence or findings, LLM/RAG, BAC, dynamic crawling,
live legacy crawler integration, database persistence, dashboards, score-weight
changes, normalization of stored RankScore, and model tuning.

## Context Read

- `AGENTS.md`, `PLANS.md`, `CODE_REVIEW.md`
- `docs/ARCHITECTURE.md`, `docs/DOMAIN_MODEL.md`
- `docs/FEATURE_SCHEMA.md`, `docs/PROTOTYPE_V0_1.md`
- `docs/LEGACY_AUDIT.md`, `docs/DECISION_LOG.md`
- current adapter, planner, executor, extractor, scorer, CLI, tests, and config

## Current State

05C emits ownership-validated `ScoringResult` objects. SQLi raw scores have a
maximum of 75 and Reflected XSS raw scores have a maximum of 45. Selection and
reporting packages are empty. The CLI supports only `--version`. The checkout
contains no callable legacy crawler runtime; the pure `LegacyCrawlerAdapter`
accepts serialized legacy crawl-record mappings. A standard-library production
probe transport and injectable transport protocol already exist.

## Proposed Changes

1. Add immutable selection records and deterministic global Top-K using raw
   score divided by the exact scorer-policy maximum.
2. Exclude all-missing results as unrankable while retaining accounting; keep
   observed-zero results rankable.
3. Add stable finite JSON serialization with full identity and evidence.
4. Add orchestration from adapter-compatible records through current planning,
   execution, extraction, scoring, selection, and reporting boundaries.
5. Add `vulnspider analyze --input ... --top-k ... --output ...` for authorized
   loopback test records, with injectable transport for deterministic tests.

## Interfaces / Data Changes

- New selection API: `select_top_k()` returning immutable outcome/summary data.
- New reporting API: report mapping, deterministic JSON text, and file writer.
- New pipeline API: analyze legacy record mappings with current components.
- CLI gains the `analyze` subcommand; existing empty invocation and version
  behavior remain supported.

## Safety / Scope Impact

The CLI does not invoke or recreate the legacy crawler. It reads existing
adapter-compatible JSON records and permits executable request templates only
for loopback hosts. Existing `execute_probe_plan()` and redirect-disabled
transport semantics remain unchanged. Tests inject a fake transport and make no
network requests.

## Test Plan

- Selection unit tests: cross-type scale fairness, raw-score preservation,
  deterministic ties, invalid/oversized K, missing versus zero, identity,
  repeated occurrences, and exact-candidate deduplication.
- Reporting tests: ownership/evidence fields, deterministic bytes, finite JSON.
- CLI negative tests: invalid K, missing input, malformed records.
- End-to-end smoke: fixture record -> adapter -> planner -> fake transport ->
  pair -> vector -> both scorers -> Top-K -> JSON through the actual CLI parser.
- Full suite plus format, lint, and type-hint checks.

## Acceptance Criteria

- [x] XSS 45/45 ranks above SQLi 50/75 globally.
- [x] Raw RankScore remains unchanged and visible.
- [x] All-missing is unrankable; observed zero remains rankable.
- [x] Ties and JSON are deterministic independent of input order.
- [x] Ownership and occurrence identities survive selection/reporting.
- [x] CLI success and normal input failures are covered without live network.
- [x] Full configured gate passes.

## Progress Log

- 2026-07-10: Confirmed clean `0e9be48` checkpoint after removing only generated
  Python cache directories.
- 2026-07-10: Confirmed adapter-record fallback boundary; no legacy runtime is
  present in the checkout.
- 2026-07-10: Implemented normalized Top-K, stable strict JSON, loopback-only
  adapter-record orchestration, and the `analyze` CLI command.
- 2026-07-10: Passed 16 focused 05D tests, the 172-test full suite, format,
  lint, type-hint checks, and the actual module version entrypoint.

## Decision Log

- Decision: Preserve raw RankScore and derive selection priority as
  `raw_score / exact_scorer_maximum` from existing immutable policy constants.
- Reason: SQLi and XSS raw scales differ and cannot be globally sorted directly.
- Decision: Resolve duplicate exact candidate identities by the best priority,
  then deterministic FeatureVector id, while never merging distinct candidate
  identities.
- Reason: Multiple request contexts may score one ranking unit, but Top-K must
  not output duplicate candidates or depend on input order.
- Decision: CLI accepts a JSON array of adapter-compatible legacy records.
- Reason: The audited legacy runtime is absent and was not safely callable as a
  core dependency even when present.

## Open Questions

- None.
