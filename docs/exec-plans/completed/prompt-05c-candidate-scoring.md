# Prompt 05C Candidate Generation and Scoring

## Goal

Generate independently scored SQLi and Reflected XSS candidates from one exact
`FeatureVector`, with deterministic ranking scores and auditable missing-aware
evidence.

## Non-Goals

Top-K selection, CLI or JSON orchestration, focused verification, confidence
updates, LLM/RAG, BAC, grid search, new probes, and new feature extraction.

## Context Read

- `AGENTS.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/FEATURE_SCHEMA.md`
- `docs/PROTOTYPE_V0_1.md`
- `docs/LEGACY_AUDIT.md`
- `docs/DECISION_LOG.md`
- `docs/EVALUATION_PROTOCOL.md`
- `src/vulnspider/domain/models.py`
- `src/vulnspider/observation/planner.py`
- `src/vulnspider/observation/executor.py`
- `src/vulnspider/features/extraction.py`
- current unit tests and quality-check scripts

## Current State

05B emits a `FeatureVector` owned by one exact `InputPoint`. Its implemented
features are `status_code_changed`, `response_length_diff_ratio`,
`marker_reflected`, and `sql_error_pattern`. Candidate and evidence domain
models exist, but candidate generation and scoring do not.

## Proposed Changes

1. Minimally extend `ScoreEvidence` so missing values and scorer type are
   explicit.
2. Add immutable, independent SQLi and XSS scoring policies that consume only
   current `FeatureObservation` values.
3. Generate both candidate interpretations using only
   `FeatureVector.input_point_id` as the ownership source.
4. Add focused adversarial tests for identity, isolation, determinism,
   missing-data semantics, arithmetic, ownership, and immutability.

## Interfaces / Data Changes

- `ScoreEvidence.feature_value` and `contribution` allow `None` only for
  unavailable evidence.
- `ScoreEvidence` records `observed`, `vulnerability_type`, and exact
  `feature_vector_id` provenance.
- The scoring package exposes `SQLiScorer`, `XSSScorer`, a result container,
  and candidate generation from one `FeatureVector`.

## Safety / Scope Impact

No network, request, probe, response parsing, or scope behavior changes. The
implementation is deterministic and constructs new downstream objects without
mutating upstream observations.

## Test Plan

- Unit tests for scorer arithmetic and cross-type feature isolation.
- Adversarial repeated-occurrence and equal-value identity tests.
- Missing, execution-failure-derived missing, and all-missing evidence tests.
- Determinism, ownership mismatch prevention, candidate type separation, and
  source immutability tests.
- Full unit suite plus repository format, lint, and type-hint checks.

## Acceptance Criteria

- [x] One vector generates distinct SQLi and Reflected XSS candidates.
- [x] Candidate ownership is derived only from the vector owner.
- [x] Repeated occurrence identities never collapse.
- [x] Missing evidence cannot appear as observed zero.
- [x] Type-specific features cannot contaminate the other scorer.
- [x] Present contributions exactly reconstruct the rank score.
- [x] Rank score remains a prioritization signal, not confidence or a finding.
- [x] Full quality gate passes.

## Progress Log

- 2026-07-10: Confirmed clean `0ba93ab` preflight and read repository contracts.
- 2026-07-10: Selected the documented weights for the subset implemented by
  05B; no unavailable features will be fabricated.
- 2026-07-10: Implemented independent scorers and candidate generation with
  exact FeatureVector provenance and missing-aware evidence.
- 2026-07-10: Passed 15 focused scoring tests, the full 151-test suite, and the
  configured format, lint, and type-hint checks.

## Decision Log

- Decision: Use raw weighted sums with maximum available scores of 75 for SQLi
  and 45 for XSS.
- Reason: The broader documented v0.1 policies include features not implemented
  by 05B. Renormalization would change their meaning and missing terms must not
  be fabricated.
- Decision: A missing term has `feature_value=None`, `observed=False`, and
  `contribution=None`; it adds no numeric evidence.
- Reason: This preserves the required distinction from an observed zero.

## Open Questions

- None.
