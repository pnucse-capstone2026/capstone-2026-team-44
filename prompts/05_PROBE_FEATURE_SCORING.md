# Prompt 05 — Vertical Slice: Probe -> Feature -> Score -> Top-K

Read:

- `AGENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/FEATURE_SCHEMA.md`
- `docs/PROTOTYPE_V0_1.md`
- `docs/EVALUATION_PROTOCOL.md`
- `CODE_REVIEW.md`

Create an execution plan under `docs/exec-plans/active/` before coding.

## Goal

Implement the smallest end-to-end v0.1 vertical slice from normalized InputPoint to explainable SQLi/XSS Top-K JSON.

## Required components

1. `ProbePlanner`
2. pluggable `RequestExecutor` interface
3. `ResponseNormalizer`
4. feature extractors from `docs/FEATURE_SCHEMA.md`
5. `CandidateGenerator`
6. `SQLiScorer`
7. `XSSScorer`
8. `TopKSelector`
9. JSON reporter

## Mandatory probe invariant

A probe changes exactly one target InputPoint while preserving all other request values.

Add tests that fail if two fields change.

## HTTP behavior

- Preserve 4xx/5xx as ResponseSnapshot data.
- Do not use crawler-style `raise_for_status()` semantics for observations.
- Keep network I/O behind an interface.
- Unit tests must use fake executors/fixtures.
- Redirect targets must be scope-checked by the caller/boundary design.

## Feature requirements

Implement the stable subset first:

- numeric_value
- status_code_changed
- response_length_diff_ratio
- response_time_diff_ratio
- redirect_changed
- marker_reflected
- reflection_count_norm
- sql_error_pattern

Implement `safe_html_encoding_detected` only if you can define and test it consistently with `docs/FEATURE_SCHEMA.md`. Do not guess context.

## Scoring requirements

- independent SQLi and XSS scorers,
- missing feature contributes 0 but is not treated as a safe observation,
- every non-zero contribution creates ScoreEvidence,
- preserve scorer version,
- use documented baseline weights,
- score is priority, not probability.

## Selection

Default to Top-K per vulnerability type.

## JSON

Include:

- candidate identity
- input point summary
- vulnerability type
- rank score
- scorer version
- score evidence
- feature schema version

## Tests

At minimum:

- one-at-a-time probe mutation
- 500 response retained
- marker reflected positive/negative
- baseline SQL error not counted as new probe SQL signal
- probe-only SQL error counted
- missing vs zero
- score contribution sum
- same InputPoint produces separate SQLi/XSS candidates
- type-specific Top-K
- deterministic JSON serialization where practical

## Done when

- unit tests pass,
- type checks pass,
- lint/format checks pass,
- one local integration smoke test or deterministic fake-executor end-to-end test demonstrates:

```text
InputPoint -> Probe -> ResponsePair -> Features -> Candidates -> Scores -> Top-K JSON
```

- execution plan progress is updated,
- diff is self-reviewed against `CODE_REVIEW.md`.

Do not add LLM, BAC, dashboard, exploit verification, browser crawling, or grid search.
