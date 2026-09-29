# Ranking Evaluation Metrics and Comparison Arms

## Goal

`EVALUATION_PROTOCOL.md` §6 names Recall@K, Precision@K, MAP@K and NDCG@K as
the core measures and §5 defines Baselines A/B/C, but nothing computed them.
The branch could improve the ranking without being able to state the
improvement in the protocol's own language. This closes that.

## Non-Goals

- Wiring value-of-information into the CLI. Deferred by the user; metrics come
  first so its effect can be measured rather than asserted.
- The Naive Bayes ablation arm.
- Real applications. Numbers here are from the synthetic corpus.

## Context Read

- `docs/EVALUATION_PROTOCOL.md` §5, §6, and the new §6-A.
- `src/vulnspider/corpus/`, `src/vulnspider/scoring/calibration.py`.

## Current State

Before: Brier/ECE (calibration quality) and a held-out recall/request tool
existed. No ranking metric, no baseline implementation.

## Proposed Changes

- `docs/EVALUATION_PROTOCOL.md` §6-A — the five judgment rules, decided before
  any code so results could not be tuned by redefining the measure.
- `evaluation/metrics.py` — the four metrics, pure, with exact tie expectations.
- `evaluation/baselines.py` — Baselines A/B/C/D, the proposed arm, bug-level
  route aggregation.
- `tools/evaluate_ranking.py` — the comparison table.

## Interfaces / Data Changes

New package `vulnspider.evaluation`. Nothing existing changed.

## Safety / Scope Impact

None. `evaluation` performs no I/O and `metrics` imports only the standard
library.

## Test Plan

- Hand-computed worked examples for every metric.
- Closed-form tie handling checked against exhaustive permutation enumeration.
- Invariants: Recall@K monotone in K, Recall@N = 1, NDCG in [0,1], perfect
  ranking scores 1, reversed ranking scores less.
- Baseline B identity: Precision@K equals prevalence at every K.
- Degenerate cases: no positives, all positives, K > n, unlabeled items.

## Acceptance Criteria

- [x] Four metrics implemented per §6-A.
- [x] Ties handled by expectation, verified against exhaustive enumeration.
- [x] Baselines A/B/C/D and the proposed arm measured by identical code.
- [x] Proposed arm scored strictly out-of-fold.
- [x] Comparison table produced and recorded in §8-C.

## Progress Log

- 2026-08-11: §6-A written first, then `evaluation/` implemented, 26 tests.
- 2026-08-11: Comparison table produced. Proposed beats Baseline D on every
  metric at every K; MAP@10 0.692 -> 0.894, NDCG@10 0.804 -> 0.939. Recorded
  in §8-C with the caveats.
- 2026-08-11: Unit suite 605 tests; the 7 pre-existing
  `test_combined_pipeline_cli` errors are unchanged.

## Decision Log

- Correction made before writing the doc: the plan originally claimed
  `/product?id=1..100` inflates candidate counts. It does not -- those share a
  `canonical_path` and an `InputPoint`, so the domain model already collapses
  them. The real inflation is **path-segment** templating (`/product/1`,
  `/product/2`), which `canonical_path()` deliberately does not normalise.
  §6-A rule 1 and `normalize_route()` reflect the corrected analysis.
- Ties are reported as expectations, not resolved by `candidate_id`.
  Inheriting selection's tie-break would make `Recall@K` depend on a hash.
- Baseline B is implemented as a single tie group rather than a seeded shuffle.
  It is exact rather than sampled, and its Precision@K must equal the
  prevalence, which turns the baseline into a correctness check for the tie
  machinery.
- Metrics take no dependency on `selection` or `corpus` types. Any arm measured
  by code that knows which arm it is would be suspect.
- Test verification uses exhaustive permutation enumeration rather than Monte
  Carlo. Exact to 9 decimals and roughly 900x faster than the sampling version
  it replaced.

## Open Questions

- K=10 is a saturation point for this corpus (8-14 candidates per application),
  so K=1 and K=3 carry the signal. Real applications with more input points
  will need larger K to be informative.
