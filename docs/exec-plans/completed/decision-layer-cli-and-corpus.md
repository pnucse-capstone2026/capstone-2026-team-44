# Decision Layer — CLI Surface and Labeled Corpus

## Goal

Close the two gaps left by `decision-layer-algorithms.md`:

1. The decision layer was reachable only programmatically.
2. Layer 1's weights and Layer 3's guarantee had no data behind them.

Both are closed by the same work: commands that run the layer, and a corpus
collected by running the real pipeline against labeled targets.

## Non-Goals

- Changing `analyze`, `-u/--url`, or any of their flags. ADR-025 adds commands.
- Scanning anything that is not an authorized loopback target.
- Standing up DVWA/WebGoat/Juice Shop containers. The collector works against
  any authorized target, but automating third-party containers needs Docker and
  its own decision.
- Adding dependencies. Still standard library only.

## Context Read

- `AGENTS.md` — frozen v0.1 surface, loopback-only safety rules.
- `docs/DECISION_LOG.md` — ADR-017, ADR-021, ADR-022, ADR-023, ADR-024.
- `docs/EVALUATION_PROTOCOL.md` §3 ground truth key, §4 leakage, §8 seeds.
- `src/vulnspider/cli.py`, `src/vulnspider/pipeline.py`.

## Current State

Before this phase: `decision/` and `scoring/calibration.py` existed with 118
tests, worked from the heuristic prior, and had no CLI entry point and no
corpus.

## Proposed Changes

### `corpus/`

- `ground_truth.py` — the §3 key, a store, JSON IO. Absent means unlabeled.
- `collection.py` — join an `AnalysisResult` to ground truth, JSON Lines IO in
  canonical order, `CorpusDataset` with leave-one-application-out.
- `fitting.py` — per-family fitting, out-of-fold prediction, conformal
  calibration, Brier/ECE against the heuristic baseline.

### `cli_decision.py` and four commands

`decide`, `corpus collect`, `corpus fit`, `corpus calibrate`. Registered on the
existing parser; `cli.py` gains an import, a registration call, and a dispatch
block.

### `tools/`

- `corpus_target_site.py` — generated loopback labeled applications.
- `build_corpus.py` — collect, fit, calibrate in one run.

## Interfaces / Data Changes

New: `vulnspider.corpus`, `vulnspider.cli_decision`. Added to existing classes:
`CalibratedScorer.as_mapping`/`from_mapping`, `ConformalThreshold.as_mapping`/
`from_mapping`. No existing signature or invariant changed.

## Safety / Scope Impact

Targets stay loopback-only; the generated applications bind 127.0.0.1 on an
ephemeral port. `decide` and `corpus collect` run the same bounded discovery and
Light Probe path `analyze` already uses. No new payloads, no state-changing
verification.

## Test Plan

- unit: ground truth normalization, absent-is-unlabeled, store validation, JSON
  round trips, schema rejection.
- unit: collection joins only observed features, reports unlabeled keys, skips
  candidates with no observed feature, rejects dangling references.
- unit: canonical write order, append, malformed line rejection.
- unit: fitting under quasi-complete separation stays bounded (regression),
  beats the base-rate Brier, can contradict the prior's sign, out-of-fold never
  sees its own group, model JSON round trip.
- unit: CLI commands end to end on fake transports; frozen surface still parses;
  every error path returns a non-zero code without a traceback.

## Acceptance Criteria

- [x] Decision layer reachable from the CLI without touching frozen commands.
- [x] Real corpus collected by running the real pipeline.
- [x] Models fitted and conformal threshold calibrated from that corpus.
- [x] Calibration quality measured against the heuristic baseline.
- [x] Artifacts byte-reproducible from a seed.
- [x] Zero new dependencies; pre-existing test failures unchanged.

## Progress Log

- 2026-08-11: `corpus/` and `cli_decision.py` implemented; four commands wired.
- 2026-08-11: Corpus collected — 14 applications, 146 samples (36 vulnerable).
  Fitted models and calibrated a conformal threshold at target recall 0.90.
- 2026-08-11: 56 new tests (39 corpus, 17 CLI). Unit suite 579 tests; the same
  7 pre-existing `test_combined_pipeline_cli` errors remain, caused by an
  argparse prefix collision between the top-level `--dynamic-allow-*` options
  and `analyze --dynamic`, confirmed present on the clean tree.
- 2026-08-11: ADR-025 recorded; `AGENTS.md`, `ARCHITECTURE.md`,
  `EVALUATION_PROTOCOL.md` updated with the measured results.

## Decision Log

- Bug found and fixed: `fit_calibrated_scorer` diverged on the real corpus.
  Undamped Newton runs away under quasi-complete separation — no vulnerable
  XSS candidate ever had `marker_reflected = 0`, so that weight grew without
  bound, the working variance collapsed, and each step overshot further. The
  first fitted model had an intercept of +29.8 and a Brier score of 0.46,
  worse than a constant predictor. Fixed with backtracking line search
  requiring every accepted step to increase the log posterior. Brier went
  0.4598 -> 0.1134. Regression test added.
  This was only visible because the corpus was real; the synthetic fixtures in
  the earlier phase were never separable enough to trigger it.
- Bug found and fixed: `build_application` sampled from
  `list(_SQLI_TRUE | _XSS_TRUE)`, a set of strings whose iteration order varies
  with the interpreter hash seed, so an identical `--seed` produced a different
  corpus per run. Replaced with explicit ordered tuples.
- Corpus files are written in canonical sorted order. Discovery does not
  guarantee stable traversal order, so without this an identical seed produced
  files differing only by line order.
- The XSS families are deliberately left indistinguishable by the current
  feature set. `xss_raw` and `xss_escaped` both set `marker_reflected = 1`, so
  the fitted `P(XSS | reflected)` is around 0.3 rather than near 1. Rigging the
  fixture to separate them would have produced a flattering model that the
  real feature set cannot deliver.

## Open Questions

- When does the corpus move to DVWA / WebGoat / Juice Shop? The collector needs
  no change; it needs those applications running and a ground truth file each.
  Until then no result here generalizes to real applications.
- `data/corpus/` is committed so results are checkable. Revisit if it grows.
