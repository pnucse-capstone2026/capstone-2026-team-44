# Decision Layer — Calibrated Scoring, Budgeted Selection, Conformal Set Size

## Goal

Move the project's algorithmic contribution from the scoring layer (hand-tuned
weighted sum) to a **decision layer** that answers three questions the current
pipeline cannot:

1. *How likely is this candidate vulnerable?* — a calibrated probability instead
   of an uncalibrated priority number.
2. *Given a request budget, what should we verify and in what order?* — a
   budget-constrained sequential policy with an approximation guarantee, instead
   of a fixed Top-K.
3. *How many candidates should we select?* — a distribution-free recall
   guarantee, instead of a human-chosen `k`.

## Non-Goals

- Replacing or removing the existing heuristic scorers. They stay, and become
  the **prior** of the calibrated model.
- Changing `RankScore`, `selection_priority`, `select_top_k()`,
  `select_combined_top_k()`, or `build_mutation_handoff()` behavior. The
  decision layer is additive and consumes their validated output.
- Wiring the decision layer into `cli.py` / `pipeline.py` default paths. That
  touches the frozen v0.1 path and needs its own reviewed change.
- Adding third-party dependencies. `pyproject.toml` declares `dependencies = []`
  and every numeric routine here is implemented in the standard library.
- Collecting the labeled corpus. The layer works from prior alone when no
  training data exists; corpus collection is separate work.

## Context Read

- `AGENTS.md` — frozen v0.1 scope, non-negotiable domain rules 6/7/8/9,
  "Future / Deferred: ML ranker or automatic weight search".
- `docs/DECISION_LOG.md` — ADR-003, ADR-010, ADR-016, ADR-021.
- `docs/EVALUATION_PROTOCOL.md` — Recall@K / MAP@K / request-budget metrics.
- `docs/FEATURE_SCHEMA.md` — missing-vs-zero rule, implemented feature subset.
- `src/vulnspider/scoring/engine.py`, `src/vulnspider/access/scoring.py`,
  `src/vulnspider/selection/top_k.py`, `src/vulnspider/selection/combined.py`.

## Current State

`scoring/engine.py` computes `rank_score = Σ wᵢ·fᵢ` with weights fixed by hand
(`SQLI_TERMS` 20/20/35, `XSS_TERMS` 35/10, `ACCESS_TERMS` 55/20).
`selection/top_k.py` divides that raw score by the scorer's own maximum to get
`selection_priority`, and `selection/combined.py` merges three families by that
quotient (ADR-010, ADR-021). The pipeline is one-shot: one baseline + one probe
per input point, then a fixed Top-K. There is no cost model, no budget input,
and no principled basis for comparing a 0..75 SQLi score with a 0..45 XSS score.

## Proposed Changes

### Layer 1 — `scoring/calibration.py`

Bayesian logistic regression over the same `FeatureObservation` inputs.

- `CalibrationFeatureSpace` fixes a deterministic feature ordering per family.
- `LogisticPrior` centers the Gaussian prior on the **existing heuristic
  weights** scaled into logit space, so the current scorer is exactly the
  zero-data special case.
- `fit_calibrated_scorer()` finds the MAP weights by Newton/IRLS with the
  prior's precision as the ridge term, then takes a Laplace approximation for
  the posterior covariance.
- `CalibratedScorer.probability()` returns a probability, a logit mean and
  variance, and per-feature evidence in logits and decibans.
- Missing features are dropped from the logit sum — the same discipline
  `engine.py` already applies, now with a principled reading ("no evidence
  observed" leaves the posterior at the prior).
- `fit_naive_bayes_llr()` provides the simpler log-likelihood-ratio estimator
  as an ablation arm, and supplies the class-conditional rates Layer 2b needs.

### Layer 2 — `decision/`

- `cost.py` — `VerificationCost` (requests per candidate per family) and
  `SeverityPolicy`; both are explicit, versioned policy objects.
- `greedy.py` — budgeted selection maximizing
  `U(S) = Σ_families Σ_j γ^(j-1)·p·severity` subject to `Σ cost ≤ B`.
  The per-family discount `γ` makes `U` monotone submodular (same code path →
  correlated findings → diminishing marginal value), so density-greedy guarded
  by the best affordable single item attains `½(1 − 1/e)·OPT`. With `γ = 1.0`
  the utility is modular and the same procedure is a `½`-approximation.
- `voi.py` — expected information gain per probe,
  `EIG = H(p) − E_o[H(p|o)]`, ranked by `EIG / cost`. The likelihood rates come
  from Layer 1, which is what makes the two layers compose.
- `conformal.py` — conformal risk control. Picks the largest probability
  threshold whose empirical risk satisfies `R̂(λ) ≤ α − (1 − α)/(n+1)`, giving
  `E[1 − Recall] ≤ α` on an exchangeable calibration set.
- `policy.py` — the sequential loop: score, spend budget on the highest
  information-gain probes, update posteriors, then commit the remainder through
  the budgeted greedy and cut the set at the conformal threshold.

## Interfaces / Data Changes

New, additive only:

- `vulnspider.scoring.calibration` — `CalibratedScorer`, `CalibratedProbability`,
  `CalibrationEvidence`, `LogisticPrior`, `TrainingSample`, `fit_calibrated_scorer`,
  `fit_naive_bayes_llr`, `heuristic_prior_for`.
- `vulnspider.decision` — `DecisionCandidate`, `BudgetedSelection`,
  `ProbeInformationGain`, `ConformalThreshold`, `DecisionOutcome`,
  `run_decision_layer`.

No existing signature, field, or invariant changes. `VulnerabilityCandidate`,
`ScoringResult`, `SelectionOutcome`, and `MutationHandoff` are untouched.

## Safety / Scope Impact

None to network behavior. The decision layer performs no I/O: `policy.py` takes
an injected `ProbeOutcomeSource` callable and the tests supply a deterministic
fake. Budgets can only *reduce* the number of verification requests relative to
today's fixed Top-K. No new payloads, no state-changing verification.

## Test Plan

- unit: prior-only calibration reproduces heuristic ordering; IRLS recovers
  known weights on separable and non-separable synthetic data; missing features
  leave the logit unchanged; probability stays in `(0, 1)`.
- unit: greedy respects the budget; beats or matches best-single; the
  submodular discount changes family concentration; exhaustive brute-force
  comparison on small instances confirms the claimed approximation ratio holds.
- unit: EIG is zero for an uninformative probe, maximal at `p = 0.5`, never
  negative; ranking is by information density not raw gain.
- unit: conformal threshold achieves the target risk on held-out groups;
  degenerate cases (no positives, all positives, single group) behave as
  documented.
- unit: end-to-end policy is deterministic, budget-respecting, and never
  fabricates a candidate the selection layer did not produce.
- negative: every validated factory rejects malformed input, matching the
  existing `SelectionError` / `ScoringError` discipline.

## Acceptance Criteria

- [x] Calibrated probability replaces `raw/max` as the cross-family comparison
      key, with the heuristic preserved as prior.
- [x] Budget-constrained selection with a stated and tested approximation bound.
- [x] Value-of-information probe ordering driven by the Layer 1 likelihood.
- [x] Conformal recall guarantee determining the selected set size.
- [x] Zero new dependencies; pure standard library.
- [x] Existing tests still pass unchanged.
- [x] ADRs recorded for the semantics that change.

## Progress Log

- 2026-08-11: Plan written. Layers 1-3 implemented in `scoring/calibration.py`
  and the new `decision/` package, with 5 new unit-test modules (118 tests).
- 2026-08-11: Checks run. `check_format.py`, `check_lint.py`,
  `check_types.py`, and `git diff --check` all pass. `unittest discover -s
  tests/unit` reports 523 tests with 7 errors, all in
  `tests/unit/test_combined_pipeline_cli.py`. Those 7 were confirmed
  pre-existing by stashing this branch's changes and re-running on the clean
  tree; they are untouched by this work. Full `discover -s tests` additionally
  aborts during Windows temp-directory cleanup in the dynamic e2e integration
  test, also pre-existing and also unrelated.
- 2026-08-11: Two claims corrected during implementation, both found by tests
  contradicting the docstring rather than the reverse. See the Decision Log.
- 2026-08-11: ADR-022, ADR-023, ADR-024 recorded; `AGENTS.md`,
  `ARCHITECTURE.md`, `EVALUATION_PROTOCOL.md`, `FEATURE_SCHEMA.md`, and
  `TEAM_INTERFACES_V0_2.md` updated.

## Decision Log

- Decision: the existing heuristic weights become the prior mean of the
  Bayesian model rather than being discarded.
  Reason: the zero-data posterior then reproduces today's ranking exactly, so
  the change is safe with no corpus, and the thesis can present the rule-based
  scorer as a special case rather than as a rejected alternative.
- Decision: utility is submodular by family discount rather than purely
  additive.
  Reason: an additive utility under a knapsack constraint only supports a `½`
  bound and does not model the real redundancy between input points sharing a
  code path. The discount is domain-motivated and earns the `½(1 − 1/e)` bound.
- Decision: the decision layer is a new package instead of an edit to
  `selection/`.
  Reason: `selection/` is an owner boundary with a published contract
  (ADR-017, ADR-021). Consuming its validated output preserves that contract.
- Correction: the initial docstring claimed the calibrated *probability*
  reproduces the heuristic ranking with no training data. It does not. The
  exact property is that `logit_mean` is affine in `RankScore`;
  `probability` additionally damps by posterior variance and can reorder.
  Both behaviors are now tested separately.
- Correction: the initial docstring claimed a score backed by more observed
  features is damped less. The opposite is true under the prior, because
  `Var(logit) = Var(intercept) + Σ fᵢ²·Var(wᵢ)` grows with each active
  feature. Damping only becomes informative after fitting, where a
  well-determined weight earns a small variance. Tested both before and after
  fitting.

## Open Questions

- Which apps form the calibration corpus, and is leave-one-app-out enough for
  the conformal exchangeability assumption to be defensible? Recorded as a
  stated limitation in `EVALUATION_PROTOCOL.md` until measured.
- Should `cli.py` expose `--budget` / `--target-recall`? Deferred: it changes
  the frozen v0.1 command surface and needs its own ADR.
