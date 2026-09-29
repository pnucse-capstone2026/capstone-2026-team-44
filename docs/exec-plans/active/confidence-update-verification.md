# Confidence-update focused verification

## Goal

Add the final v0.2 pipeline stage: for the ranked Top-K, propose same-family
*variant* payloads, gate them through a mandatory deterministic validator,
re-send the accepted ones against the loopback target, re-collect a feature
vector, difference it against the baseline vector, and update each candidate's
confidence by a reviewed rule set. Small feature difference keeps the
confidence; a large, vulnerability-specific difference raises it (a genuine
weak point the baseline probe under-suspected) or lowers it (the app defends
the context); a large change without a type-specific signal is treated as a
generic error and keeps the prior.

Implements the `VerificationResult` contract (`docs/TEAM_INTERFACES_V0_2.md`
§3) and `docs/PROTOTYPE_V0_2.md` §4.3–4.4.

## Non-Goals

- No real GPT/Gemini network client. The proposer boundary is provider-neutral
  and ships with the deterministic (no-model) provider; a model client is a
  drop-in behind the same validator gate (its own milestone, needs the API
  comparison harness and key handling).
- No BAC verification (BAC has no observation pipeline yet, ADR-014).
- No new HTML report; the verification artifact is JSON only for now.
- No change to the frozen v0.1 output, the analysis report, or the decision
  report. Verification is strictly additive and opt-in.

## Context Read

- AGENTS.md (safety rules, domain rules 6/7, validator gate)
- docs/PROTOTYPE_V0_2.md §4.3–4.4, §5 non-goals
- docs/TEAM_INTERFACES_V0_2.md §2 (RankedCandidateContext), §3 (VerificationResult)
- docs/FEATURE_SCHEMA.md (missing != observed zero)
- src/vulnspider/observation, features, scoring/calibration, selection, pipeline

## Current State

The pipeline ends at ranked selection + a calibrated-probability Top-K report
(`analyze`, `-u`). `AnalysisResult` already retains the baseline `FeatureVector`
per InputPoint and the executed baseline/probe `ProbePlan` (with its baseline
`RequestInstance`) per observation, which is everything verification needs to
re-probe without touching discovery.

## Proposed Changes

New package `src/vulnspider/verification/`:

1. `proposal.py` — `MutationFamily` (HTML_SENTINEL / SQL_META / BOUNDARY),
   `PayloadProposal`, provider-neutral `PayloadProposer` protocol, and the
   default `DeterministicMutationProposer`.
2. `validator.py` — mandatory `PayloadValidator`: allowlisted family per type,
   bounded length, printable-ASCII only, no stacked query, no destructive SQL
   keyword; fixed rejection taxonomy; `ValidatedPayload` only for acceptances.
3. `planner.py` — `plan_verification_probe`: inject one validated value into the
   target parameter of the baseline request, one-at-a-time.
4. `delta.py` — `compute_feature_delta`: baseline vs re-probe, per feature,
   with material-change and observability-flip semantics.
5. `confidence.py` — `update_confidence`: the reviewed rule set producing
   `VerificationConfidence` from the delta and a calibrated-probability prior.
6. `result.py` — the `VerificationResult` record + `to_dict`.
7. `focused.py` — orchestrator: build targets from `AnalysisResult`, run
   propose→validate→re-probe→delta→confidence, aggregate per candidate.

CLI: additive opt-in `--verify` / `--verify-output` on `analyze` and simple
`-u`, writing a separate `vulnspider-verification.json`.

## Interfaces / Data Changes

- New `VerificationResult` producer record (contract §3), JSON-serialized.
- No change to `AnalysisResult`, the analysis report, or the decision report.
- New CLI flags are additive; default behavior is unchanged.

## Safety / Scope Impact

- Network scope/payload-execution change → two-reviewer item (AGENTS.md).
- Loopback-only guard re-checked before every verification request.
- No model payload executes before the deterministic validator accepts it; a
  rejected proposal provably has no execution (enforced in `from_objects`).
- Payloads are read-only: no stacked queries, no destructive keywords, no
  state change; one parameter changes per probe (ADR-004).
- RankScore never enters confidence; the prior is the calibrated probability
  (a pre-verification probability, ADR-022), not the raw score (rules 6/7).

## Test Plan

- unit: proposer families/determinism/bounds; validator accept + every reject
  reason; planner query/form injection; delta material vs artifact flips;
  confidence keep/raise/lower/error/not-executed and (0,1) bounds; result
  ownership invariants (rejected ⇒ no execution); orchestrator across four
  scripted servers; a malicious proposer whose destructive payload is rejected
  and never sent.
- CLI: `analyze --verify` writes the report; output-collision rejected; no flag
  ⇒ no report.

## Acceptance Criteria

- [x] Provider-neutral proposal boundary with a deterministic default.
- [x] Mandatory deterministic validator with a fixed rejection taxonomy.
- [x] Re-probe reuses the v0.1 executor and feature extractor.
- [x] Feature delta + reviewed confidence rules (keep/raise/lower/error).
- [x] `VerificationResult` record + JSON report.
- [x] Opt-in CLI, no change to frozen output.
- [x] Narrow + full checks pass.
- [ ] Independent Gate Review PASS / PASS WITH MINOR.

## Progress Log

- 2026-08-18: Implemented the `verification/` package, CLI opt-in, and tests;
  full unit suite (682) + format/lint/type checks green. Pending Gate Review.
- 2026-08-18 (phase 2, ADR-033): replaced the hand-picked confidence constants
  with a corpus-calibrated per-(family, signal) LLR model
  (`verification/calibration.py`), capped so the score moves gently. Added the
  verification corpus label/protocol (`corpus/verification_collection.py`,
  `verification-corpus-v1`) and the out-of-fold Brier evaluation arm
  (`corpus/verification_fitting.py`), reachable through `corpus verify-collect`
  / `corpus verify-fit`. Folded the updated confidence into the final HTML
  report as the headline score (`reporting/decision_html_report.py`), fed by
  running verification before the report. Full unit suite (697) + checks green.

## Decision Log

- Decision: the prior for the confidence update is the calibrated probability
  from the heuristic prior, not `RankScore`.
  Reason: domain rules 6/7 keep RankScore and confidence independent; ADR-022
  authorizes the calibrated probability as a pre-verification prior.
- Decision: the discriminating signal, not the size of the change, decides
  genuine-vulnerability vs generic-error.
  Reason: response length/status move under any payload; only `sql_error_pattern`
  (SQLi) and raw reflection (XSS) distinguish a weakness from error handling.

## Open Questions

- Should a reproduced signal (baseline already suspected) nudge confidence up a
  little, or strictly keep it? **Resolved (ADR-033):** made data-driven — the
  corpus decides via the SUPPORT_REPRODUCED LLR; the default keeps it (0.0).
- HTML verification report and wiring into the decision report. **Resolved
  (ADR-033):** the HTML report now leads with the post-verification confidence.
  Folding the updated score into the decision **JSON** report is still open.
- Single end-to-end dashboard vs separate files. **Resolved (ADR-034):** the
  HTML dashboard is the primary report (`-u` writes it by default) and the
  decision JSON now carries the same post-verification confidence; JSONs remain
  machine-readable exports.
- INCONCLUSIVE_ERROR over-generation. **Resolved (ADR-034):** gated on a real
  error (transport failure or payload-induced 5xx); length/non-5xx differences
  stay UNCHANGED.
- Remaining: request budget/rate-limit/baseline-reuse (out of scope this round);
  a real labeled verification corpus and live `verify-collect` loopback
  integration; real Brier-improvement measurement; cap/smoothing hyperparameter
  selection; a real GPT/Gemini proposer; whether `analyze` should also default
  to HTML and make the JSON export optional.
