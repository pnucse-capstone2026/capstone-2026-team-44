# VulnSpider Architecture

## Status model

This document separates code that exists from architecture that is authorized
but not yet implemented.

- **Implemented:** merged in `prototype/v0.1`.
- **Planned for v0.2:** authorized target architecture.
- **Proposed Contract:** cross-owner interface awaiting implementation.
- **Experimental:** bounded research work whose outcome is not guaranteed.
- **Deferred:** explicitly outside the current milestone.

## 1. Implemented Prototype v0.1

### 1.1 Purpose

The completed v0.1 checkpoint ranks which discovered input points are worth
verifying first. It does not confirm vulnerabilities and does not run a native
crawler.

### 1.2 Actual execution path

```text
Legacy crawl-record JSON
  -> LegacyCrawlerAdapter
  -> Canonical Domain Models
       Endpoint
       InputPoint
       RequestTemplate
       InputPointRequestContext
  -> Probe Planning / Execution
       baseline request
       one-at-a-time Light Probe
  -> Minimal Feature Extraction
       status_code_changed
       response_length_diff_ratio
       marker_reflected
       sql_error_pattern
  -> SQLi / Reflected XSS Scoring
  -> normalized global Top-K
       selection_priority
  -> JSON report
  -> optional HTML report
```

The frozen compatibility CLI boundary remains
`vulnspider analyze --input <legacy-records.json>`. The advanced implemented
v0.2 boundary also accepts `analyze --url`: it uses Native Static Discovery by
default and adds combined Native Dynamic Discovery only with explicit
`--dynamic` plus caller-owned exact authority. The thin user adapter
`vulnspider -u URL` calls that same `analyze_url()` pipeline with Dynamic
enabled by default; `--static-only` selects the existing Native Static path.
Both analysis paths execute probes only against localhost/loopback targets.

### 1.3 Implemented boundaries

#### Canonical domain models

`domain/models.py` implements stable identities and validation for:

- `Endpoint`
- `InputPoint`
- `RequestTemplate`
- `InputPointRequestContext`
- `RequestInstance`
- `ProbePlan`
- `ResponseSnapshot` and `ResponsePair`
- `FeatureObservation` and `FeatureVector`
- `VulnerabilityCandidate`
- `ScoreEvidence`

`Page`, `Endpoint`, `InputPoint`, and `VulnerabilityCandidate` remain distinct.
The observation unit is an `InputPoint`; the SQLi/XSS ranking unit is
`InputPoint x VulnerabilityType`.

#### Legacy discovery adapter

`discovery/legacy_adapter.py` is a pure conversion boundary. It does not execute
the legacy crawler or import the legacy database runtime. It converts stored
records into canonical v0.1 models while preserving ordered/repeated query
pairs, occurrence identity, form provenance, completeness, and warnings.

There is no native `DiscoveryCollector` in the frozen v0.1 path. The current
v0.2 implementation produces `CanonicalDiscoveryResult` through Native Static,
Native Dynamic, and deterministic combined collectors without changing the
legacy adapter contract.

#### Probe planning and execution

`observation/` builds one baseline and one probe for a validated
`InputPointRequestContext`. Only one target occurrence changes. The executor
preserves request and response ownership, treats HTTP errors as observations,
and records transport failures as missing observation state.

The loopback restriction currently lives at the v0.1 pipeline boundary. There
is no implemented general `ScopeGuard` with crawl budgets or redirect policy.

#### Feature extraction, scoring, and selection

`features/` emits the four implemented minimal features. `scoring/` creates
independent SQLi and Reflected XSS candidates and explainable
`ScoreEvidence`. `selection/` preserves raw RankScore and uses the exact scorer
maximum to derive deterministic cross-type `selection_priority`.

There is no implemented feature cache, ground-truth store, or automated
evaluation runner.

#### Decision layer

`scoring/calibration.py` and `decision/` add a budget-aware layer *above*
selection (ADR-022, ADR-023, ADR-024). It consumes the validated
`RankedCandidateContext` handoff and recomputes nothing.

- `scoring/calibration.py` — Bayesian logistic regression producing a
  calibrated `P(vulnerable | evidence)`. The existing heuristic weights are the
  prior mean, so the zero-data `logit_mean` is an affine transform of
  `RankScore` and reproduces the heuristic order exactly.
- `decision/cost.py` — explicit, versioned verification cost and severity
  policy. Values are documented policy, not measurement.
- `decision/greedy.py` — selects the K most vulnerable input points.
  "Vulnerability" is the calibrated probability; severity does not multiply in
  and only breaks ties through family order, SQLi then Reflected XSS then BAC
  (ADR-028). The default mode is a plain sort, which is the exact optimum, so
  `approximation_ratio` is 1.0. A request budget and a redundancy discount are
  opt-in for the different question of what a fixed number of requests buys;
  those regimes carry `½(1 − 1/e)` and `1 − 1/e` respectively, and no combined
  bound is claimed when both constraints bind. `binding_constraint` reports
  which limit stopped the selection.
- `decision/voi.py` — expected information gain per request, ordering which
  probe to run next. The likelihood rates come from `fit_naive_bayes_llr()`.
  **Dormant and not wired to the CLI (ADR-026):** one probe pair already
  yields every feature, no corpus candidate has an unobserved feature,
  probing is finished before the decision layer runs, and candidates are
  modelled independently, so there is currently no probing choice for it to
  make. Correlating candidates that share a code path, or adding probe
  families, would change that; both are modelling work with their own ADR.
- `decision/conformal.py` — conformal risk control fixing the selected set
  size from a target recall instead of a chosen `k`.
- `decision/policy.py` — the explore/cut/commit loop. Performs no I/O; probe
  outcomes arrive through an injected `ProbeOutcomeSource`.

#### Corpus and decision-layer CLI

`corpus/` owns the labeled corpus the calibrated scorer and the conformal
guarantee are estimated from (ADR-025).

- `corpus/ground_truth.py` — the `EVALUATION_PROTOCOL.md` §3 key and its store.
  An absent key is unlabeled, never negative.
- `corpus/collection.py` — joins a real `AnalysisResult`'s observed features to
  ground truth. Writes JSON Lines in canonical order so an identical seed
  produces an identical file.
- `corpus/fitting.py` — per-family fitting, leave-one-application-out
  out-of-fold prediction, conformal calibration, and calibration quality
  (Brier, ECE) against the heuristic baseline.

`cli_decision.py` owns the new subcommands. It is separate from `cli.py`
because ADR-025 adds commands without changing `analyze`, `-u`, or their flags:

```text
vulnspider decide            --url ... --top-k K [--budget N] [--model M] [--conformal C] -o R [--html-output H]
vulnspider corpus collect    --url ... --application-id A --ground-truth G -o C
vulnspider corpus fit        --corpus C -o M [--report Q]
vulnspider corpus calibrate  --corpus C --target-recall R -o T
```

`decide` ranks every candidate, then applies `--top-k` (required, the primary
control), an optional `--budget`, and an optional conformal threshold as
independent stopping conditions, reporting which one bound (ADR-027). With
`--html-output` it is the single command that goes from a URL to a browsable
report, which is what `analyze --html-output` does for the heuristic path.

`reporting/decision_html_report.py` renders the `DecisionOutcome`. Like the
v0.1 report it recomputes nothing and shows unobserved features as unobserved
rather than as zero. It shares the v0.1 stylesheet so both artifacts look like
one tool; that coupling is presentation-only.

`tools/corpus_target_site.py` generates the loopback labeled applications the
corpus is collected from, and `tools/build_corpus.py` runs the whole loop.
Collected artifacts live in `data/corpus/`.

#### Ranking evaluation

`evaluation/` implements `EVALUATION_PROTOCOL.md` §6 and the §6-A judgment
rules.

- `evaluation/metrics.py` — Recall@K, Precision@K, MAP@K, NDCG@K. Pure: a
  ranking and labels in, numbers out, with no knowledge of candidates or
  scorers, so every arm is measured by identical code. Ties are reported as the
  expected value under uniformly random within-group order rather than
  inheriting `selection`'s arbitrary `candidate_id` tie-break.
- `evaluation/baselines.py` — Baselines A/B/C/D and the proposed ranking, plus
  bug-level route aggregation. The proposed arm is scored strictly out-of-fold.
- `evaluation/live.py` — the same metrics over **one live scan** instead of a
  stored corpus (ADR-036): a random predictor, the pipeline with focused
  verification removed (calibrated prior order), and the shipped product
  (`final_confidence` order), all over the same candidates and labels. A corpus
  holds no verification evidence, so this is the only path that can measure the
  verification stage's contribution. Reached with `analyze --ground-truth`
  against a labeled target — `tools/demo_shop.py` (DemoShop, 100 input points).

`tools/evaluate_ranking.py` prints the comparison table for the corpus; the live
table is printed by the scan itself and written as `live-evaluation-v1` JSON.

Baseline B scores every candidate identically, so it is one tie group; the
metric machinery then yields the exact random expectation in closed form, and
its Precision@K must equal the prevalence. That identity is the implementation's
own correctness check.

#### Reporting

`reporting/json_report.py` and `reporting/html_report.py` consume the same
validated `SelectionOutcome`. Reporting does not recalculate scoring or
selection.

The optional HTML report joins selected results to the actual
`InputPoint`/`Endpoint` and baseline/probe provenance retained by the pipeline.
Untrusted text is escaped. `--output` and `--html-output` are normalized and
must refer to different destinations.

### 1.4 Package shells that are not implementations

`scope/` contains the internal shared loopback HTTP URL validator used at
active execution boundaries, while `surface/` remains a package shell. This
does not mean that a general `ScopeGuard`, native surface collector, or
separate `AttackSurfaceNormalizer` has been implemented.

#### Native discovery

`discovery/` implements bounded Static and Dynamic producers, strict request
authority, pre-canonical sensitive-form elision for combined mode, and a
deterministic Static-first merge. The advanced `analyze --dynamic` boundary
keeps exact caller grants. The simple adapter additionally permits only an
exact same-origin GET URL already extracted from a rendered anchor, for that
single crawler navigation, same-origin GET script/style resources, and naturally
emitted same-origin GET/HEAD fetch/XHR. An already-allowed primary-page GET
fetch/XHR can enter the separate network canonicalization path. A blocked
primary-page exact-origin POST fetch/XHR with `application/json` can enter only
the value-free structural branch at the same Guard decision seam. This path never
reconstructs from passive audit, never replays transport, and never retains raw
credential headers/cookies or sensitive query values. Safe query occurrences
produce normal READY contexts. Credential-bearing requests produce at most
value-free Endpoint/InputPoint structure with NOT_READY ownership and no
RequestTemplate/context. Eligible POST JSON produces only a POST Endpoint and
top-level JSON_BODY InputPoints with NOT_READY ownership; the request remains
blocked and body values are discarded before candidate retention. WebSocket,
EventSource, all POST transport, popup, child-frame documents, cross-origin,
and different-port traffic stay blocked.
`pipeline.analyze_url()` sends the validated combined
`CombinedDiscoveryResult.discovery` to the unchanged
`analyze_discovery_result()` consumer. Advanced plain `analyze --url` and
simple `--static-only` stay Static-only, while legacy `--input` cannot activate
browser code.

### 1.5 Implemented dependency direction

```text
cli -> pipeline + reporting + cli_decision
cli_decision -> pipeline + decision + corpus
pipeline -> discovery producers/adapter + observation + features + scoring + selection
reporting -> selection -> scoring -> features -> domain
evaluation -> corpus + decision + scoring + features
corpus -> decision + scoring + domain
decision -> selection -> scoring -> features -> domain
selection -> scoring -> features -> domain
observation -> domain
discovery adapter -> domain
```

Rules:

- `domain` does not depend on network, database, or LLM code.
- `features` does not perform HTTP transport.
- `scoring` does not parse raw response bodies.
- `reporting` does not reconstruct scores or evidence.
- `decision` does not perform HTTP transport and does not recompute scores,
  evidence, or identifiers owned by `scoring`/`selection`.
- `decision` is a consumer, never a producer, of the selection contract. Only
  `corpus` and `cli_decision` depend on it.
- `corpus` builds ground truth keys from authoritative `Endpoint`/`InputPoint`
  objects, never from a report or display text.
- `cli_decision` adds commands. It does not modify the frozen `analyze` or
  simple-URL surfaces.
- `evaluation.metrics` depends on nothing but the standard library, so no
  comparison arm can be measured by code specialised to it.

## 2. Target Prototype v0.2

Everything in this section is **Planned for v0.2** unless explicitly labeled
otherwise. Native Static Discovery and opt-in combined Native Dynamic
Discovery through its CLI/pipeline Milestone 6 are implemented; the final
Milestone 7 loopback E2E remains pending.

### 2.1 Target execution path

```text
Target URL
  -> Scope / Redirect / Budget validation
  -> Native Static Crawler (implemented)
  -> optional bounded Native Dynamic Crawler (implemented through M6)
  -> CanonicalDiscoveryResult (Proposed Contract)
  -> Observation / Feature Extraction
  -> SQLi / Reflected XSS / BAC Scoring
  -> Top-K
  -> RankedCandidateContext (Proposed Contract)
  -> LLM Context Construction
  -> LLM-assisted Payload Mutation
  -> Payload Validator
  -> Focused Verification
  -> VerificationResult (Proposed Contract)
  -> Evidence-based Rule Confidence Update
  -> Final Reporting / Finding
```

A bounded native dynamic/browser crawler follows the static crawler only under
explicit opt-in and produces the same canonical discovery contract. The final
loopback E2E acceptance milestone is not yet implemented.

### 2.2 Native discovery direction

The native crawler, not `LegacyCrawlerAdapter`, is the primary v0.2 producer of
canonical domain models.

Static discovery is implemented:

- Target and scope validation.
- Redirect final-target revalidation.
- Request budget, depth, delay, timeout, and response limits.
- URL, link, form, input, and query collection.
- Hidden input preservation.
- Ordered and repeated parameter occurrence preservation.
- Raw query context and form provenance preservation.

Dynamic discovery is connected after the Static contract is validated. It adds
browser-observed surfaces under exact caller authority and cannot create a
second incompatible domain model.

### 2.3 BAC family

BAC is a separate observation/scoring family, not an injection payload subtype.
The bounded v0.2 target is:

- Explicit authorized role/session fixtures.
- Static BAC hints from routes, identifiers, and access relationships.
- Controlled cross-role/cross-object observations.
- BAC-specific features, evidence, and ranking.
- No automatic account creation, privilege changes, or destructive actions.

The exact access-candidate model and confidence rules require contract review
before implementation.

### 2.4 LLM-assisted focused verification

The planned LLM boundary contains four modules:

1. LLM Context Construction.
2. LLM-assisted Payload Mutation.
3. Deterministic Payload Validator.
4. Focused Verification.

GPT and Gemini are accessed through a provider-neutral **Experimental**
comparison harness. Model output is untrusted proposal data. It cannot execute
until the validator approves target binding, scope, payload family, encoding,
mutation limits, and safety constraints.

The LLM is not the final vulnerability judge. Focused verification produces
structured evidence; deterministic rules update `VerificationConfidence`.
`RankScore` remains independent.

### 2.5 Target dependency direction

```text
native discovery -> canonical domain
legacy compatibility -> canonical domain
observation -> canonical domain
features -> observations + domain
scoring -> features + domain
selection -> scoring
LLM context -> RankedCandidateContext
payload mutation -> provider boundary
payload validator -> proposed payload + scope policy
focused verification -> validated payload + transport
confidence rules -> VerificationEvidence
reporting -> authoritative ranking + verification results
```

No downstream owner may reconstruct an upstream ID, score, evidence item, or
request context from display strings.

## 3. Legacy Compatibility Path

`LegacyCrawlerAdapter` remains **Implemented** for compatibility:

```text
Legacy record JSON
  -> LegacyCrawlerAdapter
  -> canonical v0.1 models
  -> existing observation / scoring / reporting regression path
```

For v0.2:

- The adapter is not the main discovery route.
- It is not deleted.
- It supports legacy-input conversion and regression comparison.
- Native crawler behavior must not be implemented inside the adapter.
- Compatibility changes must preserve stable identity and provenance or
  explicitly version the boundary.

ADR-005 remains historical for v0.1 and is superseded only for the v0.2 primary
discovery path by the newer decisions in `docs/DECISION_LOG.md`.

## 4. Cross-version invariants

- One-at-a-time attribution remains the default for injection probes.
- Missing observation is distinct from observed zero.
- Raw RankScore is distinct from cross-type selection priority.
- `VerificationConfidence` is distinct from ranking.
- Reporting is downstream of authoritative results.
- Safety and scope checks precede network execution.
- Every executable payload has deterministic provenance and validator approval.
- Proposed contracts and planned classes must not be documented as implemented.

See `docs/PROTOTYPE_V0_2.md` for milestones and acceptance criteria and
`docs/TEAM_INTERFACES_V0_2.md` for cross-owner contract proposals.
