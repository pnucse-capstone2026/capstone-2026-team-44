# Prototype v0.2 Specification

> **Status: Planned for v0.2**
>
> This document authorizes implementation scope. It does not claim that native
> crawling, BAC, LLM mutation, focused verification, or confidence code exists.
> The implemented checkpoint remains
> [`PROTOTYPE_V0_1.md`](PROTOTYPE_V0_1.md).

## 1. Goal

v0.2 extends the completed ranking vertical slice into a bounded end-to-end
research prototype:

```text
authorized target
  -> native discovery
  -> explainable prioritization
  -> validator-gated LLM payload proposal
  -> focused verification
  -> evidence-based confidence
```

The research question becomes:

> Can a native, provenance-preserving discovery path prioritize SQLi,
> Reflected XSS, and bounded BAC candidates, then spend focused verification
> effort on the best candidates without delegating safety or final judgment to
> an LLM?

## 2. Why move beyond v0.1

v0.1 proved the core attribution and ranking path using stored legacy records.
That boundary cannot fully control live scope, redirects, budgets, hidden
inputs, browser-observed surfaces, or role/session relationships.

v0.2 therefore:

- Replaces the primary legacy-record entry point with native discovery.
- Preserves v0.1 as a compatibility and regression checkpoint.
- Adds BAC as a relationship-oriented ranking family.
- Adds focused verification without conflating ranking and confidence.
- Measures GPT and Gemini as interchangeable proposal providers behind the same
  deterministic validation and execution boundaries.

## 3. Target execution path

```text
Target URL
  -> Scope / Redirect / Budget checks
  -> Native Static Crawler (implemented)
  -> optional Native Dynamic Crawler (implemented through CLI/pipeline M6)
  -> CanonicalDiscoveryResult
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
```

## 4. Implementation scope

### 4.1 Native discovery

**Implemented through final Dynamic loopback E2E acceptance, observed GET API
canonicalization, and blocked POST JSON structural canonicalization**

- Direct authorized target URL input.
- Scope allowlist and final redirect-target validation.
- Request budget, crawl depth, delay, timeout, and response-size limits.
- Native static collection of URLs, links, forms, inputs, and queries.
- Preservation of hidden controls, repeated occurrence identity, ordered pairs,
  raw query context, form action/method, and source provenance.
- Direct production of canonical domain models.
- A bounded dynamic/browser crawler prototype using the same contract.
- Transport-free canonicalization of already-authorized, naturally emitted,
  exact-origin GET fetch/XHR, with credential-bearing values elided before
  canonical construction.
- Structural-only canonicalization of primary-page exact-origin POST fetch/XHR
  JSON attempts while the Guard continues to block their transport. Only
  bounded top-level member names are retained as NOT_READY JSON_BODY points.

The native Static crawler and explicit opt-in combined Dynamic path are
implemented against one validated canonical schema. Dynamic collection cannot
introduce a parallel schema. Strict real-Chromium loopback gates cover transport
authority, rendered DOM, bounded navigation, canonical merge, cleanup, and the
split crawl/analysis pipeline.

### 4.2 Observation, features, and prioritization

**Planned for v0.2**

- Preserve and extend v0.1 probe planning/execution invariants.
- Preserve independent SQLi and Reflected XSS feature/scoring families.
- Add a separate BAC observation, feature, and scoring family.
- Add a versioned feature cache and ground-truth references.
- Add ranking evaluation, weight experiments, and ablation.
- Continue deterministic Top-K and explainable evidence.

### 4.3 LLM-assisted focused verification

The four planned modules are:

1. **LLM Context Construction** - minimum authoritative candidate, scope, and
   provenance context.
2. **LLM-assisted Payload Mutation** - provider-neutral proposal generation.
3. **Payload Validator** - deterministic approval/rejection before execution.
4. **Focused Verification** - bounded execution and structured evidence.

Model output is untrusted input. An LLM does not assign final confidence and
cannot bypass the validator.

### 4.4 Evidence and confidence

Focused verification produces `VerificationEvidence`. A deterministic,
reviewed rule set then updates `VerificationConfidence`.

- RankScore answers: "What should be verified first?"
- VerificationConfidence answers: "How strong is the post-verification
  evidence?"

The two values remain independent. RankScore is not added to confidence.

## 5. Non-goals

**Deferred**

- Arbitrary Internet scanning.
- Autonomous exploit chains.
- Destructive or state-changing verification.
- Account creation, privilege modification, persistence, shell execution, or
  denial of service.
- General-purpose browser crawling beyond the bounded prototype.
- ZAP replacement.
- LLM-only findings or confidence.
- Production-scale distributed crawling.
- Fine-tuning without passing the decision gate in section 9.

## 6. Native crawler direction

### 6.1 Static first

The static crawler must establish:

- Deterministic scope decisions.
- Provenance for every discovered surface.
- Canonical identity compatible with downstream v0.1 models.
- Complete request context where safe execution is possible.
- Explicit partial/ambiguous state where context is incomplete.
- Budget and redirect accounting.

Static acceptance is required before browser work begins.

### 6.2 Dynamic second

The **Experimental** dynamic/browser crawler may collect DOM-generated links,
forms, and network-visible input surfaces. It must:

- Reuse `CanonicalDiscoveryResult`.
- Preserve collector provenance.
- Obey the same scope and budget authority.
- Avoid executing application actions that modify state.
- Deduplicate against static discovery through canonical identity.
- Build network-visible canonical surfaces only from the Guard's original GET
  allow decision or eligible POST block decision, never from audit fingerprints
  and never through replay.
- Emit value-bearing READY contexts only for credential-free requests; otherwise
  retain at most value-free structure with explicit NOT_READY ownership.

## 7. BAC bounded scope

BAC in v0.2 is limited to explicitly configured local fixtures and roles.

Included:

- Role/session labels supplied by the authorized test setup.
- Resource/object identity and ownership hints.
- Controlled same-role, cross-role, and cross-object observations.
- BAC-specific features, `ScoreEvidence`, and ranking.

Excluded:

- Credential discovery or harvesting.
- Automatic user/account creation.
- Privilege or ownership modification.
- Destructive access tests.
- Treating BAC as an SQLi/XSS payload subtype.

The BAC candidate model and execution matrix require owner review before code
is added.

## 8. GPT/Gemini comparison experiment

### 8.1 Harness

**Experimental**

GPT and Gemini providers receive the same versioned
`RankedCandidateContext`, task constraints, validator, and execution budget.
Provider-specific adapters may translate request syntax but cannot alter the
canonical experiment record.

### 8.2 Metrics

At minimum compare:

- Proposal schema-validity rate.
- Payload Validator acceptance/rejection rate and reason distribution.
- Duplicate or no-op proposal rate.
- Focused-verification execution success rate.
- New evidence yield per accepted proposal.
- False-positive and unsupported-claim rate against ground truth.
- Latency, token usage, and estimated cost.
- Determinism/repeatability across fixed trials.
- Safety-policy violation attempt rate.

Raw provider output is an access-controlled generated artifact, not source
code.

## 9. Fine-tuning decision gate

Fine-tuning remains **Deferred** unless all conditions are met:

1. The base GPT/Gemini comparison is complete on a versioned dataset.
2. Failure types are classified and reproducible.
3. Prompt/context/validator improvements have been tried first.
4. A repeated, material failure remains that training could plausibly address.
5. Dataset provenance, licensing, secret handling, and train/test isolation are
   approved.
6. The expected gain justifies cost and evaluation complexity.

Passing the gate authorizes a separate **Experimental** proposal; it does not
automatically add fine-tuning to the implementation plan.

## 10. Team roles

### 상현 - Native Discovery & Preprocessing

- Native static crawler.
- Native dynamic crawler prototype.
- Scope, redirect, request budget, depth, and delay.
- URL/link/form/input/query collection.
- Hidden/repeated/raw context preservation.
- Canonical discovery models and BAC static hints.
- Producer/owner of `CanonicalDiscoveryResult`.

### 수훈 - Observation, Feature & Prioritization

- Probe planning/execution maintenance and extension.
- SQLi, Reflected XSS, and BAC features/scoring.
- `ScoreEvidence`, Top-K, cache, ground truth, and ranking evaluation.
- Weight experiments and ablation.
- Producer/owner of `RankedCandidateContext`.

### 석현 - LLM-assisted Focused Verification

- GPT/Gemini comparison harness.
- LLM context and payload mutation.
- Payload Validator.
- Focused verification and `VerificationEvidence`.
- Rule-based confidence update implementation.
- Producer/owner of `VerificationResult`.

The whole team reviews confidence rules. 석현 owns their implementation.

## 11. Milestones

### M0 - Contracts and safety

- Approve proposed contracts and versioning.
- Define scope authority, budgets, and payload validation policy.
- Approve BAC fixture and role/session representation.

### M1 - Native static discovery

- Implement target input, scope, redirect, and budgets.
- Produce canonical domain models directly.
- Pass static crawler safety and provenance tests.

### M2 - Dynamic discovery prototype

- Connect browser collection to the same contract.
- Demonstrate canonical deduplication and unchanged downstream consumption.
- Status: implemented through strict loopback acceptance, bounded navigation,
  combined merge, simple CLI E2E, and observed GET API canonicalization.

### M3 - BAC prioritization

- Implement bounded BAC preprocessing, observations, features, scoring, and
  evaluation fixtures.

### M4 - LLM comparison and validation

- Implement provider-neutral GPT/Gemini harness and context construction.
- Implement payload proposal schema and mandatory validator.
- Run offline/validator-only comparison before network execution.

### M5 - Focused verification and confidence

- Execute only approved bounded payloads.
- Produce structured evidence and rule-based confidence.
- Integrate final reporting without reconstructing ranking or evidence.

### M6 - Evaluation and freeze

- Complete ranking and provider comparisons.
- Run ablation and adversarial safety review.
- Decide whether the fine-tuning gate is met.
- Freeze documentation and reproducibility artifacts.

## 12. Acceptance criteria

1. A direct authorized target URL enters native static discovery.
2. Out-of-scope redirects and links are rejected before requests are sent.
3. Budgets, depth, delay, timeout, and response bounds are enforced.
4. Native discovery emits validated canonical models with stable identity and
   provenance.
5. Static and dynamic collectors share one contract.
6. Legacy adapter remains usable only through the compatibility path.
7. SQLi, Reflected XSS, and BAC results remain independently explainable.
8. RankScore and VerificationConfidence remain independent.
9. No LLM proposal executes before deterministic validator approval.
10. Focused verification preserves candidate, payload, request, response, and
    evidence provenance.
11. GPT/Gemini comparison uses the same dataset, context version, validator,
    budgets, and metrics.
12. Reports consume authoritative contracts without reconstructing scores,
    evidence, or confidence.
13. Unit, integration, adversarial safety, and local end-to-end tests pass.

## 13. Safety boundary

- Testing is limited to explicit local/controlled targets.
- Scope authority is deterministic and cannot be expanded by a model.
- Redirects are revalidated at the final target.
- Payload families and mutation size are allowlisted.
- Validator rejection prevents execution.
- Verification is bounded by request, time, and response limits.
- Secrets are supplied outside Git and are redacted from logs/artifacts.
- Raw experiments follow `docs/GIT_WORKFLOW.md`.
- Any network-scope or payload-execution change receives two reviewers when
  practical.
