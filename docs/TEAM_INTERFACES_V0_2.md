# Team Interfaces v0.2

> **Status: Proposed Contract**
>
> These are review targets, not implemented Python classes. Field names and
> versions may change through the interface review process before production
> code is added.

The implemented Probe/Feature, selected-candidate, and two-artifact handoff
boundary is frozen separately in
[`INTERFACE_CONTRACT_V1.md`](INTERFACE_CONTRACT_V1.md). Where this proposal is
broader or idealized, the implemented Contract v1 is authoritative for current
code.

## Contract principles

- The producer owns construction and validation.
- The consumer accepts the complete validated contract or rejects it.
- Stable IDs are produced by the authoritative owner, never reconstructed.
- Provenance references point to authoritative source objects or immutable
  records.
- Display strings are not data contracts.
- A breaking change requires a version increment and affected-owner review.
- Unknown fields may be ignored only when the declared version policy allows
  it; missing required fields are always an error.

## 1. CanonicalDiscoveryResult

**Status:** Proposed Contract

### Purpose

Carry one bounded native discovery run into observation and feature processing
without requiring the consumer to crawl, parse HTML, infer form boundaries, or
reconstruct canonical identities.

### Ownership

- Producer: 상현
- Consumer: 수훈
- Owner: 상현
- Reviewers for contract changes: 상현 and 수훈

### Required fields

| Field | Meaning |
| --- | --- |
| `contract_version` | Semantic contract version. |
| `discovery_run_id` | Stable identity for this bounded run. |
| `target_scope_id` | Reference to the validated target/scope authority. |
| `collector_kind` | `native_static` or approved dynamic prototype kind. |
| `collector_version` | Exact collector policy/version. |
| `endpoints` | Canonical `Endpoint` objects. |
| `input_points` | Canonical `InputPoint` objects. |
| `request_templates` | Canonical `RequestTemplate` objects. |
| `input_point_request_contexts` | Validated input/template relationships. |
| `crawl_provenance` | Source URL, parent, depth, collector, and timestamps. |
| `scope_decisions` | Allowed/rejected request and redirect decisions. |
| `budget_summary` | Request/depth/time budget configured and consumed. |
| `warnings` | Structured partial/ambiguous discovery warnings. |

### Stable identity

`Endpoint`, `InputPoint`, `RequestTemplate`, and context identity use canonical
domain fingerprint rules. `discovery_run_id` additionally binds target scope,
collector policy version, and run configuration.

Static and dynamic collectors must emit compatible object identities when they
observe the same surface.

### Provenance reference

Every surface references its discovery run and source observation. Form and
query contexts preserve ordered pairs, repeated occurrence index, hidden state,
raw query information, method/action provenance, and completeness.

### Validation boundary

The producer validates before handoff:

- Every child reference resolves.
- IDs match authoritative object content.
- Scope and budget summaries are internally consistent.
- Complete contexts contain executable information.
- Partial/ambiguous contexts carry structured reasons.
- No collected URL silently bypassed final-target scope validation.

### Forbidden reconstruction

The consumer must not:

- Reparse source HTML to rebuild forms.
- Generate missing hidden inputs.
- Infer occurrence indexes from unordered mappings.
- Rebuild raw query strings from display URLs when raw context exists.
- Upgrade partial contexts to complete.
- Recompute canonical IDs.

### Versioning and compatibility

- Additive optional fields: minor version.
- New required fields or identity/meaning changes: major version.
- Dynamic collection must support the static contract's current major version.
- Legacy adapter output may be transformed through an explicit compatibility
  layer; it cannot claim native collector provenance.

## 2. RankedCandidateContext

**Status:** Proposed Contract

### Purpose

Carry one selected candidate and its authoritative ranking, evidence, request
context, and safety envelope to the LLM-assisted verification owner.

### Ownership

- Producer: 수훈
- Consumer: 석현
- Owner: 수훈
- Reviewers for contract changes: 수훈 and 석현

### Required fields

| Field | Meaning |
| --- | --- |
| `contract_version` | Semantic contract version. |
| `ranked_context_id` | Stable identity for this handoff. |
| `selection_run_id` | Identity/version of the authoritative Top-K run. |
| `rank` | Position in the validated selection outcome. |
| `candidate_id` | Authoritative candidate identity. |
| `candidate_subject_kind` | Discriminator for the candidate subject, such as `input_point` or the proposed `bac_access_context`. |
| `candidate_subject_ref` | Type-specific authoritative subject reference selected by `candidate_subject_kind`. |
| `vulnerability_type` | SQLi, Reflected XSS, or reviewed BAC family. |
| `raw_rank_score` | Scorer-owned raw priority value. |
| `raw_rank_score_max` | Exact scorer maximum under the declared scorer policy; not yet defined for BAC. |
| `selection_priority` | Authoritative cross-type selection key under an approved comparison policy; BAC comparability is not yet defined. |
| `score_evidence` | Complete authoritative `ScoreEvidence`. |
| `feature_vector_id` | Source feature-vector identity. |
| `request_context_ref` | Validated request/access context reference. |
| `observation_refs` | Baseline/probe or BAC observation provenance. |
| `target_scope_id` | Scope authority for any later proposal. |
| `allowed_verification_policy` | Allowed family, mutation, and budget envelope. |

### Candidate subject boundary

This is a proposed handoff contract, not an implemented class hierarchy.

- For SQLi and Reflected XSS, `candidate_subject_kind` is `input_point` and
  `candidate_subject_ref` identifies the authoritative `InputPoint`. This
  preserves the frozen v0.1 invariant:
  `VulnerabilityCandidate = InputPoint x VulnerabilityType`.
- A BAC candidate may instead describe a reviewed relationship among role,
  session, resource, and access context. It is not required to identify one
  `InputPoint`.
- `bac_access_context` is a proposed discriminator only. The exact BAC
  candidate identity, access-context fields, and subject-reference schema
  remain an Open Contract Decision.

### Stable identity

`ranked_context_id` binds selection run, candidate, source feature vector, and
policy version. Candidate and feature identities remain owned by existing
domain/scoring boundaries.

### Provenance reference

Evidence references the exact feature vector and candidate. Injection
observations reference the exact `ProbePlan`, baseline response, and probe
response with roles intact. BAC observations reference the reviewed role,
session, object, and request matrix.

### Validation boundary

The producer validates:

- `SelectionOutcome` and summary consistency.
- Rank ordering and candidate uniqueness.
- Raw score, maximum, and selection priority ownership.
- Evidence candidate/vector/type ownership.
- Request/response or BAC provenance consistency.
- Scope and allowed verification policy references.

### Forbidden reconstruction

The consumer must not:

- Recompute RankScore or `selection_priority`.
- Infer confidence from rank.
- Parse HTML/JSON display text to recover evidence.
- Swap baseline and probe roles.
- Rebuild requests from an `InputPoint` without its context.
- Broaden the allowed verification policy.

### Second consumer: the decision layer

`vulnspider.decision` is a second, read-only consumer of this contract
(ADR-022, ADR-023, ADR-024). `decision_candidate_from_context()` is its only
entry point. It attaches a calibrated probability, a verification cost, and a
severity, then allocates a request budget across the result.

It obeys the same forbidden-reconstruction rules above: it recomputes no
RankScore, no `selection_priority`, and no evidence, and it never emits a
candidate the selection layer did not produce. It deliberately does not
populate `target_scope_id` or `allowed_verification_policy` — those stay owned
by the scope and verification-policy boundaries.

The calibrated probability it computes is a **pre-verification prior**, not a
`VerificationConfidence` (§3). The two are never summed or substituted.

### Versioning and compatibility

- Scorer-policy changes require an explicit policy version and evaluation note.
- Evidence schema or ownership changes require affected-owner review.
- A consumer may support multiple major versions through explicit adapters;
  silent fallback is forbidden.

### BAC ranking and global selection boundary

- BAC family-internal ranking may be designed independently from injection
  ranking.
- **Resolved by ADR-021.** BAC participates in the shared global Top-K using the
  ADR-010 `selection_priority` (`raw_rank_score / exact_scorer_maximum`). The
  approved BAC exact scorer maximum is `ACCESS_MAX_RANK_SCORE` (75.0,
  `access-control-weighted-v1`); `selection.combined.select_combined_top_k()`
  merges the two already-validated category selections and
  `selection.handoff.build_mutation_handoff()` emits the resulting
  `RankedCandidateContext` bundle.
- `selection_priority` remains a selection-only comparison key, not a
  probability or confidence (ADR-010, ADR-016).

## 3. VerificationResult

**Status:** Proposed Contract — first producer implemented in
`vulnspider.verification` (ADR-032). The implemented record realizes this
contract's required fields (`verification_result_id`, `candidate_id`,
`provider`, `proposal_id`, `validator_policy_version`, `validator_decision`,
`validated_payload_ref` as `validated_payload_id`, `execution_refs`,
`verification_evidence` inside the confidence block, `confidence_rule_version`,
`verification_confidence`, `outcome_status`, `warnings`); a real GPT/Gemini
`provider` is still pending.

### Purpose

Carry validator decisions, bounded focused-verification execution, structured
evidence, and rule-based confidence into final reporting/finding construction.

### Ownership

- Producer: 석현
- Consumer: final Reporting / Finding owner
- Owner: 석현
- Confidence rule review: whole team

### Required fields

| Field | Meaning |
| --- | --- |
| `contract_version` | Semantic contract version. |
| `verification_result_id` | Stable result identity. |
| `ranked_context_id` | Source candidate handoff. |
| `candidate_id` | Authoritative candidate identity. |
| `provider` | GPT, Gemini, deterministic baseline, or no-model mode. |
| `provider_request_ref` | Redacted/versioned model request provenance. |
| `proposal_id` | Stable proposed payload identity. |
| `validator_policy_version` | Exact deterministic validator version. |
| `validator_decision` | Accepted or rejected with structured reasons. |
| `validated_payload_ref` | Approved payload record, absent when rejected. |
| `execution_refs` | Bounded request/response provenance, if executed. |
| `verification_evidence` | Structured `VerificationEvidence`. |
| `confidence_rule_version` | Exact deterministic confidence policy. |
| `verification_confidence` | Rule-derived result, not model output. |
| `outcome_status` | Rejected, not executed, inconclusive, supported, etc. |
| `warnings` | Structured limitations and missing observations. |

### Stable identity

The result identity binds ranked context, proposal, validator policy, execution
trace, evidence, and confidence rule version. Re-running with a different
provider/policy produces a distinct result.

### Provenance reference

Every accepted payload references the original model/deterministic proposal and
validator decision. Every evidence item references exact execution requests and
responses. Secrets and full provider credentials are never provenance fields.

### Validation boundary

The producer validates:

- Candidate and ranked-context ownership.
- No execution exists for a rejected/unvalidated payload.
- Execution stayed within target, scope, and budget.
- Request/response role and payload provenance.
- Evidence references actual execution.
- Confidence was produced by the declared rule version.

### Forbidden reconstruction

The consumer must not:

- Treat model prose as evidence.
- Mark a vulnerability confirmed from rank or provider claims.
- Recompute confidence from RankScore.
- Invent missing executions or evidence.
- Hide validator rejection or inconclusive status.
- Reconstruct secrets from redacted provider metadata.

### Versioning and compatibility

- Validator and confidence policies are independently versioned.
- New outcome meanings, identity rules, or required provenance are major
  contract changes.
- Reporting may add presentation-only fields but cannot change authoritative
  result semantics.
- Historical results remain readable with their original policy versions.

## Open contract decisions

Human approval is still required for:

- Exact BAC candidate/access-context model.
- ~~BAC scorer maximum, family-internal ranking contract, and whether/how BAC
  participates in the SQLi/Reflected XSS global Top-K.~~ Resolved by ADR-021:
  BAC uses `ACCESS_MAX_RANK_SCORE` (75.0) as its exact scorer maximum and
  participates in the combined Top-K via the ADR-010 `selection_priority`.
- Canonical scope-decision and budget record schemas.
- Provider request/output retention and redaction policy.
- Allowed payload families and validator rejection taxonomy.
- `VerificationEvidence` field set.
- Confidence scale, thresholds, and rule update process.
- Final Reporting/Finding ownership.
