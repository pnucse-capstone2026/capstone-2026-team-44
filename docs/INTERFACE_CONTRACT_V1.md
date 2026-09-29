# VulnSpider Interface Contract v1

**Status:** Implemented contract

**Version:** `1.0`

This document fixes the cross-team boundary implemented by the current v0.2
pipeline. It does not introduce a new crawl, probe, scoring, mutation, or BAC
pipeline.

## Pipeline boundary

```text
Discovery                         Analysis
---------                         --------
Endpoint                          ProbePlan
InputPoint                        ResponsePair / ResponseSnapshot
RequestTemplate                   FeatureVector
InputPointRequestContext          ScoringResult
DiscoveryProvenance               selected Candidate
discovery_snapshot_id             discovery_snapshot_id reference
        |                              |
        +-- vulnspider-crawl.json      +-- vulnspider-analysis.json
                         \              /
                          handoff adapter
                                |
                       NormalizedCandidate
                                |
                     future Mutation consumer
```

The producer of each canonical object owns its construction and validation.
Consumers resolve stable IDs; they do not reparse HTML, recompute IDs, infer
missing context, or upgrade incomplete context.

## Contract A: Probe to Feature

The official Injection feature-extraction input is the existing validated
object set:

```text
InputPoint + ProbePlan + ResponsePair
           + baseline ResponseSnapshot + probe ResponseSnapshot
        -> FeatureVector
```

`extract_minimal_features` is the contract entry point. No wrapper object is
introduced. The extractor requires exact ownership across the InputPoint,
ProbePlan, ResponsePair, request IDs, response roles, and ProbePlan IDs.
Responses from different plans cannot be mixed, even when request bytes happen
to be identical. Missing provenance is an error.

Bounded decoded response text may be used internally to calculate the existing
SQLi and Reflected XSS features. Response bodies and decoded text are not added
to the canonical JSON reports. Feature names, scorer behavior, and Top-K policy
are unchanged by Contract v1.

## Contract B: Selection to Mutation

`vulnspider.handoff.NormalizedCandidate` is the common selected-candidate
handoff. It preserves the existing Injection candidate and scoring identities
and adds only the explicit category, resolved Endpoint, provenance, and safe
mutation context needed at the boundary.

Required common fields are:

| Field | Contract |
| --- | --- |
| `candidate_id` | Required stable candidate identity. |
| `category` | `INJECTION` or reserved `BROKEN_ACCESS_CONTROL`. |
| `vulnerability_type` | `SQLI`, `REFLECTED_XSS`, or reserved `BROKEN_ACCESS_CONTROL`. |
| `rank` | Positive selection rank; it has no meaning before selection. |
| `raw_rank_score` | Score in the owning scorer's native range. |
| `raw_rank_score_max` | Positive maximum for that scorer. |
| `selection_priority` | Canonical cross-scorer value, `raw_rank_score / raw_rank_score_max`. |
| `input_point_id` | Nullable, but cannot be null together with `endpoint_id`. |
| `endpoint_id` | Nullable, but cannot be null together with `input_point_id`. |
| `scorer_version` | Required scorer policy identity. |
| `feature_vector_id` | Nullable when the category does not use features. |
| `evidence` | Deterministically ordered evidence items. |
| `provenance` | IDs that bind the candidate to discovery and analysis records. |

Each evidence item contains `feature_name`, `feature_value`, `observed`,
`weight`, `contribution`, and `reason`. When `observed` is false, unavailable
numeric fields remain null. They must not be converted to zero, because zero is
a real observed feature value.

Raw scores from different scorer families are not comparable. Cross-family
ordering uses `selection_priority`; deterministic identity tie-breakers remain
owned by the existing selection implementation.

The handoff adapter reconstructs the serialized FeatureVectors as existing
domain objects, runs the existing `generate_candidates` scorers, and calls the
existing `select_top_k` implementation. Artifact-provided score maxima,
priorities, evidence, summary counts, candidate order, and ranks must match
those authoritative results. The adapter does not carry a second scorer or
Top-K implementation.

Contract v1 names the future BAC category and vulnerability discriminator only.
It does not create BAC candidates, scoring, access context, or mutation logic,
and the production v1 adapter rejects BAC candidates as unsupported until a
reviewed authoritative BAC scorer and selection policy exist.

## Contract C: Crawl and Analysis to Mutation Context

There are exactly two canonical JSON artifacts:

1. `vulnspider-crawl.json` is the source of truth for Discovery, Endpoint,
   InputPoint, RequestTemplate, InputPointRequestContext, readiness, and crawl
   provenance.
2. `vulnspider-analysis.json` is the source of truth for ProbePlan,
   ResponsePair identity, response metadata, FeatureVector, ScoringResult, and
   selected Candidate.

There is no canonical `context_registry.json`. `build_candidate_handoff` and
`normalize_selected_candidates` join already-loaded mappings in memory and do
not write a third artifact.

The canonical discovery serialization contains a deterministic
`discovery_snapshot_id`. It is calculated with the existing stable fingerprint
primitive over the complete canonical discovery mapping except the snapshot
field itself. It includes Endpoint, InputPoint, RequestTemplate, request
context, readiness, provenance, metadata, warnings, and other canonical
discovery content. Timestamps and filesystem paths are not added. The
operational `crawl_statistics.elapsed_ms` measurement remains in the artifact
but is normalized to `0.0` for snapshot calculation because it is
non-decision, non-provenance timing telemetry; it therefore cannot make two
otherwise identical discoveries produce different snapshot IDs.

The analysis `crawl_reference` stores the exact `discovery_snapshot_id` it
analyzed. The handoff recalculates the crawl snapshot, rejects a stale or
tampered stored value, and requires the analysis reference to match. The
existing deterministic `discovery_run_id` keeps its configuration/scope
meaning; it is not used as exact content binding.

For an Injection candidate, the adapter resolves this exact chain:

```text
analysis Candidate.input_point_id
    -> crawl InputPoint.endpoint_id
    -> crawl Endpoint
    -> analysis ProbePlan.request_template_id / request_context_id
    -> crawl RequestTemplate / InputPointRequestContext
```

It also resolves FeatureVector, ScoringResult, ResponsePair IDs, baseline/probe
request and response IDs, and discovery provenance. Missing or contradictory
references fail explicitly with `HandoffContractError`; they are never silently
dropped.

The derived Injection mutation context contains the canonical method and URL,
parameter name, canonical `InputLocation`, repeated-parameter occurrence, the
original value recoverable from the safe RequestTemplate, RequestTemplate and
request-context IDs, and nullable `auth_context_id`. The v1 adapter supports the
currently executable QUERY and FORM request-template locations. It does not
fabricate context for other locations.

Dynamic discovery may serialize `JSON_BODY` InputPoints for top-level structure
from an eligible blocked POST JSON attempt. These records are deliberately
NOT_READY and have no RequestTemplate or InputPointRequestContext, so the v1
handoff and ProbePlanner cannot consume or execute them.

A future BAC adapter starts from `endpoint_id` and resolves an Endpoint plus
reviewed access-related context. That behavior is not implemented in v1.

## Stable identity and provenance

- IDs come from their authoritative producer and are never recomputed by the
  handoff consumer.
- The analysis `crawl_reference.discovery_run_id` and
  `crawl_reference.discovery_snapshot_id` must match the crawl artifact, and
  the snapshot must match recalculated canonical discovery content.
- Candidate, ScoringResult, evidence, FeatureVector, and probe observation
  ownership must agree.
- Probe responses retain exact ProbePlan, request, and baseline/probe role
  ownership.
- InputPoint, Endpoint, RequestTemplate, and request context must be covered by
  the same discovery run's provenance.
- Duplicate IDs, unresolved references, and nondeterministic selected ranks are
  contract failures.

## Sensitive data

Canonical JSON must not contain plaintext passwords, raw Cookie values, raw
session tokens, JWTs, Authorization bearer tokens, API keys, or other credential
secrets. Response bodies and decoded response text are also excluded from the
reports.

The adapter recursively examines both nested canonical artifact mappings and
ordered parameter pairs. Credential-bearing field names, raw Bearer/Basic
authorization values, bounded structurally valid JWTs, and well-known API-key
forms fail closed. JWT recognition requires three bounded base64url segments,
JSON object header/payload segments, and a non-empty header algorithm; ordinary
non-secret query strings are not rejected merely for containing punctuation.
Secrets are not redacted into executable mutation context.

Future authenticated/BAC work uses identifiers and non-secret metadata such as
`auth_context_id`, `role`, and `is_anonymous`. Missing context remains null or
unavailable; it is never fabricated. The handoff adapter fails closed when raw
credential material is present and never copies headers, cookies, or response
bodies into `NormalizedCandidate`.

## Downstream adapter rules

- Read both canonical artifacts and validate their declared report kinds and
  supported schema/contract versions.
- Resolve by stable IDs and reject inconsistencies.
- Preserve canonical `HttpMethod` and `InputLocation`; translate enum strings
  only at an external Mutation boundary.
- Treat the handoff as derived in-memory data, not a new source of truth.
- Do not submit forms, execute payloads, replay state-changing requests, or make
  network calls while adapting artifacts.
- Do not infer BAC/session/authentication data that the artifacts do not carry.

## Compatibility and versioning

Contract v1 is additive to the existing v0.2 domain and report schemas. It does
not change their version strings or construction APIs. It adds the required
`discovery_snapshot_id` to canonical discovery serialization and the matching
analysis crawl reference. Contract v1 accepts report schema `0.1` and discovery
contract `canonical-discovery/1.0`; other declared versions fail explicitly.

- Optional additive handoff fields require a minor contract version increment.
- Required fields, enum meaning, identity rules, ranking semantics, provenance
  requirements, or canonical artifact ownership changes require a major version
  increment and review by affected producers and consumers.
- Unknown fields may be ignored only under an explicitly compatible minor
  version. Missing required fields are always errors.
- BAC implementation must satisfy this common schema and add a reviewed
  category-specific context; the reserved enum alone does not authorize BAC
  behavior.
