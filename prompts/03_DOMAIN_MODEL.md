# Prompt 03 — Domain Model

Read:

- `AGENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/FEATURE_SCHEMA.md`
- `docs/PROTOTYPE_V0_1.md`
- `docs/DECISION_LOG.md`

If the task is complex enough, create an execution plan per `PLANS.md`.

## Goal

Implement only the core typed domain model needed by prototype v0.1.

## Required domain concepts

- `Endpoint`
- `InputPoint`
- `InputLocation`
- `RequestTemplate`
- `ProbeFamily`
- `ProbePlan`
- `ResponseSnapshot`
- `ResponsePair`
- `FeatureObservation`
- `FeatureVector`
- `VulnerabilityType`
- `VulnerabilityCandidate`
- `ScoreEvidence`

## Non-negotiable invariants

1. `Page != Endpoint != InputPoint != VulnerabilityCandidate`.
2. `FeatureVector` belongs to one `InputPoint`.
3. ranking unit is `InputPoint x VulnerabilityType`.
4. missing feature and observed zero are distinct.
5. `ProbePlan` must represent one-at-a-time mutation.
6. `RankScore` must not be named or documented as vulnerability probability.
7. Core domain models must not depend on HTTP clients, database libraries, LLM SDKs, or crawler implementation details.

## Fingerprints

Implement deterministic fingerprint helpers for at least:

- Endpoint identity
- InputPoint identity

Do not use Python's process-randomized `hash()` as a persistent fingerprint.

## Tests

Add deterministic unit tests covering:

- endpoint identity ignores query values,
- two parameters on same endpoint create distinct InputPoints,
- same normalized InputPoint produces same fingerprint,
- query and form parameters with same name are distinct,
- missing feature != observed zero,
- candidate identity differs by vulnerability type,
- invalid multi-field ProbePlan is rejected if the chosen model encodes changed fields.

## Out of scope

- network requests
- crawler adapter
- database persistence
- feature extraction logic
- score weights
- LLM
- BAC

## Done when

- tests pass,
- type checks pass,
- public model semantics match docs,
- diff review finds no endpoint/input-point conflation.

Before coding, inspect the current scaffold and state a concise implementation plan.
