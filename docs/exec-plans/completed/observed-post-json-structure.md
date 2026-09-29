# NO-4 Observed Blocked POST JSON Structural Canonicalization

## Goal

Extract only the top-level member names from a naturally attempted, primary-page,
exact-origin `POST` fetch/XHR with `Content-Type: application/json`, then emit a
canonical `POST` Endpoint and structural `JSON_BODY` InputPoints without sending,
replaying, probing, or otherwise executing that request.

## Preconditions

- [x] Read repository rules, review policy, architecture, domain, interface, Git,
  v0.2 specification, and the NO-1/NO-2/NO-3 execution plans.
- [x] Verify `79e43432bb28df4e0c37f1b1e31a553d0078f8fb` is an ancestor of
  `origin/integration/v0.2` through merge commit
  `e48469b2ee91ae1ed624c1bff3edb31a4bb56761`.
- [x] Verify zero tracked/staged changes, seven protected JSON files remain
  untracked, and `stash@{0}` remains
  `4cb421fdc274504f1768ddc8cbee0b1d84dd8dbf`.
- [x] Create `feat/observed-post-json-structure` from
  `origin/integration/v0.2`.
- [x] Focused pre-change baseline: 168 tests passed.

## Design

1. Collect at the Route Guard's blocked `NON_GET_METHOD` decision seam before
   `route.abort()`. Eligibility independently requires the primary Page, exact
   origin, fetch/XHR, exact `POST`, canonical HTTP(S) URL without userinfo, and
   `application/json` with an optional UTF-8 charset parameter.
2. Read headers and body only transiently. Parse a bounded UTF-8 body with an
   object-pairs hook so malformed JSON, arrays/scalars, duplicate keys at any
   depth, oversized bodies, invalid/too-many top-level names, and ambiguous
   provider data fail closed.
3. Reuse `contains_credential_material()` across the parsed JSON tree and the
   existing credential-header-name policy. Any credential material elides the
   whole POST candidate; only a deterministic reason/count warning remains.
4. Store an immutable POST candidate containing only canonical source/base URLs,
   resource kind, and sorted canonical top-level member names. Never retain a
   raw body, JSON value, header value, cookie, Authorization value, or token.
5. Canonicalize through the existing builder and merge path as one `POST`
   Endpoint plus `JSON_BODY` InputPoints with network provenance. Emit no
   `RequestTemplate` or `InputPointRequestContext`; every point owns a
   `NOT_READY / REQUEST_CONTEXT_MISSING` record.
6. Leave the existing GET candidate bound unchanged and apply the same ceiling
   independently to POST candidates, retaining the stable-ID-smallest bounded
   set under event reordering. Apply a separate top-level field limit and
   deterministic sanitized skip/overflow counts.

## Non-goals and invariants

- Balanced transport policy is unchanged: POST is aborted before transport.
- No observation/audit JSON is read back and no path fingerprint is reversed.
- No READY context, ProbePlan, baseline, probe, mutation, scoring, Top-K, BAC,
  LLM, or focused-verification behavior is added or changed.
- GET NO-3 and static-only results remain unchanged for unchanged inputs.
- Candidate canonicalization performs zero transport.
- Protected JSON artifacts and the protected stash are never modified.
- NO-4 is committed locally only; no push, PR, or merge is performed.

## Expected files

- `src/vulnspider/domain/models.py`
- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/discovery/network_canonicalization.py`
- `src/vulnspider/discovery/html_extractor.py`
- `src/vulnspider/discovery/__init__.py`
- focused unit and Chromium loopback tests/fixture/Gate manifest
- architecture/domain/v0.2/decision documentation
- this execution plan

## Verification

1. Focused candidate, Guard, canonical builder/merge, pipeline, serialization,
   pickle, determinism, GET-regression, and static-only unit tests.
2. Dedicated actual Chromium loopback case proving natural POST attempt,
   target POST count zero, canonical structural output, no executed IDs or
   ProbeObservation, no baseline/probe traffic, raw-value absence, and zero
   canonicalization transport.
3. Adversarial cases: Authorization/API key/JWT/password/token, malformed,
   oversized, top-level array, duplicate key, off-origin, suffix host,
   non-primary Page, method/resource/content-type variants, and field/candidate
   budgets.
4. Strict browser-loopback Gate with zero skips and simple CLI E2E.
5. Full regression, format, lint, type, diff, status, protected hashes, and
   stash OID.
6. Independent Gate Review; remediate every Critical/High/Medium or invariant
   test gap and rerun affected Gate plus full regression.

## Progress

- [x] Implement bounded structural candidate collection.
- [x] Add canonical `POST`/`JSON_BODY` construction.
- [x] Add focused and adversarial unit coverage.
- [x] Add dedicated actual Chromium loopback coverage and strict Gate entry.
- [x] Run all verification gates.
- [x] Complete independent review and remediation.
- [x] Move this plan to `completed/` and commit allowed files explicitly.

## Verification record

- Focused regression: 185/185 passed after final review remediation.
- Dedicated Chromium POST JSON case: passed; target and off-scope POST counts
  both zero.
- Strict browser-loopback Gate: 19/19 required, zero skipped/failed.
- Simple CLI Chromium E2E: 2/2 passed; POST structural IDs absent from executed
  IDs/ProbeObservation and crawl/analysis snapshot IDs matched.
- Full repository regression: 513/513 passed after final eligibility correction.
- Format, lint, type-hint, and `git diff --check`: passed.
- Seven protected JSON SHA-256 values and protected stash OID: unchanged.

## Independent Gate Review

The first review identified Medium gaps in over-budget event-order determinism
and sensitive material hidden under arbitrary header names or credential-shaped
JSON member names. The implementation now retains the stable-ID-smallest bounded
POST set, normalizes overflow state, and applies the shared sensitive policy to
the complete transient header mapping, parsed JSON tree, and member-name tuple.
Fresh focused, strict Chromium, full regression, and static checks passed after
those corrections. Final independent verdict: APPROVE/PASS with no remaining
Critical, High, Medium, invariant, or test gap.
