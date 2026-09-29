# Split Crawl And Analysis Outputs

## Goal

Make the public `vulnspider -u URL` adapter publish a canonical crawl report and
an analysis report as two independently atomic JSON files while preserving the
implemented discovery and probe pipeline.

## Non-Goals

- Redesigning crawler, discovery, merge, ProbePlanner, RequestExecutor, feature,
  scoring, or Top-K behavior.
- Changing long-form `analyze --url` or `analyze --input` report semantics.
- Push, PR, or merge operations.

## Context Read

- `AGENTS.md`
- `PLANS.md`
- `docs/exec-plans/completed/simple-dynamic-cli.md`
- `src/vulnspider/cli.py`
- `src/vulnspider/pipeline.py`
- `src/vulnspider/discovery/combined.py`
- `src/vulnspider/reporting/json_report.py`
- relevant domain models and CLI/integration tests

## Current State

The simple command runs the validated combined pipeline and atomically emits one
selection-oriented `vulnspider-result.json`. The validated discovery wrapper is
held inside `AnalysisResult`, so it is only visible to the CLI after probe
analysis succeeds.

## Proposed Changes

1. Add canonical crawl and extended analysis serializers which delegate to the
   existing discovery and selection serializers and omit raw bodies and request
   values.
2. Add a narrow validated-discovery callback to `analyze_url()` so the simple
   adapter can publish crawl evidence before probe analysis without duplicating
   pipeline orchestration.
3. Make simple CLI defaults `vulnspider-crawl.json` and
   `vulnspider-analysis.json`, add `--crawl-output`, and preserve long-form
   commands.
4. Add focused failure/publication, linking, compatibility, safety, help, and
   real-Chromium tests; update minimal user documentation.

## Interfaces / Data Changes

- `analyze_url()` gains an optional callable receiving a revalidated
  `StaticCrawlResult` or `CombinedDiscoveryResult` before analysis.
- `AnalysisResult` retains produced `FeatureVector` values for authoritative
  reporting.
- Simple root CLI gains `--crawl-output`; root `-o/--output` becomes the
  analysis path. Long-form parser and existing report format remain unchanged.

## Safety / Scope Impact

No network policy or execution behavior changes. Crawl output uses canonical
discovery `to_dict()` data already validated for sensitive-value elision.
Analysis output records stable identities and safe observations, but omits
request parameters, headers, cookies, response headers/text, redirect values,
probe markers, and raw DOM. Each destination is written through a same-directory
temporary file, flushed, fsynced, and atomically replaced.

## Test Plan

- Focused unit tests for defaults, custom paths, static/dynamic inputs, stable
  linking, canonical contents, publication failures, atomic cleanup, help, and
  long-form compatibility.
- At least one real Chromium loopback integration test covering both files,
  READY/probe evidence, same-origin traversal, cross-origin and active-channel
  blocking, sentinel elision, and cleanup.
- Final Gate, full unittest, Native Static E2E, v0.1 smoke, format, lint, types,
  and diff checks.
- Exactly one independent Gate Review; one Critical/High-only fix loop at most.

## Acceptance Criteria

- [x] Simple Dynamic and `--static-only` success publish both requested JSON
  files with stable crawl-to-analysis references.
- [x] Invalid discovery publishes neither file; post-crawl analysis failure
  leaves only a valid crawl report; degraded completion publishes crawl only and
  exits 4.
- [x] Existing long-form CLI behavior and exit codes remain compatible.
- [x] Reports and stdout contain no raw DOM, password/sentinel, request secret,
  or active-channel leak.
- [x] All required verification passed and the one independent Gate Review's
  sole High finding was fixed in the permitted single correction loop.
- [x] Focused commit is `feat(cli): split crawl and analysis outputs`.

## Progress Log

- 2026-08-04: Confirmed clean branch at `9af5c44`; inspected the existing
  simple adapter, pipeline handoff, canonical discovery serializers, atomic JSON
  writer, and reporting provenance models.
- 2026-08-04: Implemented canonical crawl and authoritative analysis reports,
  the validated crawl handoff, independent atomic publication, degraded
  crawl-only termination, simple Static sensitive-form elision, CLI defaults,
  documentation, and focused failure/safety coverage.
- 2026-08-04: Focused CLI/output plus real-Chromium coverage passed 52/52;
  full unittest passed 438/438; Final Gate passed 8/8 with skipped/failed/missing
  all zero; Native Static E2E passed 1/1; v0.1 smoke passed 7/7; format, lint,
  types, and diff checks passed.
- 2026-08-04: Exactly one independent Gate Review reported Critical 0, High 1,
  Minor 2, and three related adversarial test gaps. The sole High was fixed in
  the permitted one correction loop by revalidating response pairing,
  FeatureVector/ResponsePair ownership, scoring coverage, and deterministic
  selection agreement. No second review was requested.
- 2026-08-04: Post-fix focused CLI/output plus real-Chromium coverage passed
  55/55; full unittest passed 441/441; Final Gate passed 8/8 with
  skipped/failed/missing all zero; Native Static E2E passed 1/1; v0.1 smoke
  passed 7/7; format, lint, types, and diff checks passed.

## Decision Log

- Decision: Publish crawl output through an optional pipeline handoff callback.
- Reason: This preserves exactly one `analyze_url()` orchestration call while
  making the required partial-success boundary observable to the CLI.
- Decision: Extend `AnalysisResult` with retained feature vectors.
- Reason: Reporting must serialize authoritative extracted features rather than
  recomputing them from scoring evidence.
- Decision: Bind the existing pre-canonical sensitive-form elision extractor in
  simple Static-only mode, leaving long-form Native Static behavior unchanged.
- Reason: A newly serialized crawl report must not expose password controls or
  their sentinel values in either simple discovery mode.

## Open Questions

- None.
