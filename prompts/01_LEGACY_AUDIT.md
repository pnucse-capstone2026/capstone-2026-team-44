# Prompt 01 — Legacy WHSPIDER Audit

Copy the prompt below into a fresh Codex thread.

---

Read `AGENTS.md` first, then read:

- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/FEATURE_SCHEMA.md`
- `docs/PROTOTYPE_V0_1.md`
- `docs/DECISION_LOG.md`

Then analyze the entire legacy project under:

- `reference/whspider_legacy/`

## Repository-root rule

Treat the current working directory containing `AGENTS.md` as the only project root.

The legacy project must exist at:

`reference/whspider_legacy/`

Do not search parent directories for alternative copies of the legacy project.
Do not analyze files outside the current project root.
If the expected legacy directory is missing, stop and report the missing path instead of guessing.

## Goal

Determine exactly how much of the previous WHSPIDER project should be reused for VulnSpider prototype v0.1.

## Critical constraint

**Do not modify any code. Do not refactor. Do not create implementation files.**

This task is audit and design analysis only.

## Questions to answer

1. What is the current module map?
2. What is the actual execution flow from CLI/start URL to stored/exported crawl results?
3. What are the exact crawler input/output structures?
4. What is the current persistence schema?
5. Where are query parameters extracted?
6. Where are forms and input fields extracted?
7. How are form `method` and `action` handled?
8. Are hidden inputs discarded? If so, where?
9. How is internal URL scope checked?
10. How are redirects handled?
11. How are cookies/sessions handled?
12. How are HTTP 4xx/5xx responses handled?
13. Is response encoding forced or inferred?
14. Where is crawling coupled to database, CLI, LLM, RAG, graphing, or export logic?
15. Which modules are safe to reuse as-is?
16. Which modules should be reused only through adapters?
17. Which modules should not be reused in v0.1?
18. What mismatches exist between the legacy page-centric data model and the new:
    - Endpoint
    - InputPoint
    - VulnerabilityCandidate
    model?
19. What security/scope bugs or unsafe assumptions should be fixed before reuse?
20. What is the smallest adapter boundary that preserves proven crawling logic without importing old architecture?

## Required output

Create only:

`docs/LEGACY_AUDIT.md`

Use this structure:

1. Executive Summary
2. Repository Module Map
3. Actual Execution Flow
4. Data Flow and Persistence
5. Crawler Output Examples
6. Coupling Points
7. Reuse Matrix
   - reuse as-is
   - reuse behind adapter
   - refactor later
   - do not reuse
8. Architecture Mismatches
9. Safety and Correctness Risks
10. Proposed LegacyCrawlerAdapter Boundary
11. Migration Plan for v0.1
12. Open Questions
13. File-level Evidence

## Evidence rule

Every important claim must cite concrete repository file paths and relevant symbols/functions/classes. Do not write generic guesses.

## Done when

- no source code changed,
- `docs/LEGACY_AUDIT.md` exists,
- all reuse recommendations have file-level evidence,
- the proposed adapter maps legacy records into the domain model in `docs/DOMAIN_MODEL.md`,
- unresolved uncertainty is explicitly listed instead of guessed.

At the end, report:

- files inspected,
- files created,
- code changes: must be none,
- top 5 risks,
- recommended reuse decision.
