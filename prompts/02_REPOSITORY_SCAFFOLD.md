# Prompt 02 — Repository Scaffold

Read `AGENTS.md` and all relevant docs first.

Also read `docs/LEGACY_AUDIT.md` if it exists.

1. Read AGENTS.md.
2. Read docs/LEGACY_AUDIT.md.
3. Treat the decisions in LEGACY_AUDIT.md as implementation constraints.
4. Do not modify reference/whspider_legacy/.
5. Do not implement crawling, probing, feature extraction, or scoring yet.
6. This task creates only the Python implementation scaffold and development harness.
7. Keep the scaffold minimal. Do not create speculative modules that are not justified by current docs.

## Goal

Create the minimal Python repository scaffold required for VulnSpider prototype v0.1 without implementing crawler, probe, feature extraction, or scoring behavior yet.

## Constraints

- Follow `docs/ARCHITECTURE.md`.
- Do not modify `reference/whspider_legacy/`.
- Do not add LLM, BAC, dashboard, Playwright, FastAPI, PostgreSQL, or ML dependencies.
- Keep dependencies minimal.
- Prefer a `src/` layout.
- Add exact developer commands to `AGENTS.md` only if the scaffold establishes them.
- Do not invent behavior not specified in docs.

## Required scaffold

At minimum:

```text
src/vulnspider/
  domain/
  scope/
  discovery/
  surface/
  observation/
  features/
  scoring/
  selection/
  reporting/
  cli.py

tests/
  unit/
  integration/
  fixtures/
```

Choose and configure a small coherent Python toolchain for:

- package management/build metadata
- unit tests
- formatting/linting
- type checking

Explain dependency choices before adding them.

## Required checks

- package imports
- empty test suite command works
- lint/format configuration works
- type-check command works

## Done when

- repository installs in development mode or equivalent,
- `python -m vulnspider...` or planned CLI entrypoint is structurally possible,
- test/lint/type-check commands are documented,
- no network behavior is implemented,
- relevant checks pass.

Before editing, present a short plan. After implementation, review the diff and report exact commands and results.
