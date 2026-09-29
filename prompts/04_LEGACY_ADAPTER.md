# Prompt 04 — Legacy Crawler Adapter

Read:

- `AGENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/PROTOTYPE_V0_1.md`
- `docs/LEGACY_AUDIT.md`
- relevant legacy files

## Goal

Implement the smallest adapter that converts legacy WHSPIDER crawl records into normalized VulnSpider domain objects.

## Architecture constraint

The legacy project remains read-only by default.

Prefer:

```text
Legacy record
  -> LegacyCrawlerAdapter
  -> Raw/normalized surface
  -> Endpoint
  -> separate InputPoint objects
```

Do not refactor the old crawler into the new architecture in this task.

## Required behavior

### Query parameters

Input:

```text
/search?q=book&page=1
```

Output:

```text
GET /search :: query.q
GET /search :: query.page
```

### Forms

Resolve, where legacy evidence permits:

- form action
- form method
- input name
- input type hint
- source page

Create one InputPoint per named field.

### Hidden inputs

Do not silently drop hidden inputs in the new adapter output. Preserve their type/visibility in metadata when legacy records expose them.

### Deduplication

Equivalent normalized InputPoints must deduplicate deterministically.

## Safety constraints

- no new network calls in unit tests,
- no scanning behavior added,
- no external-host expansion,
- do not import old LLM/RAG path.

## Tests

Use fixtures for:

1. multiple query params,
2. repeated URL with different values,
3. GET form,
4. POST form,
5. same parameter name in query and form,
6. duplicate records,
7. missing/partial legacy fields,
8. hidden input if legacy representation allows it.

## Done when

- adapter output matches the domain model,
- tests pass,
- no legacy source file changed unless a separately documented blocker made it unavoidable,
- unresolved mapping gaps are written to `docs/LEGACY_AUDIT.md` or `docs/DECISION_LOG.md` rather than guessed.

Before implementation, produce a plan and identify the exact legacy record shape from code evidence.
