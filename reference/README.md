# Legacy Reference Code

Place the previous WHSPIDER project under:

```text
reference/whspider_legacy/
```

Policy:

- read-only by default,
- audit before reuse,
- prefer adapter boundaries,
- do not import the old LLM/RAG pipeline into v0.1,
- do not adopt the old database schema as the new domain model.

After adding the legacy code, run `prompts/01_LEGACY_AUDIT.md` in a fresh Codex thread.
