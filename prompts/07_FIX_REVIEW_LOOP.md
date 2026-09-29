# Prompt 07 — Fix Review Findings Loop

Read:

- `AGENTS.md`
- `CODE_REVIEW.md`
- relevant docs
- the independent review findings
- current diff

## Goal

Fix only valid review findings, preserve scope, re-run checks, and prepare for re-review.

## Rules

1. Classify each finding:
   - accept
   - reject with evidence
   - needs clarification
2. Fix BLOCKER and MAJOR first.
3. Do not use review feedback as permission for broad refactoring.
4. Add regression tests for correctness/safety bugs when feasible.
5. Update docs if behavior changed.
6. Keep a short resolution log.

## Verification loop

```text
apply fixes
-> run narrow tests
-> run full relevant tests
-> lint/format/type checks
-> review diff against CODE_REVIEW.md
-> report remaining findings
```

## Stop conditions

Stop and request re-review when:

- required checks pass,
- accepted BLOCKER findings = 0 unresolved,
- accepted MAJOR findings = 0 unresolved.

Do not loop more than 3 repair iterations without escalating the underlying blocker and explaining whether the missing capability is:

- unclear docs,
- missing fixture,
- missing tool,
- unstable test,
- architecture conflict,
- environment problem.

At the end report:

- finding-by-finding resolution,
- files changed,
- tests/checks run and results,
- remaining risks,
- whether independent re-review is required.
