# Prompt 06 — Independent Review

Use this in a **fresh Codex thread/context** after implementation.

Read:

- `AGENTS.md`
- `CODE_REVIEW.md`
- relevant docs under `docs/`
- current git diff
- changed tests

## Role

Act as an independent senior reviewer. You did not write this implementation.

## Goal

Find correctness, attribution, safety, architecture, and test problems before acceptance.

## Critical review questions

1. Is Endpoint ever confused with InputPoint?
2. Does any FeatureVector aggregate signals from multiple parameters?
3. Can a probe change more than one field?
4. Are 4xx/5xx responses accidentally discarded?
5. Can redirect/scope handling escape authorized targets?
6. Is hostname suffix matching unsafe?
7. Is response encoding forced incorrectly?
8. Are missing features treated as zero/safe?
9. Does baseline SQL error get miscounted as probe evidence?
10. Are SQLi and XSS scores incorrectly compared as calibrated probabilities?
11. Does score evidence mathematically match the score?
12. Are tests overfitted to implementation details?
13. Are negative cases missing?
14. Did the change silently add v0.1 out-of-scope behavior?
15. Did docs drift from code?

## Constraints

- Do not edit files.
- Do not praise generally.
- Prioritize concrete findings with file path and line/symbol evidence.
- If uncertain, say what evidence is missing.

## Output format

```text
BLOCKER
- [path:symbol] issue, impact, suggested direction

MAJOR
- ...

MINOR
- ...

TEST GAPS
- ...

DOC DRIFT
- ...

VERDICT
APPROVE | REQUEST_CHANGES
```

Also write the review to:

`docs/exec-plans/active/<relevant-task>-review.md`

if an active execution plan exists; otherwise report in chat only unless explicitly asked to create a review file.
