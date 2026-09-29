# Git Workflow

## Branch status

- **Current transitional base:** `prototype/v0.1`
- **Future official base:** `main`, after the completed v0.1 checkpoint is
  promoted.

Until promotion is explicitly completed, PRs target `prototype/v0.1`. After
promotion, new work targets `main`. Do not infer the transition from branch
names alone; confirm the repository announcement and PR base.

## Protected base policy

- Never commit directly to the active base branch.
- Never force-push the active base branch.
- Use a short-lived branch and PR.
- Keep one PR focused on one goal.
- Require passing checks before merge.
- Use reviewers appropriate to the changed ownership boundary.

## Branch naming

Examples:

```text
feature/native-static-crawler
feature/bac-scoring
experiment/gpt-gemini-harness
fix/probe-provenance
docs/v0.2-alignment
integration/html-report
```

Use `feature/`, `fix/`, `docs/`, `experiment/`, or `integration/` followed by a
short purpose. Do not work on a teammate's branch without explicit agreement.

## Starting work

For the current working copy, the user-selected branch is
`feat/dashboard-improve` (2026-09-21). Continue on this existing branch; create
a different branch only when explicitly requested. This instruction takes
precedence over the default branch-creation example below.

```text
git fetch origin --prune
git switch prototype/v0.1
git pull --ff-only origin prototype/v0.1
git switch -c <branch-name>
```

After main promotion, substitute `main` for `prototype/v0.1`.

Before editing, confirm:

- The current branch is the intended short-lived branch.
- `git status --short` is understood and safe.
- Local demo/generated files are ignored or stashed intentionally.
- No secret or personal configuration is staged.

## Draft PR flow

Open a Draft PR early when work affects a shared interface, network scope, or
payload behavior. The PR description follows
`.github/pull_request_template.md`.

Draft PRs are useful for:

- Proposed Contract review before implementation.
- Early safety review.
- Coordinating producer/consumer changes.
- Detecting overlapping branches before conflicts grow.

Mark ready only when scope, tests, adversarial cases, and docs are current.

## Merge strategy

### Default: squash merge

Use squash merge for normal short-lived feature, fix, docs, and experiment PRs.
The final commit should describe one coherent goal.

### Exception: integration merge commit

A merge commit is allowed when an integration PR must preserve meaningful
existing teammate commits or combine reviewed histories. The PR must explain:

- Why squash would lose useful ownership/history.
- Which commits are preserved.
- How conflicts were resolved.
- Which additional integration fixes are in the merge commit.

Never push conflict resolutions back to the teammate's original branch unless
that owner explicitly requests it.

## Updating a branch from base

Always fetch first:

```text
git fetch origin --prune
```

For a private, unpublished short-lived branch, rebase onto the latest base is
allowed:

```text
git rebase origin/prototype/v0.1
```

For a shared or already reviewed branch, prefer merging the base into an
integration branch so existing commit identity remains stable:

```text
git merge origin/prototype/v0.1
```

After main promotion, use `origin/main`.

Rules:

- Do not rebase or force-push a teammate's branch.
- Do not use `reset --hard` as a conflict-resolution shortcut.
- If a pushed private branch must be rewritten, coordinate first and use only
  the repository-approved procedure; never use plain `--force`.
- Re-run tests and review the final base-relative diff.

## Conflict resolution

Resolve conflicts from code meaning, not by choosing all of "ours" or "theirs".

1. Identify the merge base and both owners' intent.
2. Preserve the latest base behavior.
3. Preserve the feature's reviewed behavior.
4. Reconcile contracts and provenance explicitly.
5. Add an integration regression test when the conflict can recur.
6. Run narrow and full checks.
7. Review `git diff --check` and the base-relative diff.
8. Commit the resolution only on the integration branch.

For shared contracts, affected producer and consumer review the resolution.

## Review requirements

- Documentation-only changes: one reviewer unless they authorize behavior or
  contract changes.
- Public/canonical interface changes: all affected producer/consumer owners.
- Network scope, redirect policy, or payload execution changes: two reviewers
  recommended.
- Confidence-rule changes: whole-team review.
- Secret-handling or experiment-retention changes: owner plus safety reviewer.

## Secrets and local configuration

Never commit:

- API keys or provider credentials.
- Cookies, session tokens, authorization headers, or test-account secrets.
- `.env` contents.
- Browser profiles or credential stores.
- Unredacted request/response captures containing secrets.

Policy:

- Commit an `.env.example` only with placeholder names and no real values.
- Load secrets from environment variables or an approved local secret store.
- Redact logs before sharing.
- If a secret is staged or pushed, stop, revoke/rotate it, and follow the
  repository incident procedure. Removing it from the latest diff is not
  sufficient.

## Generated artifacts and experiments

Source control may include small deterministic fixtures required by tests.
Do not commit local reports, screenshots, caches, provider raw responses, or
large experiment outputs by default.

Store raw experimental results in the team-approved artifact location with:

- Dataset and run ID.
- Code/config/contract versions.
- Provider/model version.
- Redaction status.
- Retention and access policy.

Commit only reviewed summaries, schemas, and small sanitized fixtures.

## Before requesting review

```text
git status --short
git diff --check
python -B -m unittest discover -s tests
python tools/check_format.py
python tools/check_lint.py
python tools/check_types.py
```

Also verify:

- The PR contains one goal.
- No unrelated formatting or generated artifacts are present.
- No secret or personal file is tracked.
- Documentation distinguishes Implemented, Planned for v0.2, Proposed Contract,
  Experimental, Deferred, Historical, and Completed and Frozen status.
- The PR base is the current protected branch.
