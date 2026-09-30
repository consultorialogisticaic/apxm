---
name: finish
group: Lifecycle
description: Pre-claim gate — runs focused Dekk tests, doctor, secrets, and artifact-placement checks before any claim of completion. Refuses to claim done until all pass.
user-invocable: true
---

# APXM Finish

Load `_shared/apxm-agent-operating-rules.md` before running this gate.

Enforces that "completion" claims are backed by checks, not by agent
confidence. Run before any verbal "done", PR-ready, or handoff to user.

## What this skill does

Run these in order. If any fail, do **not** claim completion:

1. **Run `simplify` first** if not already.
2. **Focused tests for touched crates**:
   - the named `test-*` recipe per crate that changed (`dekk agents --help`);
     there is no bare `test -p <crate>` scope.
   - `dekk agents test-cli` if `crates/tools/cli/` changed.
   - `dekk agents test-python-frontend` if
     `crates/compiler/frontend/python/` changed.
3. **Doctor**: `dekk agents doctor`. Catches a drifted Nix shell or
   stale MLIR.
4. **Commit-message lint** for any queued commits:
   `dekk agents commit-lint --range origin/main..HEAD`.
5. **Skills and adapter check** if anything under `.agents/` or `AGENTS.md`
   changed: run `dekk agents check-agent-skills`, then run the workspace
   agent-skill check for this checkout so pointers and `.agents.json` are
   current.
6. **`git status --short`** and **`git diff --stat`**. Read every
   line. Nothing should be unexpected.
7. **Secrets scan** if settings/env/deploy files changed:
   ```bash
   git diff --staged | grep -iE 'LLM_GATEWAY_KEY|oauth_token|hf_token|HUGGING_FACE_HUB_TOKEN|sk-[a-zA-Z0-9]{20,}'
   ```
   Should return nothing. Also confirm `.claude/settings.local.json`
   is **not** staged (it's gitignored for a reason).
8. **Artifact placement** if any new path is added:
    - All generated artifacts under `.apxm/`?
    - Nothing under `examples/**/results/`, `examples/**/runs/`, or
      `examples/**/sessions/`?
    - `RepoLayout` used for any new path?
9. **Report concretely** to the user:
    - What changed (per file/crate).
    - What passed (each command + exit code).
    - What's local-only (build artifacts, local config).
    - What remains (any follow-up tasks, deferred items).

## Output template

```
## Finish report

### Changed
- crates/runtime/...: <one-line summary>
- ...

### Passed
- dekk agents test-<crate>: green
- dekk agents doctor: green
- dekk agents check-agent-skills: green

### Local-only
- /tmp/apxm-target-$USER (build cache, not committed)

### Remaining
- <follow-up task 1>
- <follow-up task 2>
```

## Anti-patterns

- "Tests pass" without naming which tests.
- Skipping the secrets scan because "I'm sure it's clean".
- Marking done when a release or commit check warned but you didn't
  address it.
- "I didn't run X because it's slow" — slow is not a reason to skip;
  scope down the command instead.

## Next step

Hand off to `commit` when the user is ready to stage/commit/push.
Never auto-commit from `finish`.
