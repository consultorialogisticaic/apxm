---
name: context
group: Lifecycle
description: Prime an APXM session before broad work — runs doctor, reads AGENTS.md and the relevant _shared rules, surfaces subsystem ownership, and recalls APXM memory. Run at the start of any session that will touch >1 file or any non-trivial change.
user-invocable: true
---

# APXM Context

Load context before broad work so you don't make confident wrong
assumptions about the project. Run this at the start of every session
that will touch more than one file or any non-trivial change. Skip only
for typo fixes or single-line edits.

## What this skill does

1. **Verify env** — `dekk agents doctor`. Catches a misconfigured Nix
   shell, stale MLIR build, or missing `LLM_GATEWAY_KEY` before any work
   starts.
2. **Surface live AIS op list** if AIS dialect work is anticipated —
   `dekk agents ops list`. Confirms what's actually defined in
   `crates/machine/ais/` rather than what you remember.
3. **Read project memory**:
   - `AGENTS.md` — the SSOT.
   - The closest relevant `_shared/` rule(s):
     - Code edits → `_shared/apxm-development-rules.md`
     - Touching `~/.apxm/config.toml`, HF cache, zoo manifests, build
       paths → `_shared/apxm-storage-layout-rules.md`
     - Anything with a git mutation → `_shared/apxm-agent-operating-rules.md`
4. **Read the closest subsystem doc**:
   - Compiler/passes → `docs/compiler/pipeline.md`
   - Backends and Port bindings →
     `docs/agents/portable-core-interface-contract.md`
   - Capability admission, Port bindings, checkpoints, confinement, or
     evidence → `docs/agents/portable-core-interface-contract.md`,
     `docs/agents/agent-program-composition-and-air-contract.md`
5. **Recall memory** — APXM has 20+ memories in
   `~/.claude/.../memory/`. Always check for matches on:
   `apxm_*`, `feedback_*`. Especially:
   - `apxm_positioning` (don't call APXM "an agent framework")
   - `apxm_phase_status` (what's actually shipped)
   - `feedback_no_referential_comments`
   - `feedback_no_kill_user_slurm`
6. **Confirm subsystem ownership**:
   - Compiler edits → `crates/compiler/`
   - Runtime edits → `crates/runtime/`
   - AIS op edits → `crates/machine/ais/` only (everything else consumes)
   - Backend glue → `crates/runtime/backends/`

## Output

A brief summary back to the user:

- What subsystem the work targets.
- What rules apply.
- What doctor reported.
- What memory was relevant.

Then proceed to `plan` (if non-trivial) or to the edit itself
(if trivial).

## Anti-patterns

- Skipping doctor because "I just ran it last session".
- Starting compiler work without checking `crates/machine/ais/` is the
  op-defining owner.
- Quoting old AIS op names from memory instead of `dekk agents ops list`.
- Skipping memory recall — most past incidents are documented.
