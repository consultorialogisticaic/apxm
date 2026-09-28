# agents — agent-facing project memory

`AGENTS.md` is the canonical portable instruction source for this repository.
Generated adapters are deliberately thin: `CLAUDE.md`, `CODEX.md`,
`.cursorrules`, and `.github/copilot-instructions.md` point back to this file;
`.agents.json` indexes the source and skills; `.claude/skills` points to
`.agents/skills`. Update `AGENTS.md` and the skills under `.agents/` first, then
regenerate or validate the adapters with the workspace agent-skill tooling.
Do not create a second instruction source or copy product-specific vocabulary
into this product-neutral repository.

## 1. What agents is

`agents` is the APXM abstract-machine repo: AIS dialect, compiler, runtime,
capability contracts, context handling, permissions, orchestration, CLI, and
the profile-backed agent execution path. It is not the whole APXM workspace;
the top-level workspace coordinates shared documentation but owns no
product control plane or alternate execution semantics. Downstream products may
pin APXM, but `agents` stays product-neutral and cannot depend on their
identifiers, schemas, routes, or services.

Do **not** describe `agents` as the APXM coordinator, a managed product control
plane, a downstream Host/SDK owner, or only "vLLM dispatch". The correct
anchor is: *the abstract machine and runtime contracts for APXM agents*.

## 2. Authority CLI

`dekk agents` is the only sanctioned entry point. Never invoke `cargo`,
`docker`, `srun`, `sbatch`, or `python tools/scripts/cargo.py` directly.
Always go through Dekk so the env contract, target dir, and process
accounting stay consistent.

Command groups (see `dekk agents --help` for the live list):

- **Build & Test**: `build`, `build-dialect`, `test`, `test-cli`,
  `test-python-frontend`, `codegen`, `clean`, `scrub-rustc-cache`
- **Compilation**: `canonical-air`, `compile-service-canonical`,
  `execute-canonical`
- **Authoring**: `validate`, `analyze`, `explain`, `agent`
- **Configuration**: `doctor`, `backend`, `cache`, `process`, `mcp`,
  `commit-lint`
- **Discovery**: `ops`, `template`, `tokenize`

`dekk agents --help` is the only live list; this one drifts.

Most `dekk agents` recipes are fixed command chains with no argument
placeholder. A bare `dekk agents test -p <crate>` is not a supported scoped
command; use the named per-surface recipes instead (`test-program`,
`test-kernel`, `test-compiler`, `test-runtime-seams`, …).

If a needed action isn't yet wrapped, **add a Dekk command** in `.dekk.toml`
rather than shelling out — that is the project-wide pattern.

Any downstream-managed MCP surface may project exact granted Capabilities
through its own transport, but it is not an Agents-owned Agent Program
lifecycle tool family.

## 3. Lifecycle workflow

Use the lifecycle skills when the task scope warrants them. They are thin
orchestrators (≤100 lines each) — they do not contain rule content themselves;
they point at `_shared/` rules.

1. **`context`** — prime the session: `dekk agents doctor`,
   read `AGENTS.md`, pull the relevant `_shared/` rule, recall
   memory, confirm subsystem ownership. Run before any work touching >1
   file.
2. **`plan`** — write a plan before implementing. Required
   for changes that touch >3 files, modify a public API/AIS op, introduce
   a claim, or need GPU allocation.
3. **`execute-plan`** — drive a written plan to completion with focused
   per-phase verification and no scope creep.
4. **`simplify`** — remove copied `_shared/` text, weak
   abstractions, referential comments, and over-large skill bodies before
   declaring done.
5. **`finish`** — pre-claim gate: run the focused
   `test-*` recipe, `dekk agents doctor`, secrets scan,
   artifact-placement check. Refuse to claim "done" until all pass.
6. **`commit`** — commit/push gate: enforce the
   user's commit rules — no auto-commit, no push without explicit
   approval, PRs only for pushed work, push to `main` only when explicitly
   authorized.

This is the *ironbear pattern* — each skill is a checkpoint, not a body of
new content.

## 4. Repo layout

- **`crates/`** — Rust workspace.
  - `crates/machine/ais/` — AIS-owned closed effect/composition and structural
    operation definitions and generated catalogue.
  - `crates/machine/program/` — FrontendGraph, AIR structure, verification,
    and Rust lowering that consume the AIS catalogue.
  - `crates/compiler/` — canonical AIR lowering, frontend Python/TypeScript
    bindings, TableGen-driven MLIR. Its `build.rs` emits the pass TableGen and
    C-API dispatch from the AIS-owned pass specs; it does not define passes.
  - `crates/runtime/` — executor, handlers, backend adapters (LLM, local,
    tool).
  - `crates/runtime/backends/` — LLM provider implementations.
  - `crates/tools/cli/` — `apxm` binary subcommands.
- **`tools/scripts/`** — Python entrypoints Dekk calls into (`cargo.py`,
  `apxm_mcp_install.py`).
- **`crates/compiler/frontend/python/apxm_program/`** — the canonical
  installable Python Agent Program authoring frontend. It is the only
  Python package under the authoring frontend.
- **`docs/`** — design docs for the core runtime.
- **`.agents/`** — this SSOT plus `_shared/` rules, lifecycle skills,
  domain skills, and `domains/` navigation README-only directories.
- **`.apxm/`** — generated compiler, execution, and local session artifacts
  (gitignored).

Skills under `.agents/skills/` are agent-tooling for working *on* APXM and
stay here.

## 5. Build, test, codegen

Required env (provided by `nix develop` and checked by `dekk agents doctor`):

- `CARGO_TARGET_DIR=/tmp/apxm-target-$USER` — `/home` is shared WekaFS,
  builds there contend with 50+ other users and randomly fail.
- `MLIR_DIR`, `LLVM_DIR` — set by the Nix shell (the pinned Nixpkgs LLVM/MLIR package).
- `LLM_GATEWAY_KEY` — comes from the shell `env:LLM_GATEWAY_KEY`; never commit.

Enter the reproducible shell before running any owner command:

```bash
nix develop
```

Standard cadences:

```bash
dekk agents doctor                # always run on session start
dekk agents build                 # build of apxm-cli (driver+metrics)
dekk agents build-dialect         # rebuild MLIR after .td or C++ shim edits
dekk agents codegen               # regen Python frontend bindings after .td edits
dekk agents test-all              # full workspace tests (requires MLIR)
dekk agents test-cli              # cli-only (preserves MLIR-linked binary)
dekk agents test-python-frontend  # pytest the Python frontend
```

Run **focused** checks during iteration. Full `test-all` is for pre-PR
verification only.

When you edit a `.td` file or a TableGen-emitted C++ shim, you must run
`dekk agents build-dialect` first **then** `dekk agents codegen` before the
Rust workspace will compile or the Python frontend will see the new op.

## 6. Artifact placement

All generated artifacts live under `.apxm/` (repo-local, gitignored).
Never put benchmark CSVs, session directories, `.apxmobj` files, compiler
diagnostics, evidence manifests, or per-run configs under
`examples/`, `docs/`, or repo root.

If you find a generated artifact under `examples/` or `docs/`, move it to
the matching `.apxm` location and patch whatever script wrote it there —
do **not** add an ignore guard to mask the bug.

## 7. Verification contract

Run `dekk agents doctor` and the smallest focused test for the changed crate.
Promote schema and attribute strings to their owning constants rather than
duplicating literals.

## 8. PXM theory and current semantics

The pages under `docs/pxm/` preserve the theory and historical lineage of the
abstract machine. They are not alternate executable APIs. Current authority is
the five-operation AIS catalogue, FrontendGraph, AIR, exact Port Contracts,
and the execution runtime described by current contracts and guides.

## 9. AIS operation ownership

**`crates/machine/ais` is the sole operation-definition owner.** It defines a
closed five-operation effect/composition family and a separate closed
structural family including compiler-emitted `ais.loop`. Program lowering,
compiler passes, runtime handlers, frontends, and inference backends are
consumers. `ais.loop` is not a sixth effect/composition operation, and no
frontend exposes a raw operation builder.

Repository examples are ordinary Agent Programs, not core runtime types or
product lifecycle concepts. Runtime evidence records committed loop
iterations through generic `LoopIterationCompleted` facts; core has no `Turn`
type.

After editing any `.td` file (TableGen op definition) or a TableGen-emitted C++
shim:

```bash
dekk agents build-dialect   # rebuild MLIR (TableGen + C++ + Rust)
dekk agents codegen         # regenerate Python frontend bindings
```

Both are non-negotiable: skipping either produces silent type drift
between the Rust runtime, the Python frontend, and the MLIR layer.

Canonical AIR → AIS MLIR lowering lives in
`crates/compiler/pipeline/src/canonical.rs`. That is the lowering path, not the
pass surface: `crates/machine/ais/src/passes/mod.rs` is the sole source of truth
for compiler passes (14 AIS passes plus `canonicalizer`/`cse`/`symbol-dce`,
across the Transform, Optimization, Analysis and Lowering categories).
`crates/compiler/pipeline/build.rs` calls its `generate_passes_tablegen`,
`generate_pass_dispatch`, and `generate_pass_descriptors` at build time to emit
`Passes.generated.td`, `PassDispatch.inc`, and `PassDescriptors.inc`. Add or
change a pass in the AIS owner; never register one in the compiler crate.

Attribute names must be a single source of truth — see the
`feedback_attribute_dual_naming` incident: the canonical enum lives in the AIS
owner; Python kwargs, MLIR attrs, and Rust executors must all
resolve through it, never via duplicated string literals.

## 10. Capability abstract machine vocabulary

APXM models **capabilities** as the first-class abstract-machine unit.
Each capability composes a **capability_binding** (callable implementation) plus a
**permission policy** (authority). Runtime authority flows through typed
**capability grants** (`grant_*` ids), not bare handler strings.

Canonical capability, Port-binding, and execution terms live in the local owner
contracts:

- `docs/agents/portable-core-interface-contract.md` — Port Contracts,
  Implementation Descriptors, Runtime Profiles, exact Port Bindings, and
  product-neutral Execution/Invocation Admission.
- `docs/agents/agent-program-composition-and-air-contract.md` — Capability,
  Tool, Skill, `ModelTargetRef`, Program Invocation, checkpoint, confinement,
  and evidence semantics.

When touching Capability definitions, admission, pack schemas,
`capability.invoke` lowering, or MCP tool projection, read those docs first and
keep code, schemas, and evidence aligned.

## 11. Storage layout

`/home` is shared WekaFS. It is **not** personal disk:

- **Build outputs**: `/tmp/apxm-target-$USER` (456 GiB local). `/home`
  contention has caused random ENOSPC and invalid-rustc-cache SIGBUS in
  the past.
- **Backend config**: `BackendStore::open` reads exactly one file,
  `$APXM_HOME/config.toml` (default `~/.apxm/config.toml`). A project-local
  `.apxm/config.toml` is **intentionally ignored** for backend registration —
  it is a per-instance concern, not a per-checkout one. If backends look
  missing, check `APXM_HOME`, not the project directory.
  (`crates/runtime/backend-registry/src/backend.rs`,
  `crates/machine/contracts/src/env.rs`.)
- **Read root**: `APXM_HOME` resolves backend configuration.

## 12. Boundaries (read before any potentially destructive action)

### Never, under any circumstance

- **Push to `main`**. Always work on a feature branch. The user moves
  the work to `main` through their own flow.
- **`git push --force`** anywhere without explicit approval.
- **`gh pr create`** unless the user explicitly asks for a PR. The
  commit + push gate stops at push.
- **Skipping commit checks**. Use `dekk agents commit-lint` when a commit
  message needs explicit validation.
- **`scancel`** a Slurm job owned by `apxm`. Always allocate a
  fresh service job alongside.
- **Commit secrets**: `LLM_GATEWAY_KEY`, OAuth tokens, HF tokens.
  `finish` scans for these.
- **Commit generated artifacts**: `.apxm/`, `zoo.toml`, `slurm-*.out`,
  `.apxmobj` files, benchmark CSVs.
- **Bypass `dekk agents`** for normal work — raw `cargo`/`docker`/`srun`
  break the env contract.
- **Delete or `git checkout --` unexplained files/branches**. They may
  be the user's in-progress work. Investigate first.
- **`git rebase --no-edit`**, `--no-gpg-sign`, `git commit --amend` on
  pushed commits.

### Confirm before doing

- Any `sudo` invocation.
- Any `docker run/build/rm/rmi` or image-tag mutation.
- Any Slurm submission (`sbatch`, `srun`, `salloc`).
- Posting to external notification or webhook endpoints.
- Any edit to `~/.apxm/config.toml`, `~/.bashrc`, `~/.gitconfig`,
  systemd units, cron entries, or `.claude/settings.local.json`.
- Cross-crate refactors and changes to public APIs / AIS ops — these
  warrant `plan` first.

### When in doubt

Read the relevant doc, recall memory, and ask. The cost of one
clarifying question is far smaller than the cost of an unintended
push, an overwritten branch, or a tainted benchmark.
