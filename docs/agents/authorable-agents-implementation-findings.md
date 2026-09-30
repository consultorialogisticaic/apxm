# Authorable Agents implementation findings

## Runtime composition correction — 2026-09-30

Runtime Service composition no longer seeds model request SSA identities with
synthetic `{value_id}` objects. Invocation input enters exclusively through
`EntrypointInput`; authored expressions and upstream operations produce every
other request value. The execution driver’s duplicate-input and future-result
guards remain unchanged.

The regression compiles typed Python and TypeScript Agents that pass their
input directly to a Model, then invokes the sealed artifact through Runtime
Service. It checks both resumable and single-shot starts, matching output for
an equivalent authored request assembly, and distinct output for distinct
prompts. The explicitly selected development inference backend is isolated in
a child process; no request SSA values are injected by the test.

`nix develop --command dekk agents test-runtime-service` reproduced the exact
duplicate-entrypoint rejection before the correction and passed afterward:
140 unit tests, 5 Unix integration tests, and 25 host/model integration tests.
`nix develop --command dekk agents build-service-artifacts` built the native
service pair. A disposable compiler-port-to-runtime-binary JSONL smoke
committed a typed Model result and checked durable `committed_return` state.
The complete `check-service` gate passed all 17 steps after formatting,
including Clippy and both frontend suites. This is local fixture inference
evidence, not hosted-provider qualification or a Linux release build.
No release selection changed.

The subsequent native `preflight-release` attempt passed all 16 executable
service-gate steps but stopped at commit metadata before release packaging:
the published manual-build commit used `ci`, which the owner lint does not
accept. Published history is retained; the next evidence commit uses the
documented vocabulary. Manual candidate images still require the complete
Linux gate, exact descriptor preparation and consumer image verification.
They do not activate the persistent worker or select a consumer runtime pin.

Audit date: 2026-08-15

Scope: the `apxm/authorable-agents` tree, including the S0–S12 plan, checked-in
agent packages, Python and TypeScript frontends, compiler/runtime path, CLI
canonical commands, generated artifacts, docs, and repository gates.

## Result

The implementation is complete against the S0–S12 plan, and the second closure
pass found and fixed the remaining cross-layer gaps. Capture exceptions now
carry generated diagnostic codes in both frontends; package shape validation is
shared by lint and canonical compile admission; package permission decisions
reach canonical capability admission; Hook bindings and continuation snapshots
are checked at runtime; handler packaging fails closed on duplicate or unsafe
manifests; and the admitted `max_wall_ms` ceiling is enforced with a typed,
cancellation-safe timeout. The shared frontend surface gate rejects untyped
capture errors.

The worktree is intentionally uncommitted, but it is fully revalidated in its
current dirty state. No commit or push was requested.

The working tree used for this audit is a separate temporary qualification
clone on an isolated feature branch. The source worktree was left untouched
because it contains unrelated user changes on another branch.

This closure pass used six parallel audits followed by a second runtime-focused
wave. All valid edits were reviewed in the shared target tree before the final
gates below.

## Requirement disposition

| Plan area | Disposition | Evidence |
| --- | --- | --- |
| S0–S2: de-versioning and docs truth | Complete | `check-deversion`, package-format guide, ADR-0022, and docs gates pass. |
| S3: generated capability catalogue | Complete | Generated capability modules and `dekk agents check` capability drift arm. |
| S4–S6: typed requirements, permissions, admission | Complete | Generated records/permissions, capability resolution and admission tests, including Ask/deny paths. |
| S7: two-file package manifests | Complete | Five package fixtures lint and verify; no retired manifest files remain in package trees. |
| S8–SC: generated frontend layers and parity | Complete | Generated vocabulary, records, serializers, diagnostics, conformance; Python/TypeScript parity passes. |
| SH: live Hooks and canonical execution | Complete | Canonical AIR contains Hook bindings and captured Hook bodies; canonical execution completes with zero failed nodes. |
| S9: checked frontend interface | Complete | Surface declarations, handler packaging types, diagnostics, and no-hand-authored-AIR gates pass. |
| S10: Skills | Complete | `read_skill`, `search_skills`, `list_skills`, package skills, and the Skilled example pass. |
| S11: docs and docs gate | Complete | Generated docs check passes; ADR-0015/0016, the package guide, the frontend vocabulary design note, and the verification runbook distinguish landed behavior from historical design. |
| S12: full verification | Complete | Aggregate workspace tests, release build, compiler/CLI suites, frontend/package/handler E2E, canonical compile/execute, static drift gates, tooling tests, and clippy are green in the current dirty tree. |

## Runtime and E2E evidence

The following checks were run from the target tree:

- `dekk agents setup`
- `dekk agents codegen`
- `dekk agents check`
- `dekk agents build`
- `dekk agents test`
- `dekk agents test-all`
- `dekk agents test-compiler`
- `dekk agents test-cli`
- `dekk agents test-cli-installed-frontend`
- `dekk agents check-agent-packages`
- `dekk agents test-handler-packaging`
- `dekk agents test-external-source-package`
- `dekk agents test-skill-example`
- `dekk agents test-package-handler-example`
- `dekk agents test-python-handler-example`
- `dekk agents check-example-artifacts`
- `dekk agents compile-service-canonical`
- `dekk agents execute-canonical`
- `dekk agents test-canonical-only`
- `dekk agents doctor`
- `dekk agents fmt-check`
- `dekk agents commit-lint --current`
- `dekk agents clippy`
- `dekk agents build-dialect`
- `python -m pytest tools/tests/ -q`

The frontends passed 41 Python tests, 36 TypeScript tests, and 9 installed-
package parity tests. The release CLI passed 40 library tests and 147 main
tests (one explicitly ignored), plus the canonical capability, canonical
execute, and canonical Skill subprocess suites. The workspace/compiler/runtime
suites and handler/package fixtures were green; `tools/tests/` passed 34 tests.

The canonical AIR inspection verified both `read_skill` calls, declared
`search_web` and `count_tokens` capability nodes, model target/compaction
metadata, Hook `PrepareSearchContext` and `RecordSearchContext` bindings, Hook
body operations, and permission requests. Canonical execution committed with
`executed_nodes=3`, `failed_nodes=0`, status `completed`.

## Verification coverage

The local Dekk surface makes each closure class independently runnable:

| Closure class | Local commands |
| --- | --- |
| Generated/docs/de-versioning | `check`, `check-frontend-surface`, `check-deversion`, `check-agent-skills` |
| Build and aggregate tests | `build`, `test`, `test-all`, `test-compiler`, `test-cli` |
| Frontend/package E2E | `test-typescript-frontend`, `test-external-source-package`, `test-frontend-examples`, `check-agent-packages`, `check-example-artifacts` |
| Skills and handler E2E | `test-skill-example`, `test-package-handler-example`, `test-python-handler-example` |
| Canonical shipping spine | `compile-service-canonical`, `execute-canonical`, tooling tests |

`test-all` is intentionally retained alongside the split suites: it is the
aggregate Cargo workspace test, while the focused commands add release-feature,
installed-frontend, package-handler, and source-level E2E coverage that the
aggregate command does not provide.

## Current revalidation

The final current-tree run is green:

- `git diff --check`, `dekk agents fmt-check`, and `dekk agents commit-lint --current`
- `dekk agents check`, `dekk agents build`, `dekk agents clippy`, and `dekk agents build-dialect`
- `dekk agents test`, `dekk agents test-all`, `dekk agents test-compiler`, and `dekk agents test-cli`
- `dekk agents test-cli-installed-frontend`, `check-agent-packages`, `test-handler-packaging`, and `test-external-source-package`
- `dekk agents test-frontend-examples`, `check-example-artifacts`, `test-skill-example`, `test-package-handler-example`, and `test-python-handler-example`
- `dekk agents compile-service-canonical`, `execute-canonical`, `test-canonical-only`, and `doctor`
- `dekk agents check-deversion`, `check-frontend-surface`, `check-frontend-parity`, and `check-agent-skills`
- `.dekk/env/bin/python -m pytest tools/tests/ -q` — 34 passed

The only `doctor` notices are intentional environment warnings: no local model
backend is registered, no CLI-constructed OS isolation backend is present, and
`APXM_BACKEND` is unset. The canonical tests use deterministic development
ports and do not require an external provider.

## Intentional boundaries

- `cap.search` remains only in low-level conformance and negative fixtures where
  opaque-reference rejection is tested. Author-facing examples use generated
  `SEARCH_WEB`.
- The retired `[prompts]` manifest table is rejected. A legacy package may still
  carry a passive `prompts/<name>.md` resource because the folder contract
  preserves arbitrary historical instruction files; no runtime loader treats it
  as executable or as a declaration. New instructions use `Skill(...).load()`
  and the `skills/<id>/SKILL.md` contract.
- Deployment-profile permission decisions have no producer in this local
  composition root; the code → package → deployment resolver is closed and the
  deployment layer is applied whenever a caller supplies one. This is an
  explicit composition boundary, not an implicit allow.
- Generated frontend modules remain private implementation modules; public
  author imports come from the documented frontend roots.

## Open security blocker

`Status: blocked for hostile same-isolate source capture.` The Python source
port evaluates submitted text in the same interpreter as its capture helpers
and invokes the capture result after evaluation
(`crates/compiler/source-port/harness/capture_python.py`). A hostile submission
can reach `sys.modules["__main__"]` and mutate a helper function's `__code__`
while the in-progress bind is evaluating; a read-only review reproduced this
by replacing `_capture` and `_validate_graph_provenance`, after which the
harness emitted a forged graph. The native Python graph registry and the
TypeScript frozen handle prototype close the handle-level mutation cases
(`crates/compiler/frontend/native/python/src/lib.rs`,
`crates/compiler/frontend/typescript/src/agent.ts`), but they do not isolate
the Python harness helpers. This capture path must not be described as fully
confined until trusted helper state is isolated or moved behind a stronger
process/native boundary; no implementation fix is recorded in this note.

## Reproduction

From the repository root, provision the local environment once, then run:

```bash
dekk agents setup
dekk agents check
dekk agents build
dekk agents test
dekk agents test-all
dekk agents test-compiler
dekk agents test-cli
dekk agents check-agent-packages
dekk agents compile-service-canonical
dekk agents execute-canonical
```

The focused static checks are also useful when changing only frontend code:

```bash
python tools/scripts/deversion_inventory.py --check
python tools/scripts/check_frontend_surface.py
dekk agents check-frontend-parity
```
