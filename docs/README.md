# APXM agents documentation

This repository is the product-neutral APXM abstract machine: source-first
Agent Programs, the closed AIR/AIS semantics, exact capability and inference
ports, and the runtime that executes admitted artifacts.

## Current reading order

1. [PXM theory](pxm/theory.md) — the current execution-model vocabulary.
2. [PXM lineage](pxm/readme.md) — historical theory retained for context.
3. [Agent Program composition and AIR](agents/agent-program-composition-and-air-contract.md).
4. [Portable core interface](agents/portable-core-interface-contract.md).
5. [Execution Admission](agents/execution-admission-contract.md).
6. [Authoring guides](guides/README.md).
7. [Architecture decisions](adr/README.md).
8. [Design ideas](ideas/README.md) — non-canonical proposals under review.
9. [Authorable Agents implementation findings](agents/authorable-agents-implementation-findings.md) — audit disposition and reproducible verification evidence.

## Canonical pipeline

```text
Python or TypeScript source
  -> FrontendGraph
  -> Rust verification and lowering
  -> AIR
  -> canonical AIS dialect MLIR (verified when the native MLIR toolchain is available)
  -> immutable executable artifact
  -> exact Invocation Admission and Port bindings
  -> generic execution kernel
  -> monotonic runtime evidence
```

The public semantic family is exactly:

1. `model.call`
2. `capability.invoke`
3. `program.new`
4. `program.invoke`
5. `await.event`

Compiler-emitted structural operations are a separate closed family. They are
not a raw authoring API and `ais.loop` is not a sixth semantic operation.

## Scope boundary

This repository does not own product control planes, Studio workflows,
Telegram/webhook integrations, deployment fleets, model zoos, prompt
evaluation studies, or hosted release infrastructure. Those systems may bind
to the contracts from outside through exact ports and admission.

The historical PXM pages remain because they explain the ideas that shaped the
current machine. They are theory and lineage only; no current implementation
may depend on their retired operations or runtime state models.

## Verification

Provision the declared toolchain once, then run the named local gates. `check`
includes every generated-metadata arm, including the generated
documentation tables, and also runs frontend parity, frontend-surface, and
workspace type checks. `check-deversion` is the focused guard for Agents-owned
versioned ids and filenames; foreign-owner contract ids such as
`apxm.contract-common.v1` are intentionally outside that guard.

```bash
nix develop
dekk agents doctor
dekk agents check
dekk agents check-deversion
dekk agents build
dekk agents test
dekk agents test-all
dekk agents test-compiler
dekk agents test-cli
```

The shipping-path E2E gates are explicit rather than inferred from unit tests:

```bash
dekk agents test-frontend-examples
dekk agents check-agent-packages
dekk agents check-example-artifacts
dekk agents test-skill-example
dekk agents test-package-handler-example
dekk agents test-python-handler-example
dekk agents compile-service-canonical
dekk agents execute-canonical
python -m pytest tools/tests/
```

When a contract changes, regenerate the checked-in reference tables with
`dekk agents codegen-docs`; use `dekk agents check` to fail on drift. The
aggregate workspace suite and the frontend/package/compile/execute E2E gates
are explicit local Dekk commands, so they can be run independently or as a
complete verification pass.
