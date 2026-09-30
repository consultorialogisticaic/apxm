# APXM agents

`agents` is the product-neutral APXM abstract machine: source-first Agent
Programs, the closed AIR/AIS semantics, exact capability and inference ports,
and the runtime that executes admitted artifacts.

It is not a product control plane, Studio, Server, Telegram integration,
deployment fleet, model zoo, or prompt-evaluation repository. Those systems may
bind to these contracts from outside.

## Current spine

```text
Python / TypeScript source
  -> FrontendGraph
  -> Rust verification and AIR lowering
  -> canonical AIS dialect MLIR (verified when the native MLIR toolchain is available)
  -> immutable artifact
  -> exact Invocation Admission and Port bindings
  -> generic execution kernel
  -> monotonic runtime evidence
```

The public semantic operations are exactly `model.call`,
`capability.invoke`, `program.new`, `program.invoke`, and `await.event`.
Compiler-emitted structural operations are separate and are never a raw
frontend builder API.

## Layout

- `crates/machine/ais` — canonical operation definitions and generated AIS.
- `crates/machine/program` — FrontendGraph, AIR, artifact verification.
- `crates/compiler` — Rust compiler and Python/TypeScript bridges.
- `crates/runtime` — exact inference, kernel, execution, and capability ports.
- `crates/tools/cli` — focused compile, validate, inspect, and execute CLI.
- `contracts` — schemas, Port Contracts, and conformance vectors.
- `examples/agents` — small generic source-first examples.
- `docs/pxm` — current theory plus historical PXM lineage.

## Development

Use Dekk for repository commands:

```bash
dekk agents doctor
dekk agents ops list
dekk agents check
dekk agents test-frontend-examples
```

Agent instructions come from `AGENTS.md`. The workspace agent-skill tooling
generates and checks the thin root adapters (`CLAUDE.md`, `CODEX.md`,
`.cursorrules`, `.github/copilot-instructions.md`, `.agents.json`, and
`.claude/skills`) without writing global agent configuration. Edit `AGENTS.md`
and `.agents/skills/` first, then run the adapter check for this checkout.

## Reproducible Nix shell

The repository publishes a locked Nix development shell for macOS ARM64 and
Linux ARM64/AMD64. It supplies Dekk, the pinned Rust toolchain, Python,
Node.js, LLVM/MLIR, and the native build tools; no Conda activation is needed.

```bash
nix develop
dekk agents doctor
dekk agents check
```

`nix flake check` validates the flake and its locked inputs. Service images
remain a separate Docker concern and must be built for the target platform:

```bash
dekk agents build-images --platform linux/amd64
```

`MLIR_DIR` and `LLVM_DIR` are exported by the shell. The exact package
versions come from `flake.lock`; update the lock only as an intentional
toolchain change.

## Release outputs
Before publishing or dispatching the release workflow, run the complete local owner preflight:

```bash
nix develop --command dekk agents preflight-release
```

This runs the service gate, both release service builds, native frontend build,
local package qualification, and consumer-side package verification in the
same order as the release workflow. It is a host-native preflight; the trusted
worker still MUST repeat it for the exact linux/amd64 release cohort.


APXM has two release products, with different consumers:

- `package-release` is the owner-local, digest-bound binary package. It carries
  both service executables, the Python native bridge, protocol descriptors,
  schemas, and the source/owner/release manifests. Its manifest is the
  consumer verification boundary; a directory or archive without that manifest
  is not a release.
- `build-images --platform linux/amd64` is the CLIC runtime product. It
  builds both OCI images from the same source cohort and stamps the exact
  service, manifest, frontend, owner, and schema digests into their labels.

Pull-request workers may build and verify candidates, but MUST NOT publish
runtime tags or receive production credentials. After merge, a trusted release
worker builds the exact main SHA on `linux/amd64`, runs the owner qualification
and image verification, publishes by digest to the private OCI registry, and
opens a CLIC pin PR containing those digests. CLIC then consumes only the
reviewed `name@sha256:<digest>` references; it never compiles APXM from a
checkout during deployment.

An explicitly authorized manual branch image build uses the same owner gate,
descriptor preparation, AMD64 build and consumer verification on GitHub-hosted
ephemeral runners. Main image publication stays on the isolated `clic-build`
worker. This manual path does not merge source, select a consumer release,
or establish hosted workload acceptance.

The Nix shell makes the toolchain reproducible. It is not itself a binary
cache and does not replace the owner release manifest or OCI publication.
## Local service-image candidates

Normal `dekk agents build-images` builds a clean release cohort and continues
to reject a dirty checkout. To qualify local source edits before a separate
release decision, use:

```sh
dekk agents build-images --candidate --platform linux/arm64 --repository-prefix apxm-local
```

The command freezes tracked and nonignored source beneath
`.apxm/service-image-candidates/`, records each path, file mode and content
hash, and builds both services from that one snapshot. Absolute and escaping
source symlinks are refused. Input and build-tree digests are separate because
the snapshot's source/owner descriptors are rebased to the real Git HEAD and
its manifest records the actual snapshot schema digests;
the working checkout and its release descriptors are untouched. In a candidate,
`source_revision` identifies that base commit, while `source_tree_digest`
identifies the exact source bytes. It does not claim the edits were committed.

Candidate tags start with `candidate-`; image labels state candidate status,
source-tree and provenance digests, dirty state, and `published=false`.
The returned `receipt_path` names the local build receipt. Verify its frozen
source, image labels, manifests and executables with:

```sh
dekk agents verify-images --candidate-provenance <receipt_path>
```

These are local, unpromoted images. Candidate verification does not publish
artifacts, change any consumer release pin, or establish downstream acceptance.
