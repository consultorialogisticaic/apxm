#!/usr/bin/env python3
"""Service-only gate: every APXM gate that needs no MLIR toolchain.

The compiler pipeline crate (`apxm-compiler`) is the only crate that links the
native AIS dialect, and it links it only behind its `mlir` Cargo feature. No
other crate in the workspace depends on it, so both services, both service
protocols, the source port, the Agent Program, kernel, execution and Event
projection suites, both authoring frontends and the qualification tooling build
and test on a toolchain that carries Rust, Python and Node and nothing else —
no MLIR, no LLVM, no libclang, no CMake, no Ninja.

This runs exactly that set. It is the complete service-only gate, and it is
what `install-service` provisions for. The MLIR-dependent path keeps `test-all`,
`test-compiler` and `build-dialect`, which are the only gates that need the
dialect.

Steps are not spelled out here: each one names a command in `.dekk.toml` and
this executes that command's `run` string verbatim, so a change to a suite is
picked up by both gates at once and the two can never drift.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
import tomllib
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEKK_MANIFEST_PATH = REPOSITORY_ROOT / ".dekk.toml"

#: `.dekk.toml` command names this gate runs, in order. Cheap and deterministic
#: first (format, lint), then the protocol and service suites, then the four
#: owner suites the services are built out of, then the two frontends, then the
#: qualification tooling, and finally the commit lint.
#:
#: The four owner suites are here because until they were, the contracts they
#: decide had no gate that a service-only runner could run: owner-consent
#: admission and the `EventRef` negative decode live in `apxm-program` and
#: `apxm-kernel`, `contract_vector_conformance` is the only reader of the
#: published vector files, `contract_document_conformance` (in `apxm-execution`)
#: is the only reader of the Rust carriers those vectors are also held against,
#: and the Event HTTP projection crossed no gate at all. Every one of them
#: builds without the dialect, so `test-all` — which needs MLIR — was the only
#: thing standing between them and drift.
#:
#: `test-execution` runs after `test-compilation-service` rather than before it:
#: it runs `npm run build` but no `npm ci`, so it consumes the locked frontend
#: dependencies that step installs.
SERVICE_GATE_COMMANDS: tuple[str, ...] = (
    "fmt-check",
    "clippy",
    "test-compilation-protocol",
    "test-runtime-protocol",
    "test-compilation-service",
    "test-source-port",
    "test-runtime-service",
    "test-program",
    "test-kernel",
    "test-event-http",
    "test-execution",
    "test-python-frontend",
    "test-typescript-frontend",
    "test-release-qualification",
    "test-owner-qualification",
    "test-service-images",
    "test-ci",
    "commit-lint",
)

#: `commit-lint` is the one step that takes an argument. `--range` when the
#: caller supplies one (a pull request's base..head), `--current` otherwise.
COMMIT_LINT_COMMAND = "commit-lint"
COMMIT_LINT_RANGE_ENV = "APXM_COMMIT_LINT_RANGE"

#: Variables `.dekk.toml [env]` sets for the MLIR toolchain. The service
#: environment does not carry the packages they point at, so this gate removes
#: them rather than letting a developer's full environment leak the dialect
#: into a run that is supposed to prove independence from it. Unsetting the
#: linker override drops cargo onto the host `cc`, which is what a service-only
#: runner has.
MLIR_ENVIRONMENT_KEYS: tuple[str, ...] = (
    "MLIR_DIR",
    "LLVM_DIR",
    "MLIR_PREFIX",
    "LLVM_PREFIX",
    "CC",
    "CXX",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
)


def load_commands(manifest_path: Path = DEKK_MANIFEST_PATH) -> dict[str, str]:
    """Return every `.dekk.toml` top-level command name mapped to its `run`."""
    with manifest_path.open("rb") as handle:
        manifest = tomllib.load(handle)
    commands = manifest.get("commands", {})
    return {
        name: value["run"]
        for name, value in commands.items()
        if isinstance(value, dict) and "run" in value
    }


def resolve_steps(
    commands: dict[str, str],
    *,
    commit_lint_range: str | None = None,
    skip: tuple[str, ...] = (),
) -> list[tuple[str, str]]:
    """Resolve the gate's command names to `(name, shell command)` pairs."""
    unknown = [name for name in skip if name not in SERVICE_GATE_COMMANDS]
    if unknown:
        raise KeyError(f"{unknown} are not steps of this gate")
    steps: list[tuple[str, str]] = []
    for name in SERVICE_GATE_COMMANDS:
        if name in skip:
            continue
        if name not in commands:
            raise KeyError(f"{name!r} is not a command in {DEKK_MANIFEST_PATH.name}")
        run = commands[name]
        if name == COMMIT_LINT_COMMAND:
            argument = (
                f"--range {shlex.quote(commit_lint_range)}"
                if commit_lint_range
                else "--current"
            )
            run = f"{run} {argument}"
        steps.append((name, run))
    return steps


def service_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return the process environment with the MLIR toolchain variables gone."""
    env = dict(os.environ if base is None else base)
    for key in MLIR_ENVIRONMENT_KEYS:
        env.pop(key, None)
    return env


def run_steps(steps: list[tuple[str, str]], *, env: dict[str, str]) -> int:
    """Run every step in order, stopping at the first failure."""
    results: list[tuple[str, float, bool]] = []
    for name, run in steps:
        print(f"\n=== check-service: {name}", flush=True)
        print(f"$ {run}", flush=True)
        started = time.monotonic()
        completed = subprocess.run(
            ["bash", "-c", run],
            cwd=REPOSITORY_ROOT,
            env=env,
            check=False,
        )
        elapsed = time.monotonic() - started
        passed = completed.returncode == 0
        results.append((name, elapsed, passed))
        if not passed:
            _report(results)
            print(f"check-service: {name} failed ({completed.returncode})", file=sys.stderr)
            return completed.returncode
    _report(results)
    print(f"check-service: {len(results)} steps passed")
    return 0


def _report(results: list[tuple[str, float, bool]]) -> None:
    print("\n--- check-service summary")
    for name, elapsed, passed in results:
        print(f"{'pass' if passed else 'FAIL'}  {elapsed:7.1f}s  {name}")
    print(f"total {sum(elapsed for _, elapsed, _ in results):.1f}s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--range",
        dest="commit_lint_range",
        default=os.environ.get(COMMIT_LINT_RANGE_ENV),
        help="commit range REV1..REV2 for the commit-lint step (default: HEAD)",
    )
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="STEP",
        help=(
            "omit one step; a caller using a commit range may omit commit-lint, whose only "
            "remedy on a published branch would be a rewrite"
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the resolved steps without running them",
    )
    args = parser.parse_args(argv)

    steps = resolve_steps(
        load_commands(),
        commit_lint_range=args.commit_lint_range,
        skip=tuple(args.skip),
    )
    if args.list:
        for name, run in steps:
            print(f"{name}: {run}")
        return 0
    return run_steps(steps, env=service_environment())


if __name__ == "__main__":
    raise SystemExit(main())
