#!/usr/bin/env python3
"""The full CI check, runnable on a developer machine exactly as CI runs it.

CI on the VPS platform is one job that calls `dekk agents ci`; nothing is spelled
out in the workflow. The steps are the MLIR-free service gate, then the two
MLIR-dependent gates (the compiler tests and the CLI release build), then the
release cohort: preparation, packaging and consumer verification.

Like the service gate, each step names a command in `.dekk.toml` and runs its
`run` string verbatim, so a local run and a CI run cannot drift apart. The service
gate strips the MLIR variables itself; the other steps keep the full environment.
Publishing is not a step: it needs the registry credential, which only the
publishing runner holds, and it only happens on a push to main.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEKK_MANIFEST_PATH = REPOSITORY_ROOT / ".dekk.toml"

#: `.dekk.toml` command names, in order. The gate that needs no toolchain comes
#: first so a cheap failure ends the run before the long MLIR builds.
CI_COMMANDS: tuple[str, ...] = (
    "check-service",
    "test-compiler",
    "build",
    "prepare-release-descriptors",
    "package-release",
    "verify-package",
)


def _load_commands() -> dict[str, str]:
    spec = importlib.util.spec_from_file_location(
        "service_gate", Path(__file__).with_name("service_gate.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.load_commands(DEKK_MANIFEST_PATH)


def resolve_steps(
    commands: dict[str, str], *, skip: tuple[str, ...] = ()
) -> list[tuple[str, str]]:
    """Resolve the step names to `(name, shell command)` pairs."""
    unknown = [name for name in skip if name not in CI_COMMANDS]
    if unknown:
        raise KeyError(f"{unknown} are not steps of the ci command")
    steps = []
    for name in CI_COMMANDS:
        if name in skip:
            continue
        if name not in commands:
            raise KeyError(f"{name!r} is not a command in {DEKK_MANIFEST_PATH.name}")
        steps.append((name, commands[name]))
    return steps


def run_steps(steps: list[tuple[str, str]]) -> int:
    results: list[tuple[str, float, bool]] = []
    for name, run in steps:
        print(f"\n=== ci: {name}", flush=True)
        print(f"$ {run}", flush=True)
        started = time.monotonic()
        completed = subprocess.run(["bash", "-c", run], cwd=REPOSITORY_ROOT, check=False)
        passed = completed.returncode == 0
        results.append((name, time.monotonic() - started, passed))
        if not passed:
            break
    print("\n--- ci summary")
    for name, elapsed, passed in results:
        print(f"{'pass' if passed else 'FAIL'}  {elapsed:7.1f}s  {name}")
    if results and not results[-1][2]:
        print(f"ci: {results[-1][0]} failed", file=sys.stderr)
        return 1
    print(f"ci: {len(results)} steps passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skip", action="append", default=[], metavar="STEP")
    parser.add_argument("--list", action="store_true", help="print the steps without running them")
    args = parser.parse_args(argv)
    steps = resolve_steps(_load_commands(), skip=tuple(args.skip))
    if args.list:
        for name, run in steps:
            print(f"{name}: {run}")
        return 0
    return run_steps(steps)


if __name__ == "__main__":
    raise SystemExit(main())
