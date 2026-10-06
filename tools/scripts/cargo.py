#!/usr/bin/env python3
"""Run Cargo for APXM with a machine-local target directory."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from enum import StrEnum
from pathlib import Path


class CargoCommand(StrEnum):
    BUILD = "build"
    BUILD_DIALECT = "build-dialect"
    CLEAN = "clean"
    SCRUB_SIGBUS_CACHE = "scrub-sigbus-cache"
    TARGET_DIR = "target-dir"
    TEST = "test"


class EnvKey(StrEnum):
    APXM_CARGO_TARGET_DIR = "APXM_CARGO_TARGET_DIR"
    CARGO_TARGET_DIR = "CARGO_TARGET_DIR"
    CI = "CI"
    CARGO_PROFILE_DEV_DEBUG = "CARGO_PROFILE_DEV_DEBUG"
    CARGO_PROFILE_TEST_DEBUG = "CARGO_PROFILE_TEST_DEBUG"


REPO_MARKER = "Cargo.toml"
DEKK_MARKER = ".dekk.toml"
CARGO = "cargo"
CMAKE = "cmake"
BUILD_FLAG = "--build"
TARGET_FLAG = "--target"
RELEASE_FLAG = "--release"
CONFIG_FLAG = "--config"
PROFILE_FLAG = "--profile"
PACKAGE_FLAG = "-p"
LONG_PACKAGE_FLAG = "--package"
FEATURES_FLAG = "--features"
DRIVER_METRICS_FEATURES = "driver,metrics"
APXM_CLI_PACKAGE = "apxm-cli"
APXM_CLI_BINARY = "apxm"
APXM_COMPILER_PACKAGE = "apxm-compiler"
#: Cargo feature that links the native AIS dialect into `apxm-compiler`.
MLIR_FEATURE = "mlir"
TARGET_ROOT_NAME = "apxm-cargo-targets"
PROJECT_TARGET_DIR_NAME = "target"
DEBUG_PROFILE_DIR_NAME = "debug"
RELEASE_PROFILE_DIR_NAME = "release"
FINGERPRINT_DIR_NAME = ".fingerprint"
BUILD_DIR_NAME = "build"
LIB_DIR_NAME = "lib"
CMAKE_CACHE_FILE_NAME = "CMakeCache.txt"
DEPS_DIR_NAME = "deps"
EXAMPLES_DIR_NAME = "examples"
INCREMENTAL_DIR_NAME = "incremental"
APXM_COMPILER_BUILD_GLOB = f"apxm-compiler*/out/{BUILD_DIR_NAME}/{CMAKE_CACHE_FILE_NAME}"
TABLEGEN_TARGET = "AISIRIncGen"
PROJECT_DIGEST_SIZE = 16
EXECUTABLE_SUFFIX = ".exe"
FINGERPRINT_OUTPUT_GLOB = "output-*"
RUSTC_SIGBUS_MARKER = "rustc interrupted by SIGBUS"
TEMP_ARCHIVE_GLOB = ".tmp*.temp-archive"
LIBRARY_SUFFIXES = frozenset({".a", ".dylib", ".dll", ".so"})
RUN_TARGET_FLAGS = frozenset({"--bin", "--example", "--test", "--bench"})
# Every dependency-resolving Cargo invocation goes through the checked-in
# lockfile.  This keeps the Dekk wrapper reproducible and prevents a build or
# test from silently rewriting Cargo.lock when the registry has changed.
LOCKED_SUBCOMMANDS = frozenset({"build", "check", "clippy", "run", "test"})
LOCK_FLAGS = frozenset({"--locked", "--frozen"})
NATIVE_TOOLCHAIN_GATED_SUBCOMMANDS = frozenset({
    CargoCommand.BUILD.value,
    CargoCommand.TEST.value,
    "check",
    "clippy",
    "run",
})
LINUX_GNU_COMPILER_MARKERS = ("-conda-linux-gnu-", "-linux-gnu-")
LINUX_GNU_COMPILER_SUFFIXES = ("-gcc", "-g++", "-ld")
NATIVE_TOOLCHAIN_ENV_KEYS = ("CC", "CXX")
NATIVE_COMPILER_NAMES = {
    "CC": ("clang", "clang-22"),
    "CXX": ("clang++", "clang++-22"),
}
READINESS_FAILURE_EXIT_CODE = 2
SKIP_RELEASE_ENTRIES = frozenset({
    BUILD_DIR_NAME,
    DEPS_DIR_NAME,
    EXAMPLES_DIR_NAME,
    INCREMENTAL_DIR_NAME,
})


def _repo_root(start: Path) -> Path:
    for candidate in (start.resolve(), *start.resolve().parents):
        if (candidate / REPO_MARKER).is_file() and (candidate / DEKK_MARKER).is_file():
            return candidate
    raise SystemExit("error: unable to locate APXM repository root")


def _project_digest(project_root: Path) -> str:
    payload = str(project_root.resolve()).encode()
    return hashlib.sha256(payload).hexdigest()[:PROJECT_DIGEST_SIZE]


def _target_dir(project_root: Path) -> Path:
    explicit = os.environ.get(EnvKey.APXM_CARGO_TARGET_DIR.value)
    if explicit:
        return Path(explicit).expanduser().resolve()
    return (
        Path(tempfile.gettempdir())
        / TARGET_ROOT_NAME
        / f"{project_root.name}-{_project_digest(project_root)}"
    )


def _command_profile(command: list[str]) -> str:
    if RELEASE_FLAG in command:
        return RELEASE_PROFILE_DIR_NAME
    for idx, value in enumerate(command):
        if value == PROFILE_FLAG and idx + 1 < len(command):
            profile = command[idx + 1].lower()
            if profile == RELEASE_PROFILE_DIR_NAME:
                return RELEASE_PROFILE_DIR_NAME
    for idx, value in enumerate(command):
        if value == CONFIG_FLAG and idx + 1 < len(command):
            config = command[idx + 1].lower()
            if config == RELEASE_PROFILE_DIR_NAME:
                return RELEASE_PROFILE_DIR_NAME
    return DEBUG_PROFILE_DIR_NAME


def _prepend_env_path(env: dict[str, str], key: str, paths: list[Path]) -> None:
    existing = env.get(key, "")
    current = [str(path) for path in paths]
    if existing:
        current.extend(existing.split(os.pathsep))
    if current:
        env[key] = os.pathsep.join(current)


def _cargo_env(project_root: Path, target_dir: Path, command: list[str]) -> dict[str, str]:
    env = dict(os.environ)
    env[EnvKey.CARGO_TARGET_DIR.value] = str(target_dir)
    if env.get(EnvKey.CI.value) == "true":
        env.setdefault(EnvKey.CARGO_PROFILE_DEV_DEBUG.value, "0")
        env.setdefault(EnvKey.CARGO_PROFILE_TEST_DEBUG.value, "0")
    if platform.system().lower() == "darwin" and not _is_explicit_linux_target(
        _explicit_target(command)
    ):
        mismatched_keys = [
            key
            for key in NATIVE_TOOLCHAIN_ENV_KEYS
            if (value := env.get(key)) and _looks_like_linux_gnu_compiler(value)
        ]
        if mismatched_keys:
            native_compilers = _native_compiler_pair(project_root, env)
            if native_compilers is not None:
                env["CC"], env["CXX"] = native_compilers
    profile = _command_profile(command)
    project_profile_dir = project_root / PROJECT_TARGET_DIR_NAME / profile
    # The native MLIR bridge is installed into the workspace target/profile
    # directory by the compiler build script, even when Rust artifacts use the
    # machine-local CARGO_TARGET_DIR.  dekk sets LD_LIBRARY_PATH to the release
    # install for normal CLI use; prepend the active profile here so debug tests
    # never load a stale release libapxm_compiler_c.so.
    profile_paths = [project_profile_dir / LIB_DIR_NAME, project_profile_dir]
    _prepend_env_path(env, "LD_LIBRARY_PATH", profile_paths)
    _prepend_env_path(env, "DYLD_LIBRARY_PATH", profile_paths)
    return env


def _explicit_target(command: list[str]) -> str | None:
    for idx, value in enumerate(command):
        if value == TARGET_FLAG and idx + 1 < len(command):
            return command[idx + 1]
        if value.startswith(f"{TARGET_FLAG}="):
            return value.split("=", 1)[1]
    return None


def _selected_package(command: list[str]) -> str | None:
    for idx, value in enumerate(command):
        if value in {PACKAGE_FLAG, LONG_PACKAGE_FLAG} and idx + 1 < len(command):
            return command[idx + 1]
    return None


def _has_explicit_run_target(command: list[str]) -> bool:
    return any(flag in command for flag in RUN_TARGET_FLAGS)


def _ambiguous_run_target_error(command: list[str]) -> str | None:
    if not command or command[0] != "run":
        return None
    if _selected_package(command) != APXM_CLI_PACKAGE or _has_explicit_run_target(command):
        return None
    return (
        "error: tools/scripts/cargo.py requires an exact `cargo run` target for package "
        f"{APXM_CLI_PACKAGE}. Add `--bin {APXM_CLI_BINARY}` for the canonical CLI or "
        "stays closed until the target is explicit."
    )


def _looks_like_linux_gnu_compiler(value: str) -> bool:
    compiler_name = Path(value).name.lower()
    return any(marker in compiler_name for marker in LINUX_GNU_COMPILER_MARKERS)


def _linux_gnu_compiler_prefix(value: str) -> str | None:
    compiler_name = Path(value).name.lower()
    for marker in LINUX_GNU_COMPILER_MARKERS:
        if marker not in compiler_name:
            continue
        prefix, _, suffix = compiler_name.partition(marker)
        if not suffix:
            continue
        if any(suffix == candidate[1:] for candidate in LINUX_GNU_COMPILER_SUFFIXES):
            return f"{prefix}{marker[:-1]}"
    return None


def _declared_linux_compiler_packages(project_root: Path) -> list[str]:
    environment_path = project_root / ".dekk" / "environment.yaml"
    if not environment_path.is_file():
        return []

    packages: list[str] = []
    for raw_line in environment_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("- "):
            continue
        package = line[2:].strip()
        if package.startswith(("gxx_linux", "gcc_linux", "binutils_linux", "sysroot_linux")):
            packages.append(package)
    return packages


def _installed_linux_gnu_compiler_prefixes(project_root: Path) -> list[str]:
    env_bin = project_root / ".dekk" / "env" / "bin"
    if not env_bin.is_dir():
        return []

    prefixes = {
        prefix
        for pattern in ("*-linux-gnu-gcc", "*-linux-gnu-g++", "*-linux-gnu-ld")
        for path in env_bin.glob(pattern)
        if (prefix := _linux_gnu_compiler_prefix(path.name)) is not None
    }
    return sorted(prefixes)


def _native_compiler_pair(project_root: Path, env: dict[str, str]) -> tuple[str, str] | None:
    """Find an executable native Darwin clang pair in the active toolchain."""

    search_dirs: list[Path] = []
    conda_prefix = env.get("CONDA_PREFIX")
    if conda_prefix:
        search_dirs.append(Path(conda_prefix) / "bin")
    search_dirs.append(project_root / ".dekk" / "env" / "bin")

    path_entries = env.get("PATH", "").split(os.pathsep)
    search_dirs.extend(Path(entry) for entry in path_entries if entry)
    search_dirs.append(Path("/usr/bin"))

    for directory in dict.fromkeys(search_dirs):
        candidates = {}
        for key, names in NATIVE_COMPILER_NAMES.items():
            candidates[key] = next(
                (
                    candidate
                    for name in names
                    if _is_executable(candidate := directory / name)
                    and _is_native_darwin_compiler(candidate)
                ),
                None,
            )
        if candidates["CC"] is not None and candidates["CXX"] is not None:
            return str(candidates["CC"]), str(candidates["CXX"])
    return None


def _is_native_darwin_compiler(path: Path) -> bool:
    """Verify a candidate compiler targets this Darwin host architecture."""

    try:
        result = subprocess.run(
            [str(path), "-dumpmachine"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    if result.returncode != 0:
        return False

    target = result.stdout.strip().casefold()
    if "-apple-darwin" not in target:
        return False
    host_machine = platform.machine().casefold()
    expected_machine = {"arm64": ("arm64", "aarch64"), "x86_64": ("x86_64",)}.get(
        host_machine,
        (host_machine,),
    )
    return target.startswith(expected_machine)


def _is_explicit_linux_target(target: str | None) -> bool:
    return bool(target) and "-linux-" in target.lower()


def _is_linux_arm64_target(target: str | None) -> bool:
    return bool(target) and target.lower().startswith("aarch64-unknown-linux-")


def _unsupported_linux_arm64_target_error(
    project_root: Path,
    cargo_args: list[str],
    env: dict[str, str],
) -> str | None:
    target = _explicit_target(cargo_args)
    if not _is_linux_arm64_target(target):
        return None

    declared_packages = _declared_linux_compiler_packages(project_root)
    installed_prefixes = _installed_linux_gnu_compiler_prefixes(project_root)
    mismatches = [
        (key, value, prefix)
        for key in NATIVE_TOOLCHAIN_ENV_KEYS
        if (value := env.get(key))
        and (prefix := _linux_gnu_compiler_prefix(value)) is not None
        and not prefix.startswith("aarch64")
    ]
    has_declared_arm64 = any("aarch64" in package or "arm64" in package for package in declared_packages)
    has_installed_arm64 = any(prefix.startswith("aarch64") for prefix in installed_prefixes)
    if not mismatches and has_declared_arm64 and has_installed_arm64:
        return None

    detail_lines = [
        "error: APXM Linux target readiness failed.",
        f"  Requested cargo target: {target}",
        f"  Blocked cargo subcommand: {cargo_args[0]}",
    ]
    detail_lines.append(
        "  The sanctioned Cargo/Dekk toolchain does not provide a matching Linux arm64 compiler/sysroot."
    )
    if declared_packages:
        detail_lines.append(
            "  Declared Dekk Linux compiler packages: " + ", ".join(declared_packages)
        )
    if installed_prefixes:
        detail_lines.append(
            "  Installed Linux GNU compiler prefixes under .dekk/env/bin: "
            + ", ".join(installed_prefixes)
        )
    if not declared_packages and not installed_prefixes:
        detail_lines.append(
            "  No Dekk Linux compiler metadata was found under `.dekk/` for this target."
        )
    if mismatches:
        detail_lines.append("  Active compiler selections:")
        detail_lines.extend(f"    {key}={value}" for key, value, _ in mismatches)
    detail_lines.extend(
        [
            "  No configured or installed compiler matches `aarch64*-linux-gnu`, so a reproducible Linux arm64 build cannot be claimed through the current wrapper.",
            "  Fix this before claiming support:",
            "  - provision an `aarch64` Linux GNU compiler and sysroot in the Dekk environment",
            "  - keep the build on the sanctioned Cargo/Dekk path and add focused verification for the arm64 artifact",
            "  The readiness gate stays closed until the repository ships a matching Linux arm64 toolchain.",
        ]
    )
    return "\n".join(detail_lines)


def _native_toolchain_readiness_error(
    cargo_args: list[str],
    env: dict[str, str],
    *,
    system: str | None = None,
    machine: str | None = None,
) -> str | None:
    if not cargo_args or cargo_args[0] not in NATIVE_TOOLCHAIN_GATED_SUBCOMMANDS:
        return None

    host_system = system or platform.system()
    host_machine = machine or platform.machine()
    if host_system.lower() != "darwin":
        return None
    if _is_explicit_linux_target(_explicit_target(cargo_args)):
        return None

    mismatches = [
        (key, value)
        for key in NATIVE_TOOLCHAIN_ENV_KEYS
        if (value := env.get(key)) and _looks_like_linux_gnu_compiler(value)
    ]
    if not mismatches:
        return None

    configured = "\n".join(f"  {key}={value}" for key, value in mismatches)
    return (
        "error: APXM native toolchain readiness failed.\n"
        f"  Host: {host_system} {host_machine}\n"
        f"  Blocked cargo subcommand: {cargo_args[0]}\n"
        "  macOS host builds cannot use Linux conda cross-compilers.\n"
        f"{configured}\n"
        "  These compiler selections target Linux and reject native macOS flags such as "
        "`-arch arm64` and `-mmacosx-version-min`.\n"
        "  Fix one of:\n"
        "  - On macOS, unset `CC` and `CXX` or point them at `/usr/bin/clang` and "
        "`/usr/bin/clang++` before invoking `dekk agents ...`.\n"
        "  - Keep the Linux conda compiler pins only for explicit Linux-target builds.\n"
        "  The readiness gate stays closed until the native compiler selection matches the host."
    )


def _run(command: list[str], *, project_root: Path, target_dir: Path) -> int:
    if len(command) > 1 and command[0] == CARGO:
        subcommand = command[1]
        if subcommand in LOCKED_SUBCOMMANDS and not any(
            flag in command[2:] for flag in LOCK_FLAGS
        ):
            # Cargo accepts command options after the subcommand.  Preserve
            # caller-provided argument order while making the default safe.
            command = [command[0], subcommand, "--locked", *command[2:]]
    env = _cargo_env(project_root, target_dir, command)
    if Path(command[0]).name == CARGO:
        target_error = _unsupported_linux_arm64_target_error(project_root, command[1:], env)
        if target_error is not None:
            print(target_error, file=sys.stderr)
            return READINESS_FAILURE_EXIT_CODE
        readiness_error = _native_toolchain_readiness_error(command[1:], env)
        if readiness_error is not None:
            print(readiness_error, file=sys.stderr)
            return READINESS_FAILURE_EXIT_CODE
    result = subprocess.run(
        command,
        cwd=project_root,
        env=env,
        check=False,
    )
    return int(result.returncode)


def _is_executable(path: Path) -> bool:
    if path.suffix == EXECUTABLE_SUFFIX:
        return True
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _is_release_artifact(path: Path) -> bool:
    if not path.is_file():
        return False
    return _is_executable(path) or path.suffix in LIBRARY_SUFFIXES


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        shutil.copy2(source, temp_path)
        os.replace(temp_path, destination)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _stage_release_outputs(project_root: Path, target_dir: Path) -> None:
    source = target_dir / RELEASE_PROFILE_DIR_NAME
    if not source.is_dir():
        return

    destination = project_root / PROJECT_TARGET_DIR_NAME / RELEASE_PROFILE_DIR_NAME
    destination.mkdir(parents=True, exist_ok=True)

    for entry in source.iterdir():
        if entry.name in SKIP_RELEASE_ENTRIES:
            continue
        if _is_release_artifact(entry):
            _copy_file(entry, destination / entry.name)

    source_lib = source / LIB_DIR_NAME
    if source_lib.is_dir():
        destination_lib = destination / LIB_DIR_NAME
        for entry in source_lib.iterdir():
            if entry.is_file():
                _copy_file(entry, destination_lib / entry.name)


def _find_compiler_build_dir(target_dir: Path) -> Path | None:
    build_root = target_dir / RELEASE_PROFILE_DIR_NAME / BUILD_DIR_NAME
    matches = sorted(build_root.glob(APXM_COMPILER_BUILD_GLOB))
    if not matches:
        return None
    return matches[0].parent


def _build_cli(project_root: Path, target_dir: Path) -> int:
    return _run(
        [
            CARGO,
            CargoCommand.BUILD.value,
            PACKAGE_FLAG,
            APXM_CLI_PACKAGE,
            FEATURES_FLAG,
            DRIVER_METRICS_FEATURES,
            RELEASE_FLAG,
        ],
        project_root=project_root,
        target_dir=target_dir,
    )


def _build_compiler(project_root: Path, target_dir: Path) -> int:
    # `build-dialect` exists to rebuild the native dialect, which lives behind
    # the compiler crate's `mlir` feature; without the feature this would emit
    # stub bindings and leave no CMake build directory to drive.
    return _run(
        [
            CARGO,
            CargoCommand.BUILD.value,
            PACKAGE_FLAG,
            APXM_COMPILER_PACKAGE,
            FEATURES_FLAG,
            MLIR_FEATURE,
            RELEASE_FLAG,
        ],
        project_root=project_root,
        target_dir=target_dir,
    )


def _build_dialect(project_root: Path, target_dir: Path) -> int:
    build_dir = _find_compiler_build_dir(target_dir)
    if build_dir is None:
        result = _build_compiler(project_root, target_dir)
        if result != 0:
            return result
        build_dir = _find_compiler_build_dir(target_dir)
    if build_dir is None:
        print("error: unable to locate APXM compiler CMake build directory", file=sys.stderr)
        return 1

    result = _run(
        [CMAKE, BUILD_FLAG, str(build_dir), TARGET_FLAG, TABLEGEN_TARGET],
        project_root=project_root,
        target_dir=target_dir,
    )
    if result != 0:
        return result

    result = _run(
        [CMAKE, BUILD_FLAG, str(build_dir)],
        project_root=project_root,
        target_dir=target_dir,
    )
    if result != 0:
        return result

    result = _build_cli(project_root, target_dir)
    if result == 0:
        _stage_release_outputs(project_root, target_dir)
    return result


def _clean(project_root: Path, target_dir: Path, args: list[str]) -> int:
    result = _run(
        [CARGO, CargoCommand.CLEAN.value, *args],
        project_root=project_root,
        target_dir=target_dir,
    )
    return result


def _scrub_sigbus_cache(project_root: Path, target_dir: Path) -> int:
    target_roots = [project_root / PROJECT_TARGET_DIR_NAME, target_dir]
    removed = 0

    for root in dict.fromkeys(path.resolve() for path in target_roots):
        if not root.exists():
            continue

        fingerprint_root = root / DEBUG_PROFILE_DIR_NAME / FINGERPRINT_DIR_NAME
        if fingerprint_root.is_dir():
            for output in fingerprint_root.glob(f"*/{FINGERPRINT_OUTPUT_GLOB}"):
                if not output.is_file():
                    continue
                try:
                    content = output.read_text(errors="replace")
                except OSError:
                    continue
                if RUSTC_SIGBUS_MARKER in content:
                    output.unlink()
                    removed += 1

        deps_root = root / DEBUG_PROFILE_DIR_NAME / DEPS_DIR_NAME
        if deps_root.is_dir():
            for entry in deps_root.glob(TEMP_ARCHIVE_GLOB):
                if entry.is_dir():
                    shutil.rmtree(entry)
                    removed += 1

    suffix = "y" if removed == 1 else "ies"
    print(f"removed {removed} stale rustc SIGBUS cache entr{suffix}")
    return 0


def main(argv: list[str]) -> int:
    project_root = _repo_root(Path(__file__))
    target_dir = _target_dir(project_root)
    target_dir.mkdir(parents=True, exist_ok=True)

    if argv == [CargoCommand.TARGET_DIR.value]:
        print(target_dir)
        return 0
    if not argv:
        print("error: expected cargo subcommand", file=sys.stderr)
        return 2
    if argv[0] == CargoCommand.BUILD_DIALECT.value:
        return _build_dialect(project_root, target_dir)
    if argv[0] == CargoCommand.CLEAN.value:
        return _clean(project_root, target_dir, argv[1:])
    if argv[0] == CargoCommand.SCRUB_SIGBUS_CACHE.value:
        return _scrub_sigbus_cache(project_root, target_dir)
    run_target_error = _ambiguous_run_target_error(argv)
    if run_target_error is not None:
        print(run_target_error, file=sys.stderr)
        return READINESS_FAILURE_EXIT_CODE

    result = _run([CARGO, *argv], project_root=project_root, target_dir=target_dir)
    if result == 0 and argv[0] == CargoCommand.BUILD.value and RELEASE_FLAG in argv:
        _stage_release_outputs(project_root, target_dir)
    return result


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
