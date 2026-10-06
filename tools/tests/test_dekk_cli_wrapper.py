"""Guard exact APXM CLI wrapper target selection and diagnostics."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
APXM_CLI_PATH = REPOSITORY_ROOT / "tools" / "scripts" / "apxm_cli.py"
CARGO_WRAPPER_PATH = REPOSITORY_ROOT / "tools" / "scripts" / "cargo.py"
DEKK_MANIFEST_PATH = REPOSITORY_ROOT / ".dekk.toml"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DekkCliWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.apxm_cli = load_module(APXM_CLI_PATH, "apxm_cli")
        cls.cargo_wrapper = load_module(CARGO_WRAPPER_PATH, "cargo_wrapper")

    def test_apxm_cli_wrapper_runs_exact_canonical_binary(self) -> None:
        expected_command = [
            sys.executable,
            str(self.apxm_cli.REPOSITORY_ROOT / "tools" / "scripts" / "cargo.py"),
            "run",
            "-p",
            "apxm-cli",
            "--bin",
            "apxm",
            "--features",
            "driver,metrics",
            "--release",
            "--",
            "doctor",
        ]
        with mock.patch.object(
            self.apxm_cli.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=17),
        ) as run_mock:
            exit_code = self.apxm_cli.main(["doctor"])

        self.assertEqual(exit_code, 17)
        run_mock.assert_called_once_with(expected_command, cwd=self.apxm_cli.REPOSITORY_ROOT, check=False)

    def test_cargo_wrapper_rejects_ambiguous_apxm_cli_run(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with mock.patch.object(self.cargo_wrapper.subprocess, "run") as run_mock:
                exit_code = self.cargo_wrapper.main(["run", "-p", "apxm-cli", "--", "doctor"])

        self.assertEqual(exit_code, 2)
        run_mock.assert_not_called()
        rendered = stderr.getvalue()
        self.assertIn("requires an exact `cargo run` target", rendered)
        self.assertIn("`--bin apxm`", rendered)

    def test_ci_debug_defaults_preserve_explicit_and_local_profiles(self) -> None:
        for initial, expected in (
            ({"CI": "true"}, ("0", "0")),
            (
                {"CI": "true", "CARGO_PROFILE_DEV_DEBUG": "2", "CARGO_PROFILE_TEST_DEBUG": "1"},
                ("2", "1"),
            ),
            ({}, (None, None)),
        ):
            with self.subTest(initial=initial), mock.patch.dict(
                self.cargo_wrapper.os.environ, initial, clear=True
            ):
                env = self.cargo_wrapper._cargo_env(
                    REPOSITORY_ROOT, Path("/tmp/apxm-test-target"), ["cargo", "test"]
                )
                self.assertEqual(
                    (env.get("CARGO_PROFILE_DEV_DEBUG"), env.get("CARGO_PROFILE_TEST_DEBUG")),
                    expected,
                )

    def test_cargo_wrapper_uses_checked_in_lockfile_by_default(self) -> None:
        with mock.patch.object(
            self.cargo_wrapper.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0),
        ) as run_mock:
            with mock.patch.dict(
                self.cargo_wrapper.os.environ,
                {"CC": "", "CXX": ""},
                clear=False,
            ):
                exit_code = self.cargo_wrapper.main(["test", "-p", "apxm-core"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(run_mock.call_args.args[0][:3], ["cargo", "test", "--locked"])

    def test_cargo_wrapper_preserves_explicit_cargo_lock_mode(self) -> None:
        with mock.patch.object(
            self.cargo_wrapper.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0),
        ) as run_mock:
            with mock.patch.dict(
                self.cargo_wrapper.os.environ,
                {"CC": "", "CXX": ""},
                clear=False,
            ):
                exit_code = self.cargo_wrapper.main(["build", "--frozen", "-p", "apxm-core"])

        self.assertEqual(exit_code, 0)
        self.assertNotIn("--locked", run_mock.call_args.args[0])
        self.assertEqual(run_mock.call_args.args[0][:3], ["cargo", "build", "--frozen"])

    def test_cargo_wrapper_fails_closed_on_macos_linux_compiler_mismatch(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(self.cargo_wrapper.platform, "system", return_value="Darwin"):
            with mock.patch.object(self.cargo_wrapper.platform, "machine", return_value="arm64"):
                with mock.patch.object(self.cargo_wrapper, "_native_compiler_pair", return_value=None):
                    with mock.patch.dict(
                        self.cargo_wrapper.os.environ,
                        {
                            "CC": "/tmp/x86_64-conda-linux-gnu-gcc",
                            "CXX": "/tmp/x86_64-conda-linux-gnu-g++",
                        },
                        clear=False,
                    ):
                        with contextlib.redirect_stderr(stderr):
                            with mock.patch.object(self.cargo_wrapper.subprocess, "run") as run_mock:
                                exit_code = self.cargo_wrapper.main(
                                    ["test", "-p", "apxm-cli", "--lib", "--release"]
                                )

        self.assertEqual(exit_code, self.cargo_wrapper.READINESS_FAILURE_EXIT_CODE)
        run_mock.assert_not_called()
        rendered = stderr.getvalue()
        self.assertIn("APXM native toolchain readiness failed", rendered)
        self.assertIn("macOS host builds cannot use Linux conda cross-compilers", rendered)
        self.assertIn("CC=/tmp/x86_64-conda-linux-gnu-gcc", rendered)
        self.assertIn("CXX=/tmp/x86_64-conda-linux-gnu-g++", rendered)
        self.assertIn("/usr/bin/clang", rendered)

    def test_cargo_wrapper_resolves_native_pair_when_dekk_pins_linux_compilers(self) -> None:
        with mock.patch.object(self.cargo_wrapper.platform, "system", return_value="Darwin"):
            with mock.patch.object(self.cargo_wrapper.platform, "machine", return_value="arm64"):
                with mock.patch.object(
                    self.cargo_wrapper,
                    "_native_compiler_pair",
                    return_value=("/native/clang", "/native/clang++"),
                ):
                    with mock.patch.dict(
                        self.cargo_wrapper.os.environ,
                        {
                            "CC": "/tmp/x86_64-conda-linux-gnu-gcc",
                            "CXX": "/tmp/x86_64-conda-linux-gnu-g++",
                        },
                        clear=False,
                    ):
                        with mock.patch.object(
                            self.cargo_wrapper.subprocess,
                            "run",
                            return_value=SimpleNamespace(returncode=29),
                        ) as run_mock:
                            exit_code = self.cargo_wrapper.main(["test", "-p", "apxm-cli"])

        self.assertEqual(exit_code, 29)
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.kwargs["env"]["CC"], "/native/clang")
        self.assertEqual(run_mock.call_args.kwargs["env"]["CXX"], "/native/clang++")

    def test_native_compiler_pair_requires_same_host_native_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            prefix = Path(temp_dir_name)
            bin_dir = prefix / "bin"
            bin_dir.mkdir()
            for name in ("clang", "clang++-22"):
                candidate = bin_dir / name
                candidate.touch()
                candidate.chmod(0o755)

            with mock.patch.object(
                self.cargo_wrapper,
                "_is_native_darwin_compiler",
                side_effect=lambda path: path.name in {"clang", "clang++-22"},
            ):
                pair = self.cargo_wrapper._native_compiler_pair(
                    prefix,
                    {"CONDA_PREFIX": str(prefix), "PATH": ""},
                )

        self.assertEqual(pair, (str(bin_dir / "clang"), str(bin_dir / "clang++-22")))

    def test_cargo_wrapper_allows_native_macos_compilers(self) -> None:
        with mock.patch.object(self.cargo_wrapper.platform, "system", return_value="Darwin"):
            with mock.patch.object(self.cargo_wrapper.platform, "machine", return_value="arm64"):
                with mock.patch.dict(
                    self.cargo_wrapper.os.environ,
                    {"CC": "/usr/bin/clang", "CXX": "/usr/bin/clang++"},
                    clear=False,
                ):
                    with mock.patch.object(
                        self.cargo_wrapper.subprocess,
                        "run",
                        return_value=SimpleNamespace(returncode=29),
                    ) as run_mock:
                        exit_code = self.cargo_wrapper.main(["test", "-p", "apxm-cli"])

        self.assertEqual(exit_code, 29)
        run_mock.assert_called_once()

    def test_cargo_wrapper_allows_explicit_linux_target_on_macos(self) -> None:
        with mock.patch.object(self.cargo_wrapper.platform, "system", return_value="Darwin"):
            with mock.patch.object(self.cargo_wrapper.platform, "machine", return_value="arm64"):
                with mock.patch.dict(
                    self.cargo_wrapper.os.environ,
                    {
                        "CC": "/tmp/x86_64-conda-linux-gnu-gcc",
                        "CXX": "/tmp/x86_64-conda-linux-gnu-g++",
                    },
                    clear=False,
                ):
                    with mock.patch.object(
                        self.cargo_wrapper.subprocess,
                        "run",
                        return_value=SimpleNamespace(returncode=31),
                    ) as run_mock:
                        exit_code = self.cargo_wrapper.main(
                            [
                                "build",
                                "-p",
                                "apxm-cli",
                                "--bin",
                                "apxm",
                                "--release",
                                "--target",
                                "x86_64-unknown-linux-gnu",
                            ]
                        )

        self.assertEqual(exit_code, 31)
        run_mock.assert_called_once()

    def test_dekk_manifest_pins_compiler_dev_run_target(self) -> None:
        manifest = tomllib.loads(DEKK_MANIFEST_PATH.read_text(encoding="utf-8"))
        expected_commands = {
            "check",
            "codegen",
            "check-frontend-codegen",
            "codegen-typescript",
            "codegen-typescript-frontend",
            "codegen-event-kinds",
            "codegen-op-spec",
        }
        commands = manifest["commands"]
        for name in expected_commands:
            run = commands[name]["run"]
            self.assertIn(
                "cargo.py run -p apxm-cli-dev --bin apxm-dev",
                run,
                f"`dekk agents {name}` must select the compiler-dev binary exactly",
            )


if __name__ == "__main__":
    unittest.main()
