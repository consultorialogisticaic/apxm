"""Tests for the product-neutral APXM owner release gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "scripts" / "release_qualification.py"


def git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    if sys.platform == "darwin":
        environment.pop("DYLD_LIBRARY_PATH", None)
        environment.pop("DYLD_FALLBACK_LIBRARY_PATH", None)
    return environment


def load_module():
    spec = importlib.util.spec_from_file_location("release_qualification", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load release qualification script")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_clean_owner_checkout(root: Path) -> tuple[str, dict[str, Path]]:
    """Create a tiny clean checkout with the two ignored APXM service binaries."""

    subprocess.run(["git", "init", "-q", str(root)], check=True, env=git_environment())
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "tests@example.invalid"],
        check=True,
        env=git_environment(),
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Release Qualification Tests"],
        check=True,
        env=git_environment(),
    )
    (root / ".gitignore").write_text("target/\n", encoding="utf-8")
    (root / "README.md").write_text("fixture\n", encoding="utf-8")
    for relative, contents in (
        (
            "crates/compiler/service-protocol/src/lib.rs",
            b"pub const COMPILATION_PROTOCOL_VERSION: &str = \"apxm.compilation.protocol/2\";\n",
        ),
        (
            "crates/runtime/service-protocol/src/lib.rs",
            b"pub const RUNTIME_PROTOCOL_VERSION: &str = \"apxm.runtime.protocol/1\";\n",
        ),
    ):
        protocol = root / relative
        protocol.parent.mkdir(parents=True, exist_ok=True)
        protocol.write_bytes(contents)
    schemas = root / "contracts" / "schemas"
    schemas.mkdir(parents=True, exist_ok=True)
    for schema_name in ("apxm.host-capability.v1", "apxm.execution-observation.v1"):
        (schemas / f"{schema_name}.json").write_text(
            json.dumps({"$id": schema_name, "type": "object"}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    subprocess.run(
        ["git", "-C", str(root), "add", ".gitignore", "README.md", "crates", "contracts"],
        check=True,
        env=git_environment(),
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "-qm", "fixture"],
        check=True,
        env=git_environment(),
    )
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        env=git_environment(),
    ).stdout.strip()
    artifacts = {
        "compilation-service": root / "target" / "release" / "apxm-compilation-service",
        "runtime-service": root / "target" / "release" / "apxm-runtime-service",
        "python-frontend-native": root / "target" / "release" / "lib_native.so",
    }
    for index, artifact in enumerate(artifacts.values()):
        artifact.parent.mkdir(parents=True, exist_ok=True)
        if artifact.name == "lib_native.so":
            native = bytearray(64)
            native[:7] = b"\x7fELF\x02\x01\x01"
            native[18:20] = (62).to_bytes(2, "little")
            artifact.write_bytes(native)
        else:
            artifact.write_bytes(f"real service bytes {index}\n".encode())
        artifact.chmod(0o755)
    return revision, artifacts


class ReleaseQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.qualification = load_module()

    def _prepare_descriptor_overlay(self, root: Path, artifacts: dict[str, Path]) -> None:
        for relative in self.qualification.RELEASE_DESCRIPTOR_RELS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(root), "add", "deploy", "contracts"],
            check=True,
            env=git_environment(),
        )
        subprocess.run(
            ["git", "-C", str(root), "commit", "-qm", "track descriptor inputs"],
            check=True,
            env=git_environment(),
        )
        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            env=git_environment(),
        ).stdout.strip()
        self.qualification.generate_descriptors(
            root,
            compilation_service_path=str(artifacts["compilation-service"]),
            runtime_service_path=str(artifacts["runtime-service"]),
            output_dir=root,
            source_revision=revision,
        )

    def test_missing_publishable_artifact_fails_closed_with_actionable_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.qualification.qualify(root, run_gates=False)
        self.assertFalse(result.ok)
        rendered = "\n".join(item.render() for item in result.diagnostics)
        self.assertIn("missing-publishable-service-artifact", rendered)
        self.assertIn("apxm-compilation-service", rendered)
        self.assertIn("apxm-runtime-service", rendered)
        self.assertNotIn("reference-host", rendered)
        self.assertIn("runtime-activation-blocked", rendered)

    def test_gate_failures_are_classified_as_resource_abi_or_code(self) -> None:
        classify = self.qualification._classify_gate_failure
        self.assertEqual(classify(137, "Killed: 9"), "resource")
        self.assertEqual(classify(1, "error[E0514]: found crate compiled by an incompatible rustc"), "abi")
        self.assertEqual(classify(1, "assertion failed: expected artifact"), "code")

    def test_local_service_binaries_without_release_cohort_are_not_activation_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compilation = root / "apxm-compilation-service"
            runtime = root / "apxm-runtime-service"
            for artifact in (compilation, runtime):
                artifact.write_bytes(b"local build")
                artifact.chmod(0o755)
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(compilation),
                runtime_service_path=str(runtime),
                run_gates=False,
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(item.code == "unattested-service-artifacts" for item in result.diagnostics))

    def test_generation_uses_exact_service_bytes_and_writes_all_release_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            output = root / "out"
            source, owner, sidecar, manifest = self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=output,
                source_revision=revision,
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            expected = {
                name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in artifacts.items()
                if name in {"compilation-service", "runtime-service"}
            }
            self.assertEqual(
                {item["name"]: item["digest"] for item in payload["services"]}, expected
            )
            self.assertNotIn("placeholder", sidecar.read_text(encoding="utf-8").lower())
            self.assertEqual(payload["source_revision"], revision)
            self.assertEqual(
                payload["frontend_native"]["digest"],
                "sha256:" + hashlib.sha256(artifacts["python-frontend-native"].read_bytes()).hexdigest(),
            )
            self.assertTrue(source.is_file())
            self.assertTrue(owner.is_file())

    def test_qualification_passes_only_after_publishing_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
        self.assertTrue(result.ok, [item.render() for item in result.diagnostics])

    def test_qualification_restores_manifest_bridge_after_mutating_owner_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            original = artifacts["python-frontend-native"].read_bytes()
            post_restore_observations: list[tuple[bytes, object]] = []

            def mutating_gate(
                _root: Path,
                _gates: tuple[str, ...],
                _result: object,
                *,
                emit_output: bool,
                environment: object = None,
            ) -> None:
                del emit_output
                if _gates == ("test-python-frontend",):
                    post_restore_observations.append(
                        (artifacts["python-frontend-native"].read_bytes(), environment)
                    )
                    return
                artifacts["python-frontend-native"].write_bytes(b"gate rebuilt bridge")

            with patch.object(self.qualification, "_run_gates", side_effect=mutating_gate):
                result = self.qualification.qualify(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    run_gates=True,
                )

            self.assertTrue(result.ok, [item.render() for item in result.diagnostics])
            self.assertEqual(artifacts["python-frontend-native"].read_bytes(), original)
            self.assertEqual(
                result.artifact_digests["python-frontend-native"],
                "sha256:" + hashlib.sha256(original).hexdigest(),
            )
            self.assertEqual(post_restore_observations[0][0], original)
            self.assertEqual(
                post_restore_observations[0][1], {"APXM_SKIP_NATIVE_BUILD": "1"}
            )

    def test_qualification_rejects_stale_bridge_even_if_a_gate_rebuilds_matching_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            published = artifacts["python-frontend-native"].read_bytes()
            artifacts["python-frontend-native"].write_bytes(b"stale bridge")

            def matching_gate(
                _root: Path,
                _gates: tuple[str, ...],
                _result: object,
                *,
                emit_output: bool,
                environment: object = None,
            ) -> None:
                del emit_output
                del environment
                if _gates == ("test-python-frontend",):
                    return
                artifacts["python-frontend-native"].write_bytes(published)

            with patch.object(self.qualification, "_run_gates", side_effect=matching_gate):
                result = self.qualification.qualify(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    run_gates=True,
                )

            self.assertFalse(result.ok)
            self.assertTrue(
                any(item.code == "frontend-native-digest-mismatch" for item in result.diagnostics)
            )
            self.assertEqual(artifacts["python-frontend-native"].read_bytes(), b"stale bridge")

    def test_qualification_rejects_gate_created_bridge_when_manifest_input_was_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            published = artifacts["python-frontend-native"].read_bytes()
            artifacts["python-frontend-native"].unlink()

            def creating_gate(
                _root: Path,
                _gates: tuple[str, ...],
                _result: object,
                *,
                emit_output: bool,
                environment: object = None,
            ) -> None:
                del emit_output
                del environment
                if _gates == ("test-python-frontend",):
                    return
                artifacts["python-frontend-native"].write_bytes(published)

            with patch.object(self.qualification, "_run_gates", side_effect=creating_gate):
                result = self.qualification.qualify(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    run_gates=True,
                )

            self.assertFalse(result.ok)
            self.assertTrue(
                any(item.code == "missing-publishable-frontend-native" for item in result.diagnostics)
            )
            self.assertFalse(artifacts["python-frontend-native"].exists())

    def test_qualification_honors_manifest_frontend_override_over_default_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            package_bridge = (
                root
                / "crates/compiler/frontend/python/apxm_program/_native.so"
            )
            package_bridge.parent.mkdir(parents=True, exist_ok=True)
            package_bridge.write_bytes(b"the explicitly selected bridge")
            package_bridge.chmod(0o755)
            subprocess.run(
                ["git", "-C", str(root), "add", str(package_bridge.relative_to(root))],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish bridge fixture"],
                check=True,
                env=git_environment(),
            )
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                python_frontend_native_path=str(package_bridge),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )

        self.assertTrue(result.ok, [item.render() for item in result.diagnostics])
        self.assertEqual(
            result.artifacts["python-frontend-native"].resolve(), package_bridge.resolve()
        )

    def test_gated_qualification_conformance_imports_an_alternate_manifest_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            alternate = root / "target/release/alternate_native.so"
            published = b"explicit alternate bridge"
            alternate.write_bytes(published)
            alternate.chmod(0o755)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                python_frontend_native_path=str(alternate),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            package_bridge = root / self.qualification.PYTHON_FRONTEND_PACKAGE_REL
            observed: list[bytes] = []

            def mutating_gate(
                _root: Path,
                _gates: tuple[str, ...],
                _result: object,
                *,
                emit_output: bool,
                environment: object = None,
            ) -> None:
                del emit_output
                if environment is not None:
                    observed.append(package_bridge.read_bytes())
                    return
                alternate.write_bytes(b"gate alternate bridge")
                package_bridge.parent.mkdir(parents=True, exist_ok=True)
                package_bridge.write_bytes(b"gate package bridge")

            with patch.object(self.qualification, "_run_gates", side_effect=mutating_gate):
                result = self.qualification.qualify(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    run_gates=True,
                )

            self.assertTrue(result.ok, [item.render() for item in result.diagnostics])
            self.assertEqual(observed, [published])
            self.assertEqual(alternate.read_bytes(), published)
            self.assertFalse(package_bridge.exists())

    def test_qualification_rejects_inside_and_outside_frontend_symlinks_before_gates(self) -> None:
        for target_kind in ("inside", "outside"):
            with self.subTest(target_kind=target_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                revision, artifacts = make_clean_owner_checkout(root)
                self.qualification.generate_descriptors(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    output_dir=root,
                    source_revision=revision,
                )
                subprocess.run(
                    ["git", "-C", str(root), "add", "deploy", "contracts"],
                    check=True,
                    env=git_environment(),
                )
                subprocess.run(
                    ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                    check=True,
                    env=git_environment(),
                )
                bridge = artifacts["python-frontend-native"]
                if target_kind == "inside":
                    target = root / "inside-bridge"
                    target.write_bytes(b"inside target")
                else:
                    outside_directory = Path(tempfile.mkdtemp())
                    self.addCleanup(shutil.rmtree, outside_directory)
                    target = outside_directory / "outside-bridge"
                    target.write_bytes(b"outside target")
                bridge.unlink()
                bridge.symlink_to(target)

                with patch.object(
                    self.qualification,
                    "_run_gates",
                    side_effect=AssertionError("invalid symlink must stop before gates"),
                ):
                    result = self.qualification.qualify(
                        root,
                        compilation_service_path=str(artifacts["compilation-service"]),
                        runtime_service_path=str(artifacts["runtime-service"]),
                        run_gates=True,
                    )

                self.assertFalse(result.ok)
                self.assertTrue(
                    any(item.code == "invalid-frontend-native-input" for item in result.diagnostics)
                )
                self.assertTrue(bridge.is_symlink())

    def test_qualification_rejects_manifest_root_frontend_path_without_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            manifest_path = root / self.qualification.RELEASE_MANIFEST_REL
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["frontend_native"]["path"] = "."
            manifest_path.write_bytes(
                self.qualification._canonical_json(manifest)
            )
            with patch.object(self.qualification, "_run_gates"):
                result = self.qualification.qualify(root, run_gates=True)

        self.assertFalse(result.ok)
        self.assertTrue(
            any(item.code == "missing-publishable-frontend-native" for item in result.diagnostics)
        )

    def test_dirty_checkout_never_qualifies_even_with_matching_release_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(item.code == "dirty-checkout" for item in result.diagnostics))

    def test_exact_head_descriptor_overlay_can_be_explicitly_qualified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, artifacts = make_clean_owner_checkout(root)
            self._prepare_descriptor_overlay(root, artifacts)
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
                qualified_descriptor_overlay=True,
            )
        self.assertTrue(result.ok, [item.render() for item in result.diagnostics])

    def test_descriptor_overlay_does_not_admit_unrelated_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, artifacts = make_clean_owner_checkout(root)
            self._prepare_descriptor_overlay(root, artifacts)
            (root / "README.md").write_text("unrelated change\n", encoding="utf-8")
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
                qualified_descriptor_overlay=True,
            )
        self.assertTrue(any(item.code == "dirty-checkout" for item in result.diagnostics))

    def test_generation_refuses_to_overwrite_different_release_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as output_dir:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            output = Path(output_dir)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=output,
                source_revision=revision,
            )
            owner = output / self.qualification.OWNER_DESCRIPTOR_REL
            owner.write_text("{\"tampered\":true}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                self.qualification.generate_descriptors(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    output_dir=output,
                    source_revision=revision,
                )

    def test_tampered_artifact_is_rejected_when_manifest_digest_is_present(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            artifacts["runtime-service"].write_bytes(b"tampered")
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(item.code == "service-artifact-digest-mismatch" for item in result.diagnostics))

    def test_generation_publishes_every_shipped_schema_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            _, _, _, manifest = self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root / "out",
                source_revision=revision,
            )
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            expected = {
                path.stem: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted((root / "contracts" / "schemas").iterdir())
            }
        self.assertEqual({item["name"]: item["digest"] for item in payload["schemas"]}, expected)
        self.assertEqual(
            {item["path"] for item in payload["schemas"]},
            {f"contracts/schemas/{name}.json" for name in expected},
        )

    def test_generation_refuses_a_cohort_that_ships_no_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            subprocess.run(
                ["git", "-C", str(root), "rm", "-rq", "contracts/schemas"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "drop schemas"],
                check=True,
                env=git_environment(),
            )
            with self.assertRaisesRegex(ValueError, "contract schemas are missing"):
                self.qualification.generate_descriptors(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    output_dir=root / "out",
                    source_revision=revision,
                )

    def test_mutated_schema_is_rejected_against_the_published_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            (root / "contracts/schemas/apxm.host-capability.v1.json").write_text(
                '{"$id": "apxm.host-capability.v1", "type": "string"}\n', encoding="utf-8"
            )
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(item.code == "schema-digest-mismatch" for item in result.diagnostics))

    def test_unpublished_schema_blocks_qualification_until_the_manifest_is_regenerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            (root / "contracts/schemas/apxm.execution-read.v1.json").write_text(
                '{"$id": "apxm.execution-read.v1", "type": "object"}\n', encoding="utf-8"
            )
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
        self.assertFalse(result.ok)
        rendered = "\n".join(item.render() for item in result.diagnostics)
        self.assertIn("missing-published-schema", rendered)
        self.assertIn("apxm.execution-read.v1", rendered)

    def test_consumer_verification_rejects_a_tampered_packaged_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as package_dir:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            self.qualification.package_release(
                root,
                output_dir=Path(package_dir),
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
            packaged_schema = (
                Path(package_dir) / "contracts/schemas/apxm.host-capability.v1.json"
            )
            self.assertTrue(packaged_schema.is_file())
            packaged_schema.write_text('{"type": "string"}\n', encoding="utf-8")
            verified = self.qualification.verify_package(Path(package_dir))
        self.assertFalse(verified["qualified"])
        codes = {item["code"] for item in verified["diagnostics"]}
        self.assertIn("schema-digest-mismatch", codes)

    def test_release_manifest_schema_document_matches_the_validator(self) -> None:
        document = json.loads(
            (
                ROOT / "contracts/schemas/apxm.agents-service-release-manifest.v1.json"
            ).read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (ROOT / self.qualification.RELEASE_MANIFEST_REL).read_text(encoding="utf-8")
        )
        self.assertEqual(set(document["required"]), set(document["properties"]))
        self.assertEqual(set(manifest), set(document["required"]))
        self.assertIn("schemas", document["required"])
        self.assertEqual(
            set(document["properties"]["schemas"]["items"]["required"]),
            {"name", "path", "digest"},
        )

    def test_checked_in_manifest_publishes_every_shipped_schema(self) -> None:
        manifest = json.loads(
            (ROOT / self.qualification.RELEASE_MANIFEST_REL).read_text(encoding="utf-8")
        )
        published = {item["name"]: item["digest"] for item in manifest["schemas"]}
        shipped = {
            name: "sha256:" + hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for name, relative in self.qualification._discover_shipped_schemas(ROOT)
        }
        self.assertEqual(published, shipped)

    def test_manifest_must_bind_owner_descriptor_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            manifest_path = root / self.qualification.RELEASE_MANIFEST_REL
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            del manifest["owner_descriptor_digest"]
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(item.code == "invalid-schema" for item in result.diagnostics))

    def test_protocol_descriptor_drift_is_rejected_against_source_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            (root / "crates/compiler/service-protocol/src/lib.rs").write_bytes(
                b"drifted protocol bytes\n"
            )
            result = self.qualification.qualify(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
        self.assertFalse(result.ok)
        self.assertTrue(any(item.code == "protocol-descriptor-drift" for item in result.diagnostics))

    def test_package_release_is_write_once_and_binds_all_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as package_dir:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            output = self.qualification.package_release(
                root,
                output_dir=Path(package_dir),
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
            self.assertTrue(output["qualified"], output["diagnostics"])
            self.assertEqual(output["qualification_scope"], "owner-local")
            self.assertFalse(output["external_live_approval"])
            package = output["package"]
            self.assertIsInstance(package, dict)
            self.assertEqual(
                {item["name"] for item in package["files"] if "name" in item},
                {
                    "source-descriptor",
                    "owner-descriptor",
                    "owner-descriptor-sidecar",
                    "release-manifest",
                    "compilation-protocol",
                    "runtime-protocol",
                    "compilation-service",
                    "runtime-service",
                    "python-frontend-native",
                    "apxm.host-capability.v1",
                    "apxm.execution-observation.v1",
                },
            )
            package_manifest = Path(package["root"]) / package["manifest"]
            before = package_manifest.read_bytes()
            repeated = self.qualification.package_release(
                root,
                output_dir=Path(package_dir),
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
            self.assertEqual(repeated["package"]["manifest_digest"], package["manifest_digest"])
            self.assertEqual(package_manifest.read_bytes(), before)
            (Path(package["root"]) / "target/release/apxm-runtime-service").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "immutable release package file"):
                self.qualification.package_release(
                    root,
                    output_dir=Path(package_dir),
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    run_gates=False,
                )

    def test_package_release_defaults_to_new_cohort_without_replacing_current(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            (root / ".gitignore").write_text("target/\n.apxm/\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", ".gitignore"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "ignore runtime artifacts"],
                check=True,
                env=git_environment(),
            )
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            current = root / ".apxm" / "release-artifacts" / "current"
            current.mkdir(parents=True)
            marker = current / "legacy.marker"
            marker.write_bytes(b"superseded cohort remains untouched")

            output = self.qualification.package_release(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )

            self.assertTrue(output["qualified"], output["diagnostics"])
            package_root = Path(output["package"]["root"])
            self.assertEqual(package_root.name, f"cohort-{revision[:8]}")
            self.assertNotEqual(package_root, current)
            self.assertEqual(marker.read_bytes(), b"superseded cohort remains untouched")
            self.assertTrue(
                (package_root / self.qualification.LOCAL_ARTIFACT_MANIFEST_REL).is_file()
            )

    def test_consumer_verification_accepts_exact_package_and_emits_neutral_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as package_dir:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            packaged = self.qualification.package_release(
                root,
                output_dir=Path(package_dir),
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
            verified = self.qualification.verify_package(Path(package_dir))
        self.assertTrue(verified["qualified"], verified["diagnostics"])
        self.assertEqual(verified["qualification_scope"], "consumer-local")
        self.assertFalse(verified["external_live_approval"])
        self.assertEqual(
            verified["package_manifest_digest"], packaged["package"]["manifest_digest"]
        )
        self.assertEqual(len(verified["verified_files"]), 11)

    def test_consumer_verification_rejects_tampered_bytes_and_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as package_dir:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            self.qualification.package_release(
                root,
                output_dir=Path(package_dir),
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
            runtime = Path(package_dir) / "target/release/apxm-runtime-service"
            runtime.write_bytes(b"tampered package bytes")
            (Path(package_dir) / "unexpected.txt").write_bytes(b"extra")
            verified = self.qualification.verify_package(Path(package_dir))
        self.assertFalse(verified["qualified"])
        codes = {item["code"] for item in verified["diagnostics"]}
        self.assertIn("package-file-digest-mismatch", codes)
        self.assertIn("package-file-set-mismatch", codes)

    def test_consumer_verification_rejects_manifest_digest_rebinding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as package_dir:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish fixture"],
                check=True,
                env=git_environment(),
            )
            self.qualification.package_release(
                root,
                output_dir=Path(package_dir),
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                run_gates=False,
            )
            package_manifest = Path(package_dir) / self.qualification.LOCAL_ARTIFACT_MANIFEST_REL
            manifest = json.loads(package_manifest.read_text(encoding="utf-8"))
            manifest["source_descriptor_digest"] = "sha256:" + "0" * 64
            package_manifest.write_bytes(self.qualification._canonical_json(manifest))
            verified = self.qualification.verify_package(Path(package_dir))
        self.assertFalse(verified["qualified"])
        codes = {item["code"] for item in verified["diagnostics"]}
        self.assertIn("package-digest-binding-mismatch", codes)

    def test_dekk_manifest_exposes_consumer_verification_command(self) -> None:
        import tomllib

        manifest = tomllib.loads((ROOT / ".dekk.toml").read_text(encoding="utf-8"))
        command = manifest["commands"]["verify-package"]
        self.assertEqual(
            command["run"],
            "python tools/scripts/release_qualification.py verify-package --json",
        )
        self.assertIn("consumer boundary", command["description"])

    def test_in_place_regeneration_moves_the_checkout_to_a_new_cohort(self) -> None:
        # A cohort is re-cut by regenerating the descriptors the checkout ships.
        # Write-once is right for a package tree, but in the checkout it only
        # forced the owner to launder the same bytes through a temporary
        # directory: Git already holds the documents being replaced.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "publish cohort"],
                check=True,
                env=git_environment(),
            )
            superseded = (root / self.qualification.RELEASE_MANIFEST_REL).read_bytes()
            artifacts["compilation-service"].write_bytes(b"rebuilt service bytes\n")
            artifacts["compilation-service"].chmod(0o755)
            next_revision = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                env=git_environment(),
            ).stdout.strip()
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=next_revision,
            )
            manifest = json.loads(
                (root / self.qualification.RELEASE_MANIFEST_REL).read_text(encoding="utf-8")
            )
            self.assertNotEqual(
                (root / self.qualification.RELEASE_MANIFEST_REL).read_bytes(), superseded
            )
            self.assertEqual(manifest["source_revision"], next_revision)
            subprocess.run(
                ["git", "-C", str(root), "add", "deploy", "contracts"],
                check=True,
                env=git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "re-cut cohort"],
                check=True,
                env=git_environment(),
            )
            result = self.qualification.qualify(root, run_gates=False)
        self.assertTrue(result.ok, [item.render() for item in result.diagnostics])

    def test_image_descriptors_reproduce_the_cohort_or_refuse_to_emit(self) -> None:
        # An image has no checkout to ask which revision it is, so it proves the
        # one it was handed: the source and owner descriptors must regenerate
        # byte-identically and the schema digests must match the cohort. Only
        # the service bytes it just built may differ.
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as out:
            root = Path(temporary)
            output = Path(out)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            artifacts["compilation-service"].write_bytes(b"linux service bytes\n")
            artifacts["compilation-service"].chmod(0o755)
            payload = self.qualification.generate_image_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=output,
                source_revision=revision,
            )
            self.assertEqual(payload["source_revision"], revision)
            self.assertEqual(payload["schema_count"], 2)
            emitted = (output / self.qualification.RELEASE_MANIFEST_REL).read_bytes()
            self.assertEqual(
                payload["release_manifest_digest"],
                self.qualification._digest_bytes(emitted),
            )
            self.assertEqual(
                (output / self.qualification.SOURCE_DESCRIPTOR_REL).read_bytes(),
                (root / self.qualification.SOURCE_DESCRIPTOR_REL).read_bytes(),
            )
            compilation = next(
                item for item in payload["services"] if item["name"] == "compilation-service"
            )
            self.assertEqual(
                compilation["digest"],
                self.qualification._digest_file(artifacts["compilation-service"]),
            )

            schema = root / "contracts" / "schemas" / "apxm.host-capability.v1.json"
            schema.write_text('{"$id":"tampered"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema digests"):
                self.qualification.generate_image_descriptors(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    output_dir=output,
                    source_revision=revision,
                )

    def test_image_descriptors_refuse_a_revision_the_checkout_does_not_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as out:
            root = Path(temporary)
            revision, artifacts = make_clean_owner_checkout(root)
            self.qualification.generate_descriptors(
                root,
                compilation_service_path=str(artifacts["compilation-service"]),
                runtime_service_path=str(artifacts["runtime-service"]),
                output_dir=root,
                source_revision=revision,
            )
            with self.assertRaisesRegex(ValueError, "does not match the checked-in cohort"):
                self.qualification.generate_image_descriptors(
                    root,
                    compilation_service_path=str(artifacts["compilation-service"]),
                    runtime_service_path=str(artifacts["runtime-service"]),
                    output_dir=Path(out),
                    source_revision="0" * 40,
                )

    def test_dekk_manifest_exposes_owner_qualification_commands(self) -> None:
        import tomllib

        manifest = tomllib.loads((ROOT / ".dekk.toml").read_text(encoding="utf-8"))
        commands = manifest["commands"]
        self.assertIn("release-qualification", commands)
        self.assertIn("package-release", commands)
        self.assertIn("release-descriptors", commands)
        self.assertIn("release_qualification.py", commands["release-qualification"]["run"])
        descriptor_command = commands["release-descriptors"]["run"]
        self.assertIn("APXM_COMPILATION_SERVICE_BINARY", descriptor_command)
        self.assertIn("APXM_RUNTIME_SERVICE_BINARY", descriptor_command)
        self.assertNotIn("target/release/apxm-compilation-service", descriptor_command)

    def test_dekk_manifest_exposes_distinct_owner_phase_declarations(self) -> None:
        import tomllib

        commands = tomllib.loads((ROOT / ".dekk.toml").read_text(encoding="utf-8"))["commands"]
        names = (
            "owner-e2e",
            "owner-compilation-runtime",
            "owner-negative-recovery",
            "owner-integrated-execution",
            "owner-protocol-clients",
            "owner-restart-reopen",
        )
        runs = {name: commands[name]["run"] for name in names}
        self.assertEqual(len(set(runs.values())), len(names))
        for name, run in runs.items():
            self.assertEqual(run, f"python tools/scripts/owner_phase.py {name}")
            self.assertNotIn("&&", run, name)


if __name__ == "__main__":
    unittest.main()
