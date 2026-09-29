"""Pin the service-image contract without needing a container runtime.

The images are the consumer boundary, so the properties that matter are the
ones a consumer relies on: every label a pin names is stamped, every stamped
digest is re-proved inside the build against the bytes the image carries, the
manifest path in the image is the path the release manifest publishes, and the
expensive stages of the two Dockerfiles are identical so one compile serves
both. `dekk agents verify-images` checks a built image; this checks the
contract that makes such an image verifiable, and runs in the MLIR-free gate.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from unittest import mock
import tomllib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEKK_MANIFEST_PATH = REPOSITORY_ROOT / ".dekk.toml"
SERVICE_IMAGES_PATH = REPOSITORY_ROOT / "tools" / "scripts" / "service_images.py"
RELEASE_INSIDE_IMAGE = REPOSITORY_ROOT / "deploy" / "release-inside-image.sh"
RELEASE_MANIFEST = (
    REPOSITORY_ROOT
    / "contracts"
    / "services"
    / "manifests"
    / "apxm.agents-service-release-manifest.v1.json"
)

#: The instructions both Dockerfiles must share, so BuildKit compiles the
#: workspace once and both images carry bytes from the same compilation.
SHARED_STAGE_MARKERS = (
    "FROM ${APXM_BUILDER_IMAGE} AS builder",
    "FROM builder AS release",
)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def instructions(text: str) -> list[str]:
    """Return one logical Dockerfile instruction per element, comments dropped."""

    joined = text.replace("\\\n", " ")
    return [
        " ".join(line.split())
        for line in joined.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class ServiceImageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with mock.patch.object(sys, "path", [str(SERVICE_IMAGES_PATH.parent), *sys.path]):
            cls.images = load_module(SERVICE_IMAGES_PATH, "service_images")
        with DEKK_MANIFEST_PATH.open("rb") as handle:
            cls.manifest = tomllib.load(handle)
        cls.dockerfiles = {
            service: (REPOSITORY_ROOT / spec["dockerfile"]).read_text(encoding="utf-8")
            for service, spec in cls.images.SERVICES.items()
        }

    def candidate_fixture(self, root: Path):
        for relative in (self.images.SOURCE_DESCRIPTOR_REL, self.images.OWNER_DESCRIPTOR_REL,
                         self.images.OWNER_SIDECAR_REL, self.images.RELEASE_MANIFEST_REL):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((REPOSITORY_ROOT / relative).read_bytes())
        schema = root / "contracts/schemas/apxm.frontend-conformance.json"
        schema.parent.mkdir(parents=True, exist_ok=True)
        schema.write_text('{"changed":true}\n', encoding="utf-8")
        (root / "driver.rs").write_text("changed driver\n", encoding="utf-8")
        paths = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
        def run(command, **kwargs):
            if "rev-parse" in command:
                return "a" * 40 + "\n"
            if "status" in command:
                return " M driver.rs\n"
            if "ls-files" in command:
                return "\0".join(paths) + "\0"
            raise AssertionError(command)
        return run

    def test_candidate_freezes_exact_dirty_bytes_without_rewriting_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = self.candidate_fixture(root)
            original_descriptor = (root / self.images.SOURCE_DESCRIPTOR_REL).read_bytes()
            with mock.patch.object(self.images, "_run", side_effect=run):
                output, provenance = self.images.snapshot_candidate(root)
            snapshot = output / "source"
            self.assertTrue(output.is_relative_to(root / ".apxm"))
            self.assertTrue(provenance["dirty"])
            self.assertFalse(provenance["published"])
            self.assertEqual(provenance["base_revision"], "a" * 40)
            self.assertEqual((root / self.images.SOURCE_DESCRIPTOR_REL).read_bytes(), original_descriptor)
            self.assertEqual(self.images.declared_revision(snapshot), "a" * 40)
            self.assertEqual(provenance["source_tree_digest"], self.images._digest_bytes(
                self.images._canonical_json(self.images._tree_manifest(snapshot))))
            (root / "driver.rs").write_text("later edit\n", encoding="utf-8")
            self.assertEqual((snapshot / "driver.rs").read_text(), "changed driver\n")
            self.assertNotEqual(provenance["input_tree_digest"], provenance["source_tree_digest"])

    def test_candidate_rehashes_changed_schema_without_rewriting_release_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = self.candidate_fixture(root)
            manifest_path = root / self.images.RELEASE_MANIFEST_REL
            original = manifest_path.read_bytes()
            with mock.patch.object(self.images, "_run", side_effect=run):
                output, provenance = self.images.snapshot_candidate(root)
            snapshot = output / "source"
            candidate = json.loads((snapshot / self.images.RELEASE_MANIFEST_REL).read_bytes())
            relative = "contracts/schemas/apxm.frontend-conformance.json"
            self.assertEqual(candidate["schemas"], [{"name": "apxm.frontend-conformance",
                "path": relative, "digest": self.images._digest_file(snapshot / relative)}])
            self.assertEqual(manifest_path.read_bytes(), original)
            original_value = json.loads(original)
            for key in original_value.keys() - {"source_revision", "owner_descriptor_digest", "schemas"}:
                self.assertEqual(candidate[key], original_value[key])
            self.assertFalse(provenance["published"])

    def test_normal_image_descriptors_still_refuse_changed_schema(self):
        owner = sys.modules["release_qualification"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.candidate_fixture(root)
            relatives = (owner.SOURCE_DESCRIPTOR_REL, owner.OWNER_DESCRIPTOR_REL,
                         owner.OWNER_DESCRIPTOR_SIDECAR_REL, owner.RELEASE_MANIFEST_REL)
            documents = {relative: (root / relative).read_bytes() for relative in relatives}
            manifest = json.loads(documents[owner.RELEASE_MANIFEST_REL])
            manifest["schemas"][0]["digest"] = "sha256:" + "f" * 64
            documents[owner.RELEASE_MANIFEST_REL] = self.images._canonical_json(manifest)
            with mock.patch.object(owner, "build_release_documents", return_value=documents):
                with self.assertRaisesRegex(ValueError, "schema digests do not match"):
                    owner.generate_image_descriptors(root, compilation_service_path="unused",
                        runtime_service_path="unused", output_dir=root / "out",
                        source_revision="a" * 40)
            self.assertFalse((root / "out").exists())

    def test_candidate_builds_one_snapshot_with_distinct_tags_and_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = self.candidate_fixture(root)
            calls = []
            def build(snapshot, service, **kwargs):
                calls.append((snapshot, service, kwargs))
                return {"service": service, "tag": f"local/{service}:{kwargs['tag_suffix']}"}
            with mock.patch.object(self.images, "_run", side_effect=run), mock.patch.object(
                    self.images, "build_service_image", side_effect=build):
                result = self.images.build_candidate_images(root, platform="linux/arm64", prefix="local",
                    services=tuple(self.images.SERVICES))
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0], calls[1][0])
            self.assertNotEqual(calls[0][0], root)
            for _, _, kwargs in calls:
                self.assertTrue(kwargs["tag_suffix"].startswith("candidate-"))
                self.assertEqual(kwargs["labels"][self.images.CANDIDATE_LABEL], "true")
                self.assertEqual(kwargs["labels"][self.images.TREE_DIGEST_LABEL], result["source"]["source_tree_digest"])
                self.assertEqual(kwargs["labels"]["io.apxm.published"], "false")
            self.assertTrue(Path(result["receipt_path"]).is_file())
            (calls[0][0] / "driver.rs").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(self.images.ImageError, "snapshot changed"):
                self.images.verify_candidate_images(root, Path(result["receipt_path"]))

    def test_normal_release_build_still_refuses_dirty_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = self.candidate_fixture(root)
            with mock.patch.object(self.images, "_run", side_effect=run), mock.patch.object(
                    self.images, "build_service_image") as build:
                with self.assertRaisesRegex(self.images.ImageError, "dirty checkout"):
                    self.images.build_images(root, platform="linux/arm64", prefix="release", services=tuple(self.images.SERVICES))
                build.assert_not_called()
    def test_release_build_accepts_only_exact_qualified_descriptor_overlay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.candidate_fixture(root)
            source_path = root / self.images.SOURCE_DESCRIPTOR_REL
            source = json.loads(source_path.read_bytes())
            source["source_revision"] = "a" * 40
            source_path.write_bytes(self.images._canonical_json(source))

            def run(command, **kwargs):
                if "status" in command:
                    return f" M {self.images.SOURCE_DESCRIPTOR_REL.as_posix()}\n"
                if "rev-parse" in command:
                    return "a" * 40 + "\n"
                raise AssertionError(command)

            with mock.patch.object(self.images, "_run", side_effect=run), mock.patch.object(
                    self.images, "build_service_image", return_value={"qualified": True}) as build, \
                    mock.patch.object(self.images.subprocess, "run", return_value=mock.Mock(returncode=0)):
                result = self.images.build_images(
                    root,
                    platform="linux/amd64",
                    prefix="release",
                    services=("compilation-service",),
                    qualified_descriptor_overlay=True,
                )
            self.assertEqual(result["source_revision"], "a" * 40)
            build.assert_called_once()

    def test_release_build_rejects_unrelated_dirty_file_with_descriptor_overlay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.candidate_fixture(root)
            with mock.patch.object(
                    self.images,
                    "_run",
                    return_value=" M driver.rs\n",
                ), mock.patch.object(self.images, "build_service_image") as build:
                with self.assertRaisesRegex(self.images.ImageError, "dirty checkout"):
                    self.images.build_images(
                        root,
                        platform="linux/amd64",
                        prefix="release",
                        services=("compilation-service",),
                        qualified_descriptor_overlay=True,
                    )
                build.assert_not_called()

    def test_candidate_verification_rejects_a_retagged_different_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = self.candidate_fixture(root)
            labels = {}
            def build(snapshot, service, **kwargs):
                labels.update(kwargs["labels"])
                return {"service":service, "tag":"local/candidate:one", "service_digest":"sha256:original"}
            with mock.patch.object(self.images, "_run", side_effect=run), mock.patch.object(
                    self.images, "build_service_image", side_effect=build):
                receipt = self.images.build_candidate_images(root, platform="linux/arm64", prefix="local", services=("runtime-service",))
            with mock.patch.object(self.images, "_inspect", return_value={"Config":{"Labels":labels}}), mock.patch.object(
                    self.images, "verify_service_image", return_value={"qualified":True, "platform":"linux/arm64", "service_digest":"sha256:replaced", "diagnostics":[]}):
                result = self.images.verify_candidate_images(root, Path(receipt["receipt_path"]))
            self.assertFalse(result["qualified"])
            self.assertEqual(result["images"][0]["diagnostics"][0]["code"], "candidate-build-result-mismatch")

    def test_release_verification_never_promotes_a_candidate_label(self):
        with mock.patch.object(self.images, "_inspect", return_value={"Config":{"Labels":{
                self.images.CANDIDATE_LABEL:"true"}}}), mock.patch.object(self.images, "_extract") as extract:
            with self.assertRaisesRegex(self.images.ImageError, "explicit candidate-provenance"):
                self.images.verify_service_image(REPOSITORY_ROOT, "runtime-service", "retagged:release")
            extract.assert_not_called()

    def test_source_snapshot_rejects_links_outside_owner_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "escape").symlink_to(root.parent)
            with self.assertRaisesRegex(self.images.ImageError, "symlink escapes"):
                self.images._tree_manifest(root)

    def test_docker_builds_use_the_supplied_snapshot_directory(self):
        captured = []
        descriptors = {"source_revision": "a" * 40, "services": [{"name":"runtime-service", "digest":"sha256:service"}],
            "release_manifest_digest":"sha256:manifest", "frontend_native":{"digest":"sha256:frontend"},
            "owner_descriptor_digest":"sha256:owner", "schema_count": 1}
        def run(command, **kwargs):
            captured.append((command, kwargs))
            return json.dumps(descriptors) if command[1] == "run" else ""
        with mock.patch.object(self.images, "_run", side_effect=run):
            self.images.build_service_image(Path("/frozen/source"), "runtime-service", revision="a" * 40,
                platform="linux/arm64", prefix="local", tag_suffix="candidate-example", labels={self.images.CANDIDATE_LABEL:"true"})
        builds = [(command, kwargs) for command, kwargs in captured if command[1] == "build"]
        self.assertEqual(len(builds), 2)
        self.assertTrue(all(kwargs["cwd"] == Path("/frozen/source") for _, kwargs in builds))
        self.assertTrue(all("io.apxm.candidate=true" in command for command, _ in builds))

    def test_every_image_builds_its_executable_from_the_checkout(self) -> None:
        for service, text in self.dockerfiles.items():
            with self.subTest(service=service):
                self.assertIn("COPY . /workspace", text)
                self.assertIn("cargo build --release --locked", text)
                self.assertNotIn(
                    "COPY target/release/",
                    text,
                    "a service image must not inherit a host build output",
                )

    def test_release_stage_regenerates_the_cohort_from_the_bytes_it_built(self) -> None:
        for service, text in self.dockerfiles.items():
            with self.subTest(service=service):
                self.assertIn("sh deploy/release-inside-image.sh /workspace /out", text)
        script = RELEASE_INSIDE_IMAGE.read_text(encoding="utf-8")
        self.assertIn("image-descriptors", script)
        for spec in self.images.SERVICES.values():
            self.assertIn(spec["executable"], script)

    def test_expensive_stages_are_identical_so_one_compile_serves_both(self) -> None:
        prefixes = []
        for text in self.dockerfiles.values():
            steps = instructions(text)
            end = steps.index("FROM ${APXM_BASE_IMAGE}")
            prefixes.append(steps[:end])
            for marker in SHARED_STAGE_MARKERS:
                self.assertIn(marker, steps)
        self.assertEqual(prefixes[0], prefixes[1])

    def test_every_pinned_label_is_stamped_and_re_proved_inside_the_build(self) -> None:
        expected = {
            "compilation-service": (
                self.images.SERVICE_DIGEST_LABEL,
                self.images.RELEASE_MANIFEST_DIGEST_LABEL,
                self.images.FRONTEND_NATIVE_DIGEST_LABEL,
                self.images.SERVICE_LABEL,
                self.images.REVISION_LABEL,
            ),
            "runtime-service": (
                self.images.SERVICE_DIGEST_LABEL,
                self.images.RELEASE_MANIFEST_DIGEST_LABEL,
                self.images.SERVICE_LABEL,
                self.images.REVISION_LABEL,
            ),
        }
        for service, labels in expected.items():
            text = self.dockerfiles[service]
            with self.subTest(service=service):
                for label in labels:
                    self.assertIn(f'{label}="', text)
                argument = self.images.SERVICES[service]["digest_arg"]
                self.assertIn(f"ARG {argument}", text)
                self.assertIn("ARG APXM_RELEASE_MANIFEST_DIGEST", text)
                # The stamped digest is only a claim until the build hashes the
                # bytes it stamped it from.
                self.assertIn(
                    f'| cut -d\' \' -f1)" = "${argument}" ]',
                    text,
                    "the build must reject an executable whose bytes drift from its label",
                )
                self.assertIn(
                    '| cut -d\' \' -f1)" = "$APXM_RELEASE_MANIFEST_DIGEST" ]',
                    text,
                    "the build must reject a manifest whose bytes drift from its label",
                )

    def test_base_images_are_immutable_digest_references(self) -> None:
        for service, text in self.dockerfiles.items():
            with self.subTest(service=service):
                for argument in ("APXM_BUILDER_IMAGE", "APXM_NODE_IMAGE", "APXM_BASE_IMAGE"):
                    self.assertIn(f"ARG {argument}=", text)
                self.assertIn("must be an immutable digest reference", text)

    def test_image_executable_path_is_the_path_the_release_manifest_publishes(self) -> None:
        manifest = json.loads(RELEASE_MANIFEST.read_text(encoding="utf-8"))
        published = {item["name"]: item["path"] for item in manifest["services"]}
        for service, spec in self.images.SERVICES.items():
            with self.subTest(service=service):
                self.assertEqual(published[service], spec["executable"])
                self.assertIn(
                    f'ENTRYPOINT ["/workspace/{spec["executable"]}"]',
                    self.dockerfiles[service],
                )

    def test_dekk_manifest_exposes_the_image_commands_and_no_package_architecture_gate(self) -> None:
        commands = self.manifest["commands"]
        self.assertEqual(
            commands["build-images"]["run"], "python tools/scripts/service_images.py build"
        )
        self.assertEqual(
            commands["verify-images"]["run"], "python tools/scripts/service_images.py verify"
        )
        # Consumers verify Linux service bytes by reading the image that built
        # them, not by inspecting ELF headers in an owner-produced package.
        self.assertNotIn("verify-linux-package", commands)


if __name__ == "__main__":
    unittest.main()
