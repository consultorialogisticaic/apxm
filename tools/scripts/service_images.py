#!/usr/bin/env python3
"""Build and verify the two APXM service images.

The images are the consumer boundary. A consumer pins a cohort by its source
revision, its release manifest digest, its service digests, its frontend digest
and its schema digests, and it must be able to check every one of those against
a running image with nothing but `docker image inspect` and the image's own
filesystem -- no owner checkout, no owner tooling, no image manifest digest
(which cannot match a locally built image and is why a digest pin fails closed).

`build` therefore runs each image in two passes. The first builds the `release`
stage, which compiles the Linux executables from this checkout and regenerates
the cohort's descriptors from those exact bytes; the digests come out of that
stage. The second builds the whole image with those digests as build arguments,
so the image's labels are stamped from the manifest it carries and the build
re-proves both against the bytes that survived the copy. The expensive stages
are identical in both Dockerfiles and both passes, so the workspace compiles
once and every later stage is a cache hit.

`verify` is the consumer's side of that: it reads the labels, extracts the
manifest and the executable from the image, and checks the labels against the
manifest, the manifest against the executable's real bytes, and the cohort
identity (source revision, owner descriptor digest, schema digests) against the
descriptors checked in here. Service bytes are not expected to reproduce across
hosts; the cohort's identity is, and that is what binds an image to a pin.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from release_qualification import LOCAL_ARTIFACT_MANIFEST_REL, _discover_shipped_schemas, verify_package

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

SOURCE_DESCRIPTOR_REL = Path("deploy/services/source-revision.v1.json")
OWNER_DESCRIPTOR_REL = Path("contracts/descriptors/apxm.agents-owner-descriptor.v1.json")
RELEASE_MANIFEST_REL = Path(
    "contracts/services/manifests/apxm.agents-service-release-manifest.v1.json"
)

#: Service name -> (Dockerfile, executable path inside the image, digest build
#: argument). The executable path is the manifest path, so "the manifest names
#: the bytes this image runs" is a statement about one file, not a mapping.
SERVICES: dict[str, dict[str, str]] = {
    "compilation-service": {
        "dockerfile": "deploy/Dockerfile.compilation-service",
        "executable": "target/release/apxm-compilation-service",
        "digest_arg": "APXM_COMPILATION_SERVICE_DIGEST",
    },
    "runtime-service": {
        "dockerfile": "deploy/Dockerfile.runtime-service",
        "executable": "target/release/apxm-runtime-service",
        "digest_arg": "APXM_RUNTIME_SERVICE_DIGEST",
    },
}

FRONTEND_NATIVE_REL = "crates/compiler/frontend/python/apxm_program/_native.so"
SERVICE_LABEL = "io.apxm.service"
SERVICE_DIGEST_LABEL = "io.apxm.service-digest"
RELEASE_MANIFEST_DIGEST_LABEL = "io.apxm.release-manifest-digest"
FRONTEND_NATIVE_DIGEST_LABEL = "io.apxm.python-frontend-native-digest"
REVISION_LABEL = "org.opencontainers.image.revision"
CANDIDATE_LABEL = "io.apxm.candidate"
TREE_DIGEST_LABEL = "io.apxm.source-tree-digest"
PROVENANCE_DIGEST_LABEL = "io.apxm.source-provenance-digest"
CANDIDATE_SCHEMA = "apxm.agents.service-images-candidate.v1"
OWNER_SIDECAR_REL = OWNER_DESCRIPTOR_REL.with_suffix(".sha256")
RELEASE_DESCRIPTOR_RELS = (
    SOURCE_DESCRIPTOR_REL,
    OWNER_DESCRIPTOR_REL,
    OWNER_SIDECAR_REL,
    RELEASE_MANIFEST_REL,
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_PLATFORM = "linux/arm64"
DEFAULT_REPOSITORY_PREFIX = "apxm"


class ImageError(RuntimeError):
    """A build or verification could not be completed as specified."""


def _run(command: list[str], *, capture: bool = False, cwd: Path = REPOSITORY_ROOT) -> str:
    started = time.monotonic()
    if not capture:
        print(f"$ {' '.join(command)}", flush=True)
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=capture,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip() if capture else ""
        raise ImageError(
            f"command failed ({completed.returncode}) after {time.monotonic() - started:.1f}s: "
            f"{' '.join(command)}{': ' + detail if detail else ''}"
        )
    return completed.stdout if capture else ""


def _digest_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _digest_file(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def declared_revision(root: Path) -> str:
    """Return the source revision the checked-in descriptors publish."""

    document = _load_json(root / SOURCE_DESCRIPTOR_REL)
    revision = document.get("source_revision") if isinstance(document, dict) else None
    if not isinstance(revision, str) or not HEX40.fullmatch(revision):
        raise ImageError(
            f"{SOURCE_DESCRIPTOR_REL.as_posix()} publishes no full lowercase source revision"
        )
    return revision


def _require_publishable_checkout(
    root: Path, revision: str, *, qualified_descriptor_overlay: bool = False
) -> None:
    """Refuse to build an image from a tree that is not the cohort."""

    status = _run(["git", "-C", str(root), "status", "--porcelain"], capture=True)
    status_lines = {line for line in status.splitlines() if line}
    allowed_overlay = {f" M {relative.as_posix()}" for relative in RELEASE_DESCRIPTOR_RELS}
    if status_lines and not (
        qualified_descriptor_overlay and status_lines <= allowed_overlay
    ):
        raise ImageError(
            "cannot build service images from a dirty checkout; the image regenerates the "
            "cohort's descriptors and would not match the ones committed here"
        )
    head = _run(["git", "-C", str(root), "rev-parse", "HEAD"], capture=True).strip()
    if qualified_descriptor_overlay and revision != head:
        raise ImageError(
            f"qualified release descriptors publish {revision}, not exact checkout {head}"
        )
    ancestry = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=root,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        raise ImageError(
            f"the descriptors publish {revision}, which is not an ancestor of {head}; "
            "regenerate the descriptors before building images"
        )


def _tag(prefix: str, service: str, revision: str) -> str:
    return f"{prefix}/{service}:{revision[:8]}"


def build_service_image(
    root: Path,
    service: str,
    *,
    revision: str,
    platform: str,
    prefix: str,
    no_cache: bool = False,
    tag_suffix: str | None = None,
    labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build one service image and return the cohort values it was stamped with."""

    spec = SERVICES[service]
    suffix = tag_suffix or revision[:8]
    tag = f"{prefix}/{service}:{suffix}"
    release_tag = f"{prefix}/{service}-release:{suffix}"
    common = [
        "docker",
        "build",
        "--platform",
        platform,
        "--file",
        spec["dockerfile"],
        "--build-arg",
        f"APXM_SOURCE_REVISION={revision}",
    ]
    if no_cache:
        common.append("--no-cache")
    for key, value in sorted((labels or {}).items()):
        common.extend(["--label", f"{key}={value}"])

    _run([*common, "--target", "release", "--tag", release_tag, "."], cwd=root)
    descriptors = json.loads(
        _run(
            ["docker", "run", "--rm", "--platform", platform, release_tag,
             "cat", "/out/apxm-image-release.v1.json"],
            capture=True,
        )
    )
    if descriptors.get("source_revision") != revision:
        raise ImageError(
            f"the {service} release stage regenerated {descriptors.get('source_revision')}, not {revision}"
        )
    service_digest = next(
        item["digest"] for item in descriptors["services"] if item["name"] == service
    )
    manifest_digest = descriptors["release_manifest_digest"]
    frontend_digest = descriptors["frontend_native"]["digest"]

    arguments = [
        "--build-arg",
        f"APXM_RELEASE_MANIFEST_DIGEST={manifest_digest}",
        "--build-arg",
        f"{spec['digest_arg']}={service_digest}",
    ]
    if service == "compilation-service":
        arguments += ["--build-arg", f"APXM_PYTHON_FRONTEND_NATIVE_DIGEST={frontend_digest}"]
    _run([*common, *arguments, "--tag", tag, "."], cwd=root)
    return {
        "service": service,
        "tag": tag,
        "platform": platform,
        "source_revision": revision,
        "release_manifest_digest": manifest_digest,
        "service_digest": service_digest,
        "frontend_native_digest": frontend_digest,
        "owner_descriptor_digest": descriptors["owner_descriptor_digest"],
        "schema_count": descriptors["schema_count"],
    }


def build_images(
    root: Path,
    *,
    platform: str,
    prefix: str,
    services: tuple[str, ...],
    no_cache: bool = False,
    qualified_descriptor_overlay: bool = False,
) -> dict[str, Any]:
    revision = declared_revision(root)
    _require_publishable_checkout(
        root,
        revision,
        qualified_descriptor_overlay=qualified_descriptor_overlay,
    )
    return {
        "schema": "apxm.agents.service-images-build.v1",
        "semantic_owner": "agents",
        "source_revision": revision,
        "platform": platform,
        "images": [
            build_service_image(
                root, service, revision=revision, platform=platform, prefix=prefix, no_cache=no_cache
            )
            for service in services
        ],
    }


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _source_paths(root: Path) -> list[str]:
    paths = _run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        capture=True,
    ).split("\0")
    return sorted({name for name in paths if name and ((root / name).exists() or (root / name).is_symlink())})


def _tree_manifest(root: Path, paths: list[str] | None = None) -> list[dict[str, Any]]:
    if paths is None:
        paths = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if not path.is_dir() or path.is_symlink())
    manifest = []
    for name in paths:
        path = root / name
        mode = path.lstat().st_mode
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute() or not path.resolve().is_relative_to(root.resolve()):
                raise ImageError(f"candidate source symlink escapes its snapshot: {name}")
            manifest.append({"path": name, "kind": "symlink", "target": target})
        elif stat.S_ISREG(mode):
            manifest.append({"path": name, "kind": "file", "mode": stat.S_IMODE(mode), "digest": _digest_file(path)})
        else:
            raise ImageError(f"candidate source is not a regular file or internal symlink: {name}")
    return manifest


def _candidate_descriptors(snapshot: Path, revision: str) -> None:
    source = _load_json(snapshot / SOURCE_DESCRIPTOR_REL)
    source["source_revision"] = revision
    source_bytes = _canonical_json(source)
    (snapshot / SOURCE_DESCRIPTOR_REL).write_bytes(source_bytes)
    owner = _load_json(snapshot / OWNER_DESCRIPTOR_REL)
    owner["source_revision"] = revision
    owner["source_descriptor_digest"] = _digest_bytes(source_bytes)
    owner_bytes = _canonical_json(owner)
    (snapshot / OWNER_DESCRIPTOR_REL).write_bytes(owner_bytes)
    owner_digest = _digest_bytes(owner_bytes)
    (snapshot / OWNER_SIDECAR_REL).write_text(f"{owner_digest}  {OWNER_DESCRIPTOR_REL.as_posix()}\n", encoding="utf-8")
    manifest = _load_json(snapshot / RELEASE_MANIFEST_REL)
    manifest["source_revision"] = revision
    manifest["owner_descriptor_digest"] = owner_digest
    # An unpublished candidate binds its actual snapshot contracts, including
    # schema changes that have not entered a published release cohort.
    manifest["schemas"] = [
        {"name": name, "path": relative.as_posix(), "digest": _digest_file(snapshot / relative)}
        for name, relative in _discover_shipped_schemas(snapshot)
    ]
    (snapshot / RELEASE_MANIFEST_REL).write_bytes(_canonical_json(manifest))


def snapshot_candidate(root: Path) -> tuple[Path, dict[str, Any]]:
    """Freeze tracked and nonignored source; record both input and build trees."""
    revision = _run(["git", "-C", str(root), "rev-parse", "HEAD"], capture=True).strip()
    if not HEX40.fullmatch(revision):
        raise ImageError("candidate base HEAD must be a real full Git revision")
    status = _run(["git", "-C", str(root), "status", "--porcelain"], capture=True)
    paths = _source_paths(root)
    original = _tree_manifest(root, paths)
    parent = root / ".apxm" / "service-image-candidates"
    parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix=f"{revision[:8]}-", dir=parent))
    snapshot = output / "source"
    snapshot.mkdir()
    for name in paths:
        source, destination = root / name, snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            destination.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, destination)
    if (_tree_manifest(snapshot) != original or _tree_manifest(root, _source_paths(root)) != original
            or _run(["git", "-C", str(root), "rev-parse", "HEAD"], capture=True).strip() != revision):
        raise ImageError(f"source changed while freezing candidate; refusing snapshot {snapshot}")
    _candidate_descriptors(snapshot, revision)
    build_tree = _tree_manifest(snapshot)
    provenance = {
        "schema": "apxm.agents.candidate-source.v1",
        "semantic_owner": "agents",
        "base_revision": revision,
        "dirty": bool(status.strip()),
        "published": False,
        "source_selection": "tracked-and-nonignored-working-tree",
        "input_tree_digest": _digest_bytes(_canonical_json(original)),
        "source_tree_digest": _digest_bytes(_canonical_json(build_tree)),
        "input_files": original,
        "build_files": build_tree,
        "descriptor_revision_semantics": "base-git-revision; exact candidate source identified by source_tree_digest",
    }
    (output / "source-provenance.json").write_bytes(_canonical_json(provenance))
    return output, provenance


def build_candidate_images(root: Path, *, platform: str, prefix: str, services: tuple[str, ...], no_cache: bool = False) -> dict[str, Any]:
    output, provenance = snapshot_candidate(root)
    snapshot = output / "source"
    revision = provenance["base_revision"]
    tree_digest = provenance["source_tree_digest"]
    labels = {
        CANDIDATE_LABEL: "true", TREE_DIGEST_LABEL: tree_digest,
        PROVENANCE_DIGEST_LABEL: _digest_bytes(_canonical_json(provenance)),
        "io.apxm.source-dirty": str(provenance["dirty"]).lower(),
        "io.apxm.published": "false",
    }
    images = []
    for service in services:
        if _tree_manifest(snapshot) != provenance["build_files"]:
            raise ImageError("candidate snapshot changed before image build")
        images.append(build_service_image(snapshot, service, revision=revision, platform=platform,
            prefix=prefix, no_cache=no_cache, tag_suffix=f"candidate-{revision[:8]}-{tree_digest[7:19]}", labels=labels))
    if _tree_manifest(snapshot) != provenance["build_files"]:
        raise ImageError("candidate snapshot changed during image build")
    payload = {"schema": CANDIDATE_SCHEMA, "semantic_owner": "agents", "published": False,
        "source": provenance, "source_provenance_digest": labels[PROVENANCE_DIGEST_LABEL],
        "snapshot_path": str(snapshot), "platform": platform, "images": images,
        "receipt_path": str(output / "candidate.json")}
    (output / "candidate.json").write_bytes(_canonical_json(payload))
    return payload


def verify_candidate_images(root: Path, receipt: Path) -> dict[str, Any]:
    receipt = receipt.resolve()
    parent = (root / ".apxm" / "service-image-candidates").resolve()
    if not receipt.is_relative_to(parent):
        raise ImageError("candidate receipt must be inside the owner's .apxm/service-image-candidates")
    candidate = _load_json(receipt)
    if candidate.get("schema") != CANDIDATE_SCHEMA or candidate.get("published") is not False:
        raise ImageError("not an unpromoted candidate receipt")
    snapshot = receipt.parent / "source"
    provenance = _load_json(receipt.parent / "source-provenance.json")
    provenance_digest = _digest_bytes(_canonical_json(provenance))
    if (candidate.get("source") != provenance or candidate.get("source_provenance_digest") != provenance_digest
            or provenance.get("published") is not False or _tree_manifest(snapshot) != provenance.get("build_files")
            or _digest_bytes(_canonical_json(provenance["build_files"])) != provenance.get("source_tree_digest")):
        raise ImageError("candidate source provenance or frozen snapshot changed")
    images = []
    for image in candidate["images"]:
        tag, service = image["tag"], image["service"]
        labels = (_inspect(tag).get("Config") or {}).get("Labels") or {}
        expected = {CANDIDATE_LABEL: "true", TREE_DIGEST_LABEL: provenance["source_tree_digest"],
            PROVENANCE_DIGEST_LABEL: provenance_digest, "io.apxm.published": "false",
            "io.apxm.source-dirty": str(provenance["dirty"]).lower()}
        if any(labels.get(key) != value for key, value in expected.items()):
            raise ImageError(f"candidate provenance labels disagree for {tag}")
        result = verify_service_image(snapshot, service, tag, allow_candidate=True)
        pinned_fields = ("source_revision", "service_digest", "release_manifest_digest", "owner_descriptor_digest")
        if service == "compilation-service":
            pinned_fields += ("frontend_native_digest",)
        if any(result.get(key) != image.get(key) for key in pinned_fields):
            result["qualified"] = False
            result["diagnostics"].append({"code": "candidate-build-result-mismatch", "message": "image bytes differ from the recorded candidate build"})
        if result["platform"] != candidate["platform"]:
            result["qualified"] = False
            result["diagnostics"].append({"code": "candidate-platform-mismatch", "message": "image platform differs from candidate receipt"})
        images.append(result)
    return {"schema": "apxm.agents.service-images-verification.v1", "semantic_owner": "agents",
        "qualification_scope": "local-unpromoted-candidate", "published": False,
        "source_revision": provenance["base_revision"], "source_tree_digest": provenance["source_tree_digest"],
        "qualified": bool(images) and all(image["qualified"] for image in images), "images": images}


def _inspect(tag: str) -> dict[str, Any]:
    document = json.loads(_run(["docker", "image", "inspect", tag], capture=True))
    if not document:
        raise ImageError(f"no such image: {tag}")
    return document[0]


def _extract(tag: str, members: dict[str, Path]) -> None:
    """Copy files out of an image without running it."""

    container = _run(["docker", "create", tag], capture=True).strip()
    try:
        for member, destination in members.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            _run(["docker", "cp", f"{container}:{member}", str(destination)], capture=True)
    finally:
        _run(["docker", "rm", "--force", container], capture=True)


def verify_service_image(root: Path, service: str, tag: str, *, allow_candidate: bool = False) -> dict[str, Any]:
    """Verify one image's labels, manifest and bytes from the consumer side."""

    spec = SERVICES[service]
    diagnostics: list[dict[str, str]] = []

    def fail(code: str, message: str) -> None:
        diagnostics.append({"code": code, "message": message})

    inspected = _inspect(tag)
    labels = (inspected.get("Config") or {}).get("Labels") or {}
    if labels.get(CANDIDATE_LABEL) == "true" and not allow_candidate:
        raise ImageError("candidate images require explicit candidate-provenance verification")
    image_platform = f"{inspected.get('Os')}/{inspected.get('Architecture')}"

    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        _extract(
            tag,
            {
                f"/workspace/{RELEASE_MANIFEST_REL.as_posix()}": staging / "manifest.json",
                f"/workspace/{SOURCE_DESCRIPTOR_REL.as_posix()}": staging / "source.json",
                f"/workspace/{OWNER_DESCRIPTOR_REL.as_posix()}": staging / "owner.json",
                f"/workspace/{spec['executable']}": staging / "service",
                **(
                    {f"/workspace/{FRONTEND_NATIVE_REL}": staging / "native"}
                    if service == "compilation-service"
                    else {}
                ),
            },
        )
        manifest_bytes = (staging / "manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        manifest_digest = _digest_bytes(manifest_bytes)
        service_digest = _digest_file(staging / "service")
        native_digest = (
            _digest_file(staging / "native") if service == "compilation-service" else None
        )
        image_source_revision = (_load_json(staging / "source.json") or {}).get("source_revision")
        image_owner_digest = _digest_file(staging / "owner.json")

    checked_in_manifest = _load_json(root / RELEASE_MANIFEST_REL)
    checked_in_revision = declared_revision(root)
    checked_in_owner_digest = _digest_file(root / OWNER_DESCRIPTOR_REL)

    # 1. The labels say what the image carries.
    if labels.get(SERVICE_LABEL) != service:
        fail("service-label-mismatch", f"{SERVICE_LABEL}={labels.get(SERVICE_LABEL)!r}, expected {service!r}")
    if labels.get(RELEASE_MANIFEST_DIGEST_LABEL) != manifest_digest:
        fail(
            "release-manifest-digest-label-mismatch",
            f"{RELEASE_MANIFEST_DIGEST_LABEL} does not digest the manifest the image carries",
        )
    if labels.get(REVISION_LABEL) != image_source_revision:
        fail(
            "revision-label-mismatch",
            f"{REVISION_LABEL}={labels.get(REVISION_LABEL)!r} but the image's source descriptor says {image_source_revision!r}",
        )

    # 2. The manifest names the bytes the image actually runs.
    manifest_service = next(
        (item for item in manifest.get("services", []) if item.get("name") == service), None
    )
    if manifest_service is None:
        fail("manifest-missing-service", f"the image's release manifest publishes no {service!r} entry")
    else:
        if manifest_service.get("path") != spec["executable"]:
            fail(
                "manifest-service-path-mismatch",
                f"the manifest names {manifest_service.get('path')!r}, but the image runs {spec['executable']!r}",
            )
        if manifest_service.get("digest") != service_digest:
            fail(
                "service-digest-mismatch",
                "the executable in the image does not digest to the manifest's service digest",
            )
        if labels.get(SERVICE_DIGEST_LABEL) != service_digest:
            fail(
                "service-digest-label-mismatch",
                f"{SERVICE_DIGEST_LABEL}={labels.get(SERVICE_DIGEST_LABEL)!r} is not the digest of the executable in the image",
            )
    if native_digest is not None:
        if (manifest.get("frontend_native") or {}).get("digest") != native_digest:
            fail(
                "frontend-native-digest-mismatch",
                "the Python frontend bridge in the image does not digest to the manifest's entry",
            )
        if labels.get(FRONTEND_NATIVE_DIGEST_LABEL) != native_digest:
            fail(
                "frontend-native-digest-label-mismatch",
                f"{FRONTEND_NATIVE_DIGEST_LABEL} is not the digest of the bridge in the image",
            )

    # 3. The image is this cohort. Service bytes are host-specific, so the
    #    binding to the checked-in descriptors is the revision, the owner
    #    descriptor and the schema digests -- all of which are byte-identical
    #    wherever the cohort is built.
    if image_source_revision != checked_in_revision:
        fail(
            "cohort-revision-mismatch",
            f"the image publishes {image_source_revision!r}; this checkout publishes {checked_in_revision!r}",
        )
    if manifest.get("source_revision") != checked_in_revision:
        fail(
            "manifest-revision-mismatch",
            "the image's release manifest does not name the cohort's source revision",
        )
    if image_owner_digest != checked_in_owner_digest:
        fail(
            "owner-descriptor-mismatch",
            "the owner descriptor in the image is not the one this checkout publishes",
        )
    if manifest.get("owner_descriptor_digest") != checked_in_owner_digest:
        fail(
            "manifest-owner-descriptor-mismatch",
            "the image's release manifest does not bind this cohort's owner descriptor",
        )
    if manifest.get("schemas") != checked_in_manifest.get("schemas"):
        fail(
            "schema-digest-mismatch",
            "the image publishes different contract schema digests than this checkout",
        )

    return {
        "service": service,
        "tag": tag,
        "platform": image_platform,
        "image_id": inspected.get("Id"),
        "qualified": not diagnostics,
        "labels": {
            key: labels.get(key)
            for key in (
                REVISION_LABEL,
                SERVICE_LABEL,
                SERVICE_DIGEST_LABEL,
                RELEASE_MANIFEST_DIGEST_LABEL,
                FRONTEND_NATIVE_DIGEST_LABEL,
                "io.apxm.base-image",
                CANDIDATE_LABEL,
                TREE_DIGEST_LABEL,
                PROVENANCE_DIGEST_LABEL,
                "io.apxm.source-dirty",
                "io.apxm.published",
            )
            if labels.get(key) is not None
        },
        "source_revision": image_source_revision,
        "release_manifest_digest": manifest_digest,
        "service_digest": service_digest,
        "frontend_native_digest": native_digest,
        "owner_descriptor_digest": image_owner_digest,
        "schema_count": len(manifest.get("schemas") or []),
        "diagnostics": diagnostics,
    }


def verify_images(root: Path, *, prefix: str, services: tuple[str, ...]) -> dict[str, Any]:
    revision = declared_revision(root)
    images = [
        verify_service_image(root, service, _tag(prefix, service, revision))
        for service in services
    ]
    if set(SERVICES).issubset(services) and len({
        image["release_manifest_digest"] for image in images
    }) != 1:
        for image in images:
            image["qualified"] = False
            image["diagnostics"].append({
                "code": "image-pair-manifest-mismatch",
                "message": "Compilation and Runtime images must publish the same release manifest",
            })
    return {
        "schema": "apxm.agents.service-images-verification.v1",
        "semantic_owner": "agents",
        "qualification_scope": "consumer-image",
        "source_revision": revision,
        "qualified": all(image["qualified"] for image in images),
        "images": images,
    }


def export_images(root: Path, *, prefix: str, output: Path,
                  run_id: str, run_attempt: str, release_files: Path) -> dict[str, Any]:
    """Export a verified cohort as credential-free OCI publication inputs."""
    output = output.resolve()
    if not output.is_relative_to((root / ".apxm").resolve()):
        raise ImageError("image handoff must be under .apxm")
    if not all(re.fullmatch(r"[1-9][0-9]*", value) for value in (run_id, run_attempt)):
        raise ImageError("image handoff requires an explicit workflow run and attempt")
    if not release_files.is_dir() or release_files.is_symlink():
        raise ImageError("verified binary release files are required")
    evidence = verify_images(root, prefix=prefix, services=tuple(SERVICES))
    if not evidence["qualified"]:
        raise ImageError("unqualified images cannot be exported")
    package_manifests = list(release_files.rglob(LOCAL_ARTIFACT_MANIFEST_REL.name))
    if len(package_manifests) != 1:
        raise ImageError("one exact binary release package is required")
    binary_evidence = verify_package(package_manifests[0].parent)
    if not binary_evidence["qualified"] or binary_evidence["source_revision"] != evidence["source_revision"]:
        raise ImageError("binary release package is unqualified or belongs to a different revision")
    output.mkdir(parents=True, exist_ok=False)
    archives = {}
    release_tag = "apxm-" + evidence["source_revision"]
    for image in evidence["images"]:
        if _inspect(image["tag"]).get("Id") != image["image_id"]:
            raise ImageError("verified image changed before export")
        archive = output / (image["service"] + ".oci.tar")
        _run(["skopeo", "copy", "--all", "docker-daemon:" + image["tag"],
              "oci-archive:" + str(archive)], capture=True)
        if _inspect(image["tag"]).get("Id") != image["image_id"]:
            raise ImageError("verified image changed during export")
        digest = _run(["skopeo", "inspect", "--format", "{{.Digest}}",
                       "oci-archive:" + str(archive)], capture=True).strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ImageError("exported OCI manifest has no immutable digest")
        config = json.loads(_run(["skopeo", "inspect", "--config",
                                  "oci-archive:" + str(archive)], capture=True))
        if f"{config.get('os')}/{config.get('architecture')}" != image["platform"]:
            raise ImageError("exported OCI platform changed")
        labels = (config.get("config") or {}).get("Labels") or {}
        if any(labels.get(key) != value for key, value in image["labels"].items()):
            raise ImageError("exported OCI cohort labels changed")
        with archive.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        archives[image["service"]] = {"archive": archive.name,
                                     "destination": prefix + "/" + image["service"] + ":" + release_tag,
                                     "sha256": checksum, "digest": digest,
                                     "image_id": image["image_id"], "platform": image["platform"]}
    package = output / (release_tag + ".tar.gz")
    with tarfile.open(package, "w:gz") as bundle:
        for path in sorted(release_files.rglob("*")):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ImageError("release package contains an unsafe file")
            bundle.add(path, arcname=str(path.relative_to(release_files)), recursive=False)
    with package.open("rb") as stream:
        package_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    payload = {"schema": "apxm.agents.oci-handoff.v1",
               "source_revision": evidence["source_revision"],
               "run_id": int(run_id), "run_attempt": int(run_attempt), "release_tag": release_tag,
               "release_files": [{"path": package.name, "sha256": package_digest}],
               "images": archives, "verification": evidence, "binary_verification": binary_evidence}
    (output / "handoff.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="service_images.py")
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    build_parser = subparsers.add_parser("build", help="build both service images from the checkout")
    build_parser.add_argument("--platform", default=DEFAULT_PLATFORM)
    build_parser.add_argument("--repository-prefix", default=DEFAULT_REPOSITORY_PREFIX)
    build_parser.add_argument("--service", choices=tuple(SERVICES), action="append")
    build_parser.add_argument("--no-cache", action="store_true")
    build_parser.add_argument("--candidate", action="store_true", help="build an unpublished working-tree snapshot with exact source provenance")
    build_parser.add_argument(
        "--qualified-descriptor-overlay",
        action="store_true",
        help="allow only run-qualified descriptor files to differ from exact HEAD",
    )

    verify_parser = subparsers.add_parser("verify", help="verify both service images as a consumer")
    verify_parser.add_argument("--repository-prefix", default=DEFAULT_REPOSITORY_PREFIX)
    verify_parser.add_argument("--service", choices=tuple(SERVICES), action="append")
    verify_parser.add_argument("--candidate-provenance", type=Path, help="verify an unpublished candidate receipt and its frozen source snapshot")

    export_parser = subparsers.add_parser("export", help="export verified images for a separate trusted publisher")
    export_parser.add_argument("--repository-prefix", default=DEFAULT_REPOSITORY_PREFIX)
    export_parser.add_argument("--output-dir", type=Path, default=REPOSITORY_ROOT / ".apxm/oci-handoff")
    export_parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    export_parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    export_parser.add_argument("--release-files-dir", type=Path, default=REPOSITORY_ROOT / ".apxm/release-artifacts")

    args = parser.parse_args(argv)
    if shutil.which("docker") is None:
        print("docker is not on PATH; service images need a container runtime", file=sys.stderr)
        return 2
    services = tuple(getattr(args, "service", None) or SERVICES)
    root = args.root.resolve()
    started = time.monotonic()
    try:
        if args.mode == "export":
            payload = export_images(root, prefix=args.repository_prefix, output=args.output_dir,
                                    run_id=args.run_id, run_attempt=args.run_attempt,
                                    release_files=args.release_files_dir)
        elif args.mode == "build":
            builder = build_candidate_images if args.candidate else build_images
            build_args = {
                "platform": args.platform,
                "prefix": args.repository_prefix,
                "services": services,
                "no_cache": args.no_cache,
            }
            if not args.candidate:
                build_args["qualified_descriptor_overlay"] = args.qualified_descriptor_overlay
            payload = builder(root, **build_args)
        else:
            payload = (verify_candidate_images(root, args.candidate_provenance) if args.candidate_provenance
                else verify_images(root, prefix=args.repository_prefix, services=services))
    except (ImageError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"service images {args.mode} failed: {exc}", file=sys.stderr)
        return 1
    payload["duration_seconds"] = round(time.monotonic() - started, 1)
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.mode == "verify" and not payload["qualified"]:
        for image in payload["images"]:
            for diagnostic in image["diagnostics"]:
                print(f"[{diagnostic['code']}] {image['tag']}: {diagnostic['message']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
