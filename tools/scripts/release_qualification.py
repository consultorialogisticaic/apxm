"""Qualify an immutable APXM owner release.

The gate is deliberately owner-local.  It runs the declared Compilation and
Runtime protocol suites, validates the product-neutral release descriptors,
and compares every available digest with the exact bytes it names.  A source
checkout is not a publishable runtime release merely because it builds.

The ``generate`` mode writes descriptors only when the caller supplies a real
artifact.  It computes digests from bytes; it never creates placeholder or
sentinel identities.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

SOURCE_DESCRIPTOR_REL = Path("deploy/services/source-revision.v1.json")
OWNER_DESCRIPTOR_REL = Path("contracts/descriptors/apxm.agents-owner-descriptor.v1.json")
OWNER_DESCRIPTOR_SIDECAR_REL = Path(
    "contracts/descriptors/apxm.agents-owner-descriptor.v1.sha256"
)
RELEASE_MANIFEST_REL = Path(
    "contracts/services/manifests/apxm.agents-service-release-manifest.v1.json"
)
RELEASE_DESCRIPTOR_RELS = (
    SOURCE_DESCRIPTOR_REL,
    OWNER_DESCRIPTOR_REL,
    OWNER_DESCRIPTOR_SIDECAR_REL,
    RELEASE_MANIFEST_REL,
)
PYTHON_FRONTEND_PACKAGE_REL = Path(
    "crates/compiler/frontend/python/apxm_program/_native.so"
)
PROTOCOL_DESCRIPTORS = (
    ("compilation-protocol", Path("crates/compiler/service-protocol/src/lib.rs")),
    ("runtime-protocol", Path("crates/runtime/service-protocol/src/lib.rs")),
)
SCHEMA_DIRECTORY_REL = Path("contracts/schemas")
SCHEMA_SUFFIX = ".json"
LOCAL_ARTIFACT_SCHEMA = "apxm.agents.local-release-artifact.v1"
LOCAL_ARTIFACT_MANIFEST_REL = Path("apxm.agents-local-release-artifact.v1.json")
CONSUMER_VERIFICATION_SCHEMA = "apxm.agents.release-consumer-verification.v1"


def default_release_package_dir(root: Path, source_revision: str) -> Path:
    """Return the write-once package location for one source cohort.

    ``current`` is intentionally not a mutable promotion slot: an existing
    package there may be the evidence for an older cohort.  New releases are
    therefore materialized under a source-derived cohort directory.  The
    short directory name is only a filesystem label; the package manifest
    still binds the complete revision and rejects a prefix collision.
    """

    if not HEX40.fullmatch(source_revision):
        raise ValueError("cannot derive a release package path without a full lowercase source revision")
    return root / ".apxm" / "release-artifacts" / f"cohort-{source_revision[:8]}"


def declared_release_package_dir(root: Path) -> Path:
    """Return the cohort directory the checked-in source descriptor selects.

    Consumer verification used to default to ``.apxm/release-artifacts/current``,
    which the packager never writes: it materializes every cohort under its own
    source-derived directory, so that default addressed whichever superseded
    package happened to be left behind and reported its stale schema as a
    consumer failure.  Resolve the source revision this checkout declares
    instead, so the default verifies the cohort the descriptors name.
    """

    descriptor = _load_json(root, root / SOURCE_DESCRIPTOR_REL, [], "source descriptor")
    revision = descriptor.get("source_revision") if isinstance(descriptor, dict) else None
    if not isinstance(revision, str):
        raise ValueError(
            f"cannot select a release package without a source descriptor at {SOURCE_DESCRIPTOR_REL}"
        )
    return default_release_package_dir(root, revision)


SOURCE_DESCRIPTOR_SCHEMA = "apxm.agents-source-revision.v1"
OWNER_DESCRIPTOR_SCHEMA = "apxm.agents-owner-descriptor.v1"
RELEASE_MANIFEST_SCHEMA = "apxm.agents-service-release-manifest.v1"
COMPILATION_PROTOCOL_VERSION = "apxm.compilation.protocol/2"
RUNTIME_PROTOCOL_VERSION = "apxm.runtime.protocol/1"
ARTIFACT_KIND = "compilation-runtime-services"

SERVICE_ARTIFACTS = (
    ("compilation-service", "apxm-compilation-service"),
    ("runtime-service", "apxm-runtime-service"),
)
FRONTEND_NATIVE_ARTIFACT = ("python-frontend-native", "lib_native.so")

HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_RELATIVE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$)).+$")

PROTOCOL_GATES = (
    "test-compilation-protocol",
    "test-compilation-service",
    "test-runtime-protocol",
    "test-runtime-service",
)
OWNER_GATES = ("check", "test", *PROTOCOL_GATES)


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    remediation: str

    def render(self) -> str:
        return f"[{self.code}] {self.message} Remediation: {self.remediation}"


@dataclass
class Qualification:
    diagnostics: list[Diagnostic] = field(default_factory=list)
    gates: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, Path] = field(default_factory=dict)
    artifact_digests: dict[str, str] = field(default_factory=dict)
    protocol_descriptors: dict[str, dict[str, str]] = field(default_factory=dict)
    schema_digests: dict[str, str] = field(default_factory=dict)
    schema_paths: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.diagnostics


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _digest_file(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _load_json(
    root: Path, path: Path, diagnostics: list[Diagnostic], label: str
) -> dict[str, Any] | None:
    resolved = _resolve_regular_file(root, path)
    if resolved is None:
        if path.is_symlink() or path.exists():
            diagnostics.append(
                Diagnostic(
                    "non-regular-descriptor",
                    f"{label} is not a regular file inside the owner checkout: {path}",
                    "publish the exact descriptor bytes in the owner checkout; symlinks and external files are rejected",
                )
            )
        else:
            diagnostics.append(
                Diagnostic(
                    "missing-descriptor",
                    f"{label} is missing: {path}",
                    "publish the owner descriptor/manifest generated from the selected source revision",
                )
            )
        return None
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        diagnostics.append(
            Diagnostic(
                "invalid-json",
                f"{label} cannot be read as UTF-8 JSON ({exc})",
                "regenerate the descriptor from the owner checkout and commit the exact bytes",
            )
        )
        return None
    if not isinstance(value, dict):
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                f"{label} root must be a JSON object",
                "regenerate the descriptor with the release-descriptor tooling",
            )
        )
        return None
    return value


def _require_exact_shape(
    value: Mapping[str, Any],
    *,
    label: str,
    required: Iterable[str],
    optional: Iterable[str],
    diagnostics: list[Diagnostic],
) -> bool:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(key for key in required_set if key not in value)
    unknown = sorted(key for key in value if key not in allowed)
    valid = True
    if missing:
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                f"{label} is missing required field(s): {', '.join(missing)}",
                "regenerate the descriptor; unknown and omitted release identity fields are rejected",
            )
        )
        valid = False
    if unknown:
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                f"{label} contains unknown field(s): {', '.join(unknown)}",
                "remove fields outside the product-neutral owner release schema",
            )
        )
        valid = False
    return valid


def _require_string(
    value: Mapping[str, Any],
    key: str,
    *,
    label: str,
    diagnostics: list[Diagnostic],
    pattern: re.Pattern[str] | None = None,
    expected: str | None = None,
) -> bool:
    raw = value.get(key)
    valid = isinstance(raw, str) and bool(raw.strip())
    if valid and pattern is not None:
        valid = bool(pattern.fullmatch(raw))
    if valid and expected is not None:
        valid = raw == expected
    if not valid:
        expectation = f" equal {expected!r}" if expected is not None else " match the declared schema"
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                f"{label}.{key} is invalid; it must be a non-empty string{expectation}",
                "regenerate the descriptor with the owner release tooling",
            )
        )
    return valid


def _git_text(root: Path, *args: str) -> str | None:
    git_env = os.environ.copy()
    if sys.platform == "darwin":
        # Dekk's conda environment ships libiconv, while Homebrew's git links
        # against its own ABI. Keep the Dekk environment for Python and Rust,
        # but do not let it interpose on the Git subprocess used for identity.
        git_env.pop("DYLD_LIBRARY_PATH", None)
        git_env.pop("DYLD_FALLBACK_LIBRARY_PATH", None)
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        env=git_env,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _git_bytes(root: Path, *args: str) -> bytes | None:
    git_env = os.environ.copy()
    if sys.platform == "darwin":
        git_env.pop("DYLD_LIBRARY_PATH", None)
        git_env.pop("DYLD_FALLBACK_LIBRARY_PATH", None)
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        env=git_env,
    )
    return completed.stdout if completed.returncode == 0 else None


def _git_revision(root: Path) -> str | None:
    revision = _git_text(root, "rev-parse", "HEAD")
    return revision if revision and HEX40.fullmatch(revision) else None


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    git_env = os.environ.copy()
    if sys.platform == "darwin":
        git_env.pop("DYLD_LIBRARY_PATH", None)
        git_env.pop("DYLD_FALLBACK_LIBRARY_PATH", None)
    completed = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        capture_output=True,
        env=git_env,
    )
    return completed.returncode == 0


def _is_clean(root: Path) -> bool:
    return _git_text(root, "status", "--porcelain", "--untracked-files=all") == ""


def _is_qualified_descriptor_overlay(root: Path) -> bool:
    """Accept only descriptors generated from exact HEAD artifacts in this run."""

    raw_status = _git_bytes(root, "status", "--porcelain", "--untracked-files=all")
    status_lines = {
        line for line in (raw_status or b"").decode("utf-8").splitlines() if line
    }
    allowed = {f" M {relative.as_posix()}" for relative in RELEASE_DESCRIPTOR_RELS}
    if not status_lines or not status_lines <= allowed:
        return False
    try:
        source = json.loads((root / SOURCE_DESCRIPTOR_REL).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return source.get("source_revision") == _git_revision(root)


def _resolve_regular_file(root: Path, candidate: Path) -> Path | None:
    """Resolve a release input only when it stays inside the owner checkout."""

    if candidate.is_symlink() or not candidate.is_file():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return resolved


def _rooted_path(root: Path, raw: str | Path) -> Path:
    candidate = Path(raw).expanduser()
    return candidate if candidate.is_absolute() else root / candidate


def _discover_shipped_schemas(root: Path) -> list[tuple[str, Path]]:
    """Enumerate every shipped contract schema under the owner checkout.

    A consumer pins schemas the same way it pins service bytes, so the
    published set is the directory itself rather than a hand-kept list that
    silently drops a schema the moment one is added.  The schema name is the
    document identity (`apxm.host-capability.v1`), not a file label.
    """

    directory = root / SCHEMA_DIRECTORY_REL
    if directory.is_symlink() or not directory.is_dir():
        return []
    discovered: list[tuple[str, Path]] = []
    for candidate in sorted(directory.iterdir(), key=lambda item: item.name):
        if candidate.suffix != SCHEMA_SUFFIX:
            continue
        if _resolve_regular_file(root, candidate) is None:
            continue
        discovered.append((candidate.stem, SCHEMA_DIRECTORY_REL / candidate.name))
    return discovered


def _validate_source_descriptor(
    root: Path, value: Mapping[str, Any] | None, diagnostics: list[Diagnostic]
) -> str | None:
    if value is None:
        return None
    valid = _require_exact_shape(
        value,
        label="source descriptor",
        required=("schema_version", "semantic_owner", "selection", "source_revision"),
        optional=(),
        diagnostics=diagnostics,
    )
    valid &= _require_string(
        value,
        "schema_version",
        label="source descriptor",
        diagnostics=diagnostics,
        expected=SOURCE_DESCRIPTOR_SCHEMA,
    )
    valid &= _require_string(
        value,
        "semantic_owner",
        label="source descriptor",
        diagnostics=diagnostics,
        expected="agents",
    )
    valid &= _require_string(
        value,
        "selection",
        label="source descriptor",
        diagnostics=diagnostics,
        expected="immutable-source-cohort",
    )
    valid &= _require_string(
        value,
        "source_revision",
        label="source descriptor",
        diagnostics=diagnostics,
        pattern=HEX40,
    )
    revision = value.get("source_revision") if valid else None
    if valid and _git_text(root, "rev-parse", f"{revision}^{{commit}}") != revision:
        diagnostics.append(
            Diagnostic(
                "unresolvable-source",
                f"source descriptor names revision {revision}, which is not present in the owner checkout",
                "fetch or publish the exact source cohort before generating a release",
            )
        )
        return None
    if valid and not _git_is_ancestor(root, revision or "", "HEAD"):
        diagnostics.append(
            Diagnostic(
                "source-not-ancestor",
                f"source descriptor revision {revision} is not an ancestor of the checkout HEAD",
                "publish from a checkout carrying the declared immutable source cohort",
            )
        )
    return revision if valid else None


def _validate_owner_descriptor(
    value: Mapping[str, Any] | None,
    *,
    source_revision: str | None,
    source_descriptor_digest: str | None,
    diagnostics: list[Diagnostic],
) -> None:
    if value is None:
        return
    valid = _require_exact_shape(
        value,
        label="owner descriptor",
        required=(
            "schema_version",
            "semantic_owner",
            "source_revision",
            "source_descriptor_digest",
            "artifact_kind",
            "compilation_protocol",
            "runtime_protocol",
        ),
        optional=(),
        diagnostics=diagnostics,
    )
    valid &= _require_string(
        value, "schema_version", label="owner descriptor", diagnostics=diagnostics, expected=OWNER_DESCRIPTOR_SCHEMA
    )
    valid &= _require_string(
        value, "semantic_owner", label="owner descriptor", diagnostics=diagnostics, expected="agents"
    )
    valid &= _require_string(
        value, "source_revision", label="owner descriptor", diagnostics=diagnostics, pattern=HEX40
    )
    valid &= _require_string(
        value,
        "source_descriptor_digest",
        label="owner descriptor",
        diagnostics=diagnostics,
        pattern=DIGEST,
    )
    valid &= _require_string(
        value, "artifact_kind", label="owner descriptor", diagnostics=diagnostics, expected=ARTIFACT_KIND
    )
    valid &= _require_string(
        value,
        "compilation_protocol",
        label="owner descriptor",
        diagnostics=diagnostics,
        expected=COMPILATION_PROTOCOL_VERSION,
    )
    valid &= _require_string(
        value,
        "runtime_protocol",
        label="owner descriptor",
        diagnostics=diagnostics,
        expected=RUNTIME_PROTOCOL_VERSION,
    )
    if valid and source_revision != value.get("source_revision"):
        diagnostics.append(
            Diagnostic(
                "source-digest-drift",
                "owner descriptor source_revision does not match the source descriptor",
                "regenerate both descriptors from one immutable source cohort",
            )
        )
    if valid and source_descriptor_digest != value.get("source_descriptor_digest"):
        diagnostics.append(
            Diagnostic(
                "source-digest-drift",
                "owner descriptor source_descriptor_digest does not match the exact source descriptor bytes",
                "regenerate the owner descriptor; do not hand-edit digest fields",
            )
        )


def _validate_protocol_descriptors(
    root: Path, source_revision: str | None, result: Qualification
) -> None:
    """Bind protocol implementation descriptors to the selected source cohort."""

    if source_revision is None:
        return
    for name, relative in PROTOCOL_DESCRIPTORS:
        current = _resolve_regular_file(root, root / relative)
        source_bytes = _git_bytes(root, "show", f"{source_revision}:{relative.as_posix()}")
        if current is None:
            result.diagnostics.append(
                Diagnostic(
                    "missing-protocol-descriptor",
                    f"{name} protocol descriptor is not a regular file: {relative}",
                    "publish the exact Compilation/Runtime protocol source descriptor in the owner checkout",
                )
            )
            continue
        if source_bytes is None:
            result.diagnostics.append(
                Diagnostic(
                    "unresolvable-protocol-descriptor",
                    f"{name} protocol descriptor is not present at source revision {source_revision}: {relative}",
                    "fetch the complete immutable source cohort before qualifying the release",
                )
            )
            continue
        current_digest = _digest_file(current)
        source_digest = _digest_bytes(source_bytes)
        if current.read_bytes() != source_bytes:
            result.diagnostics.append(
                Diagnostic(
                    "protocol-descriptor-drift",
                    f"{name} protocol descriptor bytes differ from source revision {source_revision}",
                    "qualify the service binaries and protocol descriptors from one immutable source cohort",
                )
            )
            continue
        if current_digest != source_digest:
            result.diagnostics.append(
                Diagnostic(
                    "protocol-descriptor-digest-mismatch",
                    f"{name} protocol descriptor digest does not match its source revision",
                    "regenerate the local release artifact from the exact source revision",
                )
            )
            continue
        result.protocol_descriptors[name] = {
            "path": relative.as_posix(),
            "digest": current_digest,
        }


def _validate_manifest_schemas(
    root: Path,
    declared: Any,
    *,
    schema_digests: Mapping[str, str],
    schema_paths: Mapping[str, str],
    diagnostics: list[Diagnostic],
) -> None:
    """Bind every published schema entry to the exact bytes it names.

    Service digests let a consumer pin executables; schema digests let the
    same consumer pin the wire contracts those executables speak.  A mutated,
    added, or removed schema is a different release, so it fails here rather
    than being discovered by whatever spoke the changed contract first.
    """

    if not isinstance(declared, list):
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                "release manifest.schemas must be an array",
                "regenerate the manifest with one entry for every shipped contract schema",
            )
        )
        return
    seen_names: set[str] = set()
    for index, entry in enumerate(declared):
        label = f"release manifest.schemas[{index}]"
        if not isinstance(entry, dict):
            diagnostics.append(
                Diagnostic(
                    "invalid-schema",
                    f"{label} must be an object",
                    "regenerate the manifest with named schema entries",
                )
            )
            continue
        entry_valid = _require_exact_shape(
            entry,
            label=label,
            required=("name", "path", "digest"),
            optional=(),
            diagnostics=diagnostics,
        )
        entry_valid &= _require_string(entry, "name", label=label, diagnostics=diagnostics)
        entry_valid &= _require_string(
            entry, "path", label=label, diagnostics=diagnostics, pattern=SAFE_RELATIVE_PATH
        )
        entry_valid &= _require_string(
            entry, "digest", label=label, diagnostics=diagnostics, pattern=DIGEST
        )
        if not entry_valid:
            continue
        name = str(entry["name"])
        if name in seen_names:
            diagnostics.append(
                Diagnostic(
                    "duplicate-published-schema",
                    f"release manifest contains duplicate schema {name!r}",
                    "publish one immutable entry for each shipped schema",
                )
            )
            continue
        seen_names.add(name)
        expected_path = schema_paths.get(name)
        if expected_path is not None and str(entry["path"]) != expected_path:
            diagnostics.append(
                Diagnostic(
                    "schema-path-mismatch",
                    f"release manifest schema {name!r} names {entry['path']}, but the shipped schema is {expected_path}",
                    "publish every schema at its exact repository path",
                )
            )
            continue
        declared_file = _resolve_regular_file(root, root / str(entry["path"]))
        if declared_file is None:
            diagnostics.append(
                Diagnostic(
                    "missing-published-schema",
                    f"release manifest schema {name!r} does not name a regular file inside the owner checkout: {entry['path']}",
                    "publish the exact schema document at the manifest path",
                )
            )
            continue
        if _digest_file(declared_file) != str(entry["digest"]):
            diagnostics.append(
                Diagnostic(
                    "schema-digest-mismatch",
                    f"release manifest digest for schema {name!r} does not match the published schema bytes",
                    "publish the exact schema bytes named by the manifest or regenerate the manifest",
                )
            )
    if not schema_digests:
        if not seen_names:
            diagnostics.append(
                Diagnostic(
                    "missing-published-schema",
                    "release manifest publishes no schemas",
                    "publish one entry for every shipped contract schema so a consumer can pin them",
                )
            )
        return
    missing = sorted(set(schema_digests) - seen_names)
    if missing:
        diagnostics.append(
            Diagnostic(
                "missing-published-schema",
                f"release manifest does not publish shipped schema(s): {', '.join(missing)}",
                "regenerate the release manifest so it lists every shipped schema",
            )
        )
    unknown = sorted(seen_names - set(schema_digests))
    if unknown:
        diagnostics.append(
            Diagnostic(
                "unknown-published-schema",
                f"release manifest publishes schema(s) that are not shipped: {', '.join(unknown)}",
                "publish only the schemas this source cohort ships",
            )
        )


def _validate_release_manifest(
    root: Path,
    value: Mapping[str, Any] | None,
    *,
    source_revision: str | None,
    owner_descriptor_digest: str | None,
    artifacts: Mapping[str, Path],
    artifact_digests: Mapping[str, str],
    schema_digests: Mapping[str, str],
    schema_paths: Mapping[str, str],
    diagnostics: list[Diagnostic],
) -> None:
    if value is None:
        return
    valid = _require_exact_shape(
        value,
        label="release manifest",
        required=(
            "schema_version",
            "semantic_owner",
            "source_revision",
            "artifact_kind",
            "services",
            "schemas",
            "frontend_native",
            "owner_descriptor_digest",
            "integrity_algorithm",
        ),
        optional=(),
        diagnostics=diagnostics,
    )
    valid &= _require_string(
        value, "schema_version", label="release manifest", diagnostics=diagnostics, expected=RELEASE_MANIFEST_SCHEMA
    )
    valid &= _require_string(
        value, "semantic_owner", label="release manifest", diagnostics=diagnostics, expected="agents"
    )
    valid &= _require_string(
        value, "source_revision", label="release manifest", diagnostics=diagnostics, pattern=HEX40
    )
    valid &= _require_string(
        value, "artifact_kind", label="release manifest", diagnostics=diagnostics, expected=ARTIFACT_KIND
    )
    valid &= _require_string(
        value, "integrity_algorithm", label="release manifest", diagnostics=diagnostics, expected="sha256"
    )
    valid &= _require_string(
        value,
        "owner_descriptor_digest",
        label="release manifest",
        diagnostics=diagnostics,
        pattern=DIGEST,
    )
    if valid and owner_descriptor_digest != value.get("owner_descriptor_digest"):
        diagnostics.append(
            Diagnostic(
                "descriptor-digest-drift",
                "release manifest owner_descriptor_digest does not match the owner descriptor bytes",
                "regenerate the release manifest from the exact descriptor cohort",
            )
        )
    if valid and source_revision != value.get("source_revision"):
        diagnostics.append(
            Diagnostic(
                "source-digest-drift",
                "release manifest source_revision does not match the source descriptor",
                "regenerate the release manifest from one immutable source cohort",
            )
        )
    _validate_manifest_schemas(
        root,
        value.get("schemas"),
        schema_digests=schema_digests,
        schema_paths=schema_paths,
        diagnostics=diagnostics,
    )
    services = value.get("services")
    if not isinstance(services, list):
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                "release manifest.services must be an array",
                "regenerate the manifest with exactly one compilation-service and one runtime-service entry",
            )
        )
        return
    expected_names = {name for name, _ in SERVICE_ARTIFACTS}
    seen_names: set[str] = set()
    for index, service in enumerate(services):
        label = f"release manifest.services[{index}]"
        if not isinstance(service, dict):
            diagnostics.append(
                Diagnostic(
                    "invalid-schema",
                    f"{label} must be an object",
                    "regenerate the manifest with named service artifact entries",
                )
            )
            continue
        entry_valid = _require_exact_shape(
            service,
            label=label,
            required=("name", "path", "digest"),
            optional=(),
            diagnostics=diagnostics,
        )
        entry_valid &= _require_string(
            service, "name", label=label, diagnostics=diagnostics
        )
        entry_valid &= _require_string(
            service, "path", label=label, diagnostics=diagnostics, pattern=SAFE_RELATIVE_PATH
        )
        entry_valid &= _require_string(
            service, "digest", label=label, diagnostics=diagnostics, pattern=DIGEST
        )
        name = service.get("name")
        if isinstance(name, str):
            if name not in expected_names:
                diagnostics.append(
                    Diagnostic(
                        "invalid-schema",
                        f"{label}.name {name!r} is not an APXM service owner artifact",
                        "publish exactly apxm-compilation-service and apxm-runtime-service",
                    )
                )
            elif name in seen_names:
                diagnostics.append(
                    Diagnostic(
                        "invalid-schema",
                        f"release manifest contains duplicate service {name!r}",
                        "publish one immutable entry for each APXM service",
                    )
                )
            seen_names.add(name)
        if not entry_valid or not isinstance(name, str) or name not in expected_names:
            continue
        declared_path = _resolve_regular_file(root, root / str(service["path"]))
        selected = artifacts.get(name)
        if declared_path is None:
            diagnostics.append(
                Diagnostic(
                    "missing-publishable-service-artifact",
                    f"release manifest service {name!r} does not name a regular file inside the owner checkout: {service['path']}",
                    "publish the exact APXM service executable at the manifest path",
                )
            )
        elif selected is not None and declared_path != selected:
            diagnostics.append(
                Diagnostic(
                    "service-artifact-path-mismatch",
                    f"release manifest service {name!r} resolves to {declared_path}, but qualification selected {selected}",
                    "qualify the exact service file named by the release manifest",
                )
            )
        if name in artifact_digests and service.get("digest") != artifact_digests[name]:
            diagnostics.append(
                Diagnostic(
                    "service-artifact-digest-mismatch",
                    f"release manifest digest for {name!r} does not match the selected service bytes",
                    "publish the exact service bytes named by the manifest or regenerate the manifest",
                )
            )
    frontend = value.get("frontend_native")
    if not isinstance(frontend, dict):
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                "release manifest.frontend_native must be an object",
                "regenerate the manifest with the exact Python frontend native bridge entry",
            )
        )
    else:
        entry_valid = _require_exact_shape(
            frontend,
            label="release manifest.frontend_native",
            required=("name", "path", "digest"),
            optional=(),
            diagnostics=diagnostics,
        )
        entry_valid &= _require_string(
            frontend, "name", label="release manifest.frontend_native", diagnostics=diagnostics
        )
        entry_valid &= _require_string(
            frontend,
            "path",
            label="release manifest.frontend_native",
            diagnostics=diagnostics,
            pattern=SAFE_RELATIVE_PATH,
        )
        entry_valid &= _require_string(
            frontend,
            "digest",
            label="release manifest.frontend_native",
            diagnostics=diagnostics,
            pattern=DIGEST,
        )
        if entry_valid and frontend.get("name") != FRONTEND_NATIVE_ARTIFACT[0]:
            diagnostics.append(
                Diagnostic(
                    "invalid-schema",
                    "release manifest.frontend_native.name is not the Python frontend native bridge",
                    "publish exactly one python-frontend-native bridge entry",
                )
            )
        selected = artifacts.get(FRONTEND_NATIVE_ARTIFACT[0])
        declared_path = _resolve_regular_file(root, root / str(frontend.get("path", "")))
        if declared_path is None:
            diagnostics.append(
                Diagnostic(
                    "missing-publishable-frontend-native",
                    "release manifest frontend_native does not name a regular file inside the owner checkout",
                    "publish the exact Python frontend native bridge at the manifest path",
                )
            )
        elif selected is not None and declared_path != selected:
            diagnostics.append(
                Diagnostic(
                    "frontend-native-path-mismatch",
                    "release manifest frontend_native path does not select the qualified bridge",
                    "qualify the exact native bridge named by the release manifest",
                )
            )
        if FRONTEND_NATIVE_ARTIFACT[0] in artifact_digests and frontend.get("digest") != artifact_digests[FRONTEND_NATIVE_ARTIFACT[0]]:
            diagnostics.append(
                Diagnostic(
                    "frontend-native-digest-mismatch",
                    "release manifest frontend_native digest does not match the selected bridge bytes",
                    "publish the exact native bridge bytes named by the manifest or regenerate the manifest",
                )
            )
    missing_names = sorted(expected_names - seen_names)
    if missing_names:
        diagnostics.append(
            Diagnostic(
                "invalid-schema",
                f"release manifest is missing service artifact(s): {', '.join(missing_names)}",
                "publish exactly one immutable entry for each APXM service",
            )
        )


def _sidecar_digest(path: Path) -> str | None:
    try:
        line = path.read_text(encoding="utf-8").splitlines()[0].strip()
    except (OSError, UnicodeDecodeError, IndexError):
        return None
    token = line.split()[0] if line else ""
    if DIGEST.fullmatch(token):
        return token
    if re.fullmatch(r"[0-9a-f]{64}", token):
        return f"sha256:{token}"
    return None


def _classify_gate_failure(returncode: int, output: str) -> str:
    """Separate infrastructure/toolchain failures from owner code failures."""

    lowered = output.casefold()
    abi_markers = (
        "e0514",
        ".rmeta",
        "rustc metadata",
        "metadata version",
        "wrong architecture",
        "undefined symbol",
        "symbol not found",
        "incompatible architecture",
        "bad cpu type",
        "elfclass",
    )
    if any(marker in lowered for marker in abi_markers):
        return "abi"
    resource_markers = (
        "no space left on device",
        "out of memory",
        "cannot allocate memory",
        "resource temporarily unavailable",
        "killed",
        "sigkill",
        "sigbus",
    )
    if returncode in {137, 143} or any(marker in lowered for marker in resource_markers):
        return "resource"
    return "code"


def _find_artifacts(
    root: Path,
    explicit: Mapping[str, str | None],
    manifest: Mapping[str, Any] | None,
) -> dict[str, Path]:
    found: dict[str, Path] = {}
    manifest_services = manifest.get("services") if manifest else None
    manifest_paths = {
        item.get("name"): item.get("path")
        for item in manifest_services
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    } if isinstance(manifest_services, list) else {}
    for name, binary in SERVICE_ARTIFACTS:
        candidates: list[Path] = []
        if explicit.get(name):
            candidates.append(_rooted_path(root, explicit[name] or ""))
        env_name = (
            "APXM_COMPILATION_SERVICE_BINARY"
            if name == "compilation-service"
            else "APXM_RUNTIME_SERVICE_BINARY"
        )
        env_value = os.environ.get(env_name, "").strip()
        if env_value:
            candidates.append(_rooted_path(root, env_value))
        manifest_path = manifest_paths.get(name)
        if isinstance(manifest_path, str):
            candidates.append(root / manifest_path)
        candidates.append(root / "target" / "release" / binary)
        candidates.append(root / "deploy" / "services" / binary)
        for candidate in candidates:
            resolved = _resolve_regular_file(root, candidate)
            if resolved is not None:
                found[name] = resolved
                break
    return found


def _find_frontend_native(root: Path, explicit: str | None = None) -> Path | None:
    """Find the exact Python native bridge for the compilation image."""

    candidates: list[Path] = []
    if explicit:
        candidates.append(_rooted_path(root, explicit))
    candidates.extend(
        (
            root / "target" / "release" / FRONTEND_NATIVE_ARTIFACT[1],
            root / "crates" / "compiler" / "frontend" / "python" / "apxm_program" / "_native.so",
        )
    )
    for candidate in candidates:
        resolved = _resolve_regular_file(root, candidate)
        if resolved is not None:
            return resolved
    return None


@dataclass(frozen=True)
class _FrontendNativeSnapshot:
    """The manifest-selected bridge bytes captured before owner gates run."""

    path: Path
    payload: bytes | None
    mode: int | None
    symlink_target: str | None = None
    invalid: bool = False

    def restore(self) -> None:
        """Restore the cohort bytes after gates may have rebuilt the bridge."""

        if self.symlink_target is not None:
            if self.path.exists() or self.path.is_symlink():
                self.path.unlink()
            self.path.symlink_to(self.symlink_target)
            return
        # A gate must not be able to turn a regular published artifact into a
        # symlink and have qualification silently follow it. Leave that shape
        # for the normal manifest validator to reject.
        if self.path.is_symlink():
            return
        if self.payload is None:
            if self.path.exists() and self.path.is_file():
                self.path.unlink()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.qualification-{os.getpid()}.tmp"
        )
        try:
            temporary.write_bytes(self.payload)
            os.chmod(temporary, self.mode)
            os.replace(temporary, self.path)
        finally:
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()


def _snapshot_manifest_frontend_native(root: Path) -> _FrontendNativeSnapshot | None:
    """Capture the checked-in manifest bridge before mutating owner gates run."""

    manifest = _load_json(root, root / RELEASE_MANIFEST_REL, [], "release manifest")
    if not isinstance(manifest, dict):
        return None
    frontend = manifest.get("frontend_native")
    if not isinstance(frontend, dict) or not isinstance(frontend.get("path"), str):
        return None
    relative = frontend["path"]
    if not SAFE_RELATIVE_PATH.fullmatch(relative):
        return None
    candidate = root / relative
    if candidate == root:
        return None
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    parent = candidate.parent
    while parent != root:
        if parent.is_symlink():
            return _FrontendNativeSnapshot(candidate, None, None, invalid=True)
        parent = parent.parent
    if candidate.is_symlink():
        try:
            return _FrontendNativeSnapshot(
                candidate, None, None, os.readlink(candidate), invalid=True
            )
        except OSError:
            return _FrontendNativeSnapshot(candidate, None, None, invalid=True)
    path = _resolve_regular_file(root, candidate)
    if path is None:
        if candidate.exists():
            return None
        return _FrontendNativeSnapshot(candidate, None, None)
    try:
        return _FrontendNativeSnapshot(path, path.read_bytes(), path.stat().st_mode & 0o777)
    except OSError:
        return None


def _snapshot_path(path: Path) -> _FrontendNativeSnapshot:
    """Capture a path that will be temporarily staged for conformance."""

    if path.is_symlink():
        try:
            return _FrontendNativeSnapshot(
                path, None, None, os.readlink(path), invalid=True
            )
        except OSError:
            return _FrontendNativeSnapshot(path, None, None, invalid=True)
    if not path.exists():
        return _FrontendNativeSnapshot(path, None, None)
    if not path.is_file():
        return _FrontendNativeSnapshot(path, None, None, invalid=True)
    try:
        return _FrontendNativeSnapshot(path, path.read_bytes(), path.stat().st_mode & 0o777)
    except OSError:
        return _FrontendNativeSnapshot(path, None, None, invalid=True)


def _stage_frontend_for_conformance(
    root: Path,
    selected: _FrontendNativeSnapshot | None,
    package_snapshot: _FrontendNativeSnapshot | None,
) -> _FrontendNativeSnapshot | None:
    """Stage alternate selected bridge bytes at Python's fixed import path."""

    if selected is None or selected.payload is None:
        return None
    package_path = root / PYTHON_FRONTEND_PACKAGE_REL
    try:
        if selected.path.resolve() == package_path.resolve():
            return None
    except OSError:
        return None
    package_snapshot = package_snapshot or _snapshot_path(package_path)
    if package_snapshot.invalid:
        return package_snapshot
    package_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = package_path.with_name(
        f".{package_path.name}.qualification-stage-{os.getpid()}.tmp"
    )
    try:
        temporary.write_bytes(selected.payload)
        os.chmod(temporary, selected.mode or 0o755)
        os.replace(temporary, package_path)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
    return package_snapshot


def _manifest_frontend_native_path(root: Path) -> str | None:
    """Return the checked-in bridge path so qualification honors its override."""

    manifest = _load_json(root, root / RELEASE_MANIFEST_REL, [], "release manifest")
    if not isinstance(manifest, dict):
        return None
    frontend = manifest.get("frontend_native")
    relative = frontend.get("path") if isinstance(frontend, dict) else None
    if not isinstance(relative, str) or not SAFE_RELATIVE_PATH.fullmatch(relative):
        return None
    try:
        (root / relative).resolve(strict=False).relative_to(root.resolve())
    except ValueError:
        return None
    return relative


def _run_gates(
    root: Path,
    gates: Sequence[str],
    result: Qualification,
    *,
    emit_output: bool = True,
    environment: Mapping[str, str] | None = None,
) -> None:
    dekk = os.environ.get("DEKK", "").strip() or shutil.which("dekk")
    if not dekk:
        result.diagnostics.append(
            Diagnostic(
                "dekk-unavailable",
                "the `dekk` executable is not available, so owner protocol gates could not run",
                "enter the APXM Dekk environment and rerun `dekk agents release-qualification`",
            )
        )
        return
    for gate in gates:
        gate_environment = None
        if environment is not None:
            gate_environment = dict(os.environ)
            gate_environment.update(environment)
        completed = subprocess.run(
            [dekk, "agents", gate],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            env=gate_environment,
        )
        if emit_output and completed.stdout:
            print(completed.stdout, end="")
        if emit_output and completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
        record = {"command": f"dekk agents {gate}", "returncode": completed.returncode}
        result.gates.append(record)
        if completed.returncode != 0:
            classification = _classify_gate_failure(
                completed.returncode, f"{completed.stdout}\n{completed.stderr}"
            )
            record["classification"] = classification
            diagnostic_code = {
                "resource": "owner-gate-resource-failure",
                "abi": "owner-gate-abi-failure",
                "code": "owner-gate-code-failure",
            }[classification]
            result.diagnostics.append(
                Diagnostic(
                    diagnostic_code,
                    f"`dekk agents {gate}` exited with status {completed.returncode} ({classification} failure)",
                    {
                        "resource": "fix runner capacity, disk, process limits, or cache corruption, then rerun the gate",
                        "abi": "align the pinned compiler/toolchain and native ABI, clear only the affected cache, then rerun the gate",
                        "code": "fix the APXM owner implementation or test failure, then rerun the complete release qualification",
                    }[classification],
                )
            )


def qualify(
    root: Path,
    *,
    compilation_service_path: str | None = None,
    runtime_service_path: str | None = None,
    run_gates: bool = True,
    gates: Sequence[str] = OWNER_GATES,
    emit_gate_output: bool = True,
    qualified_descriptor_overlay: bool = False,
) -> Qualification:
    result = Qualification()
    root = root.resolve()
    frontend_native_snapshot = (
        _snapshot_manifest_frontend_native(root) if run_gates else None
    )
    frontend_package_snapshot = (
        _snapshot_path(root / PYTHON_FRONTEND_PACKAGE_REL) if run_gates else None
    )
    if run_gates and frontend_native_snapshot is not None and frontend_native_snapshot.invalid:
        result.diagnostics.append(
            Diagnostic(
                "invalid-frontend-native-input",
                "release manifest frontend_native path is a symlink or traverses a symlink",
                "publish a regular native bridge file inside the owner checkout; symlinked inputs are rejected",
            )
        )
    elif run_gates:
        try:
            _run_gates(root, gates, result, emit_output=emit_gate_output)
        finally:
            # The Compilation Service gate rebuilds and reinstalls the Python
            # bridge.  Its fresh bytes are what the gate exercises, but the
            # release validator must inspect and package the exact bytes named
            # by the already-published manifest.  Restore that immutable
            # cohort input before selecting artifacts so a macOS codesign or
            # linker rewrite cannot create a false digest mismatch.  An absent
            # bridge is restored to absence, while malformed symlink inputs
            # stop before gates and remain subject to the normal validator.
            if frontend_native_snapshot is not None:
                frontend_native_snapshot.restore()
        if frontend_package_snapshot is not None:
            frontend_package_snapshot.restore()
        staged_frontend = _stage_frontend_for_conformance(
            root, frontend_native_snapshot, frontend_package_snapshot
        )
        try:
            if staged_frontend is not None and staged_frontend.invalid:
                result.diagnostics.append(
                    Diagnostic(
                        "invalid-frontend-conformance-input",
                        "the Python frontend import path cannot be safely staged for the selected bridge",
                        "publish a regular Python frontend package path or remove the conflicting directory",
                    )
                )
            else:
                _run_gates(
                    root,
                    ("test-python-frontend",),
                    result,
                    emit_output=emit_gate_output,
                    environment={"APXM_SKIP_NATIVE_BUILD": "1"},
                )
        finally:
            if staged_frontend is not None:
                staged_frontend.restore()
            if frontend_package_snapshot is not None:
                frontend_package_snapshot.restore()

    if not _is_clean(root) and not (
        qualified_descriptor_overlay and _is_qualified_descriptor_overlay(root)
    ):
        result.diagnostics.append(
            Diagnostic(
                "dirty-checkout",
                "the owner checkout contains uncommitted changes; it cannot identify an immutable release",
                "publish from a clean checkout at the declared source revision; existing local edits were not changed",
            )
        )

    source_path = root / SOURCE_DESCRIPTOR_REL
    owner_path = root / OWNER_DESCRIPTOR_REL
    sidecar_path = root / OWNER_DESCRIPTOR_SIDECAR_REL
    manifest_path = root / RELEASE_MANIFEST_REL
    source = _load_json(root, source_path, result.diagnostics, "source descriptor")
    owner = _load_json(root, owner_path, result.diagnostics, "owner descriptor")
    manifest = _load_json(root, manifest_path, result.diagnostics, "release manifest")
    source_revision = _validate_source_descriptor(root, source, result.diagnostics)
    source_descriptor_file = _resolve_regular_file(root, source_path)
    source_descriptor_digest = (
        _digest_file(source_descriptor_file) if source_descriptor_file is not None else None
    )
    _validate_owner_descriptor(
        owner,
        source_revision=source_revision,
        source_descriptor_digest=source_descriptor_digest,
        diagnostics=result.diagnostics,
    )
    _validate_protocol_descriptors(root, source_revision, result)
    owner_descriptor_file = _resolve_regular_file(root, owner_path)
    owner_descriptor_digest = (
        _digest_file(owner_descriptor_file) if owner_descriptor_file is not None else None
    )

    sidecar_file = _resolve_regular_file(root, sidecar_path)
    if sidecar_file is None:
        result.diagnostics.append(
            Diagnostic(
                "missing-sidecar" if not sidecar_path.exists() else "non-regular-sidecar",
                f"owner descriptor digest sidecar is not a regular file inside the owner checkout: {OWNER_DESCRIPTOR_SIDECAR_REL}",
                "generate and publish the sidecar next to the exact owner descriptor bytes; symlinks and external files are rejected",
            )
        )
    elif owner_descriptor_digest is not None and _sidecar_digest(sidecar_file) != owner_descriptor_digest:
        result.diagnostics.append(
            Diagnostic(
                "descriptor-digest-mismatch",
                "owner descriptor sidecar does not match the exact descriptor bytes",
                "regenerate the sidecar; never hand-edit an immutable digest",
            )
        )

    artifacts = _find_artifacts(
        root,
        {
            "compilation-service": compilation_service_path,
            "runtime-service": runtime_service_path,
        },
        manifest,
    )
    result.artifacts = artifacts
    for name, binary in SERVICE_ARTIFACTS:
        artifact = artifacts.get(name)
        if artifact is None:
            result.diagnostics.append(
                Diagnostic(
                    "missing-publishable-service-artifact",
                    f"no publishable {name} executable ({binary}) is present",
                    f"build and publish the exact `{binary}` service from this source cohort, then set the matching APXM service binary variable or pass its explicit path",
                )
            )
            continue
        result.artifact_digests[name] = _digest_file(artifact)
        if not os.access(artifact, os.X_OK):
            result.diagnostics.append(
                Diagnostic(
                    "service-artifact-not-executable",
                    f"publishable {name} is not executable: {artifact}",
                    f"publish the executable `{binary}` service with execute permission",
                )
            )
    for schema_name, schema_relative in _discover_shipped_schemas(root):
        result.schema_paths[schema_name] = schema_relative.as_posix()
        result.schema_digests[schema_name] = _digest_file(root / schema_relative)
    frontend_native = _find_frontend_native(root, _manifest_frontend_native_path(root))
    if frontend_native is None:
        result.diagnostics.append(
            Diagnostic(
                "missing-publishable-frontend-native",
                "no publishable Python frontend native bridge is present",
                "build the exact frontend bridge with `dekk agents build-frontend-native` before qualifying a release",
            )
        )
    else:
        result.artifacts[FRONTEND_NATIVE_ARTIFACT[0]] = frontend_native
        result.artifact_digests[FRONTEND_NATIVE_ARTIFACT[0]] = _digest_file(frontend_native)
    service_artifacts = {
        name: artifacts[name] for name, _ in SERVICE_ARTIFACTS if name in artifacts
    }
    if len(service_artifacts) == len(SERVICE_ARTIFACTS) and manifest is None:
        result.diagnostics.append(
            Diagnostic(
                "unattested-service-artifacts",
                "local APXM service executables were found, but they are not a published immutable service release",
                "publish both exact service binaries with the source/owner descriptors and release manifest; local builds alone cannot activate runtime",
            )
        )
    _validate_release_manifest(
        root,
        manifest,
        source_revision=source_revision,
        owner_descriptor_digest=owner_descriptor_digest,
        artifacts=artifacts,
        artifact_digests=result.artifact_digests,
        schema_digests=result.schema_digests,
        schema_paths=result.schema_paths,
        diagnostics=result.diagnostics,
    )
    if not result.ok:
        result.diagnostics.append(
            Diagnostic(
                "runtime-activation-blocked",
                "this checkout is not qualified for runtime activation",
                "publish the immutable descriptor cohort and matching Compilation/Runtime service executables; no runtime identity was inferred",
            )
        )
    return result


def _git_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def build_release_documents(
    root: Path,
    *,
    compilation_service_path: str,
    runtime_service_path: str,
    python_frontend_native_path: str | None = None,
    source_revision: str,
) -> dict[Path, bytes]:
    """Return the four release documents for one revision and one artifact set.

    This is the whole content of a release cohort's descriptors: it hashes the
    exact service executables, the exact Python frontend bridge and every
    shipped contract schema, and it reads nothing else.  The owner path
    (:func:`generate_descriptors`) wraps it with the Git checks that decide
    *which* revision may be published; a service image build reuses it with the
    revision it was handed, because an image carries no Git checkout.
    """

    root = root.resolve()
    services: dict[str, Path] = {}
    for name, binary in SERVICE_ARTIFACTS:
        raw_path = (
            compilation_service_path
            if name == "compilation-service"
            else runtime_service_path
        )
        service = _resolve_regular_file(root, _rooted_path(root, raw_path))
        if service is None:
            raise ValueError(
                f"publishable {name} must be a regular file: {raw_path}; supply the real {binary} binary"
            )
        if not os.access(service, os.X_OK):
            raise ValueError(f"publishable {name} is not executable: {service}")
        services[name] = service
    frontend_native = _find_frontend_native(root, python_frontend_native_path)
    if frontend_native is None:
        raise ValueError(
            "publishable Python frontend native bridge is missing; build the real bridge before generating descriptors"
        )
    shipped_schemas = _discover_shipped_schemas(root)
    if not shipped_schemas:
        raise ValueError(
            f"publishable contract schemas are missing under {SCHEMA_DIRECTORY_REL}; a release cannot pin contracts it does not ship"
        )
    revision = source_revision
    if not HEX40.fullmatch(revision):
        raise ValueError("cannot generate descriptors without a full lowercase source revision")

    source = {
        "schema_version": SOURCE_DESCRIPTOR_SCHEMA,
        "semantic_owner": "agents",
        "selection": "immutable-source-cohort",
        "source_revision": revision,
    }
    source_bytes = _canonical_json(source)
    source_digest = _digest_bytes(source_bytes)
    owner = {
        "schema_version": OWNER_DESCRIPTOR_SCHEMA,
        "semantic_owner": "agents",
        "source_revision": revision,
        "source_descriptor_digest": source_digest,
        "artifact_kind": ARTIFACT_KIND,
        "compilation_protocol": COMPILATION_PROTOCOL_VERSION,
        "runtime_protocol": RUNTIME_PROTOCOL_VERSION,
    }
    owner_bytes = _canonical_json(owner)
    owner_digest = _digest_bytes(owner_bytes)
    manifest = {
        "schema_version": RELEASE_MANIFEST_SCHEMA,
        "semantic_owner": "agents",
        "source_revision": revision,
        "artifact_kind": ARTIFACT_KIND,
        "services": [
            {
                "name": name,
                "path": (
                    _git_relative(root, services[name])
                    if services[name].is_relative_to(root)
                    else f"target/release/{name_for_path}"
                ),
                "digest": _digest_file(services[name]),
            }
            for name, name_for_path in SERVICE_ARTIFACTS
        ],
        "schemas": [
            {
                "name": schema_name,
                "path": schema_relative.as_posix(),
                "digest": _digest_file(root / schema_relative),
            }
            for schema_name, schema_relative in shipped_schemas
        ],
        "frontend_native": {
            "name": FRONTEND_NATIVE_ARTIFACT[0],
            "path": (
                _git_relative(root, frontend_native)
                if frontend_native.is_relative_to(root)
                else f"target/release/{FRONTEND_NATIVE_ARTIFACT[1]}"
            ),
            "digest": _digest_file(frontend_native),
        },
        "owner_descriptor_digest": owner_digest,
        "integrity_algorithm": "sha256",
    }
    return {
        SOURCE_DESCRIPTOR_REL: source_bytes,
        OWNER_DESCRIPTOR_REL: owner_bytes,
        OWNER_DESCRIPTOR_SIDECAR_REL: f"{owner_digest}  {OWNER_DESCRIPTOR_REL.as_posix()}\n".encode("utf-8"),
        RELEASE_MANIFEST_REL: _canonical_json(manifest),
    }


def generate_descriptors(
    root: Path,
    *,
    compilation_service_path: str,
    runtime_service_path: str,
    python_frontend_native_path: str | None = None,
    output_dir: Path,
    source_revision: str | None = None,
) -> tuple[Path, ...]:
    """Publish one cohort's descriptors from a clean owner checkout.

    Regenerating in place (``--output-dir .``) replaces the checked-in
    descriptors, because that is the only way to move the checkout to a new
    cohort and Git already holds the bytes being replaced.  Every other output
    directory stays write-once: a package or evidence tree must never have a
    published document rewritten underneath it.
    """

    root = root.resolve()
    if not _is_clean(root):
        raise ValueError(
            "cannot generate immutable release descriptors from a dirty owner checkout; existing local edits were not changed"
        )
    revision = source_revision or _git_revision(root)
    if revision is None or not HEX40.fullmatch(revision):
        raise ValueError("cannot generate descriptors without a full lowercase Git source revision")
    if _git_text(root, "rev-parse", f"{revision}^{{commit}}") != revision:
        raise ValueError(f"source revision is not present in the owner checkout: {revision}")
    if not _git_is_ancestor(root, revision, "HEAD"):
        raise ValueError(f"source revision is not an ancestor of the owner checkout HEAD: {revision}")
    documents = build_release_documents(
        root,
        compilation_service_path=compilation_service_path,
        runtime_service_path=runtime_service_path,
        python_frontend_native_path=python_frontend_native_path,
        source_revision=revision,
    )
    in_place = output_dir.resolve() == root
    outputs = tuple((output_dir / relative, payload) for relative, payload in documents.items())
    if not in_place:
        for path, payload in outputs:
            if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes() != payload)):
                raise ValueError(
                    f"refusing to overwrite existing release input with different bytes: {path}"
                )
    for path, payload in outputs:
        if path.is_symlink():
            raise ValueError(f"release input is not a regular file: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != payload:
            path.write_bytes(payload)
    return tuple(path for path, _ in outputs)


def generate_image_descriptors(
    root: Path,
    *,
    compilation_service_path: str,
    runtime_service_path: str,
    python_frontend_native_path: str | None = None,
    output_dir: Path,
    source_revision: str,
) -> dict[str, Any]:
    """Regenerate one cohort's descriptors inside a service image build.

    An image has no Git checkout, so the revision is handed in and the build
    proves it instead: the regenerated source and owner descriptors must be
    byte-identical to the ones the checkout ships, and the regenerated manifest
    must publish exactly the schema digests the checked-in manifest publishes.
    Only the service and frontend digests are allowed to differ, because those
    are the bytes this image just built.  A build that cannot reproduce the
    cohort's identity fails instead of stamping an unverifiable label.
    """

    root = root.resolve()
    documents = build_release_documents(
        root,
        compilation_service_path=compilation_service_path,
        runtime_service_path=runtime_service_path,
        python_frontend_native_path=python_frontend_native_path,
        source_revision=source_revision,
    )
    for relative in (SOURCE_DESCRIPTOR_REL, OWNER_DESCRIPTOR_REL, OWNER_DESCRIPTOR_SIDECAR_REL):
        checked_in = _resolve_regular_file(root, root / relative)
        if checked_in is None:
            raise ValueError(f"the checkout in this image ships no {relative.as_posix()}")
        if checked_in.read_bytes() != documents[relative]:
            raise ValueError(
                f"regenerated {relative.as_posix()} does not match the checked-in cohort at revision {source_revision}"
            )
    checked_in_manifest = _load_json(root, root / RELEASE_MANIFEST_REL, [], "release manifest")
    if not isinstance(checked_in_manifest, dict):
        raise ValueError("the checkout in this image ships no readable release manifest")
    regenerated = json.loads(documents[RELEASE_MANIFEST_REL].decode("utf-8"))
    if regenerated.get("schemas") != checked_in_manifest.get("schemas"):
        raise ValueError(
            "regenerated schema digests do not match the checked-in release manifest; the image ships different contracts than the cohort"
        )
    output_dir = output_dir.resolve()
    for relative, payload in documents.items():
        destination = output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    manifest = regenerated
    return {
        "schema": "apxm.agents.image-release-descriptors.v1",
        "semantic_owner": "agents",
        "source_revision": source_revision,
        "output_dir": str(output_dir),
        "owner_descriptor_digest": manifest["owner_descriptor_digest"],
        "release_manifest_digest": _digest_bytes(documents[RELEASE_MANIFEST_REL]),
        "services": manifest["services"],
        "frontend_native": manifest["frontend_native"],
        "schema_count": len(manifest["schemas"]),
    }


def _write_once(path: Path, payload: bytes) -> None:
    """Create a package file once; never replace bytes under an existing path."""

    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"immutable release package target is not a regular file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise ValueError(f"refusing to overwrite immutable release package file: {path}")
        return
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise ValueError(f"refusing to overwrite immutable release package file: {path}")
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def _package_payload(result: Qualification, root: Path) -> dict[str, Any]:
    source = _load_json(root, root / SOURCE_DESCRIPTOR_REL, [], "source descriptor") or {}
    owner = _load_json(root, root / OWNER_DESCRIPTOR_REL, [], "owner descriptor") or {}
    manifest = _load_json(root, root / RELEASE_MANIFEST_REL, [], "release manifest") or {}
    source_file = _resolve_regular_file(root, root / SOURCE_DESCRIPTOR_REL)
    owner_file = _resolve_regular_file(root, root / OWNER_DESCRIPTOR_REL)
    manifest_file = _resolve_regular_file(root, root / RELEASE_MANIFEST_REL)
    return {
        "schema": "apxm.agents.release-qualification.v1",
        "owner": "agents",
        "qualification_scope": "owner-local",
        "external_live_approval": False,
        "evidence_root": str(root.resolve()),
        "qualified": result.ok,
        "source_revision": source.get("source_revision"),
        "source_descriptor_digest": _digest_file(source_file) if source_file else None,
        "owner_descriptor_digest": _digest_file(owner_file) if owner_file else None,
        "release_manifest_digest": _digest_file(manifest_file) if manifest_file else None,
        "protocol_descriptors": result.protocol_descriptors,
        "manifest_services": manifest.get("services"),
        "manifest_schemas": manifest.get("schemas"),
        "manifest_frontend_native": manifest.get("frontend_native"),
        "services": {name: str(path) for name, path in result.artifacts.items()},
        "service_digests": result.artifact_digests,
        "schema_digests": result.schema_digests,
        "gates": result.gates,
        "diagnostics": [
            {"code": item.code, "message": item.message, "remediation": item.remediation}
            for item in result.diagnostics
        ],
    }


def package_release(
    root: Path,
    *,
    output_dir: Path | None = None,
    compilation_service_path: str | None = None,
    runtime_service_path: str | None = None,
    run_gates: bool = True,
    gates: Sequence[str] = OWNER_GATES,
    emit_gate_output: bool = True,
    qualified_descriptor_overlay: bool = False,
) -> dict[str, Any]:
    """Materialize and qualify one write-once local service release package."""

    root = root.resolve()
    result = qualify(
        root,
        compilation_service_path=compilation_service_path,
        runtime_service_path=runtime_service_path,
        run_gates=run_gates,
        gates=gates,
        emit_gate_output=emit_gate_output,
        qualified_descriptor_overlay=qualified_descriptor_overlay,
    )
    payload = _package_payload(result, root)
    payload["schema"] = LOCAL_ARTIFACT_SCHEMA
    payload["package"] = None
    if not result.ok:
        return payload

    source_revision = payload["source_revision"]
    if not isinstance(source_revision, str) or not HEX40.fullmatch(source_revision):
        raise ValueError("qualified release has no immutable source revision to package")
    package_root = (output_dir or default_release_package_dir(root, source_revision)).expanduser()
    if not package_root.is_absolute():
        package_root = root / package_root
    package_root = package_root.resolve()
    if package_root == root:
        raise ValueError("release package must be outside the owner source root")
    if package_root.is_symlink() or (package_root.exists() and not package_root.is_dir()):
        raise ValueError(f"release package root is not a regular directory: {package_root}")
    package_root.mkdir(parents=True, exist_ok=True)
    existing_manifest = _resolve_regular_file(
        package_root, package_root / LOCAL_ARTIFACT_MANIFEST_REL
    )
    if existing_manifest is not None:
        try:
            existing_document = json.loads(existing_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"release package cohort already exists with an invalid immutable manifest: {package_root}"
            ) from exc
        if not isinstance(existing_document, dict) or existing_document.get("source_revision") != source_revision:
            raise ValueError(
                "release package cohort directory collides with a different source revision: "
                f"{package_root}"
            )

    manifest = _load_json(
        root, root / RELEASE_MANIFEST_REL, result.diagnostics, "release manifest"
    )
    if manifest is None:
        raise ValueError("qualified release has no release manifest to package")
    manifest_services = manifest.get("services")
    service_paths = {
        item["name"]: Path(item["path"])
        for item in manifest_services
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("path"), str)
    } if isinstance(manifest_services, list) else {}

    manifest_schemas = manifest.get("schemas")
    schema_files = tuple(
        (str(item["name"]), Path(str(item["path"])))
        for item in manifest_schemas
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("path"), str)
    ) if isinstance(manifest_schemas, list) else ()
    if not schema_files:
        raise ValueError("qualified release manifest publishes no schemas to package")

    files: list[dict[str, Any]] = []
    source_files = (
        ("source-descriptor", SOURCE_DESCRIPTOR_REL),
        ("owner-descriptor", OWNER_DESCRIPTOR_REL),
        ("owner-descriptor-sidecar", OWNER_DESCRIPTOR_SIDECAR_REL),
        ("release-manifest", RELEASE_MANIFEST_REL),
    )
    for name, relative in (*source_files, *PROTOCOL_DESCRIPTORS, *schema_files):
        source = _resolve_regular_file(root, root / relative)
        if source is None:
            raise ValueError(f"qualified release input is not a regular file: {relative}")
        payload_bytes = source.read_bytes()
        files.append({"name": name, "path": relative.as_posix(), "digest": _digest_bytes(payload_bytes)})
        _write_once(package_root / relative, payload_bytes)

    package_artifacts = (*SERVICE_ARTIFACTS, FRONTEND_NATIVE_ARTIFACT)
    for name, binary in package_artifacts:
        source = result.artifacts.get(name)
        manifest_path = (
            service_paths.get(name)
            if name in service_paths
            else Path(str((manifest.get("frontend_native") or {}).get("path", "")))
        )
        if source is None or manifest_path is None:
            raise ValueError(f"qualified release has no local {name} service path")
        try:
            source_relative = source.resolve().relative_to(root)
        except ValueError:
            # A cross-platform release is qualified on the owner checkout but
            # its Linux executable is materialized by a separate builder. The
            # package still copies those exact bytes into the manifest path;
            # no external path is retained in the package identity.
            source_relative = None
        if source_relative is not None and source_relative != manifest_path:
            raise ValueError(
                f"manifest path for {name} does not select the qualified executable: {manifest_path} != {source_relative}"
            )
        if not os.access(source, os.X_OK):
            raise ValueError(f"qualified {name} service is not executable: {source}")
        payload_bytes = source.read_bytes()
        entry = {
            "name": name,
            "path": manifest_path.as_posix(),
            "digest": _digest_bytes(payload_bytes),
        }
        if name in {service_name for service_name, _ in SERVICE_ARTIFACTS}:
            entry.update({"executable": True, "bytes": len(payload_bytes)})
        files.append(entry)
        destination = package_root / manifest_path
        _write_once(destination, payload_bytes)
        if not os.access(destination, os.X_OK):
            destination.chmod(source.stat().st_mode & 0o777)
        if not os.access(destination, os.X_OK):
            raise ValueError(f"packaged {name} service is not executable: {destination}")

    files.sort(key=lambda item: item["path"])
    package_manifest = {
        "schema": LOCAL_ARTIFACT_SCHEMA,
        "semantic_owner": "agents",
        "qualification_scope": "owner-local",
        "external_live_approval": False,
        "source_revision": source_revision,
        "source_descriptor_digest": payload["source_descriptor_digest"],
        "owner_descriptor_digest": payload["owner_descriptor_digest"],
        "release_manifest_digest": payload["release_manifest_digest"],
        "protocol_descriptors": payload["protocol_descriptors"],
        "files": files,
    }
    package_manifest_bytes = _canonical_json(package_manifest)
    _write_once(package_root / LOCAL_ARTIFACT_MANIFEST_REL, package_manifest_bytes)

    expected_paths = {item["path"] for item in files} | {LOCAL_ARTIFACT_MANIFEST_REL.as_posix()}
    actual_paths = {
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*")
        if path.is_file()
    }
    if actual_paths != expected_paths:
        raise ValueError(
            "release package contains files outside its immutable manifest: "
            + ", ".join(sorted(actual_paths ^ expected_paths))
        )
    for item in files:
        packaged = package_root / item["path"]
        if _digest_file(packaged) != item["digest"]:
            raise ValueError(f"packaged bytes do not match the immutable manifest: {item['path']}")
        if item.get("executable") and not os.access(packaged, os.X_OK):
            raise ValueError(f"packaged service lost executable permission: {item['path']}")

    package_manifest_digest = _digest_bytes(package_manifest_bytes)
    payload["package"] = {
        "root": str(package_root),
        "manifest": LOCAL_ARTIFACT_MANIFEST_REL.as_posix(),
        "manifest_digest": package_manifest_digest,
        "files": files,
    }
    return payload


def verify_package(package_dir: Path) -> dict[str, Any]:
    """Verify one packaged release from the consumer side of the boundary."""

    root = package_dir.expanduser().resolve()
    diagnostics: list[Diagnostic] = []
    manifest_path = root / LOCAL_ARTIFACT_MANIFEST_REL
    manifest_file = _resolve_regular_file(root, manifest_path)
    package_manifest_digest: str | None = None
    manifest: dict[str, Any] | None = None
    if manifest_file is None:
        diagnostics.append(
            Diagnostic(
                "missing-package-manifest",
                f"consumer release package manifest is not a regular file: {LOCAL_ARTIFACT_MANIFEST_REL}",
                "provide the exact immutable package produced by the APXM owner release packager",
            )
        )
    else:
        try:
            manifest_bytes = manifest_file.read_bytes()
            package_manifest_digest = _digest_bytes(manifest_bytes)
            decoded = json.loads(manifest_bytes)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            diagnostics.append(
                Diagnostic(
                    "invalid-package-manifest",
                    f"consumer release package manifest is not canonical UTF-8 JSON ({error})",
                    "restore the exact package manifest emitted by the APXM owner release packager",
                )
            )
        else:
            if not isinstance(decoded, dict):
                diagnostics.append(
                    Diagnostic(
                        "invalid-package-manifest",
                        "consumer release package manifest root must be a JSON object",
                        "restore the exact package manifest emitted by the APXM owner release packager",
                    )
                )
            else:
                manifest = decoded
                if manifest_bytes != _canonical_json(manifest):
                    diagnostics.append(
                        Diagnostic(
                            "non-canonical-package-manifest",
                            "consumer release package manifest bytes are not canonical",
                            "regenerate or restore the package; consumer verification never normalizes identity bytes",
                        )
                    )

    payload: dict[str, Any] = {
        "schema": CONSUMER_VERIFICATION_SCHEMA,
        "owner": "agents",
        "qualification_scope": "consumer-local",
        "external_live_approval": False,
        "package_root": str(root),
        "package_manifest_digest": package_manifest_digest,
        "qualified": False,
        "verified_files": [],
        "diagnostics": [],
    }
    if manifest is None:
        payload["diagnostics"] = [
            {"code": item.code, "message": item.message, "remediation": item.remediation}
            for item in diagnostics
        ]
        return payload

    required_fields = {
        "schema",
        "semantic_owner",
        "qualification_scope",
        "external_live_approval",
        "source_revision",
        "source_descriptor_digest",
        "owner_descriptor_digest",
        "release_manifest_digest",
        "protocol_descriptors",
        "files",
    }
    unknown = sorted(set(manifest) - required_fields)
    missing = sorted(required_fields - set(manifest))
    if unknown or missing:
        diagnostics.append(
            Diagnostic(
                "invalid-package-schema",
                "consumer release package manifest has missing or unknown fields"
                + (f" (missing: {', '.join(missing)})" if missing else "")
                + (f" (unknown: {', '.join(unknown)})" if unknown else ""),
                "restore the exact APXM local release artifact schema",
            )
        )
    if manifest.get("schema") != LOCAL_ARTIFACT_SCHEMA:
        diagnostics.append(
            Diagnostic(
                "invalid-package-schema",
                "consumer release package manifest schema is not the APXM local release artifact schema",
                "restore the exact APXM local release artifact schema",
            )
        )
    if manifest.get("semantic_owner") != "agents":
        diagnostics.append(
            Diagnostic(
                "invalid-package-owner",
                "consumer release package manifest is not owned by agents",
                "consume an APXM Agents release package, not an untrusted or foreign artifact",
            )
        )
    if manifest.get("qualification_scope") != "owner-local" or manifest.get("external_live_approval") is not False:
        diagnostics.append(
            Diagnostic(
                "invalid-package-scope",
                "consumer release package does not carry the neutral owner-local scope",
                "publish a package with owner-local qualification and no external approval claim",
            )
        )
    source_revision = manifest.get("source_revision")
    if not isinstance(source_revision, str) or not HEX40.fullmatch(source_revision):
        diagnostics.append(
            Diagnostic(
                "invalid-package-source",
                "consumer release package source_revision is not a full lowercase Git revision",
                "package the exact immutable APXM source cohort",
            )
        )
    for field in (
        "source_descriptor_digest",
        "owner_descriptor_digest",
        "release_manifest_digest",
    ):
        if not isinstance(manifest.get(field), str) or not DIGEST.fullmatch(manifest[field]):
            diagnostics.append(
                Diagnostic(
                    "invalid-package-digest",
                    f"consumer release package {field} is not a sha256 digest",
                    "restore the exact package manifest emitted by the APXM owner release packager",
                )
            )

    file_entries = manifest.get("files")
    by_name: dict[str, dict[str, Any]] = {}
    by_path: dict[str, dict[str, Any]] = {}
    if not isinstance(file_entries, list):
        diagnostics.append(
            Diagnostic(
                "invalid-package-files",
                "consumer release package files must be an array",
                "restore the exact package file inventory emitted by the APXM owner release packager",
            )
        )
        file_entries = []
    for index, entry in enumerate(file_entries):
        if not isinstance(entry, dict):
            diagnostics.append(
                Diagnostic(
                    "invalid-package-files",
                    f"consumer release package files[{index}] must be an object",
                    "restore the exact package file inventory emitted by the APXM owner release packager",
                )
            )
            continue
        name = entry.get("name")
        path = entry.get("path")
        digest = entry.get("digest")
        if (
            not isinstance(name, str)
            or not isinstance(path, str)
            or not SAFE_RELATIVE_PATH.fullmatch(path)
            or not isinstance(digest, str)
            or not DIGEST.fullmatch(digest)
        ):
            diagnostics.append(
                Diagnostic(
                    "invalid-package-files",
                    f"consumer release package files[{index}] has an invalid name, path, or digest",
                    "restore the exact package file inventory emitted by the APXM owner release packager",
                )
            )
            continue
        allowed_fields = {"name", "path", "digest"}
        if name in {service_name for service_name, _ in SERVICE_ARTIFACTS}:
            allowed_fields |= {"executable", "bytes"}
        if set(entry) != allowed_fields:
            diagnostics.append(
                Diagnostic(
                    "invalid-package-files",
                    f"consumer release package files[{index}] has fields outside its declared file kind",
                    "restore the exact package file inventory emitted by the APXM owner release packager",
                )
            )
            continue
        if name in {service_name for service_name, _ in SERVICE_ARTIFACTS} and (
            entry.get("executable") is not True
            or not isinstance(entry.get("bytes"), int)
            or entry["bytes"] < 0
        ):
            diagnostics.append(
                Diagnostic(
                    "invalid-package-service",
                    f"consumer release package service entry {name!r} does not bind executable bytes",
                    "restore the exact executable service entry emitted by the APXM owner release packager",
                )
            )
            continue
        if name in by_name or path in by_path:
            diagnostics.append(
                Diagnostic(
                    "duplicate-package-file",
                    f"consumer release package repeats file identity {name!r} or path {path!r}",
                    "package each release input exactly once",
                )
            )
            continue
        by_name[name] = entry
        by_path[path] = entry

    packaged_schemas = {
        schema_name: schema_relative.as_posix()
        for schema_name, schema_relative in _discover_shipped_schemas(root)
    }
    expected_names = {
        "source-descriptor",
        "owner-descriptor",
        "owner-descriptor-sidecar",
        "release-manifest",
        "compilation-protocol",
        "runtime-protocol",
        "compilation-service",
        "runtime-service",
        FRONTEND_NATIVE_ARTIFACT[0],
        *packaged_schemas,
    }
    if set(by_name) != expected_names:
        diagnostics.append(
            Diagnostic(
                "invalid-package-files",
                "consumer release package does not contain exactly the required owner, service, and schema files",
                "package the source, owner, sidecar, manifest, protocol, schema, and two service files exactly once",
            )
        )

    actual_paths: set[str] = set()
    if root.is_symlink() or not root.is_dir():
        diagnostics.append(
            Diagnostic(
                "invalid-package-root",
                "consumer release package root is not a regular directory",
                "provide a regular package directory under consumer control",
            )
        )
    elif root.exists():
        for candidate in root.rglob("*"):
            if candidate.is_symlink():
                diagnostics.append(
                    Diagnostic(
                        "package-symlink",
                        f"consumer release package contains a symlink: {candidate.relative_to(root).as_posix()}",
                        "materialize regular package files; symlinks cannot carry release identity",
                    )
                )
            elif candidate.is_file():
                actual_paths.add(candidate.relative_to(root).as_posix())
    expected_paths = set(by_path) | {LOCAL_ARTIFACT_MANIFEST_REL.as_posix()}
    if actual_paths != expected_paths:
        diagnostics.append(
            Diagnostic(
                "package-file-set-mismatch",
                "consumer release package contains missing or extra files outside its immutable manifest",
                "restore the exact write-once package file set",
            )
        )

    for path, entry in by_path.items():
        candidate = _resolve_regular_file(root, root / path)
        if candidate is None:
            diagnostics.append(
                Diagnostic(
                    "missing-package-file",
                    f"consumer release package file is not a regular file: {path}",
                    "restore the exact package file named by the immutable manifest",
                )
            )
            continue
        digest = _digest_file(candidate)
        if digest != entry["digest"]:
            diagnostics.append(
                Diagnostic(
                    "package-file-digest-mismatch",
                    f"consumer release package bytes do not match the immutable digest: {path}",
                    "discard the tampered package and obtain the exact owner-produced release artifact",
                )
            )
            continue
        if entry.get("executable") is True:
            if not os.access(candidate, os.X_OK):
                diagnostics.append(
                    Diagnostic(
                        "package-service-not-executable",
                        f"consumer release package service is not executable: {path}",
                        "restore executable permission without changing the service bytes, or obtain a fresh package",
                    )
                )
            if entry.get("bytes") != candidate.stat().st_size:
                diagnostics.append(
                    Diagnostic(
                        "package-service-size-mismatch",
                        f"consumer release package service byte count is not bound: {path}",
                        "restore the exact service bytes described by the package manifest",
                    )
                )
        payload["verified_files"].append({"path": path, "digest": digest})

    digest_bindings = {
        "source_descriptor_digest": "source-descriptor",
        "owner_descriptor_digest": "owner-descriptor",
        "release_manifest_digest": "release-manifest",
    }
    for field, name in digest_bindings.items():
        if manifest.get(field) != by_name.get(name, {}).get("digest"):
            diagnostics.append(
                Diagnostic(
                    "package-digest-binding-mismatch",
                    f"consumer package {field} does not match the corresponding package file digest",
                    "restore the exact package manifest and its descriptor cohort",
                )
            )

    protocol_descriptors = manifest.get("protocol_descriptors")
    if not isinstance(protocol_descriptors, dict) or set(protocol_descriptors) != {
        "compilation-protocol",
        "runtime-protocol",
    }:
        diagnostics.append(
            Diagnostic(
                "invalid-package-protocols",
                "consumer package protocol_descriptors does not name exactly the Compilation and Runtime protocols",
                "restore the exact protocol descriptor bindings from the owner release packager",
            )
        )
    else:
        for name, _ in PROTOCOL_DESCRIPTORS:
            descriptor = protocol_descriptors.get(name)
            file_entry = by_name.get(name)
            if (
                not isinstance(descriptor, dict)
                or set(descriptor) != {"path", "digest"}
                or not isinstance(file_entry, dict)
                or descriptor.get("path") != file_entry.get("path")
                or descriptor.get("digest") != file_entry.get("digest")
            ):
                diagnostics.append(
                    Diagnostic(
                        "package-protocol-binding-mismatch",
                        f"consumer package protocol binding does not match its immutable file entry: {name}",
                        "restore the exact protocol descriptor bindings from the owner release packager",
                    )
                )

    source_file = _resolve_regular_file(root, root / str(by_name.get("source-descriptor", {}).get("path", "")))
    owner_file = _resolve_regular_file(root, root / str(by_name.get("owner-descriptor", {}).get("path", "")))
    sidecar_file = _resolve_regular_file(root, root / str(by_name.get("owner-descriptor-sidecar", {}).get("path", "")))
    release_file = _resolve_regular_file(root, root / str(by_name.get("release-manifest", {}).get("path", "")))
    source = _load_json(root, source_file, diagnostics, "package source descriptor") if source_file else None
    owner = _load_json(root, owner_file, diagnostics, "package owner descriptor") if owner_file else None
    release = _load_json(root, release_file, diagnostics, "package release manifest") if release_file else None
    if source is not None:
        if (
            set(source) != {"schema_version", "semantic_owner", "selection", "source_revision"}
            or source.get("schema_version") != SOURCE_DESCRIPTOR_SCHEMA
            or source.get("semantic_owner") != "agents"
            or source.get("selection") != "immutable-source-cohort"
            or source.get("source_revision") != source_revision
        ):
            diagnostics.append(
                Diagnostic(
                    "package-source-binding-mismatch",
                    "consumer package source descriptor does not bind the package source revision",
                    "restore the exact source descriptor from the owner release cohort",
                )
            )
    if owner is not None:
        if (
            set(owner) != {
                "schema_version",
                "semantic_owner",
                "source_revision",
                "source_descriptor_digest",
                "artifact_kind",
                "compilation_protocol",
                "runtime_protocol",
            }
            or owner.get("schema_version") != OWNER_DESCRIPTOR_SCHEMA
            or owner.get("semantic_owner") != "agents"
            or owner.get("source_revision") != source_revision
            or owner.get("source_descriptor_digest") != manifest.get("source_descriptor_digest")
            or owner.get("artifact_kind") != ARTIFACT_KIND
            or owner.get("compilation_protocol") != COMPILATION_PROTOCOL_VERSION
            or owner.get("runtime_protocol") != RUNTIME_PROTOCOL_VERSION
        ):
            diagnostics.append(
                Diagnostic(
                    "package-owner-binding-mismatch",
                    "consumer package owner descriptor does not bind the package source and protocols",
                    "restore the exact owner descriptor from the owner release cohort",
                )
            )
    if sidecar_file is not None and _sidecar_digest(sidecar_file) != manifest.get("owner_descriptor_digest"):
        diagnostics.append(
            Diagnostic(
                "package-sidecar-mismatch",
                "consumer package owner descriptor sidecar does not match the package owner descriptor digest",
                "restore the exact sidecar from the owner release cohort",
            )
        )
    if release is not None:
        service_files = {
            name: root / str(by_name.get(name, {}).get("path", ""))
            for name, _ in SERVICE_ARTIFACTS
        }
        service_files[FRONTEND_NATIVE_ARTIFACT[0]] = root / str(
            by_name.get(FRONTEND_NATIVE_ARTIFACT[0], {}).get("path", "")
        )
        artifact_digests = {
            name: str(by_name.get(name, {}).get("digest", ""))
            for name, _ in SERVICE_ARTIFACTS
        }
        artifact_digests[FRONTEND_NATIVE_ARTIFACT[0]] = str(
            by_name.get(FRONTEND_NATIVE_ARTIFACT[0], {}).get("digest", "")
        )
        _validate_release_manifest(
            root,
            release,
            source_revision=source_revision if isinstance(source_revision, str) else None,
            owner_descriptor_digest=manifest.get("owner_descriptor_digest")
            if isinstance(manifest.get("owner_descriptor_digest"), str)
            else None,
            artifacts=service_files,
            artifact_digests=artifact_digests,
            schema_digests={
                schema_name: _digest_file(root / relative)
                for schema_name, relative in packaged_schemas.items()
            },
            schema_paths=packaged_schemas,
            diagnostics=diagnostics,
        )
        release_digest_matches = (
            release_file is not None
            and _digest_file(release_file) == manifest.get("release_manifest_digest")
        )
        if not release_digest_matches:
            diagnostics.append(
                Diagnostic(
                    "package-release-manifest-digest-mismatch",
                    "consumer package release manifest digest is not bound to its exact bytes",
                    "restore the exact release manifest from the owner release cohort",
                )
            )

    payload["source_revision"] = source_revision
    payload["qualified"] = not diagnostics
    payload["diagnostics"] = [
        {"code": item.code, "message": item.message, "remediation": item.remediation}
        for item in diagnostics
    ]
    return payload


def _print_result(result: Qualification, *, as_json: bool, root: Path = REPOSITORY_ROOT) -> None:
    root = root.resolve()
    payload = _package_payload(result, root)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("APXM owner release qualification: PASS" if result.ok else "APXM owner release qualification: FAIL")
        for gate in result.gates:
            print(f"gate: {gate['command']} -> {gate['returncode']}")
        for diagnostic in result.diagnostics:
            print(diagnostic.render(), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="release_qualification.py")
    subparsers = parser.add_subparsers(dest="mode")
    qualify_parser = subparsers.add_parser("qualify", help="run owner gates and qualify a release cohort")
    qualify_parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    qualify_parser.add_argument("--compilation-service", help="path to the published apxm-compilation-service executable")
    qualify_parser.add_argument("--runtime-service", help="path to the published apxm-runtime-service executable")
    qualify_parser.add_argument("--skip-gates", action="store_true", help="skip only for offline metadata tests")
    qualify_parser.add_argument("--json", action="store_true", dest="as_json")
    generate_parser = subparsers.add_parser("generate", help="generate descriptors from a real artifact")
    generate_parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    generate_parser.add_argument("--compilation-service", required=True)
    generate_parser.add_argument("--runtime-service", required=True)
    generate_parser.add_argument("--python-frontend-native")
    generate_parser.add_argument("--output-dir", type=Path, required=True)
    generate_parser.add_argument("--source-revision")
    image_parser = subparsers.add_parser(
        "image-descriptors",
        help="regenerate one cohort's descriptors inside a service image build",
    )
    image_parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    image_parser.add_argument("--compilation-service", required=True)
    image_parser.add_argument("--runtime-service", required=True)
    image_parser.add_argument("--python-frontend-native")
    image_parser.add_argument("--output-dir", type=Path, required=True)
    image_parser.add_argument("--source-revision", required=True)
    package_parser = subparsers.add_parser(
        "package", help="package and qualify one immutable local service release artifact"
    )
    package_parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    package_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
    )
    package_parser.add_argument("--compilation-service")
    package_parser.add_argument("--runtime-service")
    package_parser.add_argument("--skip-gates", action="store_true")
    package_parser.add_argument("--qualified-descriptor-overlay", action="store_true")
    package_parser.add_argument("--json", action="store_true", dest="as_json")
    verify_parser = subparsers.add_parser(
        "verify-package", help="verify one immutable local service release package as a consumer"
    )
    verify_parser.add_argument("--package-dir", type=Path, default=None)
    verify_parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(list(argv) if argv is not None else None)
    mode = args.mode or "qualify"
    if mode == "generate":
        try:
            outputs = generate_descriptors(
                args.root,
                compilation_service_path=args.compilation_service,
                runtime_service_path=args.runtime_service,
                python_frontend_native_path=args.python_frontend_native,
                output_dir=args.output_dir,
                source_revision=args.source_revision,
            )
        except (OSError, ValueError) as exc:
            print(f"descriptor generation failed: {exc}", file=sys.stderr)
            return 2
        for path in outputs:
            print(path)
        return 0
    if mode == "image-descriptors":
        try:
            payload = generate_image_descriptors(
                args.root,
                compilation_service_path=args.compilation_service,
                runtime_service_path=args.runtime_service,
                python_frontend_native_path=args.python_frontend_native,
                output_dir=args.output_dir,
                source_revision=args.source_revision,
            )
        except (OSError, ValueError) as exc:
            print(f"image descriptor regeneration failed: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if mode == "package":
        try:
            payload = package_release(
                args.root,
                output_dir=args.output_dir,
                compilation_service_path=args.compilation_service,
                runtime_service_path=args.runtime_service,
                run_gates=not args.skip_gates,
                emit_gate_output=not args.as_json,
                qualified_descriptor_overlay=args.qualified_descriptor_overlay,
            )
        except (OSError, ValueError) as exc:
            payload = {
                "schema": LOCAL_ARTIFACT_SCHEMA,
                "owner": "agents",
                "qualification_scope": "owner-local",
                "external_live_approval": False,
                "qualified": False,
                "package": None,
                "diagnostics": [{"code": "package-failed", "message": str(exc)}],
            }
        if args.as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                "APXM local release artifact qualification: "
                + ("PASS" if payload.get("qualified") else "FAIL")
            )
            package = payload.get("package")
            if isinstance(package, dict):
                print(f"package.root: {package.get('root', '')}")
                print(f"package.manifest_digest: {package.get('manifest_digest', '')}")
            for diagnostic in payload.get("diagnostics", []):
                print(
                    f"[{diagnostic.get('code')}] {diagnostic.get('message')}",
                    file=sys.stderr,
                )
        return 0 if payload.get("qualified") else 1
    if mode == "verify-package" and args.package_dir is None:
        try:
            args.package_dir = declared_release_package_dir(REPOSITORY_ROOT)
        except (OSError, ValueError) as exc:
            print(f"consumer verification failed: {exc}", file=sys.stderr)
            return 2
    if mode == "verify-package":
        payload = verify_package(args.package_dir)
        if args.as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                "APXM consumer release package verification: "
                + ("PASS" if payload.get("qualified") else "FAIL")
            )
            for diagnostic in payload.get("diagnostics", []):
                print(
                    f"[{diagnostic.get('code')}] {diagnostic.get('message')}",
                    file=sys.stderr,
                )
        return 0 if payload.get("qualified") else 1
    result = qualify(
        args.root,
        compilation_service_path=args.compilation_service,
        runtime_service_path=args.runtime_service,
        run_gates=not args.skip_gates,
    )
    _print_result(result, as_json=args.as_json, root=args.root)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
