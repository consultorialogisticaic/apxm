//! Compilation Service Composition Root.
//!
//! Binds package snapshot validation, frontend selection, source-port compile,
//! package checks, and artifact commit. It does not depend on runtime execution.

mod stdio;

pub use stdio::{
    COMPILATION_CHANNEL, MAX_FRAME_BYTES, MAX_FRAMES_PER_CONNECTION, StdioFrame,
    UNIX_IO_TIMEOUT_MS, UnixEndpoint, decode_jsonl, encode_jsonl, handshake_cross_wired,
    serve_stdio, serve_unix,
};

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apxm_ais::permissions::{LayerDecisions, PermissionDecision, PermissionResolution};
use apxm_ais::{SLOT_CAPABILITY_REF, SemanticOpKind};
use apxm_artifact_registry::ArtifactRegistry;
use apxm_compilation_protocol::{
    ArtifactInventoryEntry, ArtifactRetentionHandshake, ArtifactRetentionRequest,
    ArtifactRetentionResult, CompilationHandshake, CompilationRequest, CompilationResult,
    CompileDiagnostic, DiagnosticReport, Location, Phase, ProtocolError, Severity,
};
use apxm_core::types::host_capability::{
    ManifestCapabilities, host_capability_ref, minted_host_capability_refs,
};
use apxm_program::{ExecutableArtifact, air::AirModule};
use apxm_runtime_protocol::{
    RuntimeRetirementHandshake, RuntimeRetirementRequest, RuntimeRetirementResult,
};
use apxm_source_port::{
    Frontend, FrontendDrivers, FrontendRoots, PackageSnapshot, SnapshotError, SourceBundleRequest,
    compile_source_bundle, content_digest, diagnostic_report,
};

pub use apxm_source_port::{
    CAPTURE_SCRATCH_DIR_VARIABLE, CONFINEMENT_BOUNDARY, CONFINEMENT_MODE_VARIABLE, ConfinementMode,
    ConfinementReadiness, ConfinementStatus, capture_confinement_readiness,
};

/// In-memory artifact store used to prove commit versus crash reconciliation.
#[derive(Default)]
pub struct ArtifactStore {
    committed: BTreeMap<String, String>,
}

impl ArtifactStore {
    /// Record a committed digest. Uncertain commits never appear here.
    pub fn commit(&mut self, digest: String, bytes: String) {
        self.committed.insert(digest, bytes);
    }

    /// Look up a previously committed artifact.
    #[must_use]
    pub fn get(&self, digest: &str) -> Option<&str> {
        self.committed.get(digest).map(String::as_str)
    }

    /// Whether any artifact has been committed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }
}

/// Compilation Service handler over the native protocol.
pub struct CompilationService {
    store: ArtifactStore,
    idempotency: BTreeMap<String, String>,
    roots: FrontendRoots,
    drivers: FrontendDrivers,
    artifact_dir: Option<PathBuf>,
    runtime_socket: Option<PathBuf>,
}

impl Default for CompilationService {
    fn default() -> Self {
        Self::from_env()
    }
}

impl CompilationService {
    pub fn handle_retention(
        &mut self,
        handshake: &ArtifactRetentionHandshake,
        request: ArtifactRetentionRequest,
    ) -> ArtifactRetentionResult {
        let request_id = match &request {
            ArtifactRetentionRequest::ArtifactRetain { request_id, .. }
            | ArtifactRetentionRequest::ArtifactRelease { request_id, .. }
            | ArtifactRetentionRequest::ArtifactInspect { request_id, .. }
            | ArtifactRetentionRequest::ArtifactInventorySeal { request_id, .. }
            | ArtifactRetentionRequest::ArtifactInventoryStatus { request_id }
            | ArtifactRetentionRequest::ArtifactCollect { request_id, .. } => request_id.clone(),
        };
        let failed = |code: &str| ArtifactRetentionResult::Failed {
            request_id: request_id.clone(),
            code: code.to_owned(),
        };
        if handshake.admit().is_err() || request_id.trim().is_empty() {
            return failed("invalid_request");
        }
        let Some(dir) = self.artifact_dir.as_ref() else {
            return failed("artifact_store_unavailable");
        };
        let registry = ArtifactRegistry::new(dir.clone());
        if matches!(
            request,
            ArtifactRetentionRequest::ArtifactInventoryStatus { .. }
        ) {
            return match registry.inventory() {
                Ok(artifacts) => ArtifactRetentionResult::ArtifactInventory {
                    request_id,
                    artifacts: artifacts
                        .into_iter()
                        .map(|value| ArtifactInventoryEntry {
                            artifact_digest: value.artifact_digest,
                            state: value.state,
                            live_references: value.live_references,
                            runtime_references: value.runtime_references,
                            unmanaged: value.unmanaged,
                        })
                        .collect(),
                },
                Err(error) => failed(retention_error_code(&error)),
            };
        }
        let operation = match request {
            ArtifactRetentionRequest::ArtifactRetain {
                artifact_digest,
                reference_id,
                ..
            } => {
                return match registry.retain(&artifact_digest, &reference_id) {
                    Ok((claim, _)) => ArtifactRetentionResult::ArtifactReferenceRetained {
                        request_id,
                        artifact_digest,
                        reference_id,
                        owner_claim: claim,
                    },
                    Err(error) => failed(retention_error_code(&error)),
                };
            }
            ArtifactRetentionRequest::ArtifactRelease {
                artifact_digest,
                reference_id,
                owner_claim,
                ..
            } => registry.release(&artifact_digest, &reference_id, &owner_claim),
            ArtifactRetentionRequest::ArtifactInspect {
                artifact_digest, ..
            } => registry.inspect(&artifact_digest),
            ArtifactRetentionRequest::ArtifactInventorySeal {
                artifact_digest,
                reference_ids,
                ..
            } => registry.seal_inventory(&artifact_digest, &reference_ids),
            ArtifactRetentionRequest::ArtifactInventoryStatus { .. } => {
                unreachable!("handled above")
            }
            ArtifactRetentionRequest::ArtifactCollect {
                artifact_digest, ..
            } => {
                let Some(socket) = self.runtime_socket.as_ref() else {
                    return failed("runtime_reference_unavailable");
                };
                let Ok(live) = runtime_artifact_count(socket, &artifact_digest, &request_id) else {
                    return failed("runtime_reference_unavailable");
                };
                registry.collect(&artifact_digest, live)
            }
        };
        match operation {
            Ok(value) => ArtifactRetentionResult::ArtifactDisposition {
                request_id,
                artifact_digest: value.artifact_digest,
                state: value.state,
                live_references: value.live_references,
                runtime_references: value.runtime_references,
                unmanaged: value.unmanaged,
            },
            Err(error) => failed(retention_error_code(&error)),
        }
    }

    /// Bind exact frontend package roots and interpreter drivers.
    #[must_use]
    pub fn with_frontends(roots: FrontendRoots, drivers: FrontendDrivers) -> Self {
        Self {
            store: ArtifactStore::default(),
            idempotency: BTreeMap::new(),
            roots,
            drivers,
            artifact_dir: None,
            runtime_socket: None,
        }
    }

    /// Product handler. Persists committed artifacts when `APXM_ARTIFACT_DIR` is set.
    #[must_use]
    pub fn from_env() -> Self {
        let mut service =
            Self::with_frontends(declared_frontend_roots(), declared_frontend_drivers());
        if let Ok(dir) = std::env::var("APXM_ARTIFACT_DIR")
            && !dir.trim().is_empty()
        {
            service.artifact_dir = Some(PathBuf::from(dir));
        }
        if let Ok(socket) = std::env::var("APXM_RUNTIME_SOCKET")
            && !socket.trim().is_empty()
        {
            service.runtime_socket = Some(PathBuf::from(socket));
        }
        service
    }

    /// Persist committed executable artifacts under `dir` so a Runtime child
    /// can load and verify the exact canonical envelope.
    #[must_use]
    pub fn with_artifact_dir(mut self, dir: PathBuf) -> Self {
        self.artifact_dir = Some(dir);
        self
    }

    #[must_use]
    pub fn with_runtime_socket(mut self, socket: PathBuf) -> Self {
        self.runtime_socket = Some(socket);
        self
    }

    /// Admit a handshake and request. Runtime methods are unrepresentable.
    pub fn handle(
        &mut self,
        handshake: &CompilationHandshake,
        request: CompilationRequest,
    ) -> Result<CompilationResult, ProtocolError> {
        handshake.admit()?;
        match request {
            CompilationRequest::Compile {
                request_id,
                idempotency_key,
                snapshot,
            } => self.compile(request_id, idempotency_key, snapshot),
            CompilationRequest::Cancel {
                request_id,
                target_request_id,
            } => {
                if request_id.trim().is_empty() || target_request_id.trim().is_empty() {
                    return Err(ProtocolError::InvalidRequest);
                }
                Ok(CompilationResult::Cancelled { request_id })
            }
        }
    }

    /// Committed artifacts only. Failed compiles have no store entry.
    #[must_use]
    pub fn store(&self) -> &ArtifactStore {
        &self.store
    }

    fn compile(
        &mut self,
        request_id: String,
        idempotency_key: String,
        snapshot: PackageSnapshot,
    ) -> Result<CompilationResult, ProtocolError> {
        if request_id.trim().is_empty() || idempotency_key.trim().is_empty() {
            return Err(ProtocolError::InvalidRequest);
        }
        if let Err(error) = snapshot.validate() {
            return Ok(CompilationResult::failed(
                request_id,
                package_failure(snapshot_error_code(error)),
            ));
        }
        let fingerprint = snapshot.snapshot_digest.clone();
        if let Some(prior) = self.idempotency.get(&idempotency_key)
            && prior != &fingerprint
        {
            return Err(ProtocolError::ConflictingIdempotency);
        }
        self.idempotency.insert(idempotency_key, fingerprint);

        match compile_snapshot(&snapshot, &self.roots, &self.drivers) {
            Ok(CompiledSnapshot {
                artifact_json,
                diagnostics,
            }) => {
                let artifact = ExecutableArtifact::decode(artifact_json.as_bytes())
                    .map_err(|_| ProtocolError::InvalidRequest)?;
                let artifact_digest = artifact.artifact_digest.clone();
                let execution_lineage_ref = artifact
                    .execution_lineage_ref
                    .clone()
                    .ok_or(ProtocolError::InvalidRequest)?;
                if let Some(dir) = &self.artifact_dir
                    && ArtifactRegistry::new(dir.clone())
                        .publish(&artifact_digest, artifact_json.as_bytes())
                        .is_err()
                {
                    return Ok(CompilationResult::failed_with(
                        request_id,
                        "artifact_persist",
                        Phase::Admission,
                        "the compiled artifact could not be persisted to the artifact store",
                    ));
                }
                self.store.commit(artifact_digest.clone(), artifact_json);
                Ok(CompilationResult::ArtifactCommitted {
                    request_id,
                    artifact_digest,
                    artifact: Box::new(artifact),
                    execution_lineage_ref,
                    build_key: format!("{}:{}", snapshot.frontend.wire(), snapshot.snapshot_digest),
                    diagnostics,
                })
            }
            Err(diagnostics) => Ok(CompilationResult::failed(request_id, diagnostics)),
        }
    }
}

fn runtime_artifact_count(socket: &Path, digest: &str, request_id: &str) -> Result<u32, String> {
    if !socket.is_absolute() {
        return Err("Runtime socket is not absolute".to_owned());
    }
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let id = format!("{request_id}:artifact-reference-inspect");
    let payload = serde_json::json!({
        "handshake": RuntimeRetirementHandshake::server(),
        "request": RuntimeRetirementRequest::ArtifactReferenceInspect {
            request_id: id.clone(), artifact_digest: digest.to_owned(),
        },
    });
    let frame = serde_json::json!({"channel":"runtime", "payload": payload.to_string()});
    stream
        .write_all(format!("{frame}\n").as_bytes())
        .map_err(|error| error.to_string())?;
    let mut reader = std::io::BufReader::new(stream.take(8 * 1024 * 1024));
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let reply: serde_json::Value =
        serde_json::from_str(&line).map_err(|error| error.to_string())?;
    if reply.get("channel").and_then(serde_json::Value::as_str) != Some("runtime") {
        return Err("Runtime reference channel mismatch".to_owned());
    }
    let body = reply
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .ok_or("Runtime reference response is empty")?;
    match serde_json::from_str::<RuntimeRetirementResult>(body)
        .map_err(|error| error.to_string())?
    {
        RuntimeRetirementResult::ArtifactReferenceCount {
            request_id: response_id,
            artifact_digest,
            live_instances,
        } if response_id == id && artifact_digest == digest => Ok(live_instances),
        _ => Err("Runtime reference response is not exact".to_owned()),
    }
}

fn retention_error_code(error: &str) -> &str {
    match error {
        "unknown_artifact"
        | "unknown_reference"
        | "owner_mismatch"
        | "reference_released"
        | "artifact_purged"
        | "inventory_mismatch"
        | "duplicate_reference"
        | "artifact_reference_capacity_exhausted" => error,
        "invalid artifact digest" => "invalid_artifact_digest",
        "invalid reference id" => "invalid_reference_id",
        _ => "artifact_store_unavailable",
    }
}

/// A compiled snapshot: the canonical artifact bytes and the non-error
/// diagnostics raised producing them.
struct CompiledSnapshot {
    artifact_json: String,
    diagnostics: DiagnosticReport,
}

/// The human explanation of a package-phase code. The code is the contract;
/// this text is never used for control flow.
fn package_message(code: &str) -> &'static str {
    match code {
        "unsupported_contract" => "the package snapshot names an unsupported snapshot contract",
        "incomplete_snapshot" => "the package snapshot is incomplete",
        "unsafe_path" => "the package snapshot contains an unsafe path",
        "digest_mismatch" => "a package file does not match its recorded digest",
        "duplicate_path" => "the package snapshot repeats a path",
        "lock_drift" => "the package lock does not match its recorded digest",
        "missing_entrypoint" => "the package entrypoint is not in the snapshot",
        "missing_frontend" => "the package manifest declares no [compile] frontend",
        "invalid_manifest" => "the package manifest is not a valid agent.toml",
        "frontend_mismatch" => {
            "the package manifest's frontend differs from the snapshot's frontend"
        }
        "entrypoint_mismatch" => {
            "the package manifest's entry differs from the snapshot's entrypoint"
        }
        "integrity_invalid" => "the package integrity record is not a valid integrity.toml",
        "integrity_mismatch" => "the package integrity record does not match the package files",
        "entrypoint_not_utf8" => "the package entrypoint is not UTF-8 text",
        "missing_program" => "the package entrypoint declares no authored Agent or Workflow",
        _ => "the package was rejected",
    }
}

/// One package-phase error; no later phase ran.
fn package_failure(code: &str) -> DiagnosticReport {
    DiagnosticReport::from_diagnostics(
        [CompileDiagnostic::new(
            Severity::Error,
            code,
            Phase::Package,
            package_message(code),
        )],
        Some(Phase::Package),
    )
}

/// File name for a digest in a shared artifact directory (`:` is not portable).
#[must_use]
pub fn artifact_file_name(digest: &str) -> String {
    digest.replace(':', "-")
}

#[cfg(test)]
fn persist_artifact(dir: &Path, digest: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    let directory = std::fs::symlink_metadata(dir).map_err(|error| error.to_string())?;
    if directory.file_type().is_symlink() || !directory.is_dir() {
        return Err(format!(
            "artifact directory '{}' is not a real directory",
            dir.display()
        ));
    }
    let path = dir.join(artifact_file_name(digest));
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "artifact path '{}' is not a regular file",
                    path.display()
                ));
            }
            let existing = std::fs::read(&path).map_err(|error| error.to_string())?;
            if existing == bytes {
                return Ok(());
            }
            return Err(format!(
                "artifact path '{}' already contains different bytes",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }

    use std::io::Write as _;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another compiler worker won the create race. Reconcile only
            // against the digest-bound bytes; never truncate or follow a
            // path that appeared after the initial check.
            let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "artifact path '{}' is not a regular file",
                    path.display()
                ));
            }
            let existing = std::fs::read(&path).map_err(|e| e.to_string())?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(format!(
                    "artifact path '{}' already contains different bytes",
                    path.display()
                ))
            };
        }
        Err(error) => return Err(error.to_string()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn snapshot_error_code(error: SnapshotError) -> &'static str {
    match error {
        SnapshotError::UnsupportedContract => "unsupported_contract",
        SnapshotError::Incomplete => "incomplete_snapshot",
        SnapshotError::UnsafePath => "unsafe_path",
        SnapshotError::DigestMismatch => "digest_mismatch",
        SnapshotError::DuplicatePath => "duplicate_path",
        SnapshotError::LockDrift => "lock_drift",
        SnapshotError::MissingEntrypoint => "missing_entrypoint",
    }
}

fn compile_snapshot(
    snapshot: &PackageSnapshot,
    roots: &FrontendRoots,
    drivers: &FrontendDrivers,
) -> Result<CompiledSnapshot, DiagnosticReport> {
    let manifest = declared_manifest(snapshot).map_err(|code| package_failure(&code))?;
    if manifest.frontend != snapshot.frontend {
        return Err(package_failure("frontend_mismatch"));
    }
    if manifest.entry != snapshot.entrypoint {
        return Err(package_failure("entrypoint_mismatch"));
    }
    verify_integrity(snapshot).map_err(|code| package_failure(&code))?;

    let entry = snapshot
        .file(&snapshot.entrypoint)
        .ok_or_else(|| package_failure("missing_entrypoint"))?;
    let source = String::from_utf8(entry.bytes.clone())
        .map_err(|_| package_failure("entrypoint_not_utf8"))?;
    let program =
        authored_program_name(snapshot.frontend, &source).map_err(|code| package_failure(&code))?;
    let compiled = compile_source_bundle(
        &SourceBundleRequest::new(snapshot.frontend, program, source)
            .with_host_capabilities(manifest.host_capabilities.clone()),
        roots,
        drivers,
    )
    .map_err(|diagnostics| diagnostic_report(&diagnostics))?;
    // Admission reports every refusal it finds, then stops: nothing after
    // admission runs over a program it refused.
    let warnings = compiled
        .diagnostics
        .iter()
        .map(apxm_source_port::SourceDiagnostic::to_compile_diagnostic)
        .collect::<Vec<_>>();
    let mut refusals = check_capability_references(snapshot, &manifest, &compiled.air);
    refusals.extend(check_package_permissions(
        snapshot,
        &compiled.air,
        &manifest,
    ));
    if !refusals.is_empty() {
        return Err(DiagnosticReport::from_diagnostics(
            warnings.into_iter().chain(refusals),
            Some(Phase::Admission),
        ));
    }
    let artifact = ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
        .map_err(|error| {
            DiagnosticReport::from_diagnostics(
                warnings
                    .iter()
                    .cloned()
                    .chain(artifact_build_diagnostics(error)),
                Some(Phase::Lowering),
            )
        })?;
    let artifact_json = serde_json::to_string(&artifact).map_err(|_| {
        DiagnosticReport::from_diagnostics(
            [CompileDiagnostic::new(
                Severity::Error,
                "artifact_codec",
                Phase::Lowering,
                "the executable artifact could not be encoded",
            )],
            Some(Phase::Lowering),
        )
    })?;
    Ok(CompiledSnapshot {
        artifact_json,
        diagnostics: DiagnosticReport::from_diagnostics(warnings, None),
    })
}

/// Every verifier diagnostic an artifact build raised, under its own code.
fn artifact_build_diagnostics(error: apxm_program::ArtifactBuildError) -> Vec<CompileDiagnostic> {
    let verdict = match error {
        apxm_program::ArtifactBuildError::Lowering(verdict)
        | apxm_program::ArtifactBuildError::Requirements(verdict)
        | apxm_program::ArtifactBuildError::Validation(verdict) => verdict,
        apxm_program::ArtifactBuildError::Codec(_) => {
            return vec![CompileDiagnostic::new(
                Severity::Error,
                "artifact_codec",
                Phase::Lowering,
                "the executable artifact could not be encoded",
            )];
        }
    };
    let diagnostics = verdict
        .into_diagnostics()
        .into_iter()
        .map(|diagnostic| {
            let mut item = CompileDiagnostic::new(
                Severity::Error,
                diagnostic.code.slug(),
                Phase::Lowering,
                diagnostic.message,
            );
            if !diagnostic.location.is_empty() {
                item.field_path = Some(
                    diagnostic
                        .location
                        .split('.')
                        .filter(|segment| !segment.is_empty())
                        .map(str::to_owned)
                        .collect(),
                );
            }
            item
        })
        .collect::<Vec<_>>();
    if diagnostics.is_empty() {
        vec![CompileDiagnostic::new(
            Severity::Error,
            "artifact_rejected",
            Phase::Lowering,
            "the executable artifact did not validate",
        )]
    } else {
        diagnostics
    }
}

#[derive(Debug, serde::Deserialize)]
struct AgentManifest {
    #[serde(default)]
    compile: Option<CompileManifest>,
    #[serde(default)]
    capabilities: ManifestCapabilities,
    #[serde(default)]
    permissions: BTreeMap<String, PermissionDecision>,
}

#[derive(Debug, serde::Deserialize)]
struct CompileManifest {
    entry: Option<String>,
    frontend: Option<Frontend>,
}

struct DeclaredManifest {
    frontend: Frontend,
    entry: String,
    /// The host capability ids `[[capabilities.host]]` declares, without the
    /// reserved prefix. Passed into capture so the frontend's minted set is the
    /// catalogue united with these, and united into the granted set so the
    /// admission below admits the references they mint.
    host_capabilities: Vec<String>,
    permissions: BTreeMap<String, PermissionDecision>,
}

fn declared_manifest(snapshot: &PackageSnapshot) -> Result<DeclaredManifest, String> {
    let Some(agent) = snapshot.file("agent.toml") else {
        return Err("missing_frontend".to_owned());
    };
    let text = String::from_utf8(agent.bytes.clone()).map_err(|_| "invalid_manifest".to_owned())?;
    let parsed: AgentManifest = toml::from_str(&text).map_err(|_| "invalid_manifest".to_owned())?;
    let compile = parsed
        .compile
        .ok_or_else(|| "missing_frontend".to_owned())?;
    let frontend = compile
        .frontend
        .ok_or_else(|| "missing_frontend".to_owned())?;
    let entry = compile
        .entry
        .ok_or_else(|| "missing_entrypoint".to_owned())?;
    let host_capabilities = parsed
        .capabilities
        .host
        .iter()
        .map(|declaration| declaration.id.clone())
        .collect::<Vec<_>>();
    minted_host_capability_refs(&parsed.capabilities.host)
        .map_err(|_| "invalid_manifest".to_owned())?;
    Ok(DeclaredManifest {
        frontend,
        entry,
        host_capabilities,
        permissions: parsed.permissions,
    })
}

fn authored_program_name(frontend: Frontend, source: &str) -> Result<String, String> {
    let mut found = None;
    match frontend {
        Frontend::Python => {
            // Keep the source scan linear. A package may contain many child
            // Agents, and rescanning the suffix after every decorator makes
            // authored-program discovery quadratic in source size.
            let mut awaiting_agent = false;
            let mut decorator_depth = 0usize;
            let mut python_string = None;
            for line in source.lines() {
                let code = strip_python_non_code(line, &mut python_string);
                let trimmed = code.trim_start();
                // A source comment or string is data, not an Agent
                // declaration. Only a decorator at the beginning of a Python
                // logical line may arm discovery.
                if trimmed.starts_with('#') {
                    continue;
                }
                if is_python_agent_decorator(trimmed) {
                    awaiting_agent = true;
                    decorator_depth = parenthesis_depth(trimmed);
                    continue;
                }
                if !awaiting_agent {
                    continue;
                }
                if decorator_depth > 0 {
                    let closes = trimmed.bytes().filter(|byte| *byte == b')').count();
                    let opens = trimmed.bytes().filter(|byte| *byte == b'(').count();
                    decorator_depth = decorator_depth.saturating_add(opens).saturating_sub(closes);
                    continue;
                }
                if trimmed.is_empty() || trimmed.starts_with('@') {
                    continue;
                }
                let rest = trimmed
                    .strip_prefix("async def ")
                    .or_else(|| trimmed.strip_prefix("def "));
                let Some(rest) = rest else {
                    // Do not let an arbitrary statement after a decorator
                    // bind a later function name.
                    awaiting_agent = false;
                    continue;
                };
                let name = rest.split('(').next().unwrap_or("").trim();
                awaiting_agent = false;
                if !is_identifier(name) {
                    continue;
                }
                // A composition root may declare child Agent Programs in
                // the same file. The last `@Agent` is the package entry.
                found = Some(name.to_owned());
            }
        }
        Frontend::Typescript => {
            let mut in_block_comment = false;
            for line in source.lines() {
                let line = strip_typescript_comments(line, &mut in_block_comment);
                let trimmed = line.trim_start();
                let Some((before, after)) = trimmed.split_once('=') else {
                    continue;
                };
                let mut tokens = before.split_whitespace();
                let Some(name) = tokens.next_back() else {
                    continue;
                };
                if tokens.next_back() != Some("const")
                    || !tokens.all(|token| token == "export" || token == "declare")
                    || !is_identifier(name)
                {
                    continue;
                }
                let after = after.trim_start();
                if !["Agent", "Workflow"].iter().any(|name| {
                    after.strip_prefix(name).is_some_and(|tail| {
                        tail.chars().next().is_some_and(|character| {
                            character == '<' || character == '(' || character.is_whitespace()
                        })
                    })
                }) {
                    continue;
                }
                found = Some(name.to_owned());
            }
        }
    }
    found.ok_or_else(|| "missing_program".to_owned())
}

fn is_python_agent_decorator(line: &str) -> bool {
    ["@Agent", "@Workflow"].iter().any(|name| {
        line.strip_prefix(name)
            .is_some_and(|rest| rest.is_empty() || rest.trim_start().starts_with('('))
    })
}

fn parenthesis_depth(line: &str) -> usize {
    line.bytes().fold(0usize, |depth, byte| match byte {
        b'(' => depth.saturating_add(1),
        b')' => depth.saturating_sub(1),
        _ => depth,
    })
}

/// Remove Python strings and comments before looking for decorators. The
/// service only needs a tiny lexical view here; the frontend remains the
/// authority for syntax and Agent semantics. Keeping quoted text out of this
/// scan prevents prompt-like examples in docstrings from selecting a fake
/// package root.
fn strip_python_non_code(line: &str, string: &mut Option<(char, bool)>) -> String {
    let mut output = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if let Some((quote, triple)) = *string {
            if triple && bytes[index..].starts_with(&[quote as u8; 3]) {
                *string = None;
                index += 3;
                continue;
            }
            if !triple && bytes[index] == quote as u8 {
                *string = None;
                index += 1;
                continue;
            }
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
            } else {
                index += 1;
            }
            continue;
        }

        match bytes[index] {
            b'#' => break,
            b'\'' | b'"' => {
                let quote = bytes[index] as char;
                let triple = bytes[index..].starts_with(&[bytes[index]; 3]);
                *string = Some((quote, triple));
                index += if triple { 3 } else { 1 };
            }
            byte => {
                output.push(byte as char);
                index += 1;
            }
        }
    }
    output
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn strip_typescript_comments(line: &str, in_block_comment: &mut bool) -> String {
    let mut output = String::with_capacity(line.len());
    let mut cursor = 0;
    while cursor < line.len() {
        if *in_block_comment {
            let Some(end) = line[cursor..].find("*/") else {
                return output;
            };
            cursor += end + 2;
            *in_block_comment = false;
            continue;
        }
        let remainder = &line[cursor..];
        let line_comment = remainder.find("//");
        let block_comment = remainder.find("/*");
        match (line_comment, block_comment) {
            (Some(line_index), Some(block_index)) if line_index < block_index => {
                output.push_str(&remainder[..line_index]);
                break;
            }
            (Some(line_index), None) => {
                output.push_str(&remainder[..line_index]);
                break;
            }
            (_, Some(block_index)) => {
                output.push_str(&remainder[..block_index]);
                cursor += block_index + 2;
                *in_block_comment = true;
            }
            (None, None) => {
                output.push_str(remainder);
                break;
            }
        }
    }
    output
}

fn verify_integrity(snapshot: &PackageSnapshot) -> Result<(), String> {
    let Some(integrity) = snapshot.file("integrity.toml") else {
        return Ok(());
    };
    let text =
        String::from_utf8(integrity.bytes.clone()).map_err(|_| "integrity_invalid".to_owned())?;
    let recorded: IntegrityToml =
        toml::from_str(&text).map_err(|_| "integrity_invalid".to_owned())?;
    if recorded.algorithm != "sha256" {
        return Err("integrity_invalid".to_owned());
    }
    let mut files = BTreeMap::new();
    for link in &recorded.chain {
        let content = snapshot
            .file(&link.path)
            .ok_or_else(|| "integrity_mismatch".to_owned())?;
        files.insert(link.path.clone(), content.digest.clone());
    }
    let expected = compute_integrity(&files);
    if recorded != expected {
        return Err("integrity_mismatch".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct IntegrityToml {
    algorithm: String,
    hash: String,
    chain: Vec<ChainLinkToml>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct ChainLinkToml {
    path: String,
    prev_hash: String,
    hash: String,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn compute_integrity(files: &BTreeMap<String, String>) -> IntegrityToml {
    let mut prev = GENESIS_HASH.to_owned();
    let mut chain = Vec::with_capacity(files.len());
    for (path, digest) in files {
        let mut preimage = String::with_capacity(prev.len() + path.len() + digest.len());
        preimage.push_str(&prev);
        preimage.push_str(path);
        preimage.push_str(digest);
        let hash = content_digest(preimage.as_bytes());
        chain.push(ChainLinkToml {
            path: path.clone(),
            prev_hash: prev.clone(),
            hash: hash.clone(),
        });
        prev = hash;
    }
    let hash = chain
        .last()
        .map_or_else(|| GENESIS_HASH.to_owned(), |link| link.hash.clone());
    IntegrityToml {
        algorithm: "sha256".to_owned(),
        hash,
        chain,
    }
}

fn granted_capability_ids(
    snapshot: &PackageSnapshot,
    manifest: &DeclaredManifest,
) -> BTreeSet<String> {
    let mut granted = apxm_ais::capabilities::BUILTINS
        .iter()
        .map(|id| (*id).to_owned())
        .collect::<BTreeSet<_>>();
    granted.extend(
        manifest
            .host_capabilities
            .iter()
            .map(|id| host_capability_ref(id)),
    );
    for content in &snapshot.contents {
        let Some((id, file)) = content.path.strip_prefix("capabilities/").and_then(|rest| {
            let (id, file) = rest.split_once('/')?;
            Some((id, file))
        }) else {
            continue;
        };
        if file == "handler.py" || file == "handler.ts" {
            granted.insert(id.to_owned());
        }
    }
    granted
}

/// One admission error per semantic operation that invokes a capability the
/// package does not grant, located at the operation's source span.
fn check_capability_references(
    snapshot: &PackageSnapshot,
    manifest: &DeclaredManifest,
    module: &AirModule,
) -> Vec<CompileDiagnostic> {
    let granted = granted_capability_ids(snapshot, manifest);
    module
        .semantic_operations
        .iter()
        .filter(|operation| operation.op == SemanticOpKind::CapabilityInvoke)
        .filter_map(|operation| {
            let capability_ref = operation
                .operands
                .iter()
                .find(|operand| operand.slot == SLOT_CAPABILITY_REF)
                .map(|operand| operand.value_id.as_str())?;
            if granted.contains(capability_ref) {
                return None;
            }
            let mut item = CompileDiagnostic::new(
                Severity::Error,
                "ungranted_capability",
                Phase::Admission,
                format!(
                    "the program invokes the Capability '{capability_ref}', which the package \
                     neither declares nor ships a handler for"
                ),
            );
            item.node_id = Some(operation.node_id.clone());
            item.location = module
                .source_map
                .node_spans
                .iter()
                .find(|span| span.node_id == operation.node_id)
                .map(|span| Location {
                    source_file: span.source_file.clone(),
                    span: span.span,
                });
            Some(item)
        })
        .collect()
}

fn check_package_permissions(
    snapshot: &PackageSnapshot,
    module: &AirModule,
    manifest: &DeclaredManifest,
) -> Option<CompileDiagnostic> {
    let grantable = granted_capability_ids(snapshot, manifest);
    let requested: LayerDecisions = grantable
        .iter()
        .map(|id| {
            (
                id.clone(),
                module
                    .capability_permission_requests
                    .get(id)
                    .cloned()
                    .unwrap_or_else(PermissionDecision::allow),
            )
        })
        .collect();
    PermissionResolution::resolve_code_over_package(
        requested,
        manifest.permissions.clone().into_iter().collect(),
    )
    .err()
    .map(|_| {
        CompileDiagnostic::new(
            Severity::Error,
            "permission_widening",
            Phase::Admission,
            "the program requests a Capability permission wider than the package manifest allows",
        )
    })
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("the compilation-service crate sits three levels under the repository root")
        .to_path_buf()
}

fn declared_frontend_roots() -> FrontendRoots {
    let root = workspace_root();
    FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    )
}

fn declared_frontend_drivers() -> FrontendDrivers {
    let root = workspace_root();
    let python = std::env::var_os("APXM_PYTHON_DRIVER")
        .map_or_else(|| root.join(".dekk/env/bin/python"), PathBuf::from);
    let node = std::env::var_os("APXM_TYPESCRIPT_DRIVER")
        .map_or_else(|| root.join(".dekk/env/bin/node"), PathBuf::from);
    FrontendDrivers::new(python, node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apxm_compilation_protocol::{COMPILATION_PROTOCOL_VERSION, CompilationRequest};
    use apxm_source_port::{Frontend, SnapshotContent};

    #[test]
    fn artifact_inventory_reports_legacy_blob_and_collect_requires_runtime_proof() {
        let directory = std::env::temp_dir().join(format!(
            "apxm-retention-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&directory).expect("artifact directory");
        let digest = format!("sha256:{}", "a".repeat(64));
        std::fs::write(directory.join(digest.replace(':', "-")), b"legacy").expect("legacy blob");
        let mut service = CompilationService::with_frontends(
            declared_frontend_roots(),
            declared_frontend_drivers(),
        );
        service.artifact_dir = Some(directory.clone());
        let handshake = ArtifactRetentionHandshake::server();
        let inventory = service.handle_retention(
            &handshake,
            ArtifactRetentionRequest::ArtifactInventoryStatus {
                request_id: "inventory".to_owned(),
            },
        );
        let ArtifactRetentionResult::ArtifactInventory { artifacts, .. } = inventory else {
            panic!("legacy blob missing from inventory");
        };
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_digest, digest);
        assert!(artifacts[0].unmanaged);
        let collect = service.handle_retention(
            &handshake,
            ArtifactRetentionRequest::ArtifactCollect {
                request_id: "collect".to_owned(),
                artifact_digest: digest.clone(),
            },
        );
        assert_eq!(
            collect,
            ArtifactRetentionResult::Failed {
                request_id: "collect".to_owned(),
                code: "runtime_reference_unavailable".to_owned(),
            }
        );
        assert!(directory.join(digest.replace(':', "-")).exists());
        std::fs::remove_dir_all(directory).expect("remove isolated test directory");
    }

    const PYTHON_PROGRAM: &str = r#"from apxm_program import Agent, Model, Tool


class ReviewRequest:
    pass


class Review:
    pass


ReviewModel = Model[ReviewRequest, Review]("review.model")
SearchWeb = Tool[ReviewRequest, Review]("search_web")


@Agent(input=ReviewRequest, output=Review, model=ReviewModel)
async def Reviewer(agent, request):
    evidence = await SearchWeb(request)
    return await ReviewModel(evidence)
"#;

    const TYPESCRIPT_PROGRAM: &str = r#"import { Agent, Model, Tool } from "@apxm/frontend";
import { source } from "@apxm/frontend/node";

source(import.meta.url);

type ReviewRequest = object;
type Review = object;

const ReviewModel = Model<ReviewRequest, Review>("review.model");
const SearchWeb = Tool<ReviewRequest, Review>("search_web");

export const Reviewer = Agent<ReviewRequest, Review>({
  name: "Reviewer",
  model: ReviewModel,
  async run(agent, request) {
    const evidence = await SearchWeb(request);
    return await ReviewModel(evidence);
  },
});
"#;

    fn handshake() -> CompilationHandshake {
        CompilationHandshake {
            protocol_version: COMPILATION_PROTOCOL_VERSION.to_owned(),
        }
    }

    fn frontend_present(frontend: Frontend) -> bool {
        let root = declared_frontend_roots().root(frontend).to_path_buf();
        let driver = declared_frontend_drivers().driver(frontend).to_path_buf();
        if !driver.is_file() {
            return false;
        }
        match frontend {
            Frontend::Python => root.join("apxm_program/_native.so").is_file(),
            Frontend::Typescript => {
                root.join("dist/index.js").is_file()
                    && root.join("dist/node.js").is_file()
                    && root.join("dist/_native.node").is_file()
                    && root
                        .join("node_modules/typescript/lib/typescript.js")
                        .is_file()
            }
        }
    }

    fn agent_toml(frontend: Frontend, entry: &str) -> String {
        format!(
            "id = \"tiny\"\nversion = \"0.1.0\"\nschema_version = \"apxm.agent\"\n\n[compile]\nentry = \"{entry}\"\nfrontend = \"{}\"\n",
            frontend.wire()
        )
    }

    fn package_snapshot(frontend: Frontend, entry: &str, source: &str) -> PackageSnapshot {
        package_snapshot_with(frontend, entry, source, "")
    }

    const NOTES_SEARCH_HOST: &str = "\n[[capabilities.host]]\nid = \"notes.search\"\neffect = \"read\"\ninput_schema = { type = \"object\" }\noutput_schema = { type = \"object\" }\n";

    fn package_snapshot_with(
        frontend: Frontend,
        entry: &str,
        source: &str,
        manifest_tail: &str,
    ) -> PackageSnapshot {
        let mut contents = vec![
            SnapshotContent::from_bytes(
                "agent.toml",
                format!("{}{manifest_tail}", agent_toml(frontend, entry)).into_bytes(),
            ),
            SnapshotContent::from_bytes(entry, source.as_bytes().to_vec()),
        ];
        let files = contents
            .iter()
            .map(|content| (content.path.clone(), content.digest.clone()))
            .collect();
        let integrity = compute_integrity(&files);
        contents.push(SnapshotContent::from_bytes(
            "integrity.toml",
            toml::to_string(&integrity).expect("integrity").into_bytes(),
        ));
        PackageSnapshot::assemble(
            frontend,
            entry,
            contents,
            None,
            "apxm.compatibility-set/test",
        )
        .expect("fixture snapshot")
    }

    #[test]
    fn python_and_typescript_commit_through_one_handler() {
        let directory = std::env::temp_dir().join(format!(
            "apxm-compiled-store-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut service = CompilationService::default().with_artifact_dir(directory.clone());
        for (frontend, entry, source) in [
            (Frontend::Python, "src/agent.py", PYTHON_PROGRAM),
            (Frontend::Typescript, "src/agent.ts", TYPESCRIPT_PROGRAM),
        ] {
            if !frontend_present(frontend) {
                continue;
            }
            let result = service
                .handle(
                    &handshake(),
                    CompilationRequest::Compile {
                        request_id: frontend.wire().to_owned(),
                        idempotency_key: frontend.wire().to_owned(),
                        snapshot: package_snapshot(frontend, entry, source),
                    },
                )
                .unwrap();
            assert!(result.diagnostics_are_consistent(), "{result:?}");
            let CompilationResult::ArtifactCommitted {
                artifact_digest,
                execution_lineage_ref,
                diagnostics,
                ..
            } = result
            else {
                panic!("commit for {}", frontend.wire());
            };
            assert!(execution_lineage_ref.starts_with("sha256:"));
            assert_eq!(diagnostics, DiagnosticReport::empty());
            let bytes = service
                .store()
                .get(&artifact_digest)
                .expect("store holds committed artifact");
            let artifact = ExecutableArtifact::decode(bytes.as_bytes()).expect("artifact JSON");
            assert_eq!(
                artifact.artifact_digest,
                artifact.canonical_digest().unwrap()
            );
            assert!(artifact.execution_lineage_ref.is_some());
            assert_eq!(artifact.source_map, artifact.air.source_map);
            let air = artifact.air;
            assert!(
                !air.semantic_operations.is_empty(),
                "{} artifact must contain compiled AIR",
                frontend.wire()
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compiled_wire_keeps_the_artifact_canonical_bytes() {
        if !frontend_present(Frontend::Typescript) {
            return;
        }
        let snapshot = package_snapshot(Frontend::Typescript, "src/agent.ts", TYPESCRIPT_PROGRAM);
        let frame = crate::StdioFrame {
            channel: crate::COMPILATION_CHANNEL.to_owned(),
            payload: serde_json::json!({
                "handshake": handshake(),
                "request": CompilationRequest::Compile {
                    request_id: "wire-canonical".to_owned(),
                    idempotency_key: "wire-canonical".to_owned(),
                    snapshot,
                },
            })
            .to_string(),
        };
        let mut output = Vec::new();
        crate::serve_stdio(
            crate::encode_jsonl(&frame).as_bytes(),
            &mut output,
            CompilationService::default(),
        )
        .expect("wire compile");
        let reply = crate::decode_jsonl(std::str::from_utf8(&output).unwrap()).unwrap();
        let result: CompilationResult = serde_json::from_str(&reply.payload).unwrap();
        let CompilationResult::ArtifactCommitted { artifact, .. } = result else {
            panic!("expected a committed artifact");
        };
        let encoded = artifact.encode().unwrap();
        let fragment = format!("\"artifact\":{}", std::str::from_utf8(&encoded).unwrap());
        assert!(
            reply.payload.contains(&fragment),
            "wire reordered the artifact"
        );
        ExecutableArtifact::decode_for_execution(&encoded, &artifact.artifact_digest)
            .expect("wire artifact digest remains canonical");
    }

    #[test]
    fn last_agent_in_the_entry_file_is_the_package_root() {
        if !frontend_present(Frontend::Python) {
            return;
        }
        let source = r#"
from typing import TypedDict
from apxm_program import Agent, Workflow, Event, EventRef, Model

class Approved(TypedDict):
    approved: bool

class In(TypedDict):
    message: str
    approval: EventRef[Approved]

class Out(TypedDict):
    message: str

ChildModel = Model[In, Out]("model.child")
Approval = Event[Approved]("event.harness.approval")

@Agent(input=In, output=Out, model=ChildModel)
async def Child(agent, request):
    return await ChildModel(request)

@Workflow(input=In, output=Out)
async def Harness(agent, request):
    while True:
        child = Child.new()
        review = await child.invoke(request)
        approved = await Approval.wait(request["approval"])
        request = await agent.yield_(review)
"#;
        let mut service = CompilationService::default();
        let result = service
            .handle(
                &handshake(),
                CompilationRequest::Compile {
                    request_id: "harness".to_owned(),
                    idempotency_key: "harness".to_owned(),
                    snapshot: package_snapshot(Frontend::Python, "src/agent.py", source),
                },
            )
            .unwrap();
        let CompilationResult::ArtifactCommitted {
            artifact_digest, ..
        } = result
        else {
            panic!("composed package must commit: {result:?}");
        };
        let air = service
            .store()
            .get(&artifact_digest)
            .expect("artifact envelope");
        assert!(air.contains("\"op\":\"program.new\""), "{air}");
        assert!(air.contains("\"op\":\"program.invoke\""), "{air}");
        assert!(air.contains("\"op\":\"await.event\""), "{air}");
    }

    #[test]
    fn failed_compile_has_no_store_entry() {
        let mut service = CompilationService::default();
        if !frontend_present(Frontend::Python) {
            return;
        }
        let result = service
            .handle(
                &handshake(),
                CompilationRequest::Compile {
                    request_id: "bad".to_owned(),
                    idempotency_key: "bad".to_owned(),
                    snapshot: package_snapshot(
                        Frontend::Python,
                        "src/agent.py",
                        "this is not valid python for an Agent\n",
                    ),
                },
            )
            .unwrap();
        assert!(result.diagnostics_are_consistent(), "{result:?}");
        let CompilationResult::Failed {
            code, diagnostics, ..
        } = result
        else {
            panic!("an invalid program fails: {result:?}");
        };
        assert!(!diagnostics.items.is_empty());
        assert_eq!(diagnostics.first_error_code(), Some(code.as_str()));
        assert!(
            diagnostics.stopped_at.is_some(),
            "a failed compile names where it stopped"
        );
        assert!(service.store().is_empty());
    }

    fn compile_package(
        service: &mut CompilationService,
        id: &str,
        snapshot: PackageSnapshot,
    ) -> CompilationResult {
        let result = service
            .handle(
                &handshake(),
                CompilationRequest::Compile {
                    request_id: id.to_owned(),
                    idempotency_key: id.to_owned(),
                    snapshot,
                },
            )
            .unwrap();
        assert!(result.diagnostics_are_consistent(), "{result:?}");
        result
    }

    /// Every undeclared host reference reaches the protocol as its own located
    /// error; the envelope's code is the first error's code, and the report
    /// stops before capture.
    #[test]
    fn undeclared_host_references_fail_with_every_location() {
        if !frontend_present(Frontend::Typescript) {
            return;
        }
        let source = TYPESCRIPT_PROGRAM.replace(
            "const SearchWeb = Tool<ReviewRequest, Review>(\"search_web\");",
            "const SearchWeb = Tool<ReviewRequest, Review>(\"search_web\");\n\
             const Append = Capability<ReviewRequest, Review>(\"host:notes.append\");\n\
             const Delete = Capability<ReviewRequest, Review>(\"host:notes.delete\");",
        );
        let mut service = CompilationService::default();
        let result = compile_package(
            &mut service,
            "undeclared",
            package_snapshot(Frontend::Typescript, "src/agent.ts", &source),
        );
        let CompilationResult::Failed {
            code, diagnostics, ..
        } = result
        else {
            panic!("undeclared host references fail: {result:?}");
        };
        assert_eq!(code, "graph_rejected");
        assert_eq!(diagnostics.total_count, 2);
        assert_eq!(diagnostics.stopped_at, Some(Phase::TypeCheck));
        let lines = diagnostics
            .items
            .iter()
            .map(|item| {
                let location = item.location.as_ref().expect("every item is located");
                assert_eq!(location.source_file, "submitted_source.ts");
                location.span.start_line
            })
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_ne!(lines[0], lines[1], "distinct locations: {diagnostics:?}");
        assert!(service.store().is_empty());
    }

    /// A compiler warning does not stop a commit: it rides on the committed
    /// artifact's report, which never carries an error or a stopping phase.
    #[test]
    fn a_warning_rides_on_the_committed_artifact() {
        if !frontend_present(Frontend::Python) {
            return;
        }
        let source = PYTHON_PROGRAM.replacen(
            "\n\n\nclass ReviewRequest:",
            "\n\nIDENTITY = 1 is 1\n\nclass ReviewRequest:",
            1,
        );
        let mut service = CompilationService::default();
        let result = compile_package(
            &mut service,
            "warning",
            package_snapshot(Frontend::Python, "src/agent.py", &source),
        );
        let CompilationResult::ArtifactCommitted { diagnostics, .. } = result else {
            panic!("a warning does not stop a commit: {result:?}");
        };
        assert_eq!(diagnostics.items.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics.items[0].severity, Severity::Warning);
        assert_eq!(diagnostics.items[0].code, "source_warning");
        assert!(diagnostics.items[0].location.is_some());
        assert_eq!(diagnostics.stopped_at, None);
    }

    /// A TypeScript program compiled through the service carries a node span
    /// for every semantic operation: a host capability call, and the same Tool
    /// invoked in both arms of a branch as two operations with two spans.
    #[test]
    fn typescript_artifact_source_map_spans_every_operation() {
        if !frontend_present(Frontend::Typescript) {
            return;
        }
        let source = r#"import { Workflow, Capability, Tool } from "@apxm/frontend";
import { source } from "@apxm/frontend/node";

source(import.meta.url);

type ReviewRequest = { urgent: boolean };
type Review = object;

const Notes = Capability<ReviewRequest, Review>("host:notes.search");
const SearchWeb = Tool<ReviewRequest, Review>("search_web");

export const Reviewer = Workflow<ReviewRequest, Review>({
  name: "Reviewer",
  async run(agent, request) {
    const noted = await Notes(request);
    if (request.urgent) {
      return await SearchWeb(request);
    } else {
      return await SearchWeb(request);
    }
  },
});
"#;
        let mut service = CompilationService::default();
        let result = compile_package(
            &mut service,
            "spans",
            package_snapshot_with(
                Frontend::Typescript,
                "src/agent.ts",
                source,
                NOTES_SEARCH_HOST,
            ),
        );
        let CompilationResult::ArtifactCommitted { artifact, .. } = result else {
            panic!("the branched program commits: {result:?}");
        };
        assert_eq!(artifact.source_map, artifact.air.source_map);
        let spans = artifact
            .source_map
            .node_spans
            .iter()
            .map(|span| (span.node_id.as_str(), span))
            .collect::<BTreeMap<_, _>>();
        for operation in &artifact.air.semantic_operations {
            assert!(
                spans.contains_key(operation.node_id.as_str()),
                "{} has no span in {:?}",
                operation.node_id,
                artifact.source_map.node_spans
            );
        }
        let lines = source.lines().collect::<Vec<_>>();
        let invoked = artifact
            .air
            .semantic_operations
            .iter()
            .filter(|operation| operation.op == SemanticOpKind::CapabilityInvoke)
            .map(|operation| {
                let span = spans[operation.node_id.as_str()];
                assert_eq!(span.source_file, "submitted_source.ts");
                let line = lines[usize::try_from(span.span.start_line).unwrap() - 1];
                (
                    operation.node_id.clone(),
                    span.span.start_line,
                    line.trim().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(invoked.len(), 3, "{invoked:?}");
        assert_eq!(
            invoked
                .iter()
                .filter(|(_, _, line)| line.contains("Notes(request)"))
                .count(),
            1
        );
        let searches = invoked
            .iter()
            .filter(|(_, _, line)| line.contains("SearchWeb(request)"))
            .collect::<Vec<_>>();
        assert_eq!(searches.len(), 2, "{invoked:?}");
        assert_ne!(searches[0].0, searches[1].0);
        assert_ne!(searches[0].1, searches[1].1);
    }

    #[test]
    fn missing_frontend_fails_closed() {
        let mut service = CompilationService::default();
        let snapshot = PackageSnapshot::assemble(
            Frontend::Python,
            "src/agent.py",
            vec![SnapshotContent::from_bytes(
                "src/agent.py",
                b"print('no manifest')",
            )],
            None,
            "apxm.compatibility-set/test",
        )
        .unwrap();
        let result = service
            .handle(
                &handshake(),
                CompilationRequest::Compile {
                    request_id: "missing".to_owned(),
                    idempotency_key: "missing".to_owned(),
                    snapshot,
                },
            )
            .unwrap();
        match result {
            CompilationResult::Failed {
                code, diagnostics, ..
            } => {
                assert_eq!(code, "missing_frontend");
                assert_eq!(diagnostics.items.len(), 1);
                assert_eq!(diagnostics.items[0].phase, Phase::Package);
                assert_eq!(diagnostics.stopped_at, Some(Phase::Package));
            }
            other => panic!("expected missing frontend, got {other:?}"),
        }
        assert!(service.store().is_empty());
    }

    #[test]
    fn lock_drift_fails_closed() {
        let err = PackageSnapshot::assemble(
            Frontend::Python,
            "src/agent.py",
            vec![
                SnapshotContent::from_bytes("src/agent.py", b"print('ok')"),
                SnapshotContent::from_bytes("uv.lock", b"stale"),
            ],
            Some("not-the-lock-digest".to_owned()),
            "apxm.compatibility-set/test",
        )
        .unwrap_err();
        assert_eq!(err, SnapshotError::LockDrift);
    }

    #[test]
    fn failed_handshake_never_contacts_the_store() {
        let mut service = CompilationService::default();
        let err = service
            .handle(
                &CompilationHandshake {
                    protocol_version: "nope".to_owned(),
                },
                CompilationRequest::Cancel {
                    request_id: "r".to_owned(),
                    target_request_id: "t".to_owned(),
                },
            )
            .unwrap_err();
        assert_eq!(err, ProtocolError::IncompatibleVersion);
        assert!(service.store().get("artifact:x").is_none());
    }

    #[test]
    fn authored_program_discovery_ignores_prompt_like_comments_strings_and_prefixes() {
        let python = r#"
# @Agent(input=Fake, output=Fake)
# async def CommentOnly(agent, request): pass
label = "@Agent"
@Agent(input=In, output=Out)
async def Real(agent, request):
    return request
@AgentFacade(input=In, output=Out)
async def NotAnAgentFacade(agent, request):
    return request
"#;
        assert_eq!(
            authored_program_name(Frontend::Python, python).unwrap(),
            "Real"
        );
        assert_eq!(
            authored_program_name(Frontend::Python, &python.replace("Agent", "Workflow")).unwrap(),
            "Real"
        );

        let typescript = r#"
// export const CommentOnly = Agent<In, Out>({});
const label = "= Agent";
/*
const BlockComment = Agent<In, Out>({});
*/
export const Real = Agent<In, Out>({});
const AgentFacade = AgentFacade<In, Out>({});
"#;
        assert_eq!(
            authored_program_name(Frontend::Typescript, typescript).unwrap(),
            "Real"
        );
        assert_eq!(
            authored_program_name(
                Frontend::Typescript,
                &typescript.replace("Agent", "Workflow")
            )
            .unwrap(),
            "Real"
        );
    }

    #[test]
    fn authored_program_discovery_accepts_multiline_python_agent_decorators() {
        let source = r#"
@Agent(
    input=Input,
    output=Output,
    # A decorator may carry comments while it spans lines.
    context=Context,
)
async def ConversationalExample(agent, request):
    return request
"#;
        assert_eq!(
            authored_program_name(Frontend::Python, source).unwrap(),
            "ConversationalExample"
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_persistence_refuses_to_follow_a_symlink() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join(format!(
            "apxm-artifact-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir(&directory).expect("test directory");
        let target = directory.join("target");
        std::fs::write(&target, b"must survive").expect("target");
        let artifact = directory.join(artifact_file_name("sha256:deadbeef"));
        symlink(&target, &artifact).expect("artifact symlink");

        let error = persist_artifact(&directory, "sha256:deadbeef", b"replacement")
            .expect_err("artifact persistence must not follow a pre-existing symlink");
        assert!(error.contains("not a regular file"));
        assert_eq!(
            std::fs::read(&target).expect("target survives"),
            b"must survive"
        );
        std::fs::remove_file(&artifact).expect("symlink cleanup");
        std::fs::remove_file(&target).expect("target cleanup");
        std::fs::remove_dir(&directory).expect("directory cleanup");
    }

    #[test]
    fn jsonl_round_trip_compiles_python_when_frontend_present() {
        if !frontend_present(Frontend::Python) {
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "apxm-compilation-jsonl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let service = CompilationService::default().with_artifact_dir(dir.clone());
        let envelope = serde_json::json!({
            "handshake": handshake(),
            "request": CompilationRequest::Compile {
                request_id: "c".to_owned(),
                idempotency_key: "k".to_owned(),
                snapshot: package_snapshot(Frontend::Python, "src/agent.py", PYTHON_PROGRAM),
            }
        });
        let frame = crate::StdioFrame {
            channel: "compilation".to_owned(),
            payload: envelope.to_string(),
        };
        let mut out = Vec::new();
        crate::serve_stdio(crate::encode_jsonl(&frame).as_bytes(), &mut out, service).unwrap();
        let reply = crate::decode_jsonl(std::str::from_utf8(&out).unwrap()).unwrap();
        let result: CompilationResult = serde_json::from_str(&reply.payload).unwrap();
        let CompilationResult::ArtifactCommitted {
            artifact_digest, ..
        } = result
        else {
            panic!("jsonl compile: {result:?}");
        };
        let persisted = dir.join(crate::artifact_file_name(&artifact_digest));
        assert!(persisted.is_file(), "artifact bytes persisted for runtime");
        let air = std::fs::read_to_string(persisted).unwrap();
        assert!(air.contains("apxm.air"));
    }
}
