//! Runtime Service composition: admitted ports plus artifact execution.
//!
//! This is the product handler body. It does not relocate `CanonicalRuntime`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::ports::capability::LocalCapabilityPort;
use crate::ports::model::{LocalModelInferencePort, LocalModelRequestMetadata};

use apxm_ais::permissions::{LayerDecisions, PermissionDecision, PermissionResolution};
use apxm_capability::builtins::InlineSkill;
use apxm_capability_iface::sandbox::SandboxRegistry;
use apxm_core::types::host_capability::{
    ManifestCapabilities, is_host_capability_ref, minted_host_capability_refs,
};
use apxm_execution::{
    CancellationToken, CapabilityGrantSet, CapabilityInvocationAdmission, CapturedHookBodyHandler,
    CompositionOutcome, CompositionPort, CompositionRequest, EventAwait, EventOutcome, EventPort,
    ExecutionRequest, NodeOutcome, ObservationFailurePolicy, ObservationSink, RunOutcome,
    RuntimeProfile,
};
use apxm_inference::{
    InferenceTargetCommitment, ModelBindingAdmission, ModelCallRequestMetadataPort, ModelOutcome,
    ResolvedModelBinding,
};
use apxm_kernel::{
    AcpPromptOutcome, AcpPromptRequest, AdmittedCapabilityPermission, AdmittedConfinement,
    AdmittedPortBinding, AtomicWriteSet, CapabilityOutcome, ConfinementAttestation,
    ConfinementError, ConfinementPort, ConfinementRequest, ExecutionCommitPort,
    ExecutionCommitRequest, ExecutionCommitResult, ExternalAgentCapabilityPort,
    INVOCATION_ADMISSION_SCHEMA, InvocationAdmission, InvocationAdmissionClaim, PortImplementation,
    PortSlot, ProgramInstanceRef, ProgramInvocationRef, PromptEffectState, ResourceCeilings,
    RuntimeAdmission, VerifiedInvocationAdmission, admitted_capability_permissions,
    digest_serializable, verify_invocation_admission,
};
use apxm_program::CapabilityInvocationAuthority;
use apxm_program::air::{AirModule, SemanticOpKind};
use apxm_program::artifact::ExecutableArtifact;
use apxm_program::external_agent::{AttributedEvent, AttributedEventKind, PeerUsage};
use async_trait::async_trait;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LOCAL_ACTING_PRINCIPAL_REF: &str = "apxm.canonical.local.acting-principal";
const LOCAL_AGENT_IDENTITY_REF: &str = "apxm.canonical.local.agent-identity";
const LOCAL_CAPABILITY_GRANT_PREFIX: &str = "apxm.canonical.local.grant.";

/// Exact APXM-owned descriptors used by the service composition root.
#[derive(Clone, Debug)]
pub struct CanonicalRuntimeDescriptor {
    pub port_bindings: Vec<AdmittedPortBinding>,
    pub resource_ceilings: ResourceCeilings,
    pub confinement: AdmittedConfinement,
}

/// Closed local Capability implementation set selected by the composition root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RuntimeCapabilityProfile {
    #[default]
    PortableLocal,
    HostOnly,
}

impl RuntimeCapabilityProfile {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("portable_local") => Ok(Self::PortableLocal),
            Some("host_only") => Ok(Self::HostOnly),
            Some(_) => Err("unknown APXM_RUNTIME_CAPABILITY_PROFILE".to_owned()),
        }
    }

    /// Parse the exact image-owned runtime setting.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("APXM_RUNTIME_CAPABILITY_PROFILE") {
            Ok(value) => Self::parse(Some(&value)),
            Err(std::env::VarError::NotPresent) => Self::parse(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err("invalid APXM_RUNTIME_CAPABILITY_PROFILE".to_owned())
            }
        }
    }
}

#[cfg(test)]
mod capability_profile_tests {
    use super::RuntimeCapabilityProfile;

    #[test]
    fn closed_profile_setting_refuses_unknown_values() {
        assert_eq!(
            RuntimeCapabilityProfile::parse(None),
            Ok(RuntimeCapabilityProfile::PortableLocal)
        );
        assert_eq!(
            RuntimeCapabilityProfile::parse(Some("portable_local")),
            Ok(RuntimeCapabilityProfile::PortableLocal)
        );
        assert_eq!(
            RuntimeCapabilityProfile::parse(Some("host_only")),
            Ok(RuntimeCapabilityProfile::HostOnly)
        );
        assert!(RuntimeCapabilityProfile::parse(Some("HostOnly")).is_err());
        assert!(RuntimeCapabilityProfile::parse(Some("")).is_err());
    }
}

/// Digest-bound artifact bytes the Runtime Service may instantiate.
#[derive(Default)]
pub struct ArtifactStore {
    committed: BTreeMap<String, Vec<u8>>,
}

impl ArtifactStore {
    /// Commit exact canonical executable-artifact bytes under their envelope
    /// digest. Raw AIR is deliberately not representable at this boundary.
    pub fn commit(&mut self, bytes: Vec<u8>) -> String {
        let Ok(artifact) = ExecutableArtifact::decode(&bytes) else {
            return String::new();
        };
        let Ok(digest) = artifact.canonical_digest() else {
            return String::new();
        };
        if ExecutableArtifact::decode_for_execution(&bytes, &digest).is_err() {
            return String::new();
        }
        self.committed.insert(digest.clone(), bytes);
        digest
    }

    /// Commit bytes under a caller-supplied digest. Used when the admission
    /// already named the digest.
    pub fn commit_named(&mut self, digest: String, bytes: Vec<u8>) {
        // Never let a caller create a second identity for bytes. Persisted
        // loads and protocol inputs use the same closed digest grammar.
        if apxm_core::grammar::is_digest(&digest)
            && ExecutableArtifact::decode_for_execution(&bytes, &digest).is_ok()
        {
            self.committed.insert(digest, bytes);
        }
    }

    #[must_use]
    pub fn get(&self, digest: &str) -> Option<&[u8]> {
        self.committed.get(digest).map(Vec::as_slice)
    }
}

/// SHA-256 digest in the admission wire form.
#[must_use]
pub fn artifact_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Compute the digest of a canonical executable-artifact envelope.
pub fn canonical_artifact_digest(bytes: &[u8]) -> Result<String, String> {
    let artifact = ExecutableArtifact::decode(bytes).map_err(|error| error.to_string())?;
    artifact
        .canonical_digest()
        .map_err(|error| error.to_string())
}

/// Exact reference runtime descriptor. The transport digest must hash these
/// descriptors; it is never copied onto an unrelated implementation.
#[must_use]
pub fn canonical_runtime_descriptor() -> CanonicalRuntimeDescriptor {
    let port_bindings = [
        (
            PortSlot::ExecutionCommit,
            "apxm.execution-commit",
            "b64becdf1c246b6a05bf02206dcf2306171501079257f188a7d76d88af9f26f7",
        ),
        (
            PortSlot::Confinement,
            "apxm.confinement",
            "5d5e5c8e9e0a6d6e5f87eaed8e4c5ee3dfeef7fbd2501dc4f180785b9f5d7e0f",
        ),
        (
            PortSlot::ModelInference,
            "apxm.model-inference",
            "fdf6aea657550b87f8b66f63f8e50cf793cec427b320c5bce940ba24fbc97362",
        ),
        (
            PortSlot::Capability,
            "apxm.capability-invocation",
            "9369bd4c3506ba145d9424425efcb0493b288d418c582701d0856e8216fc8383",
        ),
        (
            PortSlot::ExternalAgentCapability,
            "apxm.external-agent",
            "d7f7a1319eeac3c69af8355dd58b60a8f86d4861e5d32e3b8cac85105bd5eb5d",
        ),
        (
            PortSlot::DurableEvent,
            "apxm.durable-event",
            "75d3c93c0c34f3c3d4dfeb89cec81cdbc208ac9106bba6955a923b0c566342d9",
        ),
        (
            PortSlot::ProgramComposition,
            "apxm.program-composition",
            "7cacd4d1d1a0f17f30e167907997fbaa86e3e84026c69eee11d0673ceb67351a",
        ),
    ]
    .into_iter()
    .map(|(slot, schema_id, contract_digest)| AdmittedPortBinding {
        slot: slot.as_str().into(),
        port_contract_schema_id: schema_id.into(),
        port_contract_digest: format!("sha256:{contract_digest}"),
        binding_digest: digest_text(&format!("apxm.canonical.binding.{}", slot.as_str())),
        proof_digest: digest_text(&format!("apxm.canonical.proof.{}", slot.as_str())),
    })
    .collect();
    CanonicalRuntimeDescriptor {
        port_bindings,
        resource_ceilings: ResourceCeilings {
            max_wall_ms: 60_000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_effect_bytes: 1024 * 1024,
        },
        confinement: AdmittedConfinement {
            confinement_type: "NATIVE-SANDBOX".into(),
            sandbox_digest: digest_text("apxm.canonical.sandbox.v1"),
            policy_digest: digest_text("apxm.canonical.policy.v1"),
        },
    }
}

/// Descriptor for one exact registered Capability implementation set.
#[must_use]
pub fn runtime_descriptor_for(profile: RuntimeCapabilityProfile) -> CanonicalRuntimeDescriptor {
    let mut descriptor = canonical_runtime_descriptor();
    if profile == RuntimeCapabilityProfile::HostOnly {
        let capability = descriptor
            .port_bindings
            .iter_mut()
            .find(|binding| binding.slot == PortSlot::Capability.as_str())
            .expect("canonical Capability binding");
        capability.binding_digest = digest_text("apxm.canonical.binding.capability.host-only.v1");
        capability.proof_digest = digest_text("apxm.canonical.proof.capability.host-only.v1");
    }
    descriptor
}

/// Digest of the selected exact runtime Port bindings.
#[must_use]
pub fn port_bindings_digest_for(profile: RuntimeCapabilityProfile) -> String {
    digest_serializable(&runtime_descriptor_for(profile).port_bindings)
        .expect("runtime bindings are serializable")
}

#[must_use]
pub fn canonical_port_bindings_digest() -> String {
    digest_serializable(&canonical_runtime_descriptor().port_bindings)
        .expect("canonical bindings are serializable")
}

#[must_use]
pub fn canonical_resource_ceiling_digest() -> String {
    digest_serializable(&canonical_runtime_descriptor().resource_ceilings)
        .expect("canonical ceilings are serializable")
}

/// Immutable Runtime-owned admission profile loaded by the service image.
///
/// The profile deliberately contains only the small release and provenance
/// carriers used by the admission verifier. It never contains an executable
/// artifact, caller identity, or product authorization decision. Callers
/// refer to it by `profile_ref`; the Runtime remains the only authority that
/// can read these bytes and construct an invocation admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAdmissionProfile {
    profile_ref: String,
    release_bytes: Vec<u8>,
    provenance_bytes: Vec<u8>,
    capability_profile: RuntimeCapabilityProfile,
}

impl RuntimeAdmissionProfile {
    const MAX_CARRIER_BYTES: u64 = 1024 * 1024;
    const DEFAULT_RELEASE_PATH: &'static str = "/tmp/apxm-service-release-manifest.json";
    const DEFAULT_PROVENANCE_PATH: &'static str = "/tmp/apxm-source-revision.json";

    /// Build an image-owned profile from exact carrier bytes. The opaque
    /// profile reference is digest-bound to the carriers and canonical
    /// Runtime descriptor, so a caller cannot substitute a self-consistent
    /// profile from another Runtime composition.
    pub fn from_carriers(
        release_bytes: Vec<u8>,
        provenance_bytes: Vec<u8>,
    ) -> Result<Self, String> {
        Self::from_carriers_with_capability_profile(
            release_bytes,
            provenance_bytes,
            RuntimeCapabilityProfile::PortableLocal,
        )
    }

    /// Calculate the reviewed profile reference from exact image carriers
    /// and the selected descriptor. No running service response is trusted.
    pub fn from_carriers_with_capability_profile(
        release_bytes: Vec<u8>,
        provenance_bytes: Vec<u8>,
        capability_profile: RuntimeCapabilityProfile,
    ) -> Result<Self, String> {
        validate_carrier(&release_bytes)?;
        validate_carrier(&provenance_bytes)?;
        let profile_ref = digest_serializable(&(
            artifact_digest(&release_bytes),
            artifact_digest(&provenance_bytes),
            port_bindings_digest_for(capability_profile),
            canonical_resource_ceiling_digest(),
        ))
        .map(|digest| format!("apxm.admission-profile.{digest}"))
        .map_err(|error| error.to_string())?;
        Ok(Self {
            profile_ref,
            release_bytes,
            provenance_bytes,
            capability_profile,
        })
    }

    /// Load the exact carriers packaged in the standalone Runtime image.
    /// Explicit absolute paths may override the image defaults. If neither
    /// carrier exists, no profile is configured and invocation admission stays
    /// fail-closed.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_env_for(RuntimeCapabilityProfile::PortableLocal)
    }

    /// Load carriers for the selected image-owned runtime profile.
    pub fn from_env_for(
        capability_profile: RuntimeCapabilityProfile,
    ) -> Result<Option<Self>, String> {
        let release_path = std::env::var("APXM_RUNTIME_RELEASE_MANIFEST_PATH")
            .unwrap_or_else(|_| Self::DEFAULT_RELEASE_PATH.to_owned());
        let provenance_path = std::env::var("APXM_RUNTIME_PROVENANCE_PATH")
            .unwrap_or_else(|_| Self::DEFAULT_PROVENANCE_PATH.to_owned());
        let release_exists = std::path::Path::new(&release_path).exists();
        let provenance_exists = std::path::Path::new(&provenance_path).exists();
        if !release_exists && !provenance_exists {
            if capability_profile == RuntimeCapabilityProfile::HostOnly {
                return Err("host_only requires both admission profile carriers".to_owned());
            }
            return Ok(None);
        }
        if release_path.trim().is_empty() || provenance_path.trim().is_empty() {
            return Err("admission profile carrier paths must not be empty".to_owned());
        }
        let release_bytes = read_carrier(&release_path)?;
        let provenance_bytes = read_carrier(&provenance_path)?;
        Self::from_carriers_with_capability_profile(
            release_bytes,
            provenance_bytes,
            capability_profile,
        )
        .map(Some)
    }

    #[must_use]
    pub fn profile_ref(&self) -> &str {
        &self.profile_ref
    }

    #[must_use]
    pub fn capability_profile(&self) -> RuntimeCapabilityProfile {
        self.capability_profile
    }

    /// Construct materials with a Runtime-owned template identity. The
    /// service replaces this template with its final minted invocation id
    /// during `prepare_invocation`.
    pub fn materials_for_artifact(&self, artifact_bytes: &[u8]) -> InvocationMaterials {
        materials_for_artifact_with_profile(
            artifact_bytes,
            format!("template.{}", self.profile_ref),
            self.release_bytes.clone(),
            self.provenance_bytes.clone(),
            self.capability_profile,
        )
    }
}

fn validate_carrier(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > RuntimeAdmissionProfile::MAX_CARRIER_BYTES {
        return Err("admission profile carrier exceeds bounded size".to_owned());
    }
    serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|error| format!("invalid admission profile carrier: {error}"))?;
    Ok(())
}

fn read_carrier(path: &str) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("read profile carrier: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("admission profile carrier must be a regular file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > RuntimeAdmissionProfile::MAX_CARRIER_BYTES {
        return Err("admission profile carrier exceeds bounded size".to_owned());
    }
    let bytes = std::fs::read(path).map_err(|error| format!("read profile carrier: {error}"))?;
    validate_carrier(&bytes)?;
    Ok(bytes)
}

fn digest_text(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

struct DevConfinement;

#[async_trait]
impl ConfinementPort for DevConfinement {
    async fn attest(
        &self,
        request: ConfinementRequest,
    ) -> Result<ConfinementAttestation, ConfinementError> {
        Ok(ConfinementAttestation {
            attestation_id: format!("dev-attestation.{}", request.execution_id),
            host_id: request.host_id,
            execution_id: request.execution_id,
            confinement_type: request.confinement_type,
            sandbox_digest: request.sandbox_digest,
            policy_digest: request.policy_digest,
            attested_at: "dev-profile".into(),
            signature: "dev-profile-attestation".into(),
        })
    }
}

struct DevExternalAgent;

#[async_trait]
impl ExternalAgentCapabilityPort for DevExternalAgent {
    async fn prompt(&self, request: AcpPromptRequest) -> AcpPromptOutcome {
        AcpPromptOutcome {
            session_ref: request.session_ref,
            state: PromptEffectState::Completed {
                stop_reason: Some("dev_profile_completed".into()),
            },
            nested_events: vec![AttributedEvent {
                event_sequence: 0,
                kind: AttributedEventKind::Message,
                detail: Some("dev-profile external agent completed".into()),
                reverse_operation: None,
                reverse_target: None,
                reverse_decision: None,
            }],
            peer_usage: vec![PeerUsage {
                reported_by: "dev-profile".into(),
                metric_scope: "peer.usage.unavailable".into(),
                reported_value: "unavailable_not_observed".into(),
                availability_partial: None,
            }],
        }
    }
}

struct DevEvents;

#[async_trait]
impl EventPort for DevEvents {
    async fn await_event(&self, request: EventAwait) -> EventOutcome {
        EventOutcome::Fulfilled {
            payload: format!("event:{}", request.event_ref),
            event_ref: request.event_ref,
        }
    }
}

/// Event port used by the service's resumable entrypoint. A durable event is
/// resumed only by the owner-facing EventFulfill path after the application is
/// committed; never auto-fulfill an external wait from inside the driver.
struct ParkedEvents;

#[async_trait]
impl EventPort for ParkedEvents {
    async fn await_event(&self, _request: EventAwait) -> EventOutcome {
        EventOutcome::Parked
    }
}

/// This service has no admitted child-artifact resolver or child invocation
/// transport. A fabricated instance reference would incorrectly claim execution.
struct UnavailableComposition;

#[cfg(test)]
mod composition_availability_tests {
    use super::*;
    use apxm_execution::CompositionReceiver;

    #[tokio::test]
    async fn unimplemented_child_execution_never_fabricates_a_successful_instance() {
        let request = CompositionRequest {
            node_id: "child.create".into(),
            receiver: CompositionReceiver::Program {
                program_ref: "child.program".into(),
            },
        };
        assert!(
            matches!(UnavailableComposition.program_new(request.clone()).await, CompositionOutcome::Failed { message } if message.contains("unavailable"))
        );
        assert!(
            matches!(UnavailableComposition.program_invoke(request).await, CompositionOutcome::Failed { message } if message.contains("unavailable"))
        );
    }
}

#[async_trait]
impl CompositionPort for UnavailableComposition {
    async fn program_new(&self, _request: CompositionRequest) -> CompositionOutcome {
        CompositionOutcome::Failed {
            message: "child program execution is unavailable in this runtime composition".into(),
        }
    }

    async fn program_invoke(&self, _request: CompositionRequest) -> CompositionOutcome {
        CompositionOutcome::Failed {
            message: "child program execution is unavailable in this runtime composition".into(),
        }
    }
}

#[derive(Default)]
struct DevCommit {
    version: Mutex<u64>,
    continuation: Mutex<Option<Value>>,
}

#[async_trait]
impl ExecutionCommitPort for DevCommit {
    async fn commit(&self, request: ExecutionCommitRequest) -> ExecutionCommitResult {
        let mut version = self.version.lock().expect("dev commit mutex poisoned");
        if *version != request.expected_program_state_version {
            return ExecutionCommitResult::CompareConflict {
                current_program_state_version: *version,
            };
        }
        *version += 1;
        ExecutionCommitResult::Committed {
            new_program_state_version: *version,
            evidence_position_ref: "dev.evidence.1".into(),
        }
    }

    async fn current_version(&self, _program_instance_ref: &ProgramInstanceRef) -> u64 {
        *self.version.lock().expect("dev commit mutex poisoned")
    }

    async fn load_continuation(&self, _program_instance_ref: &ProgramInstanceRef) -> Option<Value> {
        self.continuation
            .lock()
            .expect("dev commit continuation mutex poisoned")
            .clone()
    }
}

/// Materials required to admit one invocation of a committed artifact.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InvocationMaterials {
    pub admission: InvocationAdmission,
    pub release_bytes: Vec<u8>,
    pub provenance_bytes: Vec<u8>,
}

/// Verify the complete host-supplied invocation handoff before any Runtime
/// state is changed. Artifact bytes, release/provenance carriers, canonical
/// descriptors, and semantic requirements all participate in this check.
pub fn verify_invocation_materials(
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
) -> Result<VerifiedInvocationAdmission, String> {
    verify_invocation_materials_for_profile(
        artifact_bytes,
        materials,
        RuntimeCapabilityProfile::PortableLocal,
    )
}

/// Verify exact materials against the selected implementation set.
pub fn verify_invocation_materials_for_profile(
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    capability_profile: RuntimeCapabilityProfile,
) -> Result<VerifiedInvocationAdmission, String> {
    let artifact_digest = canonical_artifact_digest(artifact_bytes)?;
    let artifact = ExecutableArtifact::decode_for_execution(artifact_bytes, &artifact_digest)
        .map_err(|error| error.clone())?;
    let descriptor = runtime_descriptor_for(capability_profile);
    if materials.admission.port_bindings_digest != port_bindings_digest_for(capability_profile)
        || materials.admission.resource_ceiling_digest != canonical_resource_ceiling_digest()
    {
        return Err("admission_profile_mismatch".to_owned());
    }
    verify_invocation_admission(
        &materials.admission,
        InvocationAdmissionClaim {
            artifact_bytes,
            release_bytes: &materials.release_bytes,
            provenance_bytes: &materials.provenance_bytes,
            artifact_semantic_requirements: &apxm_program::air_semantic_requirements(&artifact.air),
            admitted_port_bindings: &descriptor.port_bindings,
            resource_ceilings: &descriptor.resource_ceilings,
            confinement: &descriptor.confinement,
        },
    )
    .map_err(|error| error.to_string())
}

/// Package-handler implementations supplied to one Runtime Service instance.
#[derive(Debug, Clone)]
pub struct AdmittedPackageHandlers {
    /// Private handler-worker command for each language the manifest uses.
    pub workers:
        std::collections::BTreeMap<apxm_core::types::HandlerLanguage, PackageHandlerWorkerCommand>,
    /// Validated manifest those workers may evaluate.
    pub manifest: apxm_core::types::HandlerManifest,
    /// Host-issued read-only decisions. Values in the package manifest are
    /// descriptive input and never grant this authority themselves.
    pub trusted_read_only: BTreeSet<String>,
}

/// How one language's private worker is started.
#[derive(Debug, Clone)]
pub struct PackageHandlerWorkerCommand {
    /// Interpreter that runs the worker entry.
    pub interpreter: String,
    /// Private worker entry path.
    pub entry: PathBuf,
}

/// Execute one admitted AIR artifact through the shared runtime profile.
pub async fn execute_admitted_artifact(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
) -> Result<Value, String> {
    execute_admitted_artifact_with_sandbox(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        None,
    )
    .await
}

/// Execute one admitted artifact with an explicitly injected sandbox registry.
///
/// Package workers are untrusted implementation code. A missing registry is a
/// valid composition state for artifacts that do not use package handlers, but
/// package-handler execution fails closed at the worker boundary.
pub async fn execute_admitted_artifact_with_sandbox(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
) -> Result<Value, String> {
    execute_admitted_artifact_with_runtime_ports(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        Arc::new(DevCommit::default()),
        None,
    )
    .await
}

/// Execute one admitted artifact against caller-owned commit/read ports.
/// Observations remain a bounded, non-authoritative sink; committed execution
/// truth is read back from the injected Execution Commit port.
#[allow(clippy::too_many_arguments)]
pub async fn execute_admitted_artifact_with_runtime_ports(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
) -> Result<Value, String> {
    execute_admitted_artifact_with_runtime_ports_and_cancellation(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        None,
    )
    .await
}

/// Execute one admitted artifact with a caller-owned cooperative cancellation
/// signal. The signal is attached before the profile starts so service cancel
/// and wall-clock expiry both reach the driver's atomic terminal commit path.
#[allow(clippy::too_many_arguments)]
pub async fn execute_admitted_artifact_with_runtime_ports_and_cancellation(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
) -> Result<Value, String> {
    execute_admitted_artifact_with_runtime_ports_mode(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        cancellation,
        ProgramInstanceRef::new("canonical.instance"),
        false,
        Value::Null,
        None,
    )
    .await
}

/// Runtime-service start path carrying the caller's exact entrypoint input.
/// The input is bound to the AIR parameter by the composition root; it is not
/// inferred from artifact metadata or injected into the driver as context.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_admitted_artifact_with_runtime_ports_and_cancellation_with_input(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
    input: Value,
) -> Result<Value, String> {
    execute_admitted_artifact_with_runtime_ports_mode(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        cancellation,
        ProgramInstanceRef::new("canonical.instance"),
        false,
        input,
        None,
    )
    .await
}

/// Execute one admitted artifact with durable park/resume semantics. The
/// returned JSON is a transport-neutral projection of either a suspended
/// continuation or a committed terminal report; the continuation itself is
/// owned by the execution commit port.
#[allow(clippy::too_many_arguments)]
pub async fn execute_admitted_artifact_resumable_with_runtime_ports_and_cancellation(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
) -> Result<Value, String> {
    execute_admitted_artifact_resumable_for_instance(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        cancellation,
        ProgramInstanceRef::new("canonical.instance"),
    )
    .await
}

/// Resumable service entrypoint bound to the concrete Program Instance key.
#[allow(clippy::too_many_arguments)]
pub async fn execute_admitted_artifact_resumable_for_instance(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
    program_instance_ref: ProgramInstanceRef,
) -> Result<Value, String> {
    execute_admitted_artifact_with_runtime_ports_mode(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        cancellation,
        program_instance_ref,
        true,
        Value::Null,
        None,
    )
    .await
}

/// Resumable Runtime-service start path carrying the exact entrypoint input.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_admitted_artifact_resumable_for_instance_with_input(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
    program_instance_ref: ProgramInstanceRef,
    input: Value,
    events: Arc<dyn EventPort>,
) -> Result<Value, String> {
    execute_admitted_artifact_with_runtime_ports_mode(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        cancellation,
        program_instance_ref,
        true,
        input,
        Some(events),
    )
    .await
}

/// Resume one event continuation through the same admitted RuntimeProfile and
/// driver path used by resumable starts. The caller must have already
/// durably applied the matching EventApplication; this function only drives
/// the continuation and returns its committed/suspended projection.
#[allow(clippy::too_many_arguments)]
pub async fn resume_admitted_artifact_with_runtime_ports(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
    program_instance_ref: ProgramInstanceRef,
    event_ref: apxm_kernel::EventRef,
    delivered: Value,
) -> Result<Value, String> {
    resume_admitted_artifact_with_events(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        cancellation,
        program_instance_ref,
        event_ref,
        delivered,
        None,
    )
    .await
}

fn inline_skills_from_artifact(artifact: &ExecutableArtifact) -> Vec<InlineSkill> {
    artifact
        .source_bundle
        .as_ref()
        .into_iter()
        .flat_map(|bundle| bundle.skill_requirements.iter())
        .filter_map(|requirement| match &requirement.instruction_source {
            apxm_program::frontend_graph::SkillInstructionSource::Inline { text } => {
                Some(InlineSkill::new(requirement.skill_id.clone(), text.clone()))
            }
            apxm_program::frontend_graph::SkillInstructionSource::Entry { .. } => None,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resume_admitted_artifact_with_events(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
    program_instance_ref: ProgramInstanceRef,
    event_ref: apxm_kernel::EventRef,
    delivered: Value,
    events: Option<Arc<dyn EventPort>>,
) -> Result<Value, String> {
    let admission = &materials.admission;
    let artifact =
        ExecutableArtifact::decode_for_execution(artifact_bytes, &admission.artifact_digest)?;
    let inline_skills = inline_skills_from_artifact(&artifact);
    let capability_profile = capability_profile_for_digest(&admission.port_bindings_digest)?;
    let descriptor = runtime_descriptor_for(capability_profile);
    if admission.port_bindings_digest != port_bindings_digest_for(capability_profile)
        || admission.resource_ceiling_digest != canonical_resource_ceiling_digest()
    {
        return Err("admission_profile_mismatch".to_owned());
    }
    let verified = verify_invocation_admission(
        admission,
        InvocationAdmissionClaim {
            artifact_bytes,
            release_bytes: &materials.release_bytes,
            provenance_bytes: &materials.provenance_bytes,
            artifact_semantic_requirements: &apxm_program::air_semantic_requirements(&air),
            admitted_port_bindings: &descriptor.port_bindings,
            resource_ceilings: &descriptor.resource_ceilings,
            confinement: &descriptor.confinement,
        },
    )
    .map_err(|error| error.to_string())?;
    let capability = Arc::new(
        LocalCapabilityPort::with_profile(
            capability_profile,
            handlers,
            package_root,
            sandbox_registry,
            inline_skills,
        )
        .map_err(|error| error.to_string())?,
    );
    let model = Arc::new(
        LocalModelInferencePort::from_backend_roster().map_err(|error| error.to_string())?,
    );
    let profile = runtime_profile_from_invocation(
        commit,
        observation_sink,
        capability,
        model.clone(),
        Arc::new(LocalModelRequestMetadata),
        verified,
        "runtime.service.resume",
        true,
        events,
    )
    .await?;
    let profile = match cancellation {
        Some(token) => profile.with_cancellation_token(token),
        None => profile,
    };
    let outcome = profile
        .resume_event(&program_instance_ref, event_ref, delivered)
        .await
        .map_err(|error| error.to_string())?;
    match outcome {
        RunOutcome::Completed(report) => Ok(run_report_json(&report, &model)),
        RunOutcome::Suspended {
            continuation_id,
            event_ref,
            operational_usage: _,
        } => Ok(json!({
            "schema_version": "apxm.local-execute-result",
            "runtime": "apxm_execution",
            "status": "suspended",
            "continuation_id": continuation_id,
            "event_ref": event_ref,
            "commit": {"status": "suspended"},
        })),
    }
}

/// Every public entry above delegates into one driver frame, so that frame's
/// state would otherwise be carried by value through each wrapper's future.
/// Boxing it once here keeps every caller pointer-sized.
#[allow(clippy::too_many_arguments)]
async fn execute_admitted_artifact_with_runtime_ports_mode(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
    program_instance_ref: ProgramInstanceRef,
    resumable: bool,
    input: Value,
    events: Option<Arc<dyn EventPort>>,
) -> Result<Value, String> {
    Box::pin(drive_admitted_artifact(
        air,
        artifact_bytes,
        materials,
        handlers,
        package_root,
        sandbox_registry,
        commit,
        observation_sink,
        cancellation,
        program_instance_ref,
        resumable,
        input,
        events,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
async fn drive_admitted_artifact(
    air: AirModule,
    artifact_bytes: &[u8],
    materials: &InvocationMaterials,
    handlers: Option<&AdmittedPackageHandlers>,
    package_root: Option<&Path>,
    sandbox_registry: Option<Arc<SandboxRegistry>>,
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    cancellation: Option<CancellationToken>,
    program_instance_ref: ProgramInstanceRef,
    resumable: bool,
    input: Value,
    events: Option<Arc<dyn EventPort>>,
) -> Result<Value, String> {
    let admission = &materials.admission;
    let artifact =
        ExecutableArtifact::decode_for_execution(artifact_bytes, &admission.artifact_digest)?;
    let inline_skills = inline_skills_from_artifact(&artifact);
    let initial_context = match artifact.entrypoints.as_slice() {
        [entrypoint] => entrypoint
            .default_context
            .as_ref()
            .map(|default| default.literal_json())
            .transpose()?
            .unwrap_or(Value::Null),
        _ => {
            return Err(
                "root Context initialization requires one exact artifact entrypoint".into(),
            );
        }
    };
    let capability_profile = capability_profile_for_digest(&admission.port_bindings_digest)?;
    let descriptor = runtime_descriptor_for(capability_profile);
    if admission.port_bindings_digest != port_bindings_digest_for(capability_profile)
        || admission.resource_ceiling_digest != canonical_resource_ceiling_digest()
    {
        return Err("admission_profile_mismatch".to_owned());
    }
    let verified = verify_invocation_admission(
        admission,
        InvocationAdmissionClaim {
            artifact_bytes,
            release_bytes: &materials.release_bytes,
            provenance_bytes: &materials.provenance_bytes,
            artifact_semantic_requirements: &apxm_program::air_semantic_requirements(&air),
            admitted_port_bindings: &descriptor.port_bindings,
            resource_ceilings: &descriptor.resource_ceilings,
            confinement: &descriptor.confinement,
        },
    )
    .map_err(|error| error.to_string())?;
    let capability = Arc::new(
        LocalCapabilityPort::with_profile(
            capability_profile,
            handlers,
            package_root,
            sandbox_registry,
            inline_skills,
        )
        .map_err(|error| error.to_string())?,
    );
    // A host-fulfilled reference has no implementation here and never will:
    // the runtime publishes a request and parks (ADR-0025). The compilation
    // service already closed the set against the package manifest, so every
    // `host:` reference the artifact invokes is admitted and resolvable, and
    // the host — not APXM — decides whether the call happens.
    let host_refs = invoked_host_capability_refs(&air);
    let mut admitted = capability.admitted_names();
    admitted.extend(host_refs.iter().cloned());
    let mut registered = capability.registered_names();
    registered.extend(host_refs);
    let capability_permissions = local_capability_permissions(&air, &admitted, package_root)?;
    let capability_invocations = local_capability_invocation_admissions(
        &air,
        &CapabilityGrantSet::from_registered_implementations(registered),
        &capability_permissions,
    )?;
    let model_binding_digest = descriptor
        .port_bindings
        .iter()
        .find(|binding| binding.slot == PortSlot::ModelInference.as_str())
        .map(|binding| binding.binding_digest.clone())
        .ok_or_else(|| "reference runtime model binding is absent".to_owned())?;
    let hook_bindings = apxm_program::air_hook_bindings(&air);
    let request = ExecutionRequest {
        entrypoint_input: Some(apxm_execution::EntrypointInput::new(input)),
        model_admission: model_admission(&air, &model_binding_digest),
        initial_values: BTreeMap::new(),
        air,
        hook_bindings,
        capability_invocations,
        program_instance_ref,
        program_invocation_ref: ProgramInvocationRef::new(admission.invocation_id.clone()),
        commit_id: format!("canonical.commit.{}", admission.invocation_id),
        write_set: reference_write_set(&admission.invocation_id),
    };
    let resumes_yield = resumable
        && commit
            .load_continuation_with_integrity(&request.program_instance_ref)
            .await
            .is_some();
    let model = Arc::new(
        LocalModelInferencePort::from_backend_roster().map_err(|error| error.to_string())?,
    );
    let profile = runtime_profile_from_invocation(
        commit,
        observation_sink,
        capability,
        model.clone(),
        Arc::new(LocalModelRequestMetadata),
        verified,
        "runtime.service.execution",
        resumable,
        events,
    )
    .await?;
    let profile = match cancellation {
        Some(token) => profile.with_cancellation_token(token),
        None => profile,
    };
    let outcome = if resumable {
        let outcome = if resumes_yield {
            profile.resume_invocation(request).await
        } else {
            profile.execute_resumable(request, initial_context).await
        };
        match outcome {
            Ok(apxm_execution::RunOutcome::Completed(report)) => {
                return Ok(run_report_json(&report, &model));
            }
            Ok(apxm_execution::RunOutcome::Suspended {
                continuation_id,
                event_ref,
                operational_usage: _,
            }) => {
                return Ok(json!({
                    "schema_version": "apxm.local-execute-result",
                    "runtime": "apxm_execution",
                    "status": "suspended",
                    "continuation_id": continuation_id,
                    "event_ref": event_ref,
                    "commit": {"status": "suspended"},
                }));
            }
            Err(error) => return Err(error.to_string()),
        }
    } else {
        profile
            .execute(request, initial_context)
            .await
            .map_err(|error| error.to_string())?
    };
    Ok(run_report_json(&outcome, &model))
}

fn run_report_json(report: &apxm_execution::RunReport, model: &LocalModelInferencePort) -> Value {
    json!({
        "schema_version": "apxm.local-execute-result",
        "runtime": "apxm_execution",
        "status": runtime_status(report),
        "content": report.final_context,
        "results": {
            "node_outcomes": report.node_outcomes.iter().map(node_outcome_json).collect::<Vec<_>>(),
            "external_agent_evidence": report.external_agent_evidence,
            "model_attempt_diagnostics": model.attempt_diagnostics(),
        },
        "stats": {
            "executed_nodes": report.node_outcomes.len(),
            "failed_nodes": failed_node_count(&report.node_outcomes),
            "duration_ms": 0,
        },
        "llm_usage": {
            "input_tokens": report.native_usage.input_tokens,
            "output_tokens": report.native_usage.output_tokens,
            "total_requests": report
                .node_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, NodeOutcome::Model { .. }))
                .count(),
        },
        "commit": commit_result_json(&report.commit),
    })
}

/// Build admission materials that match the reference profile for these bytes.
pub fn materials_for_artifact(
    artifact_bytes: &[u8],
    invocation_id: impl Into<String>,
    release_bytes: Vec<u8>,
    provenance_bytes: Vec<u8>,
) -> InvocationMaterials {
    materials_for_artifact_with_profile(
        artifact_bytes,
        invocation_id,
        release_bytes,
        provenance_bytes,
        RuntimeCapabilityProfile::PortableLocal,
    )
}

/// Build materials for the selected exact runtime descriptor.
pub fn materials_for_artifact_with_profile(
    artifact_bytes: &[u8],
    invocation_id: impl Into<String>,
    release_bytes: Vec<u8>,
    provenance_bytes: Vec<u8>,
    capability_profile: RuntimeCapabilityProfile,
) -> InvocationMaterials {
    let admission = InvocationAdmission {
        schema_version: INVOCATION_ADMISSION_SCHEMA.to_owned(),
        invocation_id: invocation_id.into(),
        artifact_digest: canonical_artifact_digest(artifact_bytes).unwrap_or_default(),
        release_digest: artifact_digest(&release_bytes),
        port_bindings_digest: port_bindings_digest_for(capability_profile),
        resource_ceiling_digest: canonical_resource_ceiling_digest(),
        provenance_digest: artifact_digest(&provenance_bytes),
    };
    InvocationMaterials {
        admission,
        release_bytes,
        provenance_bytes,
    }
}

fn capability_profile_for_digest(digest: &str) -> Result<RuntimeCapabilityProfile, String> {
    if digest == canonical_port_bindings_digest() {
        Ok(RuntimeCapabilityProfile::PortableLocal)
    } else if digest == port_bindings_digest_for(RuntimeCapabilityProfile::HostOnly) {
        Ok(RuntimeCapabilityProfile::HostOnly)
    } else {
        Err("admission_profile_mismatch".to_owned())
    }
}

#[allow(clippy::too_many_arguments)]
async fn runtime_profile_from_invocation(
    commit: Arc<dyn ExecutionCommitPort>,
    observation_sink: Option<Arc<dyn ObservationSink>>,
    capability: Arc<LocalCapabilityPort>,
    model: Arc<LocalModelInferencePort>,
    model_call_request_metadata: Arc<dyn ModelCallRequestMetadataPort>,
    verified: VerifiedInvocationAdmission,
    execution_id: &str,
    resumable: bool,
    events: Option<Arc<dyn EventPort>>,
) -> Result<RuntimeProfile, String> {
    let entries = verified
        .port_bindings
        .iter()
        .map(|binding| {
            let implementation = match binding.slot {
                PortSlot::ExecutionCommit => PortImplementation::ExecutionCommit(commit.clone()),
                PortSlot::Confinement => PortImplementation::Confinement(Arc::new(DevConfinement)),
                PortSlot::ModelInference => PortImplementation::ModelInference(model.clone()),
                PortSlot::Capability => PortImplementation::Capability(capability.clone()),
                PortSlot::ExternalAgentCapability => {
                    PortImplementation::ExternalAgentCapability(Arc::new(DevExternalAgent))
                }
                PortSlot::DurableEvent => {
                    if resumable {
                        PortImplementation::DurableEvent(
                            events.clone().unwrap_or_else(|| Arc::new(ParkedEvents)),
                        )
                    } else {
                        PortImplementation::DurableEvent(Arc::new(DevEvents))
                    }
                }
                PortSlot::ProgramComposition => {
                    PortImplementation::ProgramComposition(Arc::new(UnavailableComposition))
                }
            };
            (binding.clone(), implementation)
        })
        .collect();
    let runtime_admission =
        RuntimeAdmission::admit_invocation(verified, entries, "apxm-runtime-service", execution_id)
            .await
            .map_err(|error| error.to_string())?;
    let profile = RuntimeProfile::from_fully_admitted(
        runtime_admission,
        model_call_request_metadata,
        Arc::new(CapturedHookBodyHandler),
    )
    .map_err(|error| error.to_string())?;
    Ok(match observation_sink {
        Some(sink) => profile.with_observation_sink(sink, ObservationFailurePolicy::FailOpen),
        None => profile,
    })
}

fn model_targets(air: &AirModule) -> Vec<String> {
    let mut targets = Vec::new();
    for op in &air.semantic_operations {
        if op.op != SemanticOpKind::ModelCall {
            continue;
        }
        let Some(target) = op
            .operands
            .iter()
            .find(|operand| operand.slot == "model_ref")
            .map(|operand| operand.value_id.clone())
        else {
            continue;
        };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

fn local_capability_invocation_admissions(
    air: &AirModule,
    grants: &CapabilityGrantSet,
    permissions: &[AdmittedCapabilityPermission],
) -> Result<BTreeMap<String, CapabilityInvocationAdmission>, String> {
    let mut admissions = BTreeMap::new();
    for operation in &air.semantic_operations {
        if operation.op != SemanticOpKind::CapabilityInvoke {
            continue;
        }
        let Some(capability_ref) = operation
            .operands
            .iter()
            .find(|operand| operand.slot == apxm_ais::SLOT_CAPABILITY_REF)
            .map(|operand| operand.value_id.clone())
        else {
            continue;
        };
        let authority = CapabilityInvocationAuthority::new(
            LOCAL_ACTING_PRINCIPAL_REF,
            LOCAL_AGENT_IDENTITY_REF,
            format!("{LOCAL_CAPABILITY_GRANT_PREFIX}{capability_ref}"),
            Vec::new(),
        )
        .map_err(|error| error.to_string())?;
        let permission = permissions
            .iter()
            .find(|entry| entry.capability_ref == capability_ref)
            .map(|entry| entry.permission.clone())
            .ok_or_else(|| format!("no permission for {capability_ref}"))?;
        let admission = grants
            .admit(&capability_ref, authority, permission)
            .map_err(|error| error.to_string())?;
        admissions.insert(operation.node_id.clone(), admission);
    }
    Ok(admissions)
}

fn local_capability_permissions(
    air: &AirModule,
    admitted: &BTreeSet<String>,
    package_root: Option<&Path>,
) -> Result<Vec<AdmittedCapabilityPermission>, String> {
    let mut requested = LayerDecisions::new();
    for capability_ref in air.invoked_capability_refs() {
        let authored = air
            .capability_permission_requests
            .get(capability_ref)
            .cloned()
            .unwrap_or_else(PermissionDecision::allow);
        requested.insert(capability_ref.to_string(), authored);
    }

    let (package_layer, deployment_layer) = if let Some(package_root) = package_root {
        let package_decisions = canonical_package_permission_decisions(package_root, &requested)?;
        let package_layer = requested
            .iter()
            .filter_map(|(capability_ref, authored)| {
                let resolved = package_decisions.get(capability_ref)?;
                (resolved != authored).then(|| (capability_ref.clone(), resolved.clone()))
            })
            .collect();
        (package_layer, denied_unadmitted_capabilities(air, admitted))
    } else {
        (
            denied_unadmitted_capabilities(air, admitted),
            LayerDecisions::new(),
        )
    };

    let layers = if package_root.is_some() {
        BTreeMap::from([
            (apxm_ais::permissions::PermissionLayer::Code, requested),
            (
                apxm_ais::permissions::PermissionLayer::Package,
                package_layer,
            ),
            (
                apxm_ais::permissions::PermissionLayer::Deployment,
                deployment_layer,
            ),
        ])
    } else {
        BTreeMap::from([
            (apxm_ais::permissions::PermissionLayer::Code, requested),
            (
                apxm_ais::permissions::PermissionLayer::Package,
                package_layer,
            ),
        ])
    };
    let resolution = PermissionResolution::resolve(&layers).map_err(|error| error.to_string())?;
    Ok(admitted_capability_permissions(&resolution))
}

/// Validate the code-to-package tightening rule before a Runtime Service asks
/// an approval broker to resolve authored `Ask` decisions. A package that tries
/// to widen an authored request must fail at admission; otherwise the broker
/// could return `ask_denied` first and hide the invalid package layer.
pub fn validate_package_permission_resolution(
    air: &AirModule,
    package_root: Option<&Path>,
) -> Result<(), String> {
    let Some(package_root) = package_root else {
        return Ok(());
    };
    let requested = air
        .invoked_capability_refs()
        .into_iter()
        .map(|capability_ref| {
            let decision = air
                .capability_permission_requests
                .get(capability_ref)
                .cloned()
                .unwrap_or_else(PermissionDecision::allow);
            (capability_ref.to_string(), decision)
        })
        .collect();
    canonical_package_permission_decisions(package_root, &requested).map(|_| ())
}

/// Every host-fulfilled reference this artifact invokes.
fn invoked_host_capability_refs(air: &AirModule) -> BTreeSet<String> {
    air.invoked_capability_refs()
        .into_iter()
        .filter(|capability_ref| is_host_capability_ref(capability_ref))
        .map(ToOwned::to_owned)
        .collect()
}

fn denied_unadmitted_capabilities(air: &AirModule, admitted: &BTreeSet<String>) -> LayerDecisions {
    air.invoked_capability_refs()
        .into_iter()
        .filter(|capability_ref| !admitted.contains(*capability_ref))
        .map(|capability_ref| {
            (
                capability_ref.to_string(),
                PermissionDecision::deny(format!(
                    "canonical local execution binds no sandbox backend and no issued Capability \
                     grant, so it admits only the read-only capability surface [{}]",
                    admitted
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            )
        })
        .collect()
}

#[derive(Debug, serde::Deserialize)]
struct CanonicalPackageManifest {
    #[serde(default)]
    capabilities: ManifestCapabilities,
    #[serde(default)]
    permissions: LayerDecisions,
}

fn canonical_package_permission_decisions(
    package_root: &Path,
    authored: &LayerDecisions,
) -> Result<BTreeMap<String, PermissionDecision>, String> {
    let manifest_path = package_root.join("agent.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .map_err(|error| format!("failed to read {}: {error}", manifest_path.display()))?;
    let manifest: CanonicalPackageManifest = toml::from_str(&manifest)
        .map_err(|error| format!("failed to parse {}: {error}", manifest_path.display()))?;

    let mut grantable = apxm_ais::capabilities::BUILTINS
        .iter()
        .map(|id| (*id).to_string())
        .collect::<BTreeSet<_>>();
    grantable.extend(
        minted_host_capability_refs(&manifest.capabilities.host).map_err(|error| {
            format!("{}: [[capabilities.host]] {error}", manifest_path.display())
        })?,
    );
    let capabilities_dir = package_root.join("capabilities");
    if capabilities_dir.is_dir() {
        for entry in std::fs::read_dir(&capabilities_dir)
            .map_err(|error| format!("failed to read {}: {error}", capabilities_dir.display()))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            if !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                continue;
            }
            let path = entry.path();
            if path.join("handler.py").is_file() || path.join("handler.ts").is_file() {
                grantable.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }

    let requested_for_package = grantable
        .into_iter()
        .map(|capability_ref| {
            let decision = authored
                .get(&capability_ref)
                .cloned()
                .unwrap_or_else(PermissionDecision::allow);
            (capability_ref, decision)
        })
        .collect();
    let resolution = PermissionResolution::resolve_code_over_package(
        requested_for_package,
        manifest.permissions,
    )
    .map_err(|error| error.to_string())?;
    Ok(resolution
        .iter()
        .map(|(capability_ref, resolved)| (capability_ref.to_string(), resolved.decision.clone()))
        .collect())
}

fn model_admission(air: &AirModule, model_binding_digest: &str) -> ModelBindingAdmission {
    ModelBindingAdmission::for_invocation(
        model_targets(air)
            .into_iter()
            .map(|target| {
                ResolvedModelBinding::from_target_commitment(
                    InferenceTargetCommitment::commit(
                        target,
                        digest('b'),
                        "canonical.model",
                        model_binding_digest,
                        digest('c'),
                        digest('d'),
                        1,
                    )
                    .expect("development target commitment"),
                )
            })
            .collect(),
    )
}

fn reference_write_set(invocation_id: &str) -> AtomicWriteSet {
    let digest_for = |member: &str| digest_text(&format!("{invocation_id}\0{member}"));
    AtomicWriteSet {
        next_program_state_digest: digest_for("state_continuation"),
        continuation_digest: digest_for("continuation"),
        checkpoint_effect_outcomes_digest: digest_for("checkpoint_effect_outcomes"),
        runtime_evidence_batch_digest: digest_for("runtime_evidence"),
        usage_facts_digest: digest_for("usage_facts"),
        session_output_refs_digest: digest_for("session_output_refs"),
    }
}

fn failed_node_count(outcomes: &[NodeOutcome]) -> usize {
    outcomes
        .iter()
        .filter(|outcome| match outcome {
            NodeOutcome::Model { outcome, .. } => {
                matches!(outcome, ModelOutcome::TypedFailure { .. })
            }
            NodeOutcome::Capability { outcome, .. } => {
                matches!(outcome, CapabilityOutcome::Failed { .. })
            }
            NodeOutcome::ProgramNew { outcome, .. }
            | NodeOutcome::ProgramInvoke { outcome, .. } => {
                matches!(outcome, CompositionOutcome::Failed { .. })
            }
            NodeOutcome::AwaitEvent { outcome, .. } => matches!(
                outcome,
                EventOutcome::Expired | EventOutcome::Mismatched { .. }
            ),
            NodeOutcome::ExternalAgent { .. } => false,
        })
        .count()
}

fn node_outcome_json(outcome: &NodeOutcome) -> Value {
    match outcome {
        NodeOutcome::Model {
            node_id,
            outcome,
            result,
            replaced,
        } => json!({
            "node_id": node_id,
            "kind": "model.call",
            "outcome": model_outcome_json(outcome),
            "result": result,
            "replaced": replaced,
        }),
        NodeOutcome::Capability {
            node_id,
            outcome,
            replaced,
        } => json!({
            "node_id": node_id,
            "kind": "capability.invoke",
            "outcome": capability_outcome_json(outcome),
            "replaced": replaced,
        }),
        NodeOutcome::ExternalAgent { node_id, evidence } => json!({
            "node_id": node_id,
            "kind": "capability.invoke.external_agent",
            "outcome": "completed",
            "evidence": evidence,
        }),
        NodeOutcome::ProgramNew { node_id, outcome } => json!({
            "node_id": node_id,
            "kind": "program.new",
            "outcome": composition_outcome_json(outcome),
        }),
        NodeOutcome::ProgramInvoke { node_id, outcome } => json!({
            "node_id": node_id,
            "kind": "program.invoke",
            "outcome": composition_outcome_json(outcome),
        }),
        NodeOutcome::AwaitEvent { node_id, outcome } => json!({
            "node_id": node_id,
            "kind": "await.event",
            "outcome": event_outcome_json(outcome),
        }),
    }
}

fn model_outcome_json(outcome: &ModelOutcome) -> Value {
    match outcome {
        ModelOutcome::CommittedSuccess { usage } => json!({
            "status": "committed_success",
            "usage": usage,
        }),
        ModelOutcome::TypedFailure { error } => json!({
            "status": "typed_failure",
            "error": error,
        }),
        ModelOutcome::Cancelled => json!({"status": "cancelled"}),
        ModelOutcome::ModelOutcomeUnknown { uncertain_usage } => json!({
            "status": "model_outcome_unknown",
            "uncertain_usage": uncertain_usage,
        }),
    }
}

fn capability_outcome_json(outcome: &CapabilityOutcome) -> Value {
    match outcome {
        CapabilityOutcome::Completed { result } => {
            json!({"status": "completed", "result": result})
        }
        CapabilityOutcome::Failed { message } => json!({"status": "failed", "message": message}),
        CapabilityOutcome::OutcomeUnknown { message } => {
            json!({"status": "outcome_unknown", "message": message})
        }
    }
}

fn composition_outcome_json(outcome: &CompositionOutcome) -> Value {
    match outcome {
        CompositionOutcome::Created { child_instance_ref } => {
            json!({"status": "created", "child_instance_ref": child_instance_ref})
        }
        CompositionOutcome::Invoked { child_instance_ref } => {
            json!({"status": "invoked", "child_instance_ref": child_instance_ref})
        }
        CompositionOutcome::Failed { message } => json!({"status": "failed", "message": message}),
    }
}

fn event_outcome_json(outcome: &EventOutcome) -> Value {
    match outcome {
        EventOutcome::Fulfilled { event_ref, payload } => {
            json!({"status": "fulfilled", "event_ref": event_ref, "payload": payload})
        }
        EventOutcome::Parked => json!({"status": "parked"}),
        EventOutcome::Expired => json!({"status": "expired"}),
        EventOutcome::Cancelled => json!({"status": "cancelled"}),
        EventOutcome::Rejected { reason } => json!({"status": "rejected", "reason": reason}),
        EventOutcome::Mismatched {
            delivered_event_ref,
        } => json!({
            "status": "mismatched",
            "delivered_event_ref": delivered_event_ref,
        }),
    }
}

fn commit_result_json(result: &ExecutionCommitResult) -> Value {
    match result {
        ExecutionCommitResult::Committed {
            new_program_state_version,
            evidence_position_ref,
        } => json!({
            "status": "committed",
            "new_program_state_version": new_program_state_version,
            "evidence_position_ref": evidence_position_ref,
        }),
        ExecutionCommitResult::CompareConflict {
            current_program_state_version,
        } => json!({
            "status": "compare_conflict",
            "current_program_state_version": current_program_state_version,
        }),
        ExecutionCommitResult::OutcomeUnknown { reconciliation_ref } => json!({
            "status": "outcome_unknown",
            "reconciliation_ref": reconciliation_ref,
        }),
    }
}

fn runtime_status(report: &apxm_execution::RunReport) -> &'static str {
    match (&report.commit, report.terminal_status) {
        (
            ExecutionCommitResult::Committed { .. },
            apxm_execution::RunTerminalStatus::CommittedReturn,
        ) => "completed",
        (ExecutionCommitResult::Committed { .. }, apxm_execution::RunTerminalStatus::Failed) => {
            "failed"
        }
        (ExecutionCommitResult::Committed { .. }, apxm_execution::RunTerminalStatus::Cancelled) => {
            "cancelled"
        }
        (
            ExecutionCommitResult::Committed { .. },
            apxm_execution::RunTerminalStatus::OutcomeUnknown,
        )
        | (ExecutionCommitResult::OutcomeUnknown { .. }, _) => "outcome_unknown",
        (ExecutionCommitResult::CompareConflict { .. }, _) => "compare_conflict",
    }
}
