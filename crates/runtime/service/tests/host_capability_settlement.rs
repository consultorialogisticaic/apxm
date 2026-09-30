//! Conformance for host-fulfilled Capability requests over Runtime/1.
//!
//! A `host:` reference is never executed by APXM. The runtime publishes a
//! `capability_requested` observation, parks the invocation on the durable
//! continuation, and settles the node when the embedding host answers with
//! `capability_fulfill` or withdraws with `capability_cancel` (ADR-0025).
//! Everything below drives the shipped service through that path.

use std::fs;
use std::path::PathBuf;

use apxm_core::types::host_capability::{
    HostCapabilityOutcomeKind, host_capability_request_id, is_host_capability_request_id,
};
use apxm_program::air::AirModule;
use apxm_program::artifact::ExecutableArtifact;
use apxm_runtime_protocol::{
    AuthoredPermission, Commitment, ExecutionObservation, GrantRef, ObservationKind, PrincipalRef,
    ProgramInvocationId, RUNTIME_PROTOCOL_VERSION, ReadContext, ReadPurpose, RequestId,
    RuntimeHandshake, RuntimeHandshakeV2, RuntimeOwnerClaim, RuntimeRequest, RuntimeRequestV2,
    RuntimeResult, RuntimeResultV2, ScopeRef,
};
use apxm_runtime_service::{
    InvocationMaterials, RuntimeService, RuntimeStatePolicy, materials_for_artifact,
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("the runtime service sits three levels under the repository root")
        .join("tools/tests/fixtures")
}

fn handshake() -> RuntimeHandshake {
    RuntimeHandshake {
        protocol_version: RUNTIME_PROTOCOL_VERSION.to_owned(),
    }
}

fn host_capability_artifact() -> Vec<u8> {
    let raw = fs::read(fixture_dir().join("canonical-host-capability-execute.air.json"))
        .expect("the host capability fixture AIR");
    let air: AirModule = serde_json::from_slice(&raw).expect("fixture AIR decodes");
    ExecutableArtifact::from_air(&air)
        .expect("the fixture seals into an artifact")
        .encode()
        .expect("the fixture artifact encodes")
}

fn materials(artifact: &[u8], invocation_id: &str) -> InvocationMaterials {
    let release = fs::read(fixture_dir().join("canonical-execute.release.json")).expect("release");
    let provenance =
        fs::read(fixture_dir().join("canonical-execute.provenance.json")).expect("provenance");
    materials_for_artifact(artifact, invocation_id, release, provenance)
}

/// One started invocation of the fixture, parked on its first host request.
struct Parked {
    service: RuntimeService,
    instance: String,
    owner_claim: RuntimeOwnerClaim,
    invocation: String,
}

fn start_fixture(invocation_id: &str) -> Parked {
    start_fixture_with_service(
        invocation_id,
        RuntimeService::in_memory()
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned()),
    )
}

fn start_fixture_with_service(invocation_id: &str, service: RuntimeService) -> Parked {
    start_artifact_with_input(
        invocation_id,
        service,
        host_capability_artifact(),
        serde_json::json!({}),
    )
}

fn start_artifact_with_input(
    invocation_id: &str,
    mut service: RuntimeService,
    artifact: Vec<u8>,
    input: serde_json::Value,
) -> Parked {
    let digest = service.admit_artifact(artifact.clone());
    assert!(!digest.is_empty(), "the fixture artifact is admitted");
    let created = service
        .handle(
            &handshake(),
            RuntimeRequest::ProgramInstanceCreate {
                request_id: "create".to_owned(),
                artifact_digest: digest,
            },
        )
        .expect("instance creation is admitted");
    let RuntimeResult::ProgramInstanceCreated {
        program_instance_id,
        owner_claim,
        ..
    } = created
    else {
        panic!("instance creation failed: {created:?}");
    };
    service
        .bind_admission(&program_instance_id, materials(&artifact, invocation_id))
        .expect("the fixture admission binds");
    let started = service
        .handle(
            &handshake(),
            RuntimeRequest::ProgramInvocationStart {
                request_id: "start".to_owned(),
                program_instance_id: program_instance_id.clone(),
                owner_claim: owner_claim.clone(),
                input,
            },
        )
        .expect("the invocation starts");
    let RuntimeResult::ProgramInvocationStarted {
        program_invocation_id,
        ..
    } = started
    else {
        panic!("the invocation did not start: {started:?}");
    };
    Parked {
        service,
        instance: program_instance_id,
        owner_claim,
        invocation: program_invocation_id,
    }
}

#[test]
fn compiled_entrypoint_input_reaches_host_with_inline_or_named_mapping() {
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for frontend in [Frontend::Python, Frontend::Typescript] {
        for named in [false, true] {
            let source = match frontend {
                Frontend::Typescript => r#"import { Workflow, Capability } from "@apxm/frontend";
type Input = {reference: string; state: string};
const Notes = Capability<unknown, unknown>("host:notes.search");
export const Transform = Workflow<Input, unknown>({name: "Transform", async run(agent, input) {
  if (input.state === "submitted") {
    MAPPING
    return await Notes(ARGUMENT);
  }
  return {ignored: true};
}});
"#
                .replace(
                    "MAPPING",
                    if named {
                        "const mapped = {reference: input.reference};"
                    } else {
                        ""
                    },
                )
                .replace(
                    "ARGUMENT",
                    if named {
                        "mapped"
                    } else {
                        "{reference: input.reference}"
                    },
                ),
                Frontend::Python => r#"from typing import TypedDict
from apxm_program import Workflow, Capability
class Input(TypedDict):
    reference: str
    state: str
Notes = Capability[object, object]("host:notes.search")
@Workflow(input=Input, output=object)
async def Transform(agent, input):
    if input["state"] == "submitted":
        MAPPING
        return await Notes(ARGUMENT)
    return {"ignored": True}
"#
                .replace(
                    "        MAPPING\n",
                    if named {
                        "        mapped = {\"reference\": input[\"reference\"]}\n"
                    } else {
                        ""
                    },
                )
                .replace(
                    "ARGUMENT",
                    if named {
                        "mapped"
                    } else {
                        "{\"reference\": input[\"reference\"]}"
                    },
                ),
            };
            let compiled = compile_source_bundle(
                &SourceBundleRequest::new(frontend, "Transform", source)
                    .with_host_capabilities(["notes.search"]),
                &roots,
                &drivers,
            )
            .unwrap();
            let artifact =
                ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                    .unwrap()
                    .encode()
                    .unwrap();
            for state in ["submitted", "draft"] {
                let mut parked = start_artifact_with_input(
                    "invocation.input.mapping",
                    RuntimeService::in_memory()
                        .with_embedded_read_access()
                        .with_output_access_scope_ref("scope.host-capability".to_owned()),
                    artifact.clone(),
                    serde_json::json!({"reference":"R-42", "state":state}),
                );
                let invocation = parked.invocation.clone();
                let stream = observations(&mut parked.service, &invocation);
                let requested = of_kind(&stream, ObservationKind::CapabilityRequested);
                assert_eq!(requested.len(), usize::from(state == "submitted"));
                if state == "submitted" {
                    let host = requested[0].host_capability.as_ref().unwrap();
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(host.input.as_ref().unwrap())
                            .unwrap(),
                        serde_json::json!({"reference":"R-42"})
                    );
                    let request_id = host.capability_request_id.clone();
                    let result = fulfill(
                        &mut parked,
                        "settle.mapping",
                        &request_id,
                        HostCapabilityOutcomeKind::Ok,
                        Some("{\"accepted\":true}"),
                    );
                    assert!(matches!(result, RuntimeResult::CapabilitySettled { .. }));
                    let final_stream = observations(&mut parked.service, &invocation);
                    assert_eq!(
                        of_kind(&final_stream, ObservationKind::CapabilitySettled).len(),
                        1
                    );
                    assert_eq!(
                        of_kind(&final_stream, ObservationKind::CapabilityRequested).len(),
                        1
                    );
                    assert_eq!(
                        of_kind(&final_stream, ObservationKind::TerminalCommitted).len(),
                        1
                    );
                } else {
                    assert_eq!(
                        of_kind(&stream, ObservationKind::TerminalCommitted).len(),
                        1
                    );
                }
                assert_eq!(
                    invocation_status(&mut parked.service, &invocation),
                    apxm_runtime_protocol::ProgramInvocationStatus::CommittedReturn
                );
                let final_stream = observations(&mut parked.service, &invocation);
                let terminal = of_kind(&final_stream, ObservationKind::TerminalCommitted);
                let output_ref = terminal[0].output_ref.clone().unwrap();
                let result = parked
                    .service
                    .handle_v2(
                        &RuntimeHandshakeV2::server(),
                        RuntimeRequestV2::OutputRead {
                            context: ReadContext {
                                request_id: RequestId::new("read.mapping.output").unwrap(),
                                scope_ref: ScopeRef::new("scope.host-capability").unwrap(),
                                principal_ref: PrincipalRef::new("principal.host-capability")
                                    .unwrap(),
                                grant_ref: GrantRef::new("grant.host-capability").unwrap(),
                                correlation_id: None,
                                purpose: ReadPurpose::Output,
                            },
                            output_ref,
                        },
                    )
                    .unwrap();
                let RuntimeResultV2::Output { output, .. } = result else {
                    panic!("{result:?}")
                };
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&output.bytes).unwrap(),
                    if state == "submitted" {
                        serde_json::json!("{\"accepted\":true}")
                    } else {
                        serde_json::json!({"ignored":true})
                    }
                );
            }
        }
    }
}

#[test]
fn compiled_typed_events_recover_into_host_capability_with_exact_payload_and_generation() {
    use apxm_kernel::event_api::{EventApplication, EventApplicationResult, EventOccurrence};
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for (frontend, yield_first) in [
        (Frontend::Typescript, false),
        (Frontend::Python, false),
        (Frontend::Typescript, true),
        (Frontend::Python, true),
    ] {
        let source = match frontend {
            Frontend::Typescript => {
                r#"import { Workflow, Event, type EventRef, Capability } from "@apxm/frontend";
type Payload = { reference: string; approved: boolean };
type Input = { event: EventRef<Payload> };
const Submitted = Event<Payload>("event.submitted");
const Read = Capability<Payload, Payload>("host:notes.search");
export const EventReader = Workflow<Input, Payload>({name:"EventReader",async run(agent,input){
    const payload = await Submitted.wait(input.event);
    return await Read(payload);
}});
"#
            }
            Frontend::Python => {
                r#"from typing import TypedDict
from apxm_program import Workflow, Event, EventRef, Capability
class Payload(TypedDict):
    reference: str
    approved: bool
class Input(TypedDict):
    event: EventRef[Payload]
Submitted = Event[Payload]("event.submitted")
Read = Capability[Payload, Payload]("host:notes.search")
@Workflow(input=Input,output=Payload)
async def EventReader(agent,input):
    payload = await Submitted.wait(input["event"])
    return await Read(payload)
"#
            }
        };
        let source = if yield_first {
            match frontend {
                Frontend::Typescript => source.replace(
                    "const payload = await Submitted.wait(input.event);",
                    "const next: Input = await agent.yield_({reference: 'ready', approved: false}); const payload = await Submitted.wait(next.event);",
                ),
                Frontend::Python => source.replace(
                    "payload = await Submitted.wait(input[\"event\"])",
                    "next_input: Input = await agent.yield_({\"reference\": \"ready\", \"approved\": False})\n    payload = await Submitted.wait(next_input[\"event\"])",
                ),
            }
        } else {
            source.to_owned()
        };
        let compiled = compile_source_bundle(
            &SourceBundleRequest::new(frontend, "EventReader", source)
                .with_host_capabilities(["notes.search"]),
            &roots,
            &drivers,
        )
        .unwrap();
        assert_eq!(compiled.air.event_requirements.len(), 1);
        let artifact =
            ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                .unwrap()
                .encode()
                .unwrap();
        for early in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let mut service = RuntimeService::in_memory()
                .with_runtime_state_dir(directory.path().to_path_buf())
                .with_embedded_read_access()
                .with_output_access_scope_ref("scope.host-capability".into());
            let digest = service.admit_artifact(artifact.clone());
            let created = service
                .handle(
                    &handshake(),
                    RuntimeRequest::ProgramInstanceCreate {
                        request_id: "event.create".into(),
                        artifact_digest: digest,
                    },
                )
                .unwrap();
            let RuntimeResult::ProgramInstanceCreated {
                program_instance_id: instance,
                owner_claim: claim,
                ..
            } = created
            else {
                panic!("{created:?}")
            };
            service
                .bind_admission(&instance, materials(&artifact, "event.admission"))
                .unwrap();
            let reserved = service
                .handle(
                    &handshake(),
                    RuntimeRequest::EventReserve {
                        request_id: "event.reserve".into(),
                        program_instance_id: instance.clone(),
                        owner_claim: claim.clone(),
                        type_id: "event.submitted".into(),
                    },
                )
                .unwrap();
            let RuntimeResult::EventReserved {
                mut event_ref,
                owner_claim: mut event_claim,
                ..
            } = reserved
            else {
                panic!("{reserved:?}")
            };
            if yield_first {
                let initial = service
                    .handle(
                        &handshake(),
                        RuntimeRequest::ProgramInvocationStart {
                            request_id: "event.initial".into(),
                            program_instance_id: instance.clone(),
                            owner_claim: claim.clone(),
                            input: serde_json::json!({"event":event_ref}),
                        },
                    )
                    .unwrap();
                let RuntimeResult::ProgramInvocationStarted {
                    program_invocation_id,
                    ..
                } = initial
                else {
                    panic!("{initial:?}")
                };
                assert_eq!(
                    invocation_status(&mut service, &program_invocation_id),
                    apxm_runtime_protocol::ProgramInvocationStatus::CommittedYield
                );
                let next = service
                    .handle(
                        &handshake(),
                        RuntimeRequest::EventReserve {
                            request_id: "event.after-yield".into(),
                            program_instance_id: instance.clone(),
                            owner_claim: claim.clone(),
                            type_id: "event.submitted".into(),
                        },
                    )
                    .unwrap();
                let RuntimeResult::EventReserved {
                    event_ref: next_ref,
                    owner_claim: next_claim,
                    ..
                } = next
                else {
                    panic!("{next:?}")
                };
                event_ref = next_ref;
                event_claim = next_claim;
            }
            let payload = serde_json::json!({"reference":"exact-source-payload","approved":true});
            let application = EventApplication {
                event_ref: event_ref.clone(),
                idempotency_key: "event.application".into(),
                occurrence: EventOccurrence {
                    occurrence_id: "event.occurrence".into(),
                    source_kind: "test.signed-source".into(),
                    mapping_digest: "source.mapping".into(),
                    source_record: "source.record".into(),
                    payload: payload.clone(),
                },
            };
            let deliver =
                |service: &mut RuntimeService, application: EventApplication<serde_json::Value>| {
                    service
                        .handle(
                            &handshake(),
                            RuntimeRequest::EventFulfill {
                                request_id: "event.fulfill".into(),
                                owner_claim: event_claim.clone(),
                                application,
                            },
                        )
                        .unwrap()
                };
            if early {
                assert!(matches!(
                    deliver(&mut service, application.clone()),
                    RuntimeResult::EventApplied {
                        result: EventApplicationResult::Fulfilled,
                        ..
                    }
                ));
            }
            let started = service
                .handle(
                    &handshake(),
                    RuntimeRequest::ProgramInvocationStart {
                        request_id: "event.start".into(),
                        program_instance_id: instance.clone(),
                        owner_claim: claim.clone(),
                        input: serde_json::json!({"event":event_ref}),
                    },
                )
                .unwrap();
            let RuntimeResult::ProgramInvocationStarted {
                program_invocation_id: invocation,
                ..
            } = started
            else {
                panic!("{started:?}")
            };
            assert!(
                of_kind(
                    &observations(&mut service, &invocation),
                    ObservationKind::CapabilityRequested
                )
                .is_empty()
            );
            if !early {
                assert!(matches!(
                    deliver(&mut service, application.clone()),
                    RuntimeResult::EventApplied {
                        result: EventApplicationResult::Fulfilled,
                        ..
                    }
                ));
            }
            drop(service); // accepted delivery + parked invocation survive a process restart
            let service = RuntimeService::in_memory()
                .with_runtime_state_dir(directory.path().to_path_buf())
                .with_embedded_read_access()
                .with_output_access_scope_ref("scope.host-capability".into());
            assert!(
                service.startup_error().is_none(),
                "{:?}",
                service.startup_error()
            );
            let shared = Arc::new(Mutex::new(service));
            let dispatcher =
                apxm_runtime_service::InvocationDispatcher::start(shared.clone()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let request = loop {
                let stream = observations(&mut shared.lock().unwrap(), &invocation);
                let requests = of_kind(&stream, ObservationKind::CapabilityRequested);
                if let Some(request) = requests.first() {
                    break request.host_capability.clone().unwrap();
                }
                assert!(
                    Instant::now() < deadline,
                    "Event wake did not reach authored Capability: {stream:?}"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(request.input.as_ref().unwrap()).unwrap(),
                payload
            );
            let mut service = shared.lock().unwrap();
            let stream = observations(&mut service, &invocation);
            for kind in [ObservationKind::EventWaiting, ObservationKind::EventResumed] {
                let events = of_kind(&stream, kind);
                assert_eq!(events.len(), 1);
                let target = events[0].event_ref.as_ref().unwrap();
                assert_eq!(target.event_ref, event_ref.event_id);
                assert_eq!(target.generation, Some(event_ref.generation));
            }
            let settled = service
                .handle(
                    &handshake(),
                    RuntimeRequest::CapabilityFulfill {
                        request_id: "host.settle".into(),
                        owner_claim: claim.clone(),
                        capability_request_id: request.capability_request_id,
                        outcome: HostCapabilityOutcomeKind::Ok,
                        output: Some(payload.to_string()),
                        receipt_ref: Some("receipt.event.host".into()),
                        message: None,
                    },
                )
                .unwrap();
            assert!(
                matches!(settled, RuntimeResult::CapabilitySettled { .. }),
                "{settled:?}"
            );
            drop(service);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let stream = observations(&mut shared.lock().unwrap(), &invocation);
                if !of_kind(&stream, ObservationKind::TerminalCommitted).is_empty() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "accepted host settlement did not finish: {stream:?}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let mut service = shared.lock().unwrap();
            assert_eq!(
                committed_output(&mut service, &invocation),
                serde_json::Value::String(payload.to_string())
            );
            assert!(
                matches!(service.handle(&handshake(), RuntimeRequest::EventReserve {
                request_id:"event.after-return".into(), program_instance_id:instance.clone(),
                owner_claim:claim.clone(), type_id:"event.submitted".into(),
            }).unwrap(), RuntimeResult::Failed {code, ..} if code == "instance_unavailable")
            );
            assert!(matches!(
                deliver(&mut service, application.clone()),
                RuntimeResult::EventApplied {
                    result: EventApplicationResult::Fulfilled,
                    ..
                }
            ));
            let mut conflict = application;
            conflict.idempotency_key = "changed.key".into();
            conflict.occurrence.payload =
                serde_json::json!({"reference":"changed","approved":false});
            assert!(matches!(
                deliver(&mut service, conflict),
                RuntimeResult::EventApplied {
                    result: EventApplicationResult::Conflict,
                    ..
                }
            ));
            assert_eq!(
                of_kind(
                    &observations(&mut service, &invocation),
                    ObservationKind::CapabilityRequested
                )
                .len(),
                1,
                "replay cannot dispatch another effect"
            );
            drop(service);
            drop(dispatcher);
            let deadline = Instant::now() + Duration::from_secs(5);
            while Arc::strong_count(&shared) > 1 {
                assert!(
                    Instant::now() < deadline,
                    "dispatcher workers did not shut down"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// The PLAN qualification item: one instance holding two live reservations, each
/// consumed by its own exact wait.
///
/// Two reservations exist from the start, so neither wait can be identified by
/// "the instance's Event" — only by its own destination. The delivery order is
/// inverted on purpose: the second reservation is fulfilled while execution is
/// still parked on the first, which must neither wake the first wait nor be lost
/// before the second wait commits its binding.
#[test]
fn two_live_reservations_bind_to_their_own_exact_waits_in_one_instance() {
    use apxm_kernel::event_api::{EventApplication, EventApplicationResult, EventOccurrence};
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for frontend in [Frontend::Typescript, Frontend::Python] {
        let source = match frontend {
            Frontend::Typescript => {
                r#"import { Workflow, Event, type EventRef } from "@apxm/frontend";
type Payload = { reference: string; approved: boolean };
type Input = { first: EventRef<Payload>; second: EventRef<Payload> };
const First = Event<Payload>("event.first");
const Second = Event<Payload>("event.second");
export const TwoWaits = Workflow<Input, Payload>({name:"TwoWaits",async run(agent,input){
    const one = await First.wait(input.first);
    const two = await Second.wait(input.second);
    return two;
}});
"#
            }
            Frontend::Python => {
                r#"from typing import TypedDict
from apxm_program import Workflow, Event, EventRef
class Payload(TypedDict):
    reference: str
    approved: bool
class Input(TypedDict):
    first: EventRef[Payload]
    second: EventRef[Payload]
First = Event[Payload]("event.first")
Second = Event[Payload]("event.second")
@Workflow(input=Input,output=Payload)
async def TwoWaits(agent,input):
    one = await First.wait(input["first"])
    two = await Second.wait(input["second"])
    return two
"#
            }
        };
        let compiled = compile_source_bundle(
            &SourceBundleRequest::new(frontend, "TwoWaits", source.to_owned()),
            &roots,
            &drivers,
        )
        .unwrap();
        assert_eq!(compiled.air.event_requirements.len(), 2);
        let artifact =
            ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                .unwrap()
                .encode()
                .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut service = RuntimeService::in_memory()
            .with_runtime_state_dir(directory.path().to_path_buf())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".into());
        let digest = service.admit_artifact(artifact.clone());
        let created = service
            .handle(
                &handshake(),
                RuntimeRequest::ProgramInstanceCreate {
                    request_id: "two.create".into(),
                    artifact_digest: digest,
                },
            )
            .unwrap();
        let RuntimeResult::ProgramInstanceCreated {
            program_instance_id: instance,
            owner_claim: claim,
            ..
        } = created
        else {
            panic!("{created:?}")
        };
        service
            .bind_admission(&instance, materials(&artifact, "two.admission"))
            .unwrap();
        let reserve = |service: &mut RuntimeService, request: &str, type_id: &str| {
            let reserved = service
                .handle(
                    &handshake(),
                    RuntimeRequest::EventReserve {
                        request_id: request.into(),
                        program_instance_id: instance.clone(),
                        owner_claim: claim.clone(),
                        type_id: type_id.into(),
                    },
                )
                .unwrap();
            let RuntimeResult::EventReserved {
                event_ref,
                owner_claim,
                ..
            } = reserved
            else {
                panic!("{reserved:?}")
            };
            (event_ref, owner_claim)
        };
        let (first_ref, first_claim) = reserve(&mut service, "two.reserve.first", "event.first");
        let (second_ref, second_claim) =
            reserve(&mut service, "two.reserve.second", "event.second");
        assert_ne!(first_ref, second_ref, "two waits need two destinations");

        let payload = |reference: &str| serde_json::json!({"reference":reference,"approved":true});
        let application = |target: &apxm_kernel::event_api::CanonicalEventRef, reference: &str| {
            EventApplication {
                event_ref: target.clone(),
                idempotency_key: format!("two.application.{reference}"),
                occurrence: EventOccurrence {
                    occurrence_id: format!("two.occurrence.{reference}"),
                    source_kind: "test.signed-source".into(),
                    mapping_digest: "source.mapping".into(),
                    source_record: "source.record".into(),
                    payload: payload(reference),
                },
            }
        };
        let started = service
            .handle(
                &handshake(),
                RuntimeRequest::ProgramInvocationStart {
                    request_id: "two.start".into(),
                    program_instance_id: instance.clone(),
                    owner_claim: claim.clone(),
                    input: serde_json::json!({"first":first_ref,"second":second_ref}),
                },
            )
            .unwrap();
        let RuntimeResult::ProgramInvocationStarted {
            program_invocation_id: invocation,
            ..
        } = started
        else {
            panic!("{started:?}")
        };
        let stream = observations(&mut service, &invocation);
        let waiting = of_kind(&stream, ObservationKind::EventWaiting);
        assert_eq!(waiting.len(), 1, "the second wait is not reached yet");
        assert_eq!(
            waiting[0].event_ref.as_ref().unwrap().event_ref,
            first_ref.event_id
        );

        let deliver = |service: &mut RuntimeService,
                       owner_claim: &RuntimeOwnerClaim,
                       application: EventApplication<serde_json::Value>| {
            service
                .handle(
                    &handshake(),
                    RuntimeRequest::EventFulfill {
                        request_id: "two.fulfill".into(),
                        owner_claim: owner_claim.clone(),
                        application,
                    },
                )
                .unwrap()
        };
        // Out of order: the destination the program has not reached yet settles
        // first and must simply wait for its own wait to commit.
        for (owner_claim, target, reference) in [
            (&second_claim, &second_ref, "second"),
            (&first_claim, &first_ref, "first"),
        ] {
            assert!(matches!(
                deliver(&mut service, owner_claim, application(target, reference)),
                RuntimeResult::EventApplied {
                    result: EventApplicationResult::Fulfilled,
                    ..
                }
            ));
        }
        // Each reservation carries its own claim: the second wait's owner cannot
        // speak for the first destination even with the first's exact payload.
        assert!(
            service
                .handle(
                    &handshake(),
                    RuntimeRequest::EventFulfill {
                        request_id: "two.crossed".into(),
                        owner_claim: second_claim.clone(),
                        application: application(&first_ref, "first"),
                    },
                )
                .is_err()
        );

        let shared = Arc::new(Mutex::new(service));
        let dispatcher = apxm_runtime_service::InvocationDispatcher::start(shared.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let stream = observations(&mut shared.lock().unwrap(), &invocation);
            if !of_kind(&stream, ObservationKind::TerminalCommitted).is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "two bound waits did not both complete: {stream:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut service = shared.lock().unwrap();
        let stream = observations(&mut service, &invocation);
        for kind in [ObservationKind::EventWaiting, ObservationKind::EventResumed] {
            let events = of_kind(&stream, kind);
            assert_eq!(events.len(), 2, "{kind:?}");
            let targets: Vec<_> = events
                .iter()
                .map(|event| {
                    let target = event.event_ref.as_ref().unwrap();
                    (target.event_ref.clone(), target.generation)
                })
                .collect();
            assert_eq!(
                targets,
                vec![
                    (first_ref.event_id.clone(), Some(first_ref.generation)),
                    (second_ref.event_id.clone(), Some(second_ref.generation)),
                ],
                "{kind:?} must name each wait's own destination in visit order"
            );
            let visits: Vec<_> = events
                .iter()
                .map(|event| event.node_execution_id.clone())
                .collect();
            assert_ne!(visits[0], visits[1], "{kind:?} binds two distinct visits");
        }
        assert_eq!(
            committed_output(&mut service, &invocation),
            payload("second"),
            "each wait consumed its own payload"
        );
        drop(service);
        drop(dispatcher);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Arc::strong_count(&shared) > 1 {
            assert!(
                Instant::now() < deadline,
                "dispatcher workers did not shut down"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn observations(service: &mut RuntimeService, invocation: &str) -> Vec<ExecutionObservation> {
    let peer = RuntimeHandshakeV2::server();
    let result = service
        .handle_v2(
            &peer,
            RuntimeRequestV2::ObservationSubscribe {
                context: ReadContext {
                    request_id: RequestId::new("read.observations").expect("request id"),
                    scope_ref: ScopeRef::new("scope.host-capability").expect("scope"),
                    principal_ref: PrincipalRef::new("principal.host-capability")
                        .expect("principal"),
                    grant_ref: GrantRef::new("grant.host-capability").expect("grant"),
                    correlation_id: None,
                    purpose: ReadPurpose::Observation,
                },
                program_invocation_id: ProgramInvocationId::new(invocation.to_owned())
                    .expect("invocation id"),
                after_cursor: None,
                limit: 1000,
            },
        )
        .expect("the observation page is readable");
    let RuntimeResultV2::ObservationPage { page, .. } = result else {
        panic!("observation subscribe returned {result:?}");
    };
    page.items
}

/// Read only the committed output reference emitted at an invocation boundary.
fn committed_output(service: &mut RuntimeService, invocation: &str) -> serde_json::Value {
    let stream = observations(service, invocation);
    let terminal = of_kind(&stream, ObservationKind::TerminalCommitted);
    assert_eq!(terminal.len(), 1, "one terminal output per invocation");
    assert_eq!(terminal[0].commitment, Commitment::Committed);
    assert!(terminal[0].evidence_ref.is_some());
    let result = service
        .handle_v2(
            &RuntimeHandshakeV2::server(),
            RuntimeRequestV2::OutputRead {
                context: ReadContext {
                    request_id: RequestId::new("read.yield.output").unwrap(),
                    scope_ref: ScopeRef::new("scope.host-capability").unwrap(),
                    principal_ref: PrincipalRef::new("principal.host-capability").unwrap(),
                    grant_ref: GrantRef::new("grant.host-capability").unwrap(),
                    correlation_id: None,
                    purpose: ReadPurpose::Output,
                },
                output_ref: terminal[0]
                    .output_ref
                    .clone()
                    .expect("typed output is committed"),
            },
        )
        .unwrap();
    let RuntimeResultV2::Output { output, .. } = result else {
        panic!("{result:?}");
    };
    serde_json::from_slice(&output.bytes).unwrap()
}

#[test]
fn compiled_yield_reopens_same_instance_with_new_input_and_preserved_locals_and_context() {
    use apxm_runtime_protocol::ProgramInvocationStatus;
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for (frontend, declared_default) in [
        (Frontend::Python, false),
        (Frontend::Typescript, false),
        (Frontend::Python, true),
        (Frontend::Typescript, true),
    ] {
        let source = match frontend {
            Frontend::Typescript => {
                r#"import { Workflow, Capability, Context } from "@apxm/frontend";
type Input = {message: string};
type State = {first: string};
const StateContext = Context<State>();
const Notes = Capability<unknown, unknown>("host:notes.search");
export const Conversation = Workflow<Input, unknown, State>({name: "Conversation", context: StateContext, async run(agent, input) {
  agent.context = {first: input.message};
  const first = input.message;
  const next = await agent.yield_({reply: input.message});
  const receipt = await Notes({reference: next.message, first: first, saved: agent.context.first});
  return {first: first, saved: agent.context.first, next: next.message};
}});
"#
            }
            Frontend::Python => {
                r#"from typing import TypedDict
from apxm_program import Workflow, Capability, Context
class Input(TypedDict):
    message: str
class State(TypedDict):
    first: str
Notes = Capability[object, object]("host:notes.search")
@Workflow(input=Input, output=object, context=Context(State))
async def Conversation(agent, input):
    agent.context = {"first": input["message"]}
    first = input["message"]
    next_input = await agent.yield_({"reply": input["message"]})
    receipt = await Notes({"reference": next_input["message"], "first": first, "saved": agent.context["first"]})
    return {"first": first, "saved": agent.context["first"], "next": next_input["message"]}
"#
            }
        };
        let source = if declared_default {
            match frontend {
                Frontend::Typescript => source
                    .replace("type State = {first: string};", "type State = {first: string; inherited: string};")
                    .replace("Context<State>();", "Context<State>({first: \"initial\", inherited: \"\"});")
                    .replace("agent.context = {first: input.message};", "agent.context = {first: input.message, inherited: agent.context.first};")
                    .replace("{reply: input.message}", "{reply: agent.context.inherited}"),
                Frontend::Python => source
                    .replace("class State(TypedDict):\n    first: str", "class State:\n    first: str = \"initial\"\n    inherited: str = \"\"")
                    .replace("agent.context = {\"first\": input[\"message\"]}", "agent.context = {\"first\": input[\"message\"], \"inherited\": agent.context[\"first\"]}")
                    .replace("{\"reply\": input[\"message\"]}", "{\"reply\": agent.context[\"inherited\"]}"),
            }
        } else {
            source.to_owned()
        };
        let expected_first_reply = if declared_default { "initial" } else { "first" };
        let compiled = compile_source_bundle(
            &SourceBundleRequest::new(frontend, "Conversation", source)
                .with_host_capabilities(["notes.search"]),
            &roots,
            &drivers,
        )
        .expect("typed yielding source compiles");
        assert_eq!(
            compiled.frontend_graph.program_definitions[0]
                .default_context
                .is_some(),
            declared_default
        );
        let artifact =
            ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                .unwrap()
                .encode()
                .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let service = RuntimeService::in_memory()
            .with_runtime_state_dir(directory.path().to_path_buf())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned());
        let mut parked = start_artifact_with_input(
            "invocation.conversation.first",
            service,
            artifact.clone(),
            serde_json::json!({"message":"first"}),
        );
        let first_invocation = parked.invocation.clone();
        assert_eq!(
            invocation_status(&mut parked.service, &first_invocation),
            ProgramInvocationStatus::CommittedYield
        );
        assert_eq!(
            committed_output(&mut parked.service, &first_invocation),
            serde_json::json!({"reply":expected_first_reply})
        );
        assert!(
            of_kind(
                &observations(&mut parked.service, &first_invocation),
                ObservationKind::CapabilityRequested
            )
            .is_empty()
        );
        let replay = RuntimeRequest::ProgramInvocationStart {
            request_id: "start".into(),
            program_instance_id: parked.instance.clone(),
            owner_claim: parked.owner_claim.clone(),
            input: serde_json::json!({"message":"first"}),
        };
        assert!(
            matches!(parked.service.handle(&handshake(), replay.clone()).unwrap(), RuntimeResult::ProgramInvocationStarted { program_invocation_id, .. } if program_invocation_id == first_invocation)
        );
        let conflict = RuntimeRequest::ProgramInvocationStart {
            request_id: "start".into(),
            program_instance_id: parked.instance.clone(),
            owner_claim: parked.owner_claim.clone(),
            input: serde_json::json!({"message":"changed"}),
        };
        assert!(
            matches!(parked.service.handle(&handshake(), conflict).unwrap(), RuntimeResult::Failed { code, .. } if code == "invocation_idempotency_conflict")
        );
        drop(parked.service);
        parked.service = RuntimeService::in_memory()
            .with_runtime_state_dir(directory.path().to_path_buf())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned());
        assert!(parked.service.startup_error().is_none());
        assert_eq!(
            committed_output(&mut parked.service, &first_invocation),
            serde_json::json!({"reply":expected_first_reply})
        );
        parked
            .service
            .bind_admission(
                &parked.instance,
                materials(&artifact, "invocation.conversation.second"),
            )
            .unwrap();
        let next = RuntimeRequest::ProgramInvocationStart {
            request_id: "start.second".into(),
            program_instance_id: parked.instance.clone(),
            owner_claim: parked.owner_claim.clone(),
            input: serde_json::json!({"message":"second"}),
        };
        let result = parked.service.handle(&handshake(), next.clone()).unwrap();
        let RuntimeResult::ProgramInvocationStarted {
            program_invocation_id,
            ..
        } = result
        else {
            panic!("new input did not resume: {result:?}");
        };
        assert_ne!(program_invocation_id, first_invocation);
        parked.invocation = program_invocation_id;
        let invocation = parked.invocation.clone();
        let stream = observations(&mut parked.service, &invocation);
        let requests = of_kind(&stream, ObservationKind::CapabilityRequested);
        assert_eq!(requests.len(), 1);
        let host = requests[0].host_capability.as_ref().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(host.input.as_ref().unwrap()).unwrap(),
            serde_json::json!({"reference":"second", "first":"first", "saved":"first"})
        );
        let capability_request_id = host.capability_request_id.clone();
        let busy = RuntimeRequest::ProgramInvocationStart {
            request_id: "start.concurrent".into(),
            program_instance_id: parked.instance.clone(),
            owner_claim: parked.owner_claim.clone(),
            input: serde_json::json!({"message":"third"}),
        };
        assert!(
            matches!(parked.service.handle(&handshake(), busy.clone()).unwrap(), RuntimeResult::Failed { code, .. } if code == "invocation_already_started")
        );
        assert!(matches!(
            fulfill(
                &mut parked,
                "settle.conversation",
                &capability_request_id,
                HostCapabilityOutcomeKind::Ok,
                Some("{}")
            ),
            RuntimeResult::CapabilitySettled { .. }
        ));
        assert_eq!(
            invocation_status(&mut parked.service, &invocation),
            ProgramInvocationStatus::CommittedReturn
        );
        assert_eq!(
            committed_output(&mut parked.service, &invocation),
            serde_json::json!({"first":"first", "saved":"first", "next":"second"})
        );
        assert!(
            matches!(parked.service.handle(&handshake(), busy).unwrap(), RuntimeResult::Failed { code, .. } if code == "program_instance_completed")
        );
        assert!(
            matches!(parked.service.handle(&handshake(), replay).unwrap(), RuntimeResult::ProgramInvocationStarted { program_invocation_id, .. } if program_invocation_id == first_invocation)
        );
        assert!(
            matches!(parked.service.handle(&handshake(), next).unwrap(), RuntimeResult::ProgramInvocationStarted { program_invocation_id, .. } if program_invocation_id == invocation)
        );
        assert_eq!(
            of_kind(
                &observations(&mut parked.service, &invocation),
                ObservationKind::CapabilityRequested
            )
            .len(),
            1,
            "request replay cannot repeat an effect"
        );
    }
}

/// Re-execute one test with its own empty roster and an optional exact fixture
/// target. This never changes the parallel test process's environment.
fn isolated_model_roster(test: &str, fixture_target: Option<&str>) -> bool {
    const CHILD: &str = "APXM_TEST_MODEL_ROSTER_CHILD";
    if std::env::var(CHILD).ok().as_deref() == Some(test) {
        return false;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, test)
        .env("APXM_HOME", directory.path())
        .env_remove("APXM_BACKEND")
        .env_remove("APXM_BACKEND_MODEL");
    if let Some(target) = fixture_target {
        command
            .env("APXM_BACKEND", "fixture")
            .env("APXM_BACKEND_MODEL", target);
    }
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "isolated source execution failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    true
}

#[test]
fn compiled_boolean_condition_without_effects_executes_typed_input() {
    use apxm_runtime_protocol::ProgramInvocationStatus;
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };
    if isolated_model_roster(
        "compiled_boolean_condition_without_effects_executes_typed_input",
        None,
    ) {
        return;
    }
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for frontend in [Frontend::Typescript, Frontend::Python] {
        let source = match frontend {
            Frontend::Typescript => {
                r#"import { Workflow } from "@apxm/frontend";
type Input = {enabled: boolean};
export const Condition = Workflow<Input, unknown>({name: "Condition", async run(agent, input) {
  if (input.enabled) { return {enabled: true}; }
  return {enabled: false};
}});
"#
            }
            Frontend::Python => {
                r#"from typing import TypedDict
from apxm_program import Workflow
class Input(TypedDict):
    enabled: bool
@Workflow(input=Input, output=object)
async def Condition(agent, input):
    if input["enabled"]:
        return {"enabled": True}
    return {"enabled": False}
"#
            }
        };
        let compiled = compile_source_bundle(
            &SourceBundleRequest::new(frontend, "Condition", source),
            &roots,
            &drivers,
        )
        .expect("pure typed condition compiles without effect dependencies");
        assert!(compiled.air.semantic_operations.is_empty());
        assert!(compiled.frontend_graph.model_requirements.is_empty());
        let artifact =
            ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                .unwrap()
                .encode()
                .unwrap();
        for enabled in [false, true] {
            let input = serde_json::json!({"enabled":enabled});
            let mut parked = start_artifact_with_input(
                "invocation.pure.condition",
                RuntimeService::in_memory()
                    .with_embedded_read_access()
                    .with_output_access_scope_ref("scope.host-capability".to_owned()),
                artifact.clone(),
                input.clone(),
            );
            let invocation = parked.invocation.clone();
            assert_eq!(
                invocation_status(&mut parked.service, &invocation),
                ProgramInvocationStatus::CommittedReturn
            );
            assert_eq!(committed_output(&mut parked.service, &invocation), input);
        }
    }
}

#[test]
fn compiled_model_request_uses_entrypoint_input_without_synthetic_values() {
    use apxm_runtime_protocol::ProgramInvocationStatus;
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };

    if isolated_model_roster(
        "compiled_model_request_uses_entrypoint_input_without_synthetic_values",
        Some("entrypoint.model"),
    ) {
        return;
    }
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for frontend in [Frontend::Typescript, Frontend::Python] {
        let source = match frontend {
            Frontend::Typescript => {
                r#"import { Agent, Model } from "@apxm/frontend";
type Input = {prompt: string};
type Output = {content: string};
const Review = Model<Input, Output>("entrypoint.model");
export const Reviewer = Agent<Input, Output>({name: "Reviewer", model: Review, async run(agent, input) {
  return await Review(input);
}});
"#
            }
            Frontend::Python => {
                r#"from typing import TypedDict
from apxm_program import Agent, Model
class Input(TypedDict):
    prompt: str
class Output(TypedDict):
    content: str
Review = Model[Input, Output]("entrypoint.model")
@Agent(input=Input, output=Output, model=Review)
async def Reviewer(agent, input):
    return await Review(input)
"#
            }
        };
        let assembled = match frontend {
            Frontend::Typescript => {
                source.replace("Review(input)", "Review({prompt: input.prompt})")
            }
            Frontend::Python => {
                source.replace("Review(input)", "Review({\"prompt\": input[\"prompt\"]})")
            }
        };
        let artifacts = [source, assembled.as_str()].map(|source| {
            let compiled = compile_source_bundle(
                &SourceBundleRequest::new(frontend, "Reviewer", source),
                &roots,
                &drivers,
            )
            .expect("the typed model-backed Agent compiles");
            ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                .unwrap()
                .encode()
                .unwrap()
        });
        for single_shot in [false, true] {
            let mut previous = None;
            for prompt in ["first exact prompt", "second exact prompt"] {
                let outputs = artifacts.each_ref().map(|artifact| {
                    let mut service = RuntimeService::in_memory()
                        .with_embedded_read_access()
                        .with_output_access_scope_ref("scope.host-capability".to_owned());
                    if single_shot {
                        service = service.with_single_shot_invocations();
                    }
                    let mut parked = start_artifact_with_input(
                        "invocation.model.entrypoint",
                        service,
                        artifact.clone(),
                        serde_json::json!({"prompt": prompt}),
                    );
                    let invocation = parked.invocation.clone();
                    assert_eq!(
                        invocation_status(&mut parked.service, &invocation),
                        ProgramInvocationStatus::CommittedReturn
                    );
                    let stream = observations(&mut parked.service, &invocation);
                    assert_eq!(of_kind(&stream, ObservationKind::ModelAttempt).len(), 1);
                    committed_output(&mut parked.service, &invocation)
                });
                // Reconstructing the same authored request must not change the
                // backend result; no test preloads either request SSA identity.
                assert_eq!(outputs[0], outputs[1]);
                assert!(
                    outputs[0]["content"]
                        .as_str()
                        .unwrap()
                        .starts_with("apxm-fixture:")
                );
                if let Some(previous) = previous {
                    assert_ne!(
                        previous, outputs[0],
                        "the actual prompt must reach inference"
                    );
                }
                previous = Some(outputs[0].clone());
            }
        }
    }
}

/// The explicitly selected development backend runs only in this child
/// process. Other tests keep their model-free runtime and ambient environment.
#[test]
fn compiled_agent_loop_uses_each_new_message_for_model_and_host_effects() {
    use apxm_runtime_protocol::ProgramInvocationStatus;
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };

    if isolated_model_roster(
        "compiled_agent_loop_uses_each_new_message_for_model_and_host_effects",
        Some("conversation.model"),
    ) {
        return;
    }

    fn settle_turn(parked: &mut Parked) -> serde_json::Value {
        let invocation = parked.invocation.clone();
        let stream = observations(&mut parked.service, &invocation);
        assert_eq!(of_kind(&stream, ObservationKind::ModelAttempt).len(), 1);
        assert_eq!(
            of_kind(&stream, ObservationKind::CapabilityRequested).len(),
            1
        );
        let (read_id, reference) = published_request(parked);
        assert_eq!(reference, "host:notes.search");
        assert!(matches!(
            fulfill(
                parked,
                "settle.read",
                &read_id,
                HostCapabilityOutcomeKind::Ok,
                Some("{}")
            ),
            RuntimeResult::CapabilitySettled { .. }
        ));
        let (write_id, reference) = published_request(parked);
        assert_ne!(write_id, read_id);
        assert_eq!(reference, "host:notes.write");
        assert!(matches!(
            fulfill(
                parked,
                "settle.write",
                &write_id,
                HostCapabilityOutcomeKind::Ok,
                Some("{}")
            ),
            RuntimeResult::CapabilitySettled { .. }
        ));
        assert_eq!(
            invocation_status(&mut parked.service, &invocation),
            ProgramInvocationStatus::CommittedYield
        );
        let stream = observations(&mut parked.service, &invocation);
        assert_eq!(
            of_kind(&stream, ObservationKind::CapabilityRequested).len(),
            2
        );
        assert_eq!(
            of_kind(&stream, ObservationKind::CapabilitySettled).len(),
            2
        );
        assert_eq!(of_kind(&stream, ObservationKind::ModelAttempt).len(), 1);
        let output = committed_output(&mut parked.service, &invocation);
        assert!(
            output["reply"]
                .as_str()
                .unwrap()
                .starts_with("apxm-fixture:")
        );
        assert_eq!(output["reviewed"], true);
        output
    }

    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for frontend in [Frontend::Typescript, Frontend::Python] {
        let source = match frontend {
            Frontend::Typescript => {
                r#"import { Agent, Capability, Model } from "@apxm/frontend";
type Input = {message: string};
type Output = {reply: string; reviewed: boolean};
type ModelInput = {prompt: string};
type ModelOutput = {content: string};
const review = Model<ModelInput, ModelOutput>("conversation.model");
const read = Capability<unknown, unknown>("host:notes.search");
const write = Capability<unknown, unknown>("host:notes.write");
export const Conversation = Agent<Input, Output>({name: "Conversation", model: review, async run(agent, input) {
  while (input.message !== "") {
    const response = await review({prompt: input.message});
    await read({limit: 10});
    await write({body: "reviewed"});
    input = await agent.yield_({reply: response.content, reviewed: true});
  }
  return {reply: "", reviewed: false};
}});
"#
            }
            Frontend::Python => {
                r#"from typing import TypedDict
from apxm_program import Agent, Capability, Model
class Input(TypedDict):
    message: str
class Output(TypedDict):
    reply: str
    reviewed: bool
class ModelInput(TypedDict):
    prompt: str
class ModelOutput(TypedDict):
    content: str
review = Model[ModelInput, ModelOutput]("conversation.model")
read = Capability[object, object]("host:notes.search")
write = Capability[object, object]("host:notes.write")
@Agent(input=Input, output=Output, model=review)
async def Conversation(agent, input):
    while input["message"] != "":
        response = await review({"prompt": input["message"]})
        await read({"limit": 10})
        await write({"body": "reviewed"})
        input = await agent.yield_({"reply": response["content"], "reviewed": True})
    return {"reply": "", "reviewed": False}
"#
            }
        };
        let compiled = compile_source_bundle(
            &SourceBundleRequest::new(frontend, "Conversation", source)
                .with_host_capabilities(["notes.search", "notes.write"]),
            &roots,
            &drivers,
        )
        .expect("typed model-backed loop source compiles");
        let artifact =
            ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                .unwrap()
                .encode()
                .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let service = || {
            RuntimeService::in_memory()
                .with_runtime_state_dir(directory.path().to_path_buf())
                .with_embedded_read_access()
                .with_output_access_scope_ref("scope.host-capability".to_owned())
        };
        let mut parked = start_artifact_with_input(
            "invocation.agent.first",
            service(),
            artifact.clone(),
            serde_json::json!({"message":"first"}),
        );
        let first = settle_turn(&mut parked);
        let first_invocation = parked.invocation.clone();
        drop(parked.service);
        parked.service = service();
        parked
            .service
            .bind_admission(
                &parked.instance,
                materials(&artifact, "invocation.agent.second"),
            )
            .unwrap();
        let next = RuntimeRequest::ProgramInvocationStart {
            request_id: "start.second".into(),
            program_instance_id: parked.instance.clone(),
            owner_claim: parked.owner_claim.clone(),
            input: serde_json::json!({"message":"second"}),
        };
        let result = parked.service.handle(&handshake(), next).unwrap();
        let RuntimeResult::ProgramInvocationStarted {
            program_invocation_id,
            ..
        } = result
        else {
            panic!("next Agent input was not admitted: {result:?}")
        };
        assert_ne!(program_invocation_id, first_invocation);
        parked.invocation = program_invocation_id;
        let second = settle_turn(&mut parked);
        assert_ne!(
            first, second,
            "a new message must produce a new model request"
        );

        // Independently start with the exact second input. Equality with its
        // request-derived completion proves the resumed loop used that input,
        // without copying the backend's request rendering/hash implementation.
        let mut baseline = start_artifact_with_input(
            "invocation.agent.baseline",
            RuntimeService::in_memory()
                .with_embedded_read_access()
                .with_output_access_scope_ref("scope.host-capability".to_owned()),
            artifact,
            serde_json::json!({"message":"second"}),
        );
        assert_eq!(second, settle_turn(&mut baseline));
    }
}

fn invocation_status(
    service: &mut RuntimeService,
    invocation: &str,
) -> apxm_runtime_protocol::ProgramInvocationStatus {
    let result = service
        .handle_v2(
            &RuntimeHandshakeV2::server(),
            RuntimeRequestV2::ProgramInvocationInspect {
                context: ReadContext {
                    request_id: RequestId::new("read.invocation").expect("request id"),
                    scope_ref: ScopeRef::new("scope.host-capability").expect("scope"),
                    principal_ref: PrincipalRef::new("principal.host-capability")
                        .expect("principal"),
                    grant_ref: GrantRef::new("grant.host-capability").expect("grant"),
                    correlation_id: None,
                    purpose: ReadPurpose::Inspection,
                },
                program_invocation_id: ProgramInvocationId::new(invocation.to_owned())
                    .expect("invocation id"),
                node_execution_id: None,
            },
        )
        .expect("the invocation inspection is readable");
    let RuntimeResultV2::ProgramInvocationInspection { inspection, .. } = result else {
        panic!("invocation inspection returned {result:?}");
    };
    inspection.status
}

fn of_kind(
    observations: &[ExecutionObservation],
    kind: ObservationKind,
) -> Vec<&ExecutionObservation> {
    observations
        .iter()
        .filter(|observation| observation.observation_kind == kind)
        .collect()
}

fn fulfill(
    parked: &mut Parked,
    request_id: &str,
    capability_request_id: &str,
    outcome: HostCapabilityOutcomeKind,
    output: Option<&str>,
) -> RuntimeResult {
    parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::CapabilityFulfill {
                request_id: request_id.to_owned(),
                owner_claim: parked.owner_claim.clone(),
                capability_request_id: capability_request_id.to_owned(),
                outcome,
                output: output.map(ToOwned::to_owned),
                receipt_ref: Some("receipt.host.1".to_owned()),
                message: (outcome != HostCapabilityOutcomeKind::Ok)
                    .then(|| "the host said so".to_owned()),
            },
        )
        .expect("the settlement is a well-formed Runtime/1 request")
}

/// The request identity the parked node published, read back from the stream
/// rather than reconstructed, so the test proves what a host would actually see.
fn published_request(parked: &mut Parked) -> (String, String) {
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    let requested = of_kind(&stream, ObservationKind::CapabilityRequested);
    let last = requested
        .last()
        .expect("the parked node published its request");
    let host = last
        .host_capability
        .as_ref()
        .expect("a capability_requested observation carries its request");
    (
        host.capability_request_id.clone(),
        host.capability_ref.clone(),
    )
}

#[test]
fn host_capability_node_inspection_settles_while_the_next_node_waits() {
    use apxm_runtime_protocol::{NodeExecutionId, NodeExecutionInspection, NodeExecutionStatus};
    fn inspect(
        service: &mut RuntimeService,
        invocation: &str,
        node: &NodeExecutionId,
    ) -> NodeExecutionInspection {
        let result = service
            .handle_v2(
                &RuntimeHandshakeV2::server(),
                RuntimeRequestV2::ProgramInvocationInspect {
                    context: ReadContext {
                        request_id: RequestId::new("read.host.node").unwrap(),
                        scope_ref: ScopeRef::new("scope.host-capability").unwrap(),
                        principal_ref: PrincipalRef::new("principal.host-capability").unwrap(),
                        grant_ref: GrantRef::new("grant.host-capability").unwrap(),
                        correlation_id: None,
                        purpose: ReadPurpose::Inspection,
                    },
                    program_invocation_id: ProgramInvocationId::new(invocation).unwrap(),
                    node_execution_id: Some(node.clone()),
                },
            )
            .unwrap();
        let RuntimeResultV2::NodeExecutionInspection { inspection, .. } = result else {
            panic!("expected node inspection: {result:?}")
        };
        assert_eq!(&inspection.node_execution_id, node);
        inspection
    }
    let mut parked = start_fixture("invocation.host.node-inspection");
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    let first = of_kind(&stream, ObservationKind::CapabilityRequested)[0]
        .node_execution_id
        .clone()
        .unwrap();
    assert_eq!(
        inspect(&mut parked.service, &invocation, &first).status,
        NodeExecutionStatus::Waiting
    );
    let (request, _) = published_request(&mut parked);
    assert!(matches!(
        fulfill(
            &mut parked,
            "settle.node.first",
            &request,
            HostCapabilityOutcomeKind::Ok,
            Some("{\"matches\":2}")
        ),
        RuntimeResult::CapabilitySettled { .. }
    ));
    let stream = observations(&mut parked.service, &invocation);
    let second = of_kind(&stream, ObservationKind::CapabilityRequested)[1]
        .node_execution_id
        .clone()
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        inspect(&mut parked.service, &invocation, &first).status,
        NodeExecutionStatus::Succeeded
    );
    assert_eq!(
        inspect(&mut parked.service, &invocation, &second).status,
        NodeExecutionStatus::Waiting
    );
    let (request, _) = published_request(&mut parked);
    assert!(matches!(
        fulfill(
            &mut parked,
            "settle.node.second",
            &request,
            HostCapabilityOutcomeKind::Ok,
            Some("{\"appended\":true}")
        ),
        RuntimeResult::CapabilitySettled { .. }
    ));
    assert_eq!(
        inspect(&mut parked.service, &invocation, &first).status,
        NodeExecutionStatus::Succeeded
    );
    assert_eq!(
        inspect(&mut parked.service, &invocation, &second).status,
        NodeExecutionStatus::Succeeded
    );
}

#[test]
fn a_host_reference_publishes_a_request_and_parks_the_invocation() {
    let mut parked = start_fixture("invocation.host.request");
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    let requested = of_kind(&stream, ObservationKind::CapabilityRequested);
    assert_eq!(
        requested.len(),
        1,
        "the driver publishes one request and stops; the second node is not reached"
    );
    let host = requested[0]
        .host_capability
        .as_ref()
        .expect("the observation carries the request");
    assert_eq!(host.capability_ref, "host:notes.search");
    assert_eq!(
        host.capability_request_id,
        host_capability_request_id(
            &invocation,
            requested[0]
                .node_execution_id
                .as_ref()
                .expect("the request names the node execution that published it")
                .as_str()
        ),
        "the identity is derived from the node that published it"
    );
    assert!(is_host_capability_request_id(&host.capability_request_id));
    assert_eq!(
        host.input.as_deref(),
        Some("{\"query\":\"canonical host capability\"}"),
        "a host that cannot read the arguments cannot perform the call"
    );
    assert_eq!(
        host.authored_permission,
        Some(AuthoredPermission::Allow),
        "the authored request travels to the host verbatim"
    );
    assert!(host.outcome.is_none(), "a request is not a settlement");
    assert!(
        of_kind(&stream, ObservationKind::CapabilitySettled).is_empty(),
        "nothing settled: no host has answered"
    );
    assert!(
        of_kind(&stream, ObservationKind::ApprovalRequested).is_empty(),
        "permission for a host reference is the host's decision; APXM does not broker it"
    );
}

#[test]
fn an_authored_ask_reaches_the_host_rather_than_the_broker() {
    // The fixture's second node authors `Ask`. The default broker denies every
    // Ask, so a brokered host reference would fail the invocation at start
    // rather than ever publishing a request. Reaching the second request at all
    // is the proof that APXM records the decision and does not resolve it.
    let mut parked = start_fixture("invocation.host.ask");
    let (first, _) = published_request(&mut parked);
    let settled = fulfill(
        &mut parked,
        "settle.first",
        &first,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"matches\":2}"),
    );
    assert!(
        matches!(settled, RuntimeResult::CapabilitySettled { .. }),
        "{settled:?}"
    );
    let (second, second_ref) = published_request(&mut parked);
    assert_ne!(second, first, "the second node publishes its own request");
    assert_eq!(second_ref, "host:notes.append");
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    let requested = of_kind(&stream, ObservationKind::CapabilityRequested);
    assert_eq!(requested.len(), 2);
    assert_eq!(
        requested[1]
            .host_capability
            .as_ref()
            .and_then(|host| host.authored_permission),
        Some(AuthoredPermission::Ask),
        "the authored Ask is recorded and carried, not resolved"
    );
}

#[test]
fn the_host_settles_a_request_and_the_invocation_continues() {
    let mut parked = start_fixture("invocation.host.ok");
    let (first, _) = published_request(&mut parked);
    let settled = fulfill(
        &mut parked,
        "settle.ok",
        &first,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"matches\":2}"),
    );
    let RuntimeResult::CapabilitySettled {
        capability_request_id,
        outcome,
        ..
    } = settled
    else {
        panic!("settlement failed: {settled:?}");
    };
    assert_eq!(capability_request_id, first);
    assert_eq!(outcome, HostCapabilityOutcomeKind::Ok);

    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    let settlements = of_kind(&stream, ObservationKind::CapabilitySettled);
    assert_eq!(settlements.len(), 1);
    let host = settlements[0]
        .host_capability
        .as_ref()
        .expect("a settlement observation carries how it settled");
    assert_eq!(host.outcome, Some(HostCapabilityOutcomeKind::Ok));
    assert_eq!(host.receipt_ref.as_deref(), Some("receipt.host.1"));
    assert!(
        host.input.is_none() && host.authored_permission.is_none(),
        "a settlement does not restate the request"
    );
    assert_eq!(
        of_kind(&stream, ObservationKind::CapabilityRequested).len(),
        2,
        "the invocation continued to the second host node"
    );
}

#[test]
fn every_refusing_outcome_settles_the_node_the_program_can_observe() {
    for (outcome, output) in [
        (HostCapabilityOutcomeKind::Denied, None),
        (HostCapabilityOutcomeKind::Failed, None),
        (HostCapabilityOutcomeKind::Unknown, None),
    ] {
        let mut parked = start_fixture("invocation.host.refused");
        let (first, _) = published_request(&mut parked);
        let settled = fulfill(&mut parked, "settle.refused", &first, outcome, output);
        let RuntimeResult::CapabilitySettled {
            outcome: recorded, ..
        } = settled
        else {
            panic!("settling as {outcome:?} failed: {settled:?}");
        };
        assert_eq!(recorded, outcome);
        let invocation = parked.invocation.clone();
        let stream = observations(&mut parked.service, &invocation);
        let settlements = of_kind(&stream, ObservationKind::CapabilitySettled);
        assert_eq!(settlements.len(), 1, "settling as {outcome:?}");
        assert_eq!(
            settlements[0]
                .host_capability
                .as_ref()
                .and_then(|host| host.outcome),
            Some(outcome)
        );
    }
}

#[test]
fn an_ok_settlement_without_an_output_is_refused_before_it_reaches_the_node() {
    let mut parked = start_fixture("invocation.host.malformed");
    let (first, _) = published_request(&mut parked);
    let refused = fulfill(
        &mut parked,
        "settle.malformed",
        &first,
        HostCapabilityOutcomeKind::Ok,
        None,
    );
    assert!(
        matches!(refused, RuntimeResult::Failed { ref code, .. } if code == "invalid_request"),
        "{refused:?}"
    );
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    assert!(
        of_kind(&stream, ObservationKind::CapabilitySettled).is_empty(),
        "a refused settlement never reaches the parked node"
    );
}

#[test]
fn a_settlement_for_a_request_nobody_published_is_refused() {
    let mut parked = start_fixture("invocation.host.unknown");
    let invented = host_capability_request_id("invocation.elsewhere", "node-execution.9");
    let refused = fulfill(
        &mut parked,
        "settle.unknown",
        &invented,
        HostCapabilityOutcomeKind::Ok,
        Some("{}"),
    );
    assert!(
        matches!(
            refused,
            RuntimeResult::Failed { ref code, .. } if code == "unknown_capability_request"
        ),
        "{refused:?}"
    );

    let malformed = fulfill(
        &mut parked,
        "settle.malformed-id",
        "evt-1",
        HostCapabilityOutcomeKind::Ok,
        Some("{}"),
    );
    assert!(
        matches!(
            malformed,
            RuntimeResult::Failed { ref code, .. } if code == "invalid_request"
        ),
        "{malformed:?}"
    );
}

#[test]
fn a_cancelled_fulfillment_is_refused_without_settling_the_node() {
    let mut parked = start_fixture("invocation.host.cancelled-fulfillment");
    let (first, _) = published_request(&mut parked);
    let refused = parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::CapabilityFulfill {
                request_id: "settle.cancelled".to_owned(),
                owner_claim: parked.owner_claim.clone(),
                capability_request_id: first.clone(),
                outcome: HostCapabilityOutcomeKind::Cancelled,
                output: None,
                receipt_ref: None,
                message: Some("withdrawn".to_owned()),
            },
        )
        .expect("the Runtime/1 request decodes");
    assert!(
        matches!(refused, RuntimeResult::Failed { ref code, .. } if code == "invalid_request"),
        "{refused:?}"
    );
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    assert!(of_kind(&stream, ObservationKind::CapabilitySettled).is_empty());
    assert!(matches!(
        fulfill(
            &mut parked,
            "settle.valid",
            &first,
            HostCapabilityOutcomeKind::Ok,
            Some("{}")
        ),
        RuntimeResult::CapabilitySettled { .. }
    ));
}

#[test]
fn a_settlement_under_the_wrong_owner_claim_is_refused() {
    let mut parked = start_fixture("invocation.host.owner");
    let (first, _) = published_request(&mut parked);
    let refused = parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::CapabilityFulfill {
                request_id: "settle.owner".to_owned(),
                owner_claim: RuntimeOwnerClaim::mint(),
                capability_request_id: first,
                outcome: HostCapabilityOutcomeKind::Ok,
                output: Some("{}".to_owned()),
                receipt_ref: None,
                message: None,
            },
        )
        .expect("a well-formed request");
    assert!(
        matches!(refused, RuntimeResult::Failed { ref code, .. } if code == "owner_mismatch"),
        "{refused:?}"
    );
}

#[test]
fn the_host_withdraws_a_request_and_the_node_settles_as_cancelled() {
    let mut parked = start_fixture("invocation.host.withdraw");
    let (first, _) = published_request(&mut parked);
    let cancelled = parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::CapabilityCancel {
                request_id: "withdraw".to_owned(),
                owner_claim: parked.owner_claim.clone(),
                capability_request_id: first.clone(),
                message: Some("the link to the system closed".to_owned()),
            },
        )
        .expect("a well-formed request");
    let RuntimeResult::CapabilitySettled {
        capability_request_id,
        outcome,
        ..
    } = cancelled
    else {
        panic!("withdrawal failed: {cancelled:?}");
    };
    assert_eq!(capability_request_id, first);
    assert_eq!(outcome, HostCapabilityOutcomeKind::Cancelled);
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    assert_eq!(
        of_kind(&stream, ObservationKind::CapabilitySettled)
            .first()
            .and_then(|observation| observation.host_capability.as_ref())
            .and_then(|host| host.outcome),
        Some(HostCapabilityOutcomeKind::Cancelled)
    );
    let replayed = parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::CapabilityCancel {
                request_id: "withdraw.replay".to_owned(),
                owner_claim: parked.owner_claim.clone(),
                capability_request_id: first,
                message: Some("the link to the system closed".to_owned()),
            },
        )
        .expect("the replay request decodes");
    assert!(matches!(
        replayed,
        RuntimeResult::CapabilitySettled {
            outcome: HostCapabilityOutcomeKind::Cancelled,
            ..
        }
    ));
}

#[test]
fn cancelling_the_invocation_cancels_the_request_it_is_parked_on() {
    let mut parked = start_fixture("invocation.host.cancel");
    let (first, _) = published_request(&mut parked);
    assert!(is_host_capability_request_id(&first));
    let cancelled = parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::ProgramInvocationCancel {
                request_id: "cancel".to_owned(),
                owner_claim: parked.owner_claim.clone(),
                program_invocation_id: parked.invocation.clone(),
            },
        )
        .expect("a well-formed request");
    assert!(
        matches!(cancelled, RuntimeResult::Cancelled { .. }),
        "{cancelled:?}"
    );
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    let settlements = of_kind(&stream, ObservationKind::CapabilitySettled);
    assert_eq!(
        settlements.len(),
        1,
        "the outstanding request is withdrawn rather than left for a host that will never answer"
    );
    assert_eq!(
        settlements[0]
            .host_capability
            .as_ref()
            .and_then(|host| host.outcome),
        Some(HostCapabilityOutcomeKind::Cancelled)
    );

    // The cancellation is authoritative: a later, conflicting fulfillment
    // cannot revive the cancelled invocation.
    let late = fulfill(
        &mut parked,
        "settle.late",
        &first,
        HostCapabilityOutcomeKind::Ok,
        Some("{}"),
    );
    assert!(
        matches!(
            late,
            RuntimeResult::Failed { ref code, .. } if code == "invalid_request"
        ),
        "{late:?}"
    );
    assert_eq!(
        invocation_status(&mut parked.service, &parked.invocation),
        apxm_runtime_protocol::ProgramInvocationStatus::Cancelled,
        "explicit invocation cancellation owns a parked, undispatched host request"
    );
    let stream = observations(&mut parked.service, &parked.invocation);
    assert!(
        of_kind(&stream, ObservationKind::InvocationCancelled)
            .iter()
            .any(|observation| observation.commitment == Commitment::Committed),
        "explicit invocation cancellation has a committed terminal observation"
    );
    assert!(
        of_kind(&stream, ObservationKind::OutcomeUnknown).is_empty(),
        "a parked host request has not crossed an external effect"
    );
    let _ = parked.instance;
}

#[test]
fn a_host_withdrawal_without_invocation_cancel_remains_unknown() {
    let mut parked = start_fixture("invocation.host.withdraw-unknown");
    let (first, _) = published_request(&mut parked);
    let cancelled = parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::CapabilityCancel {
                request_id: "withdraw.unknown".to_owned(),
                owner_claim: parked.owner_claim.clone(),
                capability_request_id: first,
                message: Some("the host withdrew the request".to_owned()),
            },
        )
        .expect("a well-formed request");
    assert!(
        matches!(
            cancelled,
            RuntimeResult::CapabilitySettled {
                outcome: HostCapabilityOutcomeKind::Cancelled,
                ..
            }
        ),
        "{cancelled:?}"
    );
    assert_eq!(
        invocation_status(&mut parked.service, &parked.invocation),
        apxm_runtime_protocol::ProgramInvocationStatus::OutcomeUnknown,
        "an unmarked host withdrawal cannot claim invocation cancellation"
    );
    let stream = observations(&mut parked.service, &parked.invocation);
    assert!(
        of_kind(&stream, ObservationKind::InvocationCancelled).is_empty(),
        "host withdrawal alone does not emit invocation cancellation"
    );
    assert_eq!(
        of_kind(&stream, ObservationKind::OutcomeUnknown).len(),
        1,
        "the cancelled host settlement remains effect-uncertain at the invocation boundary"
    );
}

#[test]
fn explicit_invocation_cancellation_survives_restart() {
    let directory = tempfile::tempdir().expect("runtime state directory");
    let path = directory.path().to_path_buf();
    let mut parked = start_fixture_with_service(
        "invocation.host.cancel-restart",
        RuntimeService::in_memory()
            .with_runtime_state_dir(path.clone())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned()),
    );
    let (first, _) = published_request(&mut parked);
    let cancelled = parked
        .service
        .handle(
            &handshake(),
            RuntimeRequest::ProgramInvocationCancel {
                request_id: "cancel.restart".to_owned(),
                owner_claim: parked.owner_claim.clone(),
                program_invocation_id: parked.invocation.clone(),
            },
        )
        .expect("a well-formed request");
    assert!(matches!(cancelled, RuntimeResult::Cancelled { .. }));
    let Parked {
        service,
        instance: _,
        owner_claim: _,
        invocation,
    } = parked;
    drop(service);

    let mut reopened = RuntimeService::in_memory()
        .with_runtime_state_dir(path)
        .with_embedded_read_access()
        .with_output_access_scope_ref("scope.host-capability".to_owned());
    assert!(reopened.startup_error().is_none());
    assert_eq!(
        invocation_status(&mut reopened, &invocation),
        apxm_runtime_protocol::ProgramInvocationStatus::Cancelled
    );
    let stream = observations(&mut reopened, &invocation);
    assert!(
        of_kind(&stream, ObservationKind::InvocationCancelled)
            .iter()
            .any(|observation| observation.commitment == Commitment::Committed)
    );
    assert_eq!(
        of_kind(&stream, ObservationKind::CapabilitySettled)
            .iter()
            .filter(|observation| {
                observation
                    .host_capability
                    .as_ref()
                    .map(|host| host.capability_request_id.as_str())
                    == Some(first.as_str())
            })
            .count(),
        1,
        "the withdrawn host request remains durably settled exactly once"
    );
}

#[test]
fn two_host_requests_settle_in_schedule_order() {
    let mut parked = start_fixture("invocation.host.two");
    let (first, first_ref) = published_request(&mut parked);
    assert_eq!(first_ref, "host:notes.search");
    fulfill(
        &mut parked,
        "settle.1",
        &first,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"matches\":1}"),
    );
    let (second, second_ref) = published_request(&mut parked);
    assert_eq!(second_ref, "host:notes.append");
    assert_ne!(second, first);
    // Retrying an identical first settlement returns its authoritative result
    // without resuming the invocation a second time.
    let replayed = fulfill(
        &mut parked,
        "settle.1.again",
        &first,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"matches\":1}"),
    );
    assert!(matches!(
        replayed,
        RuntimeResult::CapabilitySettled {
            outcome: HostCapabilityOutcomeKind::Ok,
            ..
        }
    ));
    let settled = fulfill(
        &mut parked,
        "settle.2",
        &second,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"appended\":true}"),
    );
    assert!(
        matches!(settled, RuntimeResult::CapabilitySettled { .. }),
        "{settled:?}"
    );
    let invocation = parked.invocation.clone();
    let stream = observations(&mut parked.service, &invocation);
    assert_eq!(
        of_kind(&stream, ObservationKind::CapabilityRequested).len(),
        2
    );
    assert_eq!(
        of_kind(&stream, ObservationKind::CapabilitySettled).len(),
        2
    );
    assert!(
        !of_kind(&stream, ObservationKind::TerminalCommitted).is_empty(),
        "with both requests settled the invocation reaches a terminal commit"
    );
}

#[test]
fn a_lost_ack_replays_the_authoritative_settlement_after_restart() {
    let directory = tempfile::tempdir().expect("runtime state directory");
    let path = directory.path().to_path_buf();
    let mut parked = start_fixture_with_service(
        "invocation.host.restart-replay",
        RuntimeService::in_memory()
            .with_runtime_state_dir(path.clone())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned()),
    );
    let (first, _) = published_request(&mut parked);
    assert!(matches!(
        fulfill(
            &mut parked,
            "settle.before-restart",
            &first,
            HostCapabilityOutcomeKind::Ok,
            Some("{\"matches\":1}")
        ),
        RuntimeResult::CapabilitySettled { .. }
    ));
    let invocation = parked.invocation.clone();
    let before_restart = observations(&mut parked.service, &invocation);
    let Parked {
        service,
        instance,
        owner_claim,
        invocation,
    } = parked;
    drop(service);

    let service = RuntimeService::in_memory()
        .with_runtime_state_dir(path)
        .with_embedded_read_access()
        .with_output_access_scope_ref("scope.host-capability".to_owned());
    assert!(
        service.startup_error().is_none(),
        "{:?}",
        service.startup_error()
    );
    let mut reopened = Parked {
        service,
        instance,
        owner_claim,
        invocation,
    };
    let replayed = fulfill(
        &mut reopened,
        "settle.after-restart",
        &first,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"matches\":1}"),
    );
    assert!(matches!(
        replayed,
        RuntimeResult::CapabilitySettled {
            ref request_id,
            outcome: HostCapabilityOutcomeKind::Ok,
            ..
        } if request_id == "settle.after-restart"
    ));
    let reopened_invocation = reopened.invocation.clone();
    assert_eq!(
        observations(&mut reopened.service, &reopened_invocation),
        before_restart,
        "replaying a lost acknowledgement must not resume the node twice"
    );

    let conflicting = fulfill(
        &mut reopened,
        "settle.conflict",
        &first,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"matches\":2}"),
    );
    assert!(
        matches!(conflicting, RuntimeResult::Failed { ref code, .. } if code == "invalid_request"),
        "{conflicting:?}"
    );
    assert_eq!(
        observations(&mut reopened.service, &reopened_invocation),
        before_restart,
        "a conflicting retry must not alter authoritative observations"
    );
}

#[test]
fn settlement_replay_records_fail_closed_at_the_shared_application_bound() {
    let mut policy = RuntimeStatePolicy::default();
    policy.applications.max_entries = 1;
    let mut parked = start_fixture_with_service(
        "invocation.host.settlement-bound",
        RuntimeService::in_memory()
            .with_state_policy(policy)
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned()),
    );
    let (first, _) = published_request(&mut parked);
    assert!(matches!(
        fulfill(
            &mut parked,
            "settle.bound.first",
            &first,
            HostCapabilityOutcomeKind::Ok,
            Some("{\"matches\":1}")
        ),
        RuntimeResult::CapabilitySettled { .. }
    ));
    let (second, _) = published_request(&mut parked);
    let refused = fulfill(
        &mut parked,
        "settle.bound.second",
        &second,
        HostCapabilityOutcomeKind::Ok,
        Some("{\"appended\":true}"),
    );
    assert!(
        matches!(
            refused,
            RuntimeResult::Failed { ref code, .. }
                if code == "capability_settlement_quota_exceeded"
        ),
        "{refused:?}"
    );
    let invocation = parked.invocation.clone();
    assert_eq!(
        of_kind(
            &observations(&mut parked.service, &invocation),
            ObservationKind::CapabilitySettled
        )
        .len(),
        1,
        "quota refusal must leave the next node parked"
    );
}

/// `ask_owner` rides the committed-yield path: the yield output is the typed
/// request the host reads, the next `ProgramInvocationStart` on the same
/// instance is the owner's answer envelope, and anything that is not a closed
/// envelope the request admits is refused before an invocation is minted.
#[test]
fn compiled_owner_request_yields_a_typed_request_and_resumes_only_with_a_valid_answer() {
    use apxm_runtime_protocol::ProgramInvocationStatus;
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    for (frontend, typed) in [
        (Frontend::Typescript, false),
        (Frontend::Python, false),
        (Frontend::Typescript, true),
        (Frontend::Python, true),
    ] {
        let source = match (frontend, typed) {
            (Frontend::Typescript, false) => r#"import { Workflow, Capability } from "@apxm/frontend";
type Input = {message: string};
const Notes = Capability<unknown, unknown>("host:notes.search");
export const Consent = Workflow<Input, unknown>({name: "Consent", async run(agent, input) {
  const reply = await agent.ask_owner({prompt: input.message, choices: [{id: "send", label: "Send it"}, {id: "hold", label: "Hold"}], expires_in_seconds: 3600});
  const receipt = await Notes({outcome: reply.outcome, first: input.message});
  return {outcome: reply.outcome, first: input.message};
}});
"#
            .to_owned(),
            (Frontend::Python, false) => r#"from typing import TypedDict
from apxm_program import Workflow, Capability
class Input(TypedDict):
    message: str
Notes = Capability[object, object]("host:notes.search")
@Workflow(input=Input, output=object)
async def Consent(agent, input):
    reply = await agent.ask_owner({"prompt": input["message"], "choices": [{"id": "send", "label": "Send it"}, {"id": "hold", "label": "Hold"}], "expires_in_seconds": 3600})
    receipt = await Notes({"outcome": reply["outcome"], "first": input["message"]})
    return {"outcome": reply["outcome"], "first": input["message"]}
"#
            .to_owned(),
            (Frontend::Typescript, true) => r#"import { Workflow, Capability } from "@apxm/frontend";
type Input = {message: string};
type Amount = {amount: number};
const Notes = Capability<unknown, unknown>("host:notes.search");
export const Consent = Workflow<Input, unknown>({name: "Consent", async run(agent, input) {
  const reply = await agent.ask_owner<Amount>({prompt: "How much?", expires_in_seconds: 60});
  const receipt = await Notes({outcome: reply.outcome, first: input.message});
  return {outcome: reply.outcome, first: input.message};
}});
"#
            .to_owned(),
            (Frontend::Python, true) => r#"from typing import TypedDict
from apxm_program import Workflow, Capability
class Input(TypedDict):
    message: str
class Amount(TypedDict):
    amount: float
Notes = Capability[object, object]("host:notes.search")
@Workflow(input=Input, output=object)
async def Consent(agent, input):
    reply = await agent.ask_owner({"prompt": "How much?", "expires_in_seconds": 60}, answer=Amount)
    receipt = await Notes({"outcome": reply["outcome"], "first": input["message"]})
    return {"outcome": reply["outcome"], "first": input["message"]}
"#
            .to_owned(),
        };
        let compiled = compile_source_bundle(
            &SourceBundleRequest::new(frontend, "Consent", source)
                .with_host_capabilities(["notes.search"]),
            &roots,
            &drivers,
        )
        .expect("owner request source compiles");
        let artifact =
            ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
                .unwrap()
                .encode()
                .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let service = RuntimeService::in_memory()
            .with_runtime_state_dir(directory.path().to_path_buf())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned());
        let mut parked = start_artifact_with_input(
            "invocation.consent.first",
            service,
            artifact.clone(),
            serde_json::json!({"message":"Send the quote?"}),
        );
        let first_invocation = parked.invocation.clone();
        assert_eq!(
            invocation_status(&mut parked.service, &first_invocation),
            ProgramInvocationStatus::CommittedYield
        );

        // The committed yield output is the typed request, not opaque bytes:
        // its kind, prompt, answer shape, expiry, and the compiler-stamped
        // digest of that answer shape.
        let request = committed_output(&mut parked.service, &first_invocation);
        let decoded = apxm_program::owner_request::OwnerRequest::decode(&request)
            .unwrap_or_else(|reason| panic!("{frontend:?}: {reason}: {request}"));
        assert_eq!(decoded.schema_version, "apxm.owner-request.v1");
        assert_eq!(decoded.expires_in_seconds, if typed { 60 } else { 3600 });
        assert_eq!(
            decoded.answer.canonical_digest().unwrap(),
            decoded.schema_digest,
            "lowering stamps the answer schema digest"
        );
        let valid_answer = match &decoded.answer {
            apxm_program::owner_request::OwnerAnswerSchema::Choice { choices } => {
                assert_eq!(decoded.prompt, "Send the quote?");
                assert_eq!(
                    choices
                        .iter()
                        .map(|choice| choice.id.as_str())
                        .collect::<Vec<_>>(),
                    ["send", "hold"]
                );
                serde_json::json!("send")
            }
            apxm_program::owner_request::OwnerAnswerSchema::Typed { schema } => {
                assert_eq!(decoded.prompt, "How much?");
                assert_eq!(schema.required.as_deref(), Some(&["amount".to_owned()][..]));
                serde_json::json!({"amount": 12})
            }
        };
        assert!(
            of_kind(
                &observations(&mut parked.service, &first_invocation),
                ObservationKind::CapabilityRequested
            )
            .is_empty(),
            "asking the owner dispatches nothing"
        );

        // Only a closed envelope the request admits is a next input. Each
        // refusal is typed and mints no invocation, so the owner can still
        // answer afterwards.
        for (name, rejected) in [
            ("free_text", serde_json::json!({"message": "yes"})),
            (
                "undeclared_choice",
                serde_json::json!({"outcome": "answered", "answer": "burn"}),
            ),
            (
                "wrong_typed_answer",
                serde_json::json!({"outcome": "answered", "answer": {"amount": "twelve"}}),
            ),
            ("missing_answer", serde_json::json!({"outcome": "answered"})),
            (
                "declined_with_answer",
                serde_json::json!({"outcome": "declined", "answer": valid_answer.clone()}),
            ),
            ("unknown_outcome", serde_json::json!({"outcome": "later"})),
        ] {
            let result = parked
                .service
                .handle(
                    &handshake(),
                    RuntimeRequest::ProgramInvocationStart {
                        request_id: format!("start.{name}"),
                        program_instance_id: parked.instance.clone(),
                        owner_claim: parked.owner_claim.clone(),
                        input: rejected,
                    },
                )
                .unwrap();
            assert!(
                matches!(&result, RuntimeResult::Failed { code, .. } if code == "owner_answer_rejected"),
                "{frontend:?} {name}: {result:?}"
            );
        }
        assert_eq!(
            invocation_status(&mut parked.service, &first_invocation),
            ProgramInvocationStatus::CommittedYield,
            "a refused answer leaves the instance waiting"
        );

        // A restart preserves the pending request and the same rule.
        drop(parked.service);
        parked.service = RuntimeService::in_memory()
            .with_runtime_state_dir(directory.path().to_path_buf())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned());
        assert!(parked.service.startup_error().is_none());
        assert_eq!(
            committed_output(&mut parked.service, &first_invocation),
            request
        );
        parked
            .service
            .bind_admission(
                &parked.instance,
                materials(&artifact, "invocation.consent.second"),
            )
            .unwrap();

        // The owner's valid envelope resumes the same instance; the program
        // reads the outcome and its own earlier input, and the Capability it
        // then calls is an ordinary host request the host still decides.
        let answered = RuntimeRequest::ProgramInvocationStart {
            request_id: "start.answered".into(),
            program_instance_id: parked.instance.clone(),
            owner_claim: parked.owner_claim.clone(),
            input: serde_json::json!({"outcome": "answered", "answer": valid_answer}),
        };
        let result = parked.service.handle(&handshake(), answered).unwrap();
        let RuntimeResult::ProgramInvocationStarted {
            program_invocation_id,
            ..
        } = result
        else {
            panic!("{frontend:?}: the owner's answer did not resume: {result:?}");
        };
        assert_ne!(program_invocation_id, first_invocation);
        parked.invocation = program_invocation_id.clone();
        let stream = observations(&mut parked.service, &program_invocation_id);
        let requests = of_kind(&stream, ObservationKind::CapabilityRequested);
        assert_eq!(
            requests.len(),
            1,
            "the post-answer Capability still asks the host"
        );
        let host = requests[0].host_capability.as_ref().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(host.input.as_ref().unwrap()).unwrap(),
            serde_json::json!({"outcome": "answered", "first": "Send the quote?"})
        );
        let capability_request_id = host.capability_request_id.clone();
        assert!(matches!(
            fulfill(
                &mut parked,
                "settle.consent",
                &capability_request_id,
                HostCapabilityOutcomeKind::Ok,
                Some("{}")
            ),
            RuntimeResult::CapabilitySettled { .. }
        ));
        assert_eq!(
            invocation_status(&mut parked.service, &program_invocation_id),
            ProgramInvocationStatus::CommittedReturn
        );
        assert_eq!(
            committed_output(&mut parked.service, &program_invocation_id),
            serde_json::json!({"outcome": "answered", "first": "Send the quote?"})
        );
    }
}

/// A declined or expired envelope resumes the program with that explicit
/// outcome; the runtime never fabricates an answer and needs no clock.
#[test]
fn compiled_owner_request_resumes_with_declined_and_expired_outcomes() {
    use apxm_runtime_protocol::ProgramInvocationStatus;
    use apxm_source_port::{
        Frontend, FrontendDrivers, FrontendRoots, SourceBundleRequest, compile_source_bundle,
    };
    let root = fixture_dir().ancestors().nth(3).unwrap().to_path_buf();
    let roots = FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    );
    let drivers = FrontendDrivers::new(
        root.join(".dekk/env/bin/python"),
        root.join(".dekk/env/bin/node"),
    );
    let source = r#"import { Workflow } from "@apxm/frontend";
type Input = {message: string};
export const Consent = Workflow<Input, unknown>({name: "Consent", async run(agent, input) {
  const reply = await agent.ask_owner({prompt: "Proceed?", choices: [{id: "go", label: "Go"}], expires_in_seconds: 5});
  return {outcome: reply.outcome};
}});
"#;
    let compiled = compile_source_bundle(
        &SourceBundleRequest::new(Frontend::Typescript, "Consent", source.to_owned()),
        &roots,
        &drivers,
    )
    .expect("owner request source compiles");
    let artifact = ExecutableArtifact::from_graph_and_air(&compiled.frontend_graph, &compiled.air)
        .unwrap()
        .encode()
        .unwrap();
    for outcome in ["declined", "expired"] {
        let directory = tempfile::tempdir().unwrap();
        let service = RuntimeService::in_memory()
            .with_runtime_state_dir(directory.path().to_path_buf())
            .with_embedded_read_access()
            .with_output_access_scope_ref("scope.host-capability".to_owned());
        let mut parked = start_artifact_with_input(
            &format!("invocation.consent.{outcome}.first"),
            service,
            artifact.clone(),
            serde_json::json!({"message":"hello"}),
        );
        parked
            .service
            .bind_admission(
                &parked.instance,
                materials(&artifact, &format!("invocation.consent.{outcome}.second")),
            )
            .unwrap();
        let result = parked
            .service
            .handle(
                &handshake(),
                RuntimeRequest::ProgramInvocationStart {
                    request_id: format!("start.{outcome}"),
                    program_instance_id: parked.instance.clone(),
                    owner_claim: parked.owner_claim.clone(),
                    input: serde_json::json!({"outcome": outcome}),
                },
            )
            .unwrap();
        let RuntimeResult::ProgramInvocationStarted {
            program_invocation_id,
            ..
        } = result
        else {
            panic!("{outcome}: did not resume: {result:?}");
        };
        assert_eq!(
            invocation_status(&mut parked.service, &program_invocation_id),
            ProgramInvocationStatus::CommittedReturn
        );
        assert_eq!(
            committed_output(&mut parked.service, &program_invocation_id),
            serde_json::json!({"outcome": outcome})
        );
    }
}
