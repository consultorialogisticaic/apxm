//! The frontend selector and the interpreter boundary each selector owns.
//!
//! Capturing typed intent from Python source requires the Python authoring
//! frontend to run, and the same holds for TypeScript. That is the mechanism the
//! frontends require; it is not something a caller of this port configures,
//! observes, or works around. This module holds the whole of it: which
//! interpreter each selector runs, how the interpreter is confined, and how its
//! exit is translated into one closed diagnostic.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::confinement::{CaptureScratch, Confinement};
use crate::diagnostic::{Location, Phase, Severity, SourceDiagnostic, SourceDiagnosticCode};

/// The maximum time an authoring frontend may hold the source-port boundary.
/// It is the outermost bound: the kernel's own CPU ceiling ends a program that
/// only spins well before this, and this ends a child the kernel cannot reach.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);
/// A frontend must not be able to make capture retain unbounded output. The
/// readers continue draining after this budget is full so noisy output cannot
/// deadlock the child on a full pipe.
const CAPTURE_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const CAPTURE_READ_BUFFER_BYTES: usize = 16 * 1024;
/// The old-space ceiling the TypeScript bridge runs under. Node has no
/// interpreter resource limits of its own, so the ceiling is stated on its
/// command line and holds on every host, kernel boundary or not.
const NODE_HEAP_LIMIT_MB: usize = 512;
const CAPTURE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The closed authoring-frontend selector. It matches the source-language
/// closure of the semantic surface exactly: there is no third frontend and no
/// alternate path within a selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Frontend {
    Python,
    Typescript,
}

impl Frontend {
    /// The canonical wire string for this selector.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Typescript => "typescript",
        }
    }

    /// The source language the captured graph declares for this selector.
    #[must_use]
    pub const fn source_language(self) -> apxm_program::SourceLanguage {
        match self {
            Self::Python => apxm_program::SourceLanguage::Python,
            Self::Typescript => apxm_program::SourceLanguage::Typescript,
        }
    }

    /// The portable file name the harness gives the submitted source. Every
    /// span the frontend records, and every location a diagnostic carries,
    /// names this file.
    #[must_use]
    pub const fn submitted_source_file(self) -> &'static str {
        match self {
            Self::Python => "submitted_source.py",
            Self::Typescript => "submitted_source.ts",
        }
    }

    /// The capture harness this selector runs. The harness is embedded in the
    /// binary, so the port has no installed script to locate and no path a
    /// caller can redirect.
    const fn harness(self) -> &'static str {
        match self {
            Self::Python => include_str!("../harness/capture_python.py"),
            Self::Typescript => include_str!("../harness/capture_typescript.mjs"),
        }
    }

    /// The subdirectory of the frontend root the interpreter is allowed to read,
    /// where the interpreter enforces a read wall of its own.
    fn confinement_arguments(self, frontend_root: &Path) -> Vec<String> {
        match self {
            // The isolated interpreter ignores every `PYTHON*` variable and the
            // user site directory, and reads its program text from the argument
            // rather than from a file. Confinement inside the interpreter is the
            // harness's audit hook and resource limits.
            Self::Python => vec!["-I".to_string(), "-B".to_string(), "-c".to_string()],
            // Node's permission model is an OS-level read wall: the process can
            // read the declared frontend package and nothing else on the
            // filesystem, and can write nowhere at all. Synchronous loader
            // hooks keep submitted code in this same confined process; worker
            // threads are deliberately not granted. The heap ceiling is Node's
            // own, so a submitted program that allocates without bound is
            // refused by V8 on every host, not only where the kernel bounds
            // writable data.
            Self::Typescript => vec![
                // Use the stable flag; newer Node releases removed the
                // experimental alias while retaining the permission model.
                "--no-warnings".to_string(),
                "--permission".to_string(),
                format!("--allow-fs-read={}", frontend_root.display()),
                format!("--max-old-space-size={NODE_HEAP_LIMIT_MB}"),
                "--input-type=module".to_string(),
                "--eval".to_string(),
            ],
        }
    }
}

/// One capture request handed to an interpreter on its standard input.
#[derive(Debug, Serialize)]
struct HarnessRequest<'a> {
    frontend_root: &'a Path,
    entrypoint: &'a str,
    source: &'a str,
    /// The host capability ids the package declares. The harness hands them to
    /// the frontend before evaluating the source, so the minted Capability set
    /// inside the interpreter is the builtin catalogue united with these.
    host_capabilities: &'a [String],
}

/// The document a capture harness writes on success: the graph, and any
/// non-error diagnostics the frontend raised while producing it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessResponse {
    frontend_graph: serde_json::Value,
    #[serde(default)]
    diagnostics: Vec<HarnessItem>,
}

/// The one JSON record a capture harness writes on stderr when it rejects.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessRejection {
    /// The closed reason token.
    code: String,
    /// Every diagnostic the harness raised, in emission order. Non-empty.
    items: Vec<HarnessItem>,
}

/// One diagnostic a harness reports. Columns in `location` already follow the
/// source-map convention (1-based lines, 0-based columns).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessItem {
    severity: Severity,
    code: String,
    message: String,
    #[serde(default)]
    phase: Option<Phase>,
    #[serde(default)]
    location: Option<Location>,
}

/// The longest frontend-specific code slug the port accepts from a harness.
const MAX_DETAIL_CODE_BYTES: usize = 64;

fn is_code_slug(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_DETAIL_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Remove host paths the port composed the capture from, so a diagnostic
/// never names the frontend package root or the interpreter driver.
fn scrub(message: &str, frontend_root: &Path, driver: &Path) -> String {
    let mut scrubbed = message.to_owned();
    for (path, label) in [(driver, "<driver>"), (frontend_root, "<frontend>")] {
        let rendered = path.display().to_string();
        if rendered.len() > 1 {
            scrubbed = scrubbed.replace(&rendered, label);
        }
    }
    scrubbed
}

impl HarnessItem {
    /// Project one reported item under the harness's closed reason.
    fn into_diagnostic(
        self,
        reason: SourceDiagnosticCode,
        frontend: Frontend,
        frontend_root: &Path,
        driver: &Path,
    ) -> Result<SourceDiagnostic, String> {
        if !is_code_slug(&self.code) {
            return Err("a harness diagnostic code is not a closed slug".to_owned());
        }
        if let Some(location) = &self.location
            && (location.source_file != frontend.submitted_source_file()
                || !location.span.is_forward()
                || location.span.start_line == 0)
        {
            return Err(
                "a harness diagnostic location is not a forward span in the submitted source"
                    .to_owned(),
            );
        }
        let mut diagnostic =
            SourceDiagnostic::new(reason, scrub(self.message.trim(), frontend_root, driver))
                .with_severity(self.severity);
        if self.code != reason.slug() {
            diagnostic = diagnostic.with_detail_code(self.code);
        }
        if let Some(phase) = self.phase {
            diagnostic = diagnostic.with_phase(phase);
        }
        if let Some(location) = self.location {
            diagnostic = diagnostic.with_location(location);
        }
        Ok(diagnostic)
    }
}

/// A capture's graph together with the non-error diagnostics it raised.
pub(crate) struct Captured {
    pub(crate) frontend_graph: serde_json::Value,
    pub(crate) diagnostics: Vec<SourceDiagnostic>,
}

/// Run one capture and return the FrontendGraph JSON value the frontend
/// recorded with any non-error diagnostics, or every diagnostic that rejects
/// it.
///
/// Whether a frontend package is usable is decided in exactly one place: the
/// harness, which resolves the package the way the language actually resolves
/// it. Re-deciding it here from the shape of the path would be a second answer
/// to the same question, and the two would drift.
pub(crate) fn capture(
    frontend: Frontend,
    frontend_root: &Path,
    driver: &Path,
    entrypoint: &str,
    source: &str,
    host_capabilities: &[String],
) -> Result<Captured, Vec<SourceDiagnostic>> {
    capture_once(
        frontend,
        frontend_root,
        driver,
        entrypoint,
        source,
        host_capabilities,
    )
    .map_err(|diagnostic| vec![diagnostic])
    .and_then(|output| {
        if output.status.success() {
            decode_response(frontend, frontend_root, driver, &output.stdout)
                .map_err(|diagnostic| vec![diagnostic])
        } else {
            Err(harness_rejection(
                frontend,
                frontend_root,
                driver,
                &output.stderr,
            ))
        }
    })
}

fn capture_once(
    frontend: Frontend,
    frontend_root: &Path,
    driver: &Path,
    entrypoint: &str,
    source: &str,
    host_capabilities: &[String],
) -> Result<std::process::Output, SourceDiagnostic> {
    let request = serde_json::to_vec(&HarnessRequest {
        frontend_root,
        entrypoint,
        source,
        host_capabilities,
    })
    .map_err(|error| {
        SourceDiagnostic::new(
            SourceDiagnosticCode::RequestInvalid,
            format!("the capture request does not serialize: {error}"),
        )
    })?;

    let scratch = CaptureScratch::create()?;
    let confinement = Confinement::capture(frontend_root, driver, scratch.path());
    spawn(
        frontend,
        frontend_root,
        driver,
        &request,
        &scratch,
        &confinement,
    )
}

/// Decode the whole capture output as exactly one `HarnessResponse`.
///
/// The entire byte stream is decoded as one document carrying the graph and,
/// optionally, the non-error diagnostics raised producing it. Trailing bytes,
/// leading bytes, and any other field each reject: a capture that emitted
/// anything besides the typed graph — AIR among it — is not a capture this
/// port accepts a graph from. An error-severity diagnostic beside a graph is a
/// contradiction and rejects the same way.
fn decode_response(
    frontend: Frontend,
    frontend_root: &Path,
    driver: &Path,
    stdout: &[u8],
) -> Result<Captured, SourceDiagnostic> {
    let invalid = |detail: String| {
        SourceDiagnostic::new(
            SourceDiagnosticCode::FrontendOutputInvalid,
            format!(
                "the {} authoring frontend did not emit exactly one FrontendGraph document: {detail}",
                frontend.wire()
            ),
        )
    };
    let response: HarnessResponse =
        serde_json::from_slice(stdout).map_err(|error| invalid(error.to_string()))?;
    let mut diagnostics = Vec::with_capacity(response.diagnostics.len());
    for item in response.diagnostics {
        if item.severity == Severity::Error {
            return Err(invalid(
                "an error diagnostic accompanied a captured graph".to_owned(),
            ));
        }
        diagnostics.push(
            item.into_diagnostic(
                SourceDiagnosticCode::SourceRejected,
                frontend,
                frontend_root,
                driver,
            )
            .map_err(invalid)?,
        );
    }
    Ok(Captured {
        frontend_graph: response.frontend_graph,
        diagnostics,
    })
}

/// Run the exact declared interpreter driver. A missing or unstartable driver
/// is unavailability, never a fallback search, panic, or silent success.
fn spawn(
    frontend: Frontend,
    frontend_root: &Path,
    driver: &Path,
    request: &[u8],
    scratch: &CaptureScratch,
    confinement: &Confinement,
) -> Result<std::process::Output, SourceDiagnostic> {
    spawn_with_timeout(
        frontend,
        frontend_root,
        driver,
        request,
        CAPTURE_TIMEOUT,
        Some(scratch.path()),
        confinement,
    )
}

/// Run one declared interpreter with a bounded lifetime.
fn spawn_with_timeout(
    frontend: Frontend,
    frontend_root: &Path,
    driver: &Path,
    request: &[u8],
    timeout: Duration,
    scratch: Option<&Path>,
    confinement: &Confinement,
) -> Result<std::process::Output, SourceDiagnostic> {
    let mut command = Command::new(driver);
    command
        .args(frontend.confinement_arguments(frontend_root))
        .arg(frontend.harness())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(scratch) = scratch {
        // The one writable path the child has, named where an interpreter
        // looks for one. Everything else it may write is denied by the kernel.
        command.env("TMPDIR", scratch);
    }
    confinement.arm(&mut command)?;

    let mut child = command.spawn().map_err(|error| {
        SourceDiagnostic::new(
            SourceDiagnosticCode::FrontendUnavailable,
            format!(
                "the declared {} authoring frontend driver could not start: {}",
                frontend.wire(),
                error
            ),
        )
    })?;

    let started = Instant::now();
    let deadline = started + timeout;
    let output_budget = Arc::new(AtomicUsize::new(0));
    let writer = spawn_writer(child.stdin.take(), request.to_vec());
    let stdout = spawn_reader(child.stdout.take(), Arc::clone(&output_budget));
    let stderr = spawn_reader(child.stderr.take(), Arc::clone(&output_budget));

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = collect_output(status, stdout, stderr, writer, deadline).map_err(
                    |error| {
                        SourceDiagnostic::new(
                            SourceDiagnosticCode::FrontendUnavailable,
                            format!(
                                "the declared {} authoring frontend driver did not complete capture: {error}",
                                frontend.wire(),
                            ),
                        )
                    },
                )?;
                return Ok(output);
            }
            Ok(None) if Instant::now() >= deadline => {
                terminate(&mut child);
                return Err(SourceDiagnostic::new(
                    SourceDiagnosticCode::FrontendUnavailable,
                    format!(
                        "the declared {} authoring frontend driver exceeded the capture timeout of {} ms",
                        frontend.wire(),
                        timeout.as_millis()
                    ),
                ));
            }
            Ok(None) => {
                thread::sleep(
                    CAPTURE_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => {
                terminate(&mut child);
                return Err(SourceDiagnostic::new(
                    SourceDiagnosticCode::FrontendUnavailable,
                    format!(
                        "the declared {} authoring frontend driver could not be observed: {}",
                        frontend.wire(),
                        error.kind()
                    ),
                ));
            }
        }
    }
}

type CaptureReceiver<T> = mpsc::Receiver<std::io::Result<T>>;

fn spawn_writer(stdin: Option<ChildStdin>, request: Vec<u8>) -> CaptureReceiver<()> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = stdin.map_or(Ok(()), |mut stdin| stdin.write_all(&request));
        let _ = sender.send(result);
    });
    receiver
}

fn spawn_reader<R>(reader: Option<R>, output_budget: Arc<AtomicUsize>) -> CaptureReceiver<Vec<u8>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = reader.map_or_else(
            || Ok(Vec::new()),
            |reader| read_stream(reader, output_budget),
        );
        let _ = sender.send(result);
    });
    receiver
}

fn read_stream<R: Read>(
    mut reader: R,
    output_budget: Arc<AtomicUsize>,
) -> std::io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; CAPTURE_READ_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(captured);
        }

        let retained = reserve_output(&output_budget, CAPTURE_MAX_OUTPUT_BYTES, read);
        captured.extend_from_slice(&buffer[..retained]);
    }
}

fn reserve_output(budget: &AtomicUsize, limit: usize, requested: usize) -> usize {
    loop {
        let used = budget.load(Ordering::Acquire);
        let available = limit.saturating_sub(used);
        let retained = available.min(requested);
        if retained == 0 {
            return 0;
        }
        if budget
            .compare_exchange_weak(used, used + retained, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return retained;
        }
    }
}

fn collect_output(
    status: std::process::ExitStatus,
    stdout: CaptureReceiver<Vec<u8>>,
    stderr: CaptureReceiver<Vec<u8>>,
    writer: CaptureReceiver<()>,
    deadline: Instant,
) -> std::io::Result<std::process::Output> {
    // Use one absolute deadline for all pipe workers. A successful child must
    // not extend the lifecycle merely because a worker failed to close.
    let stdout = receive_until(stdout, deadline)?;
    let stderr = receive_until(stderr, deadline)?;
    receive_until(writer, deadline)?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn receive_until<T>(receiver: CaptureReceiver<T>, deadline: Instant) -> std::io::Result<T> {
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "capture pipe worker timed out",
            ),
            mpsc::RecvTimeoutError::Disconnected => std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "capture pipe worker disconnected",
            ),
        })?
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Translate a harness exit into its closed diagnostics.
///
/// A harness that rejects writes exactly one JSON record on stderr: the closed
/// reason token and every diagnostic it raised. A harness that never began a
/// record — killed by a resource limit, crashed, or a driver that is not the
/// declared interpreter — is unavailability of the capture boundary itself. A
/// record that does not decode is output this port does not trust as a
/// reason, and it is reported as invalid frontend output. Neither is ever an
/// accepted or partially captured program.
fn harness_rejection(
    frontend: Frontend,
    frontend_root: &Path,
    driver: &Path,
    stderr: &[u8],
) -> Vec<SourceDiagnostic> {
    let rendered = String::from_utf8_lossy(stderr);
    let rendered = rendered.trim();
    if !rendered.starts_with('{') {
        return vec![SourceDiagnostic::new(
            SourceDiagnosticCode::FrontendUnavailable,
            format!(
                "the {} authoring frontend capture ended without a reported reason",
                frontend.wire()
            ),
        )];
    }
    decode_rejection(frontend, frontend_root, driver, rendered).unwrap_or_else(|detail| {
        vec![SourceDiagnostic::new(
            SourceDiagnosticCode::FrontendOutputInvalid,
            format!(
                "the {} authoring frontend capture ended without a well-formed rejection record: {detail}",
                frontend.wire()
            ),
        )]
    })
}

fn decode_rejection(
    frontend: Frontend,
    frontend_root: &Path,
    driver: &Path,
    rendered: &str,
) -> Result<Vec<SourceDiagnostic>, String> {
    let record: HarnessRejection =
        serde_json::from_str(rendered).map_err(|error| error.to_string())?;
    let reason = SourceDiagnosticCode::from_harness_token(&record.code)
        .ok_or_else(|| "the rejection record names no closed reason".to_owned())?;
    if record.items.is_empty() {
        return Err("the rejection record carries no diagnostic".to_owned());
    }
    if !record
        .items
        .iter()
        .any(|item| item.severity == Severity::Error)
    {
        return Err("the rejection record carries no error".to_owned());
    }
    record
        .items
        .into_iter()
        .map(|item| item.into_diagnostic(reason, frontend, frontend_root, driver))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use std::path::Path;

    use super::{Frontend, decode_response, harness_rejection, spawn_with_timeout};
    use crate::confinement::Confinement;
    use crate::diagnostic::{Phase, Severity, SourceDiagnosticCode};

    const ROOT: &str = "/opt/frontends/typescript";
    const DRIVER: &str = "/opt/bin/node";

    fn decode(
        frontend: Frontend,
        stdout: &[u8],
    ) -> Result<serde_json::Value, crate::diagnostic::SourceDiagnostic> {
        decode_response(frontend, Path::new(ROOT), Path::new(DRIVER), stdout)
            .map(|captured| captured.frontend_graph)
    }

    fn rejection(frontend: Frontend, stderr: &[u8]) -> Vec<crate::diagnostic::SourceDiagnostic> {
        harness_rejection(frontend, Path::new(ROOT), Path::new(DRIVER), stderr)
    }

    /// The one accepted shape: exactly one document carrying exactly the graph.
    #[test]
    fn exactly_one_graph_field_decodes() {
        let graph = decode(Frontend::Python, br#"{"frontend_graph": {"k": 1}}"#)
            .expect("a capture output holding exactly the graph decodes");
        assert_eq!(graph, serde_json::json!({"k": 1}));
    }

    /// A capture that emitted AIR alongside the graph is rejected rather than
    /// having the AIR ignored. Only Rust lowering produces AIR, so a frontend
    /// that produced any is a frontend this port takes no graph from.
    #[test]
    fn a_capture_that_also_emitted_air_is_rejected() {
        let diagnostic = decode(
            Frontend::Python,
            br#"{"frontend_graph": {"k": 1}, "air": "module { }"}"#,
        )
        .expect_err("a capture output carrying AIR beside the graph is rejected");
        assert_eq!(diagnostic.code, SourceDiagnosticCode::FrontendOutputInvalid);
    }

    /// Bytes after the document reject: the whole output is the document.
    #[test]
    fn output_with_trailing_bytes_is_rejected() {
        let diagnostic = decode(
            Frontend::Typescript,
            br#"{"frontend_graph": {"k": 1}} trailing"#,
        )
        .expect_err("a capture output with trailing bytes is rejected");
        assert_eq!(diagnostic.code, SourceDiagnosticCode::FrontendOutputInvalid);
    }

    #[test]
    fn a_capture_without_a_closed_reason_is_unavailable() {
        let diagnostics = rejection(Frontend::Python, b"");

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            SourceDiagnosticCode::FrontendUnavailable
        );
        assert!(diagnostics[0].message.contains("without a reported reason"));

        // An interpreter crash, or the legacy two-line token, never began a
        // record either; neither is quoted back to the caller.
        for stderr in [
            &b"FATAL ERROR: Reached heap limit Allocation failed"[..],
            b"source_rejected\nSyntaxError: invalid syntax",
        ] {
            let diagnostics = rejection(Frontend::Typescript, stderr);
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(
                diagnostics[0].code,
                SourceDiagnosticCode::FrontendUnavailable
            );
            assert!(!diagnostics[0].message.contains("FATAL"));
        }
    }

    /// Every item of a rejection record survives, in order, with its phase,
    /// its frontend code and its location; host paths are scrubbed.
    #[test]
    fn a_rejection_record_keeps_every_item_and_location() {
        let stderr = format!(
            r#"{{"code":"source_rejected","items":[
                {{"severity":"error","code":"source_rejected","phase":"type_check","message":"Type 'number' is not assignable","location":{{"source_file":"submitted_source.ts","span":{{"start_line":3,"start_column":4,"end_line":3,"end_column":9}}}}}},
                {{"severity":"warning","code":"source_warning","phase":"type_check","message":"deprecated"}},
                {{"severity":"error","code":"AgentDynamicArgument","phase":"capture","message":"loaded from {ROOT}/dist/index.js"}}
            ]}}"#
        );
        let diagnostics = rejection(Frontend::Typescript, stderr.as_bytes());

        assert_eq!(diagnostics.len(), 3);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == SourceDiagnosticCode::SourceRejected)
        );
        assert_eq!(diagnostics[0].phase, Phase::TypeCheck);
        assert_eq!(diagnostics[0].wire_code(), "source_rejected");
        let location = diagnostics[0].location.as_ref().expect("located item");
        assert_eq!(location.source_file, "submitted_source.ts");
        assert_eq!(
            (location.span.start_line, location.span.start_column),
            (3, 4)
        );
        assert_eq!(diagnostics[1].severity, Severity::Warning);
        assert_eq!(diagnostics[2].wire_code(), "AgentDynamicArgument");
        assert_eq!(diagnostics[2].phase, Phase::Capture);
        assert!(!diagnostics[2].message.contains(ROOT));
        assert!(diagnostics[2].message.contains("<frontend>"));
    }

    /// Output that is not one well-formed rejection record is not trusted as a
    /// reason: it is invalid frontend output, whatever it claims.
    #[test]
    fn malformed_harness_output_is_invalid_frontend_output() {
        for stderr in [
            &br#"{"code":"source_rejected","items":[{"severity":"error""#[..],
            br#"{"code":"source_rejected","items":[]}"#,
            br#"{"code":"not_a_reason","items":[{"severity":"error","code":"x","message":"m"}]}"#,
            br#"{"code":"source_rejected","items":[{"severity":"warning","code":"x","message":"m"}]}"#,
            br#"{"code":"source_rejected","items":[{"severity":"error","code":"has space","message":"m"}]}"#,
            br#"{"code":"source_rejected","items":[{"severity":"error","code":"x","message":"m","extra":1}]}"#,
            br#"{"code":"source_rejected","items":[{"severity":"error","code":"x","message":"m","location":{"source_file":"/etc/passwd","span":{"start_line":1,"start_column":0,"end_line":1,"end_column":1}}}]}"#,
            br#"{"code":"source_rejected","items":[{"severity":"error","code":"x","message":"m"}]} trailing"#,
        ] {
            let diagnostics = rejection(Frontend::Typescript, stderr);
            assert_eq!(
                diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code)
                    .collect::<Vec<_>>(),
                vec![SourceDiagnosticCode::FrontendOutputInvalid],
                "{}",
                String::from_utf8_lossy(stderr)
            );
        }
    }

    /// A graph may arrive with warnings; an error beside a graph is invalid.
    #[test]
    fn a_captured_graph_carries_warnings_but_never_errors() {
        let captured = decode_response(
            Frontend::Python,
            Path::new(ROOT),
            Path::new(DRIVER),
            br#"{"frontend_graph":{"k":1},"diagnostics":[{"severity":"warning","code":"source_warning","phase":"type_check","message":"w","location":{"source_file":"submitted_source.py","span":{"start_line":2,"start_column":0,"end_line":2,"end_column":3}}}]}"#,
        )
        .ok()
        .expect("a graph with a warning decodes");
        assert_eq!(captured.diagnostics.len(), 1);
        assert_eq!(captured.diagnostics[0].severity, Severity::Warning);
        assert_eq!(captured.diagnostics[0].wire_code(), "source_warning");

        let error = decode(
            Frontend::Python,
            br#"{"frontend_graph":{"k":1},"diagnostics":[{"severity":"error","code":"x","message":"m"}]}"#,
        )
        .expect_err("an error beside a graph is invalid output");
        assert_eq!(error.code, SourceDiagnosticCode::FrontendOutputInvalid);
    }

    /// The port's own process mechanics: a child that never exits is ended at
    /// the deadline. The stand-in driver is a shell script rather than a
    /// declared interpreter, so this drives `spawn` without the kernel boundary
    /// a real capture runs inside; that boundary is asserted directly by the
    /// hostile-source reproduction in `confinement`.
    #[cfg(unix)]
    #[test]
    fn a_capture_that_does_not_exit_is_killed_at_the_boundary() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_test_path("sleeping-driver");
        fs::write(&path, "#!/bin/sh\nwhile :; do :; done\n").expect("write sleeping driver");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make sleeping driver executable");

        let input = vec![b'x'; 128 * 1024];
        let diagnostic = spawn_with_timeout(
            Frontend::Python,
            std::path::Path::new("/tmp"),
            &path,
            &input,
            Duration::from_millis(25),
            None,
            &Confinement::none(),
        )
        .expect_err("a capture that exceeds its deadline is rejected");

        let _ = fs::remove_file(&path);
        assert_eq!(diagnostic.code, SourceDiagnosticCode::FrontendUnavailable);
        assert!(diagnostic.message.contains("capture timeout"));
    }

    /// The port's own pipe mechanics, driven the same way and for the same
    /// reason as the deadline test above.
    #[cfg(unix)]
    #[test]
    fn a_capture_drains_large_stdout_and_stderr_while_writing_input() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_test_path("large-output-driver");
        fs::write(
            &path,
            "#!/bin/sh\ncat >/dev/null\ndd if=/dev/zero bs=131072 count=1 2>/dev/null\ndd if=/dev/zero bs=131072 count=1 1>&2 2>/dev/null\n",
        )
        .expect("write large-output driver");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make large-output driver executable");

        let input = vec![b'x'; 512 * 1024];
        let output = spawn_with_timeout(
            Frontend::Python,
            std::path::Path::new("/tmp"),
            &path,
            &input,
            Duration::from_secs(2),
            None,
            &Confinement::none(),
        )
        .expect("large bidirectional output must not deadlock capture");

        let _ = fs::remove_file(&path);
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 131_072);
        assert_eq!(output.stderr.len(), 131_072);
    }

    #[test]
    fn a_decode_failure_does_not_poison_the_next_capture() {
        let failed = decode(Frontend::Typescript, b"not-json")
            .expect_err("invalid capture output is rejected");
        assert_eq!(failed.code, SourceDiagnosticCode::FrontendOutputInvalid);

        let recovered = decode(
            Frontend::Typescript,
            br#"{"frontend_graph":{"schema_version":"apxm.frontend-graph"}}"#,
        )
        .expect("the next independent capture still decodes");
        assert_eq!(
            recovered,
            serde_json::json!({"schema_version": "apxm.frontend-graph"})
        );
    }

    #[cfg(unix)]
    fn unique_test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "apxm-source-port-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_nanos()
        ))
    }
}
