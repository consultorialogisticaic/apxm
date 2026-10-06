//! Compilation Client: snapshot, submit, render diagnostics, return artifact refs.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[cfg(unix)]
use std::ffi::{CStr, CString};

use apxm_compilation_protocol::{
    COMPILATION_PROTOCOL_VERSION, CompilationHandshake, CompilationRequest, CompilationResult,
    DiagnosticReport, Severity,
};
use apxm_compilation_service::{
    CompilationService, MAX_FRAME_BYTES, StdioFrame, decode_jsonl, encode_jsonl,
};
use apxm_source_port::{Frontend, PackageSnapshot, SnapshotContent};
use serde::Deserialize;

#[cfg(unix)]
use rustix::fd::OwnedFd;
#[cfg(unix)]
use rustix::fs::{Dir, Mode, OFlags, open, openat};

/// Maximum number of nested package directories below the package root.
pub const MAX_PACKAGE_DEPTH: usize = 32;
/// Maximum number of regular files in one package snapshot.
pub const MAX_PACKAGE_FILES: usize = 4096;
/// Maximum size of one regular package file.
pub const MAX_PACKAGE_FILE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum aggregate bytes retained in one package snapshot.
pub const MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;

/// Headless build client. Contains no frontend or compiler implementation.
pub struct CompilationClient {
    inner: CompilationInner,
}

enum CompilationInner {
    InProcess(CompilationService),
    Stdio(StdioCompilation),
}

struct StdioCompilation {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    artifact_dir: PathBuf,
    last_bytes: Option<(String, String)>,
}

impl Default for CompilationClient {
    fn default() -> Self {
        Self {
            inner: CompilationInner::InProcess(CompilationService::default()),
        }
    }
}

impl Drop for CompilationClient {
    fn drop(&mut self) {
        if let CompilationInner::Stdio(stdio) = &mut self.inner {
            let _ = stdio.child.kill();
            let _ = stdio.child.wait();
        }
    }
}

impl CompilationClient {
    /// Speak JSONL to a Compilation Service child. The parent does not construct
    /// the service handler.
    pub fn spawn_stdio(
        program: impl AsRef<Path>,
        args: &[&str],
        artifact_dir: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let artifact_dir = artifact_dir.as_ref().to_path_buf();
        fs::create_dir_all(&artifact_dir).map_err(|error| error.to_string())?;
        let mut child = Command::new(program.as_ref())
            .args(args)
            .env_clear()
            .env("APXM_ARTIFACT_DIR", &artifact_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| error.to_string())?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "compilation stdin".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "compilation stdout".to_owned())?;
        Ok(Self {
            inner: CompilationInner::Stdio(StdioCompilation {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                artifact_dir,
                last_bytes: None,
            }),
        })
    }

    /// Snapshot a local package directory and compile it. The CLI never
    /// constructs a `PackageSnapshot` itself.
    pub fn build_package(&mut self, package_root: &Path) -> Result<String, String> {
        self.build(snapshot_package(package_root)?)
    }

    /// Submit one exact snapshot. Failed or uncertain compiles return no
    /// digest; a failure renders its primary code on the first line and every
    /// carried diagnostic below it.
    pub fn build(&mut self, snapshot: PackageSnapshot) -> Result<String, String> {
        let result = self.build_result(snapshot)?;
        match result {
            CompilationResult::ArtifactCommitted {
                artifact_digest, ..
            } => Ok(artifact_digest),
            CompilationResult::Failed {
                code, diagnostics, ..
            } => Err(render_failure(&code, &diagnostics)),
            CompilationResult::Cancelled { .. } => Err("cancelled".to_owned()),
        }
    }

    /// Submit one exact snapshot and retain the compiler's complete typed
    /// result, including its opaque execution lineage commitment.
    pub fn build_result(&mut self, snapshot: PackageSnapshot) -> Result<CompilationResult, String> {
        self.request(CompilationRequest::Compile {
            request_id: "build".to_owned(),
            idempotency_key: snapshot.snapshot_digest.clone(),
            snapshot,
        })
    }

    /// Committed artifact bytes for a digest this client produced.
    #[must_use]
    pub fn artifact_bytes(&self, digest: &str) -> Option<&str> {
        match &self.inner {
            CompilationInner::InProcess(service) => service.store().get(digest),
            CompilationInner::Stdio(stdio) => stdio
                .last_bytes
                .as_ref()
                .and_then(|(id, bytes)| (id == digest).then_some(bytes.as_str())),
        }
    }

    fn request(&mut self, request: CompilationRequest) -> Result<CompilationResult, String> {
        match &mut self.inner {
            CompilationInner::InProcess(service) => service
                .handle(
                    &CompilationHandshake {
                        protocol_version: COMPILATION_PROTOCOL_VERSION.to_owned(),
                    },
                    request,
                )
                .map_err(|error| format!("{error:?}")),
            CompilationInner::Stdio(stdio) => {
                let envelope = serde_json::json!({
                    "handshake": {
                        "protocol_version": COMPILATION_PROTOCOL_VERSION,
                    },
                    "request": request,
                });
                let frame = StdioFrame {
                    channel: "compilation".to_owned(),
                    payload: envelope.to_string(),
                };
                stdio
                    .stdin
                    .write_all(encode_jsonl(&frame).as_bytes())
                    .map_err(|error| error.to_string())?;
                stdio.stdin.flush().map_err(|error| error.to_string())?;
                let line = read_limited_line(&mut stdio.stdout)?;
                let reply = decode_jsonl(&line)?;
                let result: CompilationResult =
                    serde_json::from_str(&reply.payload).map_err(|error| error.to_string())?;
                if let CompilationResult::ArtifactCommitted {
                    ref artifact_digest,
                    ..
                } = result
                    && let Ok(bytes) = fs::read_to_string(
                        stdio.artifact_dir.join(artifact_digest.replace(':', "-")),
                    )
                {
                    stdio.last_bytes = Some((artifact_digest.clone(), bytes));
                }
                Ok(result)
            }
        }
    }
}

/// Render a failed compile for a terminal: the primary code, then one line per
/// carried diagnostic as `file:line:column: severity code: message` (columns
/// shown 1-based, as editors count them), then how many were not carried and
/// where the compile stopped.
#[must_use]
pub fn render_failure(code: &str, diagnostics: &DiagnosticReport) -> String {
    use std::fmt::Write as _;

    let mut rendered = code.to_owned();
    for item in &diagnostics.items {
        rendered.push_str("\n  ");
        if let Some(location) = &item.location {
            let _ = write!(
                rendered,
                "{}:{}:{}: ",
                location.source_file,
                location.span.start_line,
                location.span.start_column + 1
            );
        }
        let severity = match item.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        let _ = write!(rendered, "{severity} {}: {}", item.code, item.message);
    }
    let omitted = u64::from(diagnostics.total_count)
        .saturating_sub(u64::try_from(diagnostics.items.len()).unwrap_or(u64::MAX));
    if diagnostics.truncated && omitted > 0 {
        let _ = write!(rendered, "\n  ... {omitted} more not shown");
    }
    if let Some(phase) = diagnostics.stopped_at {
        let phase = serde_json::to_value(phase)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        let _ = write!(rendered, "\n  stopped after: {phase}");
    }
    rendered
}

fn read_limited_line(reader: &mut BufReader<ChildStdout>) -> Result<String, String> {
    let mut bytes = Vec::new();
    loop {
        let (take, newline) = {
            let available = reader.fill_buf().map_err(|error| error.to_string())?;
            if available.is_empty() {
                return if bytes.is_empty() {
                    Err("compilation service closed stdout before replying".to_owned())
                } else {
                    String::from_utf8(bytes)
                        .map_err(|error| format!("compilation reply is not UTF-8: {error}"))
                };
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(available.len(), |index| index + 1);
            if bytes.len().saturating_add(take) > MAX_FRAME_BYTES {
                return Err(format!("JSONL frame exceeds {MAX_FRAME_BYTES} bytes"));
            }
            (take, newline.is_some())
        };
        let available = reader.fill_buf().map_err(|error| error.to_string())?;
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline {
            return String::from_utf8(bytes)
                .map_err(|error| format!("compilation reply is not UTF-8: {error}"));
        }
    }
}

/// Walk a package root and bind every file's bytes into a validated snapshot.
pub fn snapshot_package(package_root: &Path) -> Result<PackageSnapshot, String> {
    #[cfg(unix)]
    {
        snapshot_package_descriptor_relative(package_root)
    }
    #[cfg(not(unix))]
    {
        snapshot_package_path_based(package_root)
    }
}

/// Snapshot package contents through directory descriptors. Every directory
/// and regular file is opened relative to a previously opened parent, so a
/// concurrent rename or symlink replacement cannot redirect a read outside
/// the package root between validation and use.
#[cfg(unix)]
fn snapshot_package_descriptor_relative(package_root: &Path) -> Result<PackageSnapshot, String> {
    let root_metadata = fs::symlink_metadata(package_root)
        .map_err(|error| format!("stat package root '{}': {error}", package_root.display()))?;
    if root_metadata.file_type().is_symlink() {
        return Err(format!(
            "package snapshot refuses symlink root '{}'",
            package_root.display()
        ));
    }
    if !root_metadata.is_dir() {
        return Err(format!("'{}' is not a directory", package_root.display()));
    }

    let (root, display_root) = open_package_root(package_root)?;
    let manifest = read_manifest_at(&root)?;
    let mut contents = Vec::new();
    let mut state = SnapshotState::default();
    collect_files_at(
        &root,
        &display_root,
        &display_root,
        0,
        &mut contents,
        &mut state,
    )?;
    if contents.is_empty() {
        return Err("package snapshot is empty".to_owned());
    }
    let lock_digest = contents
        .iter()
        .find(|content| is_lock_name(&content.path))
        .map(|content| content.digest.clone());
    PackageSnapshot::assemble(
        manifest.frontend,
        manifest.entry,
        contents,
        lock_digest,
        "apxm.compatibility-set/local",
    )
    .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn snapshot_package_path_based(package_root: &Path) -> Result<PackageSnapshot, String> {
    let root_metadata = fs::symlink_metadata(package_root)
        .map_err(|error| format!("stat package root '{}': {error}", package_root.display()))?;
    if root_metadata.file_type().is_symlink() {
        return Err(format!(
            "package snapshot refuses symlink root '{}'",
            package_root.display()
        ));
    }
    if !root_metadata.is_dir() {
        return Err(format!("'{}' is not a directory", package_root.display()));
    }

    // Work from the resolved root so every emitted path is rooted in one
    // directory, even when the caller supplied a relative path. Symlink
    // entries are rejected below instead of being resolved into another root.
    let root = fs::canonicalize(package_root).map_err(|error| {
        format!(
            "canonicalize package root '{}': {error}",
            package_root.display()
        )
    })?;
    let manifest = read_manifest(&root)?;
    let mut contents = Vec::new();
    let mut state = SnapshotState::default();
    collect_files(&root, &root, 0, &mut contents, &mut state)?;
    if contents.is_empty() {
        return Err("package snapshot is empty".to_owned());
    }
    let lock_digest = contents
        .iter()
        .find(|content| is_lock_name(&content.path))
        .map(|content| content.digest.clone());
    PackageSnapshot::assemble(
        manifest.frontend,
        manifest.entry,
        contents,
        lock_digest,
        "apxm.compatibility-set/local",
    )
    .map_err(|error| error.to_string())
}

#[derive(Debug, Deserialize)]
struct AgentToml {
    compile: Option<CompileToml>,
}

#[derive(Debug, Deserialize)]
struct CompileToml {
    entry: Option<String>,
    frontend: Option<Frontend>,
}

struct DeclaredCompile {
    frontend: Frontend,
    entry: String,
}

#[cfg(not(unix))]
fn read_manifest(package_root: &Path) -> Result<DeclaredCompile, String> {
    let path = package_root.join("agent.toml");
    let text = read_regular_file(&path, MAX_PACKAGE_FILE_BYTES).map_err(|error| match error {
        FileReadError::NotFound => "missing_frontend".to_owned(),
        FileReadError::Message(message) => message,
    })?;
    let text = String::from_utf8(text).map_err(|error| error.to_string())?;
    let parsed: AgentToml = toml::from_str(&text).map_err(|error| error.to_string())?;
    let compile = parsed
        .compile
        .ok_or_else(|| "missing_frontend".to_owned())?;
    let frontend = compile
        .frontend
        .ok_or_else(|| "missing_frontend".to_owned())?;
    let entry = compile
        .entry
        .ok_or_else(|| "missing_entrypoint".to_owned())?;
    Ok(DeclaredCompile { frontend, entry })
}

#[cfg(unix)]
fn read_manifest_at(root: &OwnedFd) -> Result<DeclaredCompile, String> {
    let name = CString::new("agent.toml").expect("static manifest name has no NUL");
    let text =
        read_regular_file_at(root, &name, MAX_PACKAGE_FILE_BYTES).map_err(|error| match error {
            FileReadError::NotFound => "missing_frontend".to_owned(),
            FileReadError::Message(message) => message,
        })?;
    let text = String::from_utf8(text).map_err(|error| error.to_string())?;
    let parsed: AgentToml = toml::from_str(&text).map_err(|error| error.to_string())?;
    let compile = parsed
        .compile
        .ok_or_else(|| "missing_frontend".to_owned())?;
    let frontend = compile
        .frontend
        .ok_or_else(|| "missing_frontend".to_owned())?;
    let entry = compile
        .entry
        .ok_or_else(|| "missing_entrypoint".to_owned())?;
    Ok(DeclaredCompile { frontend, entry })
}

#[cfg(not(unix))]
fn collect_files(
    root: &Path,
    current: &Path,
    depth: usize,
    contents: &mut Vec<SnapshotContent>,
    state: &mut SnapshotState,
) -> Result<(), String> {
    if depth > MAX_PACKAGE_DEPTH {
        return Err(format!(
            "package snapshot exceeds maximum depth of {MAX_PACKAGE_DEPTH}"
        ));
    }
    let entries = fs::read_dir(current).map_err(|error| error.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| "package snapshot path is not UTF-8".to_owned())?;
        if should_skip(name) {
            continue;
        }

        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "package snapshot refuses symlink '{}'",
                path.display()
            ));
        }
        let rooted_path = fs::canonicalize(&path).map_err(|error| error.to_string())?;
        if !rooted_path.starts_with(root) {
            return Err(format!(
                "package snapshot path '{}' escapes its root",
                path.display()
            ));
        }
        if file_type.is_dir() {
            let next_depth = depth.saturating_add(1);
            if next_depth > MAX_PACKAGE_DEPTH {
                return Err(format!(
                    "package snapshot exceeds maximum depth of {MAX_PACKAGE_DEPTH}"
                ));
            }
            collect_files(root, &rooted_path, next_depth, contents, state)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(format!(
                "package snapshot refuses special file '{}'",
                path.display()
            ));
        }
        if state.file_count >= MAX_PACKAGE_FILES {
            return Err(format!(
                "package snapshot exceeds maximum file count of {MAX_PACKAGE_FILES}"
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_str()
            .ok_or_else(|| "package snapshot path is not UTF-8".to_owned())?
            .replace('\\', "/");
        let bytes =
            read_regular_file(&rooted_path, MAX_PACKAGE_FILE_BYTES).map_err(
                |error| match error {
                    FileReadError::NotFound => {
                        format!("package file '{}' disappeared", path.display())
                    }
                    FileReadError::Message(message) => message,
                },
            )?;
        if state.total_bytes.saturating_add(bytes.len()) > MAX_PACKAGE_BYTES {
            return Err(format!(
                "package snapshot exceeds maximum size of {MAX_PACKAGE_BYTES} bytes"
            ));
        }
        state.file_count += 1;
        state.total_bytes += bytes.len();
        contents.push(SnapshotContent::from_bytes(relative, bytes));
    }
    Ok(())
}

#[cfg(unix)]
fn collect_files_at(
    parent: &OwnedFd,
    root_display: &Path,
    display_dir: &Path,
    depth: usize,
    contents: &mut Vec<SnapshotContent>,
    state: &mut SnapshotState,
) -> Result<(), String> {
    if depth > MAX_PACKAGE_DEPTH {
        return Err(format!(
            "package snapshot exceeds maximum depth of {MAX_PACKAGE_DEPTH}"
        ));
    }
    let entries = Dir::read_from(parent).map_err(|error| error.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name_text = name
            .to_str()
            .map_err(|_| "package snapshot path is not UTF-8".to_owned())?;
        if should_skip(name_text) {
            continue;
        }
        let display_path = display_dir.join(name_text);

        match open_directory_at(parent, name, &display_path)? {
            Some(directory) => {
                let next_depth = depth.saturating_add(1);
                if next_depth > MAX_PACKAGE_DEPTH {
                    return Err(format!(
                        "package snapshot exceeds maximum depth of {MAX_PACKAGE_DEPTH}"
                    ));
                }
                collect_files_at(
                    &directory,
                    root_display,
                    &display_path,
                    next_depth,
                    contents,
                    state,
                )?;
            }
            None => {
                if state.file_count >= MAX_PACKAGE_FILES {
                    return Err(format!(
                        "package snapshot exceeds maximum file count of {MAX_PACKAGE_FILES}"
                    ));
                }
                let bytes = read_regular_file_at(parent, name, MAX_PACKAGE_FILE_BYTES).map_err(
                    |error| match error {
                        FileReadError::NotFound => {
                            format!("package file '{}' disappeared", display_path.display())
                        }
                        FileReadError::Message(message) => message,
                    },
                )?;
                if state.total_bytes.saturating_add(bytes.len()) > MAX_PACKAGE_BYTES {
                    return Err(format!(
                        "package snapshot exceeds maximum size of {MAX_PACKAGE_BYTES} bytes"
                    ));
                }
                let relative = display_path
                    .strip_prefix(root_display)
                    .map_err(|error| error.to_string())?
                    .to_str()
                    .ok_or_else(|| "package snapshot path is not UTF-8".to_owned())?
                    .replace('\\', "/");
                state.file_count += 1;
                state.total_bytes += bytes.len();
                contents.push(SnapshotContent::from_bytes(relative, bytes));
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct SnapshotState {
    file_count: usize,
    total_bytes: usize,
}

enum FileReadError {
    NotFound,
    Message(String),
}

#[cfg(not(unix))]
fn read_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, FileReadError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            FileReadError::NotFound
        } else {
            FileReadError::Message(error.to_string())
        }
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(FileReadError::Message(format!(
            "package snapshot refuses symlink '{}'",
            path.display()
        )));
    }
    if !file_type.is_file() {
        return Err(FileReadError::Message(format!(
            "package snapshot refuses special file '{}'",
            path.display()
        )));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(FileReadError::Message(format!(
            "package file '{}' exceeds maximum size of {max_bytes} bytes",
            path.display()
        )));
    }

    let file = open_regular_file(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| FileReadError::Message(error.to_string()))?;
    if bytes.len() > max_bytes {
        return Err(FileReadError::Message(format!(
            "package file '{}' exceeds maximum size of {max_bytes} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_regular_file_at(
    parent: &OwnedFd,
    name: &CStr,
    max_bytes: usize,
) -> Result<Vec<u8>, FileReadError> {
    let fd = openat(
        parent,
        name,
        // O_NONBLOCK prevents a FIFO supplied as a package member from
        // stalling the snapshot before its non-regular type is rejected.
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    let file: fs::File = fd.into();
    let metadata = file
        .metadata()
        .map_err(|error| FileReadError::Message(error.to_string()))?;
    if !metadata.is_file() {
        return Err(FileReadError::Message(
            "package snapshot refuses special file".to_owned(),
        ));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(FileReadError::Message(format!(
            "package file exceeds maximum size of {max_bytes} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| FileReadError::Message(error.to_string()))?;
    if bytes.len() > max_bytes {
        return Err(FileReadError::Message(format!(
            "package file exceeds maximum size of {max_bytes} bytes"
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_canonical_directory(path: &Path) -> Result<OwnedFd, String> {
    let mut directory = open(
        Path::new("/"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                directory = openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| error.to_string())?;
            }
            _ => return Err("canonical package root contains an invalid path".to_owned()),
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_package_root(package_root: &Path) -> Result<(OwnedFd, PathBuf), String> {
    // Resolve only the parent path, then open the caller-supplied final name
    // with O_NOFOLLOW. Resolving the complete path first would allow a final
    // directory replacement to turn a previously checked package root into a
    // symlink to an unrelated directory.
    if let (Some(parent), Some(name)) = (package_root.parent(), package_root.file_name()) {
        let canonical_parent = fs::canonicalize(parent).map_err(|error| {
            format!(
                "canonicalize package root parent '{}': {error}",
                parent.display()
            )
        })?;
        let parent_fd = open_canonical_directory(&canonical_parent)?;
        let root = openat(
            &parent_fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::LOOP {
                format!(
                    "package snapshot refuses symlink root '{}'",
                    package_root.display()
                )
            } else {
                error.to_string()
            }
        })?;
        return Ok((root, canonical_parent.join(name)));
    }

    let canonical = fs::canonicalize(package_root).map_err(|error| {
        format!(
            "canonicalize package root '{}': {error}",
            package_root.display()
        )
    })?;
    let root = open_canonical_directory(&canonical)?;
    Ok((root, canonical))
}

#[cfg(unix)]
fn open_directory_at(
    parent: &OwnedFd,
    name: &CStr,
    display_path: &Path,
) -> Result<Option<OwnedFd>, String> {
    match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) => {
            if error == rustix::io::Errno::NOTDIR {
                return Ok(None);
            }
            if error == rustix::io::Errno::LOOP {
                return Err(format!(
                    "package snapshot refuses symlink '{}'",
                    display_path.display()
                ));
            }
            let error = std::io::Error::from_raw_os_error(error.raw_os_error());
            Err(error.to_string())
        }
    }
}

#[cfg(unix)]
fn map_open_error(error: rustix::io::Errno) -> FileReadError {
    let error = std::io::Error::from_raw_os_error(error.raw_os_error());
    if error.kind() == std::io::ErrorKind::NotFound {
        FileReadError::NotFound
    } else if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        FileReadError::Message("package snapshot refuses symlink".to_owned())
    } else if error.kind() == std::io::ErrorKind::Unsupported
        || error.raw_os_error() == Some(rustix::io::Errno::NXIO.raw_os_error())
    {
        FileReadError::Message("package snapshot refuses special file".to_owned())
    } else {
        FileReadError::Message(error.to_string())
    }
}

#[cfg(not(unix))]
fn open_regular_file(path: &Path) -> Result<fs::File, FileReadError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options
            .open(path)
            .map_err(|error| FileReadError::Message(error.to_string()))
    }
    #[cfg(not(unix))]
    {
        fs::File::open(path).map_err(|error| FileReadError::Message(error.to_string()))
    }
}

fn should_skip(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "target" | "__pycache__" | ".apxm" | ".dekk" | ".DS_Store"
    ) || std::path::Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pyc"))
}

fn is_lock_name(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "uv.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "Cargo.lock"
            | "poetry.lock"
    ) || std::path::Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const PYTHON_PROGRAM: &str = r#"from apxm_program import Agent, Model, Tool


class ReviewRequest:
    pass


class Review:
    pass


ReviewModel = Model[ReviewRequest, Review]("review.model")
SearchWeb = Tool[ReviewRequest, Review]("search_web")


@Agent(model=ReviewModel, input=ReviewRequest, output=Review)
async def Reviewer(agent, request):
    evidence = await SearchWeb(request)
    return await ReviewModel(evidence)
"#;

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("compilation-client sits three levels under the repository root")
            .to_path_buf()
    }

    fn frontend_present() -> bool {
        let root = workspace_root();
        root.join(".dekk/env/bin/python").is_file()
            && root
                .join("crates/compiler/frontend/python/apxm_program/_native.so")
                .is_file()
    }

    #[test]
    fn build_package_snapshots_real_bytes_and_commits_air() {
        if !frontend_present() {
            return;
        }
        let dir = tempfile_dir();
        fs::write(
            dir.join("agent.toml"),
            "id = \"tiny\"\nversion = \"0.1.0\"\nschema_version = \"apxm.agent\"\n\n[compile]\nentry = \"src/agent.py\"\nfrontend = \"python\"\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/agent.py"), PYTHON_PROGRAM).unwrap();

        let snapshot = snapshot_package(&dir).unwrap();
        assert!(
            snapshot
                .file("src/agent.py")
                .is_some_and(|content| !content.bytes.is_empty())
        );
        assert_ne!(snapshot.snapshot_digest, "local");
        assert!(snapshot.file("src/agent.py").unwrap().digest != "local");

        let mut client = CompilationClient::default();
        let result = client
            .build_result(snapshot)
            .expect("client exposes the complete compilation result");
        let CompilationResult::ArtifactCommitted {
            artifact_digest,
            execution_lineage_ref,
            ..
        } = result
        else {
            panic!("expected a committed artifact");
        };
        assert!(artifact_digest.starts_with("sha256:"));
        assert!(execution_lineage_ref.starts_with("sha256:"));
        let digest = artifact_digest;
        let air = client.artifact_bytes(&digest).expect("committed bytes");
        assert!(air.contains("apxm.air"));
    }

    #[test]
    fn conversational_example_compiles_through_the_service() {
        if !frontend_present() {
            return;
        }
        let root = workspace_root().join("examples/agents/conversational");
        let mut client = CompilationClient::default();
        let digest = client
            .build_package(&root)
            .expect("conversational example compiles through Compilation Service");
        let air = client.artifact_bytes(&digest).expect("committed AIR");
        assert!(air.contains("apxm.air"), "{air}");
    }

    #[test]
    fn interaction_harness_compiles_program_new_invoke_and_await_event() {
        if !frontend_present() {
            return;
        }
        let root = workspace_root().join("examples/agents/interaction-harness");
        let mut client = CompilationClient::default();
        let digest = client
            .build_package(&root)
            .expect("harness package compiles through Compilation Service");
        let air = client.artifact_bytes(&digest).expect("committed AIR");
        assert!(air.contains("\"op\":\"program.new\""), "{air}");
        assert!(air.contains("\"op\":\"program.invoke\""), "{air}");
        assert!(air.contains("\"op\":\"await.event\""), "{air}");
        assert!(
            !air.contains("CommittedYield") || air.contains("await.event"),
            "yield and await.event remain distinct operations"
        );
    }

    #[test]
    fn e2e_snapshot_stdio_compile_then_headless_artifact_run() {
        if !frontend_present() {
            return;
        }
        let dir = tempfile_dir();
        fs::write(
            dir.join("agent.toml"),
            "id = \"echo\"\nversion = \"0.1.0\"\nschema_version = \"apxm.agent\"\n\n[compile]\nentry = \"src/agent.py\"\nfrontend = \"python\"\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/agent.py"),
            r#"from typing import TypedDict
from apxm_program import Workflow


class Echo(TypedDict):
    message: str


@Workflow(input=Echo, output=Echo)
async def EchoAgent(agent, request):
    return request
"#,
        )
        .unwrap();

        let snapshot = snapshot_package(&dir).expect("snapshot real package bytes");
        assert_ne!(snapshot.snapshot_digest, "local");

        let artifact_dir = tempfile_dir();
        let service = CompilationService::default().with_artifact_dir(artifact_dir.clone());
        let envelope = serde_json::json!({
            "handshake": {
                "protocol_version": COMPILATION_PROTOCOL_VERSION,
            },
            "request": CompilationRequest::Compile {
                request_id: "e2e".to_owned(),
                idempotency_key: snapshot.snapshot_digest.clone(),
                snapshot,
            }
        });
        let frame = StdioFrame {
            channel: "compilation".to_owned(),
            payload: envelope.to_string(),
        };
        let mut out = Vec::new();
        apxm_compilation_service::serve_stdio(encode_jsonl(&frame).as_bytes(), &mut out, service)
            .expect("compilation stdio");
        let reply = decode_jsonl(std::str::from_utf8(&out).unwrap()).unwrap();
        let result: CompilationResult = serde_json::from_str(&reply.payload).unwrap();
        let CompilationResult::ArtifactCommitted {
            artifact_digest, ..
        } = result
        else {
            panic!("stdio compile must commit: {result:?}");
        };
        let air = fs::read(
            artifact_dir.join(apxm_compilation_service::artifact_file_name(
                &artifact_digest,
            )),
        )
        .expect("persisted artifact bytes");
        assert!(String::from_utf8_lossy(&air).contains("apxm.air"));

        let mut runtime = apxm_interaction_client::InteractionClient::default();
        let admitted = runtime
            .admit_artifact(air.clone())
            .expect("Runtime Service admits compiled bytes");
        assert_eq!(admitted, artifact_digest);
        let instance = runtime
            .run_artifact(&admitted)
            .expect("--artifact creates a Program Instance without Compilation");
        let release =
            fs::read(workspace_root().join("tools/tests/fixtures/canonical-execute.release.json"))
                .expect("canonical release bytes");
        let provenance = fs::read(
            workspace_root().join("tools/tests/fixtures/canonical-execute.provenance.json"),
        )
        .expect("canonical provenance bytes");
        runtime
            .bind_admission(
                &instance,
                apxm_runtime_service::materials_for_artifact(
                    &air,
                    format!("{instance}:inv-1"),
                    release,
                    provenance,
                ),
            )
            .expect("bind exact canonical invocation admission");
        let started = runtime
            .start_invocation(&instance, serde_json::json!({"message": "hello"}))
            .expect("headless invoke");
        assert!(
            matches!(
                started,
                apxm_runtime_protocol::RuntimeResult::ProgramInvocationStarted { .. }
            ),
            "echo Program must start successfully: {started:?}"
        );
    }

    #[test]
    fn missing_frontend_is_rejected_before_compile() {
        let dir = tempfile_dir();
        fs::write(dir.join("agent.toml"), "id = \"x\"\nversion = \"0.1.0\"\n").unwrap();
        fs::write(dir.join("src.py"), "print('x')").unwrap();
        assert_eq!(snapshot_package(&dir).unwrap_err(), "missing_frontend");
    }

    #[test]
    fn package_snapshot_rejects_a_symlinked_member() {
        #[cfg(unix)]
        {
            let dir = tempfile_dir();
            fs::write(
                dir.join("agent.toml"),
                "[compile]\nentry = \"agent.py\"\nfrontend = \"python\"\n",
            )
            .unwrap();
            fs::write(dir.join("agent.py"), "print('ok')").unwrap();
            std::os::unix::fs::symlink("/etc/passwd", dir.join("leak.py")).unwrap();

            let error = snapshot_package(&dir).expect_err("symlink must not enter a snapshot");
            assert!(error.contains("symlink"), "{error}");
        }
    }

    #[test]
    fn package_snapshot_rejects_a_symlinked_directory_member() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let dir = tempfile_dir();
            fs::write(
                dir.join("agent.toml"),
                "[compile]\nentry = \"agent.py\"\nfrontend = \"python\"\n",
            )
            .unwrap();
            fs::write(dir.join("agent.py"), "print('ok')").unwrap();
            let target = tempfile_dir();
            fs::write(target.join("escape.py"), "print('outside')").unwrap();
            symlink(&target, dir.join("outside")).unwrap();

            let error = snapshot_package(&dir).expect_err("directory symlink must be rejected");
            assert!(error.contains("symlink"), "{error}");
        }
    }

    #[test]
    fn package_snapshot_rejects_special_files() {
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixListener;

            let dir = tempfile_dir();
            fs::write(
                dir.join("agent.toml"),
                "[compile]\nentry = \"agent.py\"\nfrontend = \"python\"\n",
            )
            .unwrap();
            fs::write(dir.join("agent.py"), "print('ok')").unwrap();
            let socket_path = PathBuf::from(format!(
                "/tmp/apxm-special-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time")
                    .as_nanos()
            ));
            let _socket = UnixListener::bind(&socket_path).unwrap();
            fs::create_dir_all(&dir).unwrap();
            fs::rename(&socket_path, dir.join("special")).unwrap();

            let error = snapshot_package(&dir).expect_err("socket must not enter a snapshot");
            assert!(error.contains("special file"), "{error}");
        }
    }

    #[test]
    fn package_snapshot_enforces_file_size_and_total_size_bounds() {
        let dir = tempfile_dir();
        fs::write(
            dir.join("agent.toml"),
            "[compile]\nentry = \"agent.py\"\nfrontend = \"python\"\n",
        )
        .unwrap();
        fs::write(dir.join("agent.py"), vec![b'x'; MAX_PACKAGE_FILE_BYTES + 1]).unwrap();
        let error = snapshot_package(&dir).expect_err("oversized file must be rejected");
        assert!(error.contains("maximum size"), "{error}");

        let dir = tempfile_dir();
        fs::write(
            dir.join("agent.toml"),
            "[compile]\nentry = \"one.py\"\nfrontend = \"python\"\n",
        )
        .unwrap();
        let chunk_count = MAX_PACKAGE_BYTES / MAX_PACKAGE_FILE_BYTES + 1;
        for index in 0..chunk_count {
            fs::write(
                dir.join(format!("chunk-{index}.py")),
                vec![b'x'; MAX_PACKAGE_FILE_BYTES],
            )
            .unwrap();
        }
        let error = snapshot_package(&dir).expect_err("aggregate size must be bounded");
        assert!(error.contains("maximum size"), "{error}");
    }

    #[test]
    fn package_snapshot_enforces_depth_and_file_count_bounds() {
        let dir = tempfile_dir();
        fs::write(
            dir.join("agent.toml"),
            "[compile]\nentry = \"agent.py\"\nfrontend = \"python\"\n",
        )
        .unwrap();
        let mut nested = dir.clone();
        for index in 0..=MAX_PACKAGE_DEPTH {
            nested = nested.join(format!("d{index}"));
        }
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("agent.py"), "print('too deep')").unwrap();
        let error = snapshot_package(&dir).expect_err("deep package must be rejected");
        assert!(error.contains("maximum depth"), "{error}");

        let dir = tempfile_dir();
        fs::write(
            dir.join("agent.toml"),
            "[compile]\nentry = \"agent.py\"\nfrontend = \"python\"\n",
        )
        .unwrap();
        fs::write(dir.join("agent.py"), "print('ok')").unwrap();
        for index in 0..MAX_PACKAGE_FILES {
            fs::write(dir.join(format!("extra-{index}.py")), "pass").unwrap();
        }
        let error = snapshot_package(&dir).expect_err("file count must be bounded");
        assert!(error.contains("maximum file count"), "{error}");
    }

    #[test]
    fn stdio_child_receives_only_the_artifact_directory() {
        #[cfg(unix)]
        {
            let artifact_dir = tempfile_dir();
            let dump = artifact_dir.join("environment");
            let script = format!("/usr/bin/env > '{}'", dump.display());
            let client =
                CompilationClient::spawn_stdio("/bin/sh", &["-c", script.as_str()], &artifact_dir)
                    .unwrap();
            for _ in 0..100 {
                if dump.metadata().is_ok_and(|metadata| metadata.len() > 0) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            drop(client);

            let environment = fs::read_to_string(dump).unwrap();
            assert!(
                environment.lines().any(|line| {
                    line == format!("APXM_ARTIFACT_DIR={}", artifact_dir.display())
                })
            );
            for line in environment.lines() {
                assert!(
                    line.starts_with("APXM_ARTIFACT_DIR=")
                        || line.starts_with("PWD=")
                        || line.starts_with("SHLVL=")
                        || line.starts_with("_="),
                    "unexpected sanitized-child environment entry: {line}"
                );
            }
        }
    }

    fn tempfile_dir() -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "apxm-compilation-client-{}-{timestamp}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create temporary package directory: {error}"),
            }
        }
        panic!("could not allocate a unique temporary package directory")
    }

    /// A failure renders its primary code first, then every carried item
    /// with its location, the omitted count and where the compile stopped.
    #[test]
    fn a_failure_renders_every_carried_diagnostic() {
        use apxm_compilation_protocol::{CompileDiagnostic, Location, Phase, Span};

        let located = CompileDiagnostic {
            location: Some(Location {
                source_file: "submitted_source.ts".to_owned(),
                span: Span {
                    start_line: 9,
                    start_column: 49,
                    end_line: 9,
                    end_column: 66,
                },
            }),
            ..CompileDiagnostic::new(
                Severity::Error,
                "graph_rejected",
                Phase::TypeCheck,
                "undeclared host reference",
            )
        };
        let mut report = DiagnosticReport::from_diagnostics(
            [
                located,
                CompileDiagnostic::new(
                    Severity::Warning,
                    "source_warning",
                    Phase::TypeCheck,
                    "unused",
                ),
            ],
            Some(Phase::TypeCheck),
        );
        report.truncated = true;
        report.total_count = 5;
        assert_eq!(
            render_failure("graph_rejected", &report),
            "graph_rejected\n  submitted_source.ts:9:50: error graph_rejected: undeclared host reference\n  warning source_warning: unused\n  ... 3 more not shown\n  stopped after: type_check"
        );
    }
}
