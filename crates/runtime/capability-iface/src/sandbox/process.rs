use super::policy::SandboxPolicy;
#[cfg(test)]
use crate::sandbox::constants::session_prefixes;
use crate::sandbox::constants::{env as sandbox_env, messages};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

const OUTPUT_BUFFER_SIZE: usize = 16 * 1024;

/// Result of a sandboxed execution.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

/// Process-based sandbox for code execution.
pub struct ProcessSandbox {
    policy: SandboxPolicy,
}

impl ProcessSandbox {
    pub fn new(policy: SandboxPolicy) -> Self {
        Self { policy }
    }

    pub fn with_default_policy() -> Self {
        Self::new(SandboxPolicy::default())
    }

    /// Execute a command in the sandbox.
    pub async fn execute(
        &self,
        command: &str,
        args: &[&str],
        stdin_data: Option<&str>,
    ) -> std::io::Result<SandboxResult> {
        if !self
            .policy
            .allowed_commands
            .iter()
            .any(|allowed| allowed == command)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                messages::COMMAND_BLOCKED_BY_POLICY,
            ));
        }

        // Create temp working directory if not specified
        let temp_dir;
        let work_dir = if let Some(dir) = &self.policy.working_dir {
            dir.clone()
        } else {
            temp_dir = tempfile::tempdir()?;
            temp_dir.path().to_path_buf()
        };

        // Ensure work_dir exists
        tokio::fs::create_dir_all(&work_dir).await?;

        let mut cmd = Command::new(command);
        cmd.args(args)
            .current_dir(&work_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // A cancelled timeout future must not leave the child running
            // after its pipes and wait future have been dropped.
            .kill_on_drop(true);

        // Set up restricted environment: clear everything, then whitelist safe vars
        cmd.env_clear();
        for key in sandbox_env::CHILD_PASSTHROUGH {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }
        for (key, value) in &self.policy.env_overrides {
            if !self.policy.blocks_env_var(key) {
                cmd.env(key, value);
            }
        }

        if stdin_data.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }

        let mut child = cmd.spawn()?;

        // All four operations are live at once. Waiting before draining either
        // pipe deadlocks as soon as the child fills one of the OS pipe buffers;
        // writing stdin before the lifecycle timeout can block forever when a
        // child does not consume its input.
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let output_budget = Arc::new(AtomicUsize::new(0));
        let max_output_bytes = self.policy.max_output_bytes;
        let stdin_data = stdin_data.map(str::as_bytes).map(ToOwned::to_owned);

        let lifecycle = async {
            let write = write_stdin(stdin, stdin_data);
            let read_stdout = read_stream(stdout, max_output_bytes, Arc::clone(&output_budget));
            let read_stderr = read_stream(stderr, max_output_bytes, Arc::clone(&output_budget));
            let wait = child.wait();
            tokio::join!(write, read_stdout, read_stderr, wait)
        };

        match tokio::time::timeout(self.policy.timeout, Box::pin(lifecycle)).await {
            Ok((write_result, stdout_result, stderr_result, status_result)) => {
                // A child is allowed to close stdin before consuming the full
                // request, so BrokenPipe is expected. The process status and
                // captured streams remain the authoritative execution result;
                // do not turn a normal early close into a sandbox failure.
                let _ = write_result;
                let status = status_result?;
                let stdout = stdout_result?;
                let stderr = stderr_result?;

                Ok(SandboxResult {
                    stdout: captured_text(stdout),
                    stderr: captured_text(stderr),
                    exit_code: status.code().unwrap_or(-1),
                    timed_out: false,
                })
            }
            Err(_) => {
                // `kill_on_drop` handles cancellation of the lifecycle future;
                // explicitly kill and reap as well so the timeout path does
                // not leave a zombie on platforms where dropping a child only
                // schedules the kill.
                let _ = child.kill().await;
                let _ = child.wait().await;
                Ok(SandboxResult {
                    stdout: String::new(),
                    stderr: messages::PROCESS_TIMED_OUT_AND_KILLED.to_string(),
                    exit_code: -1,
                    timed_out: true,
                })
            }
        }
    }

    /// Execute a script (write to temp file, then run with interpreter).
    ///
    /// Test-only: production code reaches `ProcessSandbox` through
    /// `ProcessSandboxBackend::execute`, never this helper.
    #[cfg(test)]
    pub async fn execute_script(
        &self,
        interpreter: &str,
        code: &str,
    ) -> std::io::Result<SandboxResult> {
        let script_dir = tempfile::tempdir()?;
        let script_path = script_dir.path().join(session_prefixes::SCRIPT);
        tokio::fs::write(&script_path, code).await?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&script_path, perms)?;
        }

        self.execute(
            interpreter,
            &[script_path.to_str().unwrap_or(session_prefixes::SCRIPT)],
            None,
        )
        .await
    }
}

/// Write all supplied stdin without making it a prerequisite for process
/// output draining or child waiting. Closing the handle signals EOF to the
/// child after the request is complete.
async fn write_stdin<W>(stdin: Option<W>, data: Option<Vec<u8>>) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let (Some(mut stdin), Some(data)) = (stdin, data) else {
        return Ok(());
    };
    stdin.write_all(&data).await
}

/// Drain a pipe to EOF while retaining only the first available portion of a
/// shared output budget. Once the budget is full, reads continue and discard
/// bytes so a noisy child cannot deadlock on a full pipe.
async fn read_stream<R>(
    reader: Option<R>,
    max_output_bytes: usize,
    output_budget: Arc<AtomicUsize>,
) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return Ok(Vec::new());
    };

    let mut captured = Vec::new();
    let mut buffer = [0_u8; OUTPUT_BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(captured);
        }

        let retained = reserve_output(&output_budget, max_output_bytes, read);
        captured.extend_from_slice(&buffer[..retained]);
    }
}

/// Reserve output bytes without allowing stdout and stderr to exceed their
/// combined policy budget. The stream readers still drain after this returns
/// zero; this only controls retained memory.
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

fn captured_text(bytes: Vec<u8>) -> String {
    // A byte budget can end in the middle of a UTF-8 sequence. Convert lossily
    // and trim the replacement boundary so callers receive valid text without
    // retaining an unbounded intermediate string.
    truncate_output(String::from_utf8_lossy(&bytes).into_owned(), bytes.len())
}

/// Truncate captured process output without splitting a UTF-8 code point.
fn truncate_output(text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let boundary = text
        .char_indices()
        .take_while(|(index, _)| *index < max)
        .map(|(index, _)| index)
        .last()
        .unwrap_or(0);
    text[..boundary].to_string()
}

#[cfg(test)]
mod tests {
    use super::ProcessSandbox;
    use crate::sandbox::policy::SandboxPolicy;
    use std::time::Duration;

    #[cfg(unix)]
    fn sandbox(timeout: Duration, max_output_bytes: usize) -> ProcessSandbox {
        ProcessSandbox::new(SandboxPolicy {
            timeout,
            max_output_bytes,
            allowed_commands: vec!["sh".to_string()],
            ..SandboxPolicy::default()
        })
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn large_input_and_bidirectional_output_are_drained_concurrently() {
        let sandbox = sandbox(Duration::from_secs(2), 512 * 1024);
        let input = "x".repeat(512 * 1024);
        let result = sandbox
            .execute(
                "sh",
                &[
                    "-c",
                    "cat >/dev/null; dd if=/dev/zero bs=131072 count=1 2>/dev/null; dd if=/dev/zero bs=131072 count=1 1>&2 2>/dev/null",
                ],
                Some(&input),
            )
            .await
            .expect("the process should complete");

        assert!(!result.timed_out);
        assert_eq!(result.stdout.len(), 131_072);
        assert_eq!(result.stderr.len(), 131_072);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_budget_is_shared_while_noisy_pipes_continue_draining() {
        let sandbox = sandbox(Duration::from_secs(2), 1024);
        let result = sandbox
            .execute(
                "sh",
                &[
                    "-c",
                    "dd if=/dev/zero bs=1048576 count=4 2>/dev/null; dd if=/dev/zero bs=1048576 count=4 1>&2 2>/dev/null",
                ],
                None,
            )
            .await
            .expect("the noisy process should complete");

        assert!(!result.timed_out);
        assert!(result.stdout.len() + result.stderr.len() <= 1024);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_child_that_never_reads_large_stdin_is_timed_out() {
        let sandbox = sandbox(Duration::from_millis(50), 1024);
        let input = "x".repeat(4 * 1024 * 1024);
        let result = sandbox
            .execute("sh", &["-c", "sleep 2"], Some(&input))
            .await
            .expect("a timed-out process returns a result");

        assert!(result.timed_out);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn default_policy_denies_every_command() {
        let sandbox = ProcessSandbox::with_default_policy();
        let err = sandbox
            .execute("sh", &["-c", "true"], None)
            .await
            .expect_err("an empty allowlist must block execution");

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
