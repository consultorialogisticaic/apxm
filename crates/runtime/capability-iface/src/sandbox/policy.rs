use crate::sandbox::constants::{env as sandbox_env, limits as sandbox_limits};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Security policy for sandboxed code execution.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Maximum execution time before killing the process.
    pub timeout: Duration,
    /// Maximum bytes to capture from stdout+stderr.
    pub max_output_bytes: usize,
    /// Commands/interpreters allowed to run. Deny by default: an empty list
    /// permits nothing, so callers must opt in explicitly.
    pub allowed_commands: Vec<String>,
    /// Environment variables to remove before execution.
    pub blocked_env_vars: Vec<String>,
    /// Additional environment variables to inject after the safe baseline.
    pub env_overrides: HashMap<String, String>,
    /// Override working directory (uses temp dir if None).
    pub working_dir: Option<PathBuf>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            timeout: sandbox_limits::DEFAULT_TIMEOUT,
            max_output_bytes: sandbox_limits::DEFAULT_MAX_OUTPUT_BYTES,
            allowed_commands: Vec::new(),
            blocked_env_vars: sandbox_env::BLOCKED_DEFAULTS
                .iter()
                .map(|key| (*key).to_string())
                .collect(),
            env_overrides: HashMap::new(),
            working_dir: None,
        }
    }
}

impl SandboxPolicy {
    /// Return whether an environment variable must be kept out of sandboxed
    /// execution. Exact entries are policy-controlled; marker checks catch
    /// backend-specific secret names without making core know those providers.
    pub fn blocks_env_var(&self, key: &str) -> bool {
        self.blocked_env_vars.iter().any(|blocked| blocked == key)
            || sandbox_env::is_sensitive_name(key)
    }
}
