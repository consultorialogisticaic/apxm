//! Doctor reports the resolved MLIR toolchain independently of Conda.

use std::process::Command;

use apxm_core::{constants::ui, toolchain_env};

#[test]
fn nix_toolchain_without_conda_is_ready_without_an_install_hint() {
    let directory = tempfile::tempdir().expect("isolated package directory");
    let output = Command::new(env!("CARGO_BIN_EXE_apxm"))
        .arg("doctor")
        .current_dir(directory.path())
        .env_remove(toolchain_env::CONDA_PREFIX)
        .env("HOME", directory.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("doctor process");
    let stdout = String::from_utf8(output.stdout).expect("doctor output");
    assert!(
        output.status.success(),
        "{stdout}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(&format!("MLIR toolchain [{}] ready", ui::labels::OK)),
        "{stdout}"
    );
    assert!(!stdout.contains("Conda prefix"), "{stdout}");
    assert!(!stdout.contains("install --no-interactive"), "{stdout}");
    assert!(stdout.contains("agent.toml"), "{stdout}");
    assert!(
        stdout.contains(&format!("[{}] absent", ui::labels::WARN)),
        "{stdout}"
    );
}

#[test]
fn missing_mlir_toolchain_fails_without_claiming_ready() {
    let directory = tempfile::tempdir().expect("isolated toolchain directory");
    let mut command = Command::new(env!("CARGO_BIN_EXE_apxm"));
    command
        .arg("doctor")
        .current_dir(directory.path())
        .env(toolchain_env::PATH, "")
        .env("HOME", directory.path())
        .env("NO_COLOR", "1");
    for key in toolchain_env::MLIR_TOOLCHAIN_LIBRARY_ENV_KEYS {
        command.env_remove(key);
    }
    let output = command.output().expect("doctor process");
    let stdout = String::from_utf8(output.stdout).expect("doctor output");
    let stderr = String::from_utf8(output.stderr).expect("doctor error");
    assert!(!output.status.success(), "{stdout}");
    assert!(
        stdout.contains(&format!("MLIR toolchain [{}] missing", ui::labels::MISSING)),
        "{stdout}"
    );
    assert!(
        !stdout.contains(&format!("[{}] ready", ui::labels::OK)),
        "{stdout}"
    );
    assert!(stderr.contains("MLIR toolchain not detected"), "{stderr}");
}
