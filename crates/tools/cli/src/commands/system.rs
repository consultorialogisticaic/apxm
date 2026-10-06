//! System commands for environment diagnostics.

use std::env;
use std::path::PathBuf;

use anyhow::Result;
use apxm_core::constants::env as apxm_env;
use apxm_core::utils::build::MlirEnvReport;

use super::dekk_hints;
use super::implementations::{Status, print_section_header, print_status_line};
use colored::Colorize;

fn print_hint(message: &str) {
    use apxm_core::constants::ui;
    println!("  {} {}", ui::icons::INFO.cyan(), message);
}

fn print_warning_line(label: &str, value: &str) {
    use apxm_core::constants::ui;
    println!(
        "  {} {:<14} [{}] {}",
        ui::icons::WARNING.yellow(),
        label.bold(),
        ui::labels::WARN.yellow().bold(),
        value
    );
}

pub fn doctor_command(config: Option<PathBuf>, json_output: bool) -> Result<()> {
    let report = MlirEnvReport::detect();
    report.apply_env();
    let mlir_available = report.is_ready();
    let mlir_prefix = report
        .resolved_prefix
        .as_ref()
        .map(|p| p.display().to_string());
    let mlir_version = report.llvm_version.clone();

    let env_mlir_dir = env::var(apxm_env::MLIR_DIR).ok();
    let env_llvm_dir = env::var(apxm_env::LLVM_DIR).ok();
    let package_contract = inspect_package_contract();
    let _ = config;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "environment": {
                    apxm_env::MLIR_DIR: env_mlir_dir,
                    apxm_env::LLVM_DIR: env_llvm_dir,
                    "mlir_available": mlir_available,
                    "mlir_prefix": mlir_prefix,
                    "mlir_version": mlir_version,
                },
                "package_contract": package_contract,
            }))?
        );
        return Ok(());
    }

    print_section_header("Environment");
    if mlir_available {
        let detail = match &mlir_version {
            Some(v) => format!("ready (LLVM {v})"),
            None => "ready".to_owned(),
        };
        print_status_line("MLIR toolchain", Status::Ok, &detail);
    } else {
        print_status_line("MLIR toolchain", Status::Error, "missing");
    }
    for (name, value) in [
        (apxm_env::MLIR_DIR, &env_mlir_dir),
        (apxm_env::LLVM_DIR, &env_llvm_dir),
    ] {
        match value {
            Some(v) => print_status_line(name, Status::Ok, v),
            None => print_warning_line(name, "not set"),
        }
    }
    if env_mlir_dir.is_none() || env_llvm_dir.is_none() {
        print_hint(&format!(
            "Invoke project commands through `{}` so dekk injects the MLIR/LLVM environment.",
            dekk_hints::APXM_ENV_HINT
        ));
    }

    print_section_header("Package contract");
    match package_contract
        .get("status")
        .and_then(|value| value.as_str())
    {
        Some("ok") => print_status_line("agent.toml", Status::Ok, "apxm.agent"),
        Some(status) => print_warning_line("agent.toml", status),
        None => print_warning_line("agent.toml", "absent"),
    }

    if !mlir_available {
        return Err(anyhow::anyhow!("MLIR toolchain not detected"));
    }
    Ok(())
}

fn inspect_package_contract() -> serde_json::Value {
    let path = PathBuf::from("agent.toml");
    if !path.is_file() {
        return serde_json::json!({"status": "absent"});
    }
    match std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| text.parse::<toml::Value>().ok())
    {
        Some(document)
            if document.get("schema_version").and_then(toml::Value::as_str)
                == Some("apxm.agent") =>
        {
            serde_json::json!({"status": "ok", "path": "agent.toml"})
        }
        Some(_) => serde_json::json!({"status": "unrecognized", "path": "agent.toml"}),
        None => serde_json::json!({"status": "unreadable", "path": "agent.toml"}),
    }
}
