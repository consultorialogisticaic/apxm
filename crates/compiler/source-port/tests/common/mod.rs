//! Shared fixtures for the source-port conformance tests.
//!
//! The tests drive the real port against the real authoring frontends in this
//! checkout: capturing typed intent from Python source runs the Python frontend
//! and capturing it from TypeScript source runs the TypeScript frontend, so a
//! test that stubbed either one would prove nothing about the boundary.
//!
//! This module holds only what every test file needs. Program fixtures live
//! beside the tests that submit them, so each fixture stays readable next to the
//! property it establishes.

use std::path::{Path, PathBuf};

use apxm_source_port::{Frontend, FrontendDrivers, FrontendRoots};

/// The name every fixture program is authored and captured under.
pub const ENTRYPOINT: &str = "Reviewer";

/// Both selectors, so every property is asserted against each.
pub const FRONTENDS: [Frontend; 2] = [Frontend::Python, Frontend::Typescript];

/// The repository root, resolved from this crate's manifest directory.
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("the source-port crate sits three levels under the repository root")
        .to_path_buf()
}

/// The authoring frontend package roots in this checkout.
pub fn roots() -> FrontendRoots {
    let root = repository_root();
    FrontendRoots::new(
        root.join("crates/compiler/frontend/python"),
        root.join("crates/compiler/frontend/typescript"),
    )
}

/// The exact interpreter drivers supplied by this test composition root.
///
/// The port receives these paths as data and never searches `PATH`; test
/// fixtures resolve the Dekk-managed toolchain once at their own boundary.
/// A Nix development shell provides the same pinned drivers through `PATH`
/// rather than materialising `.dekk/env`, so the shell exports are accepted
/// as the local composition binding.
pub fn drivers() -> FrontendDrivers {
    let root = repository_root();
    let python = std::env::var_os("APXM_PYTHON_DRIVER")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".dekk/env/bin/python"));
    let node = std::env::var_os("APXM_TYPESCRIPT_DRIVER")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".dekk/env/bin/node"));
    FrontendDrivers::new(python, node)
}

/// Whether one authoring frontend can capture here. Each frontend's compiler
/// bridge is a build product, so a checkout that has not built it cannot
/// capture, and a capture assertion there would be asserting the build rather
/// than the port. Unavailability and request validation are asserted by tests
/// that need no build product, so those always run.
pub fn frontend_present(frontend: Frontend) -> bool {
    let root = roots().root(frontend).to_path_buf();
    let driver = drivers().driver(frontend).to_path_buf();
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
