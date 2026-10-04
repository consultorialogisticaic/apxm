//! User-facing Dekk command hints emitted by the APXM CLI.
//!
//! Keeping them centralized avoids reintroducing command-string literals at
//! call sites. A hint reachable only from a feature-gated command path carries
//! the same `cfg` as that path, so every hint here has a live caller.

pub const APXM_ENV_HINT: &str = "dekk agents ...";
