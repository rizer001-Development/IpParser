//! Application version, taken from the Cargo build (single source of truth for display).

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
