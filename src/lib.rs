//! IP Parser - Rust port of the Java application.
//!
//! Layer map (old Java package -> this crate):
//!   dev.ipparser.core      -> `app_paths`, `ip_utils`, `perf`, `version`, `timefmt`
//!   dev.ipparser.pattern   -> `syntax_conv`, `ip_pattern`
//!   dev.ipparser.probe     -> `mc_probe`
//!   dev.ipparser.scanner   -> `scanner`
//!   dev.ipparser.storage   -> `storage`
//!   dev.ipparser.gui       -> `filters`, `export`, `log_config`, `theme`
//!                            + the `main` binary (egui)

pub mod app_paths;
pub mod export;
pub mod filters;
pub mod ip_pattern;
pub mod ip_utils;
pub mod log_config;
pub mod mc_probe;
pub mod perf;
pub mod scanner;
pub mod storage;
pub mod syntax_conv;
pub mod theme;
pub mod timefmt;
pub mod version;
