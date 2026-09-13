//! Resolves the application's own home directory ("portable" root).
//!
//! The program NEVER writes to the current working directory. All persistent
//! artifacts land inside its own home:
//!   home/data/settings.db   — SQLite database with the user's settings
//!   home/logs/...           — application and scan-result log files
//!
//! Resolution order:
//!   1. Environment variable `IPPARSER_HOME` (set by launch scripts / tests).
//!   2. The directory containing the running executable.
//!   3. Fallback to the current working directory.

use std::path::PathBuf;
use std::sync::OnceLock;

static HOME: OnceLock<PathBuf> = OnceLock::new();

fn home() -> &'static PathBuf {
    HOME.get_or_init(|| {
        if let Ok(prop) = std::env::var("IPPARSER_HOME") {
            let p = PathBuf::from(prop);
            if !p.as_os_str().is_empty() {
                return p;
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                return dir.to_path_buf();
            }
        }
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    })
}

/// The application home directory (portable root).
pub fn home_dir() -> PathBuf {
    home().to_path_buf()
}

/// Directory for persistent data (SQLite DB). Created on demand.
pub fn data_dir() -> PathBuf {
    ensure_dir(home().join("data"))
}

/// Directory for log files. Created on demand.
pub fn logs_dir() -> PathBuf {
    ensure_dir(home().join("logs"))
}

/// Path of the SQLite settings database.
pub fn db_file() -> PathBuf {
    data_dir().join("settings.db")
}

fn ensure_dir(dir: PathBuf) -> PathBuf {
    let _ = std::fs::create_dir_all(&dir); // best effort
    dir
}
