//! Port of the Java `storage` package: SQLite-backed key/value settings store
//! (`AppDb`) plus the thread-safe file logger (`FileLog`).
//!
//! The database lives at `home/data/settings.db` so every portable copy keeps
//! its own configuration. All access is guarded by a mutex.

use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::app_paths;
use crate::version::VERSION;

struct DbState {
    conn: Option<Connection>,
}

static DB: Mutex<DbState> = Mutex::new(DbState { conn: None });

fn with_conn<T>(f: impl FnOnce(&Connection) -> T) -> Option<T> {
    let mut guard = DB.lock().ok()?;
    if guard.conn.is_none() {
        let conn = Connection::open(app_paths::db_file()).ok()?;
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        );
        guard.conn = Some(conn);
    }
    guard.conn.as_ref().map(f)
}

/// Returns the stored value for `key` (or None when absent).
pub fn get_opt(key: &str) -> Option<String> {
    with_conn(|c| {
        c.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .ok()
    })
    .flatten()
}

/// Returns the stored value for `key` or `def` when absent.
pub fn get(key: &str, def: &str) -> String {
    with_conn(|c| {
        c.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .ok()
    })
    .flatten()
    .unwrap_or_else(|| def.to_string())
}

/// Convenience: boolean read.
pub fn get_bool(key: &str, def: bool) -> bool {
    match get(key, "") {
        v if v.is_empty() => def,
        v => v == "1" || v.eq_ignore_ascii_case("true"),
    }
}

/// Convenience: int read with a fallback.
pub fn get_int(key: &str, def: i64) -> i64 {
    match get(key, "") {
        v if v.is_empty() => def,
        v => v.parse().unwrap_or(def),
    }
}

/// Stores (or updates) a value. Returns true on success.
pub fn set(key: &str, value: &str) -> bool {
    with_conn(|c| {
        c.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            [key, value],
        )
        .is_ok()
    })
    .unwrap_or(false)
}

/// Convenience: boolean write.
pub fn set_bool(key: &str, value: bool) -> bool {
    set(key, if value { "1" } else { "0" })
}

/// Convenience: int write.
pub fn set_int(key: &str, value: i64) -> bool {
    set(key, &value.to_string())
}

/// Closes the underlying connection (releases the lock on the db file).
pub fn close() {
    if let Ok(mut guard) = DB.lock() {
        guard.conn = None;
    }
}

// ================= FileLog =================

const MAX_SCAN_LINES: usize = 200_000; // guard against unbounded growth

struct LogState {
    app_path: Option<PathBuf>,
    scan_path: Option<PathBuf>,
    scan_writer: Option<std::fs::File>,
    scan_line_count: usize,
}

static LOG: Mutex<LogState> = Mutex::new(LogState {
    app_path: None,
    scan_path: None,
    scan_writer: None,
    scan_line_count: 0,
});

fn write_app_line(line: &str) {
    let Ok(guard) = LOG.lock() else { return };
    let Some(app_path) = guard.app_path.clone() else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&app_path) {
        use std::io::Write;
        let _ = writeln!(f, "{}", line);
    }
}

/// Writes an application-level line to ipparser-app.log.
pub fn log_app(level: &str, msg: &str) {
    let line = format!("{}  [{}]  {}", crate::timefmt::now_full(), level, msg);
    write_app_line(&line);
}

pub fn info(msg: &str) {
    log_app("INFO", msg);
}
pub fn warn(msg: &str) {
    log_app("WARN", msg);
}
pub fn error(msg: &str) {
    log_app("ERROR", msg);
}

/// Initializes the app log (called once at startup).
pub fn init_app_log() {
    let path = app_paths::logs_dir().join("ipparser-app.log");
    if let Ok(mut guard) = LOG.lock() {
        guard.app_path = Some(path);
    }
    log_app("INFO", &format!("==== IP Parser v{} starting ====", VERSION));
}

/// Starts a new dedicated scan log file. Returns its path (None on error).
pub fn begin_scan() -> Option<PathBuf> {
    let name = format!("scan-{}.log", crate::timefmt::now_filename_ts());
    let path = app_paths::logs_dir().join(name);
    let file = std::fs::File::create(&path).ok()?;
    if let Ok(mut guard) = LOG.lock() {
        guard.scan_path = Some(path.clone());
        guard.scan_writer = Some(file);
        guard.scan_line_count = 0;
    }
    Some(path)
}

/// Path of the current scan log file, if any.
pub fn current_scan_path() -> Option<PathBuf> {
    LOG.lock().ok()?.scan_path.clone()
}

/// Writes a line to the current scan log (with auto-truncation guard).
pub fn scan(line: &str) {
    let Ok(mut guard) = LOG.lock() else { return };
    if guard.scan_writer.is_none() || guard.scan_line_count >= MAX_SCAN_LINES {
        return;
    }
    if let Some(f) = guard.scan_writer.as_mut() {
        use std::io::Write;
        let _ = writeln!(f, "{}", line);
        let _ = f.flush();
        guard.scan_line_count += 1;
    }
}

/// Writes the same line to both the scan log and the application log.
pub fn both(level: &str, line: &str) {
    scan(line);
    log_app(level, line);
}

/// Writes the scan header describing a run.
pub fn scan_mode(mode: &str, type_: &str, input_mode: &str, cidr: bool, total_ips: u64) {
    scan("=== Scan started ===");
    scan(&format!(
        "Mode: {}   type={} input={} CIDR={}   total IPs={}",
        mode,
        type_,
        input_mode,
        if cidr { "on" } else { "off" },
        total_ips
    ));
}

/// Flushes and closes the current scan log.
pub fn close_scan() {
    if let Ok(mut guard) = LOG.lock() {
        guard.scan_writer = None;
    }
}
