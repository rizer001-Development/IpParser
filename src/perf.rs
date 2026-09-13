//! Real-time performance monitor for the parser process:
//!   - bytes sent/received by this app (instrumented at the socket level)
//!   - process CPU load
//!   - process RAM usage
//!
//! Port of the Java `PerfMonitor`: process-wide counters plus CPU/RAM via
//! `sysinfo`. Implemented as a process-wide singleton guarded by a mutex.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use sysinfo::System;

/// Per-connection TCP handshake estimate (SYN / SYN-ACK+ACK / close),
/// used by the telnet scanner where no application payload is exchanged.
pub const CONNECT_ESTIMATE: u64 = 66;

static SENT: AtomicU64 = AtomicU64::new(0);
static RECV: AtomicU64 = AtomicU64::new(0);
static SENT_RESET: AtomicBool = AtomicBool::new(false);
static RECV_RESET: AtomicBool = AtomicBool::new(false);

// Rate state (updated by tick_rates).
static SENT_RATE: AtomicU64 = AtomicU64::new(0);
static RECV_RATE: AtomicU64 = AtomicU64::new(0);
static CPU_LOAD_PCT: AtomicI64 = AtomicI64::new(-1); // -1 = unavailable
static RAM_USED_MB: AtomicU64 = AtomicU64::new(0);

struct SysState {
    sys: System,
    last_tick: Instant,
    last_sent: u64,
    last_recv: u64,
}

static SYS: Mutex<Option<SysState>> = Mutex::new(None);

fn with_sys<R>(f: impl FnOnce(&mut SysState) -> R) -> Option<R> {
    let mut guard = SYS.lock().ok()?;
    let state = guard.get_or_insert_with(|| {
        let mut sys = System::new_all();
        // First refresh primes the CPU-usage baseline.
        sys.refresh_all();
        SysState {
            sys,
            last_tick: Instant::now(),
            last_sent: 0,
            last_recv: 0,
        }
    });
    Some(f(state))
}

pub fn add_sent(bytes: u64) {
    if bytes > 0 {
        SENT.fetch_add(bytes, Ordering::Relaxed);
    }
}

pub fn add_recv(bytes: u64) {
    if bytes > 0 {
        RECV.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Called at the start of each scan: resets traffic counters.
pub fn reset() {
    SENT.store(0, Ordering::Relaxed);
    RECV.store(0, Ordering::Relaxed);
    SENT_RESET.store(true, Ordering::Relaxed);
    RECV_RESET.store(true, Ordering::Relaxed);
    SENT_RATE.store(0, Ordering::Relaxed);
    RECV_RATE.store(0, Ordering::Relaxed);
}

/// Call once per second (from the UI): refreshes CPU/RAM and updates B/s rates.
pub fn tick_rates() {
    let now = Instant::now();
    let sent = SENT.load(Ordering::Relaxed);
    let recv = RECV.load(Ordering::Relaxed);

    with_sys(|st| {
        if SENT_RESET.swap(false, Ordering::Relaxed) {
            st.last_sent = sent;
        }
        if RECV_RESET.swap(false, Ordering::Relaxed) {
            st.last_recv = recv;
        }
        let dt_ms = now.duration_since(st.last_tick).as_millis() as u64;
        if dt_ms > 0 {
            let ds = sent.saturating_sub(st.last_sent);
            let dr = recv.saturating_sub(st.last_recv);
            SENT_RATE.store(ds * 1000 / dt_ms, Ordering::Relaxed);
            RECV_RATE.store(dr * 1000 / dt_ms, Ordering::Relaxed);
        }
        st.last_tick = now;
        st.last_sent = sent;
        st.last_recv = recv;

        st.sys.refresh_all();
        if let Ok(pid) = sysinfo::get_current_pid() {
            if let Some(proc) = st.sys.process(pid) {
                CPU_LOAD_PCT.store(proc.cpu_usage().round() as i64, Ordering::Relaxed);
                RAM_USED_MB.store(proc.memory() / (1024 * 1024), Ordering::Relaxed);
            }
        }
    });
}

pub fn get_total_sent() -> u64 {
    SENT.load(Ordering::Relaxed)
}

pub fn get_total_recv() -> u64 {
    RECV.load(Ordering::Relaxed)
}

pub fn get_sent_rate() -> u64 {
    SENT_RATE.load(Ordering::Relaxed)
}

pub fn get_recv_rate() -> u64 {
    RECV_RATE.load(Ordering::Relaxed)
}

/// Process CPU load in percent 0..=100, or -1 if unavailable.
pub fn get_process_cpu_load() -> i64 {
    CPU_LOAD_PCT.load(Ordering::Relaxed)
}

/// Process RAM currently used, in MB.
pub fn get_ram_used_mb() -> u64 {
    RAM_USED_MB.load(Ordering::Relaxed)
}
