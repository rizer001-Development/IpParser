//! Three-stage scan pipeline shared by the Telnet and Minecraft scanners.
//!
//! Port of the Java `AbstractScanner` / `PortScanner` / `McProbeScanner`.
//! THREE SEPARATE thread groups run simultaneously at maximum speed:
//!  - GENERATORS (CPU threads): expand the regex/CIDR octet lists into
//!    IP:port targets and push them into a bounded task queue (blocking send =
//!    natural backpressure - NO busy waiting and NO artificial sleeps).
//!  - NETWORK WORKERS (network threads): pull targets and run the probe
//!    network call (blocking I/O). Their count is independent of the CPU
//!    thread count and can go up to 1024.
//!  - EVENT FORWARDER (CPU thread): counts scanned targets, applies progress
//!    throttling and forwards everything as [`ScanEvent`]s to the UI thread -
//!    the Rust equivalent of the Java CPU-parser pool + listener marshalling.
//!
//! The stages are decoupled by bounded queues, so generation never blocks
//! probing and results never pile up unbounded. Memory stays constant no
//! matter how large the range is. Iteration order is IP-major: all ports of
//! one IP first, then the next IP.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender};

use crate::ip_pattern::Block;
use crate::mc_probe;
use crate::perf;

const QUEUE_CAPACITY: usize = 8192;

/// Outcome of a single TCP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortResult {
    Open,
    Closed,
    Timeout,
    Error,
}

/// A raw probe result handed to the UI.
#[derive(Debug, Clone)]
pub enum Raw {
    Telnet { result: PortResult, time_ms: u64 },
    Mc(mc_probe::McResult),
}

/// Events consumed by the UI thread.
#[derive(Debug)]
pub enum ScanEvent {
    Result(String, u16, Raw),
    Progress(u64, u64),
    Finished,
}

/// Scan mode selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Telnet,
    Minecraft,
}

struct Shared {
    running: AtomicBool,
}

/// Handle over a running scan; the UI polls `events`.
pub struct ScanHandle {
    shared: Arc<Shared>,
    pub events: Receiver<ScanEvent>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl ScanHandle {
    /// Stops the running scan. Safe to call at any time and from any thread.
    /// The event stream still delivers `Finished` afterwards.
    pub fn stop(&self) {
        self.shared.running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::SeqCst)
    }

    /// Waits for all worker threads to exit (called after `Finished`).
    pub fn join(&mut self) {
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }
}

fn active_count(v: usize, cap: u64) -> usize {
    (v as u64).clamp(1, cap.max(1)) as usize
}

/// The network probe performed by the workers.
#[derive(Debug, Clone, Copy)]
enum ProbeMode {
    Telnet,
    Minecraft,
}

fn probe(mode: ProbeMode, ip: &str, port: u16, timeout_ms: u64) -> Raw {
    match mode {
        ProbeMode::Telnet => {
            let start = Instant::now();
            let outcome = tcp_probe(ip, port, timeout_ms);
            let elapsed = start.elapsed().as_millis() as u64;
            perf::add_sent(perf::CONNECT_ESTIMATE);
            perf::add_recv(perf::CONNECT_ESTIMATE);
            Raw::Telnet {
                result: outcome,
                time_ms: elapsed,
            }
        }
        ProbeMode::Minecraft => Raw::Mc(mc_probe::ping(ip, port, timeout_ms)),
    }
}

/// Opens the socket and classifies the outcome (Java PortScanner.probe).
fn tcp_probe(ip: &str, port: u16, timeout_ms: u64) -> PortResult {
    let addr = match (ip, port).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return PortResult::Error,
        },
        Err(e) => return classify_connect_error(&e.to_string()),
    };
    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(_) => PortResult::Open,
        Err(e) => classify_connect_error(&e.to_string()),
    }
}

fn classify_connect_error(msg: &str) -> PortResult {
    let m = msg.to_lowercase();
    if m.contains("timeout") || m.contains("timed out") {
        PortResult::Timeout
    } else if m.contains("refused") || m.contains("reset") || m.contains("unreachable") {
        PortResult::Closed
    } else {
        PortResult::Error
    }
}

/// Starts a scan over the given address blocks. Returns immediately; all work
/// runs in background threads. The UI drains `ScanHandle::events` (non-blocking).
#[allow(clippy::too_many_arguments)]
pub fn start_scan(
    blocks: Vec<Block>,
    start_port: u16,
    end_port: u16,
    timeout_ms: u64,
    gen_threads: usize,
    net_threads: usize,
    mode: ScanMode,
) -> ScanHandle {
    let shared = Arc::new(Shared {
        running: AtomicBool::new(true),
    });
    let (event_tx, event_rx): (Sender<ScanEvent>, Receiver<ScanEvent>) = bounded(QUEUE_CAPACITY);

    let total_ips: u64 = blocks.iter().map(|b| block_size(b)).sum();
    let total_targets = total_ips.saturating_mul((end_port - start_port + 1) as u64);
    if blocks.is_empty() || total_targets == 0 {
        // Degenerate scan: report finished right away.
        let _ = event_tx.send(ScanEvent::Finished);
        return ScanHandle {
            shared,
            events: event_rx,
            workers: Vec::new(),
        };
    }

    let probe_mode = match mode {
        ScanMode::Telnet => ProbeMode::Telnet,
        ScanMode::Minecraft => ProbeMode::Minecraft,
    };

    let gen_count = active_count(gen_threads, total_ips);
    let net_count = active_count(net_threads, total_targets);

    let (task_tx, task_rx): (Sender<Target>, Receiver<Target>) = bounded(QUEUE_CAPACITY);
    let (res_tx, res_rx): (Sender<RawResult>, Receiver<RawResult>) = bounded(QUEUE_CAPACITY);

    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();

    // ---- Generator stage (CPU) ----
    for t in 0..gen_count {
        let blocks = blocks.clone();
        let tx = task_tx.clone();
        let shared = Arc::clone(&shared);
        let from = total_ips * t as u64 / gen_count as u64;
        let to = total_ips * (t as u64 + 1) / gen_count as u64;
        workers.push(std::thread::spawn(move || {
            generate_range(&blocks, from, to, start_port, end_port, &shared, &tx);
        }));
    }
    drop(task_tx); // all senders now live in generator threads

    // ---- Network stage (blocking I/O) ----
    for _ in 0..net_count {
        let rx = task_rx.clone();
        let tx = res_tx.clone();
        let shared = Arc::clone(&shared);
        workers.push(std::thread::spawn(move || {
            network_loop(&shared, &rx, &tx, probe_mode, timeout_ms);
        }));
    }
    drop(res_tx); // all senders now live in network threads

    // ---- Event forwarder (CPU): results + progress + finished ----
    {
        let shared = Arc::clone(&shared);
        workers.push(std::thread::spawn(move || {
            let mut count: u64 = 0;
            let mut last_posted: u64 = 0;
            let mut stop_seen = false;
            loop {
                if !stop_seen && !shared.running.load(Ordering::SeqCst) {
                    // Stop observed once; keep draining in-flight results
                    // below until the network stage disconnects.
                    stop_seen = true;
                }
                match res_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(rr) => {
                        count += 1;
                        if event_tx
                            .send(ScanEvent::Result(rr.ip, rr.port, rr.raw))
                            .is_err()
                        {
                            return; // UI closed the channel
                        }
                        // Progress throttling like the Java frame: post at
                        // most ~total/500 steps (plus the final one).
                        if count == total_targets
                            || count - last_posted >= (total_targets / 500).max(1)
                        {
                            last_posted = count;
                            if event_tx
                                .send(ScanEvent::Progress(count, total_targets))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        // All network workers exited and the queue is drained.
                        let _ = event_tx.send(ScanEvent::Progress(count, total_targets));
                        let _ = event_tx.send(ScanEvent::Finished);
                        return;
                    }
                }
            }
        }));
    }

    ScanHandle {
        shared,
        events: event_rx,
        workers,
    }
}

/// One CPU generator: walks IPs [from, to) (IP-major: all ports per IP), pushes targets.
fn generate_range(
    blocks: &[Block],
    from: u64,
    to: u64,
    start_port: u16,
    end_port: u16,
    shared: &Shared,
    tx: &Sender<Target>,
) {
    for idx in from..to {
        if !shared.running.load(Ordering::SeqCst) {
            return;
        }
        let Some(oct) = decode_index(blocks, idx) else { continue };
        let ip = format!("{}.{}.{}.{}", oct[0], oct[1], oct[2], oct[3]);
        for port in start_port..=end_port {
            if !shared.running.load(Ordering::SeqCst) {
                return;
            }
            if tx.send(Target { ip: ip.clone(), port }).is_err() {
                return; // receivers gone: stop requested
            }
        }
    }
}

/// One network worker: runs the probe, hands raw results to the forwarder.
fn network_loop(
    shared: &Shared,
    rx: &Receiver<Target>,
    tx: &Sender<RawResult>,
    mode: ProbeMode,
    timeout_ms: u64,
) {
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(t) => {
                if !shared.running.load(Ordering::SeqCst) {
                    return; // stopped: drop the target
                }
                let raw = probe(mode, &t.ip, t.port, timeout_ms);
                if !shared.running.load(Ordering::SeqCst) {
                    return; // stopped: drop the result
                }
                if tx
                    .send(RawResult {
                        ip: t.ip,
                        port: t.port,
                        raw,
                    })
                    .is_err()
                {
                    return; // forwarder gone
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !shared.running.load(Ordering::SeqCst) {
                    return;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // All generators finished and the queue is drained: we're done.
                return;
            }
        }
    }
}

struct Target {
    ip: String,
    port: u16,
}

struct RawResult {
    ip: String,
    port: u16,
    raw: Raw,
}

/// Decodes a flat IP index (0..totalIps-1) across multiple address blocks
/// into 4 octet values. Blocks are concatenated in order.
fn decode_index(blocks: &[Block], mut idx: u64) -> Option<[i32; 4]> {
    for octets in blocks {
        let size = block_size(octets);
        if idx < size {
            let mut rem = idx;
            let mut oct = [0i32; 4];
            oct[3] = octets[3][(rem % octets[3].len() as u64) as usize];
            rem /= octets[3].len() as u64;
            oct[2] = octets[2][(rem % octets[2].len() as u64) as usize];
            rem /= octets[2].len() as u64;
            oct[1] = octets[1][(rem % octets[1].len() as u64) as usize];
            rem /= octets[1].len() as u64;
            oct[0] = octets[0][rem as usize];
            return Some(oct);
        }
        idx -= size;
    }
    None
}

fn block_size(octets: &Block) -> u64 {
    let mut total: u64 = 1;
    for list in octets {
        total *= list.len() as u64;
    }
    total
}

/// Parses port specification.
/// Accepts: "2000" (single) or "2000-2010" (range, inclusive).
/// Returns [start_port, end_port] inclusive.
pub fn parse_ports(port_spec: &str) -> [u16; 2] {
    let s = port_spec.trim();
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (
                parts[0].trim().parse::<i64>(),
                parts[1].trim().parse::<i64>(),
            ) {
                let (start, end) = if start > end { (end, start) } else { (start, end) };
                let start = start.clamp(1, 65535) as u16;
                let end = end.clamp(1, 65535) as u16;
                return [start, end];
            }
        }
    }
    match s.parse::<i64>() {
        Ok(port) => {
            let p = port.clamp(1, 65535) as u16;
            [p, p]
        }
        Err(_) => [1, 1], // fallback
    }
}
