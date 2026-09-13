//! Helpers for "Status 2": determine whether an IP is public ("white"),
//! whether it belongs to the local LAN, and the human-readable external verdict.
//! Pure local logic — no external services required.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

/// Cached local IPv4 addresses (refreshed at most every 10 seconds).
static LOCAL_IPS: Mutex<Option<(std::time::Instant, Vec<Ipv4Addr>)>> = Mutex::new(None);

/// Returns true if the IP is public ("white") - potentially reachable from the Internet.
/// Private/reserved ranges return false: RFC1918, loopback, link-local, CGNAT 100.64/10,
/// TEST-NET ranges, multicast, reserved.
pub fn is_public(ip: &str) -> bool {
    let Some(o) = octets(ip) else { return false };

    // anyLocal (0.0.0.0), loopback 127/8, link-local 169.254/16, site-local RFC1918,
    // multicast 224/4
    let is_any = o == [0, 0, 0, 0];
    let is_loopback = o[0] == 127;
    let is_link_local = o[0] == 169 && o[1] == 254;
    let is_site_local = o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168);
    let is_multicast = o[0] >= 224 && o[0] <= 239;
    if is_any || is_loopback || is_link_local || is_site_local || is_multicast {
        return false;
    }

    let (a, b) = (o[0], o[1]);
    // CGNAT 100.64.0.0/10
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    // 0.0.0.0/8
    if a == 0 {
        return false;
    }
    // 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1), 192.88.99.0/24 (6to4 relay)
    if a == 192 && (b == 0 || b == 88) {
        return false;
    }
    // 198.18.0.0/15 (benchmarking), 198.51.100.0/24 (TEST-NET-2)
    if a == 198 && (b == 18 || b == 19 || b == 51) {
        return false;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if a == 203 && b == 0 {
        return false;
    }
    // multicast 224/4 and reserved 240/4, broadcast
    a < 224
}

/// Returns true if the IP belongs to the same /24 LAN as this machine.
pub fn is_same_lan(ip: &str) -> bool {
    let Some(o) = octets(ip) else { return false };
    for local in local_ipv4s() {
        if local.octets()[0] == o[0] && local.octets()[1] == o[1] && local.octets()[2] == o[2] {
            return true;
        }
    }
    false
}

/// Human-readable "Status 2" verdict for an IP:port based on the local scan result.
pub fn external_status(ip: &str, open: bool, timeout: bool) -> String {
    if is_same_lan(ip) {
        return "адрес локальной сети — извне недоступен".to_string();
    }
    if !is_public(ip) {
        return "серый IP (приватный) — извне недоступен".to_string();
    }
    if open {
        return "белый IP — порт доступен извне (проброшен)".to_string();
    }
    if timeout {
        return "белый IP — таймаут, доступность извне не определена".to_string();
    }
    "белый IP — порт закрыт, извне недоступен".to_string()
}

fn local_ipv4s() -> Vec<Ipv4Addr> {
    if let Ok(guard) = LOCAL_IPS.lock() {
        if let Some((at, ips)) = guard.as_ref() {
            if at.elapsed() < std::time::Duration::from_secs(10) {
                return ips.clone();
            }
        }
    }
    let ips = enumerate_local_ipv4s();
    if let Ok(mut guard) = LOCAL_IPS.lock() {
        *guard = Some((std::time::Instant::now(), ips.clone()));
    }
    ips
}

#[cfg(target_os = "windows")]
fn enumerate_local_ipv4s() -> Vec<Ipv4Addr> {
    // Parses `Get-NetIPAddress -AddressFamily IPv4` style output via netsh:
    // `netsh interface ipv4 show addresses` is locale-independent enough for
    // our purpose when filtered for "IP Address"-like lines; instead we use
    // the WMI-free approach: connect a UDP socket to a public address and read
    // the local endpoint, plus fall back to hostname resolution.
    let mut out = Vec::new();
    // Primary: UDP connect trick (gives the default-route interface address).
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = s.local_addr() {
                if let IpAddr::V4(v4) = addr.ip() {
                    out.push(v4);
                }
            }
        }
    }
    // Secondary: resolve the local host name to its addresses.
    if let Ok(name) = hostname() {
        use std::net::ToSocketAddrs;
        if let Ok(addrs) = (name.as_str(), 0u16).to_socket_addrs() {
            for a in addrs {
                if let IpAddr::V4(v4) = a.ip() {
                    if !v4.is_loopback() && !out.contains(&v4) {
                        out.push(v4);
                    }
                }
            }
        }
    }
    out
}

#[cfg(not(target_os = "windows"))]
fn enumerate_local_ipv4s() -> Vec<Ipv4Addr> {
    use std::net::ToSocketAddrs;
    let mut out = Vec::new();
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = s.local_addr() {
                if let IpAddr::V4(v4) = addr {
                    out.push(v4);
                }
            }
        }
    }
    if let Ok(name) = hostname() {
        if let Ok(addrs) = (name.as_str(), 0u16).to_socket_addrs() {
            for a in addrs {
                if let IpAddr::V4(v4) = a.ip() {
                    if !v4.is_loopback() && !out.contains(&v4) {
                        out.push(v4);
                    }
                }
            }
        }
    }
    out
}

fn hostname() -> std::io::Result<String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "no hostname"))
}

fn octets(ip: &str) -> Option<[u8; 4]> {
    let p: Vec<&str> = ip.split('.').collect();
    if p.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, part) in p.iter().enumerate() {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        // Java's Integer.parseInt accepts leading '+'/'-' but IPs never have them.
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        o[i] = v as u8;
    }
    Some(o)
}
