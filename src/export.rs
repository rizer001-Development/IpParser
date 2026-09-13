//! Pure content builder for the results export file (port of Java `Export`),
//! so the wording and formatting can be unit tested.

use std::collections::HashMap;

use crate::ip_utils;
use crate::mc_probe::McResult;

/// All inputs needed to render an export.
pub struct ExportParams {
    pub mc_mode: bool,
    pub syntax_type: String,
    pub syntax_mode: String,
    pub use_cidr: bool,
    pub pattern_desc: String,
    pub port_spec: String,
    pub external: bool,
    pub external_count: u64,
    pub open_results: Vec<String>,
    pub mc_results: HashMap<String, McResult>,
}

/// Builds the export file content.
pub fn build(p: &ExportParams) -> String {
    let mut sb = String::new();
    sb.push_str("IP Parser - scan results\n");
    sb.push_str(&format!("Time: {}\n", crate::timefmt::now_export_ts()));
    sb.push_str(&format!(
        "Mode: {}\n",
        if p.mc_mode { "Minecraft (mcprobe)" } else { "Telnet (TCP)" }
    ));
    sb.push_str(&format!(
        "Syntax (type={}, input={}, CIDR={}): {}\n",
        p.syntax_type,
        p.syntax_mode.to_lowercase(),
        if p.use_cidr { "on" } else { "off" },
        p.pattern_desc
    ));
    sb.push_str(&format!("Port: {}\n", p.port_spec));
    sb.push_str(&format!("Open ports: {}\n", p.open_results.len()));
    if p.external {
        sb.push_str(&format!(
            "Reachable from outside (public IP): {}\n",
            p.external_count
        ));
    }
    sb.push_str("------------------------------------------\n");
    for res in &p.open_results {
        let mut line = res.clone();
        if p.mc_mode {
            if let Some(probe) = p.mc_results.get(res) {
                let version = if probe.version.is_empty() { "?" } else { &probe.version };
                line = format!(
                    "{}  |  version: {}{}  |  players: {}/{}{}",
                    res,
                    version,
                    if probe.brand.is_empty() {
                        String::new()
                    } else {
                        format!("  |  brand: {}", probe.brand)
                    },
                    probe.online,
                    probe.max,
                    if probe.motd.is_empty() {
                        String::new()
                    } else {
                        format!("  |  {}", probe.motd)
                    }
                );
            }
        }
        if p.external {
            let ip = if res.contains(':') {
                let pos = res.rfind(':').unwrap();
                &res[..pos]
            } else {
                res.as_str()
            };
            line = format!("{}  —  {}", line, ip_utils::external_status(ip, true, false));
        }
        sb.push_str(&line);
        sb.push('\n');
    }
    sb
}
