//! Minecraft Server List Ping protocol. Connects to a Minecraft server
//! and retrieves real server info: MOTD, version, online/max players, latency.
//! Pure Rust — no external JSON library required.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::perf;

/// Result of a Minecraft ping.
#[derive(Debug, Clone, Default)]
pub struct McResult {
    pub success: bool,
    pub motd: String,
    pub version: String,
    pub protocol: i64,
    pub online: i64,
    pub max: i64,
    pub has_favicon: bool,
    pub latency_ms: u64,
    pub error: String,
    pub brand: String,
    pub players: Vec<String>,
}

/// Pings a Minecraft server.
pub fn ping(host: &str, port: u16, timeout_ms: u64) -> McResult {
    let mut r = McResult::default();
    let start = std::time::Instant::now();
    let socket_addrs = match (host, port).to_socket_addrs() {
        Ok(it) => it.collect::<Vec<_>>(),
        Err(e) => {
            r.error = format!("resolve: {}", e);
            return r;
        }
    };
    let mut stream: Option<TcpStream> = None;
    for addr in &socket_addrs {
        if let Ok(s) = TcpStream::connect_timeout(addr, Duration::from_millis(timeout_ms)) {
            stream = Some(s);
            break;
        }
    }
    let Some(mut socket) = stream else {
        r.latency_ms = start.elapsed().as_millis() as u64;
        r.error = "соединение не удалось".to_string();
        return r;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = socket.set_nodelay(true);

    let res = run_ping(&mut socket, host, port, &mut r);
    r.latency_ms = start.elapsed().as_millis() as u64;
    if let Err(e) = res {
        let msg = format!("{}", e).to_lowercase();
        if msg.contains("timed out") || msg.contains("timeout") {
            r.error = "таймаут".to_string();
        } else {
            r.error = msg;
        }
    }
    r
}

fn run_ping(socket: &mut TcpStream, host: &str, port: u16, r: &mut McResult) -> std::io::Result<()> {
    // ---- Handshake packet: id 0x00, protocol -1, host, port, next state 1 ----
    let mut payload: Vec<u8> = Vec::new();
    write_varint(&mut payload, 0x00); // packet id
    write_varint_signed(&mut payload, -1); // protocol version (legacy client = -1)
    let host_bytes = host.as_bytes();
    write_varint(&mut payload, host_bytes.len() as u32);
    payload.extend_from_slice(host_bytes);
    payload.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut payload, 1); // next state: status

    let mut handshake: Vec<u8> = Vec::new();
    write_varint(&mut handshake, payload.len() as u32);
    handshake.extend_from_slice(&payload);
    socket.write_all(&handshake)?;
    socket.flush()?;
    perf::add_sent(handshake.len() as u64);

    // ---- Status request: packet id 0x00 ----
    let mut req: Vec<u8> = Vec::new();
    write_varint(&mut req, 1); // packet length
    write_varint(&mut req, 0x00); // packet id
    socket.write_all(&req)?;
    socket.flush()?;
    perf::add_sent(req.len() as u64);

    // ---- Read response ----
    let packet_len = read_varint(socket)? as usize;
    if packet_len > 2_097_151 {
        r.error = "некорректная длина ответа".to_string();
        return Ok(());
    }
    let mut response = vec![0u8; packet_len];
    socket.read_exact(&mut response)?;
    perf::add_recv(packet_len as u64 + varint_len(packet_len as u32) as u64);

    let mut pos = 0usize;
    let packet_id = read_varint_from(&response, &mut pos).unwrap_or(-1i64);
    if packet_id != 0x00 {
        r.error = format!("неожиданный пакет (id {})", packet_id);
        return Ok(());
    }
    let json_len = read_varint_from(&response, &mut pos).unwrap_or(0) as usize;
    if json_len > 2_000_000 || pos + json_len > response.len() {
        r.error = "некорректная длина ответа".to_string();
        return Ok(());
    }
    let json = String::from_utf8_lossy(&response[pos..pos + json_len]).to_string();

    r.success = true;
    parse_json(&json, r);
    Ok(())
}

/// Simple manual extraction of known fields from the status JSON.
/// Uses index-based scanning (no regex) so huge base64 favicons cannot
/// blow the stack. No JSON library required.
fn parse_json(json: &str, r: &mut McResult) {
    if let Some(version) = extract_object_string(json, "version", "name") {
        r.version = unescape(&version);
    }
    r.protocol = extract_int(json, "protocol");
    r.online = extract_int(json, "online");
    r.max = extract_int(json, "max");

    // MOTD: "description" can be a plain string, {"text":"..."} or
    // {"extra":[{"text":"..."},...],"text":""}
    if let Some(motd) = extract_description(json) {
        if !motd.is_empty() {
            r.motd = strip_color_codes(&unescape(&motd));
        }
    }

    r.has_favicon = json.contains("\"favicon\"");

    // brand: some servers report it as a top-level "brand":"Leaf" string
    if let Some(brand) = extract_top_level_string(json, "brand") {
        if !brand.is_empty() {
            r.brand = unescape(&brand);
        }
    }

    // player sample: "players":{"max":..,"online":..,"sample":[{"name":"..","id":".."}]}
    r.players = extract_player_names(json);

    // Many servers report the version as "Paper 1.21.1" / "Spigot 1.20.4".
    // Split the leading brand off so the version filter compares "1.21.1"
    // and the brand filter sees "Paper" (even without a top-level "brand" field).
    split_version_brand(r);
}

/// Known server software names used as prefixes in version strings.
const KNOWN_BRANDS: &[&str] = &[
    "paper", "purpur", "spigot", "craftbukkit", "bukkit", "vanilla", "fabric",
    "forge", "neoforge", "fml", "leaves", "leaf", "folia", "pufferfish",
    "velocity", "bungeecord", "waterfall", "arclight", "mohist", "catserver",
    "magma", "yatopia", "tuinity", "flamepaper", "sportpaper", "panda", "gale",
    "quilt", "krypton", "crucible", "diamondfire",
];

/// Splits a combined version string like "Paper 1.21.1" into
/// brand="Paper" and version="1.21.1". If the server already reported a
/// top-level "brand", it is also stripped from the version prefix.
/// Pure version strings ("1.21.1") are left untouched.
fn split_version_brand(r: &mut McResult) {
    let v = r.version.clone();
    if v.is_empty() {
        return;
    }
    let v_lower = v.to_lowercase();

    // 1) top-level brand known: strip its prefix from the version
    if !r.brand.is_empty() && v.len() >= r.brand.len() {
        let brand_lower = r.brand.to_lowercase();
        if v_lower.starts_with(&brand_lower) {
            let rest = v[r.brand.len()..].trim().to_string();
            if !rest.is_empty() && rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                r.version = rest;
                return;
            }
        }
    }
    // 2) known brand prefixes
    for b in KNOWN_BRANDS {
        if v_lower.starts_with(b) {
            let rest = v[b.len()..].trim().to_string();
            if !rest.is_empty() && rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                r.brand = v[..b.len()].trim().to_string();
                r.version = rest;
                return;
            }
        }
    }
    // 3) generic fallback: a single leading word before the first digit
    if let Some(first_digit) = v.find(|c: char| c.is_ascii_digit()) {
        if first_digit > 0 {
            let lead = v[..first_digit].trim().to_string();
            if !lead.is_empty() && !lead.contains(' ') {
                r.brand = lead;
                r.version = v[first_digit..].trim().to_string();
            }
        }
    }
}

/// Extracts a top-level string value: {"brand":"Leaf"}. Returns None if absent.
fn extract_top_level_string(json: &str, key: &str) -> Option<String> {
    let idx = json.find(&format!("\"{}\"", key))?;
    let colon = json[idx..].find(':')? + idx;
    let q = skip_whitespace(json, colon + 1);
    if q >= json.len() || json.as_bytes()[q] != b'"' {
        return None;
    }
    extract_quoted(json, q)
}

/// Extracts the player sample names: [{"name":"Steve","id":".."},...].
fn extract_player_names(json: &str) -> Vec<String> {
    let mut names = Vec::new();
    let Some(samp) = json.find("\"sample\"") else { return names };
    let Some(colon) = json[samp..].find(':').map(|c| c + samp) else { return names };
    let arr = skip_whitespace(json, colon + 1);
    if arr >= json.len() || json.as_bytes()[arr] != b'[' {
        return names;
    }
    let Some(close) = find_matching_bracket(json, arr) else { return names };
    let inner = &json[arr..=close];
    let mut from = 0usize;
    loop {
        let Some(nk) = inner[from..].find("\"name\"").map(|p| p + from) else { break };
        let Some(ncolon) = inner[nk..].find(':').map(|c| c + nk) else { break };
        let q = skip_whitespace(inner, ncolon + 1);
        if q < inner.len() && inner.as_bytes()[q] == b'"' {
            if let Some(name) = extract_quoted(inner, q) {
                let name = strip_color_codes(&unescape(&name)).trim().to_string();
                if !name.is_empty() {
                    names.push(name);
                }
            }
            from = q + 1;
        } else {
            from = ncolon + 1;
        }
    }
    names
}

/// Returns index of the bracket closing the array opened at open_bracket_idx, or None.
fn find_matching_bracket(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str = false;
    let bytes = s.as_bytes();
    let mut i = open;
    while i < s.len() {
        let c = bytes[i] as char;
        if in_str {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '[' {
            depth += 1;
        } else if c == ']' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Extracts a string value of a nested key: {"version":{"name":"1.20.4"}}.
fn extract_object_string(json: &str, section_key: &str, value_key: &str) -> Option<String> {
    let sec = json.find(&format!("\"{}\"", section_key))?;
    let colon = json[sec..].find(':')? + sec;
    let brace = skip_whitespace(json, colon + 1);
    if brace >= json.len() || json.as_bytes()[brace] != b'{' {
        return None;
    }
    let close = find_matching_brace(json, brace)?;
    let inner = &json[brace..=close];
    let vk = inner.find(&format!("\"{}\"", value_key))?;
    let vcolon = inner[vk..].find(':')? + vk;
    let q = skip_whitespace(inner, vcolon + 1);
    if q >= inner.len() || inner.as_bytes()[q] != b'"' {
        return None;
    }
    extract_quoted(inner, q)
}

/// Extracts the MOTD from the "description" field, concatenating text parts.
fn extract_description(json: &str) -> Option<String> {
    let desc = json.find("\"description\"")?;
    let colon = json[desc..].find(':')? + desc;
    let i = skip_whitespace(json, colon + 1);
    if i >= json.len() {
        return None;
    }
    if json.as_bytes()[i] == b'"' {
        return extract_quoted(json, i);
    }
    if json.as_bytes()[i] != b'{' {
        return None;
    }
    let close = find_matching_brace(json, i)?;
    let inner = &json[i..=close];
    let mut motd = String::new();
    let mut from = 0usize;
    loop {
        let Some(tk) = inner[from..].find("\"text\"").map(|p| p + from) else { break };
        let Some(tcolon) = inner[tk..].find(':').map(|c| c + tk) else { break };
        let q = skip_whitespace(inner, tcolon + 1);
        if q < inner.len() && inner.as_bytes()[q] == b'"' {
            if let Some(part) = extract_quoted(inner, q) {
                motd.push_str(&part);
            }
        }
        from = if q < inner.len() { q + 1 } else { inner.len() };
    }
    Some(motd)
}

/// Reads a quoted string starting at quote_idx; keeps escape sequences for later unescape.
fn extract_quoted(s: &str, quote_idx: usize) -> Option<String> {
    let mut sb = String::new();
    let bytes = s.as_bytes();
    let mut j = quote_idx + 1;
    while j < s.len() {
        let c = bytes[j] as char;
        if c == '\\' && j + 1 < s.len() {
            sb.push(c);
            sb.push(bytes[j + 1] as char);
            j += 2;
            continue;
        }
        if c == '"' {
            break;
        }
        sb.push(c);
        j += 1;
    }
    Some(sb)
}

fn extract_int(json: &str, key: &str) -> i64 {
    let Some(idx) = json.find(&format!("\"{}\"", key)) else { return 0 };
    let Some(colon) = json[idx..].find(':').map(|c| c + idx) else { return 0 };
    let j = skip_whitespace(json, colon + 1);
    let mut num = String::new();
    let bytes = json.as_bytes();
    let mut i = j;
    while i < json.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'-') {
        num.push(bytes[i] as char);
        i += 1;
    }
    num.parse().unwrap_or(0)
}

fn skip_whitespace(s: &str, from: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = from;
    while i < s.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Returns index of the brace closing the object opened at open_brace_idx, or None.
fn find_matching_brace(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str = false;
    let bytes = s.as_bytes();
    let mut i = open;
    while i < s.len() {
        let c = bytes[i] as char;
        if in_str {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Removes Minecraft section color codes (§X).
pub fn strip_color_codes(s: &str) -> String {
    if !s.contains('\u{00A7}') {
        return s.to_string();
    }
    let mut sb = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{00A7}' {
            if chars.peek().is_some() {
                chars.next(); // skip color code char
            }
        } else {
            sb.push(c);
        }
    }
    sb
}

/// Decodes common JSON escapes including unicode escapes (color codes etc).
pub fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut sb = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let n = chars[i + 1];
            match n {
                'n' => {
                    sb.push('\n');
                    i += 2;
                }
                't' => {
                    sb.push('\t');
                    i += 2;
                }
                'r' => {
                    sb.push('\r');
                    i += 2;
                }
                '"' => {
                    sb.push('"');
                    i += 2;
                }
                '\\' => {
                    sb.push('\\');
                    i += 2;
                }
                '/' => {
                    sb.push('/');
                    i += 2;
                }
                'u' => {
                    if i + 5 < chars.len() {
                        let hex: String = chars[i + 2..i + 6].iter().collect();
                        match u32::from_str_radix(&hex, 16) {
                            Ok(code) => {
                                sb.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                                i += 6;
                            }
                            Err(_) => {
                                sb.push(c);
                                i += 1;
                            }
                        }
                    } else {
                        sb.push(c);
                        i += 1;
                    }
                }
                _ => {
                    sb.push(c);
                    i += 1;
                }
            }
        } else {
            sb.push(c);
            i += 1;
        }
    }
    sb
}

/// Number of bytes a varint occupies on the wire.
fn varint_len(mut value: u32) -> usize {
    let mut len = 1;
    while value & !0x7F != 0 {
        value >>= 7;
        len += 1;
    }
    len
}

fn write_varint(out: &mut Vec<u8>, mut value: u32) {
    loop {
        if value & !0x7F == 0 {
            out.push(value as u8);
            return;
        }
        out.push(((value & 0x7F) | 0x80) as u8);
        value >>= 7;
    }
}

/// Writes a possibly-negative varint (Java writes the two's-complement u32).
fn write_varint_signed(out: &mut Vec<u8>, value: i32) {
    write_varint(out, value as u32);
}

fn read_varint(socket: &mut TcpStream) -> std::io::Result<i64> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    loop {
        let mut b = [0u8; 1];
        socket.read_exact(&mut b)?;
        result |= ((b[0] & 0x7F) as i64) << shift;
        if b[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VarInt слишком большой",
            ));
        }
    }
    Ok(result)
}

fn read_varint_from(buf: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return None;
        }
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as i64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    Some(result)
}
