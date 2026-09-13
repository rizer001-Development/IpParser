//! Port of the Java `IpPattern`: expands a regex (which may contain CIDR
//! blocks) into all concrete IPv4 addresses.
//!
//! The syntax field accepts a regex describing IPv4 addresses: 4 octets
//! (each 0-255) separated by dots. CIDR blocks can be written INSIDE the regex,
//! with regex-escaped dots (95\\.31\\.0\\.0/16) or plain dots (95.31.0.0/16), and
//! several ranges can be combined with top-level "|" alternation.
//! Anchors (^ and $) at the very ends are optional. There is NO limit on the
//! number of generated addresses.
//!
//! Examples:
//!   "95\\.31\\.\\d{1,3}\\.\\d"            → third octet 0-255, fourth 0-9   (2560 IPs)
//!   "95\\.31\\.0\\.0/16"                → 95.31.0.0 … 95.31.255.255       (65536 IPs)
//!   "95.31.0.0/16"                   → same block, plain-dot CIDR       (65536 IPs)
//!   "^192\\.168\\.1\\.0/24$"            → 192.168.1.0 … 192.168.1.255     (256 IPs)
//!   "95\\.31\\.0\\.0/16|10\\.0\\.0\\.0/8"  → both blocks combined            (16.8M IPs)

use regex::Regex;

/// One address block: 4 octet value lists (the product of their sizes is the
/// number of addresses in the block).
pub type Block = Vec<Vec<i32>>;

/// Splits a regex into top-level "|" alternatives (outside groups and
/// character classes). Used so CIDR blocks can be combined with alternation.
fn split_top_level_alternation(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    let mut in_class = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            cur.push(c);
            if i + 1 < chars.len() {
                cur.push(chars[i + 1]);
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == '[' {
            in_class = true;
        } else if c == ']' {
            in_class = false;
        }
        if !in_class {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth = depth.saturating_sub(1);
            } else if c == '|' && depth == 0 {
                parts.push(std::mem::take(&mut cur));
                i += 1;
                continue;
            }
        }
        cur.push(c);
        i += 1;
    }
    parts.push(cur);
    parts
}

/// Returns the char index of the paren that closes the group opened at `open`.
/// Returns None if unbalanced. Skips escaped chars and character classes.
fn matching_paren(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_class = false;
    let mut i = open;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            i += 2; // skip escaped char
            continue;
        }
        if c == '[' {
            in_class = true;
            i += 1;
            continue;
        }
        if c == ']' {
            in_class = false;
            i += 1;
            continue;
        }
        if in_class {
            i += 1;
            continue;
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Unwraps a single enclosing group if it wraps the WHOLE string
/// (e.g. "(?:95\\.31\\.0\\.0/16|10\\.0\\.0\\.0/8)" -> the inner alternation).
fn unwrap_outer_group(s: &str) -> &str {
    let t = s.trim();
    let chars: Vec<char> = t.chars().collect();
    if chars.len() >= 2 && chars[0] == '(' {
        if let Some(close) = matching_paren(&chars, 0) {
            // close is a char index; must be the last char
            if close == chars.len() - 1 {
                let opener_len: usize = if t.starts_with("(?:") { 3 } else { 1 };
                return t[opener_len..close].trim();
            }
        }
    }
    t
}

/// Strips optional leading ^ and trailing $ anchors, then trims.
fn strip_anchors(a: &str) -> &str {
    let mut c = a;
    if let Some(stripped) = c.strip_prefix('^') {
        c = stripped;
    }
    if let Some(stripped) = c.strip_suffix('$') {
        c = stripped;
    }
    c.trim()
}

/// Parses the input into a list of address blocks. Returns an empty list if
/// the whole input is invalid. CIDR interpretation enabled.
pub fn blocks(input: Option<&str>) -> Vec<Block> {
    blocks_opt(input, true)
}

/// blocks with an explicit CIDR flag.
pub fn blocks_opt(input: Option<&str>, allow_cidr: bool) -> Vec<Block> {
    let mut result: Vec<Block> = Vec::new();
    let Some(input) = input else { return result };
    let t = input.trim();
    if t.is_empty() {
        return result;
    }
    let t = unwrap_outer_group(t);
    let alts = split_top_level_alternation(t);
    for alt in alts {
        let a = alt.trim();
        if a.is_empty() {
            result.clear();
            return result;
        }
        let core = strip_anchors(a);
        let mut block = if allow_cidr { try_cidr(core) } else { None };
        if block.is_none() {
            block = octet_values(core);
        }
        match block {
            Some(b) => result.push(b),
            None => {
                result.clear();
                return result;
            }
        }
    }
    result
}

/// Returns the octet value lists for a CIDR block string, or None if it is not a valid CIDR.
fn try_cidr(s: &str) -> Option<Block> {
    if s.is_empty() {
        return None;
    }
    let norm = s.replace("\\.", ".");
    let slash = norm.find('/')?;
    if slash == 0 {
        return None;
    }
    let base = norm[..slash].trim();
    let pref_str = norm[slash + 1..].trim();

    let base_oct = parse_ipv4(base)?;
    let prefix: i32 = pref_str.parse().ok()?;
    if !(0..=32).contains(&prefix) {
        return None;
    }
    Some(octet_lists_from_cidr(base_oct, prefix))
}

/// Parses a strict dotted-quad IPv4 (each octet 0-255, digits only).
fn parse_ipv4(s: &str) -> Option<[i32; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0i32; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let v: i64 = p.parse().ok()?;
        if v < 0 || v > 255 {
            return None;
        }
        out[i] = v as i32;
    }
    Some(out)
}

/// Builds the four octet value lists for a CIDR block (e.g. "95.31.0.0/16").
/// Because CIDR blocks are power-of-two aligned, each octet ranges over an
/// independent interval and the product equals the block size.
fn octet_lists_from_cidr(base: [i32; 4], prefix: i32) -> Block {
    let ip: u32 = ((base[0] as u32) << 24)
        | ((base[1] as u32) << 16)
        | ((base[2] as u32) << 8)
        | (base[3] as u32);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        (u32::MAX << (32 - prefix)) & u32::MAX
    };
    let start = ip & mask;
    let end = start | (!mask);

    let mut octet_lists: Block = Vec::with_capacity(4);
    for i in 0..4 {
        let shift = 8 * (3 - i);
        let lo = ((start >> shift) & 0xFF) as i32;
        let hi = ((end >> shift) & 0xFF) as i32;
        let vals: Vec<i32> = (lo..=hi).collect();
        octet_lists.push(vals);
    }
    octet_lists
}

/// Number of IPv4 addresses the syntax matches, computed WITHOUT building the
/// list (used by the live scale indicator). Returns 0 if the syntax is
/// invalid or matches nothing. CIDR interpretation enabled.
pub fn count_ips(input: Option<&str>) -> u64 {
    count_ips_opt(input, true)
}

/// count_ips with an explicit CIDR flag.
pub fn count_ips_opt(input: Option<&str>, allow_cidr: bool) -> u64 {
    let bs = blocks_opt(input, allow_cidr);
    if bs.is_empty() {
        return 0;
    }
    let mut total: u64 = 0;
    for b in &bs {
        let mut p: u64 = 1;
        for list in b {
            p *= list.len() as u64;
        }
        total += p;
    }
    total
}

// ================= MULTI-PATTERN (list / file modes) =================

/// Combines several pattern lines (each a regex/CIDR syntax, one per line)
/// into a single list of address blocks. Blank lines are skipped.
/// Returns an empty list if any non-blank line is invalid.
pub fn blocks_all(lines: &[String], allow_cidr: bool) -> Vec<Block> {
    let mut all: Vec<Block> = Vec::new();
    for line in lines {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let b = blocks_opt(Some(t), allow_cidr);
        if b.is_empty() {
            all.clear();
            return all;
        }
        all.extend(b);
    }
    all
}

/// Total IP count across all pattern lines (blank lines skipped).
pub fn count_ips_all(lines: &[String], allow_cidr: bool) -> u64 {
    let all = blocks_all(lines, allow_cidr);
    if all.is_empty() {
        return 0;
    }
    let mut total: u64 = 0;
    for b in &all {
        let mut p: u64 = 1;
        for list in b {
            p *= list.len() as u64;
        }
        total += p;
    }
    total
}

/// Structural check across all pattern lines; blank lines skipped.
pub fn structure_ok_all(lines: &[String], allow_cidr: bool) -> bool {
    let mut any = false;
    for line in lines {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        any = true;
        if !structure_ok_opt(t, allow_cidr) {
            return false;
        }
    }
    any
}

/// Structural check only (used to pick the right error message): every
/// top-level alternative must be a valid CIDR or a regex with 4 compilable
/// octet parts. Does NOT require that the parts match any 0-255 value.
pub fn structure_ok(input: &str) -> bool {
    structure_ok_opt(input, true)
}

/// structure_ok with an explicit CIDR flag.
pub fn structure_ok_opt(input: &str, allow_cidr: bool) -> bool {
    if input.trim().is_empty() {
        return false;
    }
    let t = unwrap_outer_group(input.trim());
    let alts = split_top_level_alternation(t);
    for alt in alts {
        let a = alt.trim();
        if a.is_empty() {
            return false;
        }
        let core = strip_anchors(a);
        if allow_cidr && try_cidr(core).is_some() {
            continue;
        }
        if core.contains('/') {
            return false; // malformed CIDR-looking input
        }
        let mut parts = split_octets(core);
        if parts.len() != 4 {
            return false;
        }
        parts[0] = strip_caret(&parts[0]);
        parts[3] = strip_dollar(&parts[3]);
        for part in &parts {
            if part.is_empty() {
                return false;
            }
            let wrapped = format!("^(?:{})$", part);
            if Regex::new(&wrapped).is_err() {
                return false;
            }
        }
    }
    true
}

/// Strips a leading '^' (like Java replaceFirst("^\\^", "")).
fn strip_caret(s: &str) -> String {
    s.strip_prefix('^').unwrap_or(s).to_string()
}

/// Strips a trailing '$' (like Java replaceFirst("\\$$", "")).
fn strip_dollar(s: &str) -> String {
    s.strip_suffix('$').unwrap_or(s).to_string()
}

/// Expands the syntax into all matching IPv4 strings (used by tests/tools).
pub fn expand(input: Option<&str>) -> Vec<String> {
    let bs = blocks(input);
    if bs.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    for block in &bs {
        for a in &block[0] {
            for b in &block[1] {
                for c in &block[2] {
                    for d in &block[3] {
                        result.push(format!("{}.{}.{}.{}", a, b, c, d));
                    }
                }
            }
        }
    }
    result
}

/// Returns the four octet value lists for a regex, or None if it is invalid
/// or matches no 0-255 values.
fn octet_values(regex: &str) -> Option<Block> {
    let r = regex.trim();
    if r.is_empty() {
        return None;
    }
    if Regex::new(r).is_err() {
        return None;
    }

    let mut parts = split_octets(r);
    if parts.len() != 4 {
        return None;
    }
    parts[0] = strip_caret(&parts[0]);
    parts[3] = strip_dollar(&parts[3]);

    let mut octet_values: Block = Vec::with_capacity(4);
    for part in &parts {
        if part.is_empty() {
            return None;
        }
        let wrapped = format!("^(?:{})$", part);
        let octet_pattern = Regex::new(&wrapped).ok()?;
        let mut values: Vec<i32> = Vec::new();
        for v in 0..=255i32 {
            if octet_pattern.is_match(&v.to_string()) {
                values.push(v);
            }
        }
        if values.is_empty() {
            return None;
        }
        octet_values.push(values);
    }
    Some(octet_values)
}

/// Splits a regex into octet parts on unescaped dots that are outside
/// character classes. Handles both \\. and . separators.
pub fn split_octets(regex: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_class = false;
    let chars: Vec<char> = regex.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            if i + 1 < chars.len() {
                let next = chars[i + 1];
                if !in_class && next == '.' {
                    parts.push(std::mem::take(&mut current));
                    i += 2;
                    continue;
                }
                current.push(c);
                current.push(next);
                i += 2;
                continue;
            }
            current.push(c);
        } else if c == '[' {
            in_class = true;
            current.push(c);
        } else if c == ']' {
            in_class = false;
            current.push(c);
        } else if c == '.' && !in_class {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
        i += 1;
    }
    parts.push(current);
    parts
}
