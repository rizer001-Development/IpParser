//! Converts the user's IP syntax input (Type: ip / wildcard / regex) into the
//! internal regex form consumed by [`crate::ip_pattern`], honouring the
//! "Use CIDR" setting.
//!
//! Type  ip       - a full IP, e.g. "95.31.158.9". With CIDR: "95.31.158.9/24".
//! Type  wildcard - wildcard octets, e.g. "95.31.***.*"  (* = any number).
//!                  With CIDR: "95.31.***.*/8" (wildcard octets become 0 in
//!                  the network base, the prefix defines the range).
//! Type  regex    - a plain regex (or regex + CIDR block inside the regex).
//!
//! Returns the internal regex string, or None if the input is invalid for the
//! selected type / CIDR setting.

/// Converts one input line to the internal regex form; None if invalid.
pub fn to_regex(raw: Option<&str>, type_: &str, use_cidr: bool) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    match type_ {
        "ip" => ip_to_regex(s, use_cidr),
        "wildcard" => wildcard_to_regex(s, use_cidr),
        _ => Some(s.to_string()), // regex type: pass through, IpPattern applies the CIDR flag
    }
}

// ---------- Type: ip ----------

fn ip_to_regex(s: &str, use_cidr: bool) -> Option<String> {
    let (base, prefix) = split_cidr(s, use_cidr)?;
    if !is_literal_ip(&base) {
        return None;
    }
    let escaped = base.replace('.', "\\.");
    match prefix {
        Some(p) => {
            if !valid_prefix(&p) {
                return None;
            }
            Some(format!("{}/{}", escaped, p))
        }
        None => Some(escaped),
    }
}

fn is_literal_ip(s: &str) -> bool {
    let octs: Vec<&str> = s.split('.').collect();
    if octs.len() != 4 {
        return false;
    }
    for o in octs {
        if o.is_empty() || o.len() > 3 || !o.bytes().all(|c| c.is_ascii_digit()) {
            return false;
        }
        match o.parse::<u32>() {
            Ok(v) if v <= 255 => {}
            _ => return false,
        }
    }
    true
}

// ---------- Type: wildcard ----------

fn wildcard_to_regex(s: &str, use_cidr: bool) -> Option<String> {
    let (base, prefix) = split_cidr(s, use_cidr)?;
    let octets: Vec<&str> = base.split('.').collect();
    if octets.len() != 4 {
        return None;
    }

    let mut parts: Vec<Option<String>> = Vec::with_capacity(4);
    for o in &octets {
        parts.push(wildcard_octet(o));
    }
    if parts.iter().any(|p| p.is_none()) {
        return None;
    }

    if let Some(p) = prefix {
        // CIDR over a wildcard base: wildcard octets become 0 in the network
        // base (e.g. 95.31.***.* slash 8 -> 95.31.0.0 slash 8), prefix defines the range.
        if !valid_prefix(&p) {
            return None;
        }
        let numeric_base: Vec<String> = octets
            .iter()
            .map(|o| {
                if !o.is_empty() && o.bytes().all(|c| c.is_ascii_digit()) {
                    o.to_string()
                } else {
                    "0".to_string()
                }
            })
            .collect();
        return Some(format!("{}/{}", numeric_base.join(".").replace('.', "\\."), p));
    }

    let mut sb = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            sb.push('\\');
            sb.push('.');
        }
        sb.push_str(part.as_deref().unwrap_or(""));
    }
    Some(sb)
}

/// One wildcard octet -> regex part, or None if invalid.
/// "192" -> "192"; "*" or "***" -> any 0-255 value; "1*0" -> "1\\d0";
/// "25*" -> "25\\d". Digits and '*' only.
fn wildcard_octet(o: &str) -> Option<String> {
    if o.is_empty() || !o.bytes().all(|c| c.is_ascii_digit() || c == b'*') {
        return None;
    }
    if !o.contains('*') {
        match o.parse::<u32>() {
            Ok(v) if v <= 255 => return Some(o.to_string()),
            _ => return None,
        }
    }
    // all-stars octet: any 0-255 value
    if o.chars().all(|c| c == '*') {
        return Some("\\d{1,3}".to_string());
    }
    // mixed digits + stars: each * = one digit position
    let mut sb = String::new();
    for c in o.chars() {
        if c == '*' {
            sb.push_str("\\d");
        } else {
            sb.push(c);
        }
    }
    Some(sb)
}

// ---------- shared ----------

/// Splits "base/prefix" when CIDR is enabled. Returns (base, Some(prefix)) or
/// (s, None) when there is no prefix. Returns None when CIDR is disabled and
/// the input contains a '/'.
fn split_cidr(s: &str, use_cidr: bool) -> Option<(String, Option<String>)> {
    match s.find('/') {
        None => Some((s.to_string(), None)),
        Some(slash) => {
            if !use_cidr {
                return None; // '/' is not allowed when CIDR is off
            }
            let base = s[..slash].trim();
            let prefix = s[slash + 1..].trim();
            if base.is_empty() || prefix.is_empty() {
                return None;
            }
            Some((base.to_string(), Some(prefix.to_string())))
        }
    }
}

fn valid_prefix(p: &str) -> bool {
    match p.parse::<i32>() {
        Ok(v) => (0..=32).contains(&v),
        Err(_) => false,
    }
}
