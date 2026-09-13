//! Port of the Java `McFilters`: pure, side-effect-free MC-probe log filter
//! logic. An invalid filter value never discards results: malformed
//! numeric/version values or invalid regexes are treated as "filter disabled".

use regex::Regex;

use crate::mc_probe::McResult;

/// Operators available for online-count / version filters.
pub const OPERATORS: [&str; 5] = ["is", "above", "below", "in-range", "out-of-range"];

/// Mutable settings object read by worker threads.
#[derive(Debug, Clone, Default)]
pub struct FilterSettings {
    pub online: bool,
    pub online_op: String,
    pub online_val: String,

    pub version: bool,
    pub version_op: String,
    pub version_val: String,

    pub brand: bool,
    pub brand_val: String,

    pub motd: bool,
    pub motd_val: String,

    pub players: bool,
    pub players_val: String,
}

impl FilterSettings {
    pub fn with_defaults() -> Self {
        Self {
            online_op: "is".to_string(),
            version_op: "is".to_string(),
            ..Default::default()
        }
    }
}

/// Returns true if a successful MC probe passes all enabled filters.
pub fn passes(probe: &McResult, s: &FilterSettings) -> bool {
    if s.online {
        if let Some(range) = parse_num_range(&s.online_val) {
            if !num_in_range(probe.online as i64, &s.online_op, &range) {
                return false;
            }
        }
    }
    if s.version && !s.version_val.trim().is_empty() {
        if !version_matches(&probe.version, &s.version_op, &s.version_val) {
            return false;
        }
    }
    if s.brand && !s.brand_val.trim().is_empty() && !regex_find(&probe.brand, &s.brand_val) {
        return false;
    }
    if s.motd && !s.motd_val.trim().is_empty() && !regex_find(&probe.motd, &s.motd_val) {
        return false;
    }
    if s.players && !s.players_val.trim().is_empty() {
        let any = probe.players.iter().any(|name| regex_find(name, &s.players_val));
        if !any {
            return false;
        }
    }
    true
}

/// Parses "5" or "10-30" into (lo, hi); None if invalid.
pub fn parse_num_range(s: &str) -> Option<(i64, i64)> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if t.contains('-') {
        let parts: Vec<&str> = t.split('-').collect();
        if parts.len() != 2 {
            return None;
        }
        let lo: i64 = parts[0].trim().parse().ok()?;
        let hi: i64 = parts[1].trim().parse().ok()?;
        return Some((lo.min(hi), lo.max(hi)));
    }
    let v: i64 = t.parse().ok()?;
    Some((v, v))
}

/// Applies the operator: is / above / below / in-range / out-of-range against (lo, hi).
pub fn num_in_range(value: i64, op: &str, range: &(i64, i64)) -> bool {
    let (lo, hi) = *range;
    match op {
        "is" => value == lo,
        "above" => value > hi,
        "below" => value < lo,
        "in-range" => value >= lo && value <= hi,
        "out-of-range" => value < lo || value > hi,
        _ => true,
    }
}

/// Compares two MC version strings numerically, e.g. "1.21.1" vs "1.21.4".
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let pa = version_parts(a);
    let pb = version_parts(b);
    let n = pa.len().max(pb.len());
    for i in 0..n {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

/// Extracts numeric version parts from e.g. "1.21.1-SNAPSHOT" -> [1, 21, 1].
pub fn version_parts(v: &str) -> Vec<i64> {
    let mut digits = String::new();
    for c in v.trim().chars() {
        if c.is_ascii_digit() || c == '.' {
            digits.push(c);
        } else if c == '-' || c == '+' {
            digits.push('.');
        }
    }
    digits
        .split('.')
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Version operator check: is / above / below / in-range / out-of-range ("1.21.1-1.21.4").
pub fn version_matches(version: &str, op: &str, spec: &str) -> bool {
    let s = spec.trim();
    if op == "in-range" || op == "out-of-range" {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            let c1 = compare_versions(version, parts[0].trim());
            let c2 = compare_versions(version, parts[1].trim());
            let inside = c1 != std::cmp::Ordering::Less && c2 != std::cmp::Ordering::Greater;
            return if op == "in-range" { inside } else { !inside };
        }
        if parts.len() == 1 {
            // single value: out-of-range = any version except this one
            return op == "out-of-range" && compare_versions(version, s) != std::cmp::Ordering::Equal;
        }
        // malformed multi-dash spec: filter disabled (never discard results)
        return true;
    }
    let c = compare_versions(version, s);
    match op {
        "is" => c == std::cmp::Ordering::Equal,
        "above" => c == std::cmp::Ordering::Greater,
        "below" => c == std::cmp::Ordering::Less,
        _ => true,
    }
}

/// True if the regex is found anywhere in text. An INVALID regex is treated
/// as "filter disabled" (returns true) so a typo never silently discards
/// scan results - consistent with invalid numeric filter values.
pub fn regex_find(text: &str, regex: &str) -> bool {
    if text.is_empty() || regex.trim().is_empty() {
        return false;
    }
    match Regex::new(regex) {
        Ok(re) => re.is_match(text),
        Err(_) => true, // invalid regex: don't filter
    }
}
