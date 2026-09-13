//! Timestamp formatting helpers (UTC), replacing the Java SimpleDateFormat
//! usages. Pure `std` - no chrono dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// Splits the current time into (y, mo, d, h, mi, s, ms).
pub fn now_parts() -> (i64, u32, u32, u32, u32, u32, u32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let ms = now.subsec_millis();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    (
        y,
        mo,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
        ms,
    )
}

/// "HH:mm:ss" for on-screen log lines.
pub fn now_hms() -> String {
    let (_, _, _, h, mi, s, _) = now_parts();
    format!("{:02}:{:02}:{:02}", h, mi, s)
}

/// "yyyy-MM-dd HH:mm:ss.SSS" for file-log line prefixes.
pub fn now_full() -> String {
    let (y, mo, d, h, mi, s, ms) = now_parts();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        y, mo, d, h, mi, s, ms
    )
}

/// "yyyyMMdd-HHmmss" for per-scan log file names.
pub fn now_filename_ts() -> String {
    let (y, mo, d, h, mi, s, _) = now_parts();
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", y, mo, d, h, mi, s)
}

/// "yyyy-MM-dd HH:mm:ss" for export headers.
pub fn now_export_ts() -> String {
    let (y, mo, d, h, mi, s, _) = now_parts();
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // 2024-01-01
    }

    #[test]
    fn formats_have_expected_widths() {
        assert_eq!(now_hms().len(), 8);
        assert_eq!(now_full().len(), 23);
        assert_eq!(now_filename_ts().len(), 15);
    }
}
