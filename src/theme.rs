//! Central place for the dark-theme palette (port of Java `Theme`), fonts
//! sizes and the shared gradient helpers used by the gauges.

use ecolor::Color32;

// ================= DARK THEME PALETTE =================
pub const BG_ROOT: Color32 = Color32::from_rgb(17, 18, 26);
pub const BG_PANEL: Color32 = Color32::from_rgb(27, 28, 40);
pub const BG_PANEL_2: Color32 = Color32::from_rgb(32, 34, 48);
pub const BG_FIELD: Color32 = Color32::from_rgb(40, 42, 58);
pub const BG_LOG: Color32 = Color32::from_rgb(14, 15, 22);
pub const BORDER: Color32 = Color32::from_rgb(58, 61, 82);
pub const BORDER_FOCUS: Color32 = Color32::from_rgb(124, 108, 255);
pub const ACCENT: Color32 = Color32::from_rgb(124, 108, 255);
pub const ACCENT_DARK: Color32 = Color32::from_rgb(94, 78, 215);
pub const TEXT_MAIN: Color32 = Color32::from_rgb(226, 227, 240);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(140, 143, 165);
pub const GREEN: Color32 = Color32::from_rgb(88, 230, 140);
pub const GREEN_DARK: Color32 = Color32::from_rgb(38, 140, 76);
pub const RED: Color32 = Color32::from_rgb(255, 105, 105);
pub const RED_DARK: Color32 = Color32::from_rgb(178, 58, 58);
pub const YELLOW: Color32 = Color32::from_rgb(250, 200, 90);
pub const GRAY: Color32 = Color32::from_rgb(168, 171, 190);
pub const BLUE: Color32 = Color32::from_rgb(94, 160, 255);

/// Smooth scale gradient: white -> yellow -> orange -> red -> burgundy.
const GRADIENT: [[u8; 3]; 5] = [
    [255, 255, 255],
    [250, 220, 90],
    [255, 160, 60],
    [255, 90, 90],
    [140, 20, 40],
];

pub fn gradient_color(t: f64) -> Color32 {
    let t = t.clamp(0.0, 1.0) * (GRADIENT.len() - 1) as f64;
    let i = (t as usize).min(GRADIENT.len() - 2);
    let f = t - i as f64;
    let a = GRADIENT[i];
    let b = GRADIENT[i + 1];
    Color32::from_rgb(
        (a[0] as f64 + (b[0] as f64 - a[0] as f64) * f) as u8,
        (a[1] as f64 + (b[1] as f64 - a[1] as f64) * f) as u8,
        (a[2] as f64 + (b[2] as f64 - a[2] as f64) * f) as u8,
    )
}

/// Position 0..1 of an IP count on the log scale.
pub fn ip_position(count: u64) -> f64 {
    let log_c = (count.max(1) as f64).log10();
    (log_c / 12.0).clamp(0.0, 1.0)
}

/// Formats a big number with thin grouping (e.g. 4,294,967,296).
pub fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let bytes = s.as_bytes();
    for (i, c) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

/// "1d 02:03:04" / "02:03:04" ETA format.
pub fn format_eta(ms: u64) -> String {
    let mut sec = ms / 1000;
    let days = sec / 86_400;
    sec %= 86_400;
    let h = sec / 3600;
    sec %= 3600;
    let m = sec / 60;
    let s = sec % 60;
    if days > 0 {
        format!("{}d {:02}:{:02}:{:02}", days, h, m, s)
    } else {
        format!("{:02}:{:02}:{:02}", h, m, s)
    }
}

/// B/s rate format ("1.5 MB/s").
pub fn format_rate(bytes_per_sec: u64) -> String {
    if bytes_per_sec >= 1_000_000 {
        format!("{:.1} MB/s", bytes_per_sec as f64 / 1_000_000.0)
    } else if bytes_per_sec >= 1_000 {
        format!("{:.1} KB/s", bytes_per_sec as f64 / 1_000.0)
    } else {
        format!("{} B/s", bytes_per_sec)
    }
}

/// Total-bytes format ("12.3 MB").
pub fn format_bytes_total(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouping() {
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(4_294_967_296), "4,294,967,296");
        assert_eq!(fmt_num(42), "42");
    }

    #[test]
    fn gradient_endpoints() {
        assert_eq!(gradient_color(0.0), Color32::from_rgb(255, 255, 255));
        assert_eq!(gradient_color(1.0), Color32::from_rgb(140, 20, 40));
    }
}
