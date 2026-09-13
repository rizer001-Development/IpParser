//! IP Parser — egui GUI (Rust port of the Java Swing window).
//!
//! This is the `main` binary. All business logic lives in the library crate
//! (`ip_parser`); this file only renders the window and forwards events.
//!
//! Ported 1:1 from the Java `IpParserFrame` / `IpSettingsDialog` /
//! `LogSettingsDialog` and the `gui.components` widgets (gauges, progress bar).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke};
use ip_parser::{
    app_paths,
    export::{self, ExportParams},
    filters::{self, FilterSettings},
    ip_pattern, ip_utils,
    log_config::LogConfig,
    mc_probe::McResult,
    perf, scanner, storage, syntax_conv, theme, timefmt, version,
};

/// On-screen log entry (timestamp + colored text).
struct LogLine {
    ts: String,
    text: String,
    color: Color32,
    bold: bool,
}

/// The scanner mode selection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum McMode {
    Telnet,
    Minecraft,
}

struct App {
    // ----- syntax state -----
    syntax_type: String,   // ip / wildcard / regex
    syntax_mode: String,   // Single / List / File
    use_cidr: bool,
    ip_pattern: String,    // Single
    list_area: String,     // List
    file_field: String,    // File

    // ----- other inputs -----
    port_field: String,
    timeout_field: String,
    parse_threads: usize,
    gen_threads: usize,
    net_threads: usize,
    mc_mode: McMode,

    log_config: LogConfig,

    // ----- runtime -----
    scan: Option<scanner::ScanHandle>,
    open_results: Vec<String>,
    mc_results: HashMap<String, McResult>,
    open_count: u64,
    closed_count: u64,
    external_count: u64,
    total_targets: u64,
    scanned: u64,
    scan_start: Option<Instant>,
    progress_pct: f64,
    status: String,
    log_lines: Vec<LogLine>,

    // ----- dialogs -----
    show_ip_settings: bool,
    show_log_settings: bool,
    error_msg: Option<String>,
    confirm_large_scan: Option<u64>, // Some(total_targets) when asking

    // ----- perf tick -----
    last_perf: Instant,

    // scale caches (recomputed when inputs change)
    scale_valid: bool,
    scale_count: u64,
    last_syntax_fingerprint: String,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let mut app = App {
            syntax_type: "regex".to_string(),
            syntax_mode: "Single".to_string(),
            use_cidr: true,
            ip_pattern: r"95\.31\.\d{1,3}\.\d".to_string(),
            list_area: String::new(),
            file_field: String::new(),
            port_field: "2000".to_string(),
            timeout_field: "1500".to_string(),
            parse_threads: 1,
            gen_threads: 1,
            net_threads: 100,
            mc_mode: McMode::Telnet,
            log_config: LogConfig::default(),
            scan: None,
            open_results: Vec::new(),
            mc_results: HashMap::new(),
            open_count: 0,
            closed_count: 0,
            external_count: 0,
            total_targets: 0,
            scanned: 0,
            scan_start: None,
            progress_pct: 0.0,
            status: "Ready. Enter an IP syntax (regex) and port, then press Start.".to_string(),
            log_lines: Vec::new(),
            show_ip_settings: false,
            show_log_settings: false,
            error_msg: None,
            confirm_large_scan: None,
            last_perf: Instant::now(),
            scale_valid: false,
            scale_count: 0,
            last_syntax_fingerprint: String::new(),
        };

        let cores = available_cores();
        app.parse_threads = cores;
        app.gen_threads = cores.min(4);
        app.load_settings();
        storage::init_app_log();
        app.update_scale();
        app
    }

    // ================= UI ROOT =================

    fn build_ui(&mut self, ui: &mut egui::Ui) {
        // Top: header + settings. Bottom: buttons + monitor + status.
        // Center: the log fills the remaining space. Using real panels keeps
        // the bottom controls pinned and visible (a ScrollArea in a plain
        // vertical layout would otherwise swallow all remaining height).
        egui::Panel::top("top_panel")
            .frame(
                egui::Frame::NONE
                    .fill(theme::BG_ROOT)
                    .inner_margin(egui::Margin::symmetric(12, 12)),
            )
            .show_separator_line(false)
            .show(ui, |ui| {
                self.header(ui);
                ui.add_space(10.0);
                self.settings_panel(ui);
            });

        egui::Panel::bottom("bottom_panel")
            .frame(
                egui::Frame::NONE
                    .fill(theme::BG_ROOT)
                    .inner_margin(egui::Margin::symmetric(12, 12)),
            )
            .show_separator_line(false)
            .show(ui, |ui| {
                self.bottom_panel(ui);
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::BG_ROOT)
                    .inner_margin(egui::Margin::symmetric(12, 0)),
            )
            .show(ui, |ui| {
                ui.add_space(10.0);
                self.log_panel(ui);
            });
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        panel(ui, theme::BG_PANEL, 14, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Pattern-based IP scanner and port checker")
                        .color(theme::TEXT_MUTED),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    stat(ui, &format!("Closed: {}", theme::fmt_num(self.closed_count)), theme::RED);
                    stat(ui, &format!("External: {}", theme::fmt_num(self.external_count)), theme::BLUE);
                    stat(ui, &format!("Open: {}", theme::fmt_num(self.open_count)), theme::GREEN);
                    stat(ui, &format!("Total: {}", theme::fmt_num(self.total_targets)), theme::TEXT_MUTED);
                });
            });
        });
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        panel(ui, theme::BG_PANEL, 14, |ui| {
            // ---- Row: Syntax ----
            ui.horizontal(|ui| {
                muted_label(ui, "Syntax");
                self.syntax_row(ui);
                // Live IP-count scale (right-aligned)
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ip_scale(ui, self.scale_valid, self.scale_count);
                });
            });

            ui.add_space(6.0);

            // ---- Row: Port / range + Timeout ----
            ui.horizontal(|ui| {
                muted_label(ui, "Port / range");
                ui.add(
                    egui::TextEdit::singleline(&mut self.port_field)
                        .desired_width(90.0)
                        .hint_text("2000"),
                );
                muted_label(ui, "Timeout (ms)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.timeout_field)
                        .desired_width(70.0)
                        .hint_text("1500"),
                );
            });

            ui.add_space(6.0);

            // ---- Row: Threads ----
            let cores = available_cores();
            ui.horizontal(|ui| {
                muted_label(ui, "Threads");
                muted_label(ui, "Parse:");
                ui.add(egui::DragValue::new(&mut self.parse_threads).range(1..=cores.max(1)));
                muted_label(ui, "Gen:");
                ui.add(egui::DragValue::new(&mut self.gen_threads).range(1..=cores.max(1)));
                muted_label(ui, "Net:");
                ui.add(egui::DragValue::new(&mut self.net_threads).range(1..=1024));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    thread_scale(ui, self.net_threads);
                });
            });

            ui.add_space(6.0);

            // ---- Row: Mode ----
            ui.horizontal(|ui| {
                muted_label(ui, "Mode");
                let mut idx = if self.mc_mode == McMode::Minecraft { 1usize } else { 0usize };
                egui::ComboBox::from_id_salt("mode_combo")
                    .selected_text(match idx {
                        1 => "Minecraft (mcprobe)",
                        _ => "Telnet (TCP port)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut idx, 0, "Telnet (TCP port)");
                        ui.selectable_value(&mut idx, 1, "Minecraft (mcprobe)");
                    });
                self.mc_mode = if idx == 1 { McMode::Minecraft } else { McMode::Telnet };
            });

            muted_label(ui, "🔒 Port format:  2000  (single)  or  2000-2010  (range)");
        });
    }

    fn syntax_row(&mut self, ui: &mut egui::Ui) {
        match self.syntax_mode.as_str() {
            "List" => {
                ui.add(
                    egui::TextEdit::multiline(&mut self.list_area)
                        .desired_rows(4)
                        .desired_width(320.0)
                        .hint_text("several regexes / CIDR blocks, one per line"),
                );
            }
            "File" => {
                ui.add(
                    egui::TextEdit::singleline(&mut self.file_field)
                        .desired_width(280.0)
                        .hint_text("patterns file path"),
                );
                if ui.button("📂").on_hover_text("Choose a patterns file").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select patterns file (one regex / CIDR per line)")
                        .set_directory(app_paths::home_dir())
                        .pick_file()
                    {
                        self.file_field = path.display().to_string();
                        self.update_scale();
                    }
                }
            }
            _ => {
                ui.add(
                    egui::TextEdit::singleline(&mut self.ip_pattern)
                        .desired_width(300.0)
                        .hint_text(r"95\.31\.\d{1,3}\.\d"),
                );
            }
        }

        if ui.button("⚙").on_hover_text("IP parsing settings").clicked() {
            self.show_ip_settings = true;
        }
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        panel(ui, theme::BG_PANEL, 14, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("📋  Log — scan results").color(theme::TEXT_MAIN).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .button(RichText::new("⚙  Settings").color(theme::TEXT_MAIN))
                        .on_hover_text("Log settings and MC-probe log filters")
                        .clicked()
                    {
                        self.show_log_settings = true;
                    }
                });
            });
            ui.add_space(4.0);

            egui::Frame::NONE
                .fill(theme::BG_LOG)
                .stroke(Stroke::new(1.0, theme::BORDER))
                .corner_radius(6)
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
                    let stick = self.scan.is_some();
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .stick_to_bottom(stick)
                        .show_rows(ui, row_height, self.log_lines.len(), |ui, range| {
                            for i in range {
                                let line = &self.log_lines[i];
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!("[{}]  ", line.ts))
                                            .monospace()
                                            .color(theme::TEXT_MUTED),
                                    );
                                    let mut rt = RichText::new(&line.text)
                                        .monospace()
                                        .color(line.color);
                                    if line.bold {
                                        rt = rt.strong();
                                    }
                                    ui.label(rt);
                                });
                            }
                        });
                });
        });
    }

    fn bottom_panel(&mut self, ui: &mut egui::Ui) {
        // Buttons
        ui.horizontal(|ui| {
            let scanning = self.scan.is_some();
            let start = ui.add_enabled(
                !scanning,
                egui::Button::new(RichText::new("▶  Start").color(Color32::WHITE))
                    .fill(theme::GREEN_DARK),
            );
            if start.clicked() {
                self.start_scan();
            }
            let stop = ui.add_enabled(
                scanning,
                egui::Button::new(RichText::new("■  Stop").color(Color32::WHITE))
                    .fill(theme::RED_DARK),
            );
            if stop.clicked() {
                self.stop_scan();
            }
            let export = ui.add_enabled(
                !self.open_results.is_empty(),
                egui::Button::new(RichText::new("📄  Export").color(Color32::WHITE))
                    .fill(theme::ACCENT_DARK),
            );
            if export.clicked() {
                self.export_results();
            }
            if ui.button(RichText::new("Clear log").color(theme::TEXT_MAIN)).clicked() {
                self.clear_all();
            }
        });

        ui.add_space(6.0);

        // Perf monitor
        panel(ui, theme::BG_PANEL_2, 12, |ui| {
            ui.horizontal(|ui| {
                let (cpu, ram) = (perf::get_process_cpu_load(), perf::get_ram_used_mb());
                ui.label(
                    RichText::new(format!("CPU: {}", if cpu < 0 { "--".into() } else { format!("{cpu}%") }))
                        .color(if cpu < 0 { theme::TEXT_MUTED } else { theme::ACCENT })
                        .strong(),
                );
                ui.label(RichText::new(format!("RAM: {ram} MB")).color(theme::TEXT_MAIN).strong());
                ui.label(
                    RichText::new(format!(
                        "IN: {}  (tot {})",
                        theme::format_rate(perf::get_recv_rate()),
                        theme::format_bytes_total(perf::get_total_recv())
                    ))
                    .color(theme::GREEN)
                    .strong(),
                );
                ui.label(
                    RichText::new(format!(
                        "OUT: {}  (tot {})",
                        theme::format_rate(perf::get_sent_rate()),
                        theme::format_bytes_total(perf::get_total_sent())
                    ))
                    .color(theme::BLUE)
                    .strong(),
                );
            });
        });

        ui.add_space(6.0);

        // Status bar + progress
        panel(ui, theme::BG_PANEL_2, 12, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status).color(theme::TEXT_MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    progress_bar(ui, self.progress_pct, egui::vec2(250.0, 46.0));
                });
            });
        });
    }

    // ================= DIALOGS =================

    fn show_dialogs(&mut self, ctx: &egui::Context) {
        if self.show_ip_settings {
            let mut open = true;
            let mut close = false;
            egui::Window::new("IP parsing settings")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    close = ip_settings_dialog(self, ui);
                });
            if close || !open {
                self.show_ip_settings = false;
            }
        }
        if self.show_log_settings {
            let mut open = true;
            let mut close = false;
            egui::Window::new("Log Settings")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    close = log_settings_dialog(self, ui);
                });
            if close || !open {
                self.show_log_settings = false;
            }
        }
        if let Some(msg) = self.error_msg.clone() {
            let mut open = true;
            let mut close = false;
            egui::Window::new("Message")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(msg);
                    if ui.button("OK").clicked() {
                        close = true;
                    }
                });
            if close || !open {
                self.error_msg = None;
            }
        }
        if let Some(total) = self.confirm_large_scan {
            let mut open = true;
            let mut action: Option<bool> = None;
            egui::Window::new("Large scan")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "This scan covers {} targets. It will take a very long time. Continue?",
                        theme::fmt_num(total)
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Yes").clicked() {
                            action = Some(true);
                        }
                        if ui.button("No").clicked() {
                            action = Some(false);
                        }
                    });
                });
            match action {
                Some(true) => {
                    self.confirm_large_scan = None;
                    self.begin_scan();
                }
                Some(false) => self.confirm_large_scan = None,
                None => {
                    if !open {
                        self.confirm_large_scan = None;
                    }
                }
            }
        }
    }

    // ================= SCAN LOGIC =================

    fn start_scan(&mut self) {
        if self.syntax_mode == "File" {
            let path = self.file_field.trim();
            if path.is_empty() || !std::path::Path::new(path).exists() {
                self.error_msg = Some(format!(
                    "Patterns file not found: {}\nChoose the file with the folder icon, or enter a valid path.",
                    if path.is_empty() { "(empty)" } else { path }
                ));
                return;
            }
        }

        let raw_lines = self.current_pattern_lines();
        let port_spec = self.port_field.trim().to_string();

        if raw_lines.is_empty() || port_spec.is_empty() {
            self.error_msg = Some(
                "Fill in the IP syntax and port.\n\
                 Single: ^95\\.31\\.\\d{1,3}\\.\\d$  or  95\\.31\\.0\\.0/16\n\
                 List: several patterns, one per line\n\
                 File: path to a text file with one pattern per line\n\
                 Port: 2000  or  2000-2010"
                    .to_string(),
            );
            return;
        }

        // Convert each line according to the selected type / CIDR setting.
        let mut converted: Vec<String> = Vec::new();
        for line in &raw_lines {
            match syntax_conv::to_regex(Some(line), &self.syntax_type, self.use_cidr) {
                Some(c) => converted.push(c),
                None => {
                    let hint = match self.syntax_type.as_str() {
                        "ip" => format!(
                            "Type ip needs a full IP, e.g. 95.31.158.9{}",
                            if self.use_cidr { "  or  95.31.158.9/24" } else { "" }
                        ),
                        "wildcard" => format!(
                            "Type wildcard: * means any number, e.g. 95.31.***.*{}",
                            if self.use_cidr { "  or  95.31.***.*/8" } else { "" }
                        ),
                        _ => "Type regex: Java regex for IPv4 (4 octets), e.g. ^95\\.31\\.\\d{1,3}\\.\\d$"
                            .to_string(),
                    };
                    self.error_msg =
                        Some(format!("Invalid IP syntax for type {}.\n{}", self.syntax_type, hint));
                    return;
                }
            }
        }

        if let Some(err) = validate_port_spec(&port_spec) {
            self.error_msg = Some(err);
            return;
        }

        match self.timeout_field.trim().parse::<i64>() {
            Ok(t) if (50..=60000).contains(&t) => {}
            _ => {
                self.error_msg = Some("Timeout must be a number between 50 and 60000 ms".to_string());
                return;
            }
        }

        let total_ips = ip_pattern::count_ips_all(&converted, self.use_cidr);
        if total_ips == 0 {
            if ip_pattern::structure_ok_all(&converted, self.use_cidr) {
                self.error_msg = Some(
                    "No IPs matched the syntax.\nNothing in the 0-255 range per octet matches it."
                        .to_string(),
                );
            } else {
                self.error_msg = Some(
                    format!(
                        "Invalid IP syntax.\nType {}, CIDR {}.\n\
                         ip:       95.31.158.9{}\n\
                         wildcard: 95.31.***.*  (* = any number){}\n\
                         regex:    ^95\\.31\\.\\d{{1,3}}\\.\\d$  or  95\\.31\\.0\\.0/16",
                        self.syntax_type,
                        if self.use_cidr { "on" } else { "off" },
                        if self.use_cidr { "  or  95.31.158.9/24" } else { "" },
                        if self.use_cidr { "  or  95.31.***.*/8" } else { "" },
                    )
                );
            }
            return;
        }

        let [start_port, end_port] = scanner::parse_ports(&port_spec);
        let total_targets = total_ips * (end_port - start_port + 1) as u64;
        if total_targets > 100_000_000 {
            self.confirm_large_scan = Some(total_targets);
            self.total_targets = total_targets;
            return;
        }
        self.total_targets = total_targets;
        self.begin_scan();
    }

    /// Actually launches the scan (after any confirmation).
    fn begin_scan(&mut self) {
        let raw_lines = self.current_pattern_lines();
        let converted: Vec<String> = raw_lines
            .iter()
            .filter_map(|l| syntax_conv::to_regex(Some(l), &self.syntax_type, self.use_cidr))
            .collect();
        let blocks = ip_pattern::blocks_all(&converted, self.use_cidr);
        let total_ips = ip_pattern::count_ips_all(&converted, self.use_cidr);

        let port_spec = self.port_field.trim().to_string();
        let [start_port, end_port] = scanner::parse_ports(&port_spec);
        let timeout: u64 = self.timeout_field.trim().parse().unwrap_or(1500);

        self.open_count = 0;
        self.closed_count = 0;
        self.external_count = 0;
        self.scanned = 0;
        self.total_targets = total_ips * (end_port - start_port + 1) as u64;
        self.scan_start = Some(Instant::now());
        self.progress_pct = 0.0;

        self.open_results.clear();
        self.mc_results.clear();

        perf::reset();

        let port_desc = if start_port == end_port {
            start_port.to_string()
        } else {
            format!("{start_port}-{end_port}")
        };
        let mode_desc = if self.mc_mode == McMode::Minecraft {
            "Minecraft (mcprobe)"
        } else {
            "Telnet (TCP)"
        };

        self.log_action("");
        self.log_action("═══════════════════ SCANNING STARTED ═══════════════════");
        self.log_action(&format!(
            "Mode: {}   |   Syntax: type={}, input={}, CIDR={}   |   {} pattern(s)   ({} addresses)",
            mode_desc,
            self.syntax_type,
            self.syntax_mode.to_lowercase(),
            if self.use_cidr { "on" } else { "off" },
            converted.len(),
            theme::fmt_num(total_ips)
        ));
        self.log_action(&format!(
            "Port: {}   (targets: {})",
            port_desc,
            theme::fmt_num(self.total_targets)
        ));
        self.log_action(&format!(
            "Timeout: {} ms,  CPU threads: {} parse / {} gen,  network: {}",
            timeout, self.parse_threads, self.gen_threads, self.net_threads
        ));
        if self.log_config.external {
            self.log_action("Status 2 enabled: public IP + open port = reachable from outside");
        }

        self.save_settings();

        // Dedicated scan log file.
        storage::begin_scan();
        storage::scan_mode(mode_desc, &self.syntax_type, &self.syntax_mode, self.use_cidr, total_ips);
        storage::scan(&format!(
            "Port: {}  targets: {}  timeout: {}ms",
            port_desc, self.total_targets, timeout
        ));

        let mode = match self.mc_mode {
            McMode::Minecraft => scanner::ScanMode::Minecraft,
            McMode::Telnet => scanner::ScanMode::Telnet,
        };
        self.scan = Some(scanner::start_scan(
            blocks,
            start_port,
            end_port,
            timeout,
            self.gen_threads,
            self.net_threads,
            mode,
        ));
    }

    fn stop_scan(&mut self) {
        if let Some(h) = &self.scan {
            h.stop();
        }
        self.log_action("--- Scan stopped by user ---");
        self.status = format!("Stopped. Found: {}", theme::fmt_num(self.open_count));
        storage::close_scan();
    }

    fn drain_scan(&mut self) {
        let mut events = Vec::new();
        let mut disconnected = false;
        if let Some(h) = self.scan.as_ref() {
            loop {
                match h.events.try_recv() {
                    Ok(ev) => events.push(ev),
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        for ev in events {
            match ev {
                scanner::ScanEvent::Result(ip, port, raw) => self.on_result(ip, port, raw),
                scanner::ScanEvent::Progress(done, total) => {
                    self.scanned = done;
                    self.total_targets = total;
                    let left = total.saturating_sub(done);
                    let pct = if total == 0 { 0.0 } else { done as f64 * 100.0 / total as f64 };
                    let eta = if done > 0 {
                        let elapsed = self.scan_start.map(|s| s.elapsed().as_millis() as u64).unwrap_or(0);
                        if elapsed > 0 && left > 0 {
                            left * elapsed / done
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    self.progress_pct = pct;
                    self.status = format!(
                        "Checked: {}  |  Left: {}  |  ETA {}",
                        theme::fmt_num(done),
                        theme::fmt_num(left),
                        theme::format_eta(eta)
                    );
                }
                scanner::ScanEvent::Finished => {}
            }
        }
        if disconnected {
            if let Some(mut h) = self.scan.take() {
                h.join();
            }
            self.on_finished();
        }
    }

    fn on_result(&mut self, ip: String, port: u16, raw: scanner::Raw) {
        match raw {
            scanner::Raw::Telnet { result, time_ms } => {
                match result {
                    scanner::PortResult::Open => {
                        self.open_count += 1;
                        self.open_results.push(format!("{ip}:{port}"));
                        if self.log_config.log_open {
                            self.log_result("✅ OPEN", &format!("{ip}:{port}"), theme::GREEN, time_ms);
                        }
                        if self.log_config.external && ip_utils::is_public(&ip) && !ip_utils::is_same_lan(&ip) {
                            self.external_count += 1;
                        }
                    }
                    scanner::PortResult::Closed => {
                        self.closed_count += 1;
                        if self.log_config.log_closed {
                            self.log_result("❌ CLOSED", &format!("{ip}:{port}"), theme::RED, time_ms);
                        }
                    }
                    scanner::PortResult::Timeout => {
                        if self.log_config.log_timeout {
                            self.log_result("⏳ TIMEOUT", &format!("{ip}:{port}"), theme::YELLOW, time_ms);
                        }
                    }
                    scanner::PortResult::Error => {
                        if self.log_config.log_error {
                            self.log_result("❓ ERROR", &format!("{ip}:{port}"), theme::GRAY, time_ms);
                        }
                    }
                }
                if self.log_config.external {
                    self.log_external(&ip, port, result, time_ms);
                }
            }
            scanner::Raw::Mc(probe) => {
                if probe.success {
                    if !filters::passes(&probe, &self.log_config.mc) {
                        return;
                    }
                    self.open_count += 1;
                    let key = format!("{ip}:{port}");
                    self.open_results.push(key.clone());
                    self.mc_results.insert(key, probe.clone());
                    self.log_mc_result(&ip, port, &probe);
                    if self.log_config.external && ip_utils::is_public(&ip) && !ip_utils::is_same_lan(&ip) {
                        self.external_count += 1;
                    }
                } else {
                    self.closed_count += 1;
                    if self.log_config.log_closed {
                        self.log_result("❌ CLOSED", &format!("{ip}:{port}"), theme::RED, probe.latency_ms);
                    }
                }
                if self.log_config.external {
                    let r = if probe.success {
                        scanner::PortResult::Open
                    } else {
                        scanner::PortResult::Closed
                    };
                    self.log_external(&ip, port, r, probe.latency_ms);
                }
            }
        }
    }

    fn on_finished(&mut self) {
        self.progress_pct = 100.0;
        let ext = if self.log_config.external {
            format!("  |  External: {}", theme::fmt_num(self.external_count))
        } else {
            String::new()
        };
        let (verb, noun) = match self.mc_mode {
            McMode::Minecraft => ("MC servers found", "No response"),
            McMode::Telnet => ("Open ports", "Closed"),
        };
        self.status = format!("Done. {}: {}{}", verb, theme::fmt_num(self.open_count), ext);
        self.log_action("");
        self.log_action("═══════════════════ SCANNING FINISHED ═══════════════════");
        self.log_action(&format!(
            "{}: {}  |  {}: {}{}",
            verb,
            theme::fmt_num(self.open_count),
            noun,
            theme::fmt_num(self.closed_count),
            ext
        ));
        storage::close_scan();
    }

    fn export_results(&mut self) {
        if self.open_results.is_empty() {
            self.error_msg = Some("No results to export.".to_string());
            return;
        }
        let default_name = format!("results_{}.txt", timefmt::now_filename_ts());
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save results")
            .set_directory(app_paths::home_dir())
            .set_file_name(&default_name)
            .save_file()
        else {
            return;
        };
        let mut path = path;
        if path.extension().map(|e| !e.eq_ignore_ascii_case("txt")).unwrap_or(true) {
            path.set_extension("txt");
        }

        let params = ExportParams {
            mc_mode: self.mc_mode == McMode::Minecraft,
            syntax_type: self.syntax_type.clone(),
            syntax_mode: self.syntax_mode.clone(),
            use_cidr: self.use_cidr,
            pattern_desc: self.pattern_desc_for_export(),
            port_spec: self.port_field.trim().to_string(),
            external: self.log_config.external,
            external_count: self.external_count,
            open_results: self.open_results.clone(),
            mc_results: self.mc_results.clone(),
        };
        let content = export::build(&params);
        match std::fs::write(&path, content) {
            Ok(_) => {
                self.log_action(&format!("📄 Exported: {}", path.display()));
                self.status = format!("Results saved: {}", path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default());
            }
            Err(e) => self.error_msg = Some(format!("Save error: {e}")),
        }
    }

    fn pattern_desc_for_export(&self) -> String {
        if self.syntax_mode == "File" {
            return self.file_field.trim().to_string();
        }
        let lines = self.current_pattern_lines();
        lines.join(" ; ")
    }

    // ================= LOGGING =================

    fn push_log(&mut self, text: String, color: Color32, bold: bool) {
        self.log_lines.push(LogLine {
            ts: timefmt::now_hms(),
            text,
            color,
            bold,
        });
        // Keep the on-screen log bounded (rendering stays fast).
        if self.log_lines.len() > 100_000 {
            let drop = self.log_lines.len() - 100_000;
            self.log_lines.drain(0..drop);
        }
    }

    fn log_action(&mut self, message: &str) {
        if self.log_config.log_actions {
            self.push_log(message.to_string(), theme::TEXT_MAIN, false);
        }
    }

    fn log_result(&mut self, label: &str, addr: &str, color: Color32, time_ms: u64) {
        let text = format!("{}  {}   ({} ms)", label, addr, time_ms);
        self.push_log(text, color, true);
        storage::scan(&format!("{} {} ({} ms)", label.trim(), addr, time_ms));
    }

    fn log_external(&mut self, ip: &str, port: u16, result: scanner::PortResult, time_ms: u64) {
        let open = result == scanner::PortResult::Open;
        let timeout = result == scanner::PortResult::Timeout;
        let public = ip_utils::is_public(ip);
        let lan = ip_utils::is_same_lan(ip);
        let verdict = ip_utils::external_status(ip, open, timeout);
        let color = if lan || !public {
            theme::TEXT_MUTED
        } else if open {
            theme::GREEN
        } else if timeout {
            theme::YELLOW
        } else {
            theme::RED
        };
        let text = format!("🌍 EXTERNAL:  {}:{} — {}   ({} ms)", ip, port, verdict, time_ms);
        self.push_log(text, color, false);
    }

    fn log_mc_result(&mut self, ip: &str, port: u16, probe: &McResult) {
        self.push_log(
            format!("✅ MC-SERVER  {}:{}   ({} ms)", ip, port, probe.latency_ms),
            theme::GREEN,
            true,
        );
        let version = if probe.version.is_empty() { "?" } else { &probe.version };
        let mut det = format!("     🎮 Version: {}", version);
        if !probe.brand.is_empty() {
            det.push_str(&format!("   🎯 Brand: {}", probe.brand));
        }
        det.push_str(&format!("   👤 Players: {}/{}", probe.online, probe.max));
        if probe.has_favicon {
            det.push_str("   🖼 Icon");
        }
        self.push_log(det, theme::TEXT_MAIN, false);
        if !probe.motd.is_empty() {
            self.push_log(format!("     📢 {}", probe.motd), theme::YELLOW, false);
        }
        storage::scan(&format!(
            "MC-SERVER {}:{} version={} brand={} players={}/{}",
            ip, port, probe.version, probe.brand, probe.online, probe.max
        ));
    }

    fn clear_all(&mut self) {
        self.log_lines.clear();
        self.open_results.clear();
        self.mc_results.clear();
        self.open_count = 0;
        self.closed_count = 0;
        self.external_count = 0;
        self.scanned = 0;
        self.progress_pct = 0.0;
        self.status = "Log cleared".to_string();
    }

    // ================= PATTERNS / SCALE =================

    fn current_pattern_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        match self.syntax_mode.as_str() {
            "List" => {
                for l in self.list_area.lines() {
                    let t = l.trim();
                    if !t.is_empty() {
                        lines.push(t.to_string());
                    }
                }
            }
            "File" => {
                let path = self.file_field.trim();
                if !path.is_empty() {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        for l in content.lines() {
                            let t = l.trim();
                            if !t.is_empty() {
                                lines.push(t.to_string());
                            }
                        }
                    }
                }
            }
            _ => {
                let t = self.ip_pattern.trim();
                if !t.is_empty() {
                    lines.push(t.to_string());
                }
            }
        }
        lines
    }

    fn update_scale(&mut self) {
        // Only recompute when the relevant inputs changed.
        let fp = format!(
            "{}|{}|{}|{}|{}|{}",
            self.syntax_type,
            self.syntax_mode,
            self.use_cidr,
            self.ip_pattern,
            self.list_area,
            self.file_field
        );
        if fp == self.last_syntax_fingerprint {
            return;
        }
        self.last_syntax_fingerprint = fp;

        if self.syntax_mode == "File" {
            let path = self.file_field.trim();
            if path.is_empty() || !std::path::Path::new(path).exists() {
                self.scale_valid = false;
                self.scale_count = 0;
                return;
            }
        }

        let raw = self.current_pattern_lines();
        let mut converted = Vec::new();
        let mut ok = !raw.is_empty();
        for line in &raw {
            match syntax_conv::to_regex(Some(line), &self.syntax_type, self.use_cidr) {
                Some(c) => converted.push(c),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok || !ip_pattern::structure_ok_all(&converted, self.use_cidr) {
            self.scale_valid = false;
            self.scale_count = 0;
            return;
        }
        self.scale_count = ip_pattern::count_ips_all(&converted, self.use_cidr);
        self.scale_valid = self.scale_count > 0;
    }

    // ================= SETTINGS =================

    fn load_settings(&mut self) {
        if let Some(p0) = storage::get_opt("syntax.pattern") {
            match self.syntax_mode.as_str() {
                "List" => self.list_area = p0,
                "File" => self.file_field = p0,
                _ => self.ip_pattern = p0,
            }
        }
        if let Some(port) = storage::get_opt("syntax.port") {
            self.port_field = port;
        }
        if let Some(timeout) = storage::get_opt("syntax.timeout") {
            if !timeout.trim().is_empty() {
                self.timeout_field = timeout;
            }
        }
        let cores = available_cores();
        self.parse_threads = clamp(storage::get_int("syntax.parseThreads", self.parse_threads as i64), 1, cores as i64) as usize;
        self.gen_threads = clamp(storage::get_int("syntax.genThreads", self.gen_threads as i64), 1, cores as i64) as usize;
        self.net_threads = clamp(storage::get_int("syntax.netThreads", self.net_threads as i64), 1, 1024) as usize;

        if let Some(mode) = storage::get_opt("syntax.inputMode") {
            let m = mode.to_lowercase();
            if m == "list" {
                self.syntax_mode = "List".to_string();
            } else if m == "file" {
                self.syntax_mode = "File".to_string();
            } else {
                self.syntax_mode = "Single".to_string();
            }
        }
        if let Some(t) = storage::get_opt("syntax.type") {
            if ["ip", "wildcard", "regex"].contains(&t.as_str()) {
                self.syntax_type = t;
            }
        }
        self.use_cidr = storage::get_bool("syntax.cidr", self.use_cidr);
        let mode_idx = storage::get_int("syntax.modeIndex", 0);
        self.mc_mode = if mode_idx == 1 { McMode::Minecraft } else { McMode::Telnet };

        self.log_config = LogConfig::load();
        self.update_scale();
    }

    fn save_settings(&self) {
        let p0 = match self.syntax_mode.as_str() {
            "List" => self.list_area.clone(),
            "File" => self.file_field.trim().to_string(),
            _ => self.ip_pattern.trim().to_string(),
        };
        storage::set("syntax.pattern", &p0);
        storage::set("syntax.port", self.port_field.trim());
        storage::set("syntax.timeout", self.timeout_field.trim());
        storage::set_int("syntax.parseThreads", self.parse_threads as i64);
        storage::set_int("syntax.genThreads", self.gen_threads as i64);
        storage::set_int("syntax.netThreads", self.net_threads as i64);
        storage::set_bool("syntax.cidr", self.use_cidr);
        storage::set("syntax.inputMode", &self.syntax_mode.to_lowercase());
        storage::set("syntax.type", &self.syntax_type);
        storage::set_int("syntax.modeIndex", if self.mc_mode == McMode::Minecraft { 1 } else { 0 });
        self.log_config.save();
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // 1 Hz perf monitor tick.
        if self.last_perf.elapsed() >= Duration::from_secs(1) {
            perf::tick_rates();
            self.last_perf = Instant::now();
        }

        // Update the live scale when any syntax input changed.
        self.update_scale();

        // Drain scanner events (non-blocking).
        self.drain_scan();

        // Keep repainting while a scan runs so events/status stay live.
        if self.scan.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }

        self.build_ui(ui);
        self.show_dialogs(&ctx);
    }

    fn on_exit(&mut self) {
        if let Some(h) = &self.scan {
            h.stop();
        }
        self.save_settings();
        storage::close();
    }
}

// ================= HELPERS =================

fn available_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(1)
}

fn clamp(v: i64, lo: i64, hi: i64) -> i64 {
    v.clamp(lo, hi)
}

fn muted_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TEXT_MUTED));
}

fn stat(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.label(RichText::new(text).color(color).strong());
}

/// Rounded, dark panel with the given background color.
fn panel(ui: &mut egui::Ui, color: Color32, radius: u8, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .fill(color)
        .corner_radius(radius)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, add);
}

// ================= GAUGES =================

fn draw_gradient_bar(ui: &mut egui::Ui, rect: egui::Rect, position: f64) {
    let painter = ui.painter();
    let n = 64i32;
    let w = rect.width() / n as f32;
    for i in 0..n {
        let t = i as f64 / (n - 1) as f64;
        let color = theme::gradient_color(t);
        let x = rect.left() + i as f32 * w;
        painter.rect_filled(
            egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(w + 1.0, rect.height())),
            0.0,
            color,
        );
    }
    // marker
    let mx = rect.left() + rect.width() * position.clamp(0.0, 1.0) as f32;
    painter.rect_filled(
        egui::Rect::from_min_size(
            egui::pos2(mx - 1.0, rect.top() - 3.0),
            egui::vec2(2.0, rect.height() + 6.0),
        ),
        0.0,
        Color32::BLACK,
    );
}

fn ip_scale(ui: &mut egui::Ui, structure_ok: bool, count: u64) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(150.0, 30.0), egui::Sense::hover());
    let valid = structure_ok && count > 0;
    if !structure_ok {
        let painter = ui.painter();
        painter.rect_filled(rect, 6.0, theme::BG_PANEL_2);
        painter.text(
            egui::pos2(rect.left() + 4.0, rect.bottom() - 2.0),
            egui::Align2::LEFT_BOTTOM,
            "no scale",
            egui::FontId::proportional(9.0),
            theme::TEXT_MUTED,
        );
        return;
    }
    if !valid {
        let painter = ui.painter();
        painter.rect_filled(rect, 6.0, theme::BG_PANEL_2);
        painter.text(
            egui::pos2(rect.left() + 4.0, rect.bottom() - 2.0),
            egui::Align2::LEFT_BOTTOM,
            "no scale",
            egui::FontId::proportional(9.0),
            theme::TEXT_MUTED,
        );
        return;
    }
    draw_gradient_bar(ui, rect, theme::ip_position(count));

    // Right-side text.
    let band = band_for_count(count);
    let count_str = format_count(count);
    let count_color = theme::gradient_color(theme::ip_position(count));
    ui.vertical(|ui| {
        ui.label(RichText::new(count_str).color(count_color).strong());
        ui.label(RichText::new(band).color(theme::TEXT_MUTED).size(11.0));
    });
}

fn thread_scale(ui: &mut egui::Ui, value: usize) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(110.0, 22.0), egui::Sense::hover());
    let pos = ((value as f64 - 1.0) / 1023.0).clamp(0.0, 1.0);
    draw_gradient_bar(ui, rect, pos);
    let band = thread_band(value);
    let color = theme::gradient_color(pos);
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{value} network threads")).color(color).strong());
        });
        ui.label(RichText::new(band).color(theme::TEXT_MUTED).size(11.0));
    });
}

fn progress_bar(ui: &mut egui::Ui, pct: f64, size: egui::Vec2) {
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter();
    let left = rect.left() + 8.0;
    let right = rect.right() - 8.0;
    let bar_y = rect.top() + 12.0;
    let bar_h = 14.0;
    let bar_w = right - left;

    // track
    painter.rect_filled(
        egui::Rect::from_min_size(egui::pos2(left, bar_y), egui::vec2(bar_w, bar_h)),
        bar_h / 2.0,
        theme::BG_FIELD,
    );
    painter.rect_stroke(
        egui::Rect::from_min_size(egui::pos2(left, bar_y), egui::vec2(bar_w, bar_h)),
        bar_h / 2.0,
        Stroke::new(1.0, theme::BORDER),
        egui::StrokeKind::Outside,
    );

    // fill
    let fill_w = bar_w * (pct.clamp(0.0, 100.0) / 100.0) as f32;
    if fill_w > 0.0 {
        painter.rect_filled(
            egui::Rect::from_min_size(egui::pos2(left, bar_y), egui::vec2(fill_w.min(bar_w), bar_h)),
            bar_h / 2.0,
            Color32::from_rgb(250, 200, 90),
        );
    }
    // leading white edge
    let mx = (left + fill_w).clamp(left + 1.0, right - 1.0);
    painter.rect_filled(
        egui::Rect::from_min_size(egui::pos2(mx - 1.0, bar_y + 1.0), egui::vec2(2.0, bar_h - 2.0)),
        0.0,
        Color32::WHITE,
    );

    // percentage text
    let pct_str = format!("{pct:.3}%");
    painter.text(
        egui::pos2(left + bar_w / 2.0, bar_y + bar_h / 2.0),
        egui::Align2::CENTER_CENTER,
        pct_str,
        egui::FontId::proportional(11.0),
        Color32::from_rgb(20, 21, 30),
    );
}

fn band_for_count(count: u64) -> &'static str {
    if count <= 10_000 {
        "Normal - quick scan"
    } else if count <= 100_000 {
        "Normal - a minute or two"
    } else if count <= 1_000_000 {
        "Elevated - may take several minutes"
    } else if count <= 10_000_000 {
        "High - may take tens of minutes"
    } else if count <= 100_000_000 {
        "Very high - may take hours"
    } else if count <= 1_000_000_000 {
        "Extreme - may take many hours"
    } else {
        "Massive - may take days"
    }
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1} B IPs", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1} M IPs", n as f64 / 1_000_000.0)
    } else {
        format!("{} IPs", theme::fmt_num(n))
    }
}

fn thread_band(threads: usize) -> &'static str {
    if threads <= 16 {
        "Light"
    } else if threads <= 64 {
        "Normal"
    } else if threads <= 256 {
        "Heavy - many sockets"
    } else {
        "Very heavy - may exhaust sockets"
    }
}

fn validate_port_spec(spec: &str) -> Option<String> {
    let s = spec.trim();
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() > 2 {
        return Some("Invalid port range (too many '-').\nUse: 2000  or  2000-2010".to_string());
    }
    for p in parts {
        let t = p.trim();
        if t.is_empty() {
            return Some(format!("Invalid port: '{s}'.\nUse: 2000  or  2000-2010"));
        }
        let v: i64 = match t.parse() {
            Ok(v) => v,
            Err(_) => {
                return Some(format!(
                    "Invalid port: '{t}'.\nMust be a number between 1 and 65535."
                ));
            }
        };
        if !(1..=65535).contains(&v) {
            return Some(format!(
                "Port {v} is out of range.\nPorts must be between 1 and 65535."
            ));
        }
    }
    None
}

// ================= SETTINGS DIALOGS =================

fn ip_settings_dialog(app: &mut App, ui: &mut egui::Ui) -> bool {
    egui::Grid::new("ip_settings_grid")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            muted_label(ui, "Type");
            egui::ComboBox::from_id_salt("ip_type")
                .selected_text(app.syntax_type.as_str())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.syntax_type, "ip".to_string(), "ip");
                    ui.selectable_value(&mut app.syntax_type, "wildcard".to_string(), "wildcard");
                    ui.selectable_value(&mut app.syntax_type, "regex".to_string(), "regex");
                });
            ui.end_row();

            muted_label(ui, "Input mode");
            egui::ComboBox::from_id_salt("ip_mode")
                .selected_text(app.syntax_mode.as_str())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.syntax_mode, "Single".to_string(), "Single");
                    ui.selectable_value(&mut app.syntax_mode, "List".to_string(), "List");
                    ui.selectable_value(&mut app.syntax_mode, "File".to_string(), "File");
                });
            ui.end_row();

            muted_label(ui, "Use CIDR");
            let mut cidr_yes = app.use_cidr;
            egui::ComboBox::from_id_salt("ip_cidr")
                .selected_text(if cidr_yes { "yes" } else { "no" })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut cidr_yes, false, "no");
                    ui.selectable_value(&mut cidr_yes, true, "yes");
                });
            app.use_cidr = cidr_yes;
            ui.end_row();
        });

    // hint
    let cidr_hint = if app.use_cidr {
        "  |  CIDR: 95.31.158.9/24 or 95.31.***.*/8"
    } else {
        ""
    };
    let hint = match app.syntax_type.as_str() {
        "ip" => format!("Full IP, e.g. 95.31.158.9{}", cidr_hint),
        "wildcard" => format!("* = any number, e.g. 95.31.***.*{}", cidr_hint),
        _ => format!("Java regex, e.g. ^95\\.31\\.\\d{{1,3}}\\.\\d${}", cidr_hint),
    };
    ui.add_space(8.0);
    ui.label(RichText::new(hint).color(theme::TEXT_MUTED).size(11.0));

    ui.add_space(8.0);
    let mut close = false;
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui
                .button(RichText::new("Cancel").color(theme::TEXT_MAIN))
                .clicked()
            {
                close = true;
            }
            if ui
                .button(RichText::new("Apply").color(Color32::WHITE))
                .clicked()
            {
                app.save_settings();
                app.update_scale();
                close = true;
            }
        });
    });
    close
}

fn log_settings_dialog(app: &mut App, ui: &mut egui::Ui) -> bool {
    let mut config = app.log_config.clone();

    ui.columns(2, |cols| {
        panel(&mut cols[0], theme::BG_PANEL, 12, |ui| {
            ui.label(RichText::new("Logs settings").color(theme::ACCENT).strong());
            ui.add_space(4.0);
            ui.checkbox(&mut config.log_open, "Log available IP/Port connections");
            ui.checkbox(&mut config.log_closed, "Log closed IP/Port connections");
            ui.checkbox(&mut config.log_timeout, "Log timed out IP/Port connections");
            ui.checkbox(&mut config.log_error, "Log errored IP/Port connections");
            ui.checkbox(&mut config.log_actions, "Log actions (e.g. change IP regex)");
            ui.checkbox(&mut config.external, "Status 2: port reachable from outside (public IP)");
        });

        panel(&mut cols[1], theme::BG_PANEL, 12, |ui| {
            ui.label(RichText::new("MC-probe log filter").color(theme::ACCENT).strong());
            ui.add_space(4.0);

            // online
            filter_row_online(ui, &mut config.mc);
            // version
            filter_row_version(ui, &mut config.mc);
            // brand
            filter_row_brand(ui, &mut config.mc);
            // motd
            filter_row_motd(ui, &mut config.mc);
            // players
            filter_row_players(ui, &mut config.mc);

            ui.add_space(4.0);
            ui.label(
                RichText::new("Empty value = filter disabled.\nOperators: is / above / below / in-range.")
                    .color(theme::TEXT_MUTED)
                    .size(11.0),
            );
        });
    });

    ui.add_space(8.0);
    let mut close = false;
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui
                .button(RichText::new("Cancel").color(theme::TEXT_MAIN))
                .clicked()
            {
                close = true;
            }
            if ui
                .button(RichText::new("Apply").color(Color32::WHITE))
                .clicked()
            {
                app.log_config = config;
                app.save_settings();
                close = true;
            }
        });
    });
    close
}

fn filter_row_online(ui: &mut egui::Ui, mc: &mut FilterSettings) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut mc.online, "Log if online");
        egui::ComboBox::from_id_salt("f_online_op")
            .selected_text(mc.online_op.as_str())
            .show_ui(ui, |ui| {
                for op in filters::OPERATORS {
                    ui.selectable_value(&mut mc.online_op, op.to_string(), op);
                }
            });
        ui.add(
            egui::TextEdit::singleline(&mut mc.online_val)
                .desired_width(70.0)
                .hint_text("5 or 10-30"),
        );
    });
}

fn filter_row_version(ui: &mut egui::Ui, mc: &mut FilterSettings) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut mc.version, "Log if version");
        egui::ComboBox::from_id_salt("f_version_op")
            .selected_text(mc.version_op.as_str())
            .show_ui(ui, |ui| {
                for op in filters::OPERATORS {
                    ui.selectable_value(&mut mc.version_op, op.to_string(), op);
                }
            });
        ui.add(
            egui::TextEdit::singleline(&mut mc.version_val)
                .desired_width(100.0)
                .hint_text("1.21.1-1.21.4"),
        );
    });
}

fn filter_row_brand(ui: &mut egui::Ui, mc: &mut FilterSettings) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut mc.brand, "Log if brand name contains");
        ui.add(
            egui::TextEdit::singleline(&mut mc.brand_val)
                .desired_width(120.0)
                .hint_text("Leaf|Paper"),
        );
    });
}

fn filter_row_motd(ui: &mut egui::Ui, mc: &mut FilterSettings) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut mc.motd, "Log if MOTD contains");
        ui.add(
            egui::TextEdit::singleline(&mut mc.motd_val)
                .desired_width(120.0)
                .hint_text("\\bAnarchy\\b"),
        );
    });
}

fn filter_row_players(ui: &mut egui::Ui, mc: &mut FilterSettings) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut mc.players, "Log if player list contains");
        ui.add(
            egui::TextEdit::singleline(&mut mc.players_val)
                .desired_width(120.0)
                .hint_text("Notch"),
        );
    });
}

// ================= ENTRY POINT =================

fn main() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("IP Parser - IP and port scanner")
        .with_inner_size([860.0, 700.0])
        .with_min_inner_size([700.0, 560.0]);

    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../resources/app-icon.png")) {
        viewport = viewport.with_icon(Arc::new(icon));
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        &format!("IP Parser v{}", version::VERSION),
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
