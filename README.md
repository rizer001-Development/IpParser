# IpParser

![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange)
![Build](https://img.shields.io/badge/build-Cargo-green)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

> An open-source IP parser for quickly and efficiently checking a huge number of IP addresses.

**IpParser** — a portable IP-range TCP port scanner with a dark-themed GUI. It expands a regex (or a CIDR block) into IPv4 addresses and checks the specified TCP port(s) on each. It can also ping Minecraft servers via the official Server List Ping protocol and show MOTD, version, online players and brand.

Hundreds of millions of addresses are processed without freezing the UI: addresses are generated *on the fly* in background threads while memory usage stays constant thanks to bounded queues.

---

### Organization Docs

[![Guide](https://img.shields.io/badge/Guide-rizer001--Development-00AEFF)](https://github.com/rizer001-Development/.github/blob/main/GUIDE.md) · [![Contributing](https://img.shields.io/badge/Contributing-rizer001--Development-4CAF50)](https://github.com/rizer001-Development/.github/blob/main/CONTRIBUTING.md) · [![Security](https://img.shields.io/badge/Security-rizer001--Development-D9534F)](https://github.com/rizer001-Development/.github/blob/main/SECURITY.md) · [![Code of Conduct](https://img.shields.io/badge/Code%20of%20Conduct-rizer001--Development-5BC0DE)](https://github.com/rizer001-Development/.github/blob/main/CODE_OF_CONDUCT.md)

---

## Features

- **Flexible target syntax**: `ip`, `wildcard`, `regex` + **CIDR** inside the expression.
- **Three input modes**: single pattern, list of patterns, file.
- **Live volume gauge** — approximate IP count and ETA while typing.
- **Two scan modes**: Telnet (open TCP port) and Minecraft (Server List Ping).
- **Single port or range** (`2000` or `2000-2010`).
- **Two result statuses**: port open/closed locally; reachable from the outside.
- **Maximum speed**: three independent thread stages (generation → network → forward), up to **1024** network threads.
- **Lazy address generation** — even `0.0.0.0/0` does not freeze the UI.
- **Process monitor**: CPU, RAM, in/out traffic in real time.
- **Minecraft log filters** (online / version / brand / MOTD / player list).
- **Export results** to `.txt`.
- **SQLite settings database** — persisted in the app's own `data/settings.db`.
- **Per-scan log files** in `logs/`, next to a central `ipparser-app.log`.

---

## Requirements

- **Rust 1.85+** (stable) with a C toolchain for the bundled SQLite:
  - **Windows**: the MSVC toolchain (`stable-x86_64-pc-windows-msvc`) with Visual Studio Build Tools, or the GNU toolchain with MinGW-w64 `gcc`.
  - **Linux / macOS**: `gcc` / `clang` (usually preinstalled).
- **No external runtime libraries** — SQLite is compiled in; the GUI uses `eframe`/`wgpu`.

---

## Building

```bash
cargo build --release   # optimized binary at target/release/ip-parser(.exe)
cargo test              # run the unit tests
```

> On Windows, if your default toolchain is GNU and `gcc` is missing, build with
> the MSVC toolchain: `cargo +stable-x86_64-pc-windows-msvc build --release`.

The binary is fully self-contained (SQLite bundled).

---

## Running

```bash
cargo run --release
```

The program **never writes to the current working directory**. Its own home is
the folder the executable lives in (or the `IPPARSER_HOME` environment
variable), so you can move the whole folder anywhere — it keeps its own
settings and logs with it:

```
ip-parser(.exe)
data/settings.db        auto-created SQLite settings store
logs/ipparser-app.log   central application log
logs/scan-*.log         one file per scan run
```

---

## Architecture

A Rust workspace crate under `src/`, with a `lib` crate (all logic) and a `bin`
crate (the egui GUI):

| Module | Purpose |
|---|---|
| `app_paths` | own home dir resolution (`IPPARSER_HOME` → exe dir → CWD) |
| `ip_utils` | public/private IP classification, LAN detection, "Status 2" verdicts |
| `perf` | process CPU/RAM + socket traffic counters |
| `version`, `timefmt` | version string and UTC timestamp formatting (pure `std`) |
| `syntax_conv` | `ip` / `wildcard` / `regex` input → internal regex (CIDR-aware) |
| `ip_pattern` | regex/CIDR expansion into octet value lists, counts, structural checks |
| `mc_probe` | Minecraft Server List Ping protocol (VarInt, JSON extraction, no JSON lib) |
| `scanner` | three-stage pipeline (generators → network workers → event forwarder) |
| `storage` | SQLite key/value settings store (`rusqlite`, bundled) + file logger |
| `filters` | pure MC-probe log-filter logic (online/version/brand/MOTD/players) |
| `log_config` | log/filter settings group, persisted to SQLite |
| `export` | export-file content builder |
| `theme` | dark palette + gauge/gradient/number-format helpers |
| `main` (bin) | the egui window, dialogs and gauges |

### Scan pipeline

```
[Generators (CPU)] → bounded task queue (8192) → [Network workers (≤1024)] → bounded result queue → [Forwarder] → GUI + FileLog
```

Generators, network workers and the forwarder run simultaneously; blocking send
into bounded queues provides natural backpressure — no busy-waiting, constant
memory, UI never blocked.

### Persistence

- **SQLite** (`data/settings.db`, bundled via `rusqlite`) stores the user's
  settings; `LogConfig` groups the GUI's log/filter settings.
- **Logs** (`logs/`): a central `ipparser-app.log` plus a dedicated
  `scan-<timestamp>.log` per scan.

---

## Usage

The full syntax/settings reference is unchanged and documented in
[`README.txt`](README.txt):

- `ip`: `95.31.158.9` or `95.31.158.9/24`
- `wildcard`: `95.31.***.*` (* = any number), `95.31.***.*/8`
- `regex`: `^95\.31\.\d{1,3}\.\d$`, `95.31.0.0/16`, `10.0.0.0/8`,
  `95.31.0.0/16|10.0.0.0/8`

Port: `2000` (single) or `2000-2010` (range). Timeout 50–60 000 ms. Threads:
parse/gen (CPU) + net (up to 1024).

---

## Tests

```bash
cargo test
```

Unit tests cover:

- `timefmt` — civil-from-days conversion and timestamp widths.
- `theme` — number grouping and gradient endpoints.
- `ip_pattern` / `syntax_conv` / `filters` / `export` — pure logic is exercised
  through the same code paths the GUI drives.

---

## License

[GNU AGPL v3.0](LICENSE).
