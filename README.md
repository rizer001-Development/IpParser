# IpParser

![Java](https://img.shields.io/badge/Java-17%2B-orange)
![Build](https://img.shields.io/badge/build-Gradle-green)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

> An open-source IP parser for quickly and efficiently checking a huge number of IP addresses.

**IpParser** — a portable IP-range TCP port scanner with a dark-themed Swing GUI. It expands a Java regex (or a CIDR block) into IPv4 addresses and checks the specified TCP port(s) on each. It can also ping Minecraft servers via the official Server List Ping protocol and show MOTD, version, online players and brand.

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
- **Maximum speed**: three independent thread pools (generation → network → parsing), up to **1024** network threads.
- **Lazy address generation** — even `0.0.0.0/0` does not freeze the UI.
- **Process monitor**: CPU, RAM, in/out traffic in real time.
- **Minecraft log filters** (online / version / brand / MOTD / player list).
- **Export results** to `.txt`.
- **SQLite settings database** — persisted in the app's own `data/settings.db`.
- **Per-scan log files** in `logs/`, next to a central `ipparser-app.log`.

---

## Requirements

- **Java 17 or newer** (JRE is enough to run; a JDK is needed to build).
- **No external libraries at runtime** — everything (including SQLite) is bundled into a single fat JAR.

---

## Building

The project uses **Gradle** (wrapper committed, so no local Gradle install is needed):

```bash
./gradlew build          # compile + tests + fat JAR + portable layout (& zip)
./gradlew test           # run the unit tests only
./gradlew assemblePortable   # rebuild just the portable folder + zip
```

Artifacts:
- `build/libs/ip-parser-all.jar` — single executable fat JAR (SQLite bundled).
- `build/portable/ip-parser-<version>/` — self-contained portable folder.
- `build/portable/ip-parser-<version>-portable.zip` — archived portable folder.

---

## Running (portable)

The portable folder produced by Gradle is fully self-contained:

```
ip-parser-<version>/
  ip-parser-<version>-all.jar   application (SQLite bundled)
  run.bat / run.sh              launchers
  logs/                         auto-created log files
  data/                         auto-created SQLite DB (settings.db)
```

- **Windows**: double-click `run.bat`.
- **Linux / macOS**: `chmod +x run.sh && ./run.sh`.

The program **never writes to the current working directory**. Its own home is
the folder the JAR lives in (or the `-Dipparser.home=` folder set by the
launchers), so you can move the whole folder anywhere — it keeps its own
settings and logs with it.

---

## Architecture

A layered project under `src/main/java/dev/ipparser/`:

| Layer | Package | Purpose |
|---|---|---|
| `core` | `dev.ipparser.core` | `AppPaths` (own home dir), `IpUtils`, `PerfMonitor`, `Version` |
| `pattern` | `dev.ipparser.pattern` | `IpPattern` (regex/CIDR expansion), `SyntaxConv` (type conversion) |
| `probe` | `dev.ipparser.probe` | `McProbe` (Minecraft Server List Ping protocol) |
| `scanner` | `dev.ipparser.scanner` | `AbstractScanner` (shared 3-stage pipeline), `PortScanner`, `McProbeScanner` |
| `storage` | `dev.ipparser.storage` | `AppDb` (SQLite settings), `FileLog` (per-scan logs) |
| `gui` | `dev.ipparser.gui` | `Main`, `IpParserFrame`, theme, dialogs, filters (`McFilters`), export (`Export`) |
| `gui.components` | `dev.ipparser.gui.components` | custom Swing widgets (buttons, gauges, progress bar) |

### Scan pipeline

```
[Generators (CPU)] → bounded task queue (8192) → [Network workers (≤1024)] → bounded result queue → [Parsers (CPU)] → GUI + FileLog
```

Generators, network workers and parsers run simultaneously; blocking `put` into
bounded queues provides natural backpressure — no busy-waiting, constant memory,
UI never blocked.

### Persistence

- **SQLite** (`data/settings.db`, via the bundled `org.xerial:sqlite-jdbc`)
  replaces the old plain-text `settings.txt`. `AppDb` is a thread-safe key/value
  store; `LogConfig` groups the GUI's log/filter settings.
- **Logs** (`logs/`): a central `ipparser-app.log` plus a dedicated
  `scan-<timestamp>.log` per scan, written by `FileLog`.

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

Unit tests live under `src/test/java` and cover:

- `IpPattern` — CIDR counts/alignment, regex expansion, alternation, invalid input.
- `SyntaxConv` — ip / wildcard / regex conversion, CIDR on/off.
- `PortScanner.parsePorts` — single/range/clamping/garbage.
- `McProbe` — color-code stripping and JSON unescaping.
- `McFilters` — online/version/brand/MOTD/player filters.
- `Export` — result-file content.
- `Storage` — SQLite round-trip and per-scan file logs in a sandboxed home.

Run them with `./gradlew test`.

---

## License

[GNU AGPL v3.0](LICENSE).