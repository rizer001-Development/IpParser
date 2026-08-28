# Changelog — IP Parser

All notable changes to the **IP Parser** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Repo: [rizer001-Development/IpParser](https://github.com/rizer001-Development/IpParser)

---

## [Unreleased]

### Planned
- NIO networking layer (`SocketChannel` + `Selector`) for the network workers.
- Migration of legacy `settings.txt` into the SQLite store on first run.
- Headless CLI mode (`--scan`, `--export`) for scripting / CI.
- GitHub Actions CI: build + test 45 tests + publish portable zip on tags.

---

## [2.0.0] — 2026-08-28

### 🏗 Major re-architecture
- **Gradle build** (wrapper committed, ShadowJar fat JAR) replaces the raw
  `javac` / `build.bat` workflow. `./gradlew build` runs tests and produces a
  single executable JAR.
- **Layered package structure** under `dev.ipparser`: `core`, `pattern`,
  `probe`, `scanner`, `storage`, `gui`, `gui.components`.
- **Monolithic window split** — `IpParserGUI` (2 444 lines) decomposed into
  `IpParserFrame`, `Theme`, `McFilters`, `Export`, `LogSettingsDialog`,
  `IpSettingsDialog`, and the custom components package. The dark UI is kept.

### 🔧 Bug fixes
- **Race on scan counters**: `openCount` / `closedCount` / `externalCount` were
  plain `volatile int` incremented from several parser threads, silently losing
  updates. Now `AtomicLong`.
- **Scanner duplication removed**: `PortScanner` and `McProbeScanner` (almost
  identical pipelines) now share a single `AbstractScanner`, each keeping a thin
  `probe(...)` implementation.

### 🗄 Storage / portability
- **SQLite settings store** (`AppDb`, `org.xerial:sqlite-jdbc` bundled)
  replaces the fragile positional `settings.txt`.
- **Dedicated file logs** (`FileLog`): central `ipparser-app.log` plus a
  `scan-<timestamp>.log` per run, both under the app's own `logs/`.
- **Portable home resolution** (`AppPaths`): the app never writes to the CWD —
  everything lands under `data/` and `logs/` next to the JAR (or `-Dipparser.home=`).
- **Gradle portable tasks**: `assemblePortable` builds a self-contained folder
  (`build/portable/ip-parser-<version>/`) with `run.bat` / `run.sh` and zips it.

### 🧪 Tests
- First test suite added (JUnit 5): `IpPattern`, `SyntaxConv`,
  `PortScanner.parsePorts`, `McProbe`, `McFilters`, `Export`,
  `Storage` (SQLite + FileLog). **45 tests.**

---

## [1.1] — 2026-08-23

### 🐛 Bug Fixes
- **Fixed `mcFilterPlayers` settings not being loaded from file** (`IpParserGUI.java`)
  - `saveSettings()` wrote the player-name filter (`mcFilterPlayers`,
    `mcFilterPlayersVal`) at indices 24–25 of `settings.txt`, but `loadSettings()`
    skipped those lines — jumping directly from index 23 (mcFilterMotd) to
    indices 26–27 (syntaxType / useCidr).
  - **Result:** the MC-probe player-name filter was silently reset to disabled
    on every application restart.
  - Added the missing `if (lines.size() >= 26)` block to correctly restore both fields.

### ✅ Codebase Audit (full review)
All core source files were reviewed for correctness, thread-safety, and edge cases:

| File | Status |
|---|---|
| `IpPattern.java` | ✅ No issues — CIDR expansion, regex splitting, anchor handling all correct |
| `PortScanner.java` | ✅ No issues — three-stage pipeline (gen/net/parse) with proper backpressure and graceful stop |
| `McProbeScanner.java` | ✅ No issues — same pipeline architecture, correctly mirrors PortScanner |
| `McProbe.java` | ✅ No issues — MC Server List Ping protocol, VarInt, JSON parsing all correct |
| `IpUtils.java` | ✅ No issues — public/private IP classification covers RFC1918, CGNAT, TEST-NET, multicast |
| `PerfMonitor.java` | ✅ No issues — CPU/RAM/traffic monitoring with atomic counters |
| `SyntaxConv.java` | ✅ No issues — ip / wildcard / regex type conversion with CIDR support |
| `IpParserGUI.java` | 🔧 Fixed (see bug fix above) |

---

## [1.0] — Initial Release

### Features
- **IP range expansion** from regex patterns, CIDR blocks, and wildcard syntax.
- **Three input types:** `ip` (literal), `wildcard` (`*` = any octet), `regex`.
- **Three input modes:** Single pattern, List (multi-line), File (one per line).
- **CIDR support:** e.g. `95.31.0.0/16`, `10.0.0.0/8`, `95.31.***.*/8`.
- **Live IP-count scale** with color-coded gauge (green → red gradient).
- **Multithreaded TCP port scanner**: three independent thread pools
  (generators / network workers / parsers) with bounded queues and backpressure.
- **Minecraft Server List Ping** probe (version, MOTD, players, brand, favicon).
- **Configurable timeout** (50–60000 ms) and **port range** support (`2000-2010`).
- **Log settings & MC-probe log filters** (online / version / brand / MOTD / players).
- **Status 2** — external availability verdict (public IP + port forwarding).
- **Colored log output**, progress bar with ETA, process monitor (CPU/RAM/traffic).
- **Export results** to `.txt` with full scan metadata.
- **Settings persistence** in `settings.txt`.
- **Portable** — no external dependencies, pure JDK; `launch.bat` / `launch.vbs`.

---

[2.0.0]: https://github.com/rizer001-Development/IpParser/releases/tag/v2.0.0
[1.1]: https://github.com/rizer001-Development/IpParser/releases/tag/v1.1
[1.0]: https://github.com/rizer001-Development/IpParser/releases/tag/v1.0