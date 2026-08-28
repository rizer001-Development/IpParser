# Changelog — IP Parser

All notable changes to the **IP Parser** project are documented in this file.

---

## [Release-1.1](https://github.com/your-repo/releases/tag/v1.1) — 2026-08-23

### 🐛 Bug Fixes

- **Fixed `mcFilterPlayers` settings not being loaded from file** (`IpParserGUI.java`)
  - `saveSettings()` wrote the player-name filter (`mcFilterPlayers`, `mcFilterPlayersVal`) at indices 24–25 of `settings.txt`, but `loadSettings()` skipped those lines — jumping directly from index 23 (mcFilterMotd) to indices 26–27 (syntaxType / useCidr).
  - **Result:** the MC-probe player-name filter was silently reset to disabled on every application restart.
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

## [Unreleased / Pre-1.1] — Project Features

### Core Functionality
- **IP range expansion** from regex patterns, CIDR blocks, and wildcard syntax
- **Three input types:** `ip` (literal), `wildcard` (`*` = any octet), `regex` (Java regex)
- **Three input modes:** Single pattern, List (multi-line), File (one pattern per line)
- **CIDR support:** e.g. `95.31.0.0/16`, `10.0.0.0/8`, `95.31.***.*/8`
- **Live IP-count scale** with color-coded gauge (green → red gradient)

### Scanning
- **Multithreaded TCP port scanner** with three independent thread pools:
  - Generators (CPU) — expand regex/CIDR into IP:port targets
  - Network workers (I/O) — open TCP sockets (up to 1024)
  - Parsers (CPU) — process results, update UI
- **Bounded task queues** for natural backpressure — no busy waiting, no memory blow-up
- **Minecraft Server List Ping** probe (version, MOTD, players, brand, favicon)
- **Configurable timeout** per connection (50–60000 ms)
- **Port range support** (e.g. `2000-2010`)

### Filtering & Logging
- **Log settings dialog** — toggle logging of open / closed / timeout / error results
- **MC-probe log filters** — filter by online count, version, brand, MOTD, player list
- **Status 2** — external availability verdict (public IP + port forwarding detection)
- **Colored log output** with timestamps and styled results

### UI / UX
- **Dark theme** (Swing, custom painting)
- **Progress bar** with ETA, percentage, and tick marks
- **Real-time system monitor** — CPU, RAM, incoming/outgoing traffic
- **Thread count scale** with color-coded gauge
- **Export results** to `.txt` with full scan metadata
- **Settings persistence** in `settings.txt`

### Platform
- Portable — no external dependencies, pure JDK
- Launch scripts: `launch.bat` (Windows), `launch.vbs` (silent Windows launch)
- Build script: `build.bat`

---

## [2.0.0] — 2026-08-28

### 🏗 Major re-architecture

- **Gradle build** (wrapper committed, ShadowJar fat JAR) replaces the raw
  `javac`/`build.bat` workflow. `./gradlew build` runs tests and produces a
  single executable JAR.
- **Layered package structure** under `dev.ipparser`: `core`, `pattern`,
  `probe`, `scanner`, `storage`, `gui`, `gui.components`.
- **Monolithic window split** — `IpParserGUI` (2 444 lines) decomposed into
  `IpParserFrame`, `Theme`, `McFilters`, `Export`, `LogSettingsDialog`,
  `IpSettingsDialog`, and the custom components package. The dark UI is kept.

### 🔧 Bug fixes

- **Race on scan counters**: `openCount`/`closedCount`/`externalCount` were
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
- **Portable home resolution** (`AppPaths`): the app never writes to the CWD -
  everything lands under `data/` and `logs/` next to the JAR (or `-Dipparser.home=`).
- **Gradle portable tasks**: `assemblePortable` builds a self-contained folder
  (`build/portable/ip-parser-<version>/`) with `run.bat`/`run.sh` and zips it.

### 🧪 Tests

- First test suite (JUnit 5): `IpPattern`, `SyntaxConv`, `PortScanner.parsePorts`,
  `McProbe`, `McFilters`, `Export`, `Storage` (SQLite + FileLog). 45 tests.

---

## [1.0] — Initial Release

- Initial commit with full IP Parser codebase
- TCP port scanner, Minecraft probe, Swing dark-theme GUI
- README and LICENSE
