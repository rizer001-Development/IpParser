# IpParser

![Java](https://img.shields.io/badge/Java-8%2B-orange)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

> An open-source IP address parser for quickly and efficiently checking a huge number of IP addresses.

**IpParser** — a portable IP address and TCP port scanner with a graphical user interface (Swing, dark theme). The program expands a Java regular expression (or a CIDR block) into a list of IPv4 addresses and checks whether the specified port (or port range) is open on each of them. It can also ping Minecraft servers using the official Server List Ping protocol and show their MOTD, version, online players and brand.

Hundreds of millions of addresses are processed without freezing: addresses are generated "on the fly" in background threads, while memory usage stays constant thanks to bounded queues.

---

## Features

- 🔢 **Flexible target syntax**: `ip`, `wildcard`, `regex` + **CIDR** block support right inside the expression.
- 📋 **Three input modes**: single pattern, list of patterns, file.
- 📊 **Live volume gauge** — instantly shows the approximate number of IPs and an ETA estimate.
- 🌐 **Two scan modes**:
  - **Telnet (TCP port)** — classic open TCP port check;
  - **Minecraft (mcprobe)** — Server List Ping: version, MOTD, online/max players, favicon, server brand, latency.
- 🚪 **Single port or range** (`2000` or `2000-2010`).
- ✅ **Two result statuses**: status 1 — port open/closed locally; status 2 — whether IP:port is reachable from the outside (public/private IP, no external services).
- ⚡ **Maximum speed**: three independent thread pools (generation → network → parsing), up to **1024** network threads.
- 🧠 **Lazy address generation** — even `0.0.0.0/0` (the whole IPv4, ~4.3 billion addresses) does not freeze the UI.
- 🛡 Confirmation dialog before starting when there are more than **100M** targets.
- 📈 **Process monitor**: CPU, RAM (heap), incoming/outgoing traffic in real time.
- 🔎 **Minecraft log filters**: online, version, brand, MOTD, player list (operators `is / above / below / in-range / out-of-range`).
- 📄 **Export results** to `.txt`.
- 💾 Settings are automatically saved to `settings.txt`.
- 📦 **No external libraries** — standard JDK only.

---

## Requirements

- **Java 8 or newer** (JRE is enough to run, JDK is needed to build).
- No external libraries.

---

## Running (Windows)

Double-click **`launch.bat`** — if the classes are already compiled, the program starts immediately (via `javaw`, the console window closes instantly). On first launch, `launch.bat` calls `build.bat` automatically.

Double-click **`launch.vbs`** — fully silent launch: no console window appears at all.

## Building manually

```bash
javac -encoding UTF-8 -cp . IpPattern.java PortScanner.java IpUtils.java McProbe.java McProbeScanner.java PerfMonitor.java IpParserGUI.java
```

Or simply run **`build.bat`**.

---

## Usage

### Target syntax

The **⚙** button to the right of the "Syntax" field opens the "IP parsing settings" dialog:

| Setting | Options |
|---|---|
| **Type** | `ip` / `wildcard` / `regex` — how to interpret the text in the field |
| **Input mode** | `single` / `list` / `file` — where the patterns come from |
| **Use CIDR** | `no` / `yes` — whether to allow CIDR blocks |

**Type `ip`** — a full IP address: `95.31.158.9` (with CIDR: `95.31.158.9/24`).

**Type `wildcard`** — octets with asterisks, `*` = "any number":
- `95.31.***.*` → any values in the 3rd and 4th octets;
- `95.31.1*0.1` → 100..190 in the 3rd octet (step 10);
- with CIDR: `95.31.***.*/8` — asterisks in the base become 0.

**Type `regex`** — a regular Java regex over IPv4 (4 octets 0-255, separated by dots). Anchors `^` and `$` at the start/end are optional, and the separator can be written as `\.` or as a plain dot.

**Use CIDR** toggles "address/prefix" interpretation. With `CIDR=no`, a `/` in the field is treated as an error.

### Input modes

1. **Single** — one line (a pattern of the selected type).
2. **List** — several patterns, one per line; all results are scanned together:
   ```
   ^95\.31\.\d{1,3}\.\d$
   192\.168\.1\.\d
   10.0.0.0/8
   ```
3. **File** — a file in the same format (one pattern per line); the path is typed into the field or picked with the 📂 button. The file is re-read at scan start.

The gauge on the right sums the IP count over **all** patterns (List/File) according to the selected type and CIDR setting.

### Syntax examples

| Expression | Result | Addresses |
|---|---|---|
| `^95\.31\.\d{1,3}\.\d$` | 95.31.0.0 … 95.31.255.9 | 2,560 |
| `^192\.168\.1\.\d$` | 192.168.1.0 … 192.168.1.9 | 10 |
| `172\.16\.1\d\d\.1` | 172.16.100.1 … 172.16.199.1 | 100 |
| <code>10\.0\.(?:[1-9]&#124;1[0-9])\.\d</code> | 10.0.1-19.0-9 | 190 |
| `192.168.1.0/24` | 192.168.1.0 … 192.168.1.255 | 256 |
| `95\.31\.0\.0/16` | 95.31.0.0 … 95.31.255.255 | 65,536 |
| `^10\.0\.0\.0/8$` | 10.0.0.0 … 10.255.255.255 | 16,777,216 |
| `0.0.0.0/0` | the whole IPv4 | 4,294,967,296 |
| <code>95\.31\.0\.0/16&#124;10\.0\.0\.0/8</code> | both blocks at once | ~16.8M |

Useful regex constructs: `\d` (a single digit), `\d{1,3}` (an octet 0-255), `[0-9]`/`[1-9]` (character classes), `(?:a|b)` (non-capturing alternatives), `\d+` (repetitions).

**CIDR**: prefix from 0 to 32, the base does not have to be aligned (`192.168.1.5/24` → still the whole `192.168.1.0/24` block). There is no limit — a regex expands into any number of addresses, with on-the-fly generation.

**Volume gauge** (updates on every keystroke):

| Volume | Estimate |
|---|---|
| 🟢 up to 10,000 | Normal — quick scan |
| 🟢 10k – 100k | Normal — a minute or two |
| 🟡 100k – 1M | Elevated — may take several minutes |
| 🟠 1M – 10M | High — may take tens of minutes |
| 🔴 10M – 100M | Very high — may take hours |
| 🔴 more than 100M | Extreme — may take many hours |

### Port

- A single port: `2000`
- A range: `2000-2010` (separated by a **hyphen**, no spaces; the program sorts the ports itself if you enter `2010-2000`)

Scan order: all ports of the first IP first, then all ports of the second IP, and so on (IP by IP).

### Scan modes (Mode)

1. **Telnet (TCP port)** — a simple open TCP port check.
2. **Minecraft (mcprobe)** — pings Minecraft servers using the Server List Ping protocol. The log shows the version, MOTD, online/max players, favicon presence and latency. A server that replies with a valid packet is considered open. Default port: **25565**. Port ranges are supported too.

### Two result statuses

- **Status 1 — ACCESS** (always): ✅ `OPEN` / ❌ `CLOSED` / ⏳ `TIMEOUT` / ❓ `ERROR`.
- **Status 2 — FROM OUTSIDE** (enabled in the log settings): whether the IP:port is reachable from the Internet. Everything is determined locally, without external services:
  - 🌍 public IP + open port → reachable from outside (forwarded);
  - 🌍 public IP + closed port → not reachable;
  - 🌍 private IP (grey) / local network address → not reachable from outside at all.

  *Note: not a 100% guarantee (rare exceptions — source-based filtering, hairpin NAT when checking your own public IP).*

### Buttons

| Button | Action |
|---|---|
| ▶ **Start** | start scanning |
| ■ **Stop** | stop scanning |
| 📄 **Export** | save the found open ports to a `.txt` file |
| **Clear log** | clear the log window |
| ⚙ **Settings** | log settings (header of the log window) |

### Settings

- **Timeout (ms)** — port response timeout (default 1500).
- **Threads**:
  - **Parse** — CPU threads that process results (max = number of CPU cores);
  - **Gen** — CPU threads that generate addresses (max = number of CPU cores);
  - **Net** — **network** threads that open connections (up to **1024**, independent of the core count).

Generation, networking and parsing run simultaneously at full speed: generators distribute addresses into a bounded queue (blocking only when the queue is full, no artificial delays).

### Log filters (Minecraft mode)

In the "Log settings" dialog, besides the checkboxes (available/closed/timeouts/errors/actions/Status 2), there are MC filters:

- ☐ Log if **online** — `is/above/below/in-range/out-of-range` (`5` or `10-30`);
- ☐ Log if **version** — the same (`1.21.1` or `1.21.1-1.21.4`);
- ☐ Log if **brand name contains** — Java regex (e.g. `Leaf|Paper`);
- ☐ Log if **MOTD contains** — Java regex;
- ☐ Log if **player list contains** — Java regex.

Responses that fail any enabled filter are excluded from the log, the counters and the export. An empty value means the filter is disabled.

### Process monitor

Updated once a second at the bottom of the window:
- **CPU** — load of the Java process (in %);
- **RAM** — JVM memory usage (used / total heap, MB);
- **IN / OUT** — incoming and outgoing network traffic (rate and total). In Minecraft mode — real ping bytes, in Telnet mode — an estimate of the TCP handshake.

---

## How it works

Scanning is built on **three independent thread pools** connected by bounded queues (8,192 elements each):

```
[Generators (CPU)] → task queue → [Network workers (up to 1024)] → result queue → [Parsers (CPU)] → log/counters
```

- **Generators** expand the regex/CIDR into `IP:port` pairs and push them into the queue (a blocking `put` = natural backpressure, no busy-waiting and no artificial pauses).
- **Network workers** open TCP connections (blocking I/O) — these are not CPU threads, their count is independent and can reach 1024.
- **Parsers** process the results and invoke the callbacks (counting, stats, log formatting).

Memory stays **constant** (bounded queues) regardless of the range size, and the UI is never blocked: all work runs in background daemon threads.

---

## Project structure

| File | Purpose |
|---|---|
| `IpParserGUI.java` | GUI (Swing, dark theme), settings dialogs |
| `IpPattern.java` | Expands a Java regex / CIDR into lists of IPv4 addresses |
| `SyntaxConv.java` | Converts `ip` / `wildcard` / `regex` types into the internal regex |
| `PortScanner.java` | Multithreaded TCP scanner (Telnet mode) |
| `McProbe.java` | Minecraft Server List Ping (pure JDK) |
| `McProbeScanner.java` | Multithreaded MC server scanner |
| `IpUtils.java` | Public/private IP and local network detection (Status 2) |
| `PerfMonitor.java` | Process CPU / RAM / network traffic monitor |
| `build.bat` | Compiles the project |
| `launch.bat` | Launches the program (javaw) |
| `launch.vbs` | Silent launch without a console window |
| `settings.txt` | Last used settings (auto-generated) |

A detailed description of the syntax and settings is available in [`README.txt`](README.txt).

---

## License

This project is licensed under the [GNU AGPL v3.0](LICENSE).
