# GDEF-L1NK

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![Package Manager](https://img.shields.io/badge/Package%20Manager-uv-4B32C3)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?logo=windows)
![License](https://img.shields.io/github/license/arn-c0de/GDEF-L1NK?color=green)
![Network](https://img.shields.io/badge/Network-Monitoring-critical?logo=wireshark)
![Backend](https://img.shields.io/badge/Backend-Flask-black?logo=flask)

<p align="center">
  <img src="media/videos/gdef-l1nk-rot-main.gif" alt="GDEF-L1NK globe" width="640">
</p>

<p align="center">
  <img src="media/images/gdef-l1nk-link.png" alt="GDEF-L1NK screenshot" width="900">
</p>

GDEF-L1NK is a modular network intelligence component of the **GDEF Suite**. It captures authorized network traffic, enriches observed endpoints, and visualizes live connections on an interactive 3D globe for defensive analysis, lab work, and internal security operations.

It is designed as a standalone module that can be run independently today and integrated into larger GDEF Suite workflows over time.

## Navigation

- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
  - [Docker (Linux)](#docker-linux--the-standard-way-to-run-it)
  - [Windows](#windows-recommended)
- [Service Commands](#service-commands-linux--docker)
  - [Development (live code reload)](#development-live-code-reload)
- [Database (PostgreSQL)](#database-postgresql)
- [Multi-Device Monitoring (Sensors)](#multi-device-monitoring-sensors)
  - [Dashboard overlay tabs](#dashboard-overlay-tabs)
  - [FritzDump module](#fritzdump-module-capture-from-pcap-files)
- [Security & Privacy](#security--privacy)
  - [Security Environment Variables](#security-environment-variables)
- [Python Workflow](#python-workflow)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Security Notice](#security-notice)
- [Troubleshooting](#troubleshooting)
- [Known Issues](#known-issues)
- [License](#license)
- [Author](#author)

## Features

- **Live packet visibility**: Captures TCP, UDP, and ICMP traffic with Scapy.
- **3D geo-visualization**: Displays external connections on an interactive globe.
- **Local network discovery**: Detects local devices and mDNS activity.
- **Threat enrichment**: Uses FireHOL-style blocklist data for basic reputation context.
- **Multi-device aggregation**: Acts as a hub for remote sensors — each a named, coloured origin — with encrypted push ingestion and per-device statistics.
- **Operational controls**: Supports TCP/UDP filters, local/external toggles, pinned IPs, and live statistics.
- **Unified dashboard panel**: A single tabbed overlay (**Statistics · Connections · Devices · Settings**) for all charts, the connection table, device management, and configuration — opened via the ⚙ (Settings) or 📊 (Statistics) buttons.
- **Suite-ready structure**: Keeps runtime configuration, datasets, scripts, and web assets separated for modular GDEF Suite integration.

## Requirements

- Python 3.11+
- `uv` recommended for Python dependency management
- Administrator/root privileges for packet capture
- Linux/macOS: `libpcap`/`tcpdump` packages where required by the platform
- Windows: Npcap or WinPcap

## Quick Start

GDEF-L1NK is protected by a token-based login. The access token is generated on first start and stored securely in `database/access_token.txt`.

### Docker (Linux — the standard way to run it)

`run.sh` is a thin wrapper around Docker Compose: the sniffer/web app and a PostgreSQL database run as containers. The app container uses **host networking** plus the `NET_RAW`/`NET_ADMIN` capabilities so Scapy captures from the physical interface — no host-level `setcap` needed. Requires [Docker Engine + the Compose plugin](https://docs.docker.com/engine/install/).

```bash
cp .env.example .env
# Edit .env: set NETWORK_INTERFACE (e.g. eth0/enp3s0) and a strong POSTGRES_PASSWORD
./run.sh start        # build (if needed) + start the stack
```

- **Dashboard**: `http://localhost:8000`
- **Token**: `./run.sh token` (the app writes it into the mounted `database/` folder; `cat database/access_token.txt` also works). Set a fixed `ACCESS_TOKEN` in `.env` to keep it stable across restarts.
- **Data**: PostgreSQL data persists in the `pgdata` named volume; the GeoIP `.mmdb` datasets and generated secrets stay in the mounted `database/` folder.

> The database port is published to `127.0.0.1` only (default **55432**, to avoid a system PostgreSQL on 5432), so it is never exposed to the LAN. Set `APP_HOST=0.0.0.0` in `.env` only if you intentionally want the UI reachable from other hosts. If your user isn't in the `docker` group, prefix the commands with `sudo`.

### Windows (Recommended)

1.  **Install Npcap**: Download and install from [npcap.com](https://npcap.com/). Select "Install Npcap with WinPcap API-compatible Mode".
2.  **Run Launcher**: Right-click `start.bat` and select **"Run as Administrator"**.
    *   The script will automatically harden the `database/` folder permissions (only you and Administrators will have access).
    *   It will synchronize dependencies using `uv` (or `pip` fallback).
3.  **Access Dashboard**: Open `http://localhost:8000`.
4.  **Login**: Find your access token in `database/access_token.txt`.

## Service Commands (Linux — Docker)

`run.sh` drives the Docker Compose stack:

```bash
./run.sh start      # build (if needed) + start app + PostgreSQL (baked image)
./run.sh dev        # start with source bind-mounted (live frontend, fast backend reload)
./run.sh stop       # stop and remove the containers
./run.sh restart    # rebuild changed parts (frontend/backend) + restart — picks up code edits
./run.sh status     # container status (docker compose ps)
./run.sh logs       # follow the app logs
./run.sh build      # (re)build the app image
./run.sh rebuild    # rebuild from scratch and start
./run.sh token      # print the dashboard access token
```

### Development (live code reload)

`./run.sh dev` starts the same stack but bind-mounts the source (`app.py`, `db.py`,
`static/`, `templates/`) into the app container via `docker-compose.dev.yml`, so
edits don't need an image rebuild:

- **Frontend** (`static/`, `templates/`): visible immediately on a browser refresh — no restart.
- **Backend** (`app.py`, `db.py`): run `./run.sh restart` for a fast process restart (no image build).

Dev mode is remembered via a `.dev-mode` marker file, so `restart`/`logs`/`status`
keep the mounts. Switch back to the production-like baked image with `./run.sh start`
(or leave dev mode entirely with `./run.sh stop`).

Prefix with `sudo` if your user isn't in the `docker` group. Capture works via the container's `NET_RAW`/`NET_ADMIN` capabilities, so no host `setcap` is required (and `setcap` is in any case ignored on `nosuid`/`ecryptfs` mounts).

## Database (PostgreSQL)

GDEF-L1NK stores its live IP table, pinned IPs, MAC-vendor cache, settings, and threat list in **PostgreSQL** (replacing the former embedded SQLite database). The GeoIP `.mmdb` datasets in `database/datasets/` remain file-based and are unaffected.

With the Docker stack the `db` service provides PostgreSQL automatically — nothing to install. It is published to `127.0.0.1` only, on port **55432** by default (set via `POSTGRES_PORT` in `.env`) to avoid clashing with a system PostgreSQL on 5432.

To run the app outside Docker against your own PostgreSQL, configure the connection via these environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | *(unset)* | Full libpq URL, e.g. `postgresql://user:pass@127.0.0.1:5432/gdef_l1nk`. Overrides the `PG*` vars below. |
| `PGHOST` | `127.0.0.1` | Database host |
| `PGPORT` | `5432` | Database port |
| `PGDATABASE` | `gdef_l1nk` | Database name |
| `PGUSER` | `gdef_l1nk` | Database user |
| `PGPASSWORD` | `gdef_l1nk` | Database password |
| `DB_POOL_SIZE` | `10` | Max pooled connections per process |
| `DB_CONNECT_TIMEOUT` | `15` | Seconds to wait for a connection |
| `NETWORK_INTERFACE` | *(from config)* | Capture interface; overrides `database/backend_conf.json` (useful in containers) |

The app waits for PostgreSQL to accept connections on startup and creates its schema automatically (`init_db`).

## Multi-Device Monitoring (Sensors)

GDEF-L1NK can act as a **central hub** that aggregates traffic from several
capture **devices** at once — your local host plus any number of remote
**sensors**. Each device is its own named, coloured origin on the globe, so you
can see at a glance which connections belong to which machine.

- **Register a device**: in the dashboard sidebar, **Devices → + Add device**.
  The hub issues a `DEVICE_ID` and a one-time `DEVICE_KEY` (shown once).
- **Install the sensor** on the target server: see [`sensor/README.md`](sensor/README.md).
  The sensor captures locally and pushes connections to the hub, **gzip-compressed
  and Fernet-encrypted** with the device key — confidential and replay-protected
  even over plain HTTP on a LAN. It carries no database and no datasets.
- **Colour & filter**: toggle globe colouring between **threat** and **device**,
  show/hide individual devices, and scope the statistics panel to one device or all.
  Filters and device settings persist across page reloads.
- **Start / Stop (every device)**: each device row has a **▶ Start / ■ Stop**
  button (its `enabled` flag). While a device is stopped, **none of its traffic is
  processed** — not even in the background — and it disappears from the globe and
  all lists. Starting it again immediately re-fetches and redraws its data. Even
  the built-in `local` capture can be stopped.

Devices are identified by their `DEVICE_ID`, **never by IP** — so several sensors
behind the same home router (one shared public IP) stay distinct. The hub's own
capture is the built-in `local` device; its display name comes from
`HUB_DEVICE_NAME` (defaults to the hostname).

The hub exposes `POST /api/ingest` for sensors (per-device key auth, rate-limited,
size-capped) and a session-authenticated device API (`/api/devices…`). Ingestion
limits are tunable via `INGEST_MAX_AGE`, `INGEST_MAX_EVENTS`, `INGEST_MAX_BODY`
and `INGEST_RATE_LIMIT`.

### Dashboard overlay tabs

Open the dashboard overlay with the **⚙ Settings** button or the **📊 Statistics**
button. It has four tabs:

- **Statistics**: live counters, protocol/threat charts, top talkers, newest
  connections, unknown IPs, and suspicious targets. Use the **Device** selector in
  the header to view all traffic or only one device.
- **Connections**: sortable connection table with IP, LAN device(s), country,
  organisation, protocol, packet counts, threat level, and last-seen time. The
  same **Device** selector scopes the table.
- **Devices**: enable, stop, rename, colour, filter, add, rotate, or delete
  capture devices.
- **Settings**: display options, organisation lists, IP labels, CSV export, and
  logout.

In the **Devices** tab, each row has two different controls:

- The checkbox at the left only shows/hides that device on the globe and in the
  lists. It is a display filter.
- **▶ Start / ■ Stop** controls whether the hub processes that device's traffic.
  Stopped devices are not processed in the background and disappear from the live
  views.

Common device rows:

- **local** / your hub device: this is the hub's own network adapter capture. The
  adapter is selected with `NETWORK_INTERFACE` in the root `.env` or
  `database/backend_conf.json`. Start it to capture from that adapter; stop it if
  you only want sensor/FritzDump traffic.
- **FritzBox** / `module`: this is the FritzDump pcap source. It appears only
  after the module is enabled. Configure `modules/FritzDump/.env`, then open
  **Devices** and press **▶ Start** on the FritzBox row. Start launches the
  FritzDump worker and begins tailing `modules/FritzDump/dumps/`; Stop kills the
  worker and clears its current data.
- **sensor** devices: remote hosts registered with **+ Add device**. Start/Stop
  accepts or rejects their encrypted ingest batches.

### FritzDump module (capture from pcap files)

Besides live capture from a NIC, the hub can use the **FritzDump** module as a
capture *source*: instead of sniffing an interface, it captures from your
**FRITZ!Box** and feeds that traffic into the same globe/stats as everything else.
This lets a hub with no usable capture interface (or no `CAP_NET_RAW`) still see
real traffic — and gives you full visibility of every device behind the router,
not just the host the hub runs on.

**How it works:**

```
FRITZ!Box ──(login + capture)──> modules/FritzDump/run.sh ──> dumps/*.pcap
                                                                   │ tail
   dashboard  <── globe/stats <── process_packets <── hub reader ──┘
```

1. You press **▶ Start** on the FritzBox device in the dashboard.
2. The hub launches the FritzDump worker (`modules/FritzDump/run.sh`), which logs
   into the box and streams its capture to pcap files under
   `modules/FritzDump/dumps/`.
3. The hub **tails those pcaps** and parses each packet (it understands both
   standard libpcap and the FRITZ!Box "modified" pcap variant, magic
   `0xa1b2cd34`), tagging every connection as the FritzBox device.
4. Geo/threat/vendor enrichment happens centrally, exactly like live capture, and
   the connections appear on the globe and in the stats.

Because the FRITZ!Box sees the whole LAN, each external connection also records
its **local peer(s)** — *which device(s) in your network* are talking to that
external IP. A single external server is often reached by several local hosts at
once (e.g. `192.168.178.100`, `.90`, `.44`), so the dashboard collects **all** of
them. The LAN device(s) appear:

- inline under each row in the live **connection list** (`→ 192.168.178.100, …`),
- as **"LAN device(s)"** in a point's detail panel, and
- as a sortable **"LAN device(s)"** column in the Connections tab.

You can give your own hosts friendly names under **Settings → IP Labels** (one
`IP Name` per line, e.g. `192.168.178.100 PC-E1`). Names are stored as a simple
JSON map (`database/ip_labels.json`) and shown as `PC-E1 (192.168.178.100)`
everywhere a LAN device is listed.

**Stop** kills the worker and clears its data. The module is just another device,
so it honours the same per-device colour, visibility, and Start/Stop as any sensor.

**The module is OFF by default** — if you don't use it, you never see the device
and nothing extra runs. Turn it on (Docker):

```bash
./run.sh fritzdump on      # bind-mounts the module, enables it, and recreates the app container
./run.sh fritzdump off     # turn it back off any time (also applies immediately)
```

`fritzdump on/off` **recreates the app container itself** (a plain `restart`
wouldn't pick up the new mount/env). Outside Docker, just set `FRITZDUMP_ENABLED=1`.

Before you press Start, put the FRITZ!Box login data into the module's own env
file. This is **not** the root project `.env`; FritzDump reads:

```text
modules/FritzDump/.env
```

The module has its own detailed README here:
[`modules/FritzDump/README.md`](modules/FritzDump/README.md).

Create it from the template and restrict the permissions:

```bash
cd modules/FritzDump
cp .env.example .env
chmod 600 .env
```

Then edit `modules/FritzDump/.env`:

```dotenv
FRITZ_HOST=192.168.178.1
FRITZ_USER=fritz-capture-user
FRITZ_PW=your-fritzbox-password
FRITZ_HTTPS=true

# Recommended when FRITZ_HTTPS=true: pin the FRITZ!Box certificate.
# FRITZ_CACERT=fritzbox.pem
```

Use a dedicated FRITZ!Box user if possible. It only needs the **"FRITZ!Box
settings"** permission. If your box uses password-only login without a username,
set `FRITZ_USER=dslf-config`.

You can test the credentials and list the available capture interfaces directly:

```bash
cd modules/FritzDump
./run.sh test
```

Once configured and enabled, the **FritzBox** device appears in the dashboard:

- FritzDump appears in **Devices** as a built-in `module` device with its own
  colour. It starts **stopped**; press its **▶ Start** button.
- **Start launches the capture worker for you.** Pressing Start runs the FritzDump
  worker (`modules/FritzDump/run.sh`, which logs into the box and writes the
  pcaps) as a managed child process, then tails the resulting pcaps live. **Stop**
  kills that worker. You only need to configure `modules/FritzDump/.env` once.
- New packets are picked up within ~1 s; the `home` mode's per-interface
  sub-directories are discovered automatically. FritzDump has no public IP, so its
  globe arcs anchor at the hub's own location.
- If the worker exits immediately (usually a missing/wrong `.env`), the hub backs
  off and logs it instead of respawn-looping.

**No data after Start?** Check, in order:
- `./run.sh logs` — the reader logs `FritzDump status: N capture file(s), M packet(s) parsed`
  every ~20 s. `N=0` → the worker isn't writing pcaps; `N>0, M=0` → files exist but
  aren't being parsed.
- `cat database/fritzdump_worker.log` — the worker's own stdout/stderr. Login
  failures, wrong interface IDs, or no route to the box show up here.
- Confirm `modules/FritzDump/.env` has the right host/credentials, and that the
  interface IDs in `modules/FritzDump/run.sh` (`home` mode) match your box.

Tune it with `FRITZDUMP_DIR` (watched dir), `FRITZDUMP_DEVICE_NAME`,
`FRITZDUMP_WORKER_MODE` (`home` by default), or replace the launch command
entirely with `FRITZDUMP_WORKER_CMD`. Set `FRITZDUMP_AUTOSTART=0` if you prefer to
run FritzDump yourself and have the hub only **read** the pcaps.

> **Docker:** `./run.sh fritzdump on` already bind-mounts `modules/FritzDump`
> into the container (so Start can launch the worker) and the base stack uses host
> networking (so the worker reaches the box). The module is **not** baked into the
> image — it is mounted only while enabled. If you'd rather run FritzDump on the
> host, set `FRITZDUMP_AUTOSTART=0` and have the hub only **read** the pcaps via a
> mounted `dumps` directory (or point `FRITZDUMP_DIR` at the mount).

## Security & Privacy

GDEF-L1NK is built with a **Security-First** approach:
- **Authentication**: Mandatory token-based login (Timing-safe comparison).
- **Hardened Sessions**: HTTPOnly, SameSite=Lax, and Secure-cookie support.
- **XSS Protection**: Strict HTML escaping and a robust Content Security Policy (CSP).
- **CSRF Protection**: Cryptographic tokens for all state-changing actions.
- **DoS Resilience**: In-memory resource limits and Socket.IO rate limiting.
- **Data Protection**:
    - **Windows**: ACL hardening (icacls) for sensitive data.
    - **Linux**: Secure umask (077) and private directory permissions (0700).
- **Least Privilege**: Support for Linux capabilities (`setcap`).

### Security Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | random | Stable session signing key |
| `SESSION_COOKIE_SECURE` | off | Set to `1` when using HTTPS |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed logins per IP before lockout |
| `SOCKET_RATE_LIMIT` | `5` | Max Socket.IO events per second per client |
| `ALLOW_INSECURE_GEO_API`| `0` | Geo lookups are HTTPS-only by default; set to `1` to allow the unencrypted `http://ip-api.com` fallback |
| `TRUST_PROXY` | off | Set to `1` ONLY when behind a trusted reverse proxy that overwrites `X-Forwarded-For`; lets per-IP limits see the real client IP |
| `TRUST_PROXY_HOPS` | `1` | Exact number of trusted proxies in front of the app (only with `TRUST_PROXY=1`) |
| `HUB_DEVICE_NAME` | hostname | Display name for the hub's built-in `local` capture device |
| `INGEST_RATE_LIMIT` | `20` | Max sensor ingest batches per second per device |
| `INGEST_MAX_AGE` | `300` | Reject sensor batches older than this many seconds (replay window) |
| `INGEST_MAX_EVENTS` | `5000` | Max connection events accepted per ingest batch |
| `INGEST_MAX_BODY` | `8388608` | Max encrypted ingest body size in bytes |
| `FRITZDUMP_ENABLED` | `0` | Master switch for the FritzDump module (`1` = on; `./run.sh fritzdump on` sets it) |
| `FRITZDUMP_DIR` | `modules/FritzDump/dumps` | Directory the FritzDump pcap source tails |
| `FRITZDUMP_DEVICE_NAME` | `FritzBox` | Display name of the built-in FritzDump module device |
| `FRITZDUMP_POLL_INTERVAL` | `1.0` | Seconds between FritzDump pcap polls when idle |
| `FRITZDUMP_AUTOSTART` | `1` | On Start, also launch the FritzDump worker (`0` = only read pcaps) |
| `FRITZDUMP_WORKER_MODE` | `home` | `run.sh` mode used when autostarting the worker |
| `FRITZDUMP_WORKER_CMD` | (run.sh) | Override the entire FritzDump worker launch command |

Sensor-side configuration (`CENTRAL_URL`, `DEVICE_ID`, `DEVICE_KEY`,
`NETWORK_INTERFACE`, and tuning knobs) is documented in
[`sensor/sensor.env.example`](sensor/sensor.env.example) and
[`sensor/README.md`](sensor/README.md).

## Python Workflow

This repository follows current Python packaging practice with `pyproject.toml`, `.python-version`, and `uv.lock`.

```bash
uv sync
uv run python app.py
uv run ruff check .
```

Runtime dependencies are declared in `pyproject.toml`. `uv.lock` records resolved versions for reproducible environments. `requirements.txt` is kept as a legacy fallback for systems without `uv`.

## Configuration

Generated runtime files live in `database/` and are ignored by Git where appropriate:

- `backend_conf.json`: selected packet-capture interface
- `trusted_organisations.json`: organization classification data
- `datasets/*.mmdb`: GeoIP datasets

Application state (live IPs, pinned IPs, settings, MAC cache, threat list) is stored in **PostgreSQL** — see [Database (PostgreSQL)](#database-postgresql).

### Performance / throughput tuning

The capture path (live sniffer, the forked internal scanner, and the FritzDump reader) all feed **one** cross-process priority queue, which a pool of worker threads drains into the database. If a single high-traffic device bursts faster than the workers can keep up, the queue fills and packets are **dropped** — and the dropped packet can be the very *first* one to a brand-new external IP (e.g. a freshly connected VPN server), so its point never appears on the globe. When that happens you'll see a throttled `PacketQueue full: N packet(s) dropped` warning in the log; raise the values below until it stops.

| Variable | Default | Description |
| --- | --- | --- |
| `PACKET_WORKERS` | half the CPU cores, clamped to `[2, 8]` | Parallel worker threads draining the capture queue into the DB write buffer. Increase if packets are dropped under load. |
| `PACKET_QUEUE_MAX` | `20000` | Per-lane capacity of the priority capture queue (high/low). Larger absorbs bigger bursts before dropping; each slot is a small dict, so it's cheap. |
| `GEO_WORKERS` | `4` | Parallel geo-lookup workers. A new IP is shown at a placeholder location immediately, then a worker resolves its real coordinates; a small pool lets a burst of new IPs resolve concurrently instead of one slow lookup at a time. |
| `IP_WRITE_FLUSH_INTERVAL` | `1.0` | Seconds between batched DB flushes of buffered IP updates. |
| `IP_WRITE_BUFFER_MAX` | `20000` | Max distinct IPs buffered between flushes (a unique-IP flood beyond this is dropped and logged, never silently). |

The two lanes are **fair-scheduled**: external traffic keeps priority, but the internal (LAN) lane is guaranteed a slice every few dequeues, so a sustained external flood (e.g. all traffic tunnelled to one VPN endpoint) can no longer starve a busy LAN device's packets. *Note:* LAN/private IPs are only drawn as their own nodes when **Show local network** is enabled in the overlay — otherwise only their external peers are shown.

#### Capture-health status bar

The top bar shows a live read-out of the capture pipeline, refreshed every 5 s, so you can see at a glance whether everything is being processed:

- **pkt/s** — packets processed per second (throughput)
- **processed** — total processed this session
- **dropped** — packets dropped because the queue was full (turns red as soon as it is non-zero)
- **queued** — current backlog waiting in the queue
- **OK / BUSY / OVERLOAD** — an at-a-glance indicator; it goes **OVERLOAD** (pulsing red) while packets are actively being dropped or the queue is ≥ 90 % full. If you see this, raise `PACKET_WORKERS` / `PACKET_QUEUE_MAX`.

## Project Structure

```text
GDEF-L1NK/
├── app.py                           # Flask hub: capture, ingestion, devices, Socket.IO
├── capture_core.py                  # Shared packet classification (hub + sensor)
├── capture_sources.py               # Pcap-file capture sources (FritzDump tailing)
├── device_crypto.py                 # Shared sensor↔hub encrypted batch framing (Fernet)
├── sensor/                          # Standalone remote sensor worker (see sensor/README.md)
├── modules/FritzDump/               # FRITZ!Box pcap capture helper (own repo)
├── db.py                            # PostgreSQL connection-pool layer (fork-aware)
├── Dockerfile                       # App/sniffer container image
├── docker-compose.yml              # App + PostgreSQL stack
├── docker-compose.dev.yml          # Dev override: bind-mounts source (./run.sh dev)
├── .env.example                     # Sample environment for Docker Compose
├── run.sh                           # Docker Compose launcher (Linux)
├── smoke-test.sh                    # Smoke-test launcher
├── start.bat                        # Windows launcher
├── scripts/                         # Smoke tests and local helper scripts
│   ├── smoketest.py                 # Full app smoke test
│   ├── select_interface.py          # Interface selection helper
│   └── debug_interfaces.py          # Interface diagnostics helper
├── pyproject.toml                   # Project metadata and dependencies
├── uv.lock                          # Locked dependency graph
├── .python-version                  # Preferred Python runtime for uv
├── requirements.txt                 # Legacy pip fallback
├── database/                        # Generated configs, DB files, GeoIP datasets
├── static/                          # Frontend assets
├── templates/                       # Flask templates
└── media/images/                    # Documentation images
```

## Security Notice

GDEF-L1NK is intended only for authorized defensive use:

- Monitor only networks and systems you own or are explicitly authorized to assess.
- Prefer the least-privilege capability setup over full root; only packet capture (`CAP_NET_RAW`) is required.
- Keep the default localhost bind unless you deliberately expose the UI on a trusted network.
- Follow local laws and organizational policy for packet capture and network monitoring.

The author assumes no responsibility for misuse.

## Troubleshooting

### `NPF not found` on Windows
This indicates that Npcap is missing or not running.
- **Fix**: Install Npcap from [npcap.com](https://npcap.com/).
- **Crucial**: Ensure "WinPcap API-compatible Mode" is checked during installation.

### Permission Denied / capture fails (Linux)
With the Docker stack, capture runs via the container's `NET_RAW`/`NET_ADMIN` capabilities — no host `setcap` is needed (and `setcap` is silently ignored on `nosuid`/`ecryptfs` mounts, a common cause of "Operation not permitted" when running outside Docker).
- **Fix**: Use `./run.sh start` (Docker). If `docker` itself is permission-denied, add your user to the `docker` group or run `sudo ./run.sh start`.

### Cannot bind port 8000 / database port
Another process holds the port. Stop stray bare-metal instances (`sudo pkill -f app.py`) before `./run.sh start`. The database publishes **55432** by default to avoid a system PostgreSQL on 5432 — change `POSTGRES_PORT` in `.env` if needed.

### Login Failed / Token Missing
The dashboard is locked by default.
- **Fix**: Run `./run.sh token` (or `cat database/access_token.txt`). Set a fixed `ACCESS_TOKEN` in `.env` to keep it stable across restarts.
- **Windows**: If you cannot see the file, ensure you ran `start.bat` as Administrator.

### Wrong capture interface
Set `NETWORK_INTERFACE` in `.env` to a real host interface (e.g. `enp3s0`, `wlan0`), then `./run.sh restart`. List interfaces with `python scripts/debug_interfaces.py` or `ip -br link`.

## Known Issues

A running list of known bugs and their fixes / workarounds.

### Own position shows in the ocean (0,0) / Provider, IP, Country all "Unknown"
A DNS-level blocker (AdGuard Home / Pi-hole — e.g. HaGeZi's Ultimate Blocklist) sinkholes the geolocation providers, so determining your *own* public IP and location fails. The app then falls back to `DEFAULT_COORDS = [0, 0]` ("Null Island" in the Gulf of Guinea — the middle of the sea). Foreign IPs still resolve correctly because they use the offline MaxMind DB (`database/datasets/*.mmdb`), which needs no DNS — only the self-lookup hits the network.
- **Symptom in the log**: `Error at api.ipify (https): ... [Errno 111] Connection refused` (the domain resolves to the blocker's own IP).
- **Fix**: Allowlist the two domains the self-lookup needs in your DNS blocker. In AdGuard Home → **Filters → Custom filtering rules**:
  ```
  @@||api.ipify.org^
  @@||ipinfo.io^
  ```
  Save, then reload the dashboard (no restart needed — `index()` re-fetches the geo data on every page load).

### `Interface:`, `Adapter:` and `Speed:` are always empty in the top bar
The dashboard template reads `backend_config.interface_name`, `.adapter_description` and `.speed`, but only the `network_interface` key is ever written to `database/backend_conf.json` (`scripts/select_interface.py`). These three fields therefore have no data source and render blank — unrelated to the geolocation issue above.
- **Status**: Cosmetic. The capture interface itself still works (it is read from `network_interface` / the `NETWORK_INTERFACE` env var).

### FritzDump: a Wi-Fi device (e.g. a phone) never shows up, while wired/other-band devices do
A device that only ever connects over **2.4 GHz Wi-Fi** produces no data on the globe, even though it is actively online. Its row in the DB stays frozen (`last_seen` stops advancing) while LAN and 5 GHz devices update in real time.

- **Cause**: FritzDump's `home` mode captures three FRITZ!Box interfaces — LAN (`1-lan`), Wi-Fi 5 GHz (`4-133`) and Wi-Fi 2.4 GHz. On some FRITZ!OS firmwares the *logical* 2.4 GHz AP interface (`4-135`, "AP2 (2.4 GHz)") **accepts the capture but streams zero packets** — its pcap stays at 24 bytes (just the global header). The actual 2.4 GHz client traffic appears on the **raw radio interface `1-ath0`** instead (delivered as Ethernet frames, which the reader already decodes). Capturing `4-135` therefore silently lost every 2.4 GHz-only device.
- **Fix**: `home` mode now captures `1-ath0` for the 2.4 GHz band by default. If your box numbers its interfaces differently, list them with `./run.sh test` (inside `modules/FritzDump`) and override the whole set via the `FRITZ_HOME_IFACES` env var — a space-separated list of `name:iface` pairs:
  ```bash
  FRITZ_HOME_IFACES="lan:1-lan wifi_5ghz:4-133 wifi_24ghz:1-ath0"
  ```
- **Diagnosing it yourself**: the FritzDump status log now prints a per-interface parse breakdown, e.g.
  `FritzDump status: 3 capture file(s), 135889 packet(s) parsed [lan_1-lan.pcap=78019, wifi_5ghz_4-133.pcap=52870, wifi_24ghz_1-ath0.pcap=...]`.
  A capture file stuck at `0` (or absent from the list) is being silently dropped by the box — try a different interface ID for that band. Quick probe of a single interface:
  ```bash
  # inside the app container, from modules/FritzDump:
  timeout 10 python fritzdump.py --iface 1-ath0 --to dumps/probe.pcap; ls -l dumps/probe.pcap
  ```
  A file larger than 24 bytes means that interface actually carries traffic.

## License

MIT. See [LICENSE](LICENSE).

## Author

arn-c0de

GitHub: [@arn-c0de](https://github.com/arn-c0de)
