# ConnectSpoofer

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![Package Manager](https://img.shields.io/badge/Package%20Manager-uv-4B32C3)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?logo=windows)
![License](https://img.shields.io/github/license/arn-c0de/ConnectSpoofer?color=green)
![Network](https://img.shields.io/badge/Network-Monitoring-critical?logo=wireshark)
![Backend](https://img.shields.io/badge/Backend-Flask-black?logo=flask)

![ConnectSpoofer screenshot](images/Connectspoofer-link.png)

ConnectSpoofer is a modular network intelligence component of the **GDEF Suite**. It captures authorized network traffic, enriches observed endpoints, and visualizes live connections on an interactive 3D globe for defensive analysis, lab work, and internal security operations.

It is designed as a standalone module that can be run independently today and integrated into larger GDEF Suite workflows over time.

## Features

- **Live packet visibility**: Captures TCP, UDP, and ICMP traffic with Scapy.
- **3D geo-visualization**: Displays external connections on an interactive globe.
- **Local network discovery**: Detects local devices and mDNS activity.
- **Threat enrichment**: Uses FireHOL-style blocklist data for basic reputation context.
- **Multi-device aggregation**: Acts as a hub for remote sensors — each a named, coloured origin — with encrypted push ingestion and per-device statistics.
- **Operational controls**: Supports TCP/UDP filters, local/external toggles, pinned IPs, and live statistics.
- **Suite-ready structure**: Keeps runtime configuration, datasets, scripts, and web assets separated for modular GDEF Suite integration.

## Requirements

- Python 3.11+
- `uv` recommended for Python dependency management
- Administrator/root privileges for packet capture
- Linux/macOS: `libpcap`/`tcpdump` packages where required by the platform
- Windows: Npcap or WinPcap

## Quick Start

ConnectSpoofer is protected by a token-based login. The access token is generated on first start and stored securely in `database/access_token.txt`.

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

ConnectSpoofer stores its live IP table, pinned IPs, MAC-vendor cache, settings, and threat list in **PostgreSQL** (replacing the former embedded SQLite database). The GeoIP `.mmdb` datasets in `database/datasets/` remain file-based and are unaffected.

With the Docker stack the `db` service provides PostgreSQL automatically — nothing to install. It is published to `127.0.0.1` only, on port **55432** by default (set via `POSTGRES_PORT` in `.env`) to avoid clashing with a system PostgreSQL on 5432.

To run the app outside Docker against your own PostgreSQL, configure the connection via these environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | *(unset)* | Full libpq URL, e.g. `postgresql://user:pass@127.0.0.1:5432/connectspoofer`. Overrides the `PG*` vars below. |
| `PGHOST` | `127.0.0.1` | Database host |
| `PGPORT` | `5432` | Database port |
| `PGDATABASE` | `connectspoofer` | Database name |
| `PGUSER` | `connectspoofer` | Database user |
| `PGPASSWORD` | `connectspoofer` | Database password |
| `DB_POOL_SIZE` | `10` | Max pooled connections per process |
| `DB_CONNECT_TIMEOUT` | `15` | Seconds to wait for a connection |
| `NETWORK_INTERFACE` | *(from config)* | Capture interface; overrides `database/backend_conf.json` (useful in containers) |

The app waits for PostgreSQL to accept connections on startup and creates its schema automatically (`init_db`).

## Multi-Device Monitoring (Sensors)

ConnectSpoofer can act as a **central hub** that aggregates traffic from several
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

Devices are identified by their `DEVICE_ID`, **never by IP** — so several sensors
behind the same home router (one shared public IP) stay distinct. The hub's own
capture is the built-in `local` device; its display name comes from
`HUB_DEVICE_NAME` (defaults to the hostname).

The hub exposes `POST /api/ingest` for sensors (per-device key auth, rate-limited,
size-capped) and a session-authenticated device API (`/api/devices…`). Ingestion
limits are tunable via `INGEST_MAX_AGE`, `INGEST_MAX_EVENTS`, `INGEST_MAX_BODY`
and `INGEST_RATE_LIMIT`.

## Security & Privacy

ConnectSpoofer is built with a **Security-First** approach:
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

## Project Structure

```text
ConnectSpoofer/
├── app.py                           # Flask hub: capture, ingestion, devices, Socket.IO
├── capture_core.py                  # Shared packet classification (hub + sensor)
├── device_crypto.py                 # Shared sensor↔hub encrypted batch framing (Fernet)
├── sensor/                          # Standalone remote sensor worker (see sensor/README.md)
├── db.py                            # PostgreSQL connection-pool layer (fork-aware)
├── Dockerfile                       # App/sniffer container image
├── docker-compose.yml              # App + PostgreSQL stack
├── docker-compose.dev.yml          # Dev override: bind-mounts source (./run.sh dev)
├── .env.example                     # Sample environment for Docker Compose
├── run.sh                           # Docker Compose launcher (Linux)
├── start.bat                        # Windows launcher
├── select_interface.py              # Interface selection helper
├── debug_interfaces.py              # Interface diagnostics helper
├── pyproject.toml                   # Project metadata and dependencies
├── uv.lock                          # Locked dependency graph
├── .python-version                  # Preferred Python runtime for uv
├── requirements.txt                 # Legacy pip fallback
├── database/                        # Generated configs, DB files, GeoIP datasets
├── static/                          # Frontend assets
├── templates/                       # Flask templates
└── images/                          # Documentation images
```

## Security Notice

ConnectSpoofer is intended only for authorized defensive use:

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
Set `NETWORK_INTERFACE` in `.env` to a real host interface (e.g. `enp3s0`, `wlan0`), then `./run.sh restart`. List interfaces with `python debug_interfaces.py` or `ip -br link`.

## License

MIT. See [LICENSE](LICENSE).

## Author

arn-c0de

GitHub: [@arn-c0de](https://github.com/arn-c0de)
