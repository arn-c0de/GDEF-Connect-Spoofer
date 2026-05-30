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
- **Operational controls**: Supports TCP/UDP filters, local/external toggles, pinned IPs, and live statistics.
- **Suite-ready structure**: Keeps runtime configuration, datasets, scripts, and web assets separated for modular GDEF Suite integration.

## Requirements

- Python 3.11+
- `uv` recommended for Python dependency management
- Administrator/root privileges for packet capture
- Linux/macOS: `libpcap`/`tcpdump` packages where required by the platform
- Windows: Npcap or WinPcap

## Quick Start

### Windows

Install Npcap first, then run the launcher as administrator:

```powershell
start.bat
```

### Linux/macOS

```bash
sudo ./run.sh install
sudo ./run.sh start
```

The web UI is available at:

```text
http://localhost:8000
```

The launcher creates or updates `.venv`, installs dependencies from `pyproject.toml` with `uv sync --no-dev`, falls back to `requirements.txt` with pip when `uv` is unavailable, and starts the app in the background.

## Service Commands

```bash
sudo ./run.sh install   # install system packages, sync Python deps, configure interface
sudo ./run.sh start     # start ConnectSpoofer in the background
sudo ./run.sh stop      # stop the running process
sudo ./run.sh restart   # stop and start again
sudo ./run.sh status    # print running/stopped state
sudo ./run.sh logs      # follow app.log
```

By default, the server binds to `127.0.0.1:8000`. To expose it on a trusted network, set both the bind address and allowed Socket.IO origin:

```bash
sudo APP_HOST=0.0.0.0 SOCKETIO_CORS_ORIGINS=http://YOUR-LAN-IP:8000 ./run.sh restart
```

To select a different network interface:

```bash
sudo RESELECT_INTERFACE=1 ./run.sh start
```

### Running without root (least privilege)

Packet capture only needs the `CAP_NET_RAW` capability, not full root. Grant it
once to the virtualenv interpreter, then start/stop as your normal user:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
./run.sh start
```

`install` still requires `sudo` because it installs system packages.

### Security-relevant environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | random per start | Stable session signing key |
| `SESSION_COOKIE_SECURE` | off | Set to `1`/`true` when served over HTTPS |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed logins per IP before lockout |
| `LOGIN_LOCKOUT_SECONDS` | `300` | Lockout duration after too many failures |
| `IPINFO_TOKEN` | unset | Token for the HTTPS ipinfo.io geolocation provider |
| `ALLOW_INSECURE_GEO_API` | `1` | Set to `0` to disable the HTTP ip-api.com fallback |

The access token is written only to `database/access_token.txt` (mode `0600`);
retrieve it with `cat database/access_token.txt`.

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
- `geo_data.db`: generated SQLite cache/database
- `datasets/*.mmdb`: GeoIP datasets

## Project Structure

```text
ConnectSpoofer/
├── app.py                           # Flask server, packet processing, Socket.IO events
├── run.sh                           # Linux/macOS service launcher
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

Install Npcap from `https://npcap.com/` and enable WinPcap API-compatible mode during installation if required.

### Interface names show only NPF paths

Use the interface menu debug option or run:

```bash
python debug_interfaces.py
```

### Missing privileges

Use `sudo ./run.sh start` on Linux/macOS, or grant `CAP_NET_RAW` to run without
root (see "Running without root" above). On Windows, run `start.bat` as administrator.

## License

MIT. See [LICENSE](LICENSE).

## Author

arn-c0de

GitHub: [@arn-c0de](https://github.com/arn-c0de)
