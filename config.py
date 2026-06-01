"""Static configuration constants for the GDEF-L1NK hub.

Pure, import-time configuration read from literals and environment variables:
paths, limits, timeouts, the multi-device identity defaults and the FritzDump
module settings. Everything here is set once at import and never rebound, so
other modules can safely `from config import X` without the stale-copy trap that
affects reassigned globals (e.g. NETWORK_INTERFACE, which therefore stays in
app.py next to validate_interface).

No app state, no threads, no Flask — just values; safe to import anywhere.
"""
import os
import shlex
import socket
import logging

logger = logging.getLogger(__name__)

# --- Login brute-force protection -------------------------------------------
LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', '5'))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get('LOGIN_LOCKOUT_SECONDS', '300'))

# --- Core paths / cache + API timeouts (source of truth for CONFIG) ----------
DATABASE_DIR = "database"
DATABASE_PATH = os.path.join(DATABASE_DIR, "geo_data.db")
CACHE_TIMEOUT = 3600
API_TIMEOUT = 5

DEFAULT_COORDS = [0, 0]
# Display / "active" window: how long a connection counts as live in the UI —
# drives the dot fade-out, the initial-load query and the active-connection
# accounting. Kept short by default so the globe shows recent activity; raise
# the EXPIRATION_SECONDS env var to keep points visible longer.
EXPIRATION_SECONDS = int(os.environ.get("EXPIRATION_SECONDS", "3600"))
# DB retention window: how long a row survives in ip_data before the cleanup
# thread deletes it (pinned IPs are never deleted). DECOUPLED from the display
# window above, so data is kept for history long after a point stops being drawn
# live. Default 30 days; override via RETENTION_SECONDS. Clamped to be at least
# the display window so we never delete rows the live view still wants to show.
RETENTION_SECONDS = max(EXPIRATION_SECONDS,
                        int(os.environ.get("RETENTION_SECONDS", str(30 * 24 * 3600))))
# Hard ceiling on rows kept in ip_data. Even under a spoofing flood (new IPs are
# rate-limited but can still accumulate within the retention window), the cleanup
# thread trims the oldest unpinned rows beyond this cap so the DB can't fill the
# disk. Override via the MAX_IP_ROWS env var.
MAX_IP_ROWS = int(os.environ.get("MAX_IP_ROWS", "50000"))
SNIFF_TIMEOUT = 30
SOCKETIO_PING_TIMEOUT = 120
SOCKETIO_PING_INTERVAL = 25

TRUSTED_ORGS_PATH = os.path.join(DATABASE_DIR, "trusted_organisations.json")
# Operator-defined friendly names for local/LAN IPs (e.g. 192.168.178.100 -> "PC-E1").
# Display-only; surfaced in the dashboard's "LAN device" columns.
IP_LABELS_PATH = os.path.join(DATABASE_DIR, "ip_labels.json")

# --- Geo-based threat flagging ----------------------------------------------
# Connections to/from these ISO-3166 alpha-2 country codes are flagged at
# HIGH_RISK_COUNTRY_THREAT_LEVEL. This only ever ELEVATES a verdict: an org or
# threat-list rule that already assigns an equal-or-higher level wins, and a
# country never downgrades it. Comma-separated codes via the env var; default
# flags Russia (RU). Set HIGH_RISK_COUNTRIES="" to disable entirely.
HIGH_RISK_COUNTRIES = {
    c.strip().upper()
    for c in os.environ.get("HIGH_RISK_COUNTRIES", "RU").split(",")
    if c.strip()
}
# Threat level applied to high-risk-country IPs: High | Medium | Low.
HIGH_RISK_COUNTRY_THREAT_LEVEL = (
    os.environ.get("HIGH_RISK_COUNTRY_THREAT_LEVEL", "High").strip() or "High"
)

# --- Multi-device (sensor) identity -----------------------------------------
# Every captured connection belongs to a "device". The hub's own local capture
# is the built-in device 'local'; remote sensors register their own ids. Devices
# are NEVER identified by IP — sensors in the same network share one public IP —
# so the id is the sole identity, carried explicitly through the pipeline.
LOCAL_DEVICE_ID = 'local'
LOCAL_DEVICE_COLOR = '#FFFF00'  # the legacy "Your IP" yellow
HUB_DEVICE_NAME = os.environ.get('HUB_DEVICE_NAME', '').strip() or socket.gethostname() or 'local'
# Per-device sensor keys (Fernet) live here as 0600 files, written via
# write_secret_file (symlink-safe), mirroring how the access token is stored.
DEVICE_KEYS_DIR = os.path.join(DATABASE_DIR, "devices")

# --- FritzDump pcap source ---------------------------------------------------
# A built-in capture *device* whose packets come from tailing the pcap files the
# FritzDump module writes (a FRITZ!Box capture), instead of a live NIC. It shows
# up in the device list like any device, with its own Start/Stop (the per-device
# `enabled` flag): while disabled it captures nothing at all.
FRITZDUMP_DEVICE_ID = 'fritzdump'
# Master switch for the whole FritzDump module. OFF by default so a deployment
# that doesn't use it never sees the device, the reader thread, or the worker.
# Turn it on with FRITZDUMP_ENABLED=1 (the docker-compose.fritzdump.yml override
# sets this and bind-mounts the module).
FRITZDUMP_ENABLED = os.environ.get('FRITZDUMP_ENABLED', '0').strip().lower() not in ('0', 'false', 'no', '')
FRITZDUMP_DEVICE_NAME = os.environ.get('FRITZDUMP_DEVICE_NAME', '').strip() or 'FritzBox'
FRITZDUMP_DEVICE_COLOR = '#29B6F6'
# Privacy default: run the FritzDump capture in the module's *redacted* mode —
# packet payloads are stripped and only headers (who talks to whom, ports,
# sizes) are written, so real message contents are never persisted or shown.
# ON by default (fail-safe); set FRITZDUMP_REDACT=0 (or false/no/off) to capture
# full payloads. The hub injects this as FRITZ_REDACT into the worker's
# environment, which overrides whatever modules/FritzDump/.env says — so this is
# the single switch for whether real data can be seen.
FRITZDUMP_REDACT = os.environ.get('FRITZDUMP_REDACT', '1').strip().lower() not in ('0', 'false', 'no', 'off')
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
FRITZDUMP_DIR = os.environ.get('FRITZDUMP_DIR') or os.path.join(
    _APP_DIR, 'modules', 'FritzDump', 'dumps')
FRITZDUMP_POLL_INTERVAL = float(os.environ.get('FRITZDUMP_POLL_INTERVAL', '1.0'))

# Pressing Start should also LAUNCH the FritzDump capture worker (the process that
# logs into the box and writes the pcaps), not just tail an already-running one.
# FRITZDUMP_WORKER_DIR holds modules/FritzDump; the worker is its run.sh. Override
# the whole command with FRITZDUMP_WORKER_CMD (shell-split). Set FRITZDUMP_AUTOSTART=0
# if you start FritzDump yourself and only want the hub to read the pcaps.
FRITZDUMP_WORKER_DIR = os.environ.get('FRITZDUMP_WORKER_DIR') or os.path.join(
    _APP_DIR, 'modules', 'FritzDump')
FRITZDUMP_WORKER_MODE = os.environ.get('FRITZDUMP_WORKER_MODE', 'home')
_fdcmd = os.environ.get('FRITZDUMP_WORKER_CMD', '').strip()
if _fdcmd:
    FRITZDUMP_WORKER_CMD = shlex.split(_fdcmd)
else:
    _runsh = os.path.join(FRITZDUMP_WORKER_DIR, 'run.sh')
    FRITZDUMP_WORKER_CMD = ['bash', _runsh, FRITZDUMP_WORKER_MODE] if os.path.isfile(_runsh) else None
FRITZDUMP_AUTOSTART = os.environ.get('FRITZDUMP_AUTOSTART', '1') not in ('0', 'false', 'False', 'no')
# If the worker exits within this many seconds it is treated as a failed start
# (e.g. missing .env / credentials) and we back off instead of respawn-storming.
FRITZDUMP_WORKER_MIN_UPTIME = 8.0
FRITZDUMP_WORKER_BACKOFF = 30.0
# The worker's stdout/stderr go here (persistent, in the mounted database dir) so
# a failed run.sh (wrong .env, bad interface id, no route to the box) is visible:
#   cat database/fritzdump_worker.log
FRITZDUMP_WORKER_LOG = os.path.join(DATABASE_DIR, 'fritzdump_worker.log')

# --- Per-client Socket.IO rate limiting -------------------------------------
# Sliding window: caps how often a single client may invoke state-changing
# events such as pin_ip / reset_packet_count, preventing a flood of server-side
# DB writes. Keyed on the client IP (not the SID) so a client cannot bypass the
# limit by disconnecting and immediately reconnecting under a fresh SID.
SOCKET_RATE_LIMIT = int(os.environ.get('SOCKET_RATE_LIMIT', '5'))        # events per window
SOCKET_RATE_WINDOW = float(os.environ.get('SOCKET_RATE_WINDOW', '1.0'))  # window length (seconds)

# --- DoS protection limits ---------------------------------------------------
MAX_KNOWN_IPS = 10000
MAX_CACHE_SIZE = 5000
IP_UPDATE_INTERVAL = 1.0  # Min seconds between updates for the same IP
