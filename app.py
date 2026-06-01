import db
import threading
import time
from scapy.all import sniff, get_if_list
from capture_core import (
    is_valid_mac, is_private_ip, estimate_os, build_bpf_filter, classify_packet,
)
import device_crypto
from capture_sources import FritzDumpSource
import requests
import ipaddress
import sys
import socket
from zeroconf import ServiceBrowser, Zeroconf
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, disconnect
from uuid import uuid4
import logging
from multiprocessing import Process, Manager
from queue import Empty, Full, Queue as ThreadQueue
import os
import errno
import json
import signal
import subprocess
from contextlib import contextmanager
from functools import wraps
import secrets

# Pure, app-state-free helpers split out of this module for readability. They
# hold no globals and start no threads, so importing them here is side-effect-free.
from secret_files import write_secret_file
from netutils import (
    is_safe_redirect_target, get_local_ip, has_net_capabilities, is_admin,
    auto_detect_interface,
)
from validators import (
    sanitize_mdns_hostname, _clamp_int, _valid_port, _short_str,
    _valid_device_id, _COLOR_RE,
)
from packet_pipeline import PacketQueue, SharedStats
# Static configuration constants (paths, limits, timeouts, device/FritzDump
# defaults). Pure values, never rebound — NETWORK_INTERFACE stays in this module
# because validate_interface() reassigns it (a rebound global can't be imported).
from config import (
    LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_SECONDS,
    DATABASE_DIR, DATABASE_PATH, CACHE_TIMEOUT, API_TIMEOUT,
    DEFAULT_COORDS, EXPIRATION_SECONDS, RETENTION_SECONDS, MAX_IP_ROWS, SNIFF_TIMEOUT,
    SOCKETIO_PING_TIMEOUT, SOCKETIO_PING_INTERVAL,
    TRUSTED_ORGS_PATH, IP_LABELS_PATH,
    HIGH_RISK_COUNTRIES, HIGH_RISK_COUNTRY_THREAT_LEVEL,
    LOCAL_DEVICE_ID, LOCAL_DEVICE_COLOR, HUB_DEVICE_NAME, DEVICE_KEYS_DIR,
    FRITZDUMP_DEVICE_ID, FRITZDUMP_ENABLED, FRITZDUMP_DEVICE_NAME,
    FRITZDUMP_DEVICE_COLOR, FRITZDUMP_REDACT, FRITZDUMP_DIR, FRITZDUMP_POLL_INTERVAL,
    FRITZDUMP_WORKER_DIR, FRITZDUMP_WORKER_CMD,
    FRITZDUMP_AUTOSTART, FRITZDUMP_WORKER_MIN_UPTIME, FRITZDUMP_WORKER_BACKOFF,
    FRITZDUMP_WORKER_LOG,
    SOCKET_RATE_LIMIT, SOCKET_RATE_WINDOW,
    MAX_KNOWN_IPS, MAX_CACHE_SIZE,
    PACKET_WORKERS, PACKET_QUEUE_MAX, GEO_WORKERS,
)

# Logging Setup
# Default to INFO so high-traffic environments don't drown in (and fill the disk
# with) DEBUG output; set LOG_LEVEL=DEBUG to get the verbose stream back.
# If LOG_FILE is set, logs are written to a self-rotating file (LOG_MAX_BYTES per
# file, LOG_BACKUP_COUNT rollovers) so the log size stays bounded without relying
# on an external logrotate.
_log_level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
_log_format = '%(asctime)s - %(levelname)s - %(message)s'
_log_handlers = [logging.StreamHandler()]
_log_file = os.environ.get("LOG_FILE")
if _log_file:
    from logging.handlers import RotatingFileHandler
    _log_handlers.append(RotatingFileHandler(
        _log_file,
        maxBytes=int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024))),
        backupCount=int(os.environ.get("LOG_BACKUP_COUNT", "5")),
    ))
logging.basicConfig(level=_log_level, format=_log_format, handlers=_log_handlers)
logger = logging.getLogger(__name__)

# Security Configuration
# A fixed token can be supplied via the ACCESS_TOKEN env var (e.g. in .env) so it
# stays stable across restarts; otherwise a fresh random token is generated each
# start. Either way the active token is persisted to TOKEN_FILE (0600).
ACCESS_TOKEN = os.environ.get('ACCESS_TOKEN', '').strip() or secrets.token_urlsafe(16)
TOKEN_FILE = os.path.join("database", "access_token.txt")

# write_secret_file lives in secret_files.py (imported above).

try:
    if not os.path.exists("database"):
        os.makedirs("database")
    write_secret_file(TOKEN_FILE, ACCESS_TOKEN)
except Exception as e:
    logger.error(f"Could not save access token to file: {e}")

# Log hygiene: never write the token itself anywhere a log can capture it. The
# token value is only persisted to TOKEN_FILE (0600); we log a pointer, not the
# secret. Route it through the logger (not a bare stderr print) so it is subject
# to the same handling as every other log line. Retrieve with: cat database/access_token.txt
logger.info(f"Access token written to {TOKEN_FILE} (retrieve with: cat {TOKEN_FILE})")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            next_path = request.full_path.rstrip('?')
            return redirect(url_for('login', next=next_path))
        return f(*args, **kwargs)
    return decorated_function

# is_safe_redirect_target lives in netutils.py (imported above).


def safe_post_login_url(target):
    """Return a same-origin app URL for a validated post-login target.

    The redirect sink only receives URLs produced by url_for().  The user
    supplied value is used only to choose a route that Flask already knows
    about, never as the redirect URL itself.
    """
    if not is_safe_redirect_target(target):
        return url_for('index')
    try:
        path = target.split('?', 1)[0] or '/'
        adapter = app.url_map.bind('')
        endpoint, values = adapter.match(path, method='GET')
    except Exception:
        return url_for('index')
    if endpoint in ('login', 'static'):
        return url_for('index')
    return url_for(endpoint, **values)

# Brute-force protection for the login form (simple in-memory limiter).
# LOGIN_MAX_ATTEMPTS / LOGIN_LOCKOUT_SECONDS live in config.py (imported above).
login_attempts = {}  # ip -> [fail_count, first_attempt_ts, locked_until_ts]
login_attempts_lock = threading.Lock()

def login_is_locked(ip):
    """Return remaining lockout seconds for an IP, or 0 if not locked."""
    now = time.time()
    with login_attempts_lock:
        record = login_attempts.get(ip)
        if not record:
            return 0
        locked_until = record[2]
        if locked_until and now < locked_until:
            return int(locked_until - now)
        # Lockout window expired -> reset
        if locked_until and now >= locked_until:
            login_attempts.pop(ip, None)
        return 0

def login_register_failure(ip):
    """Record a failed login attempt and lock the IP once the limit is hit."""
    now = time.time()
    with login_attempts_lock:
        # Opportunistic cleanup to bound memory usage.
        for old_ip in [k for k, v in login_attempts.items()
                       if v[2] and now >= v[2] and now - v[1] > LOGIN_LOCKOUT_SECONDS]:
            login_attempts.pop(old_ip, None)
        record = login_attempts.get(ip, [0, now, 0])
        record[0] += 1
        if record[0] >= LOGIN_MAX_ATTEMPTS:
            record[2] = now + LOGIN_LOCKOUT_SECONDS
        login_attempts[ip] = record

def login_register_success(ip):
    with login_attempts_lock:
        login_attempts.pop(ip, None)

# Path to configuration file
BACKEND_CONF_PATH = os.path.join("database", "backend_conf.json")

def load_network_interface():
    """Loads the network interface from the NETWORK_INTERFACE env var (preferred
    for containerized runs) or the JSON configuration file."""
    env_iface = os.environ.get("NETWORK_INTERFACE")
    if env_iface:
        return env_iface
    try:
        if os.path.exists(BACKEND_CONF_PATH):
            with open(BACKEND_CONF_PATH, "r") as f:
                config = json.load(f)
                return config.get("network_interface", None)
        else:
            logger.warning(f"Configuration file {BACKEND_CONF_PATH} not found. Using default value.")
    except Exception as e:
        logger.error(f"Error loading configuration file {BACKEND_CONF_PATH}: {e}")
    return None

# Configuration. The scalar settings (paths, timeouts, device + FritzDump
# defaults) live in config.py (imported above); only the interface — which
# validate_interface() reassigns at runtime — and the CONFIG dict that wraps it
# are kept here.
CONFIG = {
    "network_interface": load_network_interface(),
    "cache_timeout": CACHE_TIMEOUT,
    "api_timeout": API_TIMEOUT,
    "database_dir": DATABASE_DIR,
    "database_path": DATABASE_PATH,
}
NETWORK_INTERFACE = CONFIG["network_interface"]

# --- Per-device Start/Stop ---------------------------------------------------
# A device's `enabled` flag is its Start/Stop. While a device is stopped, NONE of
# its traffic may be processed — not even in the background. The single chokepoint
# is process_packets (every captured packet, from every source process, flows
# through it in the main process), so a fast in-memory set of stopped device ids
# is consulted there. It is refreshed from the DB on startup and on every change.
disabled_devices = set()
disabled_devices_lock = threading.Lock()


def refresh_disabled_devices():
    """Reload the set of stopped (disabled) device ids from the DB."""
    global disabled_devices
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT device_id FROM devices WHERE enabled = FALSE")
            ids = {r[0] for r in c.fetchall()}
        # When the FritzDump module is switched off entirely, force it stopped
        # regardless of its stored flag so none of its traffic is ever processed.
        if not FRITZDUMP_ENABLED:
            ids.add(FRITZDUMP_DEVICE_ID)
        with locked(disabled_devices_lock):
            disabled_devices = ids
    except db.DBError as e:
        logger.error(f"Error refreshing disabled devices: {e}")


def device_is_disabled(device_id):
    with locked(disabled_devices_lock):
        return device_id in disabled_devices


# Global variables
geo_cache = {}
known_ips = set()
tcp_connections = {}
cache_lock = threading.Lock()
active_clients = set()
active_clients_lock = threading.Lock()
db_lock = threading.Lock()
pinned_ips_cache = {}
pinned_ips_cache_lock = threading.Lock()

# Per-client Socket.IO rate limiting (sliding window). SOCKET_RATE_LIMIT /
# SOCKET_RATE_WINDOW live in config.py (imported above); the in-memory window
# state stays here next to the limiter functions.
_socket_event_times = {}   # (client_ip, event_name) -> [timestamps]
_socket_rate_lock = threading.Lock()
# Opportunistic-prune threshold: once the window map exceeds this many keys we
# sweep expired entries inline, so memory stays bounded even if clients never
# disconnect cleanly (the disconnect-time prune alone could otherwise let stale
# (ip, event) windows accumulate). Holds the rate lock — see _socket_prune_locked.
_SOCKET_RATE_PRUNE_AT = 4096

def _socket_prune_locked(now):
    """Drop fully-expired rate-limit windows. Caller MUST hold _socket_rate_lock
    (threading.Lock is non-reentrant, so we never re-acquire it here)."""
    for key in [k for k, v in _socket_event_times.items()
                if all(now - t >= SOCKET_RATE_WINDOW for t in v)]:
        del _socket_event_times[key]

def socket_rate_limited(event_name):
    """Return True if the client IP has exceeded the rate for `event_name`."""
    try:
        client = request.remote_addr or request.sid
    except Exception:
        return False
    now = time.time()
    key = (client, event_name)
    with locked(_socket_rate_lock):
        if len(_socket_event_times) > _SOCKET_RATE_PRUNE_AT:
            _socket_prune_locked(now)
        times = [t for t in _socket_event_times.get(key, []) if now - t < SOCKET_RATE_WINDOW]
        if len(times) >= SOCKET_RATE_LIMIT:
            _socket_event_times[key] = times
            return True
        times.append(now)
        _socket_event_times[key] = times
        return False

def socket_rate_prune():
    """Drop fully-expired rate-limit windows (called on disconnect to bound
    memory). Intentionally IP-keyed entries are NOT cleared on disconnect so the
    limit persists across reconnects."""
    now = time.time()
    with locked(_socket_rate_lock):
        _socket_prune_locked(now)

# DoS-protection limits (MAX_KNOWN_IPS / MAX_CACHE_SIZE / IP_UPDATE_INTERVAL)
# live in config.py (imported above).
# MAX_PACKET_LEN and the BPF capture filter live in capture_core (shared with the
# sensor worker). The filter drops the dashboard's own TCP traffic on APP_PORT so
# the web UI is neither visualized nor adds parsing load under heavy traffic.
CAPTURE_BPF_FILTER = build_bpf_filter(os.environ.get('APP_PORT', '8000'))
last_ip_updates = {}

# PacketQueue and SharedStats live in packet_pipeline.py (imported above). The
# instances are still created in this module's __main__ (before the sniffer fork).
# Set by start_sniffing so the stats payload can read live queue backlog/drops.
_capture_queue = None

# MAC_RE / is_valid_mac live in capture_core (shared with the sensor). They
# validate any MAC before it is interpolated into an outbound API URL, preventing
# path-injection / SSRF via a crafted MAC seen on the wire.

def get_mac_vendor(mac):
    if not mac:
        return "Unknown"
    if not is_valid_mac(mac):
        # Never put an unvalidated value into the request URL.
        logger.warning(f"Refusing vendor lookup for malformed MAC: {mac!r}")
        return "Unknown"
    with locked(db_lock):
        try:
            with db.get_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT vendor FROM mac_cache WHERE mac = %s", (mac,))
                result = c.fetchone()
                if result:
                    return result[0]
        except db.DBError as e:
            logger.error(f"Error accessing mac_cache for MAC {mac}: {e}")
            return "Unknown"
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=API_TIMEOUT)
        if response.status_code == 200:
            vendor = response.text.strip() or "Unknown"
            if vendor != "Unknown":
                _remember_mac_vendor(mac, vendor)
            with locked(db_lock):
                try:
                    with db.get_connection() as conn:
                        c = conn.cursor()
                        c.execute("INSERT INTO mac_cache (mac, vendor) VALUES (%s, %s) "
                                  "ON CONFLICT (mac) DO UPDATE SET vendor = EXCLUDED.vendor", (mac, vendor))
                        conn.commit()
                except db.DBError as e:
                    logger.error(f"Error saving MAC {mac} to cache: {e}")
            return vendor
        elif response.status_code == 429:
            logger.warning(f"Rate limited at api.macvendors.com for MAC {mac}")
            time.sleep(5)
    except requests.RequestException as e:
        logger.warning(f"Error at api.macvendors.com for MAC {mac}: {e}")
    try:
        response = requests.get(f"https://maclookup.app/api/v2/macs/{mac}", timeout=2)
        if response.status_code == 200:
            vendor = response.json().get("company", "Unknown").strip() or "Unknown"
            if vendor != "Unknown":
                _remember_mac_vendor(mac, vendor)
            with locked(db_lock):
                try:
                    with db.get_connection() as conn:
                        c = conn.cursor()
                        c.execute("INSERT INTO mac_cache (mac, vendor) VALUES (%s, %s) "
                                  "ON CONFLICT (mac) DO UPDATE SET vendor = EXCLUDED.vendor", (mac, vendor))
                        conn.commit()
                except db.DBError as e:
                    logger.error(f"Error saving MAC {mac} to cache: {e}")
            return vendor
    except requests.RequestException as e:
        logger.warning(f"Error at maclookup.app for MAC {mac}: {e}")
    return "Unknown"

def get_mac_vendor_cached(mac):
    """Non-blocking vendor lookup: return the cached vendor or None on a miss.

    Used inside the packet-capture callbacks so capture is never blocked by an
    outbound HTTP lookup. Cache misses are resolved later by the background
    enrichment worker (see mac_enrichment_worker)."""
    if not is_valid_mac(mac):
        return None
    now = time.time()
    with locked(mac_vendor_hot_cache_lock):
        cached = mac_vendor_hot_cache.get(mac)
        if cached:
            vendor, expiry = cached
            if expiry > now:
                return vendor
            del mac_vendor_hot_cache[mac]
    # Read-only and on the capture path (also the forked sniffer process): use a
    # lock-free connection. WAL serves a consistent snapshot without blocking on
    # the writer.
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT vendor FROM mac_cache WHERE mac = %s", (mac,))
            result = c.fetchone()
            if result:
                _remember_mac_vendor(mac, result[0])
                return result[0]
            _remember_mac_vendor(mac, None, ttl=MAC_VENDOR_MISS_TTL)
            return None
    except db.DBError as e:
        logger.error(f"Error reading mac_cache for MAC {mac}: {e}")
        return None

# Background MAC-vendor enrichment. The capture path emits packets immediately
# with a "Unknown" vendor on a cache miss; this worker resolves the vendor in
# the background and pushes a 'mac_vendor_update' to clients once known.
mac_enrich_queue = ThreadQueue(maxsize=10000)
mac_enrich_inflight = set()
mac_enrich_lock = threading.Lock()
# Negative cache: MACs that recently resolved to "Unknown" (API miss/timeout) are
# parked here with an expiry so a flood of packets from the same (possibly spoofed)
# MAC cannot hammer the external vendor APIs. TTL is refreshed on each miss.
MAC_NEGATIVE_TTL = int(os.environ.get('MAC_NEGATIVE_TTL', str(24 * 3600)))
mac_negative_cache = {}  # mac -> expiry timestamp
# Hot-path read-through cache for mac_cache. Repeated packets from the same MAC
# should not borrow a DB connection every time; misses are cached briefly because
# the enrichment worker will refresh the entry once a vendor is learned.
MAC_VENDOR_CACHE_TTL = int(os.environ.get('MAC_VENDOR_CACHE_TTL', '300'))
MAC_VENDOR_MISS_TTL = int(os.environ.get('MAC_VENDOR_MISS_TTL', '30'))
mac_vendor_hot_cache = {}  # mac -> (vendor_or_None, expiry)
mac_vendor_hot_cache_lock = threading.Lock()

def _remember_mac_vendor(mac, vendor, ttl=MAC_VENDOR_CACHE_TTL):
    if not is_valid_mac(mac):
        return
    with locked(mac_vendor_hot_cache_lock):
        mac_vendor_hot_cache[mac] = (vendor, time.time() + ttl)

def queue_mac_enrichment(mac):
    """Schedule a background vendor lookup for `mac` (deduplicated, non-blocking)."""
    if not is_valid_mac(mac):
        return
    now = time.time()
    with locked(mac_enrich_lock):
        if mac in mac_enrich_inflight:
            return
        exp = mac_negative_cache.get(mac)
        if exp:
            if exp > now:
                return  # recently failed; don't re-query yet
            del mac_negative_cache[mac]  # expired -> allow a retry
        mac_enrich_inflight.add(mac)
    try:
        mac_enrich_queue.put_nowait(mac)
    except Full:
        with locked(mac_enrich_lock):
            mac_enrich_inflight.discard(mac)

def mac_enrichment_worker():
    while True:
        try:
            mac = mac_enrich_queue.get()
        except Exception as e:
            logger.error(f"Error reading mac enrichment queue: {e}")
            time.sleep(0.1)
            continue
        try:
            vendor = get_mac_vendor(mac)  # network lookup; also writes mac_cache
            if vendor and vendor != "Unknown":
                _remember_mac_vendor(mac, vendor)
                with locked(db_lock):
                    try:
                        with db.get_connection() as conn:
                            conn.execute(
                                "UPDATE ip_data SET vendor = %s WHERE mac = %s AND (vendor IS NULL OR vendor = 'Unknown')",
                                (vendor, mac),
                            )
                            conn.commit()
                    except db.DBError as e:
                        logger.error(f"Error updating vendor for MAC {mac}: {e}")
                socketio.emit('mac_vendor_update', {'mac': mac, 'vendor': vendor})
            else:
                # Unresolved: park in the negative cache so repeated packets from
                # this MAC don't keep re-querying the external APIs.
                with locked(mac_enrich_lock):
                    mac_negative_cache[mac] = time.time() + MAC_NEGATIVE_TTL
        except Exception as e:
            logger.error(f"Error enriching MAC {mac}: {e}")
        finally:
            with locked(mac_enrich_lock):
                mac_enrich_inflight.discard(mac)

def load_pinned_ips():
    global pinned_ips_cache
    # Read-only: lock-free connection.
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT ip, packet_count FROM pinned_ips")
            loaded = {row[0]: row[1] for row in c.fetchall()}
        with locked(pinned_ips_cache_lock):
            pinned_ips_cache = loaded
    except db.DBError as e:
        logger.error(f"Error loading pinned IPs: {e}")

def is_ip_pinned_cached(ip):
    with locked(pinned_ips_cache_lock):
        return ip in pinned_ips_cache

def update_pinned_ips(ip, is_pinned):
    global pinned_ips_cache
    with locked(db_lock):
        try:
            with db.get_connection() as conn:
                c = conn.cursor()
                if is_pinned:
                    c.execute("INSERT INTO pinned_ips (ip, packet_count) VALUES (%s, 0) "
                              "ON CONFLICT (ip) DO NOTHING", (ip,))
                    with locked(pinned_ips_cache_lock):
                        pinned_ips_cache[ip] = 0
                else:
                    c.execute("DELETE FROM pinned_ips WHERE ip = %s", (ip,))
                    with locked(pinned_ips_cache_lock):
                        pinned_ips_cache.pop(ip, None)
                conn.commit()
        except db.DBError as e:
            logger.error(f"Error updating pinned IPs for {ip}: {e}")

# Flask app and Socket.IO
app = Flask(__name__)

# Trust-proxy support (opt-in, OFF by default). Behind a reverse proxy
# (Nginx/HAProxy) request.remote_addr is the proxy's IP, so every client would
# collapse to one address and defeat the per-IP login lockout and Socket.IO
# rate limiting. ProxyFix makes those controls read the real client IP from
# X-Forwarded-For. This is deliberately disabled unless TRUST_PROXY is set:
# honouring those headers when NOT actually behind a trusted proxy would let
# any client forge its source IP, which is strictly worse than the default.
#
# ProxyFix's only protection is the hop count: with TRUST_PROXY_HOPS=N it trusts
# exactly the Nth-from-the-right X-Forwarded-For entry and ignores everything a
# client prepends. So it is safe ONLY when (a) the app is genuinely reachable
# only via that proxy, and (b) the proxy overwrites/strips any client-supplied
# X-Forwarded-For. Set N to the exact number of proxies in front of the app; a
# too-large N trusts a client-controlled hop and re-opens IP spoofing.
if os.environ.get('TRUST_PROXY', '').lower() in ('1', 'true', 'yes'):
    from werkzeug.middleware.proxy_fix import ProxyFix
    _proxy_hops = int(os.environ.get('TRUST_PROXY_HOPS', '1'))
    if _proxy_hops < 1:
        raise ValueError("TRUST_PROXY_HOPS must be >= 1 when TRUST_PROXY is enabled")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_hops, x_proto=_proxy_hops,
                            x_host=_proxy_hops, x_port=_proxy_hops)
    logger.warning(
        "ProxyFix ENABLED: trusting %d proxy hop(s) for X-Forwarded-* headers. "
        "The app MUST be reachable only through a trusted proxy that overwrites "
        "client-supplied X-Forwarded-For, or clients can spoof their source IP.",
        _proxy_hops)

SECRET_KEY_FILE = os.path.join("database", "secret_key")

def load_or_create_secret_key():
    """Return a stable Flask secret key.

    Priority: FLASK_SECRET_KEY env var > persisted file > newly generated and
    persisted. Persisting avoids invalidating every session (logging all users
    out) on each restart, which under a systemd auto-restart loop would behave
    like a self-inflicted DoS."""
    env_key = os.environ.get('FLASK_SECRET_KEY')
    if env_key:
        return env_key
    try:
        if os.path.islink(SECRET_KEY_FILE):
            raise OSError(f"{SECRET_KEY_FILE} is a symlink; refusing to read a secret through it")
        if os.path.exists(SECRET_KEY_FILE):
            with open(SECRET_KEY_FILE, 'r') as f:
                key = f.read().strip()
            if key:
                return key
        key = secrets.token_urlsafe(32)
        os.makedirs("database", exist_ok=True)
        write_secret_file(SECRET_KEY_FILE, key)
        return key
    except Exception as e:
        logger.error(f"Could not persist secret key ({e}); falling back to an ephemeral key")
        return secrets.token_urlsafe(32)

app.config['SECRET_KEY'] = load_or_create_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', '').lower() in ('1', 'true', 'yes'),
    PERMANENT_SESSION_LIFETIME=3600
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # The UI is never framed (no iframes), so deny framing outright. CSP
    # frame-ancestors 'none' is the modern, finer-grained control; X-Frame-Options
    # DENY is kept for older browsers that ignore frame-ancestors.
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # script-src has NO 'unsafe-inline': every script is loaded from a file or a
    # pinned CDN (no inline <script>, on*= handlers or javascript: URIs in the
    # templates), so inline script injection is blocked outright — the primary
    # XSS defence. style-src keeps 'unsafe-inline' because the 3D globe libraries
    # (three.js / globe.gl) and the login page set inline styles; CSP cannot
    # cover those without a nonce-per-element rewrite, and style injection is a
    # far weaker vector than script injection.
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://unpkg.com https://cdn.socket.io; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://*; connect-src 'self' ws: wss: https://raw.githubusercontent.com https://api.macvendors.com https://maclookup.app http://ip-api.com https://ipinfo.io https://api.ipify.org; frame-ancestors 'none';"
    return response

@app.before_request
def csrf_protect():
    # /socket.io is exempt because Socket.IO POSTs carry no form CSRF token; it is
    # instead protected by its own handshake and the cors_allowed_origins allow-list
    # (see socketio_origins below). Keep that in mind before adding any
    # state-changing/admin action over a socket event — such handlers must do their
    # own origin/permission check, since this guard won't cover them.
    # /api/ingest is a machine-to-machine endpoint authenticated by a per-device
    # Fernet key (no browser session, no form token), so the form-CSRF check can't
    # apply; it does its own auth. The JSON device-management API under /api/devices
    # is session-authenticated and, like the existing /api/organisations PUT, relies
    # on SameSite=Lax cookies to block cross-site state changes rather than the
    # single-use form token (which a fetch() body can't carry).
    csrf_exempt = (request.path == '/api/ingest'
                   or request.path == '/api/devices'
                   or request.path.startswith('/api/devices/'))
    if request.method == "POST" and not request.path.startswith('/socket.io') and not csrf_exempt:
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            logger.warning(f"CSRF attempt detected from {request.remote_addr}")
            return "Forbidden: CSRF Token invalid or missing", 403

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token
socketio_origins = os.environ.get('SOCKETIO_CORS_ORIGINS')
if socketio_origins:
    socketio_origins = [origin.strip() for origin in socketio_origins.split(',') if origin.strip()]
else:
    app_port = os.environ.get('APP_PORT', '8000')
    socketio_origins = [f"http://127.0.0.1:{app_port}", f"http://localhost:{app_port}"]

socketio = SocketIO(app, cors_allowed_origins=socketio_origins, async_mode='threading',
                    ping_timeout=SOCKETIO_PING_TIMEOUT, ping_interval=SOCKETIO_PING_INTERVAL)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    client_ip = request.remote_addr or 'unknown'
    if request.method == 'POST':
        remaining = login_is_locked(client_ip)
        if remaining > 0:
            logger.warning(f"Login blocked for {client_ip}: locked for {remaining}s")
            error = f'Too many failed attempts. Try again in {remaining} seconds.'
            return render_template('login.html', error=error), 429
        submitted_token = request.form.get('token', '')
        if secrets.compare_digest(submitted_token, ACCESS_TOKEN):
            login_register_success(client_ip)
            session.clear()
            session['authenticated'] = True
            target = request.args.get('next')
            return redirect(safe_post_login_url(target))
        login_register_failure(client_ip)
        logger.warning(f"Failed login attempt from {client_ip}")
        error = 'Invalid access token'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/trusted_organisations')
@login_required
def get_trusted_organisations():
    try:
        with open(TRUSTED_ORGS_PATH, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error loading trusted_organisations.json: {e}")
        return jsonify({"trusted_organisations": [], "suspicious_organisations": [], "dangerous_organisations": []}), 500


@app.route('/api/stats')
@login_required
def api_stats():
    """Current network counters: active IPs in the last hour, threat summary, total packets."""
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM ip_data WHERE last_seen > %s", (time.time() - 3600,))
            active_hour = c.fetchone()[0]
            c.execute("SELECT threat_level, COUNT(*) FROM ip_data GROUP BY threat_level")
            threats = {row[0]: row[1] for row in c.fetchall()}
            c.execute("SELECT COALESCE(SUM(incoming_count + outgoing_count), 0) FROM ip_data")
            total_packets = c.fetchone()[0]
        return jsonify({
            "active_last_hour": active_hour,
            "threat_summary": threats,
            "total_packets": int(total_packets),
        })
    except Exception as e:
        logger.error(f"Error in api_stats: {e}")
        return jsonify({"error": "stats unavailable"}), 500


@app.route('/api/recent')
@login_required
def api_recent():
    """Recent connections and threats from the PERMANENT ip_seen ledger, so the
    tickers can surface history that has already aged out of ip_data — not just
    the live in-memory points. Ordered by last_seen so 'most recent' is honest."""
    cols = "ip, first_seen, last_seen, org, country, hostname, threat_level, seen_count"

    def to_dict(r):
        return {"ip": r[0], "first_seen": r[1], "last_seen": r[2], "org": r[3],
                "country": r[4], "hostname": r[5], "threat_level": r[6], "seen_count": r[7]}
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute(f"SELECT {cols} FROM ip_seen ORDER BY last_seen DESC NULLS LAST LIMIT 60")
            newest = [to_dict(r) for r in c.fetchall()]
            c.execute(f"SELECT {cols} FROM ip_seen WHERE threat_level IN ('High','Medium','Low') "
                      "ORDER BY last_seen DESC NULLS LAST LIMIT 60")
            threats = [to_dict(r) for r in c.fetchall()]
        return jsonify({"newest": newest, "threats": threats})
    except Exception as e:
        logger.error(f"Error in api_recent: {e}")
        return jsonify({"error": "recent unavailable"}), 500


# Whitelisted sort columns for /api/connections (client key -> SQL expression).
# Only these may be interpolated into ORDER BY, so the param can never inject SQL.
_CONN_SORT_COLS = {
    "ip": "d.ip", "last_seen": "d.last_seen", "first_seen": "s.first_seen",
    "incoming_count": "d.incoming_count", "outgoing_count": "d.outgoing_count",
    "country": "d.country", "org": "d.org", "protocol": "d.protocol",
    "threat_level": "d.threat_level", "local_ip": "d.local_ip",
}
# Columns scanned by the free-text `q` parameter (ILIKE, OR-combined).
_CONN_SEARCH_COLS = ("d.ip", "d.hostname", "d.org", "d.country", "d.city",
                     "d.local_ip", "d.mac", "d.vendor")
# Exact-match filter columns (client key -> SQL column). Country is free text;
# threat/protocol are validated against a fixed vocabulary below.
_CONN_FILTER_COLS = {"country": "d.country", "threat": "d.threat_level", "protocol": "d.protocol"}
_CONN_THREATS = ("High", "Medium", "Low", "No Threat")
_CONN_PROTOCOLS = ("TCP", "UDP", "ICMP")
_EMPTY_CONN_SUMMARY = {"packets": 0, "lan_devices": 0, "protocol": {}, "threat": {}, "countries": [], "db_size": 0}

# Total on-disk size of the database, cached briefly. The History view shows it so
# the operator can see how much storage the retained history is using, but
# pg_database_size reads the catalog and the History query re-fires on every
# search/sort/filter keystroke — so cache it (the size barely moves second to
# second) instead of running it per request.
_db_size_cache = {"bytes": 0, "ts": 0.0}
_DB_SIZE_TTL = 30.0


def _db_size_bytes(c):
    now = time.time()
    if _db_size_cache["bytes"] and now - _db_size_cache["ts"] < _DB_SIZE_TTL:
        return _db_size_cache["bytes"]
    try:
        c.execute("SELECT pg_database_size(current_database())")
        size = int(c.fetchone()[0] or 0)
        _db_size_cache.update(bytes=size, ts=now)
        return size
    except Exception:
        return _db_size_cache["bytes"]


def _load_ip_labels():
    """Read the operator's IP -> friendly-name map (flat JSON, display-only).
    Returns {} if the file is missing or unreadable."""
    try:
        with open(IP_LABELS_PATH, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error(f"Error reading ip labels: {e}")
        return {}


def _connections_where(device, q, filters):
    """Build the shared WHERE clause + params for the historical connections
    query from the device scope, exact-match filters, free-text search, and the
    in-memory set of stopped devices (whose traffic is never surfaced). Returns
    (None, None) when the scope is a stopped device, i.e. there is nothing to
    show. Every column referenced is `d.*` so the clause is reusable for the row
    fetch and the aggregate queries alike."""
    clauses, params = [], []
    with locked(disabled_devices_lock):
        disabled = list(disabled_devices)
    if device and device != "all":
        if device in disabled:
            return None, None
        clauses.append("d.device_id = %s")
        params.append(device)
    elif disabled:
        clauses.append("d.device_id <> ALL(%s)")
        params.append(disabled)
    for key, col in _CONN_FILTER_COLS.items():
        val = filters.get(key)
        if val:
            clauses.append(f"{col} = %s")
            params.append(val)
    if q:
        like = f"%{q}%"
        ors = [f"{col} ILIKE %s" for col in _CONN_SEARCH_COLS]
        search_params = [like] * len(_CONN_SEARCH_COLS)
        # Also match the operator's custom IP/device names (stored off-DB in a
        # JSON file, not in ip_data): any IP whose friendly name contains the
        # query should surface too, mirroring the live-mode search.
        ql = q.lower()
        label_ips = [ip for ip, name in _load_ip_labels().items() if ql in name.lower()]
        if label_ips:
            ors.append("d.ip = ANY(%s)")
            search_params.append(label_ips)
        clauses.append("(" + " OR ".join(ors) + ")")
        params.extend(search_params)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _conn_row_to_dict(r):
    (device_id, ip, local_ip, lat, lon, city, country, org, last_seen, protocol,
     src_port, dst_port, mac, vendor, incoming_count, outgoing_count, hostname,
     os_, threat_level, first_seen) = r
    inc, out = incoming_count or 0, outgoing_count or 0
    return {
        "device_id": device_id, "ip": ip, "local_ip": local_ip,
        "lat": lat, "lng": lon, "city": city, "country": country, "org": org,
        "last_seen": last_seen, "protocol": protocol,
        "src_port": src_port, "dst_port": dst_port, "mac": mac, "vendor": vendor,
        "incoming_count": inc, "outgoing_count": out, "packet_count": inc + out,
        # Private IPs show their own address rather than a (often misleading)
        # reverse-DNS hostname, matching send_all_ips_to_client.
        "hostname": ip if is_private_ip(ip) else hostname,
        "os": os_, "threat_level": threat_level or "No Threat",
        "first_seen": first_seen, "first_seen_ever": first_seen,
    }


@app.route('/api/connections')
@login_required
def api_connections():
    """Search the full retained connection history (ip_data, ~30 days) instead of
    only the live in-memory points. Powers the History mode of the Statistics +
    Connections tabs: returns the matching rows (sorted, capped) plus aggregates
    computed over the ENTIRE match set so the KPIs/charts reflect all history, not
    just the returned page, plus a country facet for the filter dropdown."""
    device = _short_str(request.args.get('device', 'all'), 'all', 64)
    q = _short_str(request.args.get('q', '').strip(), '', 128)
    sort_col = _CONN_SORT_COLS.get(request.args.get('sort'), "d.last_seen")
    direction = "ASC" if request.args.get('dir') == 'asc' else "DESC"
    limit = _clamp_int(request.args.get('limit'), 1, 1000, 500)
    raw_threat = request.args.get('threat')
    raw_proto = request.args.get('protocol')
    filters = {
        "country": _short_str(request.args.get('country', ''), '', 64) or None,
        "threat": raw_threat if raw_threat in _CONN_THREATS else None,
        "protocol": raw_proto if raw_proto in _CONN_PROTOCOLS else None,
    }

    # Facets (country dropdown) ignore the country/threat/protocol filters so the
    # operator can always switch between every available value; rows + summary use
    # the full filter set.
    base_where, base_params = _connections_where(device, q, {})
    where, params = _connections_where(device, q, filters)
    if where is None:  # scope is a stopped device -> nothing to show
        empty_summary = dict(_EMPTY_CONN_SUMMARY)
        empty_summary["db_size"] = _db_size_cache["bytes"]  # last-known, no extra query
        return jsonify({"rows": [], "total": 0, "summary": empty_summary, "facets": {"countries": []}})

    cols = ("d.device_id, d.ip, d.local_ip, d.lat, d.lon, d.city, d.country, d.org, "
            "d.last_seen, d.protocol, d.src_port, d.dst_port, d.mac, d.vendor, "
            "d.incoming_count, d.outgoing_count, d.hostname, d.os, d.threat_level, s.first_seen")
    country_cond = "d.country IS NOT NULL AND d.country <> ''"
    country_where = f"{where} AND {country_cond}" if where else f" WHERE {country_cond}"
    facet_where = f"{base_where} AND {country_cond}" if base_where else f" WHERE {country_cond}"
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute(
                f"SELECT {cols} FROM ip_data d LEFT JOIN ip_seen s ON s.ip = d.ip"
                f"{where} ORDER BY {sort_col} {direction} NULLS LAST LIMIT %s",
                (*params, limit))
            rows = [_conn_row_to_dict(r) for r in c.fetchall()]
            # Aggregates over the FULL filtered set (the page limit is ignored).
            c.execute(f"SELECT COUNT(*), COALESCE(SUM(d.incoming_count + d.outgoing_count), 0), "
                      f"COUNT(DISTINCT d.local_ip) FROM ip_data d{where}", params)
            total, packets, lan_devices = c.fetchone()
            c.execute(f"SELECT d.protocol, COUNT(*) FROM ip_data d{where} GROUP BY d.protocol", params)
            protocol = {(r[0] or 'Other'): r[1] for r in c.fetchall()}
            c.execute(f"SELECT d.threat_level, COUNT(*) FROM ip_data d{where} GROUP BY d.threat_level", params)
            threat = {(r[0] or 'No Threat'): r[1] for r in c.fetchall()}
            # Count DISTINCT IPs per country (not rows): "how many IPs are in
            # this country", deduped across capture devices.
            c.execute(f"SELECT d.country, COUNT(DISTINCT d.ip) AS n FROM ip_data d{country_where} "
                      f"GROUP BY d.country ORDER BY n DESC LIMIT 15", params)
            countries = [[r[0], r[1]] for r in c.fetchall()]
            # Country facet for the dropdown: every country (filter-independent)
            # with its distinct-IP count, so each option can show how many IPs it
            # holds. Ordered by count so the busiest countries surface first.
            c.execute(f"SELECT d.country, COUNT(DISTINCT d.ip) AS n FROM ip_data d{facet_where} "
                      f"GROUP BY d.country ORDER BY n DESC LIMIT 200", base_params)
            facet_countries = [[r[0], r[1]] for r in c.fetchall()]
            db_size = _db_size_bytes(c)
        return jsonify({
            "rows": rows,
            "total": int(total or 0),
            "summary": {
                "packets": int(packets or 0),
                "lan_devices": int(lan_devices or 0),
                "protocol": protocol,
                "threat": threat,
                "countries": countries,
                "db_size": db_size,
            },
            "facets": {"countries": facet_countries},
        })
    except Exception as e:
        logger.error(f"Error in api_connections: {e}")
        return jsonify({"error": "connections unavailable"}), 500


@app.route('/api/devices/stats')
@login_required
def api_device_stats():
    """Per-device totals over the full retained history (ip_data, ~30 days):
    distinct connections, total packets and the most recent activity. Lets the
    Devices tab show each device's history at a glance, not just its live state."""
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT device_id, COUNT(*), "
                      "COALESCE(SUM(incoming_count + outgoing_count), 0), MAX(last_seen) "
                      "FROM ip_data GROUP BY device_id")
            stats = {r[0]: {"connections": int(r[1]), "packets": int(r[2] or 0),
                            "last_seen": r[3]} for r in c.fetchall()}
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error in api_device_stats: {e}")
        return jsonify({"error": "device stats unavailable"}), 500


@app.route('/api/globe/points')
@login_required
def api_globe_points():
    """Every retained IP that has a known location, for the globe's History view.
    Lightweight projection (coordinates + the label/threat fields the globe needs);
    rows without coordinates and stopped devices are excluded, and the result is
    capped at MAX_IP_ROWS so a huge ledger can't blow up the payload."""
    try:
        with locked(disabled_devices_lock):
            disabled = list(disabled_devices)
        clauses = ["d.lat IS NOT NULL", "d.lon IS NOT NULL", "NOT (d.lat = 0 AND d.lon = 0)"]
        params = []
        if disabled:
            clauses.append("d.device_id <> ALL(%s)")
            params.append(disabled)
        where = " WHERE " + " AND ".join(clauses)
        with db_connect() as conn:
            c = conn.cursor()
            c.execute(f"""SELECT d.device_id, d.ip, d.local_ip, d.lat, d.lon, d.city, d.country,
                          d.org, d.last_seen, d.protocol, d.incoming_count, d.outgoing_count,
                          d.hostname, d.threat_level
                          FROM ip_data d{where}
                          ORDER BY d.last_seen DESC NULLS LAST LIMIT %s""",
                      (*params, MAX_IP_ROWS))
            rows = c.fetchall()
        pts = []
        for (device_id, ip, local_ip, lat, lon, city, country, org, last_seen, protocol,
             inc, out, hostname, threat_level) in rows:
            pts.append({
                "device_id": device_id, "ip": ip, "local_ip": local_ip,
                "lat": lat, "lng": lon, "city": city, "country": country, "org": org,
                "last_seen": last_seen, "protocol": protocol,
                "incoming_count": inc or 0, "outgoing_count": out or 0,
                "packet_count": (inc or 0) + (out or 0),
                "hostname": ip if is_private_ip(ip) else hostname,
                "threat_level": threat_level or "No Threat",
            })
        return jsonify({"points": pts})
    except Exception as e:
        logger.error(f"Error in api_globe_points: {e}")
        return jsonify({"error": "globe points unavailable"}), 500


@app.route('/api/export/csv')
@login_required
def api_export_csv():
    """Download all tracked IPs as a CSV file."""
    import io
    import csv as csv_mod
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT ip, city, country, org, protocol,
                       src_port, dst_port, incoming_count, outgoing_count,
                       mac, vendor, hostname, os, last_seen
                FROM ip_data ORDER BY last_seen DESC
            """)
            rows = c.fetchall()
        buf = io.StringIO()
        writer = csv_mod.writer(buf)
        writer.writerow(['IP', 'City', 'Country', 'Organization', 'Protocol',
                         'Src Port', 'Dst Port', 'Packets In', 'Packets Out',
                         'MAC', 'Vendor', 'Hostname', 'OS', 'Last Seen'])
        for row in rows:
            *fields, last_seen = row
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_seen)) if last_seen else ''
            writer.writerow([*fields, ts])
        from flask import Response
        return Response(
            buf.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename="connections.csv"'},
        )
    except Exception as e:
        logger.error(f"Error in api_export_csv: {e}")
        return "Export failed", 500


@app.route('/api/organisations', methods=['GET', 'PUT'])
@login_required
def api_organisations():
    """Read (GET) or overwrite (PUT) the trusted/suspicious/dangerous organisation lists."""
    if request.method == 'GET':
        try:
            with open(TRUSTED_ORGS_PATH, 'r') as f:
                return jsonify(json.load(f))
        except Exception as e:
            logger.error(f"Error reading organisations: {e}")
            return jsonify({"error": "read failed"}), 500

    # PUT — validate and overwrite
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    allowed = {'trusted_organisations', 'suspicious_organisations', 'dangerous_organisations'}
    if not allowed.issuperset(data.keys()):
        return jsonify({"error": "unexpected keys"}), 400
    for key in allowed:
        if key in data and not isinstance(data[key], list):
            return jsonify({"error": f"{key} must be a list"}), 400
    try:
        with open(TRUSTED_ORGS_PATH, 'r') as f:
            existing = json.load(f)
        existing.update(data)
        with open(TRUSTED_ORGS_PATH, 'w') as f:
            json.dump(existing, f, indent=4)
        logger.info(f"Organisation lists updated by {request.remote_addr}")
        return jsonify({"status": "ok"})
    except Exception as e:
        logger.error(f"Error updating organisations: {e}")
        return jsonify({"error": "write failed"}), 500


@app.route('/api/ip-labels', methods=['GET', 'PUT'])
@login_required
def api_ip_labels():
    """Read (GET) or overwrite (PUT) the operator's IP -> friendly-name map.

    Stored as a flat JSON object, e.g. {"192.168.178.100": "PC-E1"}. Used purely
    for display (the dashboard shows the name next to a LAN IP)."""
    if request.method == 'GET':
        return jsonify(_load_ip_labels())

    # PUT — replace the whole map. Validate it's a flat {str: str} object and
    # cap the size so a stray client can't write an unbounded file.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400
    if len(data) > 5000:
        return jsonify({"error": "too many entries"}), 400
    cleaned = {}
    for ip, name in data.items():
        if not isinstance(ip, str) or not isinstance(name, str):
            return jsonify({"error": "keys and values must be strings"}), 400
        ip = ip.strip()
        name = name.strip()[:64]
        if ip and name:
            cleaned[ip] = name
    try:
        with open(IP_LABELS_PATH, 'w') as f:
            json.dump(cleaned, f, indent=4)
        logger.info(f"IP labels updated by {request.remote_addr} ({len(cleaned)} entries)")
        return jsonify({"status": "ok", "count": len(cleaned)})
    except Exception as e:
        logger.error(f"Error updating ip labels: {e}")
        return jsonify({"error": "write failed"}), 500


# mDNS Listener
#
# mDNS announcements are unauthenticated broadcasts from the local segment, so
# every field here is attacker-controllable. Two concrete risks are addressed:
#  * Resource exhaustion: a host can broadcast thousands of spoofed service
#    announcements. Without a bound, MDNSListener.devices grows linearly until
#    OOM. We cap it (MDNS_MAX_DEVICES) and expire stale entries (MDNS_DEVICE_TTL).
#  * Spoofing/injection: a crafted service name can impersonate a gateway and
#    carry markup or control characters into the DB and the browser UI. mDNS
#    hostnames are therefore sanitized to a short, safe charset before storage.
MDNS_MAX_DEVICES = int(os.environ.get('MDNS_MAX_DEVICES', '4096'))
MDNS_DEVICE_TTL = int(os.environ.get('MDNS_DEVICE_TTL', str(2 * 3600)))  # 2 hours
# sanitize_mdns_hostname lives in validators.py (imported above).

class MDNSListener:
    def __init__(self):
        self.devices = {}        # ip -> sanitized hostname
        self._seen = {}          # ip -> last-announcement timestamp
        self._lock = threading.Lock()

    def _prune(self, now):
        # Drop entries older than the TTL; if still over the cap, evict oldest.
        expired = [ip for ip, ts in self._seen.items() if now - ts > MDNS_DEVICE_TTL]
        for ip in expired:
            self.devices.pop(ip, None)
            self._seen.pop(ip, None)
        overflow = len(self._seen) - MDNS_MAX_DEVICES
        if overflow > 0:
            for ip, _ in sorted(self._seen.items(), key=lambda kv: kv[1])[:overflow]:
                self.devices.pop(ip, None)
                self._seen.pop(ip, None)

    def remove_service(self, zeroconf, type, name):
        logger.info(f"mDNS service removed: {name}")

    def add_service(self, zeroconf, type, name):
        try:
            info = zeroconf.get_service_info(type, name)
            if info and info.addresses:
                ip = socket.inet_ntoa(info.addresses[0])
                hostname = sanitize_mdns_hostname(name.split('.')[0])
                now = time.time()
                with self._lock:
                    self.devices[ip] = hostname
                    self._seen[ip] = now
                    self._prune(now)
                logger.info(f"mDNS service added: {ip} -> {hostname}")
        except Exception as e:
            logger.error(f"Error adding mDNS service {name}: {e}")

    def update_service(self, zeroconf, type, name):
        pass

def init_trusted_organisations():
    try:
        if not os.path.exists(TRUSTED_ORGS_PATH):
            logger.info(f"Creating {TRUSTED_ORGS_PATH} with default values")
            default_orgs = {
                "trusted_organisations": [
                    "Google LLC", "Total Uptime Technologies, LLC", "Amazon.com, Inc.",
                    "Microsoft Corporation", "Cloudflare, Inc.", "Apple Inc.",
                    "Meta Platforms, Inc.", "GitHub, Inc.", "Akamai Technologies, Inc.",
                    "Google Cloud", "AWS CloudFront"
                ],
                "suspicious_organisations": [
                    "Unknown ISP", "Generic Hosting", "Suspected Proxy Service"
                ],
                "dangerous_organisations": [
                    "Malware Host", "Known Botnet", "Dark Web Service"
                ]
            }
            with open(TRUSTED_ORGS_PATH, 'w') as f:
                json.dump(default_orgs, f, indent=4)
            logger.info(f"{TRUSTED_ORGS_PATH} created successfully")
        else:
            logger.info(f"{TRUSTED_ORGS_PATH} already exists")
    except Exception as e:
        logger.error(f"Error initializing {TRUSTED_ORGS_PATH}: {e}")

def start_mdns_listener():
    try:
        zeroconf = Zeroconf()
        listener = MDNSListener()
        ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
        return zeroconf, listener
    except Exception as e:
        logger.error(f"Error starting mDNS listener: {e}")
        return None, None

# get_local_ip, has_net_capabilities, is_admin and auto_detect_interface live in
# netutils.py (imported above).

def validate_interface():
    available_interfaces = get_if_list()
    global NETWORK_INTERFACE
    if not NETWORK_INTERFACE or NETWORK_INTERFACE not in available_interfaces:
        if NETWORK_INTERFACE:
            logger.warning(f"Interface '{NETWORK_INTERFACE}' not found! Available interfaces: {available_interfaces}")
        detected = auto_detect_interface()
        if detected:
            NETWORK_INTERFACE = detected
            logger.info(f"Auto-detected interface: {NETWORK_INTERFACE}")
        else:
            logger.error("No network interfaces found!")
            sys.exit(1)

@contextmanager
def locked(lock):
    lock.acquire()
    try:
        yield
    finally:
        lock.release()

def db_connect():
    """Borrow a pooled PostgreSQL connection for a READ.

    Reads run WITHOUT db_lock: PostgreSQL serves every reader a consistent MVCC
    snapshot concurrently with writers, so a client's initial load
    (send_all_ips_to_client) and the hot-path pinned-IP check never wait on the
    1s write-flush transaction. Writers still take db_lock so the read-modify-
    write sequences (counter accumulation in flush_ip_writes) stay serialized
    within the process that performs every write."""
    return db.get_connection()

def init_db():
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)
        logger.info(f"Database directory created: {DATABASE_DIR}")
    init_trusted_organisations()
    # Block until the database container is accepting connections.
    db.wait_until_ready()
    with locked(db_lock):
        try:
            with db.get_connection() as conn:
                c = conn.cursor()
                # Create tables. ip_data is keyed by (device_id, ip): the same
                # external IP can be seen by several capture devices, each keeping
                # its own counts/ports/last_seen for it.
                c.execute('''CREATE TABLE IF NOT EXISTS ip_data
                             (device_id TEXT NOT NULL DEFAULT 'local', ip TEXT,
                              lat DOUBLE PRECISION, lon DOUBLE PRECISION, city TEXT,
                              country TEXT, last_seen DOUBLE PRECISION, org TEXT,
                              src_port INTEGER, dst_port INTEGER, protocol TEXT, incoming_count BIGINT DEFAULT 0,
                              outgoing_count BIGINT DEFAULT 0, mac TEXT, vendor TEXT, hostname TEXT, os TEXT,
                              local_ip TEXT, threat_level TEXT,
                              PRIMARY KEY (device_id, ip))''')
                # Devices: the hub's own local capture plus any registered remote
                # sensors. Secrets (Fernet keys) are NOT stored here — only on disk
                # under DEVICE_KEYS_DIR (0600) — so a DB leak yields no sensor key.
                c.execute('''CREATE TABLE IF NOT EXISTS devices
                             (device_id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT,
                              kind TEXT NOT NULL DEFAULT 'remote', public_ip TEXT,
                              lat DOUBLE PRECISION, lon DOUBLE PRECISION,
                              enabled BOOLEAN NOT NULL DEFAULT TRUE, seq BIGINT NOT NULL DEFAULT 0,
                              last_seen DOUBLE PRECISION, created_at DOUBLE PRECISION)''')
                c.execute('''CREATE TABLE IF NOT EXISTS pinned_ips
                             (ip TEXT PRIMARY KEY, packet_count BIGINT DEFAULT 0)''')
                c.execute('''CREATE TABLE IF NOT EXISTS settings
                             (key TEXT PRIMARY KEY, value TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS mac_cache
                             (mac TEXT PRIMARY KEY, vendor TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS threat_list
                             (ip TEXT PRIMARY KEY, threat_level TEXT, source TEXT)''')
                # Permanent first-/last-seen ledger of EVERY IP ever observed.
                # Unlike ip_data this is NEVER expired or trimmed by
                # cleanup_expired_ips, so "have we ever talked to this IP, and
                # since when?" stays answerable forever — across retention and
                # restarts. It is deliberately lightweight (no per-packet counts,
                # no ports) so it can grow to one row per unique IP indefinitely.
                # The longer the system runs cleanly, the more confidently a
                # never-before-seen IP stands out as genuinely new.
                c.execute('''CREATE TABLE IF NOT EXISTS ip_seen
                             (ip TEXT PRIMARY KEY,
                              first_seen DOUBLE PRECISION, last_seen DOUBLE PRECISION,
                              org TEXT, country TEXT, hostname TEXT,
                              threat_level TEXT, seen_count BIGINT DEFAULT 0)''')

                # Migrate a pre-multi-device ip_data (single-column 'ip' PK) in
                # place: add device_id, then swap the PK to (device_id, ip).
                # Idempotent — only runs when the PK isn't already composite.
                c.execute('''SELECT a.attname FROM pg_index i
                             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                             WHERE i.indrelid = 'ip_data'::regclass AND i.indisprimary''')
                pk_cols = {r[0] for r in c.fetchall()}
                if pk_cols != {'device_id', 'ip'}:
                    c.execute("ALTER TABLE ip_data ADD COLUMN IF NOT EXISTS device_id TEXT NOT NULL DEFAULT 'local'")
                    c.execute("ALTER TABLE ip_data DROP CONSTRAINT IF EXISTS ip_data_pkey")
                    c.execute("ALTER TABLE ip_data ADD PRIMARY KEY (device_id, ip)")
                # Local (LAN) peer of each external connection — which device in the
                # network the external IP is actually talking to (most useful for the
                # FritzDump source, which sees the whole home LAN).
                c.execute("ALTER TABLE ip_data ADD COLUMN IF NOT EXISTS local_ip TEXT")
                # Persisted threat classification for the row (High/Medium/Low/No
                # Threat). Read by /api/stats' threat_summary and by the retention
                # cleanup, which never expires a threat-flagged IP. Older databases
                # predate the column — add it idempotently.
                c.execute("ALTER TABLE ip_data ADD COLUMN IF NOT EXISTS threat_level TEXT")

                # Create indexes
                c.execute("CREATE INDEX IF NOT EXISTS idx_ip_data_last_seen ON ip_data(last_seen)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_ip_data_ip ON ip_data(ip)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_threat_list_ip ON threat_list(ip)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_ip_seen_last_seen ON ip_seen(last_seen)")

                # Seed the built-in local-capture device (kind='local').
                c.execute('''INSERT INTO devices (device_id, name, color, kind, enabled, seq, created_at)
                             VALUES (%s, %s, %s, 'local', TRUE, 0, %s)
                             ON CONFLICT (device_id) DO NOTHING''',
                          (LOCAL_DEVICE_ID, HUB_DEVICE_NAME, LOCAL_DEVICE_COLOR, time.time()))

                # Seed the built-in FritzDump pcap-source device (kind='pcap').
                # It starts STOPPED (enabled=FALSE): the user presses Start in the
                # dashboard once FritzDump is producing pcaps.
                c.execute('''INSERT INTO devices (device_id, name, color, kind, enabled, seq, created_at)
                             VALUES (%s, %s, %s, 'pcap', FALSE, 0, %s)
                             ON CONFLICT (device_id) DO NOTHING''',
                          (FRITZDUMP_DEVICE_ID, FRITZDUMP_DEVICE_NAME, FRITZDUMP_DEVICE_COLOR, time.time()))

                # Initialize settings
                c.executemany(
                    "INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                    [
                        ('is_internal_search_active', '0'),
                        ('show_all_udp_packets', '1'),
                        ('show_local_network', '1'),
                        ('show_external_network', '1'),
                        ('show_tcp_only', '0'),
                    ],
                )
                conn.commit()
        except db.DBError as e:
            logger.error(f"Error initializing database: {e}")
    # Prime the in-memory Start/Stop set from the persisted enabled flags.
    refresh_disabled_devices()
    # Prime the in-memory pin set used by process_packets to avoid one DB read
    # per private packet while internal search is disabled.
    load_pinned_ips()

_BOOL_SETTINGS = {
    'is_internal_search_active', 'show_all_udp_packets',
    'show_local_network', 'show_external_network', 'show_tcp_only',
}


def load_settings():
    settings = {
        'is_internal_search_active': True,
        'show_all_udp_packets': True,
        'show_local_network': True,
        'show_external_network': True,
        'show_tcp_only': False
    }
    # Read-only (called on every client connect): lock-free connection.
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute('SELECT key, value FROM settings')
            for key, value in c.fetchall():
                if key == _STATS_SETTINGS_KEY:
                    continue  # internal stats snapshot, not a client-facing setting
                if key in _BOOL_SETTINGS:
                    settings[key] = value == '1'
                else:
                    settings[key] = value
        logger.debug(f"Loaded settings: {settings}")
        return settings
    except db.DBError as e:
        logger.error(f"Error loading settings: {e}")
        return settings

def schedule_threat_list_updates():
    while True:
        try:
            update_threat_list()
            time.sleep(86400)
        except Exception as e:
            logger.error(f"Error updating threat lists: {e}")
            time.sleep(3600)

def update_threat_list():
    threat_sources = {
        "firehol_level1": ("High", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
        "firehol_level2": ("High", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"),
        "firehol_level3": ("Medium", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"),
        "anonymous_proxies": ("Medium", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxy_ips.netset"),
        "malicious_web_clients": ("High", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malicious_web_clients.netset"),
        "30_day_greylist": ("Low", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/30d.ipset"),
        "24_hour_blacklist": ("Medium", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/24h.ipset"),
        "web_server_threats": ("Medium", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/web_server.netset")
    }

    batch_size = 1000

    # Fetch ALL threat data over the network first, WITHOUT holding db_lock.
    # Network I/O here can take many seconds per source; holding the lock (and an
    # already-emptied table) for that long would block every other DB user and
    # leave the threat_list empty mid-update. Collect everything, then swap.
    collected = []  # list of (ip, threat_level, source)
    for source, (threat_level, url) in threat_sources.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                ips = [ip for ip in response.text.splitlines() if ip and not ip.startswith("#")]
                collected.extend((ip, threat_level, source) for ip in ips)
                logger.info(f"Threat list fetched: {source} ({len(ips)} entries)")
            else:
                logger.warning(f"Threat list {source} returned HTTP {response.status_code}; skipping")
        except Exception as e:
            logger.error(f"Error fetching threat list {source}: {e}")

    if not collected:
        # Nothing fetched (e.g. offline). Keep the existing table rather than
        # wiping it and leaving the system with no threat intelligence.
        logger.warning("No threat data fetched; leaving existing threat_list unchanged")
        return

    # Only now take the lock, and only to clear and re-populate the table.
    with locked(db_lock):
        try:
            with db.get_connection() as conn:
                c = conn.cursor()
                c.execute("DELETE FROM threat_list")
                for i in range(0, len(collected), batch_size):
                    c.executemany(
                        "INSERT INTO threat_list (ip, threat_level, source) VALUES (%s, %s, %s) "
                        "ON CONFLICT (ip) DO NOTHING",
                        collected[i:i + batch_size],
                    )
                conn.commit()
            logger.info(f"Threat list updated: {len(collected)} entries from {len(threat_sources)} sources")
        except db.DBError as e:
            logger.error(f"Error updating threat list: {e}")

# Start the thread
threading.Thread(target=schedule_threat_list_updates, daemon=True).start()

@socketio.on('set_local_network')
def handle_set_local_network(data):
    if not session.get('authenticated'):
        return
    if socket_rate_limited('set_local_network'):
        logger.warning(f"Rate limit exceeded for set_local_network from SID {request.sid}")
        return
    try:
        show_local = data.get('showLocalNetwork', True)
        if not isinstance(show_local, bool):
            logger.error(f"Invalid value for showLocalNetwork: {show_local}")
            return
        save_setting('show_local_network', show_local)
        socketio.emit('settings_update', {'show_local_network': show_local})
        logger.info(f"Local network {'shown' if show_local else 'hidden'}")
    except Exception as e:
        logger.error(f"Error in set_local_network: {e}")

@socketio.on('set_external_network')
def handle_set_external_network(data):
    if not session.get('authenticated'):
        return
    if socket_rate_limited('set_external_network'):
        logger.warning(f"Rate limit exceeded for set_external_network from SID {request.sid}")
        return
    try:
        show_external = data.get('showExternalNetwork', True)
        if not isinstance(show_external, bool):
            logger.error(f"Invalid value for showExternalNetwork: {show_external}")
            return
        save_setting('show_external_network', show_external)
        socketio.emit('settings_update', {'show_external_network': show_external})
        logger.info(f"External network {'shown' if show_external else 'hidden'}")
    except Exception as e:
        logger.error(f"Error in set_external_network: {e}")

@socketio.on('set_tcp_only')
def handle_set_tcp_only(data):
    if not session.get('authenticated'):
        return
    if socket_rate_limited('set_tcp_only'):
        logger.warning(f"Rate limit exceeded for set_tcp_only from SID {request.sid}")
        return
    try:
        show_tcp = data.get('showTCPOnly', False)
        if not isinstance(show_tcp, bool):
            logger.error(f"Invalid value for showTCPOnly: {show_tcp}")
            return
        save_setting('show_tcp_only', show_tcp)
        socketio.emit('settings_update', {'show_tcp_only': show_tcp})
        logger.info(f"TCP-only connections {'enabled' if show_tcp else 'disabled'}")
    except Exception as e:
        logger.error(f"Error in set_tcp_only: {e}")

def save_setting(key, value):
    with locked(db_lock):
        try:
            with db.get_connection() as conn:
                c = conn.cursor()
                db_value = ('1' if value else '0') if key in _BOOL_SETTINGS else value
                c.execute('INSERT INTO settings (key, value) VALUES (%s, %s) '
                          'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value', (key, db_value))
                conn.commit()
        except db.DBError as e:
            logger.error(f"Error saving setting {key}: {e}")

# is_private_ip / estimate_os / UDP_FILTER_PORTS live in capture_core (shared
# with the sensor worker).

api_call_lock = threading.Lock()
last_api_call = 0
API_CALL_INTERVAL = 0.1

# Geolocation providers. Local MaxMind .mmdb files are primary; ipinfo.io
# (HTTPS) is the network fallback. ip-api.com (HTTP, unencrypted) leaks the
# queried IPs to a third party on the wire, so it is OFF by default and only
# used when ALLOW_INSECURE_GEO_API is explicitly enabled. Provide IPINFO_TOKEN
# for higher HTTPS limits.
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '').strip()
ALLOW_INSECURE_GEO_API = os.environ.get('ALLOW_INSECURE_GEO_API', '0').lower() in ('1', 'true', 'yes')

# Local MaxMind GeoLite2 databases (offline geo + ASN lookups). Resolving from
# local .mmdb files removes per-IP network latency AND the external rate limit
# (the HTTP path is gated by API_CALL_INTERVAL to ~10 IPs/s), so enriching a flood
# of new IPs no longer trickles at the API rate. These are read-only mmap files,
# safe to share across threads and the forked sniffer process. If the library or
# the files are missing we transparently fall back to the HTTP providers below.
MMDB_DIR = os.path.join(DATABASE_DIR, "datasets")
MMDB_CITY_PATH = os.path.join(MMDB_DIR, "2.mmdb")  # GeoLite2-City
MMDB_ASN_PATH = os.path.join(MMDB_DIR, "1.mmdb")   # GeoLite2-ASN
_mmdb_city = None
_mmdb_asn = None
try:
    import maxminddb
    if os.path.exists(MMDB_CITY_PATH):
        _mmdb_city = maxminddb.open_database(MMDB_CITY_PATH)
        logger.info(f"Loaded local GeoLite2 City DB: {MMDB_CITY_PATH}")
    else:
        logger.info(f"GeoLite2 City DB not found at {MMDB_CITY_PATH}; using HTTP geolocation")
    if os.path.exists(MMDB_ASN_PATH):
        _mmdb_asn = maxminddb.open_database(MMDB_ASN_PATH)
        logger.info(f"Loaded local GeoLite2 ASN DB: {MMDB_ASN_PATH}")
except Exception as e:
    logger.warning(f"Local MaxMind DBs unavailable ({e}); falling back to HTTP geolocation")

def mmdb_lookup(ip):
    """Resolve `ip` to geo data from the local GeoLite2 mmdb files.

    Returns a geo dict in the same shape as get_geo_data(), or None if the local
    DBs are not loaded or hold no usable coordinates for this IP (the caller then
    falls back to the HTTP providers). Pure local reads: no network, no rate
    limit, microsecond latency."""
    if _mmdb_city is None:
        return None
    try:
        rec = _mmdb_city.get(ip)
    except Exception:
        return None  # invalid IP / lookup error -> let HTTP providers try
    if not rec:
        return None
    loc = rec.get("location") or {}
    lat = loc.get("latitude")
    lon = loc.get("longitude")
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        return None  # record without coordinates -> defer to HTTP providers
    subs = rec.get("subdivisions") or []
    region = (subs[0].get("names", {}).get("en", "Unknown") if subs else "Unknown")
    org = "Not available"
    if _mmdb_asn is not None:
        try:
            arec = _mmdb_asn.get(ip) or {}
            asn_org = arec.get("autonomous_system_organization")
            if asn_org:
                org = asn_org
        except Exception:
            pass
    return {
        "ip": ip,
        "lat": float(lat),
        "lon": float(lon),
        "city": rec.get("city", {}).get("names", {}).get("en", "Unknown"),
        "country": rec.get("country", {}).get("iso_code", "Unknown"),
        "region": region,
        "org": org,
    }

def get_geo_data(ip, my_geo_data=None):
    global last_api_call
    now = time.time()
    with cache_lock:
        if ip in geo_cache and now - geo_cache[ip]["timestamp"] < CACHE_TIMEOUT:
            return geo_cache[ip]["data"]

    # Reject anything that is not a syntactically valid IP before it can be
    # interpolated into an outbound geolocation URL (SSRF / path-injection guard).
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        logger.warning(f"Refusing geo lookup for invalid IP: {ip!r}")
        return {
            "ip": str(ip),
            "lat": DEFAULT_COORDS[0],
            "lon": DEFAULT_COORDS[1],
            "city": "Unknown",
            "country": "Unknown",
            "region": "Unknown",
            "org": "Not available"
        }

    if is_private_ip(ip):
        geo_data = {
            "ip": ip,
            "lat": my_geo_data["lat"] if my_geo_data else DEFAULT_COORDS[0],
            "lon": my_geo_data["lon"] if my_geo_data else DEFAULT_COORDS[1],
            "city": my_geo_data["city"] if my_geo_data else "Unknown",
            "country": my_geo_data["country"] if my_geo_data else "Unknown",
            "region": my_geo_data["region"] if my_geo_data else "Unknown",
            "org": "Local Network"
        }
        with cache_lock:
            geo_cache[ip] = {"data": geo_data, "timestamp": now}
        return geo_data

    # Primary: offline MaxMind lookup. No network, no rate limit; only falls
    # through to the HTTP providers when the local DBs are absent or lack this IP.
    local = mmdb_lookup(ip)
    if local is not None:
        with cache_lock:
            geo_cache[ip] = {"data": local, "timestamp": now}
        return local

    with api_call_lock:
        time_since_last_call = now - last_api_call
        if time_since_last_call < API_CALL_INTERVAL:
            time.sleep(API_CALL_INTERVAL - time_since_last_call)
        # Primary provider: ipinfo.io over HTTPS (encrypted in transit, free tier
        # supports TLS). Set IPINFO_TOKEN to raise the rate limit.
        try:
            ipinfo_url = f"https://ipinfo.io/{ip}/json"
            if IPINFO_TOKEN:
                ipinfo_url += f"?token={IPINFO_TOKEN}"
            response = requests.get(ipinfo_url, timeout=2)
            last_api_call = time.time()
            data = response.json()
            if "loc" in data:
                lat, lon = map(float, data["loc"].split(","))
                geo_data = {
                    "ip": ip,
                    "lat": lat,
                    "lon": lon,
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "org": data.get("org", "Not available")
                }
                with cache_lock:
                    geo_cache[ip] = {"data": geo_data, "timestamp": now}
                return geo_data
        except Exception as e:
            logger.warning(f"Error at ipinfo (https) for {ip}: {e}")
        # Fallback provider: ip-api.com. The free tier is HTTP-only (unencrypted),
        # so it is used only when the HTTPS provider above is unavailable AND the
        # operator has explicitly opted in with ALLOW_INSECURE_GEO_API=1.
        if ALLOW_INSECURE_GEO_API:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
                last_api_call = time.time()
                data = response.json()
                if data.get("status") == "success" and isinstance(data.get("lat"), (int, float)) and isinstance(data.get("lon"), (int, float)):
                    geo_data = {
                        "ip": ip,
                        "lat": data["lat"],
                        "lon": data["lon"],
                        "city": data.get("city", "Unknown"),
                        "country": data.get("country", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "org": data.get("org", data.get("isp", "Not available"))
                    }
                    with cache_lock:
                        geo_cache[ip] = {"data": geo_data, "timestamp": now}
                    return geo_data
            except Exception as e:
                logger.warning(f"Error at ip-api (http fallback) for {ip}: {e}")
        geo_data = {
            "ip": ip,
            "lat": DEFAULT_COORDS[0],
            "lon": DEFAULT_COORDS[1],
            "city": "Unknown",
            "country": "Unknown",
            "region": "Unknown",
            "org": "Not available"
        }
        with cache_lock:
            geo_cache[ip] = {"data": geo_data, "timestamp": now}
        return geo_data

def load_org_lists():
    """Load the trusted/suspicious/dangerous org classification lists."""
    try:
        with open(TRUSTED_ORGS_PATH, 'r') as f:
            d = json.load(f)
        return (d.get("trusted_organisations", []),
                d.get("suspicious_organisations", []),
                d.get("dangerous_organisations", []))
    except Exception as e:
        logger.error(f"Error loading trusted_organisations.json: {e}")
        return ([], [], [])

def classify_org_threat(org, org_lists):
    """Map an org to a threat level from the lists, or None if unclassified
    (caller should then consult the threat_list table)."""
    trusted, suspicious, dangerous = org_lists
    if org in dangerous:
        return "High"
    if org in suspicious:
        return "Medium"
    if org in trusted:
        return "No Threat"
    return None

# Threat severity ranking (higher = worse). Used to merge the org/threat-list
# verdict with the geo (country) verdict without ever downgrading it.
THREAT_RANK = {"No Threat": 0, "Low": 1, "Medium": 2, "High": 3}

def apply_country_threat(threat_level, country):
    """Elevate a threat level when the IP sits in a high-risk country
    (config.HIGH_RISK_COUNTRIES, e.g. RU). Only ever raises the verdict — an
    org/threat-list rule that already assigns an equal-or-higher level wins, and
    a country never downgrades it. Returns 'No Threat' instead of None so callers
    always get a valid level."""
    base = threat_level or "No Threat"
    if country and country.upper() in HIGH_RISK_COUNTRIES:
        if THREAT_RANK.get(HIGH_RISK_COUNTRY_THREAT_LEVEL, 0) > THREAT_RANK.get(base, 0):
            return HIGH_RISK_COUNTRY_THREAT_LEVEL
    return base

def compute_org_threat(ip, org, country=None):
    """Classify an IP's threat level from its org, falling back to the
    threat_list table, then elevate for high-risk countries. Used by the
    background geo worker."""
    tl = classify_org_threat(org, load_org_lists())
    if tl is None:
        # Read-only: lock-free connection (runs in the background geo worker).
        try:
            with db_connect() as conn:
                c = conn.cursor()
                c.execute("SELECT threat_level FROM threat_list WHERE ip = %s", (ip,))
                threat = c.fetchone()
                tl = threat[0] if threat else "No Threat"
        except db.DBError as e:
            logger.error(f"Error fetching threat level for IP {ip}: {e}")
            tl = "No Threat"
    return apply_country_threat(tl, country)

def get_geo_data_cached(ip, my_geo_data=None):
    """Non-blocking geo lookup for the packet-processing hot path.

    Returns geo data for cached or private IPs; returns None for an uncached
    PUBLIC IP, signalling the caller to render a placeholder now and defer the
    network lookup to geo_enrichment_worker. This prevents an attacker who spoofs
    many unique source IPs from blocking process_packets on outbound HTTP and
    backing up the packet queue (DoS)."""
    now = time.time()
    with cache_lock:
        entry = geo_cache.get(ip)
        if entry and now - entry["timestamp"] < CACHE_TIMEOUT:
            return entry["data"]
    if is_private_ip(ip):
        geo_data = {
            "ip": ip,
            "lat": my_geo_data.get("lat", DEFAULT_COORDS[0]) if my_geo_data else DEFAULT_COORDS[0],
            "lon": my_geo_data.get("lon", DEFAULT_COORDS[1]) if my_geo_data else DEFAULT_COORDS[1],
            "city": my_geo_data.get("city", "Unknown") if my_geo_data else "Unknown",
            "country": my_geo_data.get("country", "Unknown") if my_geo_data else "Unknown",
            "region": my_geo_data.get("region", "Unknown") if my_geo_data else "Unknown",
            "org": "Local Network"
        }
        with cache_lock:
            geo_cache[ip] = {"data": geo_data, "timestamp": now}
        return geo_data
    return None  # uncached public IP -> resolve in the background

# Background geo enrichment: resolves uncached public IPs off the hot path and
# pushes a fresh ip_update once located. Mirrors the MAC enrichment worker.
geo_enrich_queue = ThreadQueue(maxsize=10000)
geo_enrich_inflight = set()
geo_enrich_lock = threading.Lock()

def queue_geo_enrichment(ip):
    if not ip:
        return
    with locked(geo_enrich_lock):
        if ip in geo_enrich_inflight:
            return
        geo_enrich_inflight.add(ip)
    try:
        geo_enrich_queue.put_nowait(ip)
    except Full:
        with locked(geo_enrich_lock):
            geo_enrich_inflight.discard(ip)

def geo_enrichment_worker(my_geo_data):
    while True:
        try:
            ip = geo_enrich_queue.get()
        except Exception as e:
            logger.error(f"Error reading geo enrichment queue: {e}")
            time.sleep(0.1)
            continue
        try:
            geo = get_geo_data(ip, my_geo_data)  # network lookup; fills geo_cache
            if not geo:
                continue
            org = geo.get("org", "Unknown")
            threat_level = compute_org_threat(ip, org, geo.get("country"))
            # If a write for this IP is still buffered (geo resolved before the
            # first flush), patch it so the flush persists the resolved location
            # instead of the placeholder.
            # Geo is device-independent: the same IP may be buffered for several
            # devices. Patch every pending entry for this ip so each flush persists
            # the resolved location instead of the placeholder.
            with locked(ip_write_buffer_lock):
                for (_d_id, b_ip), be in ip_write_buffer.items():
                    if b_ip == ip:
                        be.update({"lat": geo["lat"], "lon": geo["lon"], "city": geo["city"],
                                   "country": geo["country"], "region": geo.get("region", ""), "org": org})
            rows = []
            with locked(db_lock):
                try:
                    with db.get_connection() as conn:
                        c = conn.cursor()
                        # One row per device that has seen this ip.
                        c.execute('''SELECT device_id, incoming_count, outgoing_count, src_port, dst_port, protocol,
                                     mac, vendor, hostname, os,
                                     (SELECT packet_count FROM pinned_ips WHERE pinned_ips.ip = ip_data.ip)
                                     FROM ip_data WHERE ip = %s''', (ip,))
                        rows = c.fetchall()
                        if rows:
                            # Geo applies to every device's row for this ip.
                            c.execute("UPDATE ip_data SET lat = %s, lon = %s, city = %s, country = %s, org = %s WHERE ip = %s",
                                      (geo["lat"], geo["lon"], geo["city"], geo["country"], org, ip))
                            conn.commit()
                except db.DBError as e:
                    logger.error(f"Error storing geo for {ip}: {e}")
                    rows = []
            for row in rows:
                device_id, incoming_count, outgoing_count, src_port, dst_port, protocol, mac, vendor, hostname, os_guess, packet_count = row
                display_hostname = ip if is_private_ip(ip) else hostname
                send_ip_to_clients(ip, geo["lat"], geo["lon"], geo["city"], geo["country"], geo.get("region", ""),
                                   org, time.time(), protocol, src_port, dst_port, mac, vendor,
                                   incoming_count, outgoing_count, packet_count or 0, display_hostname, os_guess, threat_level,
                                   device_id=device_id)
        except Exception as e:
            logger.error(f"Error enriching geo for {ip}: {e}")
        finally:
            with locked(geo_enrich_lock):
                geo_enrich_inflight.discard(ip)

def get_my_public_ip_coords():
    try:
        response = requests.get("https://api.ipify.org", timeout=2)
        public_ip = response.text
        geo_data = get_geo_data(public_ip)
        return [geo_data["lat"], geo_data["lon"]], geo_data, public_ip
    except Exception as e:
        logger.warning(f"Error at api.ipify (https): {e}")
        try:
            response = requests.get("http://api.ipify.org", timeout=2)
            public_ip = response.text
            geo_data = get_geo_data(public_ip)
            return [geo_data["lat"], geo_data["lon"]], geo_data, public_ip
        except Exception as e:
            logger.warning(f"Error at api.ipify (http): {e}")
            try:
                response = requests.get("https://ipinfo.io/json", timeout=2)
                data = response.json()
                public_ip = data.get("ip")
                geo_data = get_geo_data(public_ip)
                return [geo_data["lat"], geo_data["lon"]], geo_data, public_ip
            except Exception as e:
                logger.error(f"Error at ipinfo: {e}")
                return DEFAULT_COORDS, {
                    "ip": "Unknown",
                    "lat": DEFAULT_COORDS[0],
                    "lon": DEFAULT_COORDS[1],
                    "city": "Unknown",
                    "country": "Unknown",
                    "region": "Unknown",
                    "org": "Not available"
                }, "Unknown"

def update_ip(ip, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, mac=None, vendor="Unknown", src_ip=None, dst_ip=None, ttl=None, hostname="Unknown", device_id=LOCAL_DEVICE_ID):
    if ip in (my_local_ip, my_public_ip):
        return
    
    with cache_lock:
        if len(known_ips) >= MAX_KNOWN_IPS and ip not in known_ips:
            # Simple eviction: clear 10% of entries if limit reached
            to_remove = list(known_ips)[:int(MAX_KNOWN_IPS * 0.1)]
            for old_ip in to_remove:
                known_ips.discard(old_ip)
        known_ips.add(ip)
        
    # Non-blocking: never wait on an external geo API in the packet loop. Cached
    # and private IPs resolve instantly; an uncached public IP is rendered with a
    # placeholder location now and resolved by the background geo worker.
    geo = get_geo_data_cached(ip, my_geo_data)
    if geo is None:
        queue_geo_enrichment(ip)
        geo = {
            "ip": ip,
            "lat": DEFAULT_COORDS[0],
            "lon": DEFAULT_COORDS[1],
            "city": "Unknown",
            "country": "Unknown",
            "region": "Unknown",
            "org": "Not available"
        }
    now = time.time()

    os_guess = estimate_os(ttl)
    # The LAN-side peer of this external connection: whichever endpoint is a
    # private address (and not the external IP itself). For the FritzDump source
    # this is the actual home-network device the external IP is talking to.
    local_ip = None
    for cand in (src_ip, dst_ip):
        if cand and cand != ip and is_private_ip(cand):
            local_ip = cand
            break
    conn_key = tuple(sorted([src_ip, dst_ip]) + [src_port, dst_port, protocol]) if src_ip and dst_ip else None
    if protocol == "TCP" and conn_key:
        with cache_lock:
            if conn_key not in tcp_connections:
                tcp_connections[conn_key] = {"packet_count": 0, "last_seen": now, "direction": direction}
            tcp_connections[conn_key]["packet_count"] += 1
            tcp_connections[conn_key]["last_seen"] = now

    # Buffer the write instead of touching SQLite on the hot path. The flusher
    # thread coalesces repeated packets for the same IP and commits the whole
    # batch in a single transaction every IP_WRITE_FLUSH_INTERVAL, so a packet
    # flood can no longer hold db_lock and starve the UI (DoS). Threat level and
    # cumulative counts are resolved at flush time, not per packet.
    buffer_ip_write(ip, direction, {
        "geo_ip": geo.get("ip", ip),
        "lat": geo["lat"], "lon": geo["lon"], "city": geo["city"], "country": geo["country"],
        "region": geo.get("region", ""), "org": geo.get("org", "Unknown"),
        "protocol": protocol, "src_port": src_port, "dst_port": dst_port,
        "mac": mac, "vendor": vendor, "hostname": hostname, "os": os_guess,
        "last_seen": now, "local_ip": local_ip,
    }, device_id=device_id)

# --- Buffered IP writes (DoS protection: coalesce + batch DB writes) ----------
IP_WRITE_FLUSH_INTERVAL = float(os.environ.get('IP_WRITE_FLUSH_INTERVAL', '1.0'))
# Cap how many distinct IPs we buffer between flushes. Beyond this, new IPs are
# dropped (logged, never silently) so a unique-IP flood can't exhaust memory.
IP_WRITE_BUFFER_MAX = int(os.environ.get('IP_WRITE_BUFFER_MAX', '20000'))
ip_write_buffer = {}
ip_write_buffer_lock = threading.Lock()
_ip_write_buffer_dropped = 0

def buffer_ip_write(ip, direction, data, device_id=LOCAL_DEVICE_ID, in_delta=None, out_delta=None):
    """Accumulate a pending write for `(device_id, ip)`: latest field values win,
    packet counts accumulate as deltas (only for non-private IPs, matching the
    original semantics). The buffer is keyed per device so the same external IP
    seen by two devices stays two independent rows.

    Live capture passes `direction` and counts one packet. Batched sensor
    ingestion passes explicit `in_delta`/`out_delta` (already-summed packet
    counts) instead, so a whole batch folds in without N calls."""
    global _ip_write_buffer_dropped
    key = (device_id, ip)
    with locked(ip_write_buffer_lock):
        e = ip_write_buffer.get(key)
        if e is None:
            if len(ip_write_buffer) >= IP_WRITE_BUFFER_MAX:
                _ip_write_buffer_dropped += 1
                return
            e = {"device_id": device_id, "in_delta": 0, "out_delta": 0, "is_private": is_private_ip(ip)}
            ip_write_buffer[key] = e
        e.update(data)
        if not e["is_private"]:
            if in_delta is not None or out_delta is not None:
                e["in_delta"] += int(in_delta or 0)
                e["out_delta"] += int(out_delta or 0)
            elif direction == "incoming":
                e["in_delta"] += 1
            elif direction == "outgoing":
                e["out_delta"] += 1

def flush_ip_writes():
    global ip_write_buffer, _ip_write_buffer_dropped
    while True:
        try:
            time.sleep(IP_WRITE_FLUSH_INTERVAL)
            with locked(ip_write_buffer_lock):
                if not ip_write_buffer:
                    if _ip_write_buffer_dropped:
                        logger.warning(f"IP write buffer full: dropped {_ip_write_buffer_dropped} new IPs since last flush")
                        _ip_write_buffer_dropped = 0
                    continue
                batch = ip_write_buffer
                ip_write_buffer = {}
                dropped = _ip_write_buffer_dropped
                _ip_write_buffer_dropped = 0
            if dropped:
                logger.warning(f"IP write buffer full: dropped {dropped} new IPs since last flush")

            org_lists = load_org_lists()  # loaded once per flush, not per packet
            broadcasts = []
            # Pre-resolve threat levels WITHOUT a round-trip per IP. The org-list
            # classification is pure/in-memory, so only the IPs it can't classify
            # need the threat_list table — collect those and fetch them in ONE
            # `= ANY(...)` query below instead of a SELECT per buffered IP. Under a
            # unique-IP burst this turns N small queries (each holding db_lock) into
            # one, which is what keeps the flush from starving the UI's db_lock.
            base_levels = {}
            need_lookup = set()
            for key_di, e in batch.items():
                lvl = classify_org_threat(e.get("org", "Unknown"), org_lists)
                base_levels[key_di] = lvl
                if lvl is None:
                    need_lookup.add(key_di[1])  # (device_id, ip) -> ip
            with locked(db_lock):
                try:
                    with db.get_connection() as conn:
                        c = conn.cursor()
                        threat_map = {}
                        if need_lookup:
                            c.execute("SELECT ip, threat_level FROM threat_list WHERE ip = ANY(%s)",
                                      (list(need_lookup),))
                            threat_map = {r[0]: r[1] for r in c.fetchall()}
                        for (device_id, ip), e in batch.items():
                            org = e.get("org", "Unknown")
                            lvl = base_levels[(device_id, ip)]
                            if lvl is None:
                                lvl = threat_map.get(ip, "No Threat")
                            threat_level = apply_country_threat(lvl, e.get("country"))
                            # Don't let a buffered placeholder clobber a value an
                            # async enrichment worker may have already resolved into
                            # the row. geo_enrichment_worker owns lat/lon/city/
                            # country/org; mac_enrichment_worker owns vendor. Gate
                            # those columns on a resolved-flag so the full-row flush
                            # only writes them when the buffer carries real data.
                            geo_ok = 1 if (e["city"] != "Unknown" or e["country"] != "Unknown") else 0
                            vendor_ok = 1 if e["vendor"] not in (None, "", "Unknown") else 0
                            # One upsert replaces the old SELECT-counts + UPDATE/
                            # INSERT (3 round-trips -> 1). Counts accumulate in SQL
                            # (ip_data.x + EXCLUDED.x), so two flushers/enrichers can
                            # never lose an update the way SELECT-then-write could,
                            # and RETURNING hands back the post-merge totals for the
                            # broadcast without re-reading the row.
                            c.execute('''INSERT INTO ip_data
                                             (device_id, ip, lat, lon, city, country, last_seen, org,
                                              src_port, dst_port, protocol, incoming_count, outgoing_count,
                                              mac, vendor, hostname, os, local_ip, threat_level)
                                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                         ON CONFLICT (device_id, ip) DO UPDATE SET
                                             lat = CASE WHEN %s=1 THEN EXCLUDED.lat ELSE ip_data.lat END,
                                             lon = CASE WHEN %s=1 THEN EXCLUDED.lon ELSE ip_data.lon END,
                                             city = CASE WHEN %s=1 THEN EXCLUDED.city ELSE ip_data.city END,
                                             country = CASE WHEN %s=1 THEN EXCLUDED.country ELSE ip_data.country END,
                                             org = CASE WHEN %s=1 THEN EXCLUDED.org ELSE ip_data.org END,
                                             last_seen = EXCLUDED.last_seen, src_port = EXCLUDED.src_port,
                                             dst_port = EXCLUDED.dst_port, protocol = EXCLUDED.protocol,
                                             incoming_count = ip_data.incoming_count + EXCLUDED.incoming_count,
                                             outgoing_count = ip_data.outgoing_count + EXCLUDED.outgoing_count,
                                             mac = EXCLUDED.mac,
                                             vendor = CASE WHEN %s=1 THEN EXCLUDED.vendor ELSE ip_data.vendor END,
                                             hostname = EXCLUDED.hostname, os = EXCLUDED.os,
                                             threat_level = EXCLUDED.threat_level,
                                             local_ip = COALESCE(EXCLUDED.local_ip, ip_data.local_ip)
                                         RETURNING incoming_count, outgoing_count''',
                                      (device_id, ip, e["lat"], e["lon"], e["city"], e["country"],
                                       e["last_seen"], org, e["src_port"], e["dst_port"], e["protocol"],
                                       e["in_delta"], e["out_delta"], e["mac"], e["vendor"],
                                       e["hostname"], e["os"], e.get("local_ip"), threat_level,
                                       geo_ok, geo_ok, geo_ok, geo_ok, geo_ok, vendor_ok))
                            cnt_row = c.fetchone()
                            inc, out = (cnt_row[0], cnt_row[1]) if cnt_row else (e["in_delta"], e["out_delta"])
                            # Permanent ledger upsert. RETURNING (xmax = 0) is the
                            # standard ON CONFLICT trick to tell an INSERT (brand-new
                            # IP, xmax=0 -> is_new=True) from an UPDATE (already known);
                            # first_seen is when this IP was EVER first observed and is
                            # never overwritten. This is what survives retention and
                            # restarts, so a genuinely new connection can be flagged.
                            c.execute('''INSERT INTO ip_seen
                                             (ip, first_seen, last_seen, org, country, hostname, threat_level, seen_count)
                                         VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
                                         ON CONFLICT (ip) DO UPDATE SET
                                             last_seen    = GREATEST(ip_seen.last_seen, EXCLUDED.last_seen),
                                             org          = COALESCE(NULLIF(EXCLUDED.org, 'Unknown'), ip_seen.org),
                                             country      = COALESCE(NULLIF(EXCLUDED.country, 'Unknown'), ip_seen.country),
                                             hostname     = COALESCE(NULLIF(EXCLUDED.hostname, 'Unknown'), ip_seen.hostname),
                                             threat_level = EXCLUDED.threat_level,
                                             seen_count   = ip_seen.seen_count + 1
                                         RETURNING first_seen, (xmax = 0)''',
                                      (ip, e["last_seen"], e["last_seen"], org,
                                       e["country"], e["hostname"], threat_level))
                            seen_row = c.fetchone()
                            first_seen_ever, is_new = (seen_row[0], bool(seen_row[1])) if seen_row else (e["last_seen"], False)
                            broadcasts.append((e, inc, out, threat_level, is_new, first_seen_ever))
                        conn.commit()
                except db.DBError as ex:
                    logger.error(f"Error flushing IP writes: {ex}")
                    continue
            # Broadcast after releasing db_lock so emit never blocks the writer.
            # A5: collapse the whole interval's per-IP updates into ONE batched
            # Socket.IO message per client instead of N separate emits, cutting
            # fan-out from (IPs x clients) frames to (1 x clients) per interval.
            messages = []
            for e, inc, out, threat_level, is_new, first_seen_ever in broadcasts:
                m = build_ip_message(e["geo_ip"], e["lat"], e["lon"], e["city"], e["country"], e["region"],
                                     e.get("org", "Unknown"), e["last_seen"], e["protocol"], e["src_port"], e["dst_port"],
                                     e["mac"], e["vendor"], inc, out, 0, e["hostname"], e["os"], threat_level,
                                     device_id=e.get("device_id", LOCAL_DEVICE_ID), local_ip=e.get("local_ip"))
                if m is not None:
                    # first_seen = when this IP was EVER first observed; is_new =
                    # this flush was its very first sighting (never seen before).
                    m["first_seen"] = first_seen_ever
                    m["is_new"] = is_new
                    messages.append(m)
            if messages:
                socketio.emit('ip_update_batch', messages)
        except Exception as ex:
            logger.error(f"Error in flush_ip_writes: {ex}")
            time.sleep(IP_WRITE_FLUSH_INTERVAL)

# --- Devices & sensor ingestion ---------------------------------------------
# Remote sensors push captured connections to /api/ingest. Each device
# authenticates with its own Fernet key (see device_crypto): a payload that
# decrypts cleanly is authentic, so possession of the key IS the credential.
# The hub enriches (geo/threat/vendor) centrally, keeping sensors thin.
INGEST_MAX_AGE = int(os.environ.get('INGEST_MAX_AGE', '300'))         # replay window (s)
INGEST_MAX_EVENTS = int(os.environ.get('INGEST_MAX_EVENTS', '5000'))  # events per batch
INGEST_MAX_BODY = int(os.environ.get('INGEST_MAX_BODY', str(8 * 1024 * 1024)))  # bytes
INGEST_RATE_LIMIT = int(os.environ.get('INGEST_RATE_LIMIT', '20'))    # batches per window
INGEST_RATE_WINDOW = float(os.environ.get('INGEST_RATE_WINDOW', '1.0'))

# _DEVICE_ID_RE and _COLOR_RE live in validators.py (imported above).
_DEFAULT_DEVICE_COLORS = ['#4FC3F7', '#FF8A65', '#BA68C8', '#81C784', '#FFD54F',
                          '#F06292', '#4DB6AC', '#9575CD', '#A1887F', '#90A4AE']

# Per-device cumulative protocol/byte counters for remote sensors (the 'active'
# gauge is derived from ip_data at emit time; the hub's own local capture is
# reported from SharedStats, so only remote devices live here).
device_stats = {}
device_stats_lock = threading.Lock()

# Per-device ingest rate limiter (mirrors socket_rate_limited, keyed by device).
_ingest_times = {}
_ingest_rate_lock = threading.Lock()

_DEVICE_COLS = ("device_id", "name", "color", "kind", "public_ip", "lat", "lon",
                "enabled", "seq", "last_seen", "created_at")
_DEVICE_SELECT = ("SELECT device_id, name, color, kind, public_ip, lat, lon, "
                  "enabled, seq, last_seen, created_at FROM devices")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def device_key_filename(device_id):
    """Return the validated filename for a device key."""
    if not _valid_device_id(device_id):
        raise ValueError(f"invalid device id: {device_id!r}")
    return os.path.basename(f"{device_id}.key")


def open_device_keys_dir():
    """Open the device key directory for dir_fd-relative file operations."""
    return os.open(DEVICE_KEYS_DIR, os.O_RDONLY)


def device_key_path(device_id):
    """Build the on-disk path for a device's key.

    Single choke point for turning a device id into a path, so path-traversal
    is impossible no matter which caller we came from: the id must match
    _DEVICE_ID_RE (no '/', '.' or other separators), and as belt-and-braces we
    normalise the result and confirm it still lives directly inside
    DEVICE_KEYS_DIR. An id that fails either check raises rather than escaping
    the key directory.
    """
    base = os.path.normpath(DEVICE_KEYS_DIR)
    path = os.path.normpath(os.path.join(base, device_key_filename(device_id)))
    if os.path.dirname(path) != base:
        raise ValueError(f"device key path escapes key directory: {device_id!r}")
    return path


def load_device_key(device_id):
    """Return a device's Fernet key (str) or None. Refuses to read through a
    symlink so a planted link can't redirect the read to another file."""
    if not _valid_device_id(device_id):
        return None
    filename = device_key_filename(device_id)
    dir_fd = None
    try:
        dir_fd = open_device_keys_dir()
        fd = os.open(filename, os.O_RDONLY | _O_NOFOLLOW, dir_fd=dir_fd)
        with os.fdopen(fd, 'r') as f:
            key = f.read().strip()
        return key or None
    except FileNotFoundError:
        return None
    except OSError as e:
        if getattr(e, "errno", None) == errno.ELOOP:
            logger.warning(f"Device key path is a symlink, refusing to read: {filename}")
            return None
        logger.error(f"Error reading device key for {device_id}: {e}")
        return None
    finally:
        if dir_fd is not None:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def save_device_key(device_id, key):
    os.makedirs(DEVICE_KEYS_DIR, exist_ok=True)
    try:
        os.chmod(DEVICE_KEYS_DIR, 0o700)
    except OSError:
        pass
    write_secret_file(device_key_path(device_id), key)


def delete_device_key(device_id):
    if not _valid_device_id(device_id):
        return
    filename = device_key_filename(device_id)
    dir_fd = None
    try:
        dir_fd = open_device_keys_dir()
        os.unlink(filename, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.error(f"Error deleting device key for {device_id}: {e}")
    finally:
        if dir_fd is not None:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def _device_row_to_dict(row):
    return dict(zip(_DEVICE_COLS, row))


def get_device(device_id):
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute(_DEVICE_SELECT + " WHERE device_id = %s", (device_id,))
            row = c.fetchone()
    except db.DBError as e:
        logger.error(f"Error loading device {device_id}: {e}")
        return None
    return _device_row_to_dict(row) if row else None


def list_devices():
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute(_DEVICE_SELECT + " ORDER BY created_at")
            rows = c.fetchall()
    except db.DBError as e:
        logger.error(f"Error listing devices: {e}")
        return []
    return [_device_row_to_dict(r) for r in rows]


def public_device_list():
    """Device list for the UI: identity + colour + liveness, never secrets.
    The FritzDump module is omitted entirely while the feature is switched off."""
    return [{
        "device_id": d["device_id"], "name": d["name"], "color": d["color"],
        "kind": d["kind"], "lat": d["lat"], "lon": d["lon"],
        "enabled": d["enabled"], "last_seen": d["last_seen"],
    } for d in list_devices()
        if FRITZDUMP_ENABLED or d["device_id"] != FRITZDUMP_DEVICE_ID]


def emit_devices_update():
    socketio.emit('devices_update', public_device_list())


def _next_device_color():
    existing = {d["color"] for d in list_devices() if d["color"]}
    for col in _DEFAULT_DEVICE_COLORS:
        if col not in existing:
            return col
    return _DEFAULT_DEVICE_COLORS[len(existing) % len(_DEFAULT_DEVICE_COLORS)]


def incr_device_stat(device_id, protocol, packets, nbytes):
    with locked(device_stats_lock):
        s = device_stats.get(device_id)
        if s is None:
            s = {"tcp": 0, "udp": 0, "icmp": 0, "bytes": 0}
            device_stats[device_id] = s
        if protocol == "TCP":
            s["tcp"] += packets
        elif protocol == "UDP":
            s["udp"] += packets
        elif protocol == "ICMP":
            s["icmp"] += packets
        if isinstance(nbytes, (int, float)) and nbytes > 0:
            s["bytes"] += int(nbytes)


def ingest_rate_limited(device_id):
    now = time.time()
    with locked(_ingest_rate_lock):
        times = [t for t in _ingest_times.get(device_id, []) if now - t < INGEST_RATE_WINDOW]
        if len(times) >= INGEST_RATE_LIMIT:
            _ingest_times[device_id] = times
            return True
        times.append(now)
        _ingest_times[device_id] = times
        return False


# _clamp_int, _valid_port and _short_str live in validators.py (imported above).


def ingest_events(device_id, events, device_geo):
    """Validate and buffer a batch of sensor-reported connection events for
    `device_id`. Enrichment (geo/threat/vendor) happens centrally, exactly like
    live capture. Returns the count of accepted events."""
    accepted = 0
    now = time.time()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        ip = ev.get("ip")
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            continue
        protocol = ev.get("protocol")
        if protocol not in ("TCP", "UDP", "ICMP"):
            continue
        in_delta = _clamp_int(ev.get("in_delta"), 0, 100_000_000)
        out_delta = _clamp_int(ev.get("out_delta"), 0, 100_000_000)
        src_port = _valid_port(ev.get("src_port"))
        dst_port = _valid_port(ev.get("dst_port"))
        mac = ev.get("mac") if is_valid_mac(ev.get("mac")) else None
        vendor = _short_str(ev.get("vendor"))
        hostname = _short_str(ev.get("hostname"))
        ttl = ev.get("ttl")
        os_guess = estimate_os(ttl) if isinstance(ttl, (int, float)) else "Unknown"

        # Non-blocking geo, mirroring update_ip: cached/private resolve instantly,
        # an uncached public IP gets a placeholder now + async enrichment.
        geo = get_geo_data_cached(ip, device_geo)
        if geo is None:
            queue_geo_enrichment(ip)
            geo = {"ip": ip, "lat": DEFAULT_COORDS[0], "lon": DEFAULT_COORDS[1],
                   "city": "Unknown", "country": "Unknown", "region": "Unknown",
                   "org": "Not available"}

        buffer_ip_write(ip, None, {
            "geo_ip": geo.get("ip", ip), "lat": geo["lat"], "lon": geo["lon"],
            "city": geo["city"], "country": geo["country"], "region": geo.get("region", ""),
            "org": geo.get("org", "Unknown"), "protocol": protocol, "src_port": src_port,
            "dst_port": dst_port, "mac": mac, "vendor": vendor, "hostname": hostname,
            "os": os_guess, "last_seen": now,
        }, device_id=device_id, in_delta=in_delta, out_delta=out_delta)

        incr_device_stat(device_id, protocol, in_delta + out_delta, ev.get("bytes"))
        accepted += 1
    return accepted


def update_device_after_ingest(device_id, seq, public_ip, dev):
    """Persist the new sequence number, liveness and egress IP, and resolve the
    device's globe origin from its public IP (offline mmdb first) the first time
    we learn it."""
    lat, lon = dev.get("lat"), dev.get("lon")
    learned_coords = False
    if (lat is None or lon is None) and public_ip and not is_private_ip(public_ip):
        geo = mmdb_lookup(public_ip) or get_geo_data_cached(public_ip, None)
        if geo and isinstance(geo.get("lat"), (int, float)):
            lat, lon, learned_coords = geo["lat"], geo["lon"], True
    try:
        with locked(db_lock):
            with db.get_connection() as conn:
                c = conn.cursor()
                c.execute("""UPDATE devices SET seq = %s, last_seen = %s, public_ip = %s,
                             lat = COALESCE(%s, lat), lon = COALESCE(%s, lon)
                             WHERE device_id = %s""",
                          (seq, time.time(), public_ip, lat, lon, device_id))
                conn.commit()
    except db.DBError as e:
        logger.error(f"Error updating device after ingest {device_id}: {e}")
    if learned_coords:
        emit_devices_update()


@app.route('/api/devices', methods=['GET', 'POST'])
@login_required
def api_devices():
    if request.method == 'GET':
        return jsonify({"devices": public_device_list()})
    # POST: register a new remote sensor -> returns id + one-time key.
    data = request.get_json(silent=True) or {}
    name = _short_str(data.get('name'), default='', maxlen=64).strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    color = data.get('color')
    if not (isinstance(color, str) and _COLOR_RE.match(color or '')):
        color = _next_device_color()
    device_id = uuid4().hex
    key = device_crypto.generate_key()
    try:
        save_device_key(device_id, key)
    except OSError as e:
        logger.error(f"Could not persist device key: {e}")
        return jsonify({"error": "could not store key"}), 500
    try:
        with locked(db_lock):
            with db.get_connection() as conn:
                c = conn.cursor()
                c.execute("""INSERT INTO devices (device_id, name, color, kind, enabled, seq, created_at)
                             VALUES (%s, %s, %s, 'remote', TRUE, 0, %s)""",
                          (device_id, name, color, time.time()))
                conn.commit()
    except db.DBError as e:
        delete_device_key(device_id)
        logger.error(f"Error creating device: {e}")
        return jsonify({"error": "could not create device"}), 500
    emit_devices_update()
    logger.info(f"Registered sensor device {device_id} ({name})")
    # The key is shown exactly once and is never retrievable again.
    return jsonify({"device_id": device_id, "name": name, "color": color, "key": key}), 201


@app.route('/api/devices/<device_id>', methods=['PATCH', 'DELETE'])
@login_required
def api_device(device_id):
    if not _valid_device_id(device_id):
        return jsonify({"error": "invalid device id"}), 400
    dev = get_device(device_id)
    if not dev:
        return jsonify({"error": "not found"}), 404
    if request.method == 'DELETE':
        if dev["kind"] in ('local', 'pcap'):
            return jsonify({"error": "cannot delete a built-in device"}), 400
        try:
            with locked(db_lock):
                with db.get_connection() as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM devices WHERE device_id = %s", (device_id,))
                    c.execute("DELETE FROM ip_data WHERE device_id = %s", (device_id,))
                    conn.commit()
        except db.DBError as e:
            logger.error(f"Error deleting device {device_id}: {e}")
            return jsonify({"error": "could not delete"}), 500
        delete_device_key(device_id)
        with locked(device_stats_lock):
            device_stats.pop(device_id, None)
        refresh_disabled_devices()
        emit_devices_update()
        return jsonify({"ok": True})
    # PATCH: name / color / enabled. Column names are hardcoded literals (no
    # injection); only the values are parameterized.
    data = request.get_json(silent=True) or {}
    fields, params = [], []
    if 'name' in data:
        nm = _short_str(data.get('name'), default='', maxlen=64).strip()
        if not nm:
            return jsonify({"error": "name cannot be empty"}), 400
        fields.append("name = %s")
        params.append(nm)
    if 'color' in data:
        col = data.get('color')
        if not (isinstance(col, str) and _COLOR_RE.match(col or '')):
            return jsonify({"error": "invalid color"}), 400
        fields.append("color = %s")
        params.append(col)
    enabling = None
    if 'enabled' in data:
        # Every device (including 'local' and the FritzDump 'pcap' module) has a
        # Start/Stop. Stopping it halts all processing of its traffic.
        enabling = bool(data.get('enabled'))
        fields.append("enabled = %s")
        params.append(enabling)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    params.append(device_id)
    try:
        with locked(db_lock):
            with db.get_connection() as conn:
                c = conn.cursor()
                c.execute(f"UPDATE devices SET {', '.join(fields)} WHERE device_id = %s", params)
                conn.commit()
    except db.DBError as e:
        logger.error(f"Error updating device {device_id}: {e}")
        return jsonify({"error": "could not update"}), 500
    if enabling is not None:
        refresh_disabled_devices()
        logger.info(f"Device {device_id} {'started' if enabling else 'stopped'}")
    emit_devices_update()
    # On (re)start, push the full IP set again so every client immediately
    # redraws this device's points/arcs without waiting for new packets.
    if enabling:
        send_all_ips_to_client()
    return jsonify({"ok": True})


@app.route('/api/devices/<device_id>/rotate-key', methods=['POST'])
@login_required
def api_device_rotate_key(device_id):
    if not _valid_device_id(device_id):
        return jsonify({"error": "invalid device id"}), 400
    dev = get_device(device_id)
    if not dev or dev["kind"] in ('local', 'pcap'):
        return jsonify({"error": "not found"}), 404
    key = device_crypto.generate_key()
    try:
        save_device_key(device_id, key)
    except OSError as e:
        logger.error(f"Could not rotate device key for {device_id}: {e}")
        return jsonify({"error": "could not store key"}), 500
    logger.info(f"Rotated key for device {device_id}")
    return jsonify({"device_id": device_id, "key": key})


@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    """Sensor ingestion endpoint. Auth = the per-device Fernet key (a payload that
    decrypts is authentic). No browser session; exempt from form-CSRF."""
    device_id = request.headers.get('X-Device-Id', '')
    # Generic 401 for every auth failure so we never reveal which check failed.
    if not _valid_device_id(device_id) or device_id == LOCAL_DEVICE_ID:
        return jsonify({"error": "unauthorized"}), 401
    if ingest_rate_limited(device_id):
        return jsonify({"error": "rate limited"}), 429
    body = request.get_data(cache=False)
    if not body or len(body) > INGEST_MAX_BODY:
        return jsonify({"error": "bad payload"}), 413
    key = load_device_key(device_id)
    if not key:
        return jsonify({"error": "unauthorized"}), 401
    try:
        batch = device_crypto.decrypt_batch(key, body, max_age=INGEST_MAX_AGE)
    except device_crypto.InvalidBatch:
        return jsonify({"error": "unauthorized"}), 401
    dev = get_device(device_id)
    if not dev:
        return jsonify({"error": "unauthorized"}), 401
    if not dev["enabled"]:
        return jsonify({"error": "device disabled"}), 403
    # Replay/dup protection: the sequence number must strictly advance.
    seq = batch.get('seq')
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= (dev["seq"] or 0):
        return jsonify({"error": "stale sequence"}), 409
    events = batch.get('events')
    if not isinstance(events, list):
        return jsonify({"error": "bad events"}), 400
    if len(events) > INGEST_MAX_EVENTS:
        events = events[:INGEST_MAX_EVENTS]
        logger.warning(f"Ingest batch from {device_id} truncated to {INGEST_MAX_EVENTS} events")
    device_geo = None
    if dev["lat"] is not None and dev["lon"] is not None:
        device_geo = {"lat": dev["lat"], "lon": dev["lon"]}
    accepted = ingest_events(device_id, events, device_geo)
    update_device_after_ingest(device_id, seq, request.remote_addr, dev)
    return jsonify({"accepted": accepted, "next_seq": seq + 1, "server_time": time.time()})


def _device_stats_payload(stats):
    """Assemble the network_stats payload: legacy flat keys (the hub's own
    capture, for the current UI) plus per-device breakdown and an aggregate."""
    snap = stats.snapshot()
    # Active-connection gauge per device, straight from ip_data.
    active_by_device = {}
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT device_id, COUNT(*) FROM ip_data WHERE last_seen > %s GROUP BY device_id",
                      (time.time() - EXPIRATION_SECONDS,))
            active_by_device = {r[0]: r[1] for r in c.fetchall()}
    except db.DBError as e:
        logger.error(f"Error computing per-device active counts: {e}")
    by_device = {LOCAL_DEVICE_ID: {
        "tcp": snap.get("tcp_packets", 0), "udp": snap.get("udp_packets", 0),
        "icmp": snap.get("icmp_packets", 0), "bytes": snap.get("total_bytes", 0),
        "active": active_by_device.get(LOCAL_DEVICE_ID, 0),
    }}
    with locked(device_stats_lock):
        for did, s in device_stats.items():
            by_device[did] = {"tcp": s["tcp"], "udp": s["udp"], "icmp": s["icmp"],
                              "bytes": s["bytes"], "active": active_by_device.get(did, 0)}
    for did, n in active_by_device.items():
        if did not in by_device:
            by_device[did] = {"tcp": 0, "udp": 0, "icmp": 0, "bytes": 0, "active": n}
    agg = {k: sum(d[k] for d in by_device.values()) for k in ("tcp", "udp", "icmp", "bytes", "active")}
    payload = dict(snap)            # legacy flat keys for the current UI
    payload["by_device"] = by_device
    payload["all"] = agg
    return payload


# --- SharedStats persistence ------------------------------------------------
# The hub's cumulative packet/byte counters live in shared memory and reset to
# zero on every process start. We snapshot them to the settings table so the
# totals continue across a restart instead of dropping back to ~0. Only the
# monotonic counters are persisted; active_connections is a live gauge derived
# from ip_data, so it is intentionally excluded.
_PERSISTED_STAT_FIELDS = ('tcp_packets', 'udp_packets', 'icmp_packets',
                          'total_bytes', 'fragmented_packets')
_STATS_SETTINGS_KEY = 'stats_totals'

def load_persisted_stats(stats):
    """Seed the in-memory counters from the last saved snapshot. Called once
    before the sniffer fork so both processes share the restored baseline."""
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM settings WHERE key = %s", (_STATS_SETTINGS_KEY,))
            row = c.fetchone()
        if not row:
            return
        saved = json.loads(row[0])
        for name in _PERSISTED_STAT_FIELDS:
            v = saved.get(name)
            if isinstance(v, int) and v >= 0:
                stats.set(name, v)
        logger.info("Restored persisted stats totals from previous run")
    except Exception as e:
        logger.error(f"Could not load persisted stats: {e}")

def save_persisted_stats(stats):
    """Write the cumulative counters back so a restart resumes from here."""
    try:
        snap = stats.snapshot()
        payload = json.dumps({k: int(snap.get(k, 0)) for k in _PERSISTED_STAT_FIELDS})
        with locked(db_lock):
            with db.get_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO settings (key, value) VALUES (%s, %s) "
                          "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                          (_STATS_SETTINGS_KEY, payload))
                conn.commit()
    except Exception as e:
        logger.error(f"Could not save persisted stats: {e}")


# Capture-health sampler state: previous cumulative counters + wall time, so each
# emit can derive per-second rates over the elapsed interval.
_cap_health_prev = {"t": None, "processed": 0, "dropped": 0}

def _capture_health(stats):
    """Live capture-pipeline health for the status bar: throughput, drops and
    backlog over the last interval, plus an at-a-glance overload level."""
    snap = stats.snapshot()
    processed = int(snap.get("processed_packets", 0))
    q = _capture_queue
    dropped = q.dropped() if q is not None else 0
    depth = q.depth() if q is not None else -1
    capacity = (q.maxsize * 2) if q is not None else 0  # two lanes
    now = time.time()
    prev = _cap_health_prev
    rate = drop_rate = 0.0
    if prev["t"] is not None:
        dt = now - prev["t"]
        if dt > 0:
            rate = max(0.0, (processed - prev["processed"]) / dt)
            drop_rate = max(0.0, (dropped - prev["dropped"]) / dt)
    prev.update({"t": now, "processed": processed, "dropped": dropped})
    # Overload heuristic: actively dropping, or the backlog is filling the queue.
    fill = (depth / capacity) if (capacity and depth >= 0) else 0.0
    if drop_rate > 0 or fill >= 0.9:
        level = "overload"
    elif fill >= 0.5:
        level = "busy"
    else:
        level = "ok"
    return {
        "rate": round(rate, 1),
        "drop_rate": round(drop_rate, 1),
        "processed": processed,
        "dropped": dropped,
        "queue_depth": depth,
        "queue_capacity": capacity,
        "workers": PACKET_WORKERS,
        "level": level,
    }

def send_network_stats(stats):
    while True:
        try:
            payload = _device_stats_payload(stats)
            payload["capture"] = _capture_health(stats)
            socketio.emit('network_stats', payload)
            save_persisted_stats(stats)
            with active_clients_lock:
                count = len(active_clients)
            if count > 0:
                socketio.emit('heartbeat', {'timestamp': time.time(), 'active_clients': count})
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error sending network statistics: {e}")
            time.sleep(5)

def cleanup_expired_ips(stats):
    while True:
        try:
            now = time.time()
            with locked(db_lock):
                with db.get_connection() as conn:
                    c = conn.cursor()
                    # Only ip_data (the heavy per-connection detail) is expired
                    # here; the lightweight ip_seen ledger is intentionally NEVER
                    # touched, so the permanent record of every IP's first/last
                    # sighting outlives retention.
                    # Never expire pinned IPs, nor any IP carrying a threat level
                    # (High/Medium/Low — i.e. suspicious or worse): those are kept
                    # indefinitely so the record of a threat is never silently lost.
                    c.execute('''DELETE FROM ip_data
                                 WHERE last_seen < %s
                                   AND ip NOT IN (SELECT ip FROM pinned_ips)
                                   AND (threat_level IS NULL OR threat_level NOT IN ('High', 'Medium', 'Low'))''',
                              (now - RETENTION_SECONDS,))
                    conn.commit()

                    # Hard row cap: even within the retention window a spoofing
                    # flood could pile up enough rows to fill the disk. Trim the
                    # oldest rows beyond the cap, but — like the time-based expiry —
                    # never the pinned or threat-flagged ones. (If protected rows
                    # alone exceed the cap the table may stay above it; that is the
                    # intended trade-off for "never delete a threat".)
                    c.execute("SELECT COUNT(*) FROM ip_data")
                    if c.fetchone()[0] > MAX_IP_ROWS:
                        c.execute('''DELETE FROM ip_data WHERE ip IN (
                                         SELECT ip FROM ip_data
                                         WHERE ip NOT IN (SELECT ip FROM pinned_ips)
                                           AND (threat_level IS NULL OR threat_level NOT IN ('High', 'Medium', 'Low'))
                                         ORDER BY last_seen DESC
                                         OFFSET %s)''', (MAX_IP_ROWS,))
                        trimmed = c.rowcount
                        conn.commit()
                        if trimmed > 0:
                            logger.warning(f"ip_data exceeded MAX_IP_ROWS ({MAX_IP_ROWS}); "
                                           f"trimmed {trimmed} oldest unpinned non-threat rows")
            with cache_lock:
                # Cleanup geo_cache
                for ip in list(geo_cache.keys()):
                    if now - geo_cache[ip]["timestamp"] > CACHE_TIMEOUT:
                        del geo_cache[ip]
                
                # Enforce max cache size
                if len(geo_cache) > MAX_CACHE_SIZE:
                    sorted_cache = sorted(geo_cache.items(), key=lambda x: x[1]['timestamp'])
                    to_del = sorted_cache[:len(geo_cache) - MAX_CACHE_SIZE]
                    for key, _ in to_del:
                        del geo_cache[key]

                # Cleanup tcp_connections
                for conn_key in list(tcp_connections.keys()):
                    if now - tcp_connections[conn_key]["last_seen"] > EXPIRATION_SECONDS:
                        del tcp_connections[conn_key]
                
                # Cleanup rate limit trackers
                for ip in list(last_ip_updates.keys()):
                    if now - last_ip_updates[ip] > 60:
                        del last_ip_updates[ip]

                stats.set('active_connections', len(tcp_connections))
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            time.sleep(10)

def parse_ip_packet(packet, stats, showAllUDPPackets, lookup_private_macs=True):
    # Shared, side-effect-free L3/L4 parsing (see capture_core.classify_packet).
    # Everything below is the hub-specific layer: stats counters + the
    # non-blocking MAC-vendor cache lookup.
    parsed = classify_packet(packet, show_all_udp=showAllUDPPackets.value)
    if parsed is None:
        return None

    # IP-fragmentation evasion: a fragment can't be classified by port and would
    # otherwise vanish silently. We don't reassemble here (the buffers are
    # themselves a memory-exhaustion vector and belong in the kernel) but we
    # count every fragment — BEFORE any UDP-filter drop — so the activity stays
    # observable in the stats feed.
    if parsed["fragmented"]:
        stats.incr('fragmented_packets')
    if parsed["udp_filtered"]:
        return None

    protocol = parsed["protocol"]
    if protocol == "TCP":
        stats.incr('tcp_packets')
    elif protocol == "UDP":
        stats.incr('udp_packets')
    elif protocol == "ICMP":
        stats.incr('icmp_packets')

    ip_src = parsed["ip_src"]
    ip_dst = parsed["ip_dst"]
    src_mac = parsed["src_mac"]
    dst_mac = parsed["dst_mac"]
    src_vendor = "Unknown"
    dst_vendor = "Unknown"
    if src_mac is not None:
        # Non-blocking: only consult the local cache here so packet capture is
        # never stalled by an HTTP vendor lookup. Misses stay "Unknown" and are
        # resolved asynchronously by the background enrichment worker.
        if lookup_private_macs or not is_private_ip(ip_src):
            src_vendor = get_mac_vendor_cached(src_mac) or "Unknown"
        if lookup_private_macs or not is_private_ip(ip_dst):
            dst_vendor = get_mac_vendor_cached(dst_mac) or "Unknown"

    stats.incr('total_bytes', parsed["length"])
    return {
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "ttl": parsed["ttl"],
        "protocol": protocol,
        "src_port": parsed["src_port"],
        "dst_port": parsed["dst_port"],
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_vendor": src_vendor,
        "dst_vendor": dst_vendor
    }

def external_packet_callback(packet, my_geo_data, my_local_ip, my_public_ip, queue, stats, mdns_listener, showAllUDPPackets):
    # Start/Stop: if the hub's own (local) device is stopped, don't even queue its
    # live traffic. (process_packets also drops it, covering the forked scanner.)
    if LOCAL_DEVICE_ID in disabled_devices:
        return
    # summary() forces full scapy dissection on every frame — skip it entirely
    # unless DEBUG is on, and never let a malformed frame raise out of the prn.
    if logger.isEnabledFor(logging.DEBUG):
        try:
            logger.debug("Packet captured: %s", packet.summary())
        except Exception:
            pass
    parsed = parse_ip_packet(packet, stats, showAllUDPPackets, lookup_private_macs=False)
    if not parsed:
        return

    ip_src = parsed["ip_src"]
    ip_dst = parsed["ip_dst"]
    protocol = parsed["protocol"]
    src_port = parsed["src_port"]
    dst_port = parsed["dst_port"]
    direction = "other"
    if ip_dst in (my_local_ip, my_public_ip):
        direction = "incoming"
    elif ip_src in (my_local_ip, my_public_ip):
        direction = "outgoing"
    elif protocol == "TCP":
        if src_port in [80, 443]:
            direction = "incoming"
        elif dst_port in [80, 443]:
            direction = "outgoing"

    hostname_src = mdns_listener.devices.get(ip_src, ip_src if is_private_ip(ip_src) else "Unknown")
    hostname_dst = mdns_listener.devices.get(ip_dst, ip_dst if is_private_ip(ip_dst) else "Unknown")

    packet_data = {
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_mac": parsed["src_mac"],
        "dst_mac": parsed["dst_mac"],
        "src_vendor": parsed["src_vendor"],
        "dst_vendor": parsed["dst_vendor"],
        "direction": direction,
        "ttl": parsed["ttl"],
        "hostname_src": hostname_src,
        "hostname_dst": hostname_dst
    }
    try:
        queue.put(packet_data)
        logger.debug(f"Queued packet: {packet_data}")
    except Exception as e:
        logger.error(f"Error adding to queue: {e}")

def fritzdump_packet_callback(packet, queue, mdns_listener, show_all_udp):
    """Turn one packet read from a FritzDump pcap into a queue item tagged with
    the FritzDump device id. Uses the side-effect-free classify_packet so these
    packets never inflate the hub's own (local) SharedStats counters; per-device
    counting happens in process_packets via the device_id tag."""
    parsed = classify_packet(packet, show_all_udp)
    if not parsed or parsed.get("udp_filtered"):
        return
    ip_src = parsed["ip_src"]
    ip_dst = parsed["ip_dst"]
    # The FRITZ!Box sees the home LAN, so private<->public tells direction.
    src_priv, dst_priv = is_private_ip(ip_src), is_private_ip(ip_dst)
    if src_priv and not dst_priv:
        direction = "outgoing"
    elif dst_priv and not src_priv:
        direction = "incoming"
    else:
        direction = "other"
    hostname_src = mdns_listener.devices.get(ip_src, ip_src if src_priv else "Unknown")
    hostname_dst = mdns_listener.devices.get(ip_dst, ip_dst if dst_priv else "Unknown")
    packet_data = {
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "protocol": parsed["protocol"],
        "src_port": parsed["src_port"],
        "dst_port": parsed["dst_port"],
        "src_mac": parsed["src_mac"],
        "dst_mac": parsed["dst_mac"],
        "src_vendor": "Unknown",
        "dst_vendor": "Unknown",
        "direction": direction,
        "ttl": parsed["ttl"],
        "length": parsed["length"],
        "hostname_src": hostname_src,
        "hostname_dst": hostname_dst,
        "device_id": FRITZDUMP_DEVICE_ID,
    }
    try:
        queue.put(packet_data)
    except Exception as e:
        logger.error(f"Error adding FritzDump packet to queue: {e}")

def internal_packet_callback(packet, my_geo_data, my_local_ip, my_public_ip, queue, is_internal_search_active, stats, mdns_listener, showAllUDPPackets):
    if logger.isEnabledFor(logging.DEBUG):
        try:
            logger.debug("Internal packet captured: %s", packet.summary())
        except Exception:
            pass
    if not is_internal_search_active.value:
        return
    parsed = parse_ip_packet(packet, stats, showAllUDPPackets)
    if not parsed:
        return

    ip_src = parsed["ip_src"]
    ip_dst = parsed["ip_dst"]

    if ip_src != my_local_ip and ip_src != my_public_ip and is_private_ip(ip_src):
        direction = "incoming" if ip_dst in (my_local_ip, my_public_ip) else "other"
        queue.put({
            "ip": ip_src,
            "direction": direction,
            "protocol": parsed["protocol"],
            "src_port": parsed["src_port"],
            "dst_port": parsed["dst_port"],
            "mac": parsed["src_mac"],
            "vendor": parsed["src_vendor"],
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "ttl": parsed["ttl"],
            "hostname": ip_src
        })
    if ip_dst != my_local_ip and ip_dst != my_public_ip and is_private_ip(ip_dst):
        direction = "outgoing" if ip_src in (my_local_ip, my_public_ip) else "other"
        queue.put({
            "ip": ip_dst,
            "direction": direction,
            "protocol": parsed["protocol"],
            "src_port": parsed["src_port"],
            "dst_port": parsed["dst_port"],
            "mac": parsed["dst_mac"],
            "vendor": parsed["dst_vendor"],
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "ttl": parsed["ttl"],
            "hostname": ip_dst
        })

def build_ip_message(ip, lat, lon, city, country, region, org, last_seen, protocol, src_port, dst_port, mac, vendor, incoming_count, outgoing_count, packet_count=0, hostname="Unknown", os="Unknown", threat_level="No Threat", device_id=LOCAL_DEVICE_ID, local_ip=None):
    """Validate and assemble an ip_update payload, or return None if invalid."""
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        logger.warning(f"Invalid coordinates for IP {ip}: lat={lat}, lon={lon}")
        return None
    if lat < -90 or lat > 90 or lon < -180 or lon > 180:
        logger.warning(f"Coordinates out of valid range for IP {ip}: lat={lat}, lon={lon}")
        return None

    valid_threat_levels = ["High", "Medium", "Low", "No Threat"]
    if threat_level not in valid_threat_levels:
        logger.warning(f"Invalid threat level for IP {ip}: {threat_level}. Setting to 'No Threat'.")
        threat_level = "No Threat"

    if os == "No Threat":
        logger.warning(f"Invalid OS for IP {ip}: {os}. Setting to 'Unknown'.")
        os = "Unknown"

    return {
        "device_id": device_id,
        "ip": ip,
        "local_ip": local_ip,
        "lat": lat,
        "lon": lon,
        "city": city,
        "country": country,
        "region": region,
        "org": org,
        "last_seen": last_seen,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "mac": mac,
        "vendor": vendor,
        "incoming_count": incoming_count,
        "outgoing_count": outgoing_count,
        "packet_count": packet_count,
        "hostname": hostname,
        "os": os,
        "threat_level": threat_level
    }

def send_ip_to_clients(*args, **kwargs):
    message = build_ip_message(*args, **kwargs)
    if message is not None:
        socketio.emit('ip_update', message)

def resolve_region_nonblocking(ip):
    """Return an IP's region WITHOUT ever making a network call.

    Tries the in-memory geo cache first, then the offline mmdb; returns "" on a
    miss. Used by the initial client load so a fresh connection never blocks on an
    external geo lookup just to fill in the 'region' field."""
    with cache_lock:
        entry = geo_cache.get(ip)
    if entry:
        return entry["data"].get("region", "") or ""
    local = mmdb_lookup(ip)
    if local:
        return local.get("region", "") or ""
    return ""

def send_all_ips_to_client(sid=None):
    """Send the full current IP table to a client as ONE batched message.

    Previously this emitted a separate 'ip_update' per row AND made a blocking
    get_geo_data(ip) call per row (an external HTTP lookup on a cache miss) just to
    fill in 'region'. With 1000+ rows that produced a long, blocking emit storm on
    every connect. Now it is a single read (no db_lock, so it never waits on the
    write flush), resolves 'region' non-blocking, and pushes one 'ip_update_batch'
    — matching the live-update path (A5)."""
    messages = []
    try:
        with db_connect() as conn:
            c = conn.cursor()
            # Load the live window PLUS every threat-flagged and pinned IP,
            # regardless of how long ago it was last seen — otherwise a restart or
            # page reload silently drops threats that haven't been active in the
            # last EXPIRATION_SECONDS (they're still in the DB, just not loaded).
            # threat_level is the PERSISTED column (not re-derived here), so a
            # threat survives the reload instead of arriving as "No Threat".
            # first_seen comes from the permanent ledger for the detail popup.
            c.execute('''SELECT d.device_id, d.ip, d.lat, d.lon, d.city, d.country, d.org, d.last_seen,
                         d.src_port, d.dst_port, d.protocol, d.incoming_count, d.outgoing_count, d.mac,
                         d.vendor, d.hostname, d.os, d.local_ip, d.threat_level,
                         (SELECT packet_count FROM pinned_ips WHERE pinned_ips.ip = d.ip) as packet_count,
                         s.first_seen
                         FROM ip_data d
                         LEFT JOIN ip_seen s ON s.ip = d.ip
                         WHERE d.last_seen > %s
                            OR d.threat_level IN ('High', 'Medium', 'Low')
                            OR d.ip IN (SELECT ip FROM pinned_ips)''',
                      (time.time() - EXPIRATION_SECONDS,))
            rows = c.fetchall()
    except db.DBError as e:
        logger.error(f"Error sending all IPs: {e}")
        return
    for row in rows:
        (device_id, ip, lat, lon, city, country, org, last_seen, src_port, dst_port, protocol,
         incoming_count, outgoing_count, mac, vendor, hostname, os, local_ip, threat_level,
         packet_count, first_seen) = row
        # Stopped devices contribute no data to any client (initial load or
        # rebroadcast), matching the "no traffic while stopped" guarantee.
        if device_id in disabled_devices:
            continue
        display_hostname = ip if is_private_ip(ip) else hostname
        messages.append({
            "device_id": device_id,
            "ip": ip,
            "local_ip": local_ip,
            "lat": lat,
            "lon": lon,
            "city": city,
            "country": country,
            "region": resolve_region_nonblocking(ip),
            "org": org,
            "last_seen": last_seen,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "mac": mac,
            "vendor": vendor,
            "incoming_count": incoming_count,
            "outgoing_count": outgoing_count,
            "packet_count": packet_count or 0,
            "hostname": display_hostname,
            "os": os,
            # Persisted threat level so a reload/restart keeps threats flagged
            # instead of showing every IP as "No Threat" until fresh traffic.
            "threat_level": threat_level or "No Threat",
            "first_seen": first_seen,
        })
    if messages:
        if sid:
            socketio.emit('ip_update_batch', messages, to=sid)
        else:
            socketio.emit('ip_update_batch', messages)

def send_pinned_ips_to_client(sid):
    # Read-only: use a lock-free connection so this never waits on the write flush.
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT ip, packet_count FROM pinned_ips")
            pinned_ips = {row[0]: {'isPinned': True, 'packet_count': row[1]} for row in c.fetchall()}
        socketio.emit('pinned_ips_update', pinned_ips, to=sid)
    except db.DBError as e:
        logger.error(f"Error sending pinned IPs: {e}")

def internal_scanner_process(my_geo_data, my_local_ip, my_public_ip, queue, is_internal_search_active, stats, mdns_listener, showAllUDPPackets):
    while True:
        try:
            sniff(iface=NETWORK_INTERFACE, prn=lambda pkt: internal_packet_callback(pkt, my_geo_data, my_local_ip, my_public_ip, queue, is_internal_search_active, stats, mdns_listener, showAllUDPPackets),
                  filter=CAPTURE_BPF_FILTER, store=0, timeout=SNIFF_TIMEOUT)
        except Exception as e:
            logger.error(f"Error in internal scanner: {e}")
            time.sleep(5)


# Handle to the running FritzDump capture worker (a child process tree). Managed
# only by the fritzdump_reader thread; exposed for shutdown cleanup.
_fritzdump_worker = None


def _spawn_fritzdump_worker():
    """Launch the FritzDump capture worker (run.sh) as its own process group so we
    can later kill the whole tree (run.sh + the per-interface fritzdump.py)."""
    if not FRITZDUMP_WORKER_CMD:
        logger.warning("FritzDump worker not launched: no run.sh found "
                       f"(looked in {FRITZDUMP_WORKER_DIR}). In Docker, enable the "
                       "module with: ./run.sh fritzdump on")
        return None
    logf = None
    try:
        # Capture the worker's output to a persistent log so its failure reason is
        # diagnosable from the host.
        try:
            logf = open(FRITZDUMP_WORKER_LOG, 'ab', buffering=0)
            logf.write(f"\n=== starting {' '.join(FRITZDUMP_WORKER_CMD)} (cwd {FRITZDUMP_WORKER_DIR}) ===\n".encode())
        except OSError:
            logf = None
        # Force the worker into redacted/full-payload mode per the hub's policy.
        # fritzdump.py reads FRITZ_REDACT from its environment in preference to
        # its own .env, so injecting it here makes FRITZDUMP_REDACT the single
        # authoritative switch (default: redacted -> no real payloads on disk).
        worker_env = dict(os.environ)
        worker_env['FRITZ_REDACT'] = 'true' if FRITZDUMP_REDACT else 'false'
        proc = subprocess.Popen(
            FRITZDUMP_WORKER_CMD, cwd=FRITZDUMP_WORKER_DIR, env=worker_env,
            stdout=(logf or subprocess.DEVNULL),
            stderr=(subprocess.STDOUT if logf else subprocess.DEVNULL),
            stdin=subprocess.DEVNULL, start_new_session=True)
        logger.info(f"Started FritzDump worker (pid {proc.pid}): {' '.join(FRITZDUMP_WORKER_CMD)} "
                    f"(redact={'on' if FRITZDUMP_REDACT else 'OFF'}, output -> {FRITZDUMP_WORKER_LOG})")
        return proc
    except Exception as e:
        logger.error(f"Could not start FritzDump worker: {e}")
        return None
    finally:
        if logf is not None:
            logf.close()


def _terminate_fritzdump_worker(proc):
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        logger.info("Stopped FritzDump worker")
    except ProcessLookupError:
        pass
    except Exception as e:
        logger.error(f"Error stopping FritzDump worker: {e}")


def fritzdump_reader(queue, mdns_listener, showAllUDPPackets):
    """Drive the FritzDump module while its device is started (its `enabled` flag):
    LAUNCH the capture worker (so pressing Start actually begins capturing), then
    tail the produced pcaps into the same queue as live capture, tagged with the
    FritzDump device id. On Stop, the worker is killed and reading pauses."""
    global _fritzdump_worker
    source = FritzDumpSource(FRITZDUMP_DIR)
    logged_missing = False
    worker_started_at = 0.0
    backoff_until = 0.0
    total_packets = 0
    last_status = 0.0
    warned_no_parse = False
    logger.info(f"FritzDump reader active: dir={FRITZDUMP_DIR} autostart={FRITZDUMP_AUTOSTART} "
                f"cmd={' '.join(FRITZDUMP_WORKER_CMD) if FRITZDUMP_WORKER_CMD else None}")
    while True:
        try:
            if device_is_disabled(FRITZDUMP_DEVICE_ID):
                if _fritzdump_worker is not None:
                    _terminate_fritzdump_worker(_fritzdump_worker)
                    _fritzdump_worker = None
                backoff_until = 0.0
                last_status = 0.0
                time.sleep(FRITZDUMP_POLL_INTERVAL)
                continue

            # Started: own the capture worker's lifecycle (unless autostart is off,
            # i.e. the user runs FritzDump themselves and we only read the pcaps).
            if FRITZDUMP_AUTOSTART and FRITZDUMP_WORKER_CMD:
                if _fritzdump_worker is None:
                    if time.time() >= backoff_until:
                        _fritzdump_worker = _spawn_fritzdump_worker()
                        worker_started_at = time.time()
                elif _fritzdump_worker.poll() is not None:
                    rc = _fritzdump_worker.returncode
                    uptime = time.time() - worker_started_at
                    _fritzdump_worker = None
                    if uptime < FRITZDUMP_WORKER_MIN_UPTIME:
                        backoff_until = time.time() + FRITZDUMP_WORKER_BACKOFF
                        logger.error(
                            f"FritzDump worker exited after {uptime:.1f}s (rc={rc}); "
                            f"check modules/FritzDump/.env credentials. "
                            f"Retrying in {FRITZDUMP_WORKER_BACKOFF:.0f}s.")
                    else:
                        logger.warning(f"FritzDump worker exited (rc={rc}); restarting")

            if not os.path.isdir(FRITZDUMP_DIR):
                if not logged_missing:
                    logger.warning(f"FritzDump started but dump directory not found yet: "
                                   f"{FRITZDUMP_DIR}")
                    logged_missing = True
                time.sleep(FRITZDUMP_POLL_INTERVAL)
                continue
            logged_missing = False
            packets = source.poll()
            if packets:
                if total_packets == 0:
                    logger.info("FritzDump: receiving packets from the box")
                total_packets += len(packets)
            for pkt in packets:
                fritzdump_packet_callback(pkt, queue, mdns_listener, showAllUDPPackets.value)
            # Periodic status so "no data" is diagnosable: how many capture files
            # were found vs how many packets we have actually parsed.
            now = time.time()
            if now - last_status >= 20:
                nfiles = len(source.readers)
                # Per-interface breakdown so a starved/silent capture file (e.g. a
                # Wi-Fi band carrying a specific device) is immediately visible
                # instead of hiding inside the combined total.
                per_file = ", ".join(
                    f"{os.path.basename(p)}={n}"
                    for p, n in sorted(source.parsed_by_file.items())
                ) or "none"
                logger.info(f"FritzDump status: {nfiles} capture file(s) in {FRITZDUMP_DIR}, "
                            f"{total_packets} packet(s) parsed [{per_file}]")
                if nfiles > 0 and total_packets == 0 and not warned_no_parse:
                    logger.warning("FritzDump: capture files exist but no packets parsed yet — "
                                   "the box may be writing slowly, or the files are not classic "
                                   "pcap. Check database/fritzdump_worker.log for worker errors.")
                    warned_no_parse = True
                last_status = now
            # Busy-spin lightly while data is flowing; back off when idle.
            time.sleep(0 if packets else FRITZDUMP_POLL_INTERVAL)
        except Exception as e:
            logger.error(f"FritzDump reader error: {e}")
            time.sleep(FRITZDUMP_POLL_INTERVAL)

def process_packets(queue, my_geo_data, my_local_ip, my_public_ip, is_internal_search_active, mdns_listener, stats=None):
    # Coalesce the shared 'processed' counter. stats.incr takes a multiprocessing
    # Value lock (an OS semaphore); doing it per packet makes every worker contend
    # on the same semaphore for a number the UI only samples every few seconds, so
    # under a burst the whole pool serializes on a counter. Count locally and flush
    # in batches — and whenever the queue drains — so the live processed/s rate
    # stays accurate (lag <= one batch) without per-packet cross-process locking.
    _processed_local = 0
    _PROCESSED_FLUSH = 64

    def _flush_processed():
        nonlocal _processed_local
        if stats is not None and _processed_local:
            stats.incr('processed_packets', _processed_local)
        _processed_local = 0

    while True:
        try:
            priority, packet_data = queue.get(timeout=0.1)
            # Count every item actually taken off the queue, so the UI can show a
            # live "processed/s" rate and compare it against drops/backlog.
            _processed_local += 1
            if _processed_local >= _PROCESSED_FLUSH:
                _flush_processed()
            logger.debug(f"Dequeued packet: {packet_data}")
            try:
                # Which device this packet belongs to (live capture omits it ->
                # the hub's own 'local' device; the FritzDump reader tags its own).
                device_id = packet_data.get("device_id", LOCAL_DEVICE_ID)
                # Start/Stop chokepoint: a stopped device's traffic is dropped here
                # so nothing of it is processed, stored or broadcast — not even in
                # the background — regardless of which process captured it.
                if device_id in disabled_devices:
                    continue
                # Non-local sources keep their own protocol/byte counters; the
                # 'local' device is counted by SharedStats on the capture path.
                if device_id != LOCAL_DEVICE_ID:
                    incr_device_stat(device_id, packet_data.get("protocol"),
                                     1, packet_data.get("length"))
                if 'ip' in packet_data:
                    ip = packet_data["ip"]
                    if not packet_data.get("vendor") or packet_data.get("vendor") == "Unknown":
                        queue_mac_enrichment(packet_data.get("mac"))
                    if is_private_ip(ip) and not is_internal_search_active.value:
                        # Hot path: the pin set is tiny and changes only via UI
                        # events, so keep it in memory instead of borrowing a DB
                        # connection for every private packet.
                        if not is_ip_pinned_cached(ip):
                            continue
                    update_ip(
                        ip,
                        packet_data["direction"],
                        packet_data["protocol"],
                        packet_data["src_port"],
                        packet_data["dst_port"],
                        my_geo_data,
                        my_local_ip,
                        my_public_ip,
                        packet_data["mac"],
                        packet_data["vendor"],
                        packet_data.get("src_ip"),
                        packet_data.get("dst_ip"),
                        packet_data.get("ttl"),
                        packet_data.get("hostname"),
                        device_id=device_id
                    )
                else:
                    ip_src = packet_data["ip_src"]
                    ip_dst = packet_data["ip_dst"]
                    protocol = packet_data["protocol"]
                    src_port = packet_data["src_port"]
                    dst_port = packet_data["dst_port"]
                    src_mac = packet_data["src_mac"]
                    dst_mac = packet_data["dst_mac"]
                    src_vendor = packet_data.get("src_vendor", "Unknown")
                    dst_vendor = packet_data.get("dst_vendor", "Unknown")
                    if not src_vendor or src_vendor == "Unknown":
                        queue_mac_enrichment(src_mac)
                    if not dst_vendor or dst_vendor == "Unknown":
                        queue_mac_enrichment(dst_mac)
                    direction = packet_data["direction"]
                    ttl = packet_data.get("ttl")
                    hostname_src = packet_data.get("hostname_src")
                    hostname_dst = packet_data.get("hostname_dst")
                    if ip_src != my_local_ip and ip_src != my_public_ip and not is_private_ip(ip_src):
                        update_ip(ip_src, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, src_mac, src_vendor, ip_src, ip_dst, ttl, hostname_src, device_id=device_id)
                    if ip_dst != my_local_ip and ip_dst != my_public_ip and not is_private_ip(ip_dst):
                        update_ip(ip_dst, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, dst_mac, dst_vendor, ip_src, ip_dst, ttl, hostname_dst, device_id=device_id)
                    elif is_internal_search_active.value:
                        if is_private_ip(ip_src) and ip_src != my_local_ip and ip_src != my_public_ip:
                            update_ip(ip_src, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, src_mac, src_vendor, ip_src, ip_dst, ttl, hostname_src, device_id=device_id)
                        if is_private_ip(ip_dst) and ip_dst != my_local_ip and ip_dst != my_public_ip:
                            update_ip(ip_dst, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, dst_mac, dst_vendor, ip_src, ip_dst, ttl, hostname_dst, device_id=device_id)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        except Empty:
            # Queue drained: flush the local processed count so an idle worker's
            # tail packets are reflected in the live rate without delay.
            _flush_processed()
            continue
        except Exception as e:
            logger.error(f"Error in process_packets: {e}")
            time.sleep(0.1)

def load_backend_config():
    """Loads backend configuration data from the JSON file."""
    try:
        with open(BACKEND_CONF_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading backend configuration file: {e}")
        return {}

@app.route('/')
@login_required
def index():
    my_ip_coords, my_geo_data, my_public_ip = get_my_public_ip_coords()
    backend_config = load_backend_config()
    if not isinstance(my_ip_coords[0], (int, float)) or not isinstance(my_ip_coords[1], (int, float)):
        my_ip_coords = DEFAULT_COORDS
        my_geo_data = {
            "ip": "Unknown",
            "city": "Unknown",
            "country": "Unknown",
            "region": "Unknown",
            "org": "Not available"
        }
    return render_template(
        'index.html',
        lat=float(my_ip_coords[0]),
        lng=float(my_ip_coords[1]),
        my_geo_data=my_geo_data,
        backend_config=backend_config
    )

def start_sniffing(my_geo_data, my_local_ip, my_public_ip, queue, stats, mdns_listener, showAllUDPPackets):
    validate_interface()
    init_db()
    # Expose the capture queue so the stats payload can report live backlog/drops.
    # Set before send_network_stats starts so its first emit already sees it.
    global _capture_queue
    _capture_queue = queue
    # Worker threads + the FritzDump reader need no raw-socket privileges, so they
    # start regardless of admin: a host that can only read FritzDump pcaps (no
    # CAP_NET_RAW) still fully works as a hub.
    threading.Thread(target=cleanup_expired_ips, args=(stats,), daemon=True).start()
    threading.Thread(target=send_network_stats, args=(stats,), daemon=True).start()
    # Pool of packet-processing workers draining the shared queue. A single
    # consumer could not keep up with a burst from a high-traffic device, so the
    # queue filled and dropped packets — including the first packet to a new
    # external IP, which is why a freshly connected VPN server sometimes never
    # showed up. The state these workers touch is lock-guarded, so they scale out
    # safely. Count is configurable via PACKET_WORKERS.
    for i in range(PACKET_WORKERS):
        threading.Thread(
            target=process_packets,
            args=(queue, my_geo_data, my_local_ip, my_public_ip, is_internal_search_active, mdns_listener, stats),
            name=f"process_packets-{i}", daemon=True).start()
    logger.info(f"Started {PACKET_WORKERS} packet-processing worker(s), "
                f"queue capacity {PACKET_QUEUE_MAX}/lane")
    threading.Thread(target=mac_enrichment_worker, daemon=True).start()
    # Pool of geo-enrichment workers so a burst of new IPs resolves in parallel
    # instead of one slow network lookup at a time (GEO_WORKERS).
    for i in range(GEO_WORKERS):
        threading.Thread(target=geo_enrichment_worker, args=(my_geo_data,),
                         name=f"geo_enrichment-{i}", daemon=True).start()
    threading.Thread(target=flush_ip_writes, daemon=True).start()
    # The FritzDump reader/worker only runs when the module is switched on.
    if FRITZDUMP_ENABLED:
        threading.Thread(target=fritzdump_reader, args=(queue, mdns_listener, showAllUDPPackets), daemon=True).start()
    else:
        logger.info("FritzDump module disabled (set FRITZDUMP_ENABLED=1 to use it)")
    if not is_admin():
        if sys.platform == 'win32':
            logger.error("Live packet capture requires administrator privileges; "
                         "live capture is disabled (FritzDump pcap source still works).")
        else:
            logger.error(
                "Live packet capture requires CAP_NET_RAW, so it is disabled "
                "(the FritzDump pcap source still works). To enable live capture, "
                "run with sudo or grant capabilities (least privilege):\n"
                "  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
            )
        return
    while True:
        try:
            sniff(iface=NETWORK_INTERFACE, prn=lambda pkt: external_packet_callback(pkt, my_geo_data, my_local_ip, my_public_ip, queue, stats, mdns_listener, showAllUDPPackets),
                  filter=CAPTURE_BPF_FILTER, store=0, timeout=SNIFF_TIMEOUT)
        except Exception as e:
            logger.error(f"Error during sniffing: {e}")
            time.sleep(5)

def cleanup(internal_process, zeroconf):
    logger.info("Shutting down processes...")
    _terminate_fritzdump_worker(_fritzdump_worker)
    internal_process.terminate()
    internal_process.join()
    if zeroconf:
        zeroconf.close()

if __name__ == "__main__":
    from multiprocessing import set_start_method
    if sys.platform == 'win32':
        set_start_method('spawn')
    else:
        set_start_method('fork', force=True)

    my_local_ip = get_local_ip()
    my_ip_coords, my_geo_data, my_public_ip = get_my_public_ip_coords()
    manager = Manager()
    # Shared-memory counters (created before fork so the child sniffer shares the
    # same cells); replaces a Manager().dict() to avoid per-packet IPC overhead.
    stats = SharedStats()
    # Wait for PostgreSQL and create the schema before the first read, so a fresh
    # database doesn't make load_settings log "relation settings does not exist".
    # init_db waits for the DB internally and is idempotent (it runs again in the
    # sniffing thread).
    init_db()
    # Restore cumulative counters before the fork so total_bytes etc. resume from
    # the last run instead of resetting to zero (both processes share the cells).
    load_persisted_stats(stats)
    settings = load_settings()
    is_internal_search_active = manager.Value('b', settings.get('is_internal_search_active', True))
    showAllUDPPackets = manager.Value('b', settings.get('show_all_udp_packets', True))
    packet_queue = PacketQueue(maxsize=PACKET_QUEUE_MAX)
    # Validate/auto-detect the capture interface BEFORE forking the internal
    # scanner. The child inherits NETWORK_INTERFACE as it is at fork time, so a
    # stale value (e.g. a Windows \Device\NPF_... path in backend_conf.json after
    # moving to Linux) would otherwise make internal_scanner_process fail forever
    # while only the external sniffer self-heals.
    validate_interface()
    zeroconf, mdns_listener = start_mdns_listener()
    internal_process = Process(
        target=internal_scanner_process,
        args=(my_geo_data, my_local_ip, my_public_ip, packet_queue, is_internal_search_active, stats, mdns_listener, showAllUDPPackets),
        daemon=True
    )
    internal_process.start()
    import atexit
    atexit.register(cleanup, internal_process, zeroconf)
    threading.Thread(
        target=start_sniffing,
        args=(my_geo_data, my_local_ip, my_public_ip, packet_queue, stats, mdns_listener, showAllUDPPackets),
        daemon=True
    ).start()

    @socketio.on('connect')
    def handle_connect():
        try:
            if not session.get('authenticated'):
                disconnect()
                return
            sid = request.sid
            with active_clients_lock:
                active_clients.add(sid)
                count = len(active_clients)
            settings = load_settings()
            socketio.emit('settings_update', settings, to=sid)
            send_all_ips_to_client(sid)
            send_pinned_ips_to_client(sid)
            logger.info(f"Client connected, SID: {sid}, Active clients: {count}")
        except Exception as e:
            logger.error(f"Error on client connect: {e}")

    @socketio.on('disconnect')
    def handle_disconnect():
        try:
            sid = request.sid
            with active_clients_lock:
                active_clients.discard(sid)
                count = len(active_clients)
            socket_rate_prune()
            logger.info(f"Client disconnected, SID: {sid}, Active clients: {count}")
        except Exception as e:
            logger.error(f"Error on client disconnect: {e}")

    @socketio.on('request_initial_data')
    def handle_request_initial_data():
        if not session.get('authenticated'):
            return
        if socket_rate_limited('request_initial_data'):
            logger.warning(f"Rate limit exceeded for request_initial_data from SID {request.sid}")
            return
        try:
            sid = request.sid
            settings = load_settings()
            socketio.emit('settings_update', settings, to=sid)
            socketio.emit('devices_update', public_device_list(), to=sid)
            send_all_ips_to_client(sid)
            send_pinned_ips_to_client(sid)
        except Exception as e:
            logger.error(f"Error sending initial data: {e}")

    @socketio.on('set_internal_search')
    def handle_set_internal_search(data):
        if not session.get('authenticated'):
            return
        if socket_rate_limited('set_internal_search'):
            logger.warning(f"Rate limit exceeded for set_internal_search from SID {request.sid}")
            return
        try:
            is_active = data.get('isInternalSearchActive', False)
            if not isinstance(is_active, bool):
                logger.error(f"Invalid value for isInternalSearchActive: {is_active}")
                return
            is_internal_search_active.value = is_active
            save_setting('is_internal_search_active', is_active)
            socketio.emit('settings_update', {'is_internal_search_active': is_active})
            logger.info(f"Internal search {'enabled' if is_active else 'disabled'}")
        except Exception as e:
            logger.error(f"Error in set_internal_search: {e}")

    @socketio.on('set_udp_filter')
    def handle_set_udp_filter(data):
        if not session.get('authenticated'):
            return
        if socket_rate_limited('set_udp_filter'):
            logger.warning(f"Rate limit exceeded for set_udp_filter from SID {request.sid}")
            return
        try:
            show_all_udp = data.get('showAllUDPPackets', False)
            if not isinstance(show_all_udp, bool):
                logger.error(f"Invalid value for showAllUDPPackets: {show_all_udp}")
                return
            showAllUDPPackets.value = show_all_udp
            save_setting('show_all_udp_packets', show_all_udp)
            socketio.emit('settings_update', {'show_all_udp_packets': show_all_udp})
            logger.info(f"UDP filter {'all packets' if show_all_udp else 'filtered'}")
        except Exception as e:
            logger.error(f"Error in set_udp_filter: {e}")

    @socketio.on('pin_ip')
    def handle_pin_ip(data):
        if not session.get('authenticated'):
            return
        if socket_rate_limited('pin_ip'):
            logger.warning(f"Rate limit exceeded for pin_ip from SID {request.sid}")
            return
        try:
            ip = data.get('ip')
            is_pinned = data.get('isPinned', False)
            if not ip or not isinstance(is_pinned, bool):
                logger.error(f"Invalid data in pin_ip: ip={ip}, isPinned={is_pinned}")
                return
            update_pinned_ips(ip, is_pinned)
            socketio.emit('ip_pinned_update', {'ip': ip, 'isPinned': is_pinned})
            logger.info(f"IP {ip} {'pinned' if is_pinned else 'unpinned'}")
        except Exception as e:
            logger.error(f"Error pinning/unpinning IP {ip}: {e}")

    @socketio.on('reset_packet_count')
    def handle_reset_packet_count(data):
        if not session.get('authenticated'):
            return
        if socket_rate_limited('reset_packet_count'):
            logger.warning(f"Rate limit exceeded for reset_packet_count from SID {request.sid}")
            return
        try:
            ip = data.get('ip')
            if not ip:
                logger.error("IP address missing in reset_packet_count")
                return
            with locked(db_lock):
                with db.get_connection() as conn:
                    c = conn.cursor()
                    c.execute("UPDATE ip_data SET incoming_count = 0, outgoing_count = 0 WHERE ip = %s", (ip,))
                    c.execute("UPDATE pinned_ips SET packet_count = 0 WHERE ip = %s", (ip,))
                    conn.commit()
            logger.info(f"Packet count for IP {ip} reset")
            socketio.emit('packet_count_reset', {'ip': ip})
        except Exception as e:
            logger.error(f"Error resetting packet count for IP {ip}: {e}")

    try:
        host = os.environ.get('APP_HOST', '127.0.0.1')
        port = int(os.environ.get('APP_PORT', '8000'))
        # allow_unsafe_werkzeug: GDEF-L1NK ships the bundled Werkzeug server
        # as its runtime (no eventlet/gevent). Newer Werkzeug refuses to start via
        # socketio.run() without this flag. This is a self-hosted monitoring tool
        # bound to localhost by default, not a public production web service.
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info("Program terminated")
