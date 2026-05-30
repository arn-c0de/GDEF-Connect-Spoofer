import db
import threading
import time
import re
from scapy.all import sniff, get_if_list
from capture_core import (
    MAC_RE, MAX_PACKET_LEN, UDP_FILTER_PORTS,
    is_valid_mac, is_private_ip, estimate_os, build_bpf_filter, classify_packet,
)
import requests
import ipaddress
import ctypes
import sys
import socket
from zeroconf import ServiceBrowser, Zeroconf
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, disconnect
from uuid import uuid4
import logging
from multiprocessing import Process, Manager, Queue, Value
from queue import Empty, Full, Queue as ThreadQueue
import os
import json
from contextlib import contextmanager
from functools import wraps
from urllib.parse import urlparse, urljoin
import secrets

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

# O_NOFOLLOW only exists on POSIX; degrade to 0 on platforms (Windows) that
# lack it so the open() call stays portable.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

def write_secret_file(path, data):
    """Persist a 0600 secret file atomically and without following symlinks.

    Defends against a local attacker who pre-creates a symlink at `path` before
    the app first runs (the database/ dir is 0700, but this is belt-and-braces):
    we write to a fresh temp file in the same directory opened O_CREAT|O_EXCL|
    O_NOFOLLOW (so we neither follow nor reuse anything an attacker planted),
    then os.replace() it into place. os.replace is atomic, so the destination
    is never observed half-written, and renaming onto a symlinked path replaces
    the link itself rather than writing through it to the target.
    """
    directory = os.path.dirname(path) or "."
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)

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
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def is_safe_redirect_target(target):
    """Allow only local, relative redirect targets (open-redirect protection).

    Accepts paths like '/index' but rejects absolute URLs ('http://evil'),
    scheme-relative URLs ('//evil') and backslash tricks ('/\\evil')."""
    if not target:
        return False
    # Reject anything that isn't a plain path rooted at '/'
    if not target.startswith('/'):
        return False
    # '//host' and '/\host' are scheme-relative / host-relative -> external
    if target.startswith('//') or target.startswith('/\\'):
        return False
    # A control char or embedded scheme indicates an attempt to escape
    if '\\' in target or '\n' in target or '\r' in target:
        return False
    # Defense in depth: the target must be a pure path with no scheme/host of
    # its own, so it can never point off-origin.
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return False
    return True

# Brute-force protection for the login form (simple in-memory limiter).
LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', '5'))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get('LOGIN_LOCKOUT_SECONDS', '300'))
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

# Configuration
CONFIG = {
    "network_interface": load_network_interface(),
    "cache_timeout": 3600,
    "api_timeout": 5,
    "database_dir": "database",
    "database_path": os.path.join("database", "geo_data.db"),
}
NETWORK_INTERFACE = CONFIG["network_interface"]
DEFAULT_COORDS = [0, 0]
CACHE_TIMEOUT = CONFIG["cache_timeout"]
EXPIRATION_SECONDS = 3600
# Hard ceiling on rows kept in ip_data. Even under a spoofing flood (new IPs are
# rate-limited but can still accumulate within the EXPIRATION_SECONDS window),
# the cleanup thread trims the oldest unpinned rows beyond this cap so the DB
# can't fill the disk. Override via the MAX_IP_ROWS env var.
MAX_IP_ROWS = int(os.environ.get("MAX_IP_ROWS", "50000"))
SNIFF_TIMEOUT = 30
SOCKETIO_PING_TIMEOUT = 120
SOCKETIO_PING_INTERVAL = 25
DATABASE_DIR = CONFIG["database_dir"]
DATABASE_PATH = CONFIG["database_path"]
TRUSTED_ORGS_PATH = os.path.join(DATABASE_DIR, "trusted_organisations.json")
API_TIMEOUT = CONFIG["api_timeout"]

# Global variables
geo_cache = {}
known_ips = set()
tcp_connections = {}
cache_lock = threading.Lock()
active_clients = set()
active_clients_lock = threading.Lock()
db_lock = threading.Lock()
pinned_ips_cache = {}

# Per-client Socket.IO rate limiting (sliding window). Caps how often a single
# client may invoke state-changing events such as pin_ip / reset_packet_count,
# preventing a flood of server-side DB writes. Keyed on the client IP (not the
# SID) so a client cannot bypass the limit by disconnecting and immediately
# reconnecting under a fresh SID (SID churn).
SOCKET_RATE_LIMIT = int(os.environ.get('SOCKET_RATE_LIMIT', '5'))        # events per window
SOCKET_RATE_WINDOW = float(os.environ.get('SOCKET_RATE_WINDOW', '1.0'))  # window length (seconds)
_socket_event_times = {}   # (client_ip, event_name) -> [timestamps]
_socket_rate_lock = threading.Lock()

def socket_rate_limited(event_name):
    """Return True if the client IP has exceeded the rate for `event_name`."""
    try:
        client = request.remote_addr or request.sid
    except Exception:
        return False
    now = time.time()
    key = (client, event_name)
    with locked(_socket_rate_lock):
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
        for key in [k for k, v in _socket_event_times.items()
                    if all(now - t >= SOCKET_RATE_WINDOW for t in v)]:
            del _socket_event_times[key]

# Constants for DoS protection
MAX_KNOWN_IPS = 10000
MAX_CACHE_SIZE = 5000
IP_UPDATE_INTERVAL = 1.0  # Min seconds between updates for the same IP
# MAX_PACKET_LEN and the BPF capture filter live in capture_core (shared with the
# sensor worker). The filter drops the dashboard's own TCP traffic on APP_PORT so
# the web UI is neither visualized nor adds parsing load under heavy traffic.
CAPTURE_BPF_FILTER = build_bpf_filter(os.environ.get('APP_PORT', '8000'))
last_ip_updates = {}

# Packet Queue
class PacketQueue:
    def __init__(self):
        self.queue = Queue(maxsize=5000)

    def put(self, item):
        try:
            is_external = not (is_private_ip(item.get('ip_src', '')) and is_private_ip(item.get('ip_dst', '')))
            priority = 1 if is_external else 5
            self.queue.put_nowait((priority, item))
            logger.debug(f"Packet queued: {item.get('protocol')}, {'external' if is_external else 'internal'}")
        except Full:
            logger.warning("Queue full, packet dropped")

    def get(self, timeout=None):
        return self.queue.get(timeout=timeout)

    def empty(self):
        return self.queue.empty()

class SharedStats:
    """Cross-process packet counters backed by multiprocessing.Value (shared
    memory) instead of a Manager().dict() proxy.

    A Manager proxy serializes every read/write over a socket to the manager
    process. Updating it on every captured packet from two processes becomes a
    hard IPC bottleneck at high packet rates and makes the sniffer drop frames at
    the kernel. Value uses a shared-memory cell with a tiny lock, which is orders
    of magnitude cheaper. Created before fork so children share the same cells."""
    _FIELDS = ('tcp_packets', 'udp_packets', 'icmp_packets', 'total_bytes', 'active_connections', 'fragmented_packets')

    def __init__(self):
        # 'q' = signed 64-bit, so total_bytes cannot overflow under sustained load.
        self._v = {name: Value('q', 0) for name in self._FIELDS}

    def incr(self, name, amount=1):
        v = self._v[name]
        with v.get_lock():
            v.value += amount

    def set(self, name, value):
        v = self._v[name]
        with v.get_lock():
            v.value = value

    def snapshot(self):
        return {name: v.value for name, v in self._v.items()}

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
    if not mac:
        return None
    # Read-only and on the capture path (also the forked sniffer process): use a
    # lock-free connection. WAL serves a consistent snapshot without blocking on
    # the writer.
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT vendor FROM mac_cache WHERE mac = %s", (mac,))
            result = c.fetchone()
            return result[0] if result else None
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
            pinned_ips_cache = {row[0]: row[1] for row in c.fetchall()}
    except db.DBError as e:
        logger.error(f"Error loading pinned IPs: {e}")

def update_pinned_ips(ip, is_pinned):
    global pinned_ips_cache
    with locked(db_lock):
        try:
            with db.get_connection() as conn:
                c = conn.cursor()
                if is_pinned:
                    c.execute("INSERT INTO pinned_ips (ip, packet_count) VALUES (%s, 0) "
                              "ON CONFLICT (ip) DO NOTHING", (ip,))
                    pinned_ips_cache[ip] = 0
                else:
                    c.execute("DELETE FROM pinned_ips WHERE ip = %s", (ip,))
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
    if request.method == "POST" and not request.path.startswith('/socket.io'):
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
            if not is_safe_redirect_target(target):
                return redirect(url_for('index'))
            # Pin the redirect to this origin: the host comes from our own
            # request, only the (validated, host-free) path comes from 'next'.
            return redirect(urljoin(request.host_url, target.lstrip('/')))
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
_MDNS_HOSTNAME_RE = re.compile(r'[^A-Za-z0-9._-]')

def sanitize_mdns_hostname(name):
    """mDNS names are untrusted input. Strip to a DNS-safe charset and cap the
    length so a spoofed service name cannot smuggle markup, control characters,
    or unbounded text into the DB / UI."""
    if not name:
        return "Unknown"
    cleaned = _MDNS_HOSTNAME_RE.sub('', name)[:63]
    return cleaned or "Unknown"

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

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        logger.info(f"Local IP: {local_ip}")
        return local_ip
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return "127.0.0.1"

# Linux capability bits required for raw packet capture.
CAP_NET_ADMIN = 12
CAP_NET_RAW = 13

def has_net_capabilities():
    """On Linux, check whether the effective capability set grants the rights
    needed for sniffing (CAP_NET_RAW / CAP_NET_ADMIN). This lets the app run as
    a non-root user when the Python binary has been granted capabilities via:
        sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
    """
    try:
        with open('/proc/self/status', 'r') as f:
            for line in f:
                if line.startswith('CapEff:'):
                    cap_eff = int(line.split()[1], 16)
                    needed = (1 << CAP_NET_RAW)
                    return (cap_eff & needed) == needed
    except Exception as e:
        logger.debug(f"Could not read capabilities: {e}")
    return False

def is_admin():
    """Return True if the process can capture raw packets: either it is root /
    Administrator, or (on Linux) it holds the required net capabilities."""
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin()
        if os.geteuid() == 0:
            return True
        # Non-root: accept if capabilities have been granted (least privilege).
        return has_net_capabilities()
    except Exception as e:
        logger.error(f"Error checking admin privileges: {e}")
        return False

def auto_detect_interface():
    """Auto-detects the best network interface on all platforms."""
    available = get_if_list()
    if not available:
        return None

    if sys.platform == 'win32':
        # On Windows: first interface as fallback
        return available[0]

    # On Linux/macOS: prefer real network interfaces
    preferred_prefixes = ('eth', 'en', 'wl', 'wlan', 'ens', 'enp', 'wlp')
    for iface in available:
        if iface.startswith(preferred_prefixes):
            return iface

    # Fallback: first interface that is not lo
    for iface in available:
        if iface != 'lo':
            return iface

    return available[0]

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
                # Create tables
                c.execute('''CREATE TABLE IF NOT EXISTS ip_data
                             (ip TEXT PRIMARY KEY, lat DOUBLE PRECISION, lon DOUBLE PRECISION, city TEXT,
                              country TEXT, last_seen DOUBLE PRECISION, org TEXT,
                              src_port INTEGER, dst_port INTEGER, protocol TEXT, incoming_count BIGINT DEFAULT 0,
                              outgoing_count BIGINT DEFAULT 0, mac TEXT, vendor TEXT, hostname TEXT, os TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS pinned_ips
                             (ip TEXT PRIMARY KEY, packet_count BIGINT DEFAULT 0)''')
                c.execute('''CREATE TABLE IF NOT EXISTS settings
                             (key TEXT PRIMARY KEY, value TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS mac_cache
                             (mac TEXT PRIMARY KEY, vendor TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS threat_list
                             (ip TEXT PRIMARY KEY, threat_level TEXT, source TEXT)''')

                # Create indexes
                c.execute("CREATE INDEX IF NOT EXISTS idx_ip_data_last_seen ON ip_data(last_seen)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_threat_list_ip ON threat_list(ip)")

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
                settings[key] = value == '1' if key in settings else value
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
                db_value = '1' if value else '0' if key in ['is_internal_search_active', 'show_all_udp_packets', 'show_local_network', 'show_external_network', 'show_tcp_only'] else value
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

def compute_org_threat(ip, org):
    """Classify an IP's threat level from its org, falling back to the
    threat_list table. Used by the background geo worker."""
    tl = classify_org_threat(org, load_org_lists())
    if tl is not None:
        return tl
    # Read-only: lock-free connection (runs in the background geo worker).
    try:
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT threat_level FROM threat_list WHERE ip = %s", (ip,))
            threat = c.fetchone()
            return threat[0] if threat else "No Threat"
    except db.DBError as e:
        logger.error(f"Error fetching threat level for IP {ip}: {e}")
        return "No Threat"

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
            threat_level = compute_org_threat(ip, org)
            # If a write for this IP is still buffered (geo resolved before the
            # first flush), patch it so the flush persists the resolved location
            # instead of the placeholder.
            with locked(ip_write_buffer_lock):
                be = ip_write_buffer.get(ip)
                if be is not None:
                    be.update({"lat": geo["lat"], "lon": geo["lon"], "city": geo["city"],
                               "country": geo["country"], "region": geo.get("region", ""), "org": org})
            row = None
            with locked(db_lock):
                try:
                    with db.get_connection() as conn:
                        c = conn.cursor()
                        c.execute('''SELECT incoming_count, outgoing_count, src_port, dst_port, protocol,
                                     mac, vendor, hostname, os,
                                     (SELECT packet_count FROM pinned_ips WHERE pinned_ips.ip = ip_data.ip)
                                     FROM ip_data WHERE ip = %s''', (ip,))
                        row = c.fetchone()
                        if row:
                            c.execute("UPDATE ip_data SET lat = %s, lon = %s, city = %s, country = %s, org = %s WHERE ip = %s",
                                      (geo["lat"], geo["lon"], geo["city"], geo["country"], org, ip))
                            conn.commit()
                except db.DBError as e:
                    logger.error(f"Error storing geo for {ip}: {e}")
                    row = None
            if row:
                incoming_count, outgoing_count, src_port, dst_port, protocol, mac, vendor, hostname, os_guess, packet_count = row
                display_hostname = ip if is_private_ip(ip) else hostname
                send_ip_to_clients(ip, geo["lat"], geo["lon"], geo["city"], geo["country"], geo.get("region", ""),
                                   org, time.time(), protocol, src_port, dst_port, mac, vendor,
                                   incoming_count, outgoing_count, packet_count or 0, display_hostname, os_guess, threat_level)
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

def update_ip(ip, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, mac=None, vendor="Unknown", src_ip=None, dst_ip=None, ttl=None, hostname="Unknown"):
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
        "last_seen": now,
    })

# --- Buffered IP writes (DoS protection: coalesce + batch DB writes) ----------
IP_WRITE_FLUSH_INTERVAL = float(os.environ.get('IP_WRITE_FLUSH_INTERVAL', '1.0'))
# Cap how many distinct IPs we buffer between flushes. Beyond this, new IPs are
# dropped (logged, never silently) so a unique-IP flood can't exhaust memory.
IP_WRITE_BUFFER_MAX = int(os.environ.get('IP_WRITE_BUFFER_MAX', '20000'))
ip_write_buffer = {}
ip_write_buffer_lock = threading.Lock()
_ip_write_buffer_dropped = 0

def buffer_ip_write(ip, direction, data):
    """Accumulate a pending write for `ip`: latest field values win, packet
    counts accumulate as deltas (only for non-private IPs, matching the original
    semantics)."""
    global _ip_write_buffer_dropped
    with locked(ip_write_buffer_lock):
        e = ip_write_buffer.get(ip)
        if e is None:
            if len(ip_write_buffer) >= IP_WRITE_BUFFER_MAX:
                _ip_write_buffer_dropped += 1
                return
            e = {"in_delta": 0, "out_delta": 0, "is_private": is_private_ip(ip)}
            ip_write_buffer[ip] = e
        e.update(data)
        if not e["is_private"]:
            if direction == "incoming":
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
            with locked(db_lock):
                try:
                    with db.get_connection() as conn:
                        c = conn.cursor()
                        for ip, e in batch.items():
                            org = e.get("org", "Unknown")
                            threat_level = classify_org_threat(org, org_lists)
                            if threat_level is None:
                                c.execute("SELECT threat_level FROM threat_list WHERE ip = %s", (ip,))
                                r = c.fetchone()
                                threat_level = r[0] if r else "No Threat"
                            c.execute("SELECT incoming_count, outgoing_count FROM ip_data WHERE ip = %s", (ip,))
                            row = c.fetchone()
                            if row:
                                inc, out = row[0] + e["in_delta"], row[1] + e["out_delta"]
                                # Don't let a buffered placeholder clobber a value
                                # an async enrichment worker may have already
                                # resolved into the row. geo_enrichment_worker owns
                                # lat/lon/city/country/org; mac_enrichment_worker
                                # owns vendor. Both write fine-grained UPDATEs on
                                # disjoint columns, but this full-row flush could
                                # still overwrite them with the placeholder that was
                                # buffered before resolution (last-writer-wins). Gate
                                # those columns on a resolved-flag so we only write
                                # them when the buffer actually carries real data.
                                geo_ok = 1 if (e["city"] != "Unknown" or e["country"] != "Unknown") else 0
                                vendor_ok = 1 if e["vendor"] not in (None, "", "Unknown") else 0
                                c.execute('''UPDATE ip_data SET
                                             lat = CASE WHEN %s=1 THEN %s ELSE lat END,
                                             lon = CASE WHEN %s=1 THEN %s ELSE lon END,
                                             city = CASE WHEN %s=1 THEN %s ELSE city END,
                                             country = CASE WHEN %s=1 THEN %s ELSE country END,
                                             org = CASE WHEN %s=1 THEN %s ELSE org END,
                                             last_seen = %s, src_port = %s, dst_port = %s, protocol = %s,
                                             incoming_count = %s, outgoing_count = %s, mac = %s,
                                             vendor = CASE WHEN %s=1 THEN %s ELSE vendor END,
                                             hostname = %s, os = %s WHERE ip = %s''',
                                          (geo_ok, e["lat"], geo_ok, e["lon"], geo_ok, e["city"],
                                           geo_ok, e["country"], geo_ok, org,
                                           e["last_seen"], e["src_port"], e["dst_port"], e["protocol"],
                                           inc, out, e["mac"], vendor_ok, e["vendor"],
                                           e["hostname"], e["os"], ip))
                            else:
                                inc, out = e["in_delta"], e["out_delta"]
                                c.execute('''INSERT INTO ip_data (ip, lat, lon, city, country, last_seen, org, src_port, dst_port,
                                             protocol, incoming_count, outgoing_count, mac, vendor, hostname, os)
                                             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                                          (ip, e["lat"], e["lon"], e["city"], e["country"], e["last_seen"], org,
                                           e["src_port"], e["dst_port"], e["protocol"], inc, out,
                                           e["mac"], e["vendor"], e["hostname"], e["os"]))
                            broadcasts.append((e, inc, out, threat_level))
                        conn.commit()
                except db.DBError as ex:
                    logger.error(f"Error flushing IP writes: {ex}")
                    continue
            # Broadcast after releasing db_lock so emit never blocks the writer.
            # A5: collapse the whole interval's per-IP updates into ONE batched
            # Socket.IO message per client instead of N separate emits, cutting
            # fan-out from (IPs x clients) frames to (1 x clients) per interval.
            messages = []
            for e, inc, out, threat_level in broadcasts:
                m = build_ip_message(e["geo_ip"], e["lat"], e["lon"], e["city"], e["country"], e["region"],
                                     e.get("org", "Unknown"), e["last_seen"], e["protocol"], e["src_port"], e["dst_port"],
                                     e["mac"], e["vendor"], inc, out, 0, e["hostname"], e["os"], threat_level)
                if m is not None:
                    messages.append(m)
            if messages:
                socketio.emit('ip_update_batch', messages)
        except Exception as ex:
            logger.error(f"Error in flush_ip_writes: {ex}")
            time.sleep(IP_WRITE_FLUSH_INTERVAL)

def send_network_stats(stats):
    while True:
        try:
            socketio.emit('network_stats', stats.snapshot())
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
                    c.execute('''DELETE FROM ip_data WHERE last_seen < %s AND ip NOT IN (SELECT ip FROM pinned_ips)''',
                              (now - EXPIRATION_SECONDS,))
                    conn.commit()

                    # Hard row cap: even within the expiration window a spoofing
                    # flood could pile up enough rows to fill the disk. Keep the
                    # newest MAX_IP_ROWS unpinned rows and drop the oldest beyond it.
                    c.execute("SELECT COUNT(*) FROM ip_data")
                    if c.fetchone()[0] > MAX_IP_ROWS:
                        c.execute('''DELETE FROM ip_data WHERE ip IN (
                                         SELECT ip FROM ip_data
                                         WHERE ip NOT IN (SELECT ip FROM pinned_ips)
                                         ORDER BY last_seen DESC
                                         OFFSET %s)''', (MAX_IP_ROWS,))
                        trimmed = c.rowcount
                        conn.commit()
                        if trimmed > 0:
                            logger.warning(f"ip_data exceeded MAX_IP_ROWS ({MAX_IP_ROWS}); "
                                           f"trimmed {trimmed} oldest unpinned rows")
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
    logger.debug(f"Packet captured: {packet.summary()}")
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

def internal_packet_callback(packet, my_geo_data, my_local_ip, my_public_ip, queue, is_internal_search_active, stats, mdns_listener, showAllUDPPackets):
    logger.debug(f"Internal packet captured: {packet.summary()}")
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

def build_ip_message(ip, lat, lon, city, country, region, org, last_seen, protocol, src_port, dst_port, mac, vendor, incoming_count, outgoing_count, packet_count=0, hostname="Unknown", os="Unknown", threat_level="No Threat"):
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
        "ip": ip,
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
            c.execute('''SELECT ip, lat, lon, city, country, org, last_seen, src_port, dst_port, protocol,
                         incoming_count, outgoing_count, mac, vendor, hostname, os,
                         (SELECT packet_count FROM pinned_ips WHERE pinned_ips.ip = ip_data.ip) as packet_count
                         FROM ip_data WHERE last_seen > %s''', (time.time() - EXPIRATION_SECONDS,))
            rows = c.fetchall()
    except db.DBError as e:
        logger.error(f"Error sending all IPs: {e}")
        return
    for row in rows:
        ip, lat, lon, city, country, org, last_seen, src_port, dst_port, protocol, incoming_count, outgoing_count, mac, vendor, hostname, os, packet_count = row
        display_hostname = ip if is_private_ip(ip) else hostname
        messages.append({
            "ip": ip,
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
            "os": os
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

def process_packets(queue, my_geo_data, my_local_ip, my_public_ip, is_internal_search_active, mdns_listener):
    while True:
        try:
            priority, packet_data = queue.get(timeout=0.1)
            logger.debug(f"Dequeued packet: {packet_data}")
            try:
                if 'ip' in packet_data:
                    ip = packet_data["ip"]
                    if not packet_data.get("vendor") or packet_data.get("vendor") == "Unknown":
                        queue_mac_enrichment(packet_data.get("mac"))
                    if is_private_ip(ip) and not is_internal_search_active.value:
                        # Hot-path read: lock-free so a packet flood's pinned-check
                        # never serializes behind the 1s write flush.
                        with db_connect() as conn:
                            c = conn.cursor()
                            c.execute("SELECT ip FROM pinned_ips WHERE ip = %s", (ip,))
                            if not c.fetchone():
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
                        packet_data.get("hostname")
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
                        update_ip(ip_src, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, src_mac, src_vendor, ip_src, ip_dst, ttl, hostname_src)
                    if ip_dst != my_local_ip and ip_dst != my_public_ip and not is_private_ip(ip_dst):
                        update_ip(ip_dst, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, dst_mac, dst_vendor, ip_src, ip_dst, ttl, hostname_dst)
                    elif is_internal_search_active.value:
                        if is_private_ip(ip_src) and ip_src != my_local_ip and ip_src != my_public_ip:
                            update_ip(ip_src, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, src_mac, src_vendor, ip_src, ip_dst, ttl, hostname_src)
                        if is_private_ip(ip_dst) and ip_dst != my_local_ip and ip_dst != my_public_ip:
                            update_ip(ip_dst, direction, protocol, src_port, dst_port, my_geo_data, my_local_ip, my_public_ip, dst_mac, dst_vendor, ip_src, ip_dst, ttl, hostname_dst)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        except Empty:
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
    if not is_admin():
        if sys.platform == 'win32':
            logger.error("This script requires administrator privileges.")
        else:
            logger.error(
                "Packet capture requires CAP_NET_RAW. Either run with sudo, or "
                "grant capabilities to run as a non-root user (least privilege):\n"
                "  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
            )
        sys.exit(1)
    validate_interface()
    init_db()
    threading.Thread(target=cleanup_expired_ips, args=(stats,), daemon=True).start()
    threading.Thread(target=send_network_stats, args=(stats,), daemon=True).start()
    threading.Thread(target=process_packets, args=(queue, my_geo_data, my_local_ip, my_public_ip, is_internal_search_active, mdns_listener), daemon=True).start()
    threading.Thread(target=mac_enrichment_worker, daemon=True).start()
    threading.Thread(target=geo_enrichment_worker, args=(my_geo_data,), daemon=True).start()
    threading.Thread(target=flush_ip_writes, daemon=True).start()
    while True:
        try:
            sniff(iface=NETWORK_INTERFACE, prn=lambda pkt: external_packet_callback(pkt, my_geo_data, my_local_ip, my_public_ip, queue, stats, mdns_listener, showAllUDPPackets),
                  filter=CAPTURE_BPF_FILTER, store=0, timeout=SNIFF_TIMEOUT)
        except Exception as e:
            logger.error(f"Error during sniffing: {e}")
            time.sleep(5)

def cleanup(internal_process, zeroconf):
    logger.info("Shutting down processes...")
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
    settings = load_settings()
    is_internal_search_active = manager.Value('b', settings.get('is_internal_search_active', True))
    showAllUDPPackets = manager.Value('b', settings.get('show_all_udp_packets', True))
    packet_queue = PacketQueue()
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
        # allow_unsafe_werkzeug: ConnectSpoofer ships the bundled Werkzeug server
        # as its runtime (no eventlet/gevent). Newer Werkzeug refuses to start via
        # socketio.run() without this flag. This is a self-hosted monitoring tool
        # bound to localhost by default, not a public production web service.
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info("Program terminated")
