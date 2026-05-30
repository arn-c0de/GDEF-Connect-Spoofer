import sqlite3
import threading
import time
import re
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, Ether
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
import secrets

# Logging Setup
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Security Configuration
ACCESS_TOKEN = secrets.token_urlsafe(16)
TOKEN_FILE = os.path.join("database", "access_token.txt")

try:
    if not os.path.exists("database"):
        os.makedirs("database")
    with open(TOKEN_FILE, "w") as f:
        f.write(ACCESS_TOKEN)
    os.chmod(TOKEN_FILE, 0o600)
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
    """Loads the network interface from the JSON configuration file."""
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
# Upper bound for captured frame size. Standard Ethernet is 1500, but jumbo
# frames (up to ~9000), VLAN tagging and tunneling produce larger valid frames;
# a hard 1500 cap let an attacker evade capture with oversized packets. Override
# with MAX_PACKET_LEN.
MAX_PACKET_LEN = int(os.environ.get('MAX_PACKET_LEN', '9000'))
# Kernel-level capture filter (BPF). Restrict to IP/ICMP and drop the dashboard's
# own TCP traffic (APP_PORT) so the web UI is neither visualized nor adds Python
# parsing/CPU load under heavy traffic. APP_PORT is validated to a safe integer
# before interpolation to avoid BPF-expression injection.
try:
    _app_port_int = int(os.environ.get('APP_PORT', '8000'))
    if not 0 < _app_port_int < 65536:
        raise ValueError("port out of range")
    CAPTURE_BPF_FILTER = f"(ip or icmp) and not (tcp port {_app_port_int})"
except (ValueError, TypeError):
    CAPTURE_BPF_FILTER = "ip or icmp"
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

# Strict MAC format (aa:bb:cc:dd:ee:ff or aa-bb-...). Used to validate any value
# before it is interpolated into an outbound API URL, preventing path-injection
# / SSRF via a crafted MAC seen on the wire.
MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

def is_valid_mac(mac):
    return bool(mac) and bool(MAC_RE.match(mac))

def get_mac_vendor(mac):
    if not mac:
        return "Unknown"
    if not is_valid_mac(mac):
        # Never put an unvalidated value into the request URL.
        logger.warning(f"Refusing vendor lookup for malformed MAC: {mac!r}")
        return "Unknown"
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT vendor FROM mac_cache WHERE mac = ?", (mac,))
                result = c.fetchone()
                if result:
                    return result[0]
        except sqlite3.Error as e:
            logger.error(f"Error accessing mac_cache for MAC {mac}: {e}")
            return "Unknown"
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=API_TIMEOUT)
        if response.status_code == 200:
            vendor = response.text.strip() or "Unknown"
            with locked(db_lock):
                try:
                    with sqlite3.connect(DATABASE_PATH) as conn:
                        c = conn.cursor()
                        c.execute("INSERT OR REPLACE INTO mac_cache (mac, vendor) VALUES (?, ?)", (mac, vendor))
                        conn.commit()
                except sqlite3.Error as e:
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
                    with sqlite3.connect(DATABASE_PATH) as conn:
                        c = conn.cursor()
                        c.execute("INSERT OR REPLACE INTO mac_cache (mac, vendor) VALUES (?, ?)", (mac, vendor))
                        conn.commit()
                except sqlite3.Error as e:
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
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT vendor FROM mac_cache WHERE mac = ?", (mac,))
                result = c.fetchone()
                return result[0] if result else None
        except sqlite3.Error as e:
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
                        with sqlite3.connect(DATABASE_PATH) as conn:
                            conn.execute(
                                "UPDATE ip_data SET vendor = ? WHERE mac = ? AND (vendor IS NULL OR vendor = 'Unknown')",
                                (vendor, mac),
                            )
                            conn.commit()
                    except sqlite3.Error as e:
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
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT ip, packet_count FROM pinned_ips")
                pinned_ips_cache = {row[0]: row[1] for row in c.fetchall()}
        except sqlite3.Error as e:
            logger.error(f"Error loading pinned IPs: {e}")

def update_pinned_ips(ip, is_pinned):
    global pinned_ips_cache
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                if is_pinned:
                    c.execute("INSERT OR IGNORE INTO pinned_ips (ip, packet_count) VALUES (?, 0)", (ip,))
                    pinned_ips_cache[ip] = 0
                else:
                    c.execute("DELETE FROM pinned_ips WHERE ip = ?", (ip,))
                    pinned_ips_cache.pop(ip, None)
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error updating pinned IPs for {ip}: {e}")

# Flask app and Socket.IO
app = Flask(__name__)

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
        if os.path.exists(SECRET_KEY_FILE):
            with open(SECRET_KEY_FILE, 'r') as f:
                key = f.read().strip()
            if key:
                return key
        key = secrets.token_urlsafe(32)
        os.makedirs("database", exist_ok=True)
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(key)
        os.chmod(SECRET_KEY_FILE, 0o600)
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
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.socket.io; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://*; connect-src 'self' ws: wss: https://raw.githubusercontent.com https://api.macvendors.com https://maclookup.app http://ip-api.com https://ipinfo.io https://api.ipify.org; frame-ancestors 'none';"
    return response

@app.before_request
def csrf_protect():
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
                target = url_for('index')
            return redirect(target)
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

def init_db():
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)
        logger.info(f"Database directory created: {DATABASE_DIR}")
    init_trusted_organisations()
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                # Optimize SQLite settings
                c.execute("PRAGMA synchronous = NORMAL")
                c.execute("PRAGMA journal_mode = WAL")
                c.execute("PRAGMA cache_size = -20000")  # 20MB cache

                # Create tables
                c.execute('''CREATE TABLE IF NOT EXISTS ip_data
                             (ip TEXT PRIMARY KEY, lat REAL, lon REAL, city TEXT, country TEXT, last_seen REAL, org TEXT, 
                              src_port INTEGER, dst_port INTEGER, protocol TEXT, incoming_count INTEGER DEFAULT 0, 
                              outgoing_count INTEGER DEFAULT 0, mac TEXT, vendor TEXT, hostname TEXT, os TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS pinned_ips
                             (ip TEXT PRIMARY KEY, packet_count INTEGER DEFAULT 0)''')
                c.execute('''CREATE TABLE IF NOT EXISTS settings
                             (key TEXT PRIMARY KEY, value TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS mac_cache
                             (mac TEXT PRIMARY KEY, vendor TEXT)''')
                c.execute('''CREATE TABLE IF NOT EXISTS threat_list
                             (ip TEXT PRIMARY KEY, threat_level TEXT, source TEXT)''')

                # Create indexes
                c.execute("CREATE INDEX IF NOT EXISTS idx_ip_data_ip ON ip_data(ip)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_ip_data_last_seen ON ip_data(last_seen)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_pinned_ips_ip ON pinned_ips(ip)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_mac_cache_mac ON mac_cache(mac)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_threat_list_ip ON threat_list(ip)")

                # Initialize settings
                c.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)''',
                          ('is_internal_search_active', '0'))
                c.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)''',
                          ('show_all_udp_packets', '1'))
                c.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)''',
                          ('show_local_network', '1'))
                c.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)''',
                          ('show_external_network', '1'))
                c.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)''',
                          ('show_tcp_only', '0'))
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error initializing database: {e}")

def load_settings():
    settings = {
        'is_internal_search_active': True,
        'show_all_udp_packets': True,
        'show_local_network': True,
        'show_external_network': True,
        'show_tcp_only': False
    }
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute('SELECT key, value FROM settings')
                for key, value in c.fetchall():
                    settings[key] = value == '1' if key in settings else value
            logger.debug(f"Loaded settings: {settings}")
            return settings
        except sqlite3.Error as e:
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
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM threat_list")
                for i in range(0, len(collected), batch_size):
                    c.executemany(
                        "INSERT OR IGNORE INTO threat_list (ip, threat_level, source) VALUES (?, ?, ?)",
                        collected[i:i + batch_size],
                    )
                conn.commit()
            logger.info(f"Threat list updated: {len(collected)} entries from {len(threat_sources)} sources")
        except sqlite3.Error as e:
            logger.error(f"Error updating threat list: {e}")

# Start the thread
threading.Thread(target=schedule_threat_list_updates, daemon=True).start()

@socketio.on('set_local_network')
def handle_set_local_network(data):
    if not session.get('authenticated'):
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
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                db_value = '1' if value else '0' if key in ['is_internal_search_active', 'show_all_udp_packets', 'show_local_network', 'show_external_network', 'show_tcp_only'] else value
                c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, db_value))
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error saving setting {key}: {e}")

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_loopback
    except ValueError:
        return False

def estimate_os(ttl):
    if ttl is None:
        return "Unknown"
    ttl = int(ttl)
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "macOS/iOS"
    return "Unknown"

api_call_lock = threading.Lock()
last_api_call = 0
API_CALL_INTERVAL = 0.1
UDP_FILTER_PORTS = {137, 138, 1900, 5353}

# Geolocation providers. ipinfo.io (HTTPS) is primary; ip-api.com (HTTP) is an
# optional fallback. Provide IPINFO_TOKEN for higher limits, or set
# ALLOW_INSECURE_GEO_API=0 to disable the unencrypted HTTP fallback entirely.
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '').strip()
ALLOW_INSECURE_GEO_API = os.environ.get('ALLOW_INSECURE_GEO_API', '1').lower() in ('1', 'true', 'yes')

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
        # Fallback provider: ip-api.com. The free tier is HTTP-only, so this is
        # used only when the HTTPS provider above is unavailable. Opt out by
        # setting ALLOW_INSECURE_GEO_API=0.
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
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT threat_level FROM threat_list WHERE ip = ?", (ip,))
                threat = c.fetchone()
                return threat[0] if threat else "No Threat"
        except sqlite3.Error as e:
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
                    with sqlite3.connect(DATABASE_PATH) as conn:
                        c = conn.cursor()
                        c.execute('''SELECT incoming_count, outgoing_count, src_port, dst_port, protocol,
                                     mac, vendor, hostname, os,
                                     (SELECT packet_count FROM pinned_ips WHERE pinned_ips.ip = ip_data.ip)
                                     FROM ip_data WHERE ip = ?''', (ip,))
                        row = c.fetchone()
                        if row:
                            c.execute("UPDATE ip_data SET lat = ?, lon = ?, city = ?, country = ?, org = ? WHERE ip = ?",
                                      (geo["lat"], geo["lon"], geo["city"], geo["country"], org, ip))
                            conn.commit()
                except sqlite3.Error as e:
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
                    with sqlite3.connect(DATABASE_PATH) as conn:
                        c = conn.cursor()
                        for ip, e in batch.items():
                            org = e.get("org", "Unknown")
                            threat_level = classify_org_threat(org, org_lists)
                            if threat_level is None:
                                c.execute("SELECT threat_level FROM threat_list WHERE ip = ?", (ip,))
                                r = c.fetchone()
                                threat_level = r[0] if r else "No Threat"
                            c.execute("SELECT incoming_count, outgoing_count FROM ip_data WHERE ip = ?", (ip,))
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
                                             lat = CASE WHEN ?=1 THEN ? ELSE lat END,
                                             lon = CASE WHEN ?=1 THEN ? ELSE lon END,
                                             city = CASE WHEN ?=1 THEN ? ELSE city END,
                                             country = CASE WHEN ?=1 THEN ? ELSE country END,
                                             org = CASE WHEN ?=1 THEN ? ELSE org END,
                                             last_seen = ?, src_port = ?, dst_port = ?, protocol = ?,
                                             incoming_count = ?, outgoing_count = ?, mac = ?,
                                             vendor = CASE WHEN ?=1 THEN ? ELSE vendor END,
                                             hostname = ?, os = ? WHERE ip = ?''',
                                          (geo_ok, e["lat"], geo_ok, e["lon"], geo_ok, e["city"],
                                           geo_ok, e["country"], geo_ok, org,
                                           e["last_seen"], e["src_port"], e["dst_port"], e["protocol"],
                                           inc, out, e["mac"], vendor_ok, e["vendor"],
                                           e["hostname"], e["os"], ip))
                            else:
                                inc, out = e["in_delta"], e["out_delta"]
                                c.execute('''INSERT INTO ip_data (ip, lat, lon, city, country, last_seen, org, src_port, dst_port,
                                             protocol, incoming_count, outgoing_count, mac, vendor, hostname, os)
                                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                          (ip, e["lat"], e["lon"], e["city"], e["country"], e["last_seen"], org,
                                           e["src_port"], e["dst_port"], e["protocol"], inc, out,
                                           e["mac"], e["vendor"], e["hostname"], e["os"]))
                            broadcasts.append((e, inc, out, threat_level))
                        conn.commit()
                except sqlite3.Error as ex:
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
                with sqlite3.connect(DATABASE_PATH) as conn:
                    c = conn.cursor()
                    c.execute('''DELETE FROM ip_data WHERE last_seen < ? AND ip NOT IN (SELECT ip FROM pinned_ips)''',
                              (now - EXPIRATION_SECONDS,))
                    conn.commit()
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
    if len(packet) < 20 or len(packet) > MAX_PACKET_LEN or IP not in packet:
        return None

    # IP-fragmentation evasion: a non-initial fragment (frag offset > 0) carries
    # no L4 header, so it can't be classified by port and would fall through to
    # "return None" below — silently. An attacker can split traffic into tiny
    # fragments that the destination OS reassembles while the monitor records
    # nothing. We deliberately do NOT do stateful reassembly here (the reassembly
    # buffers are themselves a memory-exhaustion vector and belong in the kernel),
    # but we count every fragment so the activity is observable in the stats feed
    # instead of vanishing.
    ip_layer = packet[IP]
    if ip_layer.frag > 0 or (int(ip_layer.flags) & 0x1):  # MF bit set or offset > 0
        stats.incr('fragmented_packets')

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    src_port = None
    dst_port = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        stats.incr('tcp_packets')
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if not showAllUDPPackets.value and (src_port in UDP_FILTER_PORTS or dst_port in UDP_FILTER_PORTS):
            return None
        stats.incr('udp_packets')
    elif ICMP in packet and packet[ICMP].type == 8:
        protocol = "ICMP"
        stats.incr('icmp_packets')
    else:
        return None

    src_mac = None
    dst_mac = None
    src_vendor = "Unknown"
    dst_vendor = "Unknown"
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        # Non-blocking: only consult the local cache here so packet capture is
        # never stalled by an HTTP vendor lookup. Misses stay "Unknown" and are
        # resolved asynchronously by the background enrichment worker.
        if lookup_private_macs or not is_private_ip(ip_src):
            src_vendor = get_mac_vendor_cached(src_mac) or "Unknown"
        if lookup_private_macs or not is_private_ip(ip_dst):
            dst_vendor = get_mac_vendor_cached(dst_mac) or "Unknown"

    stats.incr('total_bytes', len(packet))
    return {
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "ttl": packet[IP].ttl,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
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

def send_all_ips_to_client(sid=None):
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute('''SELECT ip, lat, lon, city, country, org, last_seen, src_port, dst_port, protocol, 
                             incoming_count, outgoing_count, mac, vendor, hostname, os, 
                             (SELECT packet_count FROM pinned_ips WHERE pinned_ips.ip = ip_data.ip) as packet_count
                             FROM ip_data WHERE last_seen > ?''', (time.time() - EXPIRATION_SECONDS,))
                for row in c.fetchall():
                    ip, lat, lon, city, country, org, last_seen, src_port, dst_port, protocol, incoming_count, outgoing_count, mac, vendor, hostname, os, packet_count = row
                    display_hostname = ip if is_private_ip(ip) else hostname
                    message = {
                        "ip": ip,
                        "lat": lat,
                        "lon": lon,
                        "city": city,
                        "country": country,
                        "region": get_geo_data(ip).get("region", ""),
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
                    }
                    if sid:
                        socketio.emit('ip_update', message, to=sid)
                    else:
                        socketio.emit('ip_update', message)
        except sqlite3.Error as e:
            logger.error(f"Error sending all IPs: {e}")

def send_pinned_ips_to_client(sid):
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT ip, packet_count FROM pinned_ips")
                pinned_ips = {row[0]: {'isPinned': True, 'packet_count': row[1]} for row in c.fetchall()}
                socketio.emit('pinned_ips_update', pinned_ips, to=sid)
        except sqlite3.Error as e:
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
                        with locked(db_lock):
                            with sqlite3.connect(DATABASE_PATH) as conn:
                                c = conn.cursor()
                                c.execute("SELECT ip FROM pinned_ips WHERE ip = ?", (ip,))
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
    settings = load_settings()
    is_internal_search_active = manager.Value('b', settings.get('is_internal_search_active', True))
    showAllUDPPackets = manager.Value('b', settings.get('show_all_udp_packets', True))
    packet_queue = PacketQueue()
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
                with sqlite3.connect(DATABASE_PATH) as conn:
                    c = conn.cursor()
                    c.execute("UPDATE ip_data SET incoming_count = 0, outgoing_count = 0 WHERE ip = ?", (ip,))
                    c.execute("UPDATE pinned_ips SET packet_count = 0 WHERE ip = ?", (ip,))
                    conn.commit()
            logger.info(f"Packet count for IP {ip} reset")
            socketio.emit('packet_count_reset', {'ip': ip})
        except Exception as e:
            logger.error(f"Error resetting packet count for IP {ip}: {e}")

    try:
        host = os.environ.get('APP_HOST', '127.0.0.1')
        port = int(os.environ.get('APP_PORT', '8000'))
        socketio.run(app, host=host, port=port, debug=False)
    except KeyboardInterrupt:
        logger.info("Program terminated")
