import sqlite3
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, Ether
import requests
import ipaddress
import ctypes
import sys
import socket
from zeroconf import ServiceBrowser, Zeroconf
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from uuid import uuid4
import logging
from multiprocessing import Process, Manager, Queue
from queue import Empty
from multiprocessing.queues import Full
import os
import json
from contextlib import contextmanager

# Logging Setup
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
db_lock = threading.Lock()
pinned_ips_cache = {}

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

def get_mac_vendor(mac):
    if not mac:
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
    except Exception as e:
        logger.error(f"Error adding to queue: {e}")
    return None

def get_mac_vendor(mac):
    if not mac:
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

def get_mac_vendor_with_cache(mac):
    return get_mac_vendor(mac)

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

# Flask App und SocketIO
app = Flask(__name__)
app.config['SECRET_KEY'] = str(uuid4())
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
                    ping_timeout=SOCKETIO_PING_TIMEOUT, ping_interval=SOCKETIO_PING_INTERVAL)

@app.route('/trusted_organisations')
def get_trusted_organisations():
    try:
        with open(TRUSTED_ORGS_PATH, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error loading trusted_organisations.json: {e}")
        return jsonify({"trusted_organisations": [], "suspicious_organisations": [], "dangerous_organisations": []}), 500

# mDNS Listener
class MDNSListener:
    def __init__(self):
        self.devices = {}

    def remove_service(self, zeroconf, type, name):
        logger.info(f"mDNS service removed: {name}")

    def add_service(self, zeroconf, type, name):
        try:
            info = zeroconf.get_service_info(type, name)
            if info and info.addresses:
                ip = socket.inet_ntoa(info.addresses[0])
                hostname = name.split('.')[0]
                self.devices[ip] = hostname
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

def is_admin():
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
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
        "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "firehol_level3": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
        "anonymous_proxies": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxy_ips.netset",
        "malicious_web_clients": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malicious_web_clients.netset",
        "30_day_greylist": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/30d.ipset",
        "24_hour blacklist": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/24h.ipset",
        "web_server_threats": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/web_server.netset"
    }

    batch_size = 1000
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM threat_list")
                for source, url in threat_sources.items():
                    try:
                        response = requests.get(url, timeout=10)
                        if response.status_code == 200:
                            ips = [ip for ip in response.text.splitlines() if ip and not ip.startswith("#")]
                            for i in range(0, len(ips), batch_size):
                                batch = [(ip, source, url) for ip in ips[i:i + batch_size]]
                                c.executemany("INSERT OR IGNORE INTO threat_list (ip, threat_level, source) VALUES (?, ?, ?)", batch)
                            logger.info(f"Threat list updated: {source}")
                        conn.commit()
                    except Exception as e:
                        logger.error(f"Error fetching threat list {source}: {e}")
        except sqlite3.Error as e:
            logger.error(f"Error updating threat list: {e}")

# Start the thread
threading.Thread(target=schedule_threat_list_updates, daemon=True).start()

@socketio.on('set_local_network')
def handle_set_local_network(data):
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

def get_geo_data(ip, my_geo_data=None):
    global last_api_call
    now = time.time()
    with cache_lock:
        if ip in geo_cache and now - geo_cache[ip]["timestamp"] < CACHE_TIMEOUT:
            return geo_cache[ip]["data"]

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
            logger.warning(f"Fehler bei ip-api für {ip}: {e}")
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
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
            logger.warning(f"Fehler bei ipinfo für {ip}: {e}")
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

def get_my_public_ip_coords():
    try:
        response = requests.get("http://api.ipify.org", timeout=2)
        public_ip = response.text
        geo_data = get_geo_data(public_ip)
        return [geo_data["lat"], geo_data["lon"]], geo_data, public_ip
    except Exception as e:
        logger.warning(f"Fehler bei api.ipify: {e}")
        try:
            response = requests.get("https://ipinfo.io/json", timeout=2)
            data = response.json()
            public_ip = data.get("ip")
            geo_data = get_geo_data(public_ip)
            return [geo_data["lat"], geo_data["lon"]], geo_data, public_ip
        except Exception as e:
            logger.error(f"Fehler bei ipinfo: {e}")
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
        known_ips.add(ip)
    geo = get_geo_data(ip, my_geo_data)
    now = time.time()
    os_guess = estimate_os(ttl)
    conn_key = tuple(sorted([src_ip, dst_ip]) + [src_port, dst_port, protocol]) if src_ip and dst_ip else None
    if protocol == "TCP" and conn_key:
        with cache_lock:
            if conn_key not in tcp_connections:
                tcp_connections[conn_key] = {"packet_count": 0, "last_seen": now, "direction": direction}
            tcp_connections[conn_key]["packet_count"] += 1
            tcp_connections[conn_key]["last_seen"] = now

    try:
        with open(TRUSTED_ORGS_PATH, 'r') as f:
            org_data = json.load(f)
            trusted_orgs = org_data.get("trusted_organisations", [])
            suspicious_orgs = org_data.get("suspicious_organisations", [])
            dangerous_orgs = org_data.get("dangerous_organisations", [])
    except Exception as e:
        logger.error(f"Error loading trusted_organisations.json: {e}")
        trusted_orgs = []
        suspicious_orgs = []
        dangerous_orgs = []

    org = geo.get("org", "Unknown")
    if org in dangerous_orgs:
        threat_level = "High"
    elif org in suspicious_orgs:
        threat_level = "Medium"
    elif org in trusted_orgs:
        threat_level = "No Threat"
    else:
        with locked(db_lock):
            try:
                with sqlite3.connect(DATABASE_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT threat_level FROM threat_list WHERE ip = ?", (ip,))
                    threat = c.fetchone()
                    threat_level = threat[0] if threat else "No Threat"
            except sqlite3.Error as e:
                logger.error(f"Fehler beim Abrufen des Bedrohungslevels für IP {ip}: {e}")
                threat_level = "No Threat"

    valid_threat_levels = ["High", "Medium", "Low", "No Threat"]
    if threat_level not in valid_threat_levels:
        logger.warning(f"Ungültiger Threat Level für IP {ip}: {threat_level}. Setze auf 'Keine Bedrohung'.")
        threat_level = "No Threat"

    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT incoming_count, outgoing_count FROM ip_data WHERE ip = ?", (ip,))
                existing = c.fetchone()
                if existing:
                    incoming_count, outgoing_count = existing
                    if not is_private_ip(ip):
                        incoming_count += 1 if direction == "incoming" else 0
                        outgoing_count += 1 if direction == "outgoing" else 0
                    c.execute('''UPDATE ip_data SET lat = ?, lon = ?, city = ?, country = ?, last_seen = ?, org = ?, 
                                 src_port = ?, dst_port = ?, protocol = ?, incoming_count = ?, outgoing_count = ?, mac = ?, 
                                 vendor = ?, hostname = ?, os = ? WHERE ip = ?''',
                              (geo["lat"], geo["lon"], geo["city"], geo["country"], now, org, src_port, dst_port, protocol,
                               incoming_count, outgoing_count, mac, vendor, hostname, os_guess, ip))
                else:
                    incoming_count = 1 if direction == "incoming" else 0
                    outgoing_count = 1 if direction == "outgoing" else 0
                    c.execute('''INSERT INTO ip_data (ip, lat, lon, city, country, last_seen, org, src_port, dst_port, protocol, 
                                 incoming_count, outgoing_count, mac, vendor, hostname, os)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                              (ip, geo["lat"], geo["lon"], geo["city"], geo["country"], now, org, src_port, dst_port, protocol,
                               incoming_count, outgoing_count, mac, vendor, hostname, os_guess))
                conn.commit()
                send_ip_to_clients(geo["ip"], geo["lat"], geo["lon"], geo["city"], geo["country"], geo["region"], org, now,
                                   protocol, src_port, dst_port, mac, vendor, incoming_count, outgoing_count, 0, hostname, os_guess, threat_level)
        except sqlite3.Error as e:
            logger.error(f"Fehler beim Aktualisieren von IP {ip}: {e}")

def send_network_stats(stats):
    while True:
        try:
            socketio.emit('network_stats', {
                'tcp_packets': stats['tcp_packets'],
                'udp_packets': stats['udp_packets'],
                'icmp_packets': stats['icmp_packets'],
                'total_bytes': stats['total_bytes'],
                'active_connections': stats['active_connections']
            })
            if active_clients:
                socketio.emit('heartbeat', {'timestamp': time.time(), 'active_clients': len(active_clients)})
            time.sleep(5)
        except Exception as e:
            logger.error(f"Fehler beim Senden von Netzwerkstatistiken: {e}")
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
                for ip in list(geo_cache.keys()):
                    if now - geo_cache[ip]["timestamp"] > CACHE_TIMEOUT:
                        del geo_cache[ip]
                for conn_key in list(tcp_connections.keys()):
                    if now - tcp_connections[conn_key]["last_seen"] > EXPIRATION_SECONDS:
                        del tcp_connections[conn_key]
                stats['active_connections'] = len(tcp_connections)
            time.sleep(10)
        except Exception as e:
            logger.error(f"Fehler bei der Bereinigung: {e}")
            time.sleep(10)

def external_packet_callback(packet, my_geo_data, my_local_ip, my_public_ip, queue, stats, mdns_listener, showAllUDPPackets):
    logger.debug(f"Packet captured: {packet.summary()}")
    if len(packet) < 20 or len(packet) > 1500:
        return
    if IP not in packet:
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    ttl = packet[IP].ttl
    protocol = "Unknown"
    src_port = None
    dst_port = None
    src_mac = None
    dst_mac = None
    src_vendor = "Unknown"
    dst_vendor = "Unknown"
    packet_size = len(packet)

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        src_vendor = get_mac_vendor_with_cache(src_mac) if not is_private_ip(ip_src) else "Unknown"
        dst_vendor = get_mac_vendor_with_cache(dst_mac) if not is_private_ip(ip_dst) else "Unknown"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        stats['tcp_packets'] += 1
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if not showAllUDPPackets.value and (src_port in [137, 138, 1900, 5353] or dst_port in [137, 138, 1900, 5353]):
            return
        stats['udp_packets'] += 1
    elif ICMP in packet and packet[ICMP].type == 8:
        protocol = "ICMP"
        stats['icmp_packets'] += 1
    else:
        return

    stats['total_bytes'] += packet_size
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
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_vendor": src_vendor,
        "dst_vendor": dst_vendor,
        "direction": direction,
        "ttl": ttl,
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
    if len(packet) < 20 or len(packet) > 1500:
        return
    if not is_internal_search_active.value:
        return
    if IP not in packet:
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    ttl = packet[IP].ttl
    protocol = "Unknown"
    src_port = None
    dst_port = None
    src_mac = None
    dst_mac = None
    src_vendor = "Unknown"
    dst_vendor = "Unknown"
    packet_size = len(packet)

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        src_vendor = get_mac_vendor_with_cache(src_mac)
        dst_vendor = get_mac_vendor_with_cache(dst_mac)

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        stats['tcp_packets'] += 1
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if not showAllUDPPackets.value and (src_port in [137, 138, 1900, 5353] or dst_port in [137, 138, 1900, 5353]):
            return
        stats['udp_packets'] += 1
    elif ICMP in packet and packet[ICMP].type == 8:
        protocol = "ICMP"
        stats['icmp_packets'] += 1
    else:
        return

    stats['total_bytes'] += packet_size

    if ip_src != my_local_ip and ip_src != my_public_ip and is_private_ip(ip_src):
        direction = "incoming" if ip_dst in (my_local_ip, my_public_ip) else "other"
        queue.put({
            "ip": ip_src,
            "direction": direction,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "mac": src_mac,
            "vendor": src_vendor,
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "ttl": ttl,
            "hostname": ip_src
        })
    if ip_dst != my_local_ip and ip_dst != my_public_ip and is_private_ip(ip_dst):
        direction = "outgoing" if ip_src in (my_local_ip, my_public_ip) else "other"
        queue.put({
            "ip": ip_dst,
            "direction": direction,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "mac": dst_mac,
            "vendor": dst_vendor,
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "ttl": ttl,
            "hostname": ip_dst
        })

def send_ip_to_clients(ip, lat, lon, city, country, region, org, last_seen, protocol, src_port, dst_port, mac, vendor, incoming_count, outgoing_count, packet_count=0, hostname="Unknown", os="Unknown", threat_level="No Threat"):
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        logger.warning(f"Ungültige Koordinaten für IP {ip}: lat={lat}, lon={lon}")
        return
    if lat < -90 or lat > 90 or lon < -180 or lon > 180:
        logger.warning(f"Koordinaten außerhalb des gültigen Bereichs für IP {ip}: lat={lat}, lon={lon}")
        return

    valid_threat_levels = ["High", "Medium", "Low", "No Threat"]
    if threat_level not in valid_threat_levels:
        logger.warning(f"Ungültiger Threat Level für IP {ip}: {threat_level}. Setze auf 'Keine Bedrohung'.")
        threat_level = "No Threat"

    if os == "No Threat":
        logger.warning(f"Ungültiges Betriebssystem für IP {ip}: {os}. Setze auf 'Unbekannt'.")
        os = "Unknown"

    message = {
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
    logger.debug(f"Sende IP-Daten an {len(active_clients)} Clients: {ip}, OS: {os}, Threat Level: {threat_level}")
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
            logger.error(f"Fehler beim Senden aller IPs: {e}")

def send_pinned_ips_to_client(sid):
    with locked(db_lock):
        try:
            with sqlite3.connect(DATABASE_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT ip, packet_count FROM pinned_ips")
                pinned_ips = {row[0]: {'isPinned': True, 'packet_count': row[1]} for row in c.fetchall()}
                socketio.emit('pinned_ips_update', pinned_ips, to=sid)
        except sqlite3.Error as e:
            logger.error(f"Fehler beim Senden der gepinnten IPs: {e}")

def internal_scanner_process(my_geo_data, my_local_ip, my_public_ip, queue, is_internal_search_active, stats, mdns_listener, showAllUDPPackets):
    while True:
        try:
            sniff(iface=NETWORK_INTERFACE, prn=lambda pkt: internal_packet_callback(pkt, my_geo_data, my_local_ip, my_public_ip, queue, is_internal_search_active, stats, mdns_listener, showAllUDPPackets),
                  filter="ip or icmp", store=0, timeout=SNIFF_TIMEOUT)
        except Exception as e:
            logger.error(f"Fehler im internen Scanner: {e}")
            time.sleep(5)

def process_packets(queue, my_geo_data, my_local_ip, my_public_ip, is_internal_search_active, mdns_listener):
    while True:
        try:
            priority, packet_data = queue.get(timeout=0.1)
            logger.debug(f"Dequeued packet: {packet_data}")
            try:
                if 'ip' in packet_data:
                    ip = packet_data["ip"]
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
                logger.error(f"Fehler beim Verarbeiten von Paket: {e}")
        except Empty:
            continue
        except Exception as e:
            logger.error(f"Fehler in process_packets: {e}")
            time.sleep(0.1)

def load_backend_config():
    """Lädt die Backend-Konfigurationsdaten aus der JSON-Datei."""
    try:
        with open(BACKEND_CONF_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Fehler beim Laden der Backend-Konfigurationsdatei: {e}")
        return {}

@app.route('/')
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
            logger.error("Dieses Skript benötigt Administratorrechte.")
        else:
            logger.error("Dieses Skript benötigt Root-Rechte (sudo).")
        sys.exit(1)
    validate_interface()
    init_db()
    threading.Thread(target=cleanup_expired_ips, args=(stats,), daemon=True).start()
    threading.Thread(target=send_network_stats, args=(stats,), daemon=True).start()
    threading.Thread(target=process_packets, args=(queue, my_geo_data, my_local_ip, my_public_ip, is_internal_search_active, mdns_listener), daemon=True).start()
    while True:
        try:
            sniff(iface=NETWORK_INTERFACE, prn=lambda pkt: external_packet_callback(pkt, my_geo_data, my_local_ip, my_public_ip, queue, stats, mdns_listener, showAllUDPPackets),
                  filter="ip or icmp", store=0, timeout=SNIFF_TIMEOUT)
        except Exception as e:
            logger.error(f"Fehler beim Sniffing: {e}")
            time.sleep(5)

def cleanup(internal_process, zeroconf):
    logger.info("Beende Prozesse...")
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
    stats = manager.dict({
        'tcp_packets': 0,
        'udp_packets': 0,
        'icmp_packets': 0,
        'total_bytes': 0,
        'active_connections': 0
    })
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
            sid = request.sid
            active_clients.add(sid)
            settings = load_settings()
            socketio.emit('settings_update', settings, to=sid)
            send_all_ips_to_client(sid)
            send_pinned_ips_to_client(sid)
            logger.info(f"Client verbunden, SID: {sid}, Aktive Clients: {len(active_clients)}")
        except Exception as e:
            logger.error(f"Fehler beim Client-Connect: {e}")

    @socketio.on('disconnect')
    def handle_disconnect():
        try:
            sid = request.sid
            active_clients.discard(sid)
            logger.info(f"Client getrennt, SID: {sid}, Aktive Clients: {len(active_clients)}")
        except Exception as e:
            logger.error(f"Fehler bei Client-Trennung: {e}")

    @socketio.on('request_initial_data')
    def handle_request_initial_data():
        try:
            sid = request.sid
            settings = load_settings()
            socketio.emit('settings_update', settings, to=sid)
            send_all_ips_to_client(sid)
            send_pinned_ips_to_client(sid)
        except Exception as e:
            logger.error(f"Fehler beim Senden initialer Daten: {e}")

    @socketio.on('set_internal_search')
    def handle_set_internal_search(data):
        try:
            is_active = data.get('isInternalSearchActive', False)
            if not isinstance(is_active, bool):
                logger.error(f"Ungültiger Wert für isInternalSearchActive: {is_active}")
                return
            is_internal_search_active.value = is_active
            save_setting('is_internal_search_active', is_active)
            socketio.emit('settings_update', {'is_internal_search_active': is_active})
            logger.info(f"Interne Suche {'aktiviert' if is_active else 'deaktiviert'}")
        except Exception as e:
            logger.error(f"Fehler bei set_internal_search: {e}")

    @socketio.on('set_udp_filter')
    def handle_set_udp_filter(data):
        try:
            show_all_udp = data.get('showAllUDPPackets', False)
            if not isinstance(show_all_udp, bool):
                logger.error(f"Ungültiger Wert für showAllUDPPackets: {show_all_udp}")
                return
            showAllUDPPackets.value = show_all_udp
            save_setting('show_all_udp_packets', show_all_udp)
            socketio.emit('settings_update', {'show_all_udp_packets': show_all_udp})
            logger.info(f"UDP-Filter {'alle Pakete' if show_all_udp else 'gefiltert'}")
        except Exception as e:
            logger.error(f"Fehler bei set_udp_filter: {e}")

    @socketio.on('pin_ip')
    def handle_pin_ip(data):
        try:
            ip = data.get('ip')
            is_pinned = data.get('isPinned', False)
            if not ip or not isinstance(is_pinned, bool):
                logger.error(f"Ungültige Daten in pin_ip: ip={ip}, isPinned={is_pinned}")
                return
            update_pinned_ips(ip, is_pinned)
            socketio.emit('ip_pinned_update', {'ip': ip, 'isPinned': is_pinned})
            logger.info(f"IP {ip} wurde {'gepinnt' if is_pinned else 'entpinnt'}")
        except Exception as e:
            logger.error(f"Fehler beim Pinnen/Entpinnen von IP {ip}: {e}")

    @socketio.on('reset_packet_count')
    def handle_reset_packet_count(data):
        try:
            ip = data.get('ip')
            if not ip:
                logger.error("IP-Adresse fehlt in reset_packet_count")
                return
            with locked(db_lock):
                with sqlite3.connect(DATABASE_PATH) as conn:
                    c = conn.cursor()
                    c.execute("UPDATE ip_data SET incoming_count = 0, outgoing_count = 0 WHERE ip = ?", (ip,))
                    c.execute("UPDATE pinned_ips SET packet_count = 0 WHERE ip = ?", (ip,))
                    conn.commit()
            logger.info(f"Paketanzahl für IP {ip} zurückgesetzt")
            socketio.emit('packet_count_reset', {'ip': ip})
        except Exception as e:
            logger.error(f"Fehler beim Zurücksetzen der Paketanzahl für IP {ip}: {e}")

    try:
        socketio.run(app, host='0.0.0.0', port=8000, debug=False)
    except KeyboardInterrupt:
        logger.info("Programm beendet")