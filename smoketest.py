#!/usr/bin/env python3
"""
ConnectSpoofer – Full Smoke Test
================================

Testet JEDE Funktion von app.py (und select_interface.py) ohne echten
Netzwerk-Traffic und ohne Root. Strategie:

  * Vor dem Import wird in ein temporaeres Arbeitsverzeichnis gewechselt, damit
    alle "database/"-Schreibzugriffe (Token-Datei, SQLite, secret_key, trusted
    orgs) isoliert in einem TempDir landen und das echte Repo nicht beruehren.
  * Vor dem Import wird `requests.get` durch einen Fake ersetzt, damit weder der
    beim Import gestartete Threat-List-Thread noch irgendeine Geo-/MAC-/IP-API
    echten Traffic erzeugt.
  * Scapy-Pakete werden in-memory gebaut (kein Sniffing, kein Root noetig).
  * Worker-Endlosschleifen (Enrichment, Stats, Cleanup, Packet-Processing)
    werden als Daemon-Threads kurz angestossen und ihre Seiteneffekte geprueft.

Aufruf:  python smoketest.py   (Exit-Code 0 = alles gruen)
"""

import os
import sys
import time
import json
import shutil
import tempfile
import threading
import types
import traceback
from contextlib import contextmanager
from urllib.parse import urlsplit

# --------------------------------------------------------------------------- #
#  0)  Umgebung praeparieren  –  MUSS vor `import app` passieren
# --------------------------------------------------------------------------- #
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = tempfile.mkdtemp(prefix="connectspoofer_smoke_")

# Projektverzeichnis fuer den Import sicherstellen, dann ins TempDir wechseln.
sys.path.insert(0, PROJECT_DIR)
os.chdir(TMP_DIR)

# Damit der Import keine festen Ports / unsicheren Defaults nutzt.
os.environ.setdefault("APP_PORT", "8000")
os.environ.setdefault("MAC_NEGATIVE_TTL", "60")

import requests  # noqa: E402


class FakeResponse:
    """Minimaler requests.Response-Ersatz."""

    def __init__(self, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def _default_fake_get(url, *args, **kwargs):
    """Standard-Fake: simuliert keine echten Daten -> der Threat-Thread beim
    Import bricht sauber ab (collected leer) und es gibt keinerlei Netzwerk-IO."""
    raise requests.RequestException("network disabled in smoke test")


# Pre-Import-Patch: ab jetzt geht KEIN requests.get mehr raus.
requests.get = _default_fake_get

# Jetzt erst die App importieren (startet Threat-Thread -> nutzt Fake -> no-op).
import app  # noqa: E402

# Logspam des DEBUG-Loggings daempfen, damit die Testausgabe lesbar bleibt.
import logging  # noqa: E402
logging.getLogger().setLevel(logging.ERROR)

# Pfade der App auf das TempDir festnageln (sie sind relativ, also schon im
# TempDir, aber wir stellen sicher dass die DB-Verzeichnisse existieren).
os.makedirs(app.DATABASE_DIR, exist_ok=True)


# --------------------------------------------------------------------------- #
#  Mini-Testharness
# --------------------------------------------------------------------------- #
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


_RESULTS = []          # (funcname, ok, detail)
_COVERED = set()       # funktionsnamen die getestet wurden


def check(funcname):
    """Dekorator: registriert einen Test fuer eine konkrete App-Funktion."""
    def deco(fn):
        fn._covers = funcname
        return fn
    return deco


def run_test(fn):
    name = getattr(fn, "_covers", fn.__name__)
    try:
        fn()
        _RESULTS.append((name, True, ""))
        _COVERED.add(name)
        print(f"  {Colors.GREEN}PASS{Colors.END}  {name}")
    except Exception as e:
        detail = "".join(traceback.format_exception_only(type(e), e)).strip()
        _RESULTS.append((name, False, detail))
        _COVERED.add(name)
        print(f"  {Colors.RED}FAIL{Colors.END}  {name}  ->  {detail}")


@contextmanager
def patched(obj, attr, value):
    old = getattr(obj, attr)
    setattr(obj, attr, value)
    try:
        yield old
    finally:
        setattr(obj, attr, old)


class EmitRecorder:
    """Faengt socketio.emit-Aufrufe ab."""

    def __init__(self):
        self.calls = []

    def __call__(self, event, *args, **kwargs):
        self.calls.append((event, args, kwargs))

    def events(self):
        return [c[0] for c in self.calls]


def assert_true(cond, msg="assertion failed"):
    if not cond:
        raise AssertionError(msg)


def assert_eq(a, b, msg=None):
    if a != b:
        raise AssertionError(msg or f"{a!r} != {b!r}")


# Praktische Fake-Daten ------------------------------------------------------ #
FAKE_GEO = {
    "ip": "8.8.8.8", "lat": 1.23, "lon": 4.56, "city": "Testville",
    "country": "TC", "region": "TR", "org": "Test Org LLC",
}


def _url_host(url):
    """Lowercased hostname of a URL ('' if it can't be parsed)."""
    return (urlsplit(url).hostname or "").lower()


def routing_fake_get(url, *args, **kwargs):
    """Fake der je nach Ziel-Host plausible Antworten liefert (fuer gezielte Tests).

    Vergleicht exakt den Hostnamen (nicht per Substring), damit eine Test-URL
    nicht versehentlich ueber einen Pfad-/Query-Treffer geroutet wird.
    """
    host = _url_host(url)
    if host == "api.ipify.org":
        return FakeResponse(200, text="8.8.8.8")
    if host == "ipinfo.io":
        return FakeResponse(200, payload={
            "ip": "8.8.8.8", "loc": "1.23,4.56", "city": "Testville",
            "country": "TC", "region": "TR", "org": "Test Org LLC",
        })
    if host == "ip-api.com":
        return FakeResponse(200, payload={
            "status": "success", "lat": 1.23, "lon": 4.56, "city": "Testville",
            "country": "TC", "regionName": "TR", "org": "Test Org LLC",
        })
    if host == "api.macvendors.com":
        return FakeResponse(200, text="Test Vendor Inc")
    if host == "maclookup.app":
        return FakeResponse(200, payload={"company": "Test Vendor Inc"})
    if host == "raw.githubusercontent.com":
        return FakeResponse(200, text="1.2.3.4\n5.6.7.8\n# comment\n9.9.9.9")
    return FakeResponse(404, text="")


# --------------------------------------------------------------------------- #
#  Scapy-Paket-Helfer
# --------------------------------------------------------------------------- #
from scapy.all import Ether, IP, TCP, UDP, ICMP  # noqa: E402


def pkt_tcp(src, dst, sport=12345, dport=443, ttl=64):
    return Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
        IP(src=src, dst=dst, ttl=ttl) / TCP(sport=sport, dport=dport)


def pkt_udp(src, dst, sport=5000, dport=5001, ttl=64):
    return Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
        IP(src=src, dst=dst, ttl=ttl) / UDP(sport=sport, dport=dport)


def pkt_icmp(src, dst, ttl=64):
    return Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
        IP(src=src, dst=dst, ttl=ttl) / ICMP(type=8)


FAKE_STATS = None  # wird in setup gefuellt


# --------------------------------------------------------------------------- #
#  Globales Setup (DB anlegen)
# --------------------------------------------------------------------------- #
def global_setup():
    global FAKE_STATS
    app.init_db()                      # legt Tabellen + trusted_orgs an
    app.init_trusted_organisations()
    FAKE_STATS = app.SharedStats()


# =========================================================================== #
#  TESTS
# =========================================================================== #

# ---- Sicherheit / Auth-Helfer --------------------------------------------- #
@check("is_safe_redirect_target")
def t_is_safe_redirect_target():
    assert_true(app.is_safe_redirect_target("/index"))
    assert_true(not app.is_safe_redirect_target("http://evil.com"))
    assert_true(not app.is_safe_redirect_target("//evil.com"))
    assert_true(not app.is_safe_redirect_target("/\\evil"))
    assert_true(not app.is_safe_redirect_target(""))
    assert_true(not app.is_safe_redirect_target("/a\nb"))


@check("login_register_failure / login_is_locked / login_register_success")
def t_login_bruteforce():
    ip = "203.0.113.7"
    app.login_register_success(ip)  # clean slate
    assert_eq(app.login_is_locked(ip), 0)
    for _ in range(app.LOGIN_MAX_ATTEMPTS):
        app.login_register_failure(ip)
    assert_true(app.login_is_locked(ip) > 0, "IP sollte gesperrt sein")
    app.login_register_success(ip)
    assert_eq(app.login_is_locked(ip), 0, "Erfolg sollte Sperre loeschen")


@check("load_network_interface")
def t_load_network_interface():
    # Ohne Config-Datei -> None
    res = app.load_network_interface()
    assert_true(res is None or isinstance(res, str))
    # Mit Config-Datei -> Wert
    os.makedirs(app.DATABASE_DIR, exist_ok=True)
    with open(app.BACKEND_CONF_PATH, "w") as f:
        json.dump({"network_interface": "eth-test0"}, f)
    assert_eq(app.load_network_interface(), "eth-test0")
    os.remove(app.BACKEND_CONF_PATH)


@check("socket_rate_limited / socket_rate_prune")
def t_socket_rate_limit():
    with app.app.test_request_context(environ_base={"REMOTE_ADDR": "198.51.100.5"}):
        results = [app.socket_rate_limited("unit_evt") for _ in range(app.SOCKET_RATE_LIMIT + 2)]
    assert_true(not results[0], "erster Aufruf darf nicht limitiert sein")
    assert_true(results[-1], "nach Limit muss True kommen")
    app.socket_rate_prune()  # darf nicht crashen


# ---- Datenstrukturen ------------------------------------------------------- #
@check("PacketQueue.put / get / empty")
def t_packet_queue():
    q = app.PacketQueue()
    assert_true(q.empty())
    q.put({"ip_src": "8.8.8.8", "ip_dst": "1.1.1.1", "protocol": "TCP"})
    # multiprocessing.Queue nutzt einen Feeder-Thread -> empty() ist direkt nach
    # put() unzuverlaessig; daher zuverlaessig per get(timeout) abholen.
    prio, item = q.get(timeout=2)
    assert_eq(item["ip_src"], "8.8.8.8")
    assert_true(prio in (1, 5))


@check("SharedStats.incr / set / snapshot")
def t_shared_stats():
    s = app.SharedStats()
    s.incr("tcp_packets")
    s.incr("total_bytes", 100)
    s.set("active_connections", 3)
    snap = s.snapshot()
    assert_eq(snap["tcp_packets"], 1)
    assert_eq(snap["total_bytes"], 100)
    assert_eq(snap["active_connections"], 3)


# ---- MAC / Vendor ---------------------------------------------------------- #
@check("is_valid_mac")
def t_is_valid_mac():
    assert_true(app.is_valid_mac("aa:bb:cc:dd:ee:ff"))
    assert_true(app.is_valid_mac("AA-BB-CC-DD-EE-FF"))
    assert_true(not app.is_valid_mac("not-a-mac"))
    assert_true(not app.is_valid_mac(""))
    assert_true(not app.is_valid_mac("aa:bb:cc:dd:ee"))


@check("get_mac_vendor (mit API-Fake + SSRF-Guard)")
def t_get_mac_vendor():
    with patched(requests, "get", routing_fake_get):
        v = app.get_mac_vendor("aa:bb:cc:dd:ee:ff")
        assert_eq(v, "Test Vendor Inc")
    # Malformed MAC -> kein Request, "Unknown"
    assert_eq(app.get_mac_vendor("bad mac"), "Unknown")
    # Cache-Hit (jetzt ohne Netzwerk)
    assert_eq(app.get_mac_vendor("aa:bb:cc:dd:ee:ff"), "Test Vendor Inc")


@check("get_mac_vendor_cached")
def t_get_mac_vendor_cached():
    # aus vorigem Test im mac_cache -> Treffer
    assert_eq(app.get_mac_vendor_cached("aa:bb:cc:dd:ee:ff"), "Test Vendor Inc")
    assert_true(app.get_mac_vendor_cached("00:00:00:00:00:99") is None)
    assert_true(app.get_mac_vendor_cached(None) is None)


@check("queue_mac_enrichment (dedupe + negative cache)")
def t_queue_mac_enrichment():
    app.mac_enrich_inflight.clear()
    while not app.mac_enrich_queue.empty():
        app.mac_enrich_queue.get_nowait()
    app.queue_mac_enrichment("11:22:33:44:55:66")
    assert_true("11:22:33:44:55:66" in app.mac_enrich_inflight)
    # ungueltige MAC wird ignoriert
    app.queue_mac_enrichment("xx")
    assert_true("xx" not in app.mac_enrich_inflight)
    app.mac_enrich_inflight.clear()


@check("mac_enrichment_worker (1 Iteration)")
def t_mac_enrichment_worker():
    rec = EmitRecorder()
    app.mac_enrich_inflight.clear()
    with patched(app, "get_mac_vendor", lambda m: "Worker Vendor"), \
            patched(app.socketio, "emit", rec):
        th = threading.Thread(target=app.mac_enrichment_worker, daemon=True)
        th.start()
        app.queue_mac_enrichment("ab:cd:ef:00:11:22")
        deadline = time.time() + 3
        while time.time() < deadline and "mac_vendor_update" not in rec.events():
            time.sleep(0.02)
    assert_true("mac_vendor_update" in rec.events(), "Worker sollte mac_vendor_update emittieren")


# ---- Pinned IPs ------------------------------------------------------------ #
@check("update_pinned_ips / load_pinned_ips")
def t_pinned_ips():
    app.update_pinned_ips("8.8.4.4", True)
    app.load_pinned_ips()
    assert_true("8.8.4.4" in app.pinned_ips_cache)
    app.update_pinned_ips("8.8.4.4", False)
    app.load_pinned_ips()
    assert_true("8.8.4.4" not in app.pinned_ips_cache)


# ---- Crypto / Keys --------------------------------------------------------- #
@check("load_or_create_secret_key")
def t_secret_key():
    k1 = app.load_or_create_secret_key()
    k2 = app.load_or_create_secret_key()
    assert_true(isinstance(k1, str) and len(k1) > 10)
    assert_eq(k1, k2, "Key muss zwischen Aufrufen stabil sein")


@check("generate_csrf_token")
def t_csrf_token():
    with app.app.test_request_context():
        from flask import session
        tok = app.generate_csrf_token()
        assert_true(isinstance(tok, str) and len(tok) > 10)
        assert_eq(session["_csrf_token"], tok)


# ---- Flask Routes / Middleware -------------------------------------------- #
@check("add_security_headers (after_request)")
def t_security_headers():
    client = app.app.test_client()
    resp = client.get("/login")
    assert_eq(resp.headers.get("X-Content-Type-Options"), "nosniff")
    assert_eq(resp.headers.get("X-Frame-Options"), "DENY")
    assert_true("Content-Security-Policy" in resp.headers)


@check("login route (GET + POST Erfolg/Fehler)")
def t_login_route():
    client = app.app.test_client()
    # GET zeigt Formular
    assert_eq(client.get("/login").status_code, 200)
    # POST mit CSRF + korrektem Token -> Redirect
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf123"
    resp = client.post("/login", data={"_csrf_token": "csrf123",
                                        "token": app.ACCESS_TOKEN})
    assert_eq(resp.status_code, 302, "korrekter Token -> Redirect")
    # POST mit falschem Token
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf123"
    resp = client.post("/login", data={"_csrf_token": "csrf123", "token": "wrong"})
    assert_eq(resp.status_code, 200, "falscher Token -> bleibt auf Login")


@check("csrf_protect (before_request)")
def t_csrf_protect():
    client = app.app.test_client()
    # POST ohne CSRF-Token -> 403
    resp = client.post("/login", data={"token": "x"})
    assert_eq(resp.status_code, 403)


@check("login_required (Schutz unauth -> Redirect)")
def t_login_required():
    client = app.app.test_client()
    resp = client.get("/trusted_organisations")
    assert_eq(resp.status_code, 302, "ohne Login -> Redirect auf /login")


@check("logout route")
def t_logout_route():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    resp = client.get("/logout")
    assert_eq(resp.status_code, 302)


@check("get_trusted_organisations route")
def t_trusted_orgs_route():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    resp = client.get("/trusted_organisations")
    assert_eq(resp.status_code, 200)
    data = resp.get_json()
    assert_true("trusted_organisations" in data)


@check("index route (mit gefaketem Geo)")
def t_index_route():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    fake = ([1.23, 4.56], FAKE_GEO, "8.8.8.8")
    with patched(app, "get_my_public_ip_coords", lambda: fake):
        resp = client.get("/")
    assert_eq(resp.status_code, 200)


# ---- mDNS ------------------------------------------------------------------ #
@check("MDNSListener.add_service / remove_service / update_service")
def t_mdns_listener():
    listener = app.MDNSListener()
    import socket as _socket

    class FakeInfo:
        addresses = [_socket.inet_aton("192.168.1.50")]

    class FakeZC:
        def get_service_info(self, type, name):
            return FakeInfo()

    listener.add_service(FakeZC(), "_http._tcp.local.", "printer._http._tcp.local.")
    assert_eq(listener.devices.get("192.168.1.50"), "printer")
    listener.remove_service(FakeZC(), "t", "n")   # nur Logging
    listener.update_service(FakeZC(), "t", "n")   # no-op


@check("init_trusted_organisations")
def t_init_trusted_orgs():
    if os.path.exists(app.TRUSTED_ORGS_PATH):
        os.remove(app.TRUSTED_ORGS_PATH)
    app.init_trusted_organisations()
    assert_true(os.path.exists(app.TRUSTED_ORGS_PATH))
    with open(app.TRUSTED_ORGS_PATH) as f:
        data = json.load(f)
    assert_true("trusted_organisations" in data)


@check("start_mdns_listener")
def t_start_mdns_listener():
    zc, listener = app.start_mdns_listener()
    # Kann (None, None) sein wenn kein mDNS moeglich – beides ist ok.
    if zc is not None:
        assert_true(isinstance(listener, app.MDNSListener))
        zc.close()


# ---- System / Netzwerk-Helfer --------------------------------------------- #
@check("get_local_ip")
def t_get_local_ip():
    ip = app.get_local_ip()
    assert_true(isinstance(ip, str) and ip.count(".") == 3)


@check("has_net_capabilities")
def t_has_net_caps():
    assert_true(isinstance(app.has_net_capabilities(), bool))


@check("is_admin")
def t_is_admin():
    assert_true(isinstance(app.is_admin(), bool))


@check("auto_detect_interface")
def t_auto_detect_interface():
    res = app.auto_detect_interface()
    assert_true(res is None or isinstance(res, str))


@check("validate_interface")
def t_validate_interface():
    # darf nicht sys.exit ausloesen, solange Interfaces existieren (lo etc.)
    app.validate_interface()
    assert_true(app.NETWORK_INTERFACE is not None)


@check("locked (contextmanager)")
def t_locked():
    lk = threading.Lock()
    with app.locked(lk):
        assert_true(lk.locked())
    assert_true(not lk.locked())


# ---- Datenbank / Settings -------------------------------------------------- #
@check("init_db")
def t_init_db():
    app.init_db()
    tables = app.db.list_tables()
    for t in ("ip_data", "pinned_ips", "settings", "mac_cache", "threat_list"):
        assert_true(t in tables, f"Tabelle {t} fehlt")


@check("save_setting / load_settings")
def t_settings():
    app.save_setting("show_tcp_only", True)
    s = app.load_settings()
    assert_eq(s["show_tcp_only"], True)
    app.save_setting("show_tcp_only", False)
    s = app.load_settings()
    assert_eq(s["show_tcp_only"], False)


@check("update_threat_list (mit gefaketen Feeds)")
def t_update_threat_list():
    with patched(requests, "get", routing_fake_get):
        app.update_threat_list()
    with app.db.get_connection() as conn:
        n = conn.execute("SELECT COUNT(*) FROM threat_list").fetchone()[0]
    assert_true(n > 0, "threat_list sollte befuellt sein")


@check("schedule_threat_list_updates (1 Zyklus, dann Abbruch)")
def t_schedule_threat_list():
    calls = {"n": 0}

    def fake_update():
        calls["n"] += 1

    def stop_sleep(_):
        raise KeyboardInterrupt  # bricht die Endlosschleife nach 1 Zyklus ab

    with patched(app, "update_threat_list", fake_update), \
            patched(app.time, "sleep", stop_sleep):
        try:
            app.schedule_threat_list_updates()
        except KeyboardInterrupt:
            pass
    assert_eq(calls["n"], 1)


# ---- Socket.IO Handler (modullevel) --------------------------------------- #
def _call_socket_handler(handler, data):
    rec = EmitRecorder()
    with app.app.test_request_context(environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        from flask import session
        session["authenticated"] = True
        with patched(app.socketio, "emit", rec):
            handler(data)
    return rec


@check("handle_set_local_network")
def t_handle_set_local_network():
    rec = _call_socket_handler(app.handle_set_local_network, {"showLocalNetwork": False})
    assert_true("settings_update" in rec.events())
    assert_eq(app.load_settings()["show_local_network"], False)
    _call_socket_handler(app.handle_set_local_network, {"showLocalNetwork": True})


@check("handle_set_external_network")
def t_handle_set_external_network():
    rec = _call_socket_handler(app.handle_set_external_network, {"showExternalNetwork": False})
    assert_true("settings_update" in rec.events())
    assert_eq(app.load_settings()["show_external_network"], False)
    _call_socket_handler(app.handle_set_external_network, {"showExternalNetwork": True})


@check("handle_set_tcp_only")
def t_handle_set_tcp_only():
    rec = _call_socket_handler(app.handle_set_tcp_only, {"showTCPOnly": True})
    assert_true("settings_update" in rec.events())
    assert_eq(app.load_settings()["show_tcp_only"], True)
    _call_socket_handler(app.handle_set_tcp_only, {"showTCPOnly": False})


# ---- IP / Geo-Logik -------------------------------------------------------- #
@check("is_private_ip")
def t_is_private_ip():
    assert_true(app.is_private_ip("192.168.0.1"))
    assert_true(app.is_private_ip("10.0.0.5"))
    assert_true(app.is_private_ip("127.0.0.1"))
    assert_true(not app.is_private_ip("8.8.8.8"))
    assert_true(not app.is_private_ip("garbage"))


@check("estimate_os")
def t_estimate_os():
    assert_eq(app.estimate_os(64), "Linux/Unix")
    assert_eq(app.estimate_os(128), "Windows")
    assert_eq(app.estimate_os(255), "macOS/iOS")
    assert_eq(app.estimate_os(None), "Unknown")


@check("get_geo_data (public via Fake, private, invalid)")
def t_get_geo_data():
    app.geo_cache.clear()
    with patched(requests, "get", routing_fake_get):
        geo = app.get_geo_data("8.8.8.8")
    assert_eq(geo["city"], "Testville")
    # privat
    priv = app.get_geo_data("192.168.1.1")
    assert_eq(priv["org"], "Local Network")
    # ungueltig -> Default
    bad = app.get_geo_data("not-an-ip")
    assert_eq(bad["org"], "Not available")


@check("load_org_lists")
def t_load_org_lists():
    app.init_trusted_organisations()
    trusted, suspicious, dangerous = app.load_org_lists()
    assert_true(isinstance(trusted, list) and "Google LLC" in trusted)
    assert_true("Malware Host" in dangerous)


@check("classify_org_threat")
def t_classify_org_threat():
    lists = (["Good Inc"], ["Meh Inc"], ["Evil Inc"])
    assert_eq(app.classify_org_threat("Evil Inc", lists), "High")
    assert_eq(app.classify_org_threat("Meh Inc", lists), "Medium")
    assert_eq(app.classify_org_threat("Good Inc", lists), "No Threat")
    assert_true(app.classify_org_threat("Random Org", lists) is None,
                "unklassifiziert -> None (faellt auf threat_list zurueck)")


@check("compute_org_threat")
def t_compute_org_threat():
    app.init_trusted_organisations()
    assert_eq(app.compute_org_threat("8.8.8.8", "Malware Host"), "High")
    assert_eq(app.compute_org_threat("8.8.8.8", "Unknown ISP"), "Medium")
    assert_eq(app.compute_org_threat("8.8.8.8", "Google LLC"), "No Threat")


@check("get_geo_data_cached")
def t_get_geo_data_cached():
    app.geo_cache.clear()
    # privat -> sofort Daten
    priv = app.get_geo_data_cached("192.168.5.5")
    assert_eq(priv["org"], "Local Network")
    # uncached public -> None (Hintergrund-Enrichment)
    assert_true(app.get_geo_data_cached("9.9.9.9") is None)


@check("queue_geo_enrichment")
def t_queue_geo_enrichment():
    app.geo_enrich_inflight.clear()
    while not app.geo_enrich_queue.empty():
        app.geo_enrich_queue.get_nowait()
    app.queue_geo_enrichment("9.9.9.9")
    assert_true("9.9.9.9" in app.geo_enrich_inflight)
    app.queue_geo_enrichment(None)  # ignoriert
    app.geo_enrich_inflight.clear()


@check("geo_enrichment_worker (1 Iteration)")
def t_geo_enrichment_worker():
    # Eintrag anlegen, den der Worker aktualisiert
    with app.db.get_connection() as conn:
        conn.execute("INSERT INTO ip_data (device_id, ip, last_seen, incoming_count, outgoing_count) "
                     "VALUES (%s, %s, %s, 0, 0) ON CONFLICT (device_id, ip) DO UPDATE SET "
                     "last_seen = EXCLUDED.last_seen, incoming_count = 0, outgoing_count = 0",
                     (app.LOCAL_DEVICE_ID, "77.77.77.77", time.time()))
        conn.commit()
    rec = EmitRecorder()
    app.geo_enrich_inflight.clear()
    with patched(app, "get_geo_data", lambda ip, mg=None: dict(FAKE_GEO, ip=ip)), \
            patched(app.socketio, "emit", rec):
        th = threading.Thread(target=app.geo_enrichment_worker, args=(FAKE_GEO,), daemon=True)
        th.start()
        app.queue_geo_enrichment("77.77.77.77")
        deadline = time.time() + 3
        while time.time() < deadline and "ip_update" not in rec.events():
            time.sleep(0.02)
    assert_true("ip_update" in rec.events(), "Worker sollte ip_update emittieren")


@check("get_my_public_ip_coords")
def t_get_my_public_ip_coords():
    app.geo_cache.clear()
    with patched(requests, "get", routing_fake_get):
        coords, geo, public_ip = app.get_my_public_ip_coords()
    assert_eq(public_ip, "8.8.8.8")
    assert_true(isinstance(coords, list) and len(coords) == 2)


@check("update_ip (puffert Write in ip_write_buffer)")
def t_update_ip():
    # Neue Architektur: update_ip schreibt NICHT direkt in die DB, sondern
    # puffert (buffer_ip_write); der flush_ip_writes-Thread committet spaeter.
    with app.locked(app.ip_write_buffer_lock):
        app.ip_write_buffer.clear()
    app.geo_cache.clear()
    app.update_ip("44.44.44.44", "incoming", "TCP", 1234, 443,
                  FAKE_GEO, "192.168.1.10", "8.8.8.8",
                  mac="aa:bb:cc:dd:ee:ff", vendor="Test Vendor Inc",
                  src_ip="44.44.44.44", dst_ip="192.168.1.10", ttl=64,
                  hostname="Unknown")
    # Buffer is keyed (device_id, ip); the local capture uses LOCAL_DEVICE_ID.
    key = (app.LOCAL_DEVICE_ID, "44.44.44.44")
    assert_true(key in app.ip_write_buffer, "update_ip sollte Write puffern")
    assert_eq(app.ip_write_buffer[key]["in_delta"], 1)


# ---- Stats / Cleanup Worker ----------------------------------------------- #
@check("send_network_stats (1 Iteration)")
def t_send_network_stats():
    rec = EmitRecorder()
    s = app.SharedStats()
    with app.active_clients_lock:
        app.active_clients.add("sid-test")
    with patched(app.socketio, "emit", rec):
        th = threading.Thread(target=app.send_network_stats, args=(s,), daemon=True)
        th.start()
        deadline = time.time() + 3
        while time.time() < deadline and "network_stats" not in rec.events():
            time.sleep(0.02)
    with app.active_clients_lock:
        app.active_clients.discard("sid-test")
    assert_true("network_stats" in rec.events())


@check("cleanup_expired_ips (1 Iteration)")
def t_cleanup_expired_ips():
    s = app.SharedStats()
    # abgelaufene IP einfuegen
    old = time.time() - app.EXPIRATION_SECONDS - 100
    with app.db.get_connection() as conn:
        conn.execute("INSERT INTO ip_data (device_id, ip, last_seen) VALUES (%s, %s, %s) "
                     "ON CONFLICT (device_id, ip) DO UPDATE SET last_seen = EXCLUDED.last_seen",
                     (app.LOCAL_DEVICE_ID, "66.66.66.66", old))
        conn.commit()
    # alten geo_cache-Eintrag setzen
    with app.cache_lock:
        app.geo_cache["expired-key"] = {"data": {}, "timestamp": old}
    th = threading.Thread(target=app.cleanup_expired_ips, args=(s,), daemon=True)
    th.start()
    deadline = time.time() + 3
    removed = False
    while time.time() < deadline and not removed:
        with app.db.get_connection() as conn:
            row = conn.execute("SELECT 1 FROM ip_data WHERE ip=%s",
                               ("66.66.66.66",)).fetchone()
        removed = row is None
        time.sleep(0.05)
    assert_true(removed, "abgelaufene IP sollte geloescht sein")
    assert_true("expired-key" not in app.geo_cache, "alter geo_cache sollte weg sein")


# ---- Paket-Parsing / Callbacks -------------------------------------------- #
@check("parse_ip_packet (TCP/UDP/ICMP + Groessen-Limit)")
def t_parse_ip_packet():
    udp_flag = types.SimpleNamespace(value=True)
    tcp = app.parse_ip_packet(pkt_tcp("8.8.8.8", "1.1.1.1"), FAKE_STATS, udp_flag)
    assert_eq(tcp["protocol"], "TCP")
    udp = app.parse_ip_packet(pkt_udp("8.8.8.8", "1.1.1.1"), FAKE_STATS, udp_flag)
    assert_eq(udp["protocol"], "UDP")
    icmp = app.parse_ip_packet(pkt_icmp("8.8.8.8", "1.1.1.1"), FAKE_STATS, udp_flag)
    assert_eq(icmp["protocol"], "ICMP")
    # gefilterter UDP-Port wenn showAll=False
    udp_off = types.SimpleNamespace(value=False)
    filtered = app.parse_ip_packet(pkt_udp("8.8.8.8", "1.1.1.1", sport=5353, dport=5353),
                                   FAKE_STATS, udp_off)
    assert_true(filtered is None, "mDNS-UDP sollte gefiltert werden")


@check("external_packet_callback")
def t_external_callback():
    q = app.PacketQueue()
    udp_flag = types.SimpleNamespace(value=True)
    mdns = app.MDNSListener()
    app.external_packet_callback(pkt_tcp("8.8.8.8", "1.1.1.1"),
                                 FAKE_GEO, "192.168.1.10", "203.0.113.1",
                                 q, FAKE_STATS, mdns, udp_flag)
    prio, item = q.get(timeout=2)  # zuverlaessiger als empty()
    assert_eq(item["ip_src"], "8.8.8.8")


@check("internal_packet_callback")
def t_internal_callback():
    q = app.PacketQueue()
    udp_flag = types.SimpleNamespace(value=True)
    active = types.SimpleNamespace(value=True)
    mdns = app.MDNSListener()
    app.internal_packet_callback(pkt_tcp("192.168.1.20", "192.168.1.30"),
                                 FAKE_GEO, "192.168.1.10", "203.0.113.1",
                                 q, active, FAKE_STATS, mdns, udp_flag)
    prio, item = q.get(timeout=2)  # zuverlaessiger als empty()
    assert_true(item.get("ip") in ("192.168.1.20", "192.168.1.30"))


# ---- Buffered Writes ------------------------------------------------------- #
def _buf_data(**over):
    d = {"geo_ip": "5.5.5.5", "lat": 1.0, "lon": 2.0, "city": "C", "country": "CO",
         "region": "R", "org": "Org", "protocol": "TCP", "src_port": 1, "dst_port": 2,
         "mac": "m", "vendor": "V", "hostname": "h", "os": "Linux", "last_seen": time.time()}
    d.update(over)
    return d


@check("buffer_ip_write (Coalescing + Delta-Zaehlung)")
def t_buffer_ip_write():
    with app.locked(app.ip_write_buffer_lock):
        app.ip_write_buffer.clear()
    loc = app.LOCAL_DEVICE_ID
    app.buffer_ip_write("5.5.5.5", "incoming", _buf_data())
    app.buffer_ip_write("5.5.5.5", "incoming", _buf_data())
    assert_eq(app.ip_write_buffer[(loc, "5.5.5.5")]["in_delta"], 2,
              "zwei 'incoming' -> Delta 2 (Coalescing)")
    # private IP zaehlt nicht hoch (Original-Semantik)
    app.buffer_ip_write("192.168.9.9", "incoming", _buf_data())
    assert_eq(app.ip_write_buffer[(loc, "192.168.9.9")]["in_delta"], 0)
    # Same IP from a different device stays a separate buffer entry.
    app.buffer_ip_write("5.5.5.5", "incoming", _buf_data(), device_id="dev2")
    assert_eq(app.ip_write_buffer[("dev2", "5.5.5.5")]["in_delta"], 1,
              "zweites Geraet -> eigener Buffer-Eintrag")


@check("flush_ip_writes (1 Flush -> DB-Insert + ip_update_batch)")
def t_flush_ip_writes():
    with app.locked(app.ip_write_buffer_lock):
        app.ip_write_buffer.clear()
    rec = EmitRecorder()
    app.buffer_ip_write("88.88.88.88", "incoming", _buf_data(geo_ip="88.88.88.88"))
    # Flush-Intervall fuer den Test verkuerzen (wird pro Schleife neu gelesen).
    with patched(app, "IP_WRITE_FLUSH_INTERVAL", 0.2), \
            patched(app.socketio, "emit", rec):
        th = threading.Thread(target=app.flush_ip_writes, daemon=True)
        th.start()
        # Wait on the broadcast, which the flusher emits AFTER committing the row.
        # Polling only the DB row races: the row becomes visible a moment before
        # the emit, so waiting for the event is the reliable completion signal.
        deadline = time.time() + 4
        while time.time() < deadline and "ip_update_batch" not in rec.events():
            time.sleep(0.05)
    with app.db.get_connection() as conn:
        found = conn.execute("SELECT 1 FROM ip_data WHERE ip=%s",
                             ("88.88.88.88",)).fetchone() is not None
    assert_true(found, "flush sollte die IP in die DB schreiben")
    assert_true("ip_update_batch" in rec.events(), "flush sollte ip_update_batch broadcasten")


# ---- Ausgabe an Clients ---------------------------------------------------- #
@check("build_ip_message (gueltig + ungueltige Coords)")
def t_build_ip_message():
    m = app.build_ip_message("8.8.8.8", 1.0, 2.0, "C", "CO", "R", "Org",
                             time.time(), "TCP", 1, 2, "mac", "vendor", 0, 0)
    assert_true(m is not None and m["ip"] == "8.8.8.8")
    bad = app.build_ip_message("8.8.8.8", 999, 999, "C", "CO", "R", "Org",
                               time.time(), "TCP", 1, 2, "m", "v", 0, 0)
    assert_true(bad is None, "Koordinaten ausser Reichweite -> None")


@check("send_ip_to_clients (gueltig + ungueltige Coords)")
def t_send_ip_to_clients():
    rec = EmitRecorder()
    with patched(app.socketio, "emit", rec):
        app.send_ip_to_clients("8.8.8.8", 1.0, 2.0, "C", "CO", "R", "Org",
                               time.time(), "TCP", 1, 2, "mac", "vendor", 0, 0)
        assert_true("ip_update" in rec.events())
        rec.calls.clear()
        # ungueltige Koordinaten -> kein emit
        app.send_ip_to_clients("8.8.8.8", 999, 999, "C", "CO", "R", "Org",
                               time.time(), "TCP", 1, 2, "mac", "vendor", 0, 0)
        assert_true("ip_update" not in rec.events())


@check("send_all_ips_to_client")
def t_send_all_ips():
    with app.db.get_connection() as conn:
        conn.execute("INSERT INTO ip_data "
                     "(device_id, ip, lat, lon, city, country, org, last_seen, protocol, "
                     " incoming_count, outgoing_count) "
                     "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                     "ON CONFLICT (device_id, ip) DO UPDATE SET "
                     "lat=EXCLUDED.lat, lon=EXCLUDED.lon, city=EXCLUDED.city, "
                     "country=EXCLUDED.country, org=EXCLUDED.org, "
                     "last_seen=EXCLUDED.last_seen, protocol=EXCLUDED.protocol, "
                     "incoming_count=EXCLUDED.incoming_count, "
                     "outgoing_count=EXCLUDED.outgoing_count",
                     (app.LOCAL_DEVICE_ID, "55.55.55.55", 1.0, 2.0, "C", "CO", "Org",
                      time.time(), "TCP", 1, 1))
        conn.commit()
    rec = EmitRecorder()
    with patched(app.socketio, "emit", rec), \
            patched(app, "get_geo_data", lambda ip, mg=None: dict(FAKE_GEO, ip=ip)):
        app.send_all_ips_to_client(sid="sid-x")
    # send_all_ips_to_client coalesces the whole table into ONE batched message.
    assert_true("ip_update_batch" in rec.events())


@check("send_pinned_ips_to_client")
def t_send_pinned_ips():
    app.update_pinned_ips("33.33.33.33", True)
    rec = EmitRecorder()
    with patched(app.socketio, "emit", rec):
        app.send_pinned_ips_to_client("sid-x")
    assert_true("pinned_ips_update" in rec.events())
    app.update_pinned_ips("33.33.33.33", False)


# ---- Packet-Processing Worker --------------------------------------------- #
@check("process_packets (Dispatch interner + externer Pakete)")
def t_process_packets():
    q = app.PacketQueue()
    seen = []

    def fake_update_ip(ip, *a, **k):
        seen.append(ip)

    active = types.SimpleNamespace(value=True)
    mdns = app.MDNSListener()
    with patched(app, "update_ip", fake_update_ip):
        th = threading.Thread(
            target=app.process_packets,
            args=(q, FAKE_GEO, "192.168.1.10", "203.0.113.1", active, mdns),
            daemon=True)
        th.start()
        # externes Paket (ip_src/ip_dst Format)
        q.put({
            "ip_src": "8.8.8.8", "ip_dst": "1.1.1.1", "protocol": "TCP",
            "src_port": 1, "dst_port": 2, "src_mac": "m1", "dst_mac": "m2",
            "src_vendor": "Unknown", "dst_vendor": "Unknown",
            "direction": "incoming", "ttl": 64,
            "hostname_src": "Unknown", "hostname_dst": "Unknown",
        })
        deadline = time.time() + 3
        while time.time() < deadline and not seen:
            time.sleep(0.02)
    assert_true(len(seen) > 0, "process_packets sollte update_ip aufrufen")


# ---- Config-Loader / Cleanup ---------------------------------------------- #
@check("load_backend_config")
def t_load_backend_config():
    os.makedirs(app.DATABASE_DIR, exist_ok=True)
    with open(app.BACKEND_CONF_PATH, "w") as f:
        json.dump({"network_interface": "eth0", "x": 1}, f)
    cfg = app.load_backend_config()
    assert_eq(cfg["x"], 1)
    os.remove(app.BACKEND_CONF_PATH)
    # fehlende Datei -> leeres Dict
    assert_eq(app.load_backend_config(), {})


@check("cleanup (Prozess + zeroconf terminieren)")
def t_cleanup():
    calls = {"terminate": 0, "join": 0, "close": 0}

    class FakeProc:
        def terminate(self):
            calls["terminate"] += 1

        def join(self):
            calls["join"] += 1

    class FakeZC:
        def close(self):
            calls["close"] += 1

    app.cleanup(FakeProc(), FakeZC())
    assert_eq(calls["terminate"], 1)
    assert_eq(calls["join"], 1)
    assert_eq(calls["close"], 1)


# ---- Endlos-/Root-Funktionen: nur Erreichbarkeit (Smoke) ------------------ #
@check("start_sniffing (vorhanden, Root/Sniff – nicht live ausgefuehrt)")
def t_start_sniffing_present():
    assert_true(callable(app.start_sniffing))


@check("internal_scanner_process (vorhanden, Root/Sniff – nicht live)")
def t_internal_scanner_present():
    assert_true(callable(app.internal_scanner_process))


# --------------------------------------------------------------------------- #
#  select_interface.py
# --------------------------------------------------------------------------- #
@check("select_interface.get_friendly_interface_name / get_interface_ip")
def t_select_interface_helpers():
    import select_interface as si
    from scapy.all import get_if_list
    ifaces = get_if_list()
    if ifaces:
        name = si.get_friendly_interface_name(ifaces[0])
        assert_true(isinstance(name, str))
        ip = si.get_interface_ip(ifaces[0])
        assert_true(ip is None or isinstance(ip, str))
    else:
        # keine Interfaces -> Funktionen trotzdem aufrufbar
        assert_true(callable(si.get_friendly_interface_name))


def _auth_client():
    """A logged-in Flask test client (CSRF seeded for the login POST)."""
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf123"
    client.post("/login", data={"_csrf_token": "csrf123", "token": app.ACCESS_TOKEN})
    return client


def _ingest(client, device_id, key, seq, ip="9.9.9.9", out_delta=5):
    import device_crypto
    batch = {"schema": 1, "device_id": device_id, "seq": seq, "sent_at": time.time(),
             "events": [{"ip": ip, "direction": "outgoing", "protocol": "TCP",
                         "src_port": 51000, "dst_port": 443,
                         "in_delta": 0, "out_delta": out_delta, "bytes": 4000, "ttl": 117}]}
    token = device_crypto.encrypt_batch(key, batch)
    return client.post("/api/ingest", data=token, headers={"X-Device-Id": device_id},
                       content_type="application/octet-stream")


@check("device CRUD (create / list / patch / delete)")
def t_device_crud():
    client = _auth_client()
    r = client.post("/api/devices", json={"name": "sensorA", "color": "#4FC3F7"})
    assert_eq(r.status_code, 201, "create returns 201 + key")
    dev = r.get_json()
    did = dev["device_id"]
    assert_true(dev.get("key"), "create returns a one-time key")
    assert_true(app.load_device_key(did) is not None, "key persisted on disk")
    # list contains local + the new device
    devs = client.get("/api/devices").get_json()["devices"]
    names = {d["name"] for d in devs}
    assert_true("sensorA" in names and any(d["kind"] == "local" for d in devs), names)
    # rename + recolor
    assert_eq(client.patch(f"/api/devices/{did}", json={"name": "sensorB"}).status_code, 200)
    devs = client.get("/api/devices").get_json()["devices"]
    assert_true("sensorB" in {d["name"] for d in devs}, "rename took effect")
    # delete removes the row and the key
    assert_eq(client.delete(f"/api/devices/{did}").status_code, 200)
    assert_true(app.load_device_key(did) is None, "key removed on delete")


@check("/api/ingest (valid / replay / bad-key / disabled)")
def t_api_ingest():
    client = _auth_client()
    did = client.post("/api/devices", json={"name": "ingestDev"}).get_json()["device_id"]
    key = app.load_device_key(did)
    with app.locked(app.ip_write_buffer_lock):
        app.ip_write_buffer.clear()
    # valid batch accepted and buffered under (device, ip)
    r = _ingest(client, did, key, 1)
    assert_eq(r.status_code, 200, "valid batch accepted")
    assert_eq(r.get_json()["accepted"], 1)
    with app.locked(app.ip_write_buffer_lock):
        assert_true((did, "9.9.9.9") in app.ip_write_buffer, "buffered per (device, ip)")
    # replayed / non-advancing sequence rejected
    assert_eq(_ingest(client, did, key, 1).status_code, 409, "stale seq rejected")
    # wrong key rejected
    import device_crypto
    assert_eq(_ingest(client, did, device_crypto.generate_key(), 2).status_code, 401, "bad key rejected")
    # unknown device rejected
    assert_eq(_ingest(client, "nosuchdevice", key, 2).status_code, 401, "unknown device rejected")
    # disabled device rejected
    assert_eq(client.patch(f"/api/devices/{did}", json={"enabled": False}).status_code, 200)
    assert_eq(_ingest(client, did, key, 2).status_code, 403, "disabled device rejected")
    client.delete(f"/api/devices/{did}")


@check("network_stats by_device payload")
def t_network_stats_by_device():
    payload = app._device_stats_payload(app.SharedStats())
    assert_true("tcp_packets" in payload, "keeps legacy flat keys")
    assert_true(isinstance(payload.get("by_device"), dict), "has by_device map")
    assert_true(app.LOCAL_DEVICE_ID in payload["by_device"], "local device present")
    assert_true(isinstance(payload.get("all"), dict), "has aggregate 'all'")
    for k in ("tcp", "udp", "icmp", "bytes", "active"):
        assert_true(k in payload["all"], f"aggregate has {k}")


# =========================================================================== #
#  Runner
# =========================================================================== #
ALL_TESTS = [
    t_is_safe_redirect_target,
    t_login_bruteforce,
    t_load_network_interface,
    t_socket_rate_limit,
    t_packet_queue,
    t_shared_stats,
    t_is_valid_mac,
    t_get_mac_vendor,
    t_get_mac_vendor_cached,
    t_queue_mac_enrichment,
    t_mac_enrichment_worker,
    t_pinned_ips,
    t_secret_key,
    t_csrf_token,
    t_security_headers,
    t_login_route,
    t_csrf_protect,
    t_login_required,
    t_logout_route,
    t_trusted_orgs_route,
    t_index_route,
    t_mdns_listener,
    t_init_trusted_orgs,
    t_start_mdns_listener,
    t_get_local_ip,
    t_has_net_caps,
    t_is_admin,
    t_auto_detect_interface,
    t_validate_interface,
    t_locked,
    t_init_db,
    t_settings,
    t_update_threat_list,
    t_schedule_threat_list,
    t_handle_set_local_network,
    t_handle_set_external_network,
    t_handle_set_tcp_only,
    t_is_private_ip,
    t_estimate_os,
    t_get_geo_data,
    t_load_org_lists,
    t_classify_org_threat,
    t_compute_org_threat,
    t_get_geo_data_cached,
    t_queue_geo_enrichment,
    t_geo_enrichment_worker,
    t_get_my_public_ip_coords,
    t_buffer_ip_write,
    t_update_ip,
    t_send_network_stats,
    t_cleanup_expired_ips,
    t_parse_ip_packet,
    t_external_callback,
    t_internal_callback,
    t_build_ip_message,
    t_send_ip_to_clients,
    t_send_all_ips,
    t_send_pinned_ips,
    t_process_packets,
    t_load_backend_config,
    t_cleanup,
    t_start_sniffing_present,
    t_internal_scanner_present,
    t_select_interface_helpers,
    t_device_crud,
    t_api_ingest,
    t_network_stats_by_device,
    # zuletzt: startet einen Dauer-Thread, der den ip_write_buffer leert
    t_flush_ip_writes,
]


def main():
    print(f"\n{Colors.BOLD}{Colors.BLUE}=== ConnectSpoofer Full Smoke Test ==={Colors.END}")
    print(f"Arbeitsverzeichnis (temp): {TMP_DIR}\n")

    global_setup()

    print(f"{Colors.BOLD}Laufende Tests:{Colors.END}")
    start = time.time()
    for fn in ALL_TESTS:
        run_test(fn)
    dur = time.time() - start

    passed = sum(1 for _, ok, _ in _RESULTS if ok)
    failed = sum(1 for _, ok, _ in _RESULTS if not ok)

    print(f"\n{Colors.BOLD}=== Zusammenfassung ==={Colors.END}")
    print(f"  Gesamt : {len(_RESULTS)}")
    print(f"  {Colors.GREEN}Passed : {passed}{Colors.END}")
    if failed:
        print(f"  {Colors.RED}Failed : {failed}{Colors.END}")
        print(f"\n{Colors.BOLD}Fehlgeschlagen:{Colors.END}")
        for name, ok, detail in _RESULTS:
            if not ok:
                print(f"  {Colors.RED}- {name}: {detail}{Colors.END}")
    else:
        print(f"  Failed : 0")
    print(f"  Dauer  : {dur:.2f}s")

    # Daemon-Worker-Threads (process_packets, flush_ip_writes, ...) laufen als
    # Daemons weiter und koennen beim Interpreter-Exit harmlose Log-Zeilen
    # ("handle is closed") erzeugen -> Logging hier komplett stumm schalten.
    logging.disable(logging.CRITICAL)

    # Aufraeumen
    try:
        os.chdir(PROJECT_DIR)
        shutil.rmtree(TMP_DIR, ignore_errors=True)
    except Exception:
        pass

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
