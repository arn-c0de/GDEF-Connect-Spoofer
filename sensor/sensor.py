#!/usr/bin/env python3
"""GDEF-L1NK sensor worker.

Run this on each server you want to monitor. It captures locally with scapy,
coalesces connections, and pushes them — gzip-compressed and Fernet-encrypted —
to the central hub's ``/api/ingest``. It stays deliberately thin: no database,
no geo/threat enrichment (the hub does that centrally), just capture + batch +
send.

Setup:
  1. Register the device on the hub UI; copy the issued DEVICE_ID and DEVICE_KEY.
  2. Fill in the environment (see ``sensor.env.example``): CENTRAL_URL,
     DEVICE_ID, DEVICE_KEY and NETWORK_INTERFACE.
  3. Run as root (capture needs CAP_NET_RAW): ``sudo -E python3 sensor.py``.

The sensor shares ``capture_core`` and ``device_crypto`` with the hub so the
wire format and packet classification can never drift. Deploy those two files
next to this one (or run from a hub checkout — both locations are searched).
"""
import os
import sys
import time
import socket
import logging
import threading

# Resolve the two shared modules whether this runs from its own folder (with
# copies alongside) or from a full hub checkout (parent directory).
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.dirname(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import requests
from scapy.all import sniff

import capture_core
import device_crypto

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sensor")


def _require(name):
    val = os.environ.get(name, "").strip()
    if not val:
        logger.error("Missing required environment variable: %s", name)
        sys.exit(2)
    return val


CENTRAL_URL = _require("CENTRAL_URL").rstrip("/")
DEVICE_ID = _require("DEVICE_ID")
DEVICE_KEY = _require("DEVICE_KEY")
INTERFACE = os.environ.get("NETWORK_INTERFACE", "").strip() or None
INGEST_URL = f"{CENTRAL_URL}/api/ingest"

FLUSH_INTERVAL = float(os.environ.get("SENSOR_FLUSH_INTERVAL", "2.0"))
MAX_BUFFER_IPS = int(os.environ.get("SENSOR_MAX_BUFFER_IPS", "20000"))
MAX_EVENTS_PER_BATCH = int(os.environ.get("SENSOR_MAX_EVENTS", "5000"))
SHOW_ALL_UDP = os.environ.get("SENSOR_SHOW_ALL_UDP", "0").lower() in ("1", "true", "yes")
HTTP_TIMEOUT = float(os.environ.get("SENSOR_HTTP_TIMEOUT", "10"))
# TLS verification is on by default; disable only for a hub with a self-signed
# cert on a trusted LAN (the payload is still Fernet-encrypted regardless).
VERIFY_TLS = os.environ.get("SENSOR_VERIFY_TLS", "1").lower() in ("1", "true", "yes")

_buffer = {}                 # ip -> event dict (coalesced)
_buffer_lock = threading.Lock()
_dropped = 0
# Monotonic batch sequence: seeded from the wall clock (ms) so it keeps
# increasing across restarts without persisting state; the hub rejects any
# batch whose seq does not strictly advance (replay/dup protection).
_seq = int(time.time() * 1000)


def get_local_ip():
    """Best-effort primary local IP (a UDP connect that sends no packets)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def get_public_ip():
    """Best-effort public IP via ipify (HTTPS). Optional: direction inference
    still works from the local IP + well-known ports if this is unknown."""
    for url in ("https://api.ipify.org", "http://api.ipify.org"):
        try:
            r = requests.get(url, timeout=5)
            if r.ok and r.text.strip():
                return r.text.strip()
        except requests.RequestException:
            continue
    return None


# Resolved in main() (kept out of import so importing the module does no I/O).
MY_LOCAL_IP = None
MY_PUBLIC_IP = None


def _record(ip, direction, parsed, mac):
    """Fold one packet into the coalescing buffer under `ip`."""
    global _dropped
    now = time.time()
    with _buffer_lock:
        e = _buffer.get(ip)
        if e is None:
            if len(_buffer) >= MAX_BUFFER_IPS:
                _dropped += 1
                return
            e = {"ip": ip, "in_delta": 0, "out_delta": 0, "bytes": 0, "first_seen": now}
            _buffer[ip] = e
        e["last_seen"] = now
        e["protocol"] = parsed["protocol"]
        e["src_port"] = parsed["src_port"]
        e["dst_port"] = parsed["dst_port"]
        e["ttl"] = parsed["ttl"]
        if mac:
            e["mac"] = mac
        e["bytes"] += parsed["length"]
        if direction == "incoming":
            e["in_delta"] += 1
        elif direction == "outgoing":
            e["out_delta"] += 1


def on_packet(packet):
    parsed = capture_core.classify_packet(packet, show_all_udp=SHOW_ALL_UDP)
    if parsed is None or parsed["udp_filtered"]:
        return
    ip_src, ip_dst = parsed["ip_src"], parsed["ip_dst"]
    direction = capture_core.classify_direction(
        ip_src, ip_dst, parsed["protocol"], parsed["src_port"], parsed["dst_port"],
        MY_LOCAL_IP, MY_PUBLIC_IP)
    # Report the remote endpoint (the one that isn't us). For "other" traffic
    # neither end is us, so report both so the hub still sees the conversation.
    if direction == "incoming":
        _record(ip_src, "incoming", parsed, parsed["src_mac"])
    elif direction == "outgoing":
        _record(ip_dst, "outgoing", parsed, parsed["dst_mac"])
    else:
        _record(ip_src, "other", parsed, parsed["src_mac"])
        _record(ip_dst, "other", parsed, parsed["dst_mac"])


def _next_seq():
    global _seq
    _seq = max(_seq + 1, int(time.time() * 1000))
    return _seq


def _swap_buffer():
    """Atomically take the current buffer and reset it. Returns (events, dropped)."""
    global _buffer, _dropped
    with _buffer_lock:
        items = _buffer
        dropped = _dropped
        _buffer = {}
        _dropped = 0
    return items, dropped


def _requeue(items):
    """Merge un-sent events back into the buffer after a failed send, coalescing
    deltas and dropping oldest beyond the cap so memory stays bounded."""
    global _dropped
    with _buffer_lock:
        for ip, e in items.items():
            cur = _buffer.get(ip)
            if cur is None:
                if len(_buffer) >= MAX_BUFFER_IPS:
                    _dropped += 1
                    continue
                _buffer[ip] = e
            else:
                cur["in_delta"] += e["in_delta"]
                cur["out_delta"] += e["out_delta"]
                cur["bytes"] += e["bytes"]
                cur["first_seen"] = min(cur["first_seen"], e["first_seen"])


def _to_event(e):
    ev = {
        "ip": e["ip"],
        "protocol": e.get("protocol"),
        "src_port": e.get("src_port"),
        "dst_port": e.get("dst_port"),
        "in_delta": e["in_delta"],
        "out_delta": e["out_delta"],
        "bytes": e["bytes"],
        "ttl": e.get("ttl"),
        "first_seen": e["first_seen"],
        "last_seen": e.get("last_seen", e["first_seen"]),
    }
    if e.get("mac"):
        ev["mac"] = e["mac"]
    return ev


def flush(session):
    items, dropped = _swap_buffer()
    if dropped:
        logger.warning("buffer full: dropped %d IPs since last flush", dropped)
    if not items:
        return
    events = [_to_event(e) for e in list(items.values())[:MAX_EVENTS_PER_BATCH]]
    batch = {"schema": 1, "device_id": DEVICE_ID, "seq": _next_seq(),
             "sent_at": time.time(), "events": events}
    token = device_crypto.encrypt_batch(DEVICE_KEY, batch)
    try:
        resp = session.post(INGEST_URL, data=token,
                            headers={"X-Device-Id": DEVICE_ID,
                                     "Content-Type": "application/octet-stream"},
                            timeout=HTTP_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        logger.warning("ingest POST failed (%s); re-queuing %d events", e, len(events))
        _requeue(items)
        return
    if resp.status_code == 200:
        logger.debug("sent %d events: %s", len(events), resp.text[:120])
    elif resp.status_code == 409:
        # Sequence behind the hub (e.g. clock skew). Jump ahead and re-queue.
        global _seq
        _seq = int(time.time() * 1000) + 1
        logger.warning("hub reported stale sequence; resyncing and re-queuing")
        _requeue(items)
    elif resp.status_code in (401, 403):
        logger.error("hub rejected sensor (HTTP %s): check DEVICE_ID/DEVICE_KEY "
                     "and that the device is enabled. Dropping batch.", resp.status_code)
    else:
        logger.warning("hub returned HTTP %s; re-queuing", resp.status_code)
        _requeue(items)


def _flush_loop():
    session = requests.Session()
    while True:
        time.sleep(FLUSH_INTERVAL)
        try:
            flush(session)
        except Exception as e:  # never let the loop die
            logger.error("flush error: %s", e)


def main():
    global MY_LOCAL_IP, MY_PUBLIC_IP
    MY_LOCAL_IP = get_local_ip()
    MY_PUBLIC_IP = get_public_ip()
    logger.info("GDEF-L1NK sensor %s starting: iface=%s local_ip=%s public_ip=%s -> %s",
                DEVICE_ID[:8], INTERFACE or "(default)", MY_LOCAL_IP, MY_PUBLIC_IP, INGEST_URL)
    if INGEST_URL.startswith("https://") and not VERIFY_TLS:
        logger.warning("SENSOR_VERIFY_TLS is disabled: the hub's TLS certificate is "
                       "NOT verified, so the HTTPS connection can be MITM'd. The batch "
                       "stays Fernet-encrypted, but only use this for a self-signed hub "
                       "on a trusted LAN — pin a CA instead where possible.")
    threading.Thread(target=_flush_loop, daemon=True).start()
    bpf = capture_core.build_bpf_filter()  # ip or icmp
    try:
        sniff(iface=INTERFACE, prn=on_packet, store=False, filter=bpf)
    except PermissionError:
        logger.error("Permission denied for capture — run as root (CAP_NET_RAW).")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("sensor stopping")


if __name__ == "__main__":
    main()
