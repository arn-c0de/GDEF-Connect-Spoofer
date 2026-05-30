"""Pure, dependency-light packet classification shared by the central hub
(``app.py``) and the standalone sensor worker (``sensor/sensor.py``).

This module must NOT import Flask, the DB layer, ``socketio`` or any hub-only
state — it only needs scapy and the stdlib, so a thin remote sensor can import
it without pulling in the whole web application. Keeping the L3/L4 parsing in
one place means the hub and every sensor classify packets identically; there is
no second copy to drift out of sync.
"""
import os
import re
import ipaddress

from scapy.all import IP, TCP, UDP, ICMP, Ether

# MAC address validation (``xx:xx:xx:xx:xx:xx``, ':' or '-' separated).
MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

# Upper bound for captured frame size. Standard Ethernet is 1500, but jumbo
# frames (up to ~9000), VLAN tagging and tunneling produce larger valid frames;
# a hard 1500 cap would let an attacker evade capture with oversized packets.
# Override with the MAX_PACKET_LEN env var.
MAX_PACKET_LEN = int(os.environ.get('MAX_PACKET_LEN', '9000'))

# Noisy local-discovery UDP ports dropped unless "show all UDP" is enabled:
# 137/138 NetBIOS, 1900 SSDP, 5353 mDNS.
UDP_FILTER_PORTS = {137, 138, 1900, 5353}


def is_valid_mac(mac):
    """True if ``mac`` is a well-formed MAC address."""
    return bool(mac) and bool(MAC_RE.match(mac))


def is_private_ip(ip):
    """True for private / multicast / loopback addresses (unparseable -> False)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_loopback
    except ValueError:
        return False


def estimate_os(ttl):
    """Coarse OS guess from an observed IP TTL."""
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


def build_bpf_filter(app_port=None):
    """Kernel-level capture filter (BPF): IP/ICMP only, optionally dropping the
    dashboard's own TCP traffic on ``app_port`` so the web UI is neither
    visualized nor adds parsing load under heavy traffic. ``app_port`` is
    validated to a safe integer before interpolation to avoid BPF-expression
    injection."""
    try:
        port = int(app_port)
        if not 0 < port < 65536:
            raise ValueError("port out of range")
        return f"(ip or icmp) and not (tcp port {port})"
    except (ValueError, TypeError):
        return "ip or icmp"


def is_fragment(ip_layer):
    """True if the IP layer is a later fragment (offset > 0) or has the MF bit set.

    A non-initial fragment carries no L4 header and so can't be classified by
    port; callers count these separately so the activity stays observable in the
    stats feed instead of silently vanishing (a fragmentation evasion vector)."""
    return ip_layer.frag > 0 or (int(ip_layer.flags) & 0x1)


def classify_packet(packet, show_all_udp=False, udp_filter_ports=UDP_FILTER_PORTS,
                    max_packet_len=MAX_PACKET_LEN):
    """Extract L3/L4 fields from a scapy packet, with NO side effects.

    Returns a dict with: ``ip_src``, ``ip_dst``, ``ttl``, ``protocol``
    (``TCP``|``UDP``|``ICMP``), ``src_port``, ``dst_port``, ``src_mac``,
    ``dst_mac``, ``fragmented`` (bool), ``udp_filtered`` (bool) and ``length``.

    Returns ``None`` for non-IP frames, frames outside the size bounds, or L4
    types we don't track (only TCP, UDP and ICMP echo-request are kept).

    ``udp_filtered`` is set (rather than the packet being dropped here) for noisy
    local-discovery UDP so the caller can still account for it — e.g. count a
    fragment — before discarding, preserving the hub's original ordering."""
    if len(packet) < 20 or len(packet) > max_packet_len or IP not in packet:
        return None

    ip_layer = packet[IP]
    src_port = None
    dst_port = None
    udp_filtered = False

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if not show_all_udp and (src_port in udp_filter_ports or dst_port in udp_filter_ports):
            udp_filtered = True
    elif ICMP in packet and packet[ICMP].type == 8:
        protocol = "ICMP"
    else:
        return None

    src_mac = None
    dst_mac = None
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    return {
        "ip_src": ip_layer.src,
        "ip_dst": ip_layer.dst,
        "ttl": ip_layer.ttl,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "fragmented": bool(is_fragment(ip_layer)),
        "udp_filtered": udp_filtered,
        "length": len(packet),
    }
