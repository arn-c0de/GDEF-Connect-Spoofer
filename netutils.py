"""Host/network capability helpers with no app-state dependencies.

Open-redirect validation, local-IP discovery, raw-capture privilege checks, and
interface auto-detection. All pure (stdlib + scapy's get_if_list); they read no
module globals and start no threads, so they are safe to import anywhere.
"""
import os
import sys
import socket
import ctypes
import logging
from urllib.parse import urlparse
from scapy.all import get_if_list

logger = logging.getLogger(__name__)

# Linux capability bits required for raw packet capture.
CAP_NET_ADMIN = 12
CAP_NET_RAW = 13


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
