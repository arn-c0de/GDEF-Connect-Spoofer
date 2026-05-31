"""Input validation / sanitisation helpers (pure functions, no app state).

These guard untrusted input before it reaches the DB, an outbound URL, or the
browser: mDNS hostnames (unauthenticated broadcasts), sensor-supplied event
fields, device ids and colours. Kept dependency-free so any module can import
them without import-cycle risk.
"""
import re

# mDNS names are attacker-controllable; strip to a DNS-safe charset.
_MDNS_HOSTNAME_RE = re.compile(r'[^A-Za-z0-9._-]')
# Device ids must be path-safe (no separators) — see device_key_path.
_DEVICE_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_COLOR_RE = re.compile(r'^#[0-9A-Fa-f]{6}$')


def sanitize_mdns_hostname(name):
    """mDNS names are untrusted input. Strip to a DNS-safe charset and cap the
    length so a spoofed service name cannot smuggle markup, control characters,
    or unbounded text into the DB / UI."""
    if not name:
        return "Unknown"
    cleaned = _MDNS_HOSTNAME_RE.sub('', name)[:63]
    return cleaned or "Unknown"


def _clamp_int(v, lo, hi, default=0):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _valid_port(v):
    try:
        p = int(v)
    except (TypeError, ValueError):
        return None
    return p if 0 <= p <= 65535 else None


def _short_str(v, default="Unknown", maxlen=128):
    return v[:maxlen] if isinstance(v, str) and v else default


def _valid_device_id(s):
    return isinstance(s, str) and bool(_DEVICE_ID_RE.match(s))
