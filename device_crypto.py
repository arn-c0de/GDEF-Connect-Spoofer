"""Symmetric encryption + framing for the sensor -> hub ingestion channel.

Each device holds ONE Fernet key (32-byte urlsafe base64). A batch is serialized
to JSON, gzip-compressed, then Fernet-encrypted. Possession of the key is the
sole credential: a payload that decrypts cleanly is authentic, because only the
key holder could have produced it. Fernet stamps every token with a timestamp,
so the hub rejects anything older than ``max_age`` (replay protection). The
result is confidential and tamper-evident even over plain HTTP on a home LAN,
which is exactly the deployment the sensors target.

Shared by both ends (hub ``app.py`` and ``sensor/sensor.py``) so the wire format
can never drift between them. Depends only on ``cryptography`` + the stdlib.
"""
import gzip
import json

from cryptography.fernet import Fernet, InvalidToken

__all__ = ["generate_key", "encrypt_batch", "decrypt_batch", "InvalidBatch"]


class InvalidBatch(Exception):
    """A payload could not be decrypted, was too old, or was malformed."""


def generate_key():
    """Return a fresh urlsafe-base64 Fernet key as a ``str``."""
    return Fernet.generate_key().decode("ascii")


def _as_key(key):
    return key.encode("ascii") if isinstance(key, str) else key


def encrypt_batch(key, batch):
    """Serialize ``batch`` (a JSON-able dict) -> gzip -> Fernet token (bytes)."""
    raw = json.dumps(batch, separators=(",", ":")).encode("utf-8")
    return Fernet(_as_key(key)).encrypt(gzip.compress(raw))


def decrypt_batch(key, token, max_age=None):
    """Reverse :func:`encrypt_batch`.

    Returns the decoded dict. Raises :class:`InvalidBatch` on a wrong key, a
    token older than ``max_age`` seconds, corruption, or non-object JSON."""
    try:
        packed = Fernet(_as_key(key)).decrypt(token, ttl=max_age)
        obj = json.loads(gzip.decompress(packed).decode("utf-8"))
    except (InvalidToken, ValueError, OSError, TypeError) as e:
        raise InvalidBatch(str(e)) from e
    if not isinstance(obj, dict):
        raise InvalidBatch("batch is not a JSON object")
    return obj
