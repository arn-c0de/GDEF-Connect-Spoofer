"""Atomic, symlink-safe writing of 0600 secret files.

Shared by every secret the hub persists (the access token, the Flask secret key,
and per-device sensor keys). Kept dependency-free (stdlib os only) so it can be
imported anywhere without pulling in app state.
"""
import os

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
