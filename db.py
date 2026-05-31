"""PostgreSQL access layer for GDEF-L1NK.

Replaces the former embedded SQLite database. A single fork-aware connection
pool serves every thread; the hot packet path (pinned-IP checks, enrichment
workers) borrows a pooled connection per operation instead of opening a fresh
TCP connection each time.

Why fork-aware: the sniffer runs in a separate child process (multiprocessing,
``fork`` on Linux). A pool created in the parent before the fork would be
inherited with sockets shared with the parent and background workers that do not
survive the fork. We therefore key the pool on ``os.getpid()`` and transparently
build a fresh one the first time it is touched in a new process.

Configuration (env):
    DATABASE_URL        full libpq URL/DSN; overrides the PG* vars below
    PGHOST              default 127.0.0.1
    PGPORT              default 5432
    PGDATABASE          default gdef_l1nk
    PGUSER              default gdef_l1nk
    PGPASSWORD          default gdef_l1nk
    DB_POOL_SIZE        max pooled connections per process (default 10)
    DB_CONNECT_TIMEOUT  seconds to wait for a connection (default 15)
"""

import logging
import os
import threading
import time
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

logger = logging.getLogger("GDEF-L1NK")

# Every DB error the app used to catch via ``sqlite3.Error`` maps to this base.
DBError = psycopg.Error


# Built-in fallback password. Fine for a localhost-only dev run, but a known
# constant — anything reachable on a non-loopback PGHOST must override it.
_DEFAULT_PW = "gdef_l1nk"
_warned_default_pw = False

def _dsn():
    global _warned_default_pw
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    host = os.environ.get("PGHOST", "127.0.0.1")
    port = os.environ.get("PGPORT", "5432")
    name = os.environ.get("PGDATABASE", "gdef_l1nk")
    user = os.environ.get("PGUSER", "gdef_l1nk")
    pw = os.environ.get("PGPASSWORD", _DEFAULT_PW)
    if pw == _DEFAULT_PW and not _warned_default_pw:
        _warned_default_pw = True
        logger.warning(
            "PGPASSWORD is unset: using the built-in default DB password (a known "
            "constant). Set PGPASSWORD or DATABASE_URL to a strong secret before "
            "PostgreSQL is reachable on anything other than 127.0.0.1.")
    return f"host={host} port={port} dbname={name} user={user} password={pw}"


_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "10"))
_CONNECT_TIMEOUT = float(os.environ.get("DB_CONNECT_TIMEOUT", "15"))

_pool = None
_pool_pid = None
_pool_lock = threading.Lock()


def _get_pool():
    """Return this process's connection pool, creating it on first use.

    If the cached pool belongs to a different PID (i.e. we were forked), it is an
    inert inheritance: build a brand-new pool for the current process and never
    touch the inherited one (closing it would disturb the parent's sockets)."""
    global _pool, _pool_pid
    pid = os.getpid()
    p = _pool
    if p is not None and _pool_pid == pid:
        return p
    with _pool_lock:
        if _pool is not None and _pool_pid == pid:
            return _pool
        _pool = ConnectionPool(
            conninfo=_dsn(),
            min_size=1,
            max_size=_POOL_SIZE,
            timeout=_CONNECT_TIMEOUT,
            max_idle=60.0,
            name=f"gdef-l1nk-{pid}",
            open=True,
        )
        _pool_pid = pid
        return _pool


@contextmanager
def get_connection():
    """Yield a pooled connection. Commits on clean exit, rolls back on error,
    then returns the connection to the pool.

    Mirrors ``with sqlite3.connect(...) as conn:`` semantics so call sites keep
    using ``conn.cursor()`` / ``conn.commit()`` unchanged."""
    pool = _get_pool()
    with pool.connection() as conn:
        yield conn


def wait_until_ready(retries=60, delay=1.0):
    """Block until Postgres accepts a connection, so the app tolerates the
    database container coming up a moment after it does. Returns True on success."""
    last = None
    for attempt in range(1, retries + 1):
        try:
            with get_connection() as conn, conn.cursor() as c:
                c.execute("SELECT 1")
            if attempt > 1:
                logger.info("Database reachable after %d attempt(s)", attempt)
            return True
        except DBError as e:
            last = e
            if attempt == 1 or attempt % 5 == 0:
                logger.info("Waiting for database (attempt %d/%d)...", attempt, retries)
            time.sleep(delay)
    logger.error("Database not reachable after %d attempts: %s", retries, last)
    return False


def list_tables():
    """Return the set of user table names in the public schema (test helper)."""
    with get_connection() as conn, conn.cursor() as c:
        c.execute(
            "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'"
        )
        return {r[0] for r in c.fetchall()}
