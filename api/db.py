"""Database layer for the web API.

Runs on SQLite for local development and PostgreSQL in production.  Queries are
written with ``?`` placeholders and translated for PostgreSQL so the rest of
the codebase has one dialect to care about.
"""

import sqlite3
import threading
from pathlib import Path

from api import settings

SQLITE_PATH = Path(
    settings.env("VOLUME_WEB_DB") or (settings.ROOT_DIR / "volume" / "data" / "web.db")
)

_local = threading.local()

# If DATABASE_URL is set but unreachable, log loudly and serve this instance on
# SQLite instead of crash-looping the whole service. Data is then ephemeral,
# which is still better than a deployment that never binds a port.
_forced_sqlite = False
_fallback_reason = ""


def backend() -> str:
    """The database actually in use right now."""
    return "sqlite" if (_forced_sqlite or not settings.IS_POSTGRES) else "postgresql"


def fallback_reason() -> str:
    return _fallback_reason

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'free',
    credits INTEGER NOT NULL DEFAULT 0,
    paid_until TEXT,
    referral_code TEXT,
    referred_by TEXT,
    created TEXT NOT NULL,
    last_login TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    created TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    label TEXT,
    remember INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS otp_codes (
    email TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'login',
    code_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    expires TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL,
    ip TEXT,
    referral TEXT,
    PRIMARY KEY (email, purpose)
);

CREATE TABLE IF NOT EXISTS usage (
    user_id TEXT NOT NULL,
    day TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);

CREATE TABLE IF NOT EXISTS magic_links (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    kind TEXT NOT NULL,
    challenge TEXT NOT NULL,
    expires TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    label TEXT,
    tier TEXT NOT NULL DEFAULT 'premium',
    credits INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL,
    expires TEXT,
    redeemed_by TEXT,
    redeemed_at TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    seed TEXT,
    kind TEXT,
    created TEXT NOT NULL,
    updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    case_id TEXT,
    user_id TEXT NOT NULL,
    seed TEXT,
    kind TEXT,
    module TEXT,
    status TEXT,
    payload TEXT,
    created TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlists (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    label TEXT NOT NULL,
    seed TEXT NOT NULL,
    kind TEXT NOT NULL,
    created TEXT NOT NULL,
    last_checked TEXT,
    last_count INTEGER NOT NULL DEFAULT 0,
    last_new INTEGER NOT NULL DEFAULT 0,
    snapshot TEXT
);

CREATE TABLE IF NOT EXISTS watch_events (
    id TEXT PRIMARY KEY,
    watch_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created TEXT NOT NULL,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    label TEXT,
    created TEXT NOT NULL,
    last_used TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    ip TEXT
);

CREATE TABLE IF NOT EXISTS module_flags (
    module_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    updated TEXT
);

CREATE TABLE IF NOT EXISTS redemptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    reference TEXT,
    credits INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL
);
"""


def _sqlite_conn() -> sqlite3.Connection:
    conn = getattr(_local, "sqlite", None)
    if conn is None:
        SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(SQLITE_PATH), timeout=20, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.sqlite = conn
    return conn


def _postgres_conn():
    conn = getattr(_local, "postgres", None)
    if conn is None or conn.closed:
        import psycopg
        from psycopg.rows import dict_row

        conn = psycopg.connect(
            settings.DATABASE_URL, autocommit=True, row_factory=dict_row
        )
        _local.postgres = conn
    return conn


def _translate(sql: str) -> str:
    return sql.replace("?", "%s") if backend() == "postgresql" else sql


def query(sql: str, params: tuple | list = ()) -> list[dict]:
    if backend() == "postgresql":
        conn = _postgres_conn()
        with conn.cursor() as cur:
            cur.execute(_translate(sql), tuple(params))
            if not cur.description:
                return []
            return [dict(row) for row in cur.fetchall()]
    conn = _sqlite_conn()
    cur = conn.execute(sql, tuple(params))
    rows = [dict(row) for row in cur.fetchall()]
    conn.commit()
    return rows


def query_one(sql: str, params: tuple | list = ()) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: tuple | list = ()) -> int:
    if backend() == "postgresql":
        conn = _postgres_conn()
        with conn.cursor() as cur:
            cur.execute(_translate(sql), tuple(params))
            return cur.rowcount
    conn = _sqlite_conn()
    cur = conn.execute(sql, tuple(params))
    conn.commit()
    return cur.rowcount


def init() -> None:
    global _forced_sqlite, _fallback_reason
    if settings.IS_POSTGRES and not _forced_sqlite:
        try:
            _postgres_conn()
        except Exception as exc:  # bad host, auth failure, SSL, timeout...
            _forced_sqlite = True
            _fallback_reason = f"{type(exc).__name__}: {exc}"
            print(
                "[db] DATABASE_URL is unreachable, falling back to SQLite for this "
                f"instance. Fix DATABASE_URL to persist data. Reason: {_fallback_reason}",
                flush=True,
            )
    for statement in SCHEMA.split(";"):
        statement = statement.strip()
        if not statement:
            continue
        execute(statement)


def healthy() -> bool:
    try:
        query("SELECT 1 AS ok")
        return True
    except Exception:
        return False
