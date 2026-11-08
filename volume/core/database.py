import datetime
import json
import sqlite3

from volume.core import config


def _get_conn(db_path):
    conn = sqlite3.connect(str(db_path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _ensure_columns(conn, table: str, columns: dict):
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def init_db():
    # ---- Cases DB ---------------------------------------------------------
    conn = _get_conn(config.DB_CASES)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE,
            analyst TEXT,
            created TEXT,
            updated TEXT,
            notes TEXT DEFAULT '',
            tags TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            case_id INTEGER,
            module TEXT,
            title TEXT,
            query TEXT,
            source TEXT,
            confidence TEXT,
            retrieved_at TEXT,
            result_json TEXT,
            notes TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY,
            finding_id INTEGER,
            type TEXT,
            value TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_entities ON entities(type, value);
        CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
        """
    )
    _ensure_columns(
        conn,
        "cases",
        {
            "updated": "TEXT",
            "notes": "TEXT DEFAULT ''",
            "tags": "TEXT DEFAULT ''",
        },
    )
    _ensure_columns(conn, "findings", {"notes": "TEXT DEFAULT ''"})
    conn.commit()
    conn.close()

    # ---- Auth / license DB ------------------------------------------------
    conn = _get_conn(config.DB_AUTH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            tier TEXT NOT NULL DEFAULT 'FREE',
            created TEXT NOT NULL,
            expires TEXT,
            hwid TEXT,
            credits INTEGER NOT NULL DEFAULT 0,
            max_credits INTEGER NOT NULL DEFAULT 0,
            daily_credits INTEGER NOT NULL DEFAULT 0,
            last_refill TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            note TEXT DEFAULT '',
            last_seen TEXT,
            bound_at TEXT
        );
        CREATE TABLE IF NOT EXISTS credit_ledger (
            id INTEGER PRIMARY KEY,
            key TEXT NOT NULL,
            delta INTEGER NOT NULL,
            balance INTEGER,
            reason TEXT,
            created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            actor TEXT,
            action TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            username_lower TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            key TEXT NOT NULL,
            created TEXT NOT NULL,
            last_login TEXT,
            bio TEXT DEFAULT '',
            hwid TEXT,
            role TEXT NOT NULL DEFAULT 'member',
            role_granted_by TEXT DEFAULT '',
            role_granted_at TEXT,
            banned INTEGER NOT NULL DEFAULT 0
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_username
            ON accounts(username_lower);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_key
            ON accounts(key);
        CREATE INDEX IF NOT EXISTS idx_ledger_key ON credit_ledger(key);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
        """
    )
    _ensure_columns(
        conn,
        "keys",
        {
            "credits": "INTEGER NOT NULL DEFAULT 0",
            "max_credits": "INTEGER NOT NULL DEFAULT 0",
            "daily_credits": "INTEGER NOT NULL DEFAULT 0",
            "last_refill": "TEXT",
            "revoked": "INTEGER NOT NULL DEFAULT 0",
            "note": "TEXT DEFAULT ''",
            "last_seen": "TEXT",
            "bound_at": "TEXT",
        },
    )
    _ensure_columns(
        conn,
        "accounts",
        {
            "bio": "TEXT DEFAULT ''",
            "hwid": "TEXT",
            "role": "TEXT NOT NULL DEFAULT 'member'",
            "role_granted_by": "TEXT DEFAULT ''",
            "role_granted_at": "TEXT",
            "banned": "INTEGER NOT NULL DEFAULT 0",
        },
    )
    conn.commit()
    conn.close()


def list_cases() -> list:
    conn = _get_conn(config.DB_CASES)
    rows = conn.execute(
        "SELECT c.id, c.name, c.analyst, c.created, c.updated, c.notes, c.tags, "
        "(SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) AS findings "
        "FROM cases c ORDER BY COALESCE(c.updated, c.created) DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_case(case_id: int):
    conn = _get_conn(config.DB_CASES)
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


class CaseManager:
    def __init__(self, name=None, analyst=None):
        self.conn = _get_conn(config.DB_CASES)
        self.name = name
        self.analyst = analyst or "anonymous"
        self.id = None
        self.created = None
        self.notes = ""
        self.tags = ""

        if name:
            self.conn.execute(
                "INSERT OR IGNORE INTO cases (name, analyst, created, updated) "
                "VALUES (?, ?, ?, ?)",
                (name, self.analyst, _now(), _now()),
            )
            self.conn.commit()
            row = self.conn.execute(
                "SELECT id, name, analyst, created, notes, tags FROM cases WHERE name=?",
                (name,),
            ).fetchone()
            self.id = row["id"]
            self.name = row["name"]
            self.analyst = row["analyst"] or "anonymous"
            self.created = row["created"]
            self.notes = row["notes"] or ""
            self.tags = row["tags"] or ""

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def update(self, notes=None, tags=None, analyst=None):
        if self.id is None:
            return False
        if notes is not None:
            self.notes = notes
        if tags is not None:
            self.tags = tags
        if analyst is not None:
            self.analyst = analyst
        self.conn.execute(
            "UPDATE cases SET notes=?, tags=?, analyst=?, updated=? WHERE id=?",
            (self.notes, self.tags, self.analyst, _now(), self.id),
        )
        self.conn.commit()
        return True

    def add_finding(self, result: dict, query: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (case_id, module, title, query, source, confidence, "
            "retrieved_at, result_json) VALUES (?,?,?,?,?,?,?,?)",
            (
                self.id,
                result.get("module", ""),
                result.get("title", ""),
                query,
                result.get("source", ""),
                result.get("confidence", ""),
                _now(),
                json.dumps(result, default=str),
            ),
        )
        self.conn.execute("UPDATE cases SET updated=? WHERE id=?", (_now(), self.id))
        self.conn.commit()
        return cur.lastrowid

    def link_entity(self, finding_id: int, ent_type: str, value: str):
        value = str(value).strip()
        if not value:
            return
        self.conn.execute(
            "INSERT INTO entities (finding_id, type, value) VALUES (?, ?, ?)",
            (finding_id, ent_type, value.lower()),
        )
        self.conn.commit()

    def get_findings(self) -> list:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM findings WHERE case_id=? ORDER BY id ASC", (self.id,)
            ).fetchall()
        ]

    def get_finding(self, finding_id: int):
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id=? AND case_id=?", (finding_id, self.id)
        ).fetchone()
        return dict(row) if row else None

    def delete_finding(self, finding_id: int) -> bool:
        self.conn.execute("DELETE FROM entities WHERE finding_id=?", (finding_id,))
        self.conn.execute(
            "DELETE FROM findings WHERE id=? AND case_id=?", (finding_id, self.id)
        )
        self.conn.execute("UPDATE cases SET updated=? WHERE id=?", (_now(), self.id))
        self.conn.commit()
        return True

    def entities(self) -> list:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT e.type, e.value, COUNT(*) AS hits FROM entities e "
                "JOIN findings f ON f.id=e.finding_id WHERE f.case_id=? "
                "GROUP BY e.type, e.value ORDER BY hits DESC, e.value ASC",
                (self.id,),
            ).fetchall()
        ]

    def pivot(self, ent_type: str, value: str) -> list:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT f.* FROM findings f JOIN entities e ON e.finding_id = f.id "
                "WHERE e.type=? AND e.value=?",
                (ent_type, value.strip().lower()),
            ).fetchall()
        ]

    def stats(self) -> dict:
        findings = self.get_findings()
        entities = self.entities()
        modules = {}
        for f in findings:
            modules[f["module"]] = modules.get(f["module"], 0) + 1
        return {
            "findings": len(findings),
            "entities": len(entities),
            "modules": modules,
            "first": findings[0]["retrieved_at"] if findings else None,
            "last": findings[-1]["retrieved_at"] if findings else None,
        }

    def timeline(self) -> list:
        rows = []
        for f in self.get_findings():
            rows.append(
                {
                    "at": f["retrieved_at"],
                    "module": f["module"],
                    "title": f["title"],
                    "query": f["query"],
                    "confidence": f["confidence"],
                }
            )
        rows.sort(key=lambda r: r["at"] or "")
        return rows

    def delete_case(self) -> bool:
        """Delete this case and all its findings and entities."""
        try:
            self.conn.execute(
                "DELETE FROM entities WHERE finding_id IN "
                "(SELECT id FROM findings WHERE case_id=?)",
                (self.id,),
            )
            self.conn.execute("DELETE FROM findings WHERE case_id=?", (self.id,))
            self.conn.execute("DELETE FROM cases WHERE id=?", (self.id,))
            self.conn.commit()
            return True
        except Exception:
            return False
