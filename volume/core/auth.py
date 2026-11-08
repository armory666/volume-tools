"""License keys, HWID binding, credits and admin operations."""

import datetime
import hmac
import json
import secrets
import string
import time

from volume.core import config, database, licensing

SESSION_TTL = 7 * 24 * 3600
_KEY_CHARS = string.ascii_uppercase + string.digits


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt=None) -> str:
    return (dt or _now()).isoformat()


def _parse(value):
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def _today() -> str:
    return _now().date().isoformat()


def audit(actor: str, action: str, detail: str = ""):
    try:
        conn = database._get_conn(config.DB_AUTH)
        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
            (_iso(), actor or "-", action, str(detail)[:600]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _ledger(conn, key, delta, balance, reason):
    try:
        conn.execute(
            "INSERT INTO credit_ledger (key, delta, balance, reason, created) "
            "VALUES (?, ?, ?, ?, ?)",
            (key, int(delta), balance, reason, _iso()),
        )
    except Exception:
        pass


def _free_key(hwid: str) -> str:
    return f"FREE-{hwid[:10]}"


def _ghost_key(hwid: str) -> str:
    return f"GHOST-{hwid[:10]}"


def _insert_license(conn, key, tier, days=0, credits=None, hwid=None, note=""):
    t = licensing.defaults(tier)
    expires = None if not days else _iso(_now() + datetime.timedelta(days=days))
    max_credits = t["credits"] if credits is None else int(credits)
    conn.execute(
        "INSERT INTO keys (key, tier, created, expires, hwid, credits, max_credits, "
        "daily_credits, last_refill, revoked, note, bound_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
        (
            key,
            licensing.normalize_tier(tier),
            _iso(),
            expires,
            hwid,
            max_credits,
            max_credits,
            t["daily"],
            _today(),
            note,
            _iso() if hwid else None,
        ),
    )
    _ledger(conn, key, max_credits, max_credits, "initial grant")
    conn.commit()


def ensure_free_license(hwid: str) -> str:
    key = _free_key(hwid)
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row:
        _insert_license(conn, key, "FREE", days=0, hwid=hwid, note="device free")
    else:
        # Repair legacy/free rows so credits always behave.
        t = licensing.defaults("FREE")
        conn.execute(
            "UPDATE keys SET tier='FREE', hwid=?, max_credits=?, daily_credits=?, "
            "credits=MIN(COALESCE(credits, 0), ?), last_refill=COALESCE(last_refill, ?), "
            "revoked=0 WHERE key=?",
            (hwid, t["credits"], t["daily"], t["credits"], _today(), key),
        )
        conn.commit()
    conn.close()
    return key


def ensure_ghost_license(hwid: str) -> str:
    key = _ghost_key(hwid)
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row:
        _insert_license(conn, key, "LIFETIME", days=0, hwid=hwid, note="ghost admin")
    else:
        conn.execute(
            "UPDATE keys SET tier='LIFETIME', hwid=?, revoked=0, expires=NULL WHERE key=?",
            (hwid, key),
        )
        conn.commit()
    conn.close()
    return key


def _refill_free(conn, row, commit=True):
    """Apply the daily free-tier top-up. Returns the effective credit balance."""
    credits = int(row["credits"] or 0)
    tier = licensing.normalize_tier(row["tier"])
    if tier != "FREE":
        return credits
    daily = int(row["daily_credits"] or 0)
    cap = int(row["max_credits"] or 0)
    if daily <= 0:
        return credits
    if (row["last_refill"] or "") == _today():
        return credits
    credits = min(cap, credits + daily) if cap else credits + daily
    conn.execute(
        "UPDATE keys SET credits=?, last_refill=? WHERE key=?",
        (credits, _today(), row["key"]),
    )
    _ledger(conn, row["key"], daily, credits, "daily refill")
    if commit:
        conn.commit()
    return credits


def _license_from_row(row, hwid=None, resolve_role=True):
    tier = licensing.normalize_tier(row["tier"])

    # Roles are permanent and independent of the tier. Resolve them lazily so
    # ``auth`` does not import ``accounts`` at module load (accounts imports us).
    role = ""
    banned = False
    if resolve_role:
        try:
            from volume.core import accounts as _accounts

            account = _accounts.account_for_key(row["key"]) or {}
            role = account.get("role") or ""
            banned = bool(account.get("banned"))
        except Exception:
            role = ""
            banned = False
    role = (role or "member").strip().lower()
    if role not in ("member", "moderator", "manager", "admin", "founder"):
        role = "member"

    founder = role == "founder"
    staff = role in ("moderator", "manager", "admin", "founder")
    admin = tier == "LIFETIME" or role in ("admin", "founder")
    unlimited = licensing.is_unlimited(tier) or admin

    expires_dt = _parse(row["expires"])
    days_left = None
    if expires_dt:
        days_left = max(0, (expires_dt - _now()).days)
    expired = bool(expires_dt and _now() > expires_dt)
    revoked = bool(row["revoked"])
    bound = row["hwid"] or ""
    hwid_ok = True
    if bound and hwid:
        hwid_ok = hmac.compare_digest(str(bound), str(hwid))

    valid = not revoked and not expired and hwid_ok and not banned
    reason = ""
    if banned:
        reason = "Account suspended"
    elif revoked:
        reason = "License revoked"
    elif expired:
        reason = "License expired"
    elif not hwid_ok:
        reason = "HWID mismatch (key is bound to another device)"

    credits = None if unlimited else int(row["credits"] or 0)
    return {
        "key": row["key"],
        "tier": tier,
        "rank": licensing.tier_rank(tier),
        "role": role,
        "founder": founder,
        "staff": staff,
        "admin": admin,
        "unlimited": unlimited,
        "credits": credits,
        "max_credits": int(row["max_credits"] or 0),
        "daily_credits": int(row["daily_credits"] or 0),
        "created": row["created"],
        "expires": row["expires"],
        "days_left": days_left,
        "expired": expired,
        "revoked": revoked,
        "banned": banned,
        "hwid": bound,
        "hwid_bound": bool(bound),
        "hwid_ok": hwid_ok,
        "last_seen": row["last_seen"],
        "note": row["note"] or "",
        "valid": valid,
        "reason": reason,
    }


def get_license(key: str, hwid: str = None) -> dict:
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute("SELECT * FROM keys WHERE key=?", ((key or "").strip(),)).fetchone()
    conn.close()
    if not row:
        return {"key": key, "valid": False, "reason": "Invalid key", "tier": "FREE"}
    return _license_from_row(row, hwid)


def validate_key(key: str, hwid: str) -> dict:
    key = (key or "").strip()
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row:
        conn.close()
        return {"key": key, "valid": False, "reason": "Invalid key", "tier": "FREE"}

    # First use binds the license to this device.
    if not row["hwid"]:
        conn.execute(
            "UPDATE keys SET hwid=?, bound_at=?, last_seen=? WHERE key=?",
            (hwid, _iso(), _iso(), key),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    elif not hmac.compare_digest(str(row["hwid"]), str(hwid)):
        info = _license_from_row(row, hwid)
        conn.close()
        return info

    _refill_free(conn, row)
    conn.execute("UPDATE keys SET last_seen=? WHERE key=?", (_iso(), key))
    conn.commit()
    row = conn.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    info = _license_from_row(row, hwid)
    conn.close()
    return info


def spend_credits(key: str, amount: int, reason: str = "module run", hwid: str = None) -> dict:
    amount = max(0, int(amount or 0))
    conn = database._get_conn(config.DB_AUTH)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
        if not row:
            conn.execute("ROLLBACK")
            return {"ok": False, "remaining": 0, "error": "Invalid key"}
        info = _license_from_row(row, hwid)
        if not info["valid"]:
            conn.execute("ROLLBACK")
            return {"ok": False, "remaining": info.get("credits") or 0, "error": info["reason"]}
        if info["unlimited"] or amount == 0:
            conn.execute("UPDATE keys SET last_seen=? WHERE key=?", (_iso(), key))
            conn.execute("COMMIT")
            return {"ok": True, "remaining": None, "error": ""}

        credits = _refill_free(conn, row, commit=False)
        if credits < amount:
            conn.execute("ROLLBACK")
            return {
                "ok": False,
                "remaining": credits,
                "error": f"Not enough credits ({credits} left, {amount} required)",
            }
        credits -= amount
        conn.execute(
            "UPDATE keys SET credits=?, last_seen=? WHERE key=?",
            (credits, _iso(), key),
        )
        _ledger(conn, key, -amount, credits, reason)
        conn.execute("COMMIT")
        return {"ok": True, "remaining": credits, "error": ""}
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return {"ok": False, "remaining": 0, "error": f"Credit transaction failed: {exc}"}
    finally:
        conn.close()


def add_credits(key: str, amount: int, reason: str = "admin top-up", actor: str = "admin",
                respect_cap: bool = False) -> dict:
    amount = int(amount or 0)
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute("SELECT * FROM keys WHERE key=?", ((key or "").strip(),)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "remaining": 0, "error": "Invalid key"}
    if licensing.is_unlimited(row["tier"]):
        conn.close()
        return {"ok": True, "remaining": None, "error": ""}

    credits = max(0, int(row["credits"] or 0) + amount)
    if respect_cap and int(row["max_credits"] or 0):
        credits = min(int(row["max_credits"]), credits)
    conn.execute(
        "UPDATE keys SET credits=?, max_credits=MAX(max_credits, ?) WHERE key=?",
        (credits, credits, key),
    )
    _ledger(conn, key, amount, credits, reason)
    conn.commit()
    conn.close()
    audit(actor, "add_credits", f"{key} {amount:+d} -> {credits} ({reason})")
    return {"ok": True, "remaining": credits, "error": ""}


def set_credits(key: str, amount: int, reason: str = "admin set", actor: str = "admin") -> dict:
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute("SELECT * FROM keys WHERE key=?", ((key or "").strip(),)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "remaining": 0, "error": "Invalid key"}
    amount = max(0, int(amount or 0))
    conn.execute("UPDATE keys SET credits=?, max_credits=MAX(max_credits, ?) WHERE key=?",
                 (amount, amount, key))
    _ledger(conn, key, amount - int(row["credits"] or 0), amount, reason)
    conn.commit()
    conn.close()
    audit(actor, "set_credits", f"{key} -> {amount} ({reason})")
    return {"ok": True, "remaining": amount, "error": ""}


def generate_key(tier="FREE", days=30, credits=None, note="", hwid=None) -> str:
    tier = licensing.normalize_tier(tier)
    days = max(0, int(days or 0))
    conn = database._get_conn(config.DB_AUTH)
    for _ in range(20):
        parts = ["".join(secrets.choice(_KEY_CHARS) for _ in range(4)) for _ in range(3)]
        key = f"VOL-{parts[0]}-{parts[1]}-{parts[2]}"
        exists = conn.execute("SELECT 1 FROM keys WHERE key=?", (key,)).fetchone()
        if not exists:
            break
    else:
        conn.close()
        raise RuntimeError("Could not allocate a unique key")

    _insert_license(conn, key, tier, days=days, credits=credits, hwid=hwid, note=note)
    conn.close()
    audit("admin", "generate_key", f"{key} tier={tier} days={days} credits={credits}")
    return key


def list_keys(limit: int = 200, include_device: bool = False) -> list:
    conn = database._get_conn(config.DB_AUTH)
    rows = conn.execute(
        "SELECT * FROM keys ORDER BY created DESC LIMIT ?", (int(limit),)
    ).fetchall()
    conn.close()
    out = []
    for row in rows:
        if not include_device and (
            row["key"].startswith("FREE-") or row["key"].startswith("GHOST-")
        ):
            continue
        out.append(_license_from_row(row, None, resolve_role=False))
    return out


def revoke_key(key: str, actor: str = "admin") -> bool:
    conn = database._get_conn(config.DB_AUTH)
    cur = conn.execute("UPDATE keys SET revoked=1 WHERE key=?", ((key or "").strip(),))
    conn.commit()
    conn.close()
    ok = cur.rowcount > 0
    if ok:
        audit(actor, "revoke_key", key)
    return ok


def unrevoke_key(key: str, actor: str = "admin") -> bool:
    conn = database._get_conn(config.DB_AUTH)
    cur = conn.execute("UPDATE keys SET revoked=0 WHERE key=?", ((key or "").strip(),))
    conn.commit()
    conn.close()
    ok = cur.rowcount > 0
    if ok:
        audit(actor, "unrevoke_key", key)
    return ok


def reset_hwid(key: str, actor: str = "admin") -> bool:
    conn = database._get_conn(config.DB_AUTH)
    cur = conn.execute(
        "UPDATE keys SET hwid=NULL, bound_at=NULL WHERE key=?", ((key or "").strip(),)
    )
    conn.commit()
    conn.close()
    ok = cur.rowcount > 0
    if ok:
        audit(actor, "reset_hwid", key)
    return ok


def bind_hwid(key: str, hwid: str, actor: str = "admin") -> bool:
    conn = database._get_conn(config.DB_AUTH)
    cur = conn.execute(
        "UPDATE keys SET hwid=?, bound_at=? WHERE key=?",
        (hwid, _iso(), (key or "").strip()),
    )
    conn.commit()
    conn.close()
    ok = cur.rowcount > 0
    if ok:
        audit(actor, "bind_hwid", f"{key} -> {hwid}")
    return ok


def delete_key(key: str, actor: str = "admin") -> bool:
    key = (key or "").strip()
    if key.startswith(("FREE-", "GHOST-")):
        return False
    conn = database._get_conn(config.DB_AUTH)
    conn.execute("DELETE FROM credit_ledger WHERE key=?", (key,))
    cur = conn.execute("DELETE FROM keys WHERE key=?", (key,))
    conn.commit()
    conn.close()
    ok = cur.rowcount > 0
    if ok:
        audit(actor, "delete_key", key)
    return ok


def recent_audit(limit: int = 30) -> list:
    conn = database._get_conn(config.DB_AUTH)
    rows = conn.execute(
        "SELECT ts, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def recent_ledger(key: str, limit: int = 20) -> list:
    conn = database._get_conn(config.DB_AUTH)
    rows = conn.execute(
        "SELECT delta, balance, reason, created FROM credit_ledger "
        "WHERE key=? ORDER BY id DESC LIMIT ?",
        ((key or "").strip(), int(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def stats() -> dict:
    conn = database._get_conn(config.DB_AUTH)
    rows = conn.execute(
        "SELECT tier, COUNT(*) AS n, COALESCE(SUM(credits),0) AS credits "
        "FROM keys WHERE key NOT LIKE 'FREE-%' AND key NOT LIKE 'GHOST-%' GROUP BY tier"
    ).fetchall()
    devices = conn.execute(
        "SELECT COUNT(*) AS n FROM keys WHERE key LIKE 'FREE-%'"
    ).fetchone()["n"]
    conn.close()
    return {"tiers": {r["tier"]: {"count": r["n"], "credits": r["credits"]} for r in rows},
            "devices": devices}


def check_session() -> dict:
    if not config.SESSION_FILE.exists():
        return None
    try:
        data = json.loads(config.SESSION_FILE.read_text(encoding="utf-8"))
        if (time.time() - data["timestamp"]) >= SESSION_TTL:
            return None
        info = validate_key(data["key"], config.get_hwid())
        if not info.get("valid"):
            return info
        return info
    except Exception:
        return None


def save_session(key: str, hwid: str):
    data = {"key": key, "hwid": hwid, "timestamp": time.time()}
    try:
        config.SESSION_FILE.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def clear_session():
    try:
        if config.SESSION_FILE.exists():
            config.SESSION_FILE.unlink()
    except Exception:
        pass
