"""VOLUME accounts: usernames, password hashing, profiles and registration.

The account layer is deliberately independent of the TUI.  A future web
front-end can call the same functions (register / authenticate / search) while
the license and credit engine in :mod:`volume.core.auth` stays authoritative.
"""

import datetime
import hashlib
import hmac
import re
import secrets

from volume.core import auth, config, database, licensing, roles

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_MIN = 8
PASSWORD_MAX = 128
PBKDF2_ITERATIONS = 260_000

# Names that would be confusing, impersonate staff, or collide with UI routes.
RESERVED = {
    "admin", "administrator", "root", "system", "volume", "support", "staff",
    "owner", "founder", "coowner", "co-owner", "manager", "council", "mod",
    "moderator", "official", "help", "api", "login", "register", "signup",
    "signin", "profile", "profiles", "search", "settings", "account", "me",
    "you", "null", "none", "undefined", "ghost", "armory", "wounds",
    "worthless", "pavement", "raken", "key", "keys", "license", "credits",
    "billing", "web", "www", "mail", "security",
}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


# ---------------------------------------------------------------------------
# Validation / password hashing
# ---------------------------------------------------------------------------


def validate_username(username: str, allow_founder: bool = False):
    username = (username or "").strip()
    if not USERNAME_RE.fullmatch(username):
        return False, "Username must be 3-20 characters: letters, numbers or underscore."
    lower = username.lower()
    if lower == config.get_founder_name().lower():
        if allow_founder:
            return True, ""
        return False, "That username is reserved for the founder."
    if lower in RESERVED:
        return False, "That username is reserved."
    return True, ""


def validate_password(password: str):
    password = password or ""
    if len(password) < PASSWORD_MIN:
        return False, f"Password must be at least {PASSWORD_MIN} characters."
    if len(password) > PASSWORD_MAX:
        return False, f"Password must be at most {PASSWORD_MAX} characters."
    if password.lower() in {"password", "12345678", "qwertyui", "letmein1"}:
        return False, "That password is too common."
    return True, ""


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("ascii"), PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, expected = str(stored or "").split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            (password or "").encode("utf-8"),
            salt.encode("ascii"),
            int(iterations),
        ).hex()
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Captcha
# ---------------------------------------------------------------------------

_CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_captcha(length: int = 6) -> str:
    return "".join(secrets.choice(_CAPTCHA_ALPHABET) for _ in range(length))


def captcha_ok(expected: str, answer: str) -> bool:
    return hmac.compare_digest(
        (expected or "").strip().upper(), (answer or "").strip().upper()
    )


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def _row_to_account(row, include_private: bool = False) -> dict:
    if row is None:
        return {}
    keys = row.keys()

    def _get(name, default=""):
        return row[name] if name in keys else default

    data = {
        "id": row["id"],
        "username": row["username"],
        "key": row["key"],
        "created": row["created"],
        "last_login": row["last_login"],
        "bio": row["bio"] or "",
        "role": roles.normalize_role(row["role"] or "member"),
        "role_granted_by": _get("role_granted_by", "") or "",
        "role_granted_at": _get("role_granted_at", "") or "",
        "banned": bool(row["banned"]),
    }
    if include_private:
        data["password_hash"] = row["password_hash"]
        data["hwid"] = row["hwid"] or ""
    return data


def get_account(username: str, include_private: bool = False) -> dict:
    username = (username or "").strip()
    if not username:
        return {}
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute(
        "SELECT * FROM accounts WHERE username_lower=?", (username.lower(),)
    ).fetchone()
    conn.close()
    return _row_to_account(row, include_private)


def account_for_key(key: str) -> dict:
    key = (key or "").strip()
    if not key:
        return {}
    conn = database._get_conn(config.DB_AUTH)
    row = conn.execute("SELECT * FROM accounts WHERE key=?", (key,)).fetchone()
    conn.close()
    return _row_to_account(row)


def account_role_for_key(key: str) -> str:
    """Role of the account that owns ``key`` (empty for unlinked keys)."""
    return account_for_key(key).get("role") or ""


def founder_configured() -> bool:
    return bool(config.get_founder_token())


def register(username: str, password: str, hwid: str, bio: str = "",
             founder_token: str = "") -> dict:
    """Create an account and mint its FREE license key.

    Returns ``{"ok": bool, ...}``.  Usernames are unique case-insensitively and
    the check is performed inside an immediate transaction to avoid races.

    The founder username is reserved and requires ``VOLUME_FOUNDER_TOKEN``.  A
    successful founder registration stores the permanent ``founder`` role,
    which grants admin and unlimited credits independent of the license tier.
    """
    username = (username or "").strip()
    is_founder = username.lower() == config.get_founder_name().lower()
    ok, reason = validate_username(username, allow_founder=is_founder)
    if not ok:
        return {"ok": False, "error": reason}
    ok, reason = validate_password(password)
    if not ok:
        return {"ok": False, "error": reason}

    role = "member"
    if is_founder:
        expected = config.get_founder_token()
        if not expected:
            return {
                "ok": False,
                "error": "Founder registration is locked. Set VOLUME_FOUNDER_TOKEN in .env.",
            }
        if not hmac.compare_digest((founder_token or "").strip(), expected):
            return {"ok": False, "error": "Invalid founder token."}
        role = "founder"

    key = auth.generate_key(
        tier="FREE",
        days=0,
        note=f"account:{username}",
        hwid=hwid,
    )

    conn = database._get_conn(config.DB_AUTH)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        exists = conn.execute(
            "SELECT 1 FROM accounts WHERE username_lower=?", (username.lower(),)
        ).fetchone()
        if exists:
            conn.execute("ROLLBACK")
            auth.delete_key(key, actor="system")
            return {"ok": False, "error": "That username is already claimed."}
        if role == "founder":
            # Exactly one founder: demote any stale founder row.
            conn.execute(
                "UPDATE accounts SET role='admin' WHERE role='founder' AND username_lower<>?",
                (username.lower(),),
            )
        conn.execute(
            "INSERT INTO accounts (username, username_lower, password_hash, key, "
            "created, last_login, bio, hwid, role, role_granted_by, role_granted_at, banned) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                username,
                username.lower(),
                hash_password(password),
                key,
                _now(),
                _now(),
                (bio or "").strip()[:400],
                hwid,
                role,
                "founder-token" if role == "founder" else "",
                _now() if role == "founder" else None,
            ),
        )
        conn.execute("COMMIT")
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        conn.close()
        auth.delete_key(key, actor="system")
        return {"ok": False, "error": f"Could not create account: {exc}"}
    conn.close()

    auth.audit(username, "account_register", f"key={key} role={role}")
    info = auth.validate_key(key, hwid)
    info.update({"username": username, "role": role, "account": True})
    return {
        "ok": True,
        "username": username,
        "key": key,
        "role": role,
        "tier": info.get("tier"),
        "credits": info.get("credits"),
        "info": info,
        "error": "",
    }


def authenticate(username: str, password: str, hwid: str) -> dict:
    """Password sign-in on the account's original device."""
    account = get_account(username, include_private=True)
    if not account:
        return {"ok": False, "error": "No account with that username."}
    if account.get("banned"):
        return {"ok": False, "error": "This account is suspended."}
    if not verify_password(password, account.get("password_hash", "")):
        auth.audit(username, "account_login_failed", "bad password")
        return {"ok": False, "error": "Incorrect password."}

    info = auth.validate_key(account["key"], hwid)
    if not info.get("valid"):
        reason = info.get("reason") or "license rejected"
        return {
            "ok": False,
            "error": f"Account found, but its key is not usable here: {reason}",
            "key": account["key"],
        }

    touch_login(account["username"])
    auth.audit(account["username"], "account_login", "password")
    role = roles.normalize_role(account.get("role") or "member")
    info.update({
        "username": account["username"],
        "role": role,
        "founder": roles.is_founder(role),
        "staff": roles.is_staff(role),
        "admin": bool(info.get("admin")) or roles.is_admin(role),
        "account": True,
    })
    return {"ok": True, "info": info, "username": account["username"], "error": ""}


def touch_login(username: str):
    try:
        conn = database._get_conn(config.DB_AUTH)
        conn.execute(
            "UPDATE accounts SET last_login=? WHERE username_lower=?",
            (_now(), (username or "").lower()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def update_profile(username: str, bio=None, role=None, banned=None) -> bool:
    account = get_account(username)
    if not account:
        return False
    fields = []
    values = []
    if bio is not None:
        fields.append("bio=?")
        values.append(str(bio)[:400])
    if role is not None:
        fields.append("role=?")
        values.append(str(role)[:32])
    if banned is not None:
        fields.append("banned=?")
        values.append(1 if banned else 0)
    if not fields:
        return True
    values.append(account["username"].lower())
    conn = database._get_conn(config.DB_AUTH)
    conn.execute(
        f"UPDATE accounts SET {', '.join(fields)} WHERE username_lower=?", values
    )
    conn.commit()
    conn.close()
    return True


def public_profile(username: str) -> dict:
    account = get_account(username)
    if not account:
        return {}
    info = auth.get_license(account["key"], config.get_hwid())
    cases = 0
    findings = 0
    try:
        for row in database.list_cases():
            if (row.get("analyst") or "").lower() == account["username"].lower():
                cases += 1
                findings += int(row.get("findings") or 0)
    except Exception:
        pass
    return {
        "username": account["username"],
        "created": account["created"],
        "last_login": account["last_login"],
        "bio": account["bio"],
        "role": account["role"],
        "admin": roles.is_admin(account["role"]) or bool(info.get("admin")),
        "founder": roles.is_founder(account["role"]),
        "staff": roles.is_staff(account["role"]),
        "banned": account["banned"],
        "tier": info.get("tier", "FREE"),
        "credits": info.get("credits"),
        "unlimited": bool(info.get("unlimited")),
        "key_suffix": account["key"][-4:] if account.get("key") else "",
        "cases": cases,
        "findings": findings,
        "profile_url": f"/u/{account['username']}",
    }


def search_profiles(query: str, limit: int = 25) -> list:
    query = (query or "").strip()
    if not query:
        return []
    like = f"%{query}%"
    conn = database._get_conn(config.DB_AUTH)
    rows = conn.execute(
        "SELECT username FROM accounts "
        "WHERE username_lower LIKE ? OR bio LIKE ? "
        "ORDER BY CASE WHEN username_lower=? THEN 0 ELSE 1 END, username_lower "
        "LIMIT ?",
        (like, like, query.lower(), int(limit)),
    ).fetchall()
    conn.close()
    return [public_profile(row["username"]) for row in rows]


def list_accounts(limit: int = 200) -> list:
    conn = database._get_conn(config.DB_AUTH)
    rows = conn.execute(
        "SELECT username FROM accounts ORDER BY created DESC LIMIT ?", (int(limit),)
    ).fetchall()
    conn.close()
    return [public_profile(row["username"]) for row in rows]


# ---------------------------------------------------------------------------
# Staff roles / founder / key issuing (founder & admin operations)
# ---------------------------------------------------------------------------


def set_role(username: str, role: str, actor: str = "admin",
             actor_role: str = "founder") -> dict:
    """Change an account's permanent role.

    The actor must outrank the target and be allowed to grant the new role.
    ``founder`` cannot be granted here; use :func:`claim_founder` so there is
    always exactly one owner.
    """
    account = get_account(username)
    if not account:
        return {"ok": False, "error": "No such account."}
    target = roles.normalize_role(role)
    if target == "founder":
        return {"ok": False, "error": "Use the founder token to transfer founder."}
    if account.get("role") == "founder":
        return {"ok": False, "error": "The founder role cannot be changed here."}
    if not roles.can_grant(actor_role, target):
        return {"ok": False, "error": f"{actor_role} cannot grant {target}."}
    if roles.role_rank(actor_role) <= roles.role_rank(account.get("role")):
        return {"ok": False, "error": "You cannot modify an account at or above your rank."}

    conn = database._get_conn(config.DB_AUTH)
    conn.execute(
        "UPDATE accounts SET role=?, role_granted_by=?, role_granted_at=? "
        "WHERE username_lower=?",
        (target, actor, _now(), account["username"].lower()),
    )
    conn.commit()
    conn.close()
    auth.audit(actor, "set_role", f"{account['username']} -> {target}")
    return {"ok": True, "username": account["username"], "role": target}


def grant_admin(username: str, actor: str = "admin",
                actor_role: str = "founder") -> dict:
    """Give an account permanent admin (founder only)."""
    return set_role(username, "admin", actor=actor, actor_role=actor_role)


def revoke_admin(username: str, actor: str = "admin",
                 actor_role: str = "founder") -> dict:
    """Remove admin from an account and return it to member (founder only)."""
    return set_role(username, "member", actor=actor, actor_role=actor_role)


def claim_founder(username: str, token: str, actor: str = "") -> dict:
    """Promote an existing account to founder using ``VOLUME_FOUNDER_TOKEN``."""
    account = get_account(username)
    if not account:
        return {"ok": False, "error": "No such account."}
    expected = config.get_founder_token()
    if not expected:
        return {
            "ok": False,
            "error": "Founder token is not configured. Set VOLUME_FOUNDER_TOKEN in .env.",
        }
    if not hmac.compare_digest((token or "").strip(), expected):
        return {"ok": False, "error": "Invalid founder token."}

    actor = actor or account["username"]
    conn = database._get_conn(config.DB_AUTH)
    conn.execute(
        "UPDATE accounts SET role='admin' WHERE role='founder' AND username_lower<>?",
        (account["username"].lower(),),
    )
    conn.execute(
        "UPDATE accounts SET role='founder', role_granted_by=?, role_granted_at=? "
        "WHERE username_lower=?",
        (actor, _now(), account["username"].lower()),
    )
    conn.commit()
    conn.close()
    auth.audit(actor, "claim_founder", account["username"])
    return {"ok": True, "username": account["username"], "role": "founder"}


def issue_key(username: str, tier: str = "FREE", days: int = 0, credits=None,
              note: str = "", actor: str = "admin", replace: bool = True) -> dict:
    """Mint a key and assign it to an account, revoking the previous one."""
    account = get_account(username)
    if not account:
        return {"ok": False, "error": "No such account."}
    tier = licensing.normalize_tier(tier)
    try:
        new_key = auth.generate_key(
            tier=tier,
            days=days,
            credits=credits,
            note=note or f"issued to {account['username']}",
        )
    except Exception as exc:
        return {"ok": False, "error": f"Could not mint key: {exc}"}

    old_key = account.get("key") or ""
    conn = database._get_conn(config.DB_AUTH)
    conn.execute(
        "UPDATE accounts SET key=? WHERE username_lower=?",
        (new_key, account["username"].lower()),
    )
    conn.commit()
    conn.close()

    if replace and old_key and old_key != new_key:
        auth.revoke_key(old_key, actor=actor)
    auth.audit(
        actor, "issue_key",
        f"{account['username']} -> {new_key} tier={tier} days={days}",
    )
    return {
        "ok": True,
        "username": account["username"],
        "key": new_key,
        "old_key": old_key,
        "tier": tier,
        "credits": credits,
        "days": days,
    }


def reissue_key(username: str, actor: str = "admin") -> dict:
    """Replace an account's key while preserving its current tier and expiry."""
    account = get_account(username)
    if not account:
        return {"ok": False, "error": "No such account."}
    info = auth.get_license(account["key"])
    tier = info.get("tier", "FREE")
    days = int(info.get("days_left") or 0)
    return issue_key(
        username, tier=tier, days=days, note=f"reissued to {account['username']}",
        actor=actor, replace=True,
    )


def set_banned(username: str, banned: bool = True, actor: str = "admin",
               actor_role: str = "founder") -> dict:
    """Suspend or restore an account. Returns a result dict."""
    account = get_account(username)
    if not account:
        return {"ok": False, "error": "No such account."}
    if account.get("role") == "founder":
        return {"ok": False, "error": "The founder cannot be suspended."}
    if not roles.can_moderate(actor_role, account.get("role")):
        return {"ok": False, "error": "You cannot moderate an account at or above your rank."}
    update_profile(username, banned=banned)
    auth.audit(actor, "ban" if banned else "unban", account["username"])
    return {"ok": True, "username": account["username"], "banned": bool(banned)}


def stats() -> dict:
    conn = database._get_conn(config.DB_AUTH)
    total = conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"]
    banned = conn.execute(
        "SELECT COUNT(*) AS n FROM accounts WHERE banned=1"
    ).fetchone()["n"]
    newest = conn.execute(
        "SELECT username, created FROM accounts ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return {
        "total": total,
        "banned": banned,
        "newest": dict(newest) if newest else None,
    }
