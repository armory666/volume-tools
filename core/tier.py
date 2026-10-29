import sqlite3, datetime, os, uuid, secrets
from contextlib import contextmanager

DB = os.environ.get("VOLUME_DB", "volume.db")

FREE_SOURCES = {"holehe", "gravatar", "ipapi", "internetdb", "bgphe", "crtsh"}
FREE_KINDS   = {"email", "username", "ip"}
FREE_DAILY   = 15
PREMIUM_DAILY = 200

TIERS = {
    "free":    {"sources": FREE_SOURCES, "kinds": FREE_KINDS, "daily": FREE_DAILY},
    "premium": {"sources": "*", "kinds": "*", "daily": PREMIUM_DAILY},
    "admin":   {"sources": "*", "kinds": "*", "daily": 10**9},
}

@contextmanager
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()

def init_db():
    with db() as c:
        c.executescript(open("core/db.sql").read())

def get_user(uid=None, tg=None, email=None):
    with db() as c:
        if uid:
            r = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        elif tg:
            r = c.execute("SELECT * FROM users WHERE telegram_id=?", (tg,)).fetchone()
        elif email:
            r = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        else:
            return None
        return dict(r) if r else None

def get_or_create(tg=None, email=None):
    u = get_user(tg=tg, email=email)
    if u:
        return u
    uid = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    with db() as c:
        c.execute(
            "INSERT INTO users(id, telegram_id, email, created_at, last_seen) "
            "VALUES(?,?,?,?,?)", (uid, tg, email, now, now))
    return get_user(uid=uid)

def tier_of(user):
    if user["tier"] == "admin":
        return "admin"
    if user["tier"] == "premium":
        if user["paid_until"] and user["paid_until"] >= datetime.date.today().isoformat():
            return "premium"
        with db() as c:
            c.execute("UPDATE users SET tier='free' WHERE id=?", (user["id"],))
        return "free"
    return "free"

def tier_of_admin_safe(user, hardcoded_admin_id):
    if user["tier"] == "admin":
        if user.get("telegram_id") == hardcoded_admin_id:
            return "admin"
        if user["paid_until"] and user["paid_until"] >= datetime.date.today().isoformat():
            return "admin"
        with db() as c:
            c.execute("UPDATE users SET tier='free' WHERE id=?", (user["id"],))
        return "free"
    return tier_of(user)

def today():
    return datetime.date.today().isoformat()

def usage_today(user_id):
    with db() as c:
        r = c.execute("SELECT queries FROM usage WHERE user_id=? AND day=?",
                      (user_id, today())).fetchone()
        return r["queries"] if r else 0

def bump_usage(user_id):
    with db() as c:
        c.execute(
            "INSERT INTO usage(user_id, day, queries) VALUES(?,?,1) "
            "ON CONFLICT(user_id, day) DO UPDATE SET queries = queries + 1",
            (user_id, today()))

def check(user, kind):
    tier = tier_of(user)
    limits = TIERS[tier]
    if limits["kinds"] != "*" and kind not in limits["kinds"]:
        return False, f"kind '{kind}' requires premium"
    if usage_today(user["id"]) >= limits["daily"]:
        return False, f"daily limit reached ({limits['daily']}). upgrade for more."
    return True, None

def allowed_sources(user, all_sources):
    tier = tier_of(user)
    if TIERS[tier]["sources"] == "*":
        return all_sources
    return [s for s in all_sources if getattr(s, "name", "") in TIERS[tier]["sources"]]

def grant_premium(user_id, days=30, provider="stars", provider_id=None, amount=None):
    paid_until = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    with db() as c:
        c.execute("UPDATE users SET tier='premium', paid_until=? WHERE id=?",
                  (paid_until, user_id))
        c.execute(
            "INSERT INTO payments(id, user_id, provider, provider_id, "
            "amount_cents, tier_days, created_at) VALUES(?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), user_id, provider,
             provider_id or str(uuid.uuid4()), amount or 0, days,
             datetime.datetime.utcnow().isoformat()))
    return paid_until

def generate_key(prefix="PERM"):
    raw = secrets.token_hex(6).upper()
    return f"{prefix}-{raw[:4]}-{raw[4:8]}-{raw[8:12]}"

def create_key(kind="premium"):
    prefix = "ADMIN" if kind == "admin" else "PERM"
    k = generate_key(prefix)
    now = datetime.datetime.utcnow().isoformat()
    with db() as c:
        c.execute("INSERT INTO keys (key, kind, created_at) VALUES (?, ?, ?)", (k, kind, now))
    return k

def redeem_key(user_id, key):
    now_str = datetime.datetime.utcnow().isoformat()
    with db() as c:
        row = c.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
        if not row:
            return False, "Key not found."
        if row["revoked"]:
            return False, "This key has been revoked."
        if row["redeemed_at"]:
            if row["user_id"] != user_id:
                return False, "This key has already been redeemed."
            return True, "Already active on this account."
        kind = row["kind"]
        if kind == "admin":
            paid_until = (datetime.date.today() + datetime.timedelta(days=36500)).isoformat()
            c.execute("UPDATE users SET tier='admin', paid_until=? WHERE id=?", (paid_until, user_id))
            msg = "Permanent Admin access granted."
        else:
            paid_until = (datetime.date.today() + datetime.timedelta(days=36500)).isoformat()
            c.execute("UPDATE users SET tier='premium', paid_until=? WHERE id=?", (paid_until, user_id))
            msg = "Permanent Premium access granted."
        c.execute("UPDATE keys SET user_id=?, redeemed_at=? WHERE key=?", (user_id, now_str, key))
    return True, msg

def create_session(user_id, days=30):
    token = secrets.token_urlsafe(32)
    now = datetime.datetime.utcnow()
    expires = (now + datetime.timedelta(days=days)).isoformat()
    with db() as c:
        c.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, now.isoformat(), expires))
    return token

def get_session_user(token):
    if not token:
        return None
    with db() as c:
        row = c.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)
        ).fetchone()
    if not row:
        return None
    if row["expires_at"] < datetime.datetime.utcnow().isoformat():
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
        return None
    return get_user(uid=row["user_id"])

def revoke_session(token):
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))

def get_or_create_referral(user_id):
    with db() as c:
        row = c.execute(
            "SELECT code FROM referrals WHERE owner_id=? AND used_by IS NULL LIMIT 1",
            (user_id,)
        ).fetchone()
        if row:
            return row["code"]
        total = c.execute(
            "SELECT COUNT(*) FROM referrals WHERE owner_id=?", (user_id,)
        ).fetchone()[0]
        if total >= 3:
            first = c.execute(
                "SELECT code FROM referrals WHERE owner_id=? LIMIT 1", (user_id,)
            ).fetchone()
            return first["code"] if first else None
        code = "VOL-REF-" + secrets.token_hex(3).upper()
        now = datetime.datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO referrals (id, code, owner_id, created_at, reward_days) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), code, user_id, now, 30))
        return code

def claim_referral_code(user_id, email, code):
    now_str = datetime.datetime.utcnow().isoformat()
    code = code.strip().upper()
    with db() as c:
        already = c.execute(
            "SELECT 1 FROM referral_claims WHERE user_id=?", (user_id,)
        ).fetchone()
        if already:
            return False, "You have already claimed a referral code."
        row = c.execute("SELECT * FROM referrals WHERE code=?", (code,)).fetchone()
        if not row:
            return False, "Referral code not found."
        if row["owner_id"] == user_id:
            return False, "You cannot use your own referral code."
        if row["used_by"]:
            return False, "That code has already been used."
        owner_count = c.execute(
            "SELECT COUNT(*) FROM referrals WHERE owner_id=? AND used_by IS NOT NULL",
            (row["owner_id"],)
        ).fetchone()[0]
        if owner_count >= 3:
            return False, "That user has reached their referral limit."
        c.execute(
            "UPDATE referrals SET used_by=?, used_at=? WHERE code=?",
            (user_id, now_str, code))
        c.execute(
            "INSERT INTO referral_claims (id, user_id, code, days_granted, claimed_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), user_id, code, 15, now_str))
        c.execute(
            "INSERT INTO referral_claims (id, user_id, code, days_granted, claimed_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), row["owner_id"], code, 30, now_str))
    grant_premium(user_id, days=15, provider="referral", provider_id=code)
    grant_premium(row["owner_id"], days=30, provider="referral", provider_id=code)
    return True, "Referral accepted. You have 15 days of premium."

def get_referral_stats(user_id):
    with db() as c:
        total = c.execute(
            "SELECT COUNT(*) FROM referrals WHERE owner_id=?", (user_id,)
        ).fetchone()[0]
        used = c.execute(
            "SELECT COUNT(*) FROM referrals WHERE owner_id=? AND used_by IS NOT NULL",
            (user_id,)
        ).fetchone()[0]
        earned = c.execute(
            "SELECT COALESCE(SUM(days_granted), 0) FROM referral_claims "
            "WHERE user_id=? AND code IN (SELECT code FROM referrals WHERE owner_id=?)",
            (user_id, user_id)
        ).fetchone()[0]
    return {
        "total": total,
        "used": used,
        "earned_days": earned,
        "remaining_slots": max(0, 3 - total),
    }
