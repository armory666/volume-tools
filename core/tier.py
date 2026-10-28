import sqlite3, datetime, os, uuid, secrets
from contextlib import contextmanager

DB = os.environ.get("VOLUME_DB", "volume.db")

FREE_SOURCES = {"holehe", "gravatar", "ipapi", "internetdb", "bgphe", "crtsh"}
FREE_KINDS   = {"email", "username", "ip"}
FREE_DAILY   = 5
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

# --- KEY SYSTEM ---

def generate_key():
    raw = secrets.token_hex(6).upper()
    return f"VOL-{raw[:4]}-{raw[4:8]}-{raw[8:12]}"

def create_key(user_id, days):
    k = generate_key()
    now = datetime.datetime.utcnow().isoformat()
    with db() as c:
        c.execute(
            "INSERT INTO keys (key, user_id, duration_days, created_at) "
            "VALUES (?, ?, ?, ?)",
            (k, user_id, days, now)
        )
    return k

def redeem_key(user_id, key):
    now = datetime.datetime.utcnow()
    now_str = now.isoformat()
    with db() as c:
        row = c.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
        if not row:
            return False, "Key not found."
            
        if row["redeemed_at"]:
            if row["user_id"] != user_id:
                return False, "This key has already been redeemed by another user."
            if row["expires_at"] and row["expires_at"] < now_str:
                return False, "This key has expired."
            return True, "Already active."
            
        expires_str = (now + datetime.timedelta(days=row["duration_days"])).isoformat()
        c.execute(
            "UPDATE keys SET redeemed_at=?, expires_at=? WHERE key=?",
            (now_str, expires_str, key)
        )
        c.execute(
            "UPDATE users SET tier='premium', paid_until=? WHERE id=?",
            (expires_str, user_id)
        )
    return True, expires_str
