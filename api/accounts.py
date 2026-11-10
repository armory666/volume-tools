"""Accounts, one-time codes, sessions, keys and referrals."""

import datetime

from api import db, security, settings
from volume.core import emailer


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "auth_error"):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


# ---------------------------------------------------------------------------
# Users and tiers
# ---------------------------------------------------------------------------

def normalize_email(email: str) -> str:
    value = (email or "").strip().lower()
    if len(value) < 5 or "@" not in value or "." not in value.split("@")[-1]:
        raise AuthError("Enter a valid email address.", 422, "invalid_email")
    if len(value) > 254:
        raise AuthError("Email address is too long.", 422, "invalid_email")
    return value


def tier_rank(tier: str) -> int:
    try:
        return settings.TIER_ORDER.index((tier or "free").lower())
    except ValueError:
        return 0


def max_tier(left: str, right: str) -> str:
    return left if tier_rank(left) >= tier_rank(right) else right


def get_user(user_id: str) -> dict | None:
    return db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))


def get_user_by_email(email: str) -> dict | None:
    return db.query_one("SELECT * FROM users WHERE email = ?", (normalize_email(email),))


def ensure_user(email: str, referral: str = "") -> tuple[dict, bool]:
    """Return ``(user, created)``, provisioning a workspace on first sign-in."""
    email = normalize_email(email)
    existing = get_user_by_email(email)
    if existing:
        return existing, False

    now = security.iso()
    tier = "admin" if email in settings.ADMIN_EMAILS else "free"
    credits = settings.WELCOME_CREDITS
    referrer = None
    if referral:
        candidate = db.query_one(
            "SELECT * FROM users WHERE referral_code = ?", (referral.strip().upper(),)
        )
        if candidate and candidate["email"] != email:
            referrer = candidate
            credits += settings.REFERRED_CREDITS

    user_id = security.new_id("usr_")
    db.execute(
        "INSERT INTO users (id, email, tier, credits, paid_until, referral_code, "
        "referred_by, created, last_login) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            email,
            tier,
            credits,
            None,
            security.referral_code(email),
            referrer["id"] if referrer else None,
            now,
            None,
        ),
    )
    if referrer:
        db.execute(
            "INSERT INTO redemptions (id, user_id, kind, reference, credits, created) "
            "VALUES (?, ?, 'referral', ?, ?, ?)",
            (
                security.new_id("rdm_"),
                referrer["id"],
                user_id,
                settings.REFERRAL_CREDITS,
                now,
            ),
        )
        db.execute(
            "UPDATE users SET credits = credits + ? WHERE id = ?",
            (settings.REFERRAL_CREDITS, referrer["id"]),
        )
    user = get_user(user_id)
    audit(email, "account.create", f"tier={tier} credits={credits}")
    try:
        emailer.send_welcome(email, tier, credits)
    except Exception:
        pass
    return user, True


def is_admin(user: dict | None) -> bool:
    return bool(user) and (
        user.get("tier") == "admin"
        or (user.get("email") or "").lower() in settings.ADMIN_EMAILS
    )


def quota_limit(user: dict) -> int:
    if is_admin(user):
        return settings.TIER_LIMITS["admin"]
    return settings.TIER_LIMITS.get((user.get("tier") or "free").lower(), 15)


def used_today(user_id: str) -> int:
    day = security.utcnow().date().isoformat()
    row = db.query_one(
        "SELECT used FROM usage WHERE user_id = ? AND day = ?", (user_id, day)
    )
    return int(row["used"]) if row else 0


def consume_lookup(user: dict, cost: int = 1) -> dict:
    """Charge a lookup against the daily quota and the credit balance."""
    if is_admin(user):
        return {"charged": 0, "credits": int(user.get("credits") or 0)}

    limit = quota_limit(user)
    used = used_today(user["id"])
    if used >= limit:
        raise AuthError(
            f"Daily limit reached ({limit} lookups). Upgrade or try again tomorrow.",
            429,
            "quota_exceeded",
        )

    credits = int(user.get("credits") or 0)
    if cost > 0 and credits < cost:
        raise AuthError(
            "Out of credits. Redeem a key or invite another operator to earn more.",
            402,
            "no_credits",
        )
    if cost > 0:
        db.execute(
            "UPDATE users SET credits = credits - ? WHERE id = ?", (cost, user["id"])
        )

    day = security.utcnow().date().isoformat()
    row = db.query_one(
        "SELECT used FROM usage WHERE user_id = ? AND day = ?", (user["id"], day)
    )
    if row:
        db.execute(
            "UPDATE usage SET used = ? WHERE user_id = ? AND day = ?",
            (int(row["used"]) + 1, user["id"], day),
        )
    else:
        db.execute(
            "INSERT INTO usage (user_id, day, used) VALUES (?, ?, 1)",
            (user["id"], day),
        )

    remaining = limit - (used + 1)
    if remaining in {5, 1}:
        try:
            emailer.send_quota_warning(user["email"], used + 1, limit, user["tier"])
        except Exception:
            pass
    return {"charged": cost, "credits": credits - cost}


def grant_credits(user_id: str, credits: int, kind: str, reference: str = "") -> None:
    if credits <= 0:
        return
    db.execute(
        "UPDATE users SET credits = credits + ? WHERE id = ?", (credits, user_id)
    )
    db.execute(
        "INSERT INTO redemptions (id, user_id, kind, reference, credits, created) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (security.new_id("rdm_"), user_id, kind, reference, credits, security.iso()),
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit(actor: str, action: str, detail: str = "", ip: str = "") -> None:
    try:
        db.execute(
            "INSERT INTO audit_log (id, ts, actor, action, detail, ip) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (security.new_id("aud_"), security.iso(), actor, action, detail[:2000], ip),
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def issue_session(user: dict, request, remember: bool = False) -> str:
    token = security.new_token()
    now = security.utcnow()
    ttl = (
        datetime.timedelta(days=settings.REMEMBER_DAYS)
        if remember
        else datetime.timedelta(hours=settings.SESSION_TTL_HOURS)
    )
    user_agent = (request.headers.get("user-agent") or "")[:400]
    db.execute(
        "INSERT INTO sessions (id, token_hash, user_id, created, last_seen, expires, "
        "ip, user_agent, label, remember, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (
            security.new_id("ses_"),
            security.digest(token),
            user["id"],
            security.iso(now),
            security.iso(now),
            security.iso(now + ttl),
            security.client_ip(request),
            user_agent,
            security.device_label(user_agent),
            1 if remember else 0,
        ),
    )
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (security.iso(now), user["id"]))
    audit(user["email"], "auth.session", f"remember={remember}", security.client_ip(request))
    return token


def session_row(token: str) -> dict | None:
    if not token:
        return None
    return db.query_one(
        "SELECT * FROM sessions WHERE token_hash = ? AND revoked = 0",
        (security.digest(token),),
    )


def session_user(token: str) -> dict | None:
    row = session_row(token)
    if not row or security.expired(row["expires"]):
        return None
    db.execute(
        "UPDATE sessions SET last_seen = ? WHERE id = ?", (security.iso(), row["id"])
    )
    return get_user(row["user_id"])


def revoke_session(token: str) -> None:
    row = session_row(token)
    if row:
        db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (row["id"],))


def list_sessions(user_id: str, current_token: str = "") -> list[dict]:
    current_hash = security.digest(current_token) if current_token else ""
    rows = db.query(
        "SELECT * FROM sessions WHERE user_id = ? AND revoked = 0 ORDER BY last_seen DESC",
        (user_id,),
    )
    now = security.utcnow()
    result = []
    for row in rows:
        if security.parse(row["expires"]) and security.parse(row["expires"]) <= now:
            continue
        result.append(
            {
                "id": row["id"],
                "label": row["label"] or "Browser",
                "ip": row["ip"],
                "user_agent": row["user_agent"],
                "created": row["created"],
                "last_seen": row["last_seen"],
                "expires": row["expires"],
                "remember": bool(row["remember"]),
                "current": bool(current_hash) and row["token_hash"] == current_hash,
            }
        )
    return result


def revoke_session_by_id(user_id: str, session_id: str) -> bool:
    return (
        db.execute(
            "UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?",
            (session_id, user_id),
        )
        > 0
    )


# ---------------------------------------------------------------------------
# One-time codes
# ---------------------------------------------------------------------------

def request_code(email: str, ip: str, referral: str = "") -> dict:
    email = normalize_email(email)
    allowed, retry = security.rate_limit(
        f"otp:email:{email}", settings.OTP_EMAIL_LIMIT, settings.OTP_WINDOW_SECONDS
    )
    if not allowed:
        raise AuthError(
            f"Too many codes requested. Try again in {retry} seconds.", 429, "rate_limited"
        )
    allowed, retry = security.rate_limit(
        f"otp:ip:{ip}", settings.OTP_IP_LIMIT, settings.OTP_WINDOW_SECONDS
    )
    if not allowed:
        raise AuthError(
            f"Too many requests from this address. Try again in {retry} seconds.",
            429,
            "rate_limited",
        )

    existing = db.query_one(
        "SELECT created FROM otp_codes WHERE email = ? AND purpose = 'login'", (email,)
    )
    if existing and not security.expired(existing["created"]):
        created = security.parse(existing["created"])
        elapsed = (security.utcnow() - created).total_seconds()
        if elapsed < settings.OTP_RESEND_SECONDS:
            wait = int(settings.OTP_RESEND_SECONDS - elapsed) + 1
            raise AuthError(
                f"Please wait {wait} seconds before requesting another code.",
                429,
                "resend_cooldown",
            )

    code = security.generate_otp()
    salt = security.new_token()
    expires = security.iso(
        security.utcnow() + datetime.timedelta(minutes=settings.OTP_TTL_MINUTES)
    )
    db.execute(
        "INSERT INTO otp_codes (email, purpose, code_hash, salt, expires, attempts, "
        "consumed, created, ip, referral) VALUES (?, 'login', ?, ?, ?, 0, 0, ?, ?, ?) "
        "ON CONFLICT (email, purpose) DO UPDATE SET code_hash = ?, salt = ?, expires = ?, "
        "attempts = 0, consumed = 0, created = ?, ip = ?, referral = ?",
        (
            email,
            security.hash_code(email, code, salt),
            salt,
            expires,
            security.iso(),
            ip,
            referral.strip().upper()[:16],
            security.hash_code(email, code, salt),
            salt,
            expires,
            security.iso(),
            ip,
            referral.strip().upper()[:16],
        ),
    )

    delivery = emailer.send_otp(email, code, settings.OTP_TTL_MINUTES)
    audit(email, "auth.otp.request", f"delivery={delivery.get('provider')}", ip)
    if not delivery.get("ok"):
        raise AuthError(
            "Email delivery is not configured. Set VOLUME_EMAIL_PROVIDER and credentials.",
            503,
            "email_unavailable",
        )

    result = {
        "ok": True,
        "masked_email": security.mask_email(email),
        "resend_after": settings.OTP_RESEND_SECONDS,
        "expires_in": settings.OTP_TTL_MINUTES * 60,
        "provider": delivery.get("provider"),
    }
    if settings.EMAIL_IS_CONSOLE and settings.DEV_CODES:
        # Opt-in only. Console mode always logs the code; an API response must
        # never expose it on a public deployment.
        result["dev_code"] = code
    return result


def verify_code(email: str, code: str, request, remember: bool = False) -> tuple[str, dict]:
    email = normalize_email(email)
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != 6:
        raise AuthError("Enter the six-digit code.", 422, "invalid_code")

    ip = security.client_ip(request)
    allowed, retry = security.rate_limit(f"verify:ip:{ip}", 20, 600)
    if not allowed:
        raise AuthError(
            f"Too many attempts. Try again in {retry} seconds.", 429, "rate_limited"
        )

    row = db.query_one(
        "SELECT * FROM otp_codes WHERE email = ? AND purpose = 'login'", (email,)
    )
    if not row or row["consumed"] or security.expired(row["expires"]):
        raise AuthError("That code has expired. Request a new one.", 401, "code_expired")
    if int(row["attempts"]) >= settings.OTP_MAX_ATTEMPTS:
        raise AuthError("Too many incorrect attempts. Request a new code.", 429, "too_many_attempts")

    expected = security.hash_code(email, code, row["salt"])
    if not security.constant_time_equal(expected, row["code_hash"]):
        db.execute(
            "UPDATE otp_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = 'login'",
            (email,),
        )
        remaining = settings.OTP_MAX_ATTEMPTS - int(row["attempts"]) - 1
        raise AuthError(
            f"Incorrect code. {max(0, remaining)} attempts left.", 401, "wrong_code"
        )

    db.execute(
        "UPDATE otp_codes SET consumed = 1 WHERE email = ? AND purpose = 'login'", (email,)
    )
    user, created = ensure_user(email, row.get("referral") or "")
    token = issue_session(user, request, remember=remember)
    audit(email, "auth.otp.verify", "new_user" if created else "returning", ip)
    return token, user


# ---------------------------------------------------------------------------
# Magic links
# ---------------------------------------------------------------------------

def request_magic_link(email: str, ip: str) -> dict:
    email = normalize_email(email)
    allowed, retry = security.rate_limit(f"magic:{email}", 3, 900)
    if not allowed:
        raise AuthError(
            f"Too many links requested. Try again in {retry} seconds.", 429, "rate_limited"
        )
    token = security.new_token()
    db.execute(
        "INSERT INTO magic_links (id, email, token_hash, expires, consumed, created) "
        "VALUES (?, ?, ?, ?, 0, ?)",
        (
            security.new_id("mag_"),
            email,
            security.digest(token),
            security.iso(
                security.utcnow() + datetime.timedelta(minutes=settings.MAGIC_TTL_MINUTES)
            ),
            security.iso(),
        ),
    )
    url = f"{settings.PUBLIC_BASE_URL}/api/auth/magic/consume?token={token}"
    delivery = emailer.send_magic_link(email, url, settings.MAGIC_TTL_MINUTES)
    audit(email, "auth.magic.request", f"delivery={delivery.get('provider')}", ip)
    if not delivery.get("ok"):
        raise AuthError("Email delivery is not configured.", 503, "email_unavailable")
    result = {"ok": True, "expires_in": settings.MAGIC_TTL_MINUTES * 60}
    if settings.EMAIL_IS_CONSOLE and settings.DEV_CODES:
        result["dev_link"] = url
    return result


def consume_magic_token(token: str, request) -> str:
    token = (token or "").strip()
    if not token:
        raise AuthError("Missing link token.", 400, "invalid_token")
    row = db.query_one("SELECT * FROM magic_links WHERE token_hash = ?", (security.digest(token),))
    if not row or row["consumed"] or security.expired(row["expires"]):
        raise AuthError("That sign-in link has expired.", 401, "link_expired")
    db.execute("UPDATE magic_links SET consumed = 1 WHERE id = ?", (row["id"],))
    user, _ = ensure_user(row["email"])
    session = issue_session(user, request, remember=True)
    audit(row["email"], "auth.magic.consume", "", security.client_ip(request))
    return session


# ---------------------------------------------------------------------------
# Access keys, credits and referrals
# ---------------------------------------------------------------------------

def redeem_access_key(user: dict, raw_key: str, ip: str = "") -> dict:
    key = (raw_key or "").strip().upper()
    if not key:
        raise AuthError("Enter an access key.", 422, "invalid_key")
    row = db.query_one(
        "SELECT * FROM access_keys WHERE key_hash = ?", (security.digest(key),)
    )
    if not row:
        raise AuthError("That key is not recognised.", 404, "unknown_key")
    if row["redeemed_by"] and row["redeemed_by"] != user["id"]:
        raise AuthError("That key has already been redeemed.", 409, "key_used")
    if row["redeemed_by"] == user["id"]:
        return {"ok": True, "tier": user["tier"], "credits": user["credits"], "already": True}

    now = security.iso()
    db.execute(
        "UPDATE access_keys SET redeemed_by = ?, redeemed_at = ? WHERE id = ?",
        (user["id"], now, row["id"]),
    )
    tier = max_tier(user.get("tier") or "free", row["tier"] or "premium")
    db.execute("UPDATE users SET tier = ? WHERE id = ?", (tier, user["id"]))
    grant_credits(user["id"], int(row["credits"] or 0), "access_key", row["id"])
    updated = get_user(user["id"])
    audit(user["email"], "key.redeem", f"tier={tier} credits={row['credits']}", ip)
    return {
        "ok": True,
        "tier": updated["tier"],
        "credits": updated["credits"],
        "granted": int(row["credits"] or 0),
    }


def redeem_credit_key(user: dict, raw_key: str, ip: str = "") -> dict:
    # Access keys and credit keys share one store; label decides the outcome.
    return redeem_access_key(user, raw_key, ip)


def key_login(raw_key: str, request) -> tuple[str, dict]:
    """Sign in with nothing but an access key.

    Unredeemed keys provision a standalone workspace; keys that already belong
    to an account sign that account back in on a new device.
    """
    key = (raw_key or "").strip().upper()
    if not key:
        raise AuthError("Enter an access key.", 422, "invalid_key")
    row = db.query_one(
        "SELECT * FROM access_keys WHERE key_hash = ?", (security.digest(key),)
    )
    if not row:
        raise AuthError("That key is not recognised.", 404, "unknown_key")
    if row["expires"] and security.expired(row["expires"]):
        raise AuthError("That key has expired.", 401, "key_expired")

    if row["redeemed_by"]:
        user = get_user(row["redeemed_by"])
        if not user:
            raise AuthError("That key belongs to a deleted account.", 401, "unknown_key")
    else:
        now = security.iso()
        user_id = security.new_id("usr_")
        email = f"key-{row['id'][-10:]}@keys.volume.tools"
        tier = (row["tier"] or "premium").lower()
        db.execute(
            "INSERT INTO users (id, email, tier, credits, paid_until, referral_code, "
            "referred_by, created, last_login) VALUES (?, ?, ?, ?, NULL, ?, NULL, ?, NULL)",
            (
                user_id,
                email,
                tier,
                int(row["credits"] or 0),
                security.referral_code(email),
                now,
            ),
        )
        db.execute(
            "UPDATE access_keys SET redeemed_by = ?, redeemed_at = ? WHERE id = ?",
            (user_id, now, row["id"]),
        )
        db.execute(
            "INSERT INTO redemptions (id, user_id, kind, reference, credits, created) "
            "VALUES (?, ?, 'access_key', ?, ?, ?)",
            (
                security.new_id("rdm_"),
                user_id,
                row["id"],
                int(row["credits"] or 0),
                now,
            ),
        )
        user = get_user(user_id)
        audit(email, "key.login.provision", f"tier={tier}", security.client_ip(request))

    token = issue_session(user, request, remember=True)
    audit(user["email"], "key.login", "", security.client_ip(request))
    return token, user


def referral_summary(user: dict) -> dict:
    invited = db.query(
        "SELECT id, email, created FROM users WHERE referred_by = ? ORDER BY created DESC",
        (user["id"],),
    )
    earned = db.query_one(
        "SELECT COALESCE(SUM(credits), 0) AS total FROM redemptions "
        "WHERE user_id = ? AND kind = 'referral'",
        (user["id"],),
    )
    return {
        "code": user.get("referral_code") or security.referral_code(user["email"]),
        "invited": len(invited),
        "credits_earned": int(earned["total"]) if earned else 0,
        "referrals": [
            {
                "email": security.mask_email(row["email"]),
                "created": row["created"],
            }
            for row in invited
        ],
        "reward": settings.REFERRAL_CREDITS,
    }


def public_user(user: dict) -> dict:
    limit = quota_limit(user)
    used = used_today(user["id"])
    return {
        "id": user["id"],
        "email": user["email"],
        "tier": settings.TIER_LABELS.get(user["tier"], (user["tier"] or "free").upper()),
        "tier_key": user["tier"],
        "credits": int(user.get("credits") or 0),
        "paid_until": user.get("paid_until"),
        "admin": is_admin(user),
        "quota": {
            "daily_limit": limit,
            "used_today": used,
            "remaining": max(0, limit - used),
        },
        "referral_code": user.get("referral_code"),
    }
