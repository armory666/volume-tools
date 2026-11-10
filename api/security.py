"""Tokens, one-time-code hashing and in-process rate limiting."""

import datetime
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from api import settings

_WINDOW_LOCK = threading.Lock()
_WINDOWS: dict[str, deque] = defaultdict(deque)


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def iso(moment: datetime.datetime | None = None) -> str:
    return (moment or utcnow()).isoformat()


def parse(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    try:
        moment = datetime.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment


def expired(value: str | None) -> bool:
    moment = parse(value)
    return moment is None or moment <= utcnow()


def new_id(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(10)}"


def new_token() -> str:
    return secrets.token_urlsafe(32)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_code(email: str, code: str, salt: str) -> str:
    material = f"{email.strip().lower()}:{code}:{salt}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(str(left), str(right))


def generate_otp() -> str:
    # secrets.randbelow keeps the distribution uniform and avoids modulo bias.
    return f"{secrets.randbelow(1_000_000):06d}"


def generate_access_key() -> str:
    # Avoid characters that are easy to misread (0/O, 1/I/L).
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "VOL-" + "-".join(groups)


def mask_email(email: str) -> str:
    email = (email or "").strip()
    if "@" not in email:
        return email[:1] + "***" if email else ""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        visible = local[:1]
    else:
        visible = local[:2]
    return f"{visible}{'*' * max(3, len(local) - len(visible))}@{domain}"


def referral_code(email: str) -> str:
    seed = f"{email.strip().lower()}|volume-referral"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8].upper()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def rate_limit(bucket: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    """Sliding-window limiter. Returns ``(allowed, retry_after_seconds)``."""
    if limit <= 0:
        return True, 0
    now = time.monotonic()
    cutoff = now - window_seconds
    key = bucket
    with _WINDOW_LOCK:
        hits = _WINDOWS[key]
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= limit:
            retry = max(1, int(window_seconds - (now - hits[0])) + 1)
            return False, retry
        hits.append(now)
        if len(_WINDOWS) > 5000:
            for stale in [k for k, v in _WINDOWS.items() if not v or v[-1] < cutoff]:
                _WINDOWS.pop(stale, None)
        return True, 0


def client_ip(request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    real = request.headers.get("x-real-ip") or ""
    if real:
        return real.strip()
    return getattr(request.client, "host", "") or "unknown"


def device_label(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "iphone" in ua:
        return "iPhone"
    if "ipad" in ua:
        return "iPad"
    if "android" in ua:
        return "Android"
    if "mac os" in ua or "macintosh" in ua:
        return "macOS"
    if "windows" in ua:
        return "Windows"
    if "linux" in ua:
        return "Linux"
    return "Browser"


def allowed_origins() -> list[str]:
    return list(settings.WEB_ORIGINS)
