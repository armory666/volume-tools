"""Runtime settings for the VOLUME web API.

Every value can be overridden with an environment variable so no secret ever
lives in the repository.  Local development falls back to SQLite and console
email; production is expected to set ``DATABASE_URL`` and an email provider.
"""

import os
from pathlib import Path

APP_NAME = "VOLUME"
VERSION = "3.2.0"

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name) or default)
    except ValueError:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    raw = env(name).lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    raw = env(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Web / CORS
# ---------------------------------------------------------------------------

WEB_ORIGINS = [
    origin.rstrip("/")
    for origin in env_list(
        "VOLUME_WEB_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,"
        "http://localhost:8765,http://127.0.0.1:8765,"
        "https://volume-tools-web.vercel.app",
    )
]

PUBLIC_BASE_URL = env("VOLUME_PUBLIC_URL", "http://localhost:8000").rstrip("/")

# ---------------------------------------------------------------------------
# Sessions and one-time codes
# ---------------------------------------------------------------------------

SESSION_TTL_HOURS = env_int("VOLUME_SESSION_TTL_HOURS", 12)
REMEMBER_DAYS = env_int("VOLUME_REMEMBER_DAYS", 30)
OTP_TTL_MINUTES = env_int("VOLUME_OTP_TTL_MINUTES", 10)
OTP_MAX_ATTEMPTS = env_int("VOLUME_OTP_MAX_ATTEMPTS", 5)
OTP_RESEND_SECONDS = env_int("VOLUME_OTP_RESEND_SECONDS", 30)
OTP_EMAIL_LIMIT = env_int("VOLUME_OTP_EMAIL_LIMIT", 4)
OTP_IP_LIMIT = env_int("VOLUME_OTP_IP_LIMIT", 15)
OTP_WINDOW_SECONDS = env_int("VOLUME_OTP_WINDOW_SECONDS", 900)
MAGIC_TTL_MINUTES = env_int("VOLUME_MAGIC_TTL_MINUTES", 15)

# ---------------------------------------------------------------------------
# Tiers, quotas and credits
# ---------------------------------------------------------------------------

TIER_LIMITS = {
    "free": 15,
    "premium": 200,
    "detective": 500,
    "industrial": 2000,
    "lifetime": 10000,
    "admin": 10**9,
}

TIER_ORDER = ["free", "premium", "detective", "industrial", "lifetime", "admin"]

TIER_LABELS = {
    "free": "FREE",
    "premium": "PREMIUM",
    "detective": "DETECTIVE",
    "industrial": "INDUSTRIAL",
    "lifetime": "LIFETIME",
    "admin": "ADMIN",
}

WELCOME_CREDITS = env_int("VOLUME_WELCOME_CREDITS", 50)
REFERRAL_CREDITS = env_int("VOLUME_REFERRAL_CREDITS", 25)
REFERRED_CREDITS = env_int("VOLUME_REFERRED_CREDITS", 10)

# ---------------------------------------------------------------------------
# Administration
# ---------------------------------------------------------------------------

ADMIN_EMAILS = {email.lower() for email in env_list("VOLUME_ADMIN_EMAILS")}
ADMIN_KEY = env("VOLUME_ADMIN_KEY")

# ---------------------------------------------------------------------------
# Email delivery
# ---------------------------------------------------------------------------

EMAIL_PROVIDER = env("VOLUME_EMAIL_PROVIDER", "console").lower()
EMAIL_FROM = env("VOLUME_EMAIL_FROM", "VOLUME <no-reply@volume.tools>")
EMAIL_REPLY_TO = env("VOLUME_EMAIL_REPLY_TO")
SMTP_HOST = env("VOLUME_SMTP_HOST")
SMTP_PORT = env_int("VOLUME_SMTP_PORT", 587)
SMTP_USER = env("VOLUME_SMTP_USER")
SMTP_PASSWORD = env("VOLUME_SMTP_PASSWORD")
SMTP_TLS = env_bool("VOLUME_SMTP_TLS", True)
SMTP_SSL = env_bool("VOLUME_SMTP_SSL", False)
RESEND_API_KEY = env("RESEND_API_KEY")

# Console delivery is the default so local login works with no credentials.
EMAIL_IS_CONSOLE = EMAIL_PROVIDER == "console"

# Only surface one-time codes / magic links in API responses when explicitly
# enabled. Console mode always writes them to the server log, which is the
# safe way to test locally and in staging.
DEV_CODES = env_bool("VOLUME_DEV_CODES", False)

# ---------------------------------------------------------------------------
# WebAuthn / passkeys
# ---------------------------------------------------------------------------

WEBAUTHN_RP_ID = env("VOLUME_WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = env("VOLUME_WEBAUTHN_RP_NAME", "VOLUME")
WEBAUTHN_ORIGIN = env("VOLUME_WEBAUTHN_ORIGIN", "http://localhost:8000")
WEBAUTHN_ORIGINS = [
    origin.rstrip("/")
    for origin in env_list("VOLUME_WEBAUTHN_ORIGINS", WEBAUTHN_ORIGIN)
]

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

DATABASE_URL = env("DATABASE_URL")
IS_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

MAX_PARALLEL_MODULES = env_int("VOLUME_MAX_PARALLEL_MODULES", 6)
PIVOT_TIMEOUT_SECONDS = env_int("VOLUME_PIVOT_TIMEOUT_SECONDS", 25)
MAX_ROWS_PER_MODULE = env_int("VOLUME_MAX_ROWS_PER_MODULE", 12)
