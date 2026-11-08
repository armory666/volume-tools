import hashlib
import json
import os
import platform
import uuid
from pathlib import Path

from dotenv import load_dotenv

APP_NAME = "VOLUME"
VERSION = "3.1.0"

# The package lives at <root>/volume/core/config.py. Keep runtime state next to
# the package so the tool is self-contained, but allow an override.
ROOT_DIR = Path(
    os.getenv("VOLUME_HOME") or Path(__file__).resolve().parent.parent
).expanduser().resolve()

DATA_DIR = ROOT_DIR / "data"
ASSETS_DIR = ROOT_DIR / "assets"
EXPORT_DIR = ROOT_DIR / "exports"
LOG_DIR = ROOT_DIR / "logs"

# Load .env from the package root and from the current working directory.
load_dotenv(ROOT_DIR / ".env")
load_dotenv(Path.cwd() / ".env")

for _d in (DATA_DIR, EXPORT_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DB_CASES = DATA_DIR / "cases.db"
DB_AUTH = DATA_DIR / "auth.db"
KEYS_FILE = DATA_DIR / "keys.json"
SESSION_FILE = DATA_DIR / "session.json"

_KEYS = {}
if KEYS_FILE.exists():
    try:
        _KEYS = json.loads(KEYS_FILE.read_text(encoding="utf-8") or "{}")
    except Exception:
        _KEYS = {}


def get_key(name: str) -> str:
    env_name = name.upper()
    val = (
        _KEYS.get(name)
        or _KEYS.get(env_name)
        or os.getenv(env_name)
        or os.getenv(f"{env_name}_API_KEY")
    )
    return val if val else ""


def has_key(name: str) -> bool:
    return bool(get_key(name))


def get_ghost_key() -> str:
    # No hardcoded fallback: an unset/empty ghost key must not grant admin access.
    return (os.getenv("VOLUME_GHOST_KEY") or "").strip()


def get_founder_name() -> str:
    """Username reserved for the founder account (default: ``armory``)."""
    return (os.getenv("VOLUME_FOUNDER") or "armory").strip() or "armory"


def get_founder_token() -> str:
    """Secret required to register or claim the founder account.

    No hardcoded fallback: an unset token means the founder name cannot be
    claimed, which keeps the owner role from being hijacked on a fresh install.
    """
    return (os.getenv("VOLUME_FOUNDER_TOKEN") or "").strip()


def _machine_guid() -> str:
    """Return a stable machine identifier where the OS exposes one."""
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                return str(value)
        except Exception:
            pass
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            return Path(candidate).read_text(encoding="utf-8").strip()
        except Exception:
            continue
    return ""


def get_hwid() -> str:
    """Stable, non-reversible hardware/device fingerprint for license binding."""
    parts = [
        str(uuid.getnode()),
        platform.node(),
        platform.machine(),
        platform.processor(),
        os.getenv("COMPUTERNAME", ""),
        _machine_guid(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24].upper()


def get_device_name() -> str:
    return platform.node() or os.getenv("COMPUTERNAME", "unknown")


def mask_key(key: str) -> str:
    key = key or ""
    if len(key) <= 10:
        return key
    return f"{key[:8]}...{key[-4:]}"
