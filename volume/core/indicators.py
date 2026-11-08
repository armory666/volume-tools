"""Validation and normalisation helpers shared by modules."""

import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\.?$"
)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
URL_RE = re.compile(r"^https?://[^\s<>\"']+$", re.I)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    "discord.gg", "t.me",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "country", "gq", "tk", "ml",
    "cf", "ga", "work", "support", "rest", "cam", "surf", "fit", "monster",
    "quest", "buzz", "icu", "cyou", "sbs", "lol",
}


def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    if "@" in value and "://" not in value:
        value = value.rsplit("@", 1)[-1]
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.strip().strip(".").lower()
    if value.startswith("www."):
        value = value[4:]
    return value


def is_domain(value: str) -> bool:
    value = (value or "").strip().strip(".")
    if not value or is_ip(value):
        return False
    return bool(DOMAIN_RE.fullmatch(value))


def is_email(value: str) -> bool:
    return bool(EMAIL_RE.fullmatch((value or "").strip()))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    return value


def is_url(value: str) -> bool:
    value = normalize_url(value)
    if not URL_RE.fullmatch(value):
        return False
    parsed = urlparse(value)
    return bool(parsed.hostname) and (is_domain(parsed.hostname) or is_ip(parsed.hostname))


def url_host(value: str) -> str:
    try:
        return (urlparse(normalize_url(value)).hostname or "").lower()
    except Exception:
        return ""


def hash_type(value: str) -> str:
    value = (value or "").strip()
    if not value or not HASH_RE.fullmatch(value):
        return ""
    return {
        32: "MD5",
        40: "SHA-1",
        56: "SHA-224",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512",
    }.get(len(value), "")


def is_hash(value: str) -> bool:
    return bool(hash_type(value))


def is_cve(value: str) -> bool:
    return bool(CVE_RE.fullmatch((value or "").strip()))


def reverse_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
        if ip.version == 4:
            return ".".join(reversed(str(ip).split(".")))
    except ValueError:
        pass
    return ""


def clamp(value, low, high):
    return max(low, min(high, value))


def risk_label(score: int) -> str:
    score = int(score)
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"
