import datetime
import ipaddress
import re
from pathlib import Path

from volume.core.module_base import BaseModule
from volume.core import config

try:
    import phonenumbers
except ImportError:  # pragma: no cover - dependency is in requirements.txt
    phonenumbers = None


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
IPV6_RE = re.compile(r"(?<![\w:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
BTC_RE = re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
PHONE_RE = re.compile(r"(?<![\w.])(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?!\w)")


FILE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".csv", ".json", ".xml", ".zip", ".rar", ".7z", ".exe", ".dll", ".bin",
    ".log", ".md", ".html", ".htm", ".php", ".asp", ".aspx", ".png", ".jpg",
    ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".py", ".sh", ".bat",
}


def _trim_url(url: str) -> str:
    return url.rstrip(".,;:!?)\\]}>\"'")


def _is_ip_like(candidate: str) -> bool:
    """Return True if candidate looks like an IPv4 address fragment."""
    # Check for full IPv4 X.X.X.X (3 dots)
    if candidate.count('.') == 3:
        parts = candidate.split('.')
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    # Check for three-octet fragment X.X.X (2 dots) – still likely an IP part
    if candidate.count('.') == 2:
        parts = candidate.split('.')
        # If all parts are 1-3 digits, it's probably an IP fragment
        return all(p.isdigit() and 1 <= len(p) <= 3 for p in parts)
    return False


def _valid_phone(candidate: str) -> bool:
    # Skip IP-like patterns
    if _is_ip_like(candidate):
        return False
    # Skip CVE-shaped tokens such as 2021-44228 even if masking misses them.
    if re.fullmatch(r"\d{4}-\d{4,7}", candidate):
        return False
    digits = re.sub(r"\D", "", candidate)
    if not candidate.startswith("+") and len(digits) < 9:
        return False

    if phonenumbers is None:
        return 7 <= len(digits) <= 15

    if candidate.startswith("+"):
        regions = [None]
    else:
        regions = ["US", "GB", "DE", "FR", "IN", "AU", "CA", "NL"]

    for region in regions:
        try:
            number = phonenumbers.parse(candidate, region)
        except Exception:
            continue
        if phonenumbers.is_possible_number(number) and phonenumbers.is_valid_number(number):
            return True
    return False


def _add(bucket: dict, kind: str, value: str):
    value = value.strip()
    if not value:
        return
    bucket[kind].setdefault(value.lower(), value)


class AutoParse(BaseModule):
    @property
    def id(self):
        return "auto_parse"

    @property
    def label(self):
        return "Auto Format / Paster"

    @property
    def category(self):
        return "INVESTIGATION"

    @property
    def description(self):
        return "Extract URLs, emails, IPs, hashes, wallets and phones from text"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 0

    @property
    def inputs(self):
        return ["text"]

    @property
    def input_prompts(self):
        return {"text": "Paste text (or @file path)"}


    def _read_text(self, text: str) -> str:
        candidate = text[1:] if text.startswith("@") else text

        path = Path(candidate).expanduser()
        if path.is_file():
            return path.read_text(errors="replace")
        return text
    def _safe_case_name(self, case) -> str:
        name = getattr(case, "name", None) or "WORKSPACE"
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
        return slug[:60] or "WORKSPACE"

    _DISPLAY_TYPES = ("url", "email", "ip", "phone")

    def _should_display_type(self, kind: str) -> bool:
        """Return True if type should be shown in the default report."""
        return kind in self._DISPLAY_TYPES

    def extract(self, text: str) -> dict:
        found = {
            "url": {},
            "email": {},
            "ip": {},
            "hash": {},
            "cve": {},
            "mac": {},
            "btc": {},
            "eth": {},
            "phone": {},
            "domain": {},
        }

        for url in URL_RE.findall(text):
            _add(found, "url", _trim_url(url))

        for email in EMAIL_RE.findall(text):
            _add(found, "email", email)

        for ip in IPV4_RE.findall(text):
            _add(found, "ip", ip)

        for candidate in IPV6_RE.findall(text):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            _add(found, "ip", candidate)

        hash_count = 0
        for h in re.findall(r"\b[a-fA-F0-9]{32,64}\b", text):
            _add(found, "hash", h)
            hash_count += 1

        cve_count = 0
        for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.I):
            _add(found, "cve", cve.upper())
            cve_count += 1

        for mac in MAC_RE.findall(text):
            _add(found, "mac", mac)

        for btc in BTC_RE.findall(text):
            _add(found, "btc", btc)

        for eth in ETH_RE.findall(text):
            _add(found, "eth", eth)

        # Mask non-phone tokens first so CVE IDs, hashes, IPs, URLs, emails and
        # MAC addresses are never misread as phone numbers.
        phone_source = text
        for pattern in (URL_RE, EMAIL_RE, IPV4_RE, IPV6_RE, HASH_RE, CVE_RE, MAC_RE):
            phone_source = pattern.sub(" ", phone_source)
        for phone in PHONE_RE.findall(phone_source):
            candidate = phone.strip()
            if _valid_phone(candidate):
                _add(found, "phone", candidate)

        for domain in DOMAIN_RE.findall(text):
            lowered = domain.lower()
            if any(lowered.endswith(ext) for ext in FILE_EXTENSIONS):
                continue
            _add(found, "domain", domain)

        return {kind: list(values.values()) for kind, values in found.items() if values}

    def write_report(self, case, indicators: dict, text: str) -> Path:
        sections = [
            ("url", "URLS"),
            ("email", "EMAIL ADDRESSES"),
            ("ip", "IP ADDRESSES"),
            ("domain", "DOMAINS"),
            ("hash", "HASHES"),
            ("cve", "CVES"),
            ("mac", "MAC ADDRESSES"),
            ("btc", "BITCOIN ADDRESSES"),
            ("eth", "ETHEREUM ADDRESSES"),
            ("phone", "PHONE NUMBERS"),
        ]
        stamp = datetime.datetime.now()
        case_name = self._safe_case_name(case)
        path = config.EXPORT_DIR / f"AUTOPARSE_{case_name}_{stamp.strftime('%Y%m%d_%H%M%S')}.txt"
        config.EXPORT_DIR.mkdir(parents=True, exist_ok=True)

        total = sum(len(v) for v in indicators.values())
        analyst = getattr(case, "analyst", None) or "anonymous"
        case_id = getattr(case, "id", None) or "-"

        # Build list of types to show in the ladder report (core types + any
        # that have values, but hide hash/cve/mac/btc/eth by default).
        display_kinds = [k for k in indicators if self._should_display_type(k) or indicators[k]]

        # ASCII art – disabled to keep reports compact
        ascii_banner = ""

        lines = [
            "=" * 56,
            " VOLUME  ::  AUTO FORMAT REPORT",
            "=" * 56,
        ]

        # Inline summary – only non-zero core types
        core_types = [
            ("url", "URLS"),
            ("email", "EMAIL ADDRESSES"),
            ("ip", "IP ADDRESSES"),
            ("phone", "PHONE NUMBERS"),
        ]
        summary_parts = []
        for kind, title in core_types:
            cnt = len(indicators.get(kind, []))
            if cnt > 0:
                summary_parts.append(f"{title}={cnt}")
        summary_text = ", ".join(summary_parts) if summary_parts else "none"
        lines.append(f" SUMMARY: {summary_text} | TOTAL:{total}")

        # Ladder-style indicator list
        number = 0
        for kind in display_kinds:
            values = indicators.get(kind) or []
            if not values:
                continue
            title = kind.upper()
            for value in values:
                number += 1
                lines.append(f" {title}: {value}")
            lines.append("")

        # Source preview (first 800 chars, trimmed)
        preview = re.sub(r"\s+", " ", text).strip()
        if preview:
            if len(preview) > 800:
                preview = preview[:800] + " …"
            lines.extend([
                " SOURCE PREVIEW",
                "-" * 56,
                f"  {preview}",
                "",
            ])

        lines.extend([
            "=" * 56,
            " Generated by VOLUME. Review indicators before acting on them.",
            "=" * 56,
        ])

        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def run(self, case, **kwargs):
        text = (kwargs.get("text") or "").strip()
        if not text:
            return {"title": "Auto Format", "rows": [("Error", "No text provided")]}

        text = self._read_text(text)
        indicators = self.extract(text)

        # Determine which indicator types to display in the UI result.
        # Core types by default: urls, emails, ips, phones.
        # Include hashes/cves only if they were actually found.
        display_kinds = list(self._DISPLAY_TYPES)
        for kind in ("hash", "cve", "mac", "btc", "eth"):
            if indicators.get(kind):
                display_kinds.append(kind)

        rows = []
        labels = {
            "url": "URL", "email": "Email", "ip": "IP", "phone": "Phone",
        }
        extra_labels = {
            "hash": "Hash", "cve": "CVE", "mac": "MAC", "btc": "BTC", "eth": "ETH",
        }

        for kind in display_kinds:
            values = indicators.get(kind) or []
            if not values:
                continue
            label = labels.get(kind, kind.upper())
            for value in values:
                rows.append((f"{label}:", value))

        report_path = None
        try:
            report_path = self.write_report(case, indicators, text)
        except Exception as exc:
            report_error = str(exc)
        else:
            report_error = ""

        if not rows:
            result_rows = [
                ("Result", "No IPs, emails, URLs, domains, hashes, phones or wallets found.")
            ]
            if report_path:
                result_rows.append(("TXT report", str(report_path)))
            elif report_error:
                result_rows.append(("TXT report", f"could not write: {report_error}"))
            return {
                "module": self.id,
                "title": "Auto Format: no indicators found",
                "source": "local parser",
                "confidence": "low",
                "status": "empty",
                "rows": result_rows,
                "indicators": {},
                "report_path": str(report_path) if report_path else "",
            }

        indicator_count = sum(len(v) for v in indicators.values())
        # Build inline summary – core types only
        core_types = [
            ("url", "URLS"),
            ("email", "EMAIL ADDRESSES"),
            ("ip", "IP ADDRESSES"),
            ("phone", "PHONE NUMBERS"),
        ]
        summary_parts = []
        for kind, title in core_types:
            cnt = len(indicators.get(kind, []))
            if cnt > 0:
                summary_parts.append(f"{title}={cnt}")
        summary_text = ", ".join(summary_parts) if summary_parts else "none"
        if report_path:
            rows.append(("TXT report", str(report_path)))
        elif report_error:
            rows.append(("TXT report", f"could not write: {report_error}"))
        return {
            "module": self.id,
            "title": f"Auto Format: {indicator_count} indicators",
            "source": "local parser",
            "confidence": "high",
            "status": "ok",
            "rows": rows,
            "indicators": indicators,
            "summary": summary_text,
            "report_path": str(report_path) if report_path else "",
        }

    def pivots(self, result):
        pivots = []
        for kind, values in (result.get("indicators") or {}).items():
            for value in values:
                pivots.append((kind, value))
        return pivots
