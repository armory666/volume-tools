import re
from urllib.parse import urlparse

from volume.core import indicators, webintel
from volume.core.module_base import BaseModule


BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "meta",
    "facebook", "instagram", "whatsapp", "discord", "steam", "roblox", "coinbase",
    "binance", "metamask", "wallet", "bank", "chase", "wellsfargo", "dhl",
    "fedex", "ups", "usps", "irs", "gov", "outlook", "office365", "dropbox",
]

CREDENTIAL_WORDS = (
    "login", "signin", "sign-in", "verify", "account", "password", "secure",
    "update", "billing", "payment", "wallet", "confirm", "unlock", "recovery",
)

HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "9": "g", "@": "a", "$": "s",
}


class PhishingAnalyzer(BaseModule):
    @property
    def id(self):
        return "phishing_analyzer"

    @property
    def label(self):
        return "Phishing Analyzer"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "URL heuristics, punycode, brand spoofing and credential-form checks"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 60

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["url"]

    def _deobfuscate(self, value: str) -> str:
        return "".join(HOMOGLYPHS.get(ch, ch) for ch in value.lower())

    def run(self, case, **kwargs):
        raw = (kwargs.get("url") or "").strip()
        url = indicators.normalize_url(raw)
        if not url or not indicators.is_url(url):
            return self.result(rows=[("Error", f"Not a valid URL: {raw or '-'}")], status="error")

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        labels = host.split(".")
        tld = labels[-1] if labels else ""
        registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
        subdomain_depth = max(0, len(labels) - 2)
        normalized = self._deobfuscate(host)

        findings = []
        risk = 0

        # Punycode / homoglyph
        if host.startswith("xn--") or ".xn--" in host:
            findings.append("Punycode/IDN host (possible homoglyph attack)")
            risk += 30

        # IP literal host
        if indicators.is_ip(host):
            findings.append("Host is a raw IP address")
            risk += 20

        # Suspicious TLD
        if tld in indicators.SUSPICIOUS_TLDS:
            findings.append(f"Suspicious TLD .{tld}")
            risk += 15

        # Excessive subdomains
        if subdomain_depth >= 3:
            findings.append(f"Deep subdomain nesting ({subdomain_depth} levels)")
            risk += 10

        # Credential words in host or path
        blob = (host + parsed.path + "?" + (parsed.query or "")).lower()
        cred_hits = sorted({word for word in CREDENTIAL_WORDS if word in blob})
        if cred_hits:
            findings.append("Credential bait words: " + ", ".join(cred_hits[:6]))
            risk += min(20, 5 * len(cred_hits))

        # Brand impersonation
        brand_hits = [brand for brand in BRANDS if brand in normalized]
        if brand_hits and not any(brand in registrable for brand in brand_hits):
            findings.append("Brand name used outside its registrable domain: " + ", ".join(brand_hits[:5]))
            risk += 25

        # Hyphenated / digits-heavy host
        if registrable.count("-") >= 2:
            findings.append("Multiple hyphens in registrable domain")
            risk += 8
        if sum(ch.isdigit() for ch in registrable) >= 3:
            findings.append("Digit-heavy domain name")
            risk += 6

        # Userinfo / @ trick
        if "@" in raw.split("://", 1)[-1].split("/", 1)[0]:
            findings.append("Userinfo '@' trick in URL authority")
            risk += 25

        # Port / scheme
        if parsed.port and parsed.port not in (80, 443):
            findings.append(f"Non-standard port {parsed.port}")
            risk += 8
        if parsed.scheme == "http":
            findings.append("Plain HTTP (no transport security)")
            risk += 8

        # Long URL
        if len(url) > 120:
            findings.append(f"Long URL ({len(url)} chars)")
            risk += 5

        rows = [
            ("URL", url),
            ("Host", host),
            ("Registrable domain", registrable),
            ("TLD", f".{tld}"),
            ("Subdomain depth", str(subdomain_depth)),
            ("Scheme", parsed.scheme),
            ("Path", (parsed.path or "/")[:160]),
        ]

        # Live page checks (best effort)
        response, final_url = webintel.fetch(url)
        if response.get("status") == "ok":
            headers = webintel.header_map(response)
            body = webintel.body_text(response)
            page = webintel.parse_page(body, final_url)
            rows.append(("Final URL", response.get("url", final_url)))
            rows.append(("HTTP", str(response.get("code", "-"))))
            rows.append(("Page title", webintel.page_title(body) or "-"))
            rows.append(("Password forms", str(page["password_forms"])))
            if page["password_forms"] and parsed.scheme == "http":
                findings.append("Credential form served over plain HTTP")
                risk += 25
            if page["external_form_actions"]:
                findings.append("Form posts to an external host: " + ", ".join(page["external_form_actions"][:3]))
                risk += 15
            if page["external_scripts"] >= 8:
                findings.append(f"Many external scripts ({page['external_scripts']})")
                risk += 5
            if page["password_forms"] and page["external_form_actions"]:
                findings.append("Password form posts off-domain (credential exfiltration pattern)")
                risk += 20
            if not headers.get("strict-transport-security") and parsed.scheme == "https":
                findings.append("Missing HSTS on a credential page")
                risk += 5
        else:
            rows.append(("Live fetch", f"failed ({response.get('error') or response.get('status')})"))

        risk = min(100, risk)
        rows.append(("Indicators", str(len(findings))))
        for finding in findings:
            rows.append(("Finding", finding))
        if not findings:
            rows.append(("Result", "No strong phishing heuristics matched (not a guarantee)"))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Phishing: {host}",
            source="URL heuristics + live page analysis",
            confidence="medium",
            rows=rows,
            risk=risk,
            phishing_score=risk,
        )

    def pivots(self, result):
        host = indicators.url_host(result.get("title", "").replace("Phishing: ", ""))
        return [("domain", host)] if host else []
