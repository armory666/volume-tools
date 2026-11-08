import re
from email.parser import Parser
from email.utils import getaddresses
from pathlib import Path

from volume.core import indicators
from volume.core.module_base import BaseModule


FREEMAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "proton.me", "gmx.com",
    "mail.com", "yandex.com", "zoho.com",
}

BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "meta",
    "facebook", "instagram", "whatsapp", "discord", "steam", "roblox",
    "bank", "coinbase", "binance", "dhl", "fedex", "ups", "irs",
}

IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)


class EmailHeaderAnalyzer(BaseModule):
    @property
    def id(self):
        return "email_header_analyzer"

    @property
    def label(self):
        return "Email Header Analyzer"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "SPF/DKIM/DMARC, spoofing and routing analysis for raw headers"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["headers"]

    @property
    def multiline_inputs(self):
        return ("headers",)

    @property
    def input_prompts(self):
        return {"headers": "Paste raw email headers (or @path/to/headers.txt)"}

    def _read(self, text: str) -> str:
        if text.strip().startswith("@"):
            path = Path(text.strip()[1:]).expanduser()
            if path.is_file():
                return path.read_text(errors="replace")
        return text

    def _address_domain(self, value: str) -> str:
        addresses = getaddresses([value or ""])
        if not addresses:
            return ""
        return (addresses[0][1].rsplit("@", 1)[-1] if "@" in addresses[0][1] else "").lower()

    def _display(self, value: str) -> str:
        addresses = getaddresses([value or ""])
        return addresses[0][0] if addresses else ""

    def run(self, case, **kwargs):
        raw = self._read(kwargs.get("headers") or "")
        if not raw.strip():
            return self.result(rows=[("Error", "No headers provided")], status="error")
        if ":" not in raw:
            return self.result(rows=[("Error", "Input does not look like RFC 822 headers")], status="error")

        message = Parser().parsestr(raw)
        from_header = message.get("From", "")
        to_header = message.get("To", "")
        return_path = message.get("Return-Path", "")
        reply_to = message.get("Reply-To", "")
        subject = message.get("Subject", "")
        date = message.get("Date", "")
        message_id = message.get("Message-ID", "")
        mailer = message.get("X-Mailer", "")
        originating_ip = message.get("X-Originating-IP", "")
        auth_results = message.get_all("Authentication-Results") or []
        received_spf = " ".join(message.get_all("Received-SPF") or [])
        received = message.get_all("Received") or []
        dkim = message.get_all("DKIM-Signature") or []

        from_domain = self._address_domain(from_header)
        return_domain = self._address_domain(return_path)
        reply_domain = self._address_domain(reply_to)
        message_id_domain = ""
        if "@" in message_id:
            message_id_domain = message_id.rsplit("@", 1)[-1].strip("> ").lower()

        auth_blob = " ".join(auth_results) + " " + received_spf
        auth = {name.lower(): value.lower() for name, value in AUTH_RE.findall(auth_blob)}
        ips = []
        for line in received:
            ips.extend(IP_RE.findall(line))
        if originating_ip:
            ips.extend(IP_RE.findall(originating_ip) or [originating_ip.strip("[] ")])

        display = self._display(from_header)
        findings = []
        risk = 0
        if return_domain and from_domain and return_domain != from_domain:
            findings.append(f"Return-Path domain differs ({return_domain})")
            risk += 15
        if reply_domain and from_domain and reply_domain != from_domain:
            findings.append(f"Reply-To domain differs ({reply_domain})")
            risk += 15
        if auth.get("spf") in ("fail", "softfail", "permerror"):
            findings.append(f"SPF {auth['spf']}")
            risk += 20
        if auth.get("dkim") in ("fail", "permerror"):
            findings.append(f"DKIM {auth['dkim']}")
            risk += 20
        if auth.get("dmarc") in ("fail", "quarantine", "reject"):
            findings.append(f"DMARC {auth['dmarc']}")
            risk += 20
        if not auth:
            findings.append("No SPF/DKIM/DMARC result headers")
            risk += 5
        if from_domain in FREEMAIL and any(brand in (display + subject).lower() for brand in BRANDS):
            findings.append("Freemail sender impersonates a brand")
            risk += 20
        if from_domain and any(brand in (display + subject).lower() for brand in BRANDS):
            if not any(brand in from_domain for brand in BRANDS):
                findings.append("Brand name in display/subject does not match sender domain")
                risk += 20
        if message_id_domain and from_domain and message_id_domain != from_domain:
            findings.append(f"Message-ID domain mismatch ({message_id_domain})")
            risk += 5
        if not date:
            findings.append("Missing Date header")
            risk += 5
        if mailer and any(x in mailer.lower() for x in ("phpmailer", "mass", "bulk", "sendblaster")):
            findings.append(f"Mailer: {mailer}")
            risk += 5
        if any(indicators.is_private_ip(ip) for ip in ips if indicators.is_ip(ip)):
            findings.append("Private IP in the received chain")
            risk += 10

        rows = [
            ("From", from_header[:200] or "-"),
            ("Display name", display or "-"),
            ("From domain", from_domain or "-"),
            ("Return-Path", return_path[:200] or "-"),
            ("Return-Path domain", return_domain or "-"),
            ("Reply-To", reply_to[:200] or "-"),
            ("Subject", subject[:200] or "-"),
            ("Date", date or "-"),
            ("Message-ID", message_id[:200] or "-"),
            ("X-Mailer", mailer[:120] or "-"),
            ("SPF", auth.get("spf", "not reported")),
            ("DKIM", auth.get("dkim", "not reported")),
            ("DMARC", auth.get("dmarc", "not reported")),
            ("DKIM signatures", str(len(dkim))),
            ("Received hops", str(len(received))),
            ("Originating IP", originating_ip or (ips[0] if ips else "-")),
        ]
        if ips:
            rows.append(("Chain IPs", ", ".join(dict.fromkeys(ips))[:250]))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))
        if findings:
            for finding in findings:
                rows.append(("Finding", finding))
        else:
            rows.append(("Findings", "No obvious spoofing indicators"))

        return self.result(
            title=f"Email Headers: {from_domain or 'unknown'}",
            source="RFC 822 header analysis",
            confidence="high",
            rows=rows,
            risk=risk,
            emails=[a for _, a in getaddresses([from_header, return_path, reply_to, to_header]) if a],
            ips=list(dict.fromkeys(ips)),
            from_domain=from_domain,
        )

    def pivots(self, result):
        pivots = []
        for email in (result.get("emails") or [])[:10]:
            pivots.append(("email", email))
        for ip in (result.get("ips") or [])[:10]:
            if indicators.is_ip(ip):
                pivots.append(("ip", ip))
        if result.get("from_domain"):
            pivots.append(("domain", result["from_domain"]))
        return pivots
