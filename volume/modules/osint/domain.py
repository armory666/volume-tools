import re
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from volume.core.module_base import BaseModule
from volume.core import net


class DomainIntel(BaseModule):
    @property
    def id(self):
        return "domain_intel"

    @property
    def label(self):
        return "Domain / DNS Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "DNS, mail, DNSSEC and RDAP domain profile"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["domain"]

    def _normalize(self, value: str) -> str:
        value = (value or "").strip()
        if "@" in value and "://" not in value:
            value = value.rsplit("@", 1)[-1]
        if "://" in value:
            value = urlparse(value).hostname or value
        return value.strip().strip(".").lower()

    def _dns(self, domain: str, rdtype: str) -> list:
        try:
            answers = dns.resolver.resolve(domain, rdtype, lifetime=6)
            return [str(a) for a in answers]
        except Exception:
            return []

    def _rdap(self, domain: str) -> dict:
        response = net.get(f"https://rdap.org/domain/{domain}")
        data = response.get("data") if response.get("status") == "ok" else None
        return data if isinstance(data, dict) else {}

    def run(self, case, **kwargs):
        domain = self._normalize(kwargs.get("domain"))
        if not domain:
            return {"title": "Domain Intel", "rows": [("Error", "No domain provided")]}
        if not re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}", domain):
            return {"title": "Domain Intel", "rows": [("Error", f"Not a valid domain: {domain}")]}

        a = self._dns(domain, "A")
        aaaa = self._dns(domain, "AAAA")
        mx = self._dns(domain, "MX")
        ns = self._dns(domain, "NS")
        txt = self._dns(domain, "TXT")

        rdap = self._rdap(domain)
        registrar = ""
        created = ""
        expires = ""
        for entity in rdap.get("entities", []) or []:
            if "registrar" in (entity.get("roles") or []):
                vcard = entity.get("vcardArray") or []
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item and item[0] == "fn":
                            registrar = item[3]
                            break
                if not registrar:
                    registrar = entity.get("handle", "")
                break
        for event in rdap.get("events", []) or []:
            action = event.get("eventAction")
            date = str(event.get("eventDate", ""))[:10]
            if action == "registration":
                created = date
            elif action == "expiration":
                expires = date

        rows = [
            ("Domain", domain),
            ("A", ", ".join(a) or "-"),
            ("AAAA", ", ".join(aaaa) or "-"),
            ("MX", ", ".join(mx) or "-"),
            ("NS", ", ".join(ns) or "-"),
            ("TXT", " | ".join(t[:160] for t in txt) or "-"),
            ("Registrar", registrar or "-"),
            ("Created", created or "-"),
            ("Expires", expires or "-"),
            ("RDAP status", ", ".join(rdap.get("status", []) or []) or "-"),
        ]

        if not (a or aaaa or mx or ns):
            rows.append(("Warning", "No DNS records returned. Domain may not exist."))

        return {
            "module": self.id,
            "title": f"Domain Intel: {domain}",
            "source": "DNS + RDAP",
            "confidence": "high" if (a or aaaa) else "low",
            "status": "ok",
            "rows": rows,
        }

    def pivots(self, result):
        domain = result.get("title", "").replace("Domain Intel: ", "").strip()
        return [("domain", domain)] if domain else []
