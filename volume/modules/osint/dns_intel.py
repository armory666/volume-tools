import re

import dns.resolver

from volume.core import indicators
from volume.core.module_base import BaseModule


class DNSIntel(BaseModule):
    @property
    def id(self):
        return "dns_intel"

    @property
    def label(self):
        return "DNS Deep Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "All record types, SPF/DMARC/DKIM, DNSSEC, CAA and wildcard detection"

    @property
    def order(self):
        return 15

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["domain"]

    def _q(self, name, rdtype, lifetime=5):
        try:
            return [str(r) for r in dns.resolver.resolve(name, rdtype, lifetime=lifetime)]
        except Exception:
            return []

    def _spf(self, txt_records):
        for record in txt_records:
            value = record.strip('"')
            if value.lower().startswith("v=spf1"):
                mechanisms = value.split()[1:]
                qualifier = "neutral"
                for mech in mechanisms:
                    if mech.lower().endswith("all"):
                        qualifier = mech
                return value, qualifier, len(mechanisms)
        return "", "", 0

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain:
            return self.result(rows=[("Error", "No domain provided")], status="error")
        if not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain}")], status="error")

        a = self._q(domain, "A")
        aaaa = self._q(domain, "AAAA")
        mx = self._q(domain, "MX")
        ns = self._q(domain, "NS")
        txt = self._q(domain, "TXT")
        soa = self._q(domain, "SOA")
        caa = self._q(domain, "CAA")
        dnskey = self._q(domain, "DNSKEY")

        spf, spf_all, spf_count = self._spf(txt)
        dmarc = self._q(f"_dmarc.{domain}", "TXT")
        dmarc_policy = ""
        for record in dmarc:
            if "v=dmarc1" in record.lower():
                match = re.search(r"\bp=(\w+)", record, re.I)
                dmarc_policy = match.group(1).lower() if match else "none"
        dkim = []
        for selector in ("default", "google", "selector1", "selector2", "k1", "mail", "s1"):
            answers = self._q(f"{selector}._domainkey.{domain}", "TXT")
            if answers:
                dkim.append(selector)

        wildcard = self._q(f"volume-wildcard-{abs(hash(domain)) % 99999}.{domain}", "A", lifetime=3)

        rows = [
            ("Domain", domain),
            ("A", ", ".join(a) or "-"),
            ("AAAA", ", ".join(aaaa) or "-"),
            ("MX", ", ".join(mx) or "-"),
            ("NS", ", ".join(ns) or "-"),
            ("SOA", (soa[0][:180] if soa else "-")),
            ("CAA", ", ".join(caa) or "-"),
            ("DNSSEC", "signed (DNSKEY present)" if dnskey else "not signed / not found"),
            ("Wildcard DNS", "yes (resolves random host)" if wildcard else "no"),
            ("SPF", spf[:220] if spf else "missing"),
            ("SPF policy", spf_all or "missing"),
            ("SPF mechanisms", str(spf_count) if spf else "0"),
            ("DMARC", f"p={dmarc_policy}" if dmarc_policy else "missing"),
            ("DKIM selectors", ", ".join(dkim) if dkim else "not found (common selectors)"),
        ]
        for record in txt:
            if record.strip('"').lower().startswith(("v=spf1", "v=dmarc1")):
                continue
            rows.append(("TXT", record.strip('"')[:200]))

        findings = []
        if not spf:
            findings.append("No SPF record")
        elif spf_all not in ("-all", "~all"):
            findings.append(f"Weak SPF policy ({spf_all or 'no all'})")
        if not dmarc_policy:
            findings.append("No DMARC record")
        elif dmarc_policy == "none":
            findings.append("DMARC p=none (monitor only)")
        if not dnskey:
            findings.append("DNSSEC not enabled")
        if wildcard:
            findings.append("Wildcard DNS may hide subdomain enumeration")
        if not (a or aaaa):
            findings.append("Domain does not resolve")

        if findings:
            rows.append(("Findings", "; ".join(findings)))

        return self.result(
            title=f"DNS Intel: {domain}",
            source="DNS (dnspython)",
            confidence="high" if (a or aaaa or mx) else "low",
            rows=rows,
            findings=findings,
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("DNS Intel: ", "").strip()
        return [("domain", domain)] if domain else []
