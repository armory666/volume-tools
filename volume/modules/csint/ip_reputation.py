from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule


class IPReputation(BaseModule):
    @property
    def id(self):
        return "ip_reputation"

    @property
    def label(self):
        return "IP Reputation"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "AbuseIPDB, GreyNoise, InternetDB and DNSBL reputation for an IP"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("abuseipdb",)

    @property
    def inputs(self):
        return ["ip"]

    def run(self, case, **kwargs):
        ip = (kwargs.get("ip") or "").strip()
        if not ip or not indicators.is_ip(ip):
            return self.result(rows=[("Error", f"Not a valid IP: {ip or '-'}")], status="error")
        if indicators.is_private_ip(ip):
            return self.result(
                title=f"IP Reputation: {ip}",
                rows=[("IP", ip), ("Result", "Private/reserved address - no public reputation data")],
                status="skipped",
            )

        rows = [("IP", ip)]
        risk = 0
        signals = []

        # AbuseIPDB
        abuse_key = config.get_key("abuseipdb")
        if abuse_key:
            response = sources.abuseipdb(ip, abuse_key)
            if response.get("status") == "ok":
                data = (response.get("data") or {}).get("data") or {}
                score = int(data.get("abuseConfidenceScore") or 0)
                rows.append(("AbuseIPDB score", f"{score}/100"))
                rows.append(("Abuse reports", str(data.get("totalReports", 0))))
                rows.append(("Distinct reporters", str(data.get("numDistinctUsers", 0))))
                rows.append(("Last reported", str(data.get("lastReportedAt", "-"))[:19]))
                rows.append(("ISP", data.get("isp", "-")))
                rows.append(("Usage type", data.get("usageType", "-")))
                rows.append(("Country", data.get("countryCode", "-")))
                rows.append(("Tor", "yes" if data.get("isTor") else "no"))
                if score:
                    risk += min(60, int(score * 0.6))
                    signals.append(f"AbuseIPDB {score}%")
            else:
                rows.append(("AbuseIPDB", f"error · {response.get('error') or response.get('status')}"))
        else:
            rows.append(("AbuseIPDB", "not configured (ABUSEIPDB_API_KEY)"))

        # GreyNoise
        gn_key = config.get_key("greynoise")
        response = sources.greynoise(ip, gn_key)
        if response.get("status") == "ok":
            data = response.get("data") or {}
            classification = data.get("classification", "unknown")
            rows.append(("GreyNoise", classification))
            rows.append(("GreyNoise name", data.get("name", "-")))
            rows.append(("Last seen", str(data.get("last_seen", "-"))[:19]))
            if classification in ("malicious",):
                risk += 35
                signals.append("GreyNoise malicious")
            elif classification == "benign":
                rows.append(("GreyNoise note", "known benign scanner"))
        elif response.get("status") == "not_found":
            rows.append(("GreyNoise", "no record"))
        else:
            rows.append(("GreyNoise", f"unavailable · {response.get('status')}"))

        # InternetDB
        data = sources.internetdb(ip)
        if data:
            ports = data.get("ports") or []
            vulns = data.get("vulns") or []
            rows.append(("Open ports", ", ".join(str(p) for p in ports[:20]) or "-"))
            rows.append(("Known CVEs", str(len(vulns))))
            if vulns:
                risk += min(25, 10 + len(vulns) * 3)
                signals.append(f"{len(vulns)} CVEs")

        # DNSBL
        hits = [h for h in sources.dnsbl_hits(ip) if h.get("listed") is True]
        if hits:
            rows.append(("DNSBL", f"listed on {len(hits)} list(s)"))
            for hit in hits[:10]:
                rows.append((f"  {hit['label']}", hit.get("reason") or "listed"))
            risk += min(30, 10 + len(hits) * 5)
            signals.append(f"{len(hits)} DNSBL")

        risk = min(100, risk)
        rows.append(("Signals", ", ".join(signals) if signals else "none"))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"IP Reputation: {ip}",
            source="AbuseIPDB + GreyNoise + InternetDB + DNSBL",
            confidence="high" if signals else "medium",
            rows=rows,
            risk=risk,
            malicious=risk >= 50,
        )

    def pivots(self, result):
        ip = result.get("title", "").replace("IP Reputation: ", "").strip()
        return [("ip", ip)] if ip else []
