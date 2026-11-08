from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class ShodanHost(BaseModule):
    @property
    def id(self):
        return "shodan_host"

    @property
    def label(self):
        return "Shodan InternetDB"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "Passive open ports, hostnames, CPEs, CVEs and tags for an IP"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["ip"]

    def run(self, case, **kwargs):
        ip = (kwargs.get("ip") or "").strip()
        if not ip or not indicators.is_ip(ip):
            return self.result(rows=[("Error", f"Not a valid IP: {ip or '-'}")], status="error")

        data = sources.internetdb(ip)
        if not data:
            return self.result(
                title=f"Shodan: {ip}",
                source="Shodan InternetDB",
                status="not_found",
                rows=[("IP", ip), ("Result", "No InternetDB record for this address")],
            )

        ports = data.get("ports") or []
        hostnames = data.get("hostnames") or []
        cpes = data.get("cpes") or []
        vulns = data.get("vulns") or []
        tags = data.get("tags") or []

        risk = 0
        if vulns:
            risk += min(60, 15 + len(vulns) * 5)
        sensitive_ports = {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
        exposed = sorted(set(int(p) for p in ports if str(p).isdigit()) & sensitive_ports)
        if exposed:
            risk += min(25, len(exposed) * 4)

        rows = [
            ("IP", ip),
            ("Open ports", ", ".join(str(p) for p in ports[:40]) or "-"),
            ("Sensitive ports", ", ".join(str(p) for p in exposed) or "none"),
            ("Hostnames", ", ".join(hostnames[:12]) or "-"),
            ("Tags", ", ".join(str(t) for t in tags[:12]) or "-"),
            ("CPEs", str(len(cpes))),
            ("CVEs", str(len(vulns))),
        ]
        for cpe in cpes[:15]:
            rows.append(("CPE", str(cpe)[:150]))
        for cve in vulns[:30]:
            rows.append(("CVE", str(cve)))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Shodan: {ip}",
            source="Shodan InternetDB (passive)",
            confidence="high",
            rows=rows,
            risk=risk,
            ports=ports,
            vulns=vulns,
        )

    def pivots(self, result):
        ip = result.get("title", "").replace("Shodan: ", "").strip()
        pivots = [("ip", ip)] if ip else []
        for cve in (result.get("vulns") or [])[:20]:
            pivots.append(("cve", str(cve)))
        return pivots
