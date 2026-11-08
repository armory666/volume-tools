from concurrent.futures import ThreadPoolExecutor

from volume.core import indicators, sources, webintel
from volume.core.module_base import BaseModule


class AttackSurface(BaseModule):
    @property
    def id(self):
        return "attack_surface"

    @property
    def label(self):
        return "Attack Surface Map"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "Passive inventory: subdomains, exposed ports, headers, robots and security.txt"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 60

    @property
    def credit_cost(self):
        return 5

    @property
    def inputs(self):
        return ["domain"]

    @property
    def optional_inputs(self):
        return {"limit": "25"}

    @property
    def input_prompts(self):
        return {
            "domain": "Root domain (example.com)",
            "limit": "How many hosts to probe (max 40)",
        }

    def _probe(self, host):
        result = {
            "host": host,
            "ips": sources.resolve_host(host, "A", lifetime=3.5),
            "ports": [],
            "server": "-",
            "status": "-",
            "tls": None,
        }
        if result["ips"]:
            try:
                db = sources.internetdb(result["ips"][0])
                result["ports"] = db.get("ports") or []
            except Exception:
                pass
        response, _ = webintel.fetch(f"https://{host}")
        if response.get("status") != "ok":
            response, _ = webintel.fetch(f"http://{host}")
        if response.get("status") == "ok":
            headers = webintel.header_map(response)
            result["server"] = headers.get("server", "-")
            result["status"] = str(response.get("code", "-"))
            result["tls"] = "https" if str(response.get("url", "")).startswith("https://") else "http"
        return result

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain or not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")
        try:
            limit = max(1, min(40, int(kwargs.get("limit") or 25)))
        except (TypeError, ValueError):
            limit = 25

        subdomains = sources.subdomains_from_crt(domain)
        hosts = sorted({domain, f"www.{domain}", *subdomains})
        hosts = hosts[:limit]

        probes = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            for probe in pool.map(self._probe, hosts):
                if probe["ips"] or probe["status"] != "-":
                    probes.append(probe)

        robots = webintel.robots(domain)
        sec_txt = webintel.security_txt(domain)
        sensitive_paths = robots.get("sensitive") or []
        exposure_ports = {21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}

        rows = [
            ("Domain", domain),
            ("CT subdomains", str(len(subdomains))),
            ("Hosts probed", str(len(hosts))),
            ("Live hosts", str(len(probes))),
            ("robots.txt", f"found · {len(robots.get('disallows', []))} rules" if robots.get("found") else "not found"),
            ("security.txt", "found" if sec_txt.get("found") else "not found"),
        ]
        if sensitive_paths:
            rows.append(("Sensitive robots paths", ", ".join(sensitive_paths[:10])))

        risk = 0
        exposed = []
        plain_http = 0
        for probe in probes:
            ports = [int(p) for p in probe["ports"] if str(p).isdigit()]
            risky = sorted(set(ports) & exposure_ports)
            if risky:
                exposed.extend((probe["host"], p) for p in risky)
            if probe["tls"] == "http":
                plain_http += 1
            rows.append(
                (
                    probe["host"],
                    f"{', '.join(probe['ips'][:2]) or '-'} · HTTP {probe['status']} · {probe['server'][:40]}"
                    + (f" · ports {', '.join(str(p) for p in ports[:10])}" if ports else ""),
                )
            )

        if exposed:
            risk += min(40, len(exposed) * 4)
            rows.append(("Exposed services", str(len(exposed))))
            for host, port in exposed[:20]:
                rows.append((f"  {host}", f"port {port}"))
        if sensitive_paths:
            risk += min(20, len(sensitive_paths) * 3)
        if plain_http:
            risk += min(15, plain_http * 3)
        if not sec_txt.get("found"):
            risk += 3

        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))
        return self.result(
            title=f"Attack Surface: {domain}",
            source="crt.sh + DNS + Shodan InternetDB + HTTP",
            confidence="high" if probes else "low",
            rows=rows,
            risk=risk,
            hosts=[p["host"] for p in probes],
            exposed=len(exposed),
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("Attack Surface: ", "").strip()
        pivots = [("domain", domain)] if domain else []
        for host in (result.get("hosts") or [])[:40]:
            pivots.append(("domain", host))
        return pivots
