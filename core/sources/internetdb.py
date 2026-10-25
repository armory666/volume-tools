import httpx
from core.models import Hit

class InternetDB:
    name = "internetdb"
    accepts = ("ip",)
    free = True
    pillar = "iptrace"

    async def query(self, seed, kind):
        if kind != "ip":
            return []
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"https://internetdb.shodan.io/{seed}")
            if r.status_code != 200:
                return []
            d = r.json()
            return [Hit(self.name, "ip_scan", seed, {
                "ports": d.get("ports", []), "hostnames": d.get("hostnames", []),
                "cpes": d.get("cpes", []), "vulns": d.get("vulns", []),
                "tags": d.get("tags", []),
            })]
        except Exception:
            return []
