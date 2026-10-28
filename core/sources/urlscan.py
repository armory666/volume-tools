import httpx
from core.models import Hit

class UrlScan:
    name = "urlscan"
    accepts = ("domain", "ip")
    free = True
    pillar = "iptrace"

    async def query(self, seed, kind):
        if kind not in ("domain", "ip"): return []
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"https://urlscan.io/api/v1/search/?q={seed}")
            if r.status_code == 200:
                d = r.json()
                hits = []
                for res in d.get("results", [])[:3]:
                    hits.append(Hit(self.name, "scan", res.get("page", {}).get("url", seed), {
                        "ip": res.get("page", {}).get("ip"),
                        "server": res.get("page", {}).get("server"),
                        "asn": res.get("page", {}).get("asnname")
                    }))
                return hits
        except Exception: return []
        return []
