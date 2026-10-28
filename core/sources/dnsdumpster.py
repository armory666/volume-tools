import httpx
from core.models import Hit

class DnsDumpster:
    name = "dnsdumpster"
    accepts = ("domain",)
    free = True
    pillar = "iptrace"

    async def query(self, seed, kind):
        if kind != "domain": return []
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.get(f"https://api.hackertarget.com/hostsearch/?q={seed}")
            if r.status_code == 200 and "error" not in r.text.lower():
                hits = []
                for line in r.text.split("\n")[:10]:
                    parts = line.split(",")
                    if len(parts) == 2:
                        hits.append(Hit(self.name, "subdomain", parts[0], {"ip": parts[1]}))
                return hits
        except Exception: return []
        return []
