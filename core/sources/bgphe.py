import httpx, re
from core.models import Hit

class BgpHe:
    name = "bgphe"
    accepts = ("ip",)
    free = True
    pillar = "iptrace"

    async def query(self, seed, kind):
        if kind != "ip":
            return []
        try:
            async with httpx.AsyncClient(
                timeout=20, headers={"User-Agent": "Mozilla/5.0"},
                follow_redirects=True,
            ) as c:
                r = await c.get(f"https://bgp.he.net/ip/{seed}")
            asn = re.search(r"(AS\d+)", r.text)
            org = re.search(r"<title>([^<]+)</title>", r.text)
            return [Hit(self.name, "ip_asn", seed, {
                "asn": asn.group(1) if asn else None,
                "org": org.group(1).strip() if org else None,
            })]
        except Exception:
            return []
