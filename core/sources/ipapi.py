import httpx
from core.models import Hit

class IpApi:
    name = "ipapi"
    accepts = ("ip",)
    free = True
    pillar = "iptrace"

    async def query(self, seed, kind):
        if kind != "ip":
            return []
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f"http://ip-api.com/json/{seed}",
                    params={"fields": "status,country,regionName,city,lat,lon,"
                                      "isp,org,as,reverse,proxy,hosting,query"})
            d = r.json()
            if d.get("status") != "success":
                return []
            return [Hit(self.name, "ip_geo", seed, {
                "country": d.get("country"), "region": d.get("regionName"),
                "city": d.get("city"), "lat": d.get("lat"), "lon": d.get("lon"),
                "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as"),
                "reverse": d.get("reverse"), "proxy": d.get("proxy"),
                "hosting": d.get("hosting"),
            })]
        except Exception:
            return []
