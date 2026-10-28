import os, httpx
from core.models import Hit

KEY = os.environ.get("HORUS_API_KEY", "")

class Horus:
    name = "horus"
    accepts = ("email", "username", "ip", "domain")
    free = False
    pillar = "stealer"

    async def query(self, seed, kind):
        if not KEY:
            return []
        # Horus uses /v1/search/stealer for email/username, /v1/search/ulp for URL pivots
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get(
                    "https://horus.st/api/v1/search/stealer",
                    params={"q": seed, "limit": 20},
                    headers={"X-Api-Key": KEY},
                )
            if r.status_code != 200:
                return []
            d = r.json()
            hits = []
            for rec in d.get("data", [])[:10]:
                hits.append(Hit(self.name, "stealer_log", rec.get("email") or seed, {
                    "machine": rec.get("pcKey"),
                    "origin": rec.get("origin"),
                    "password": rec.get("password"),
                    "source": rec.get("source"),
                }))
            return hits
        except Exception:
            return []
