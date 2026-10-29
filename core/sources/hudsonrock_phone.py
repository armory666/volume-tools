import httpx
from core.models import Hit

class HudsonRockPhone:
    name = "hudsonrock_phone"
    accepts = ("phone",)
    free = True
    pillar = "stealer"

    async def query(self, seed, kind):
        if kind != "phone":
            return []
        clean = seed.replace("+", "").replace(" ", "").replace("-", "")
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get(
                    "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username",
                    params={"username": clean},
                )
            if r.status_code != 200:
                return []
            data = (r.json() or {}).get("data", {}) or {}
            if not data:
                return []
            return [Hit(self.name, "stealer_phone", seed, {
                "family": data.get("stealerFamily"),
                "machine": data.get("computerName"),
                "date": data.get("date_compromised"),
                "passwords": data.get("top_passwords", [])[:3],
            })]
        except Exception:
            return []
