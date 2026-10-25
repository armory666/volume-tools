import httpx
from core.models import Hit

BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

class HudsonRock:
    name = "hudsonrock"
    accepts = ("email", "username", "domain")
    free = True
    pillar = "stealer"

    async def query(self, seed, kind):
        endpoint = {
            "email":    f"{BASE}/search-by-email",
            "username": f"{BASE}/search-by-username",
            "domain":   f"{BASE}/search-by-domain",
        }.get(kind)
        if not endpoint:
            return []
        param = kind if kind != "domain" else "domain"
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get(endpoint, params={param: seed})
            if r.status_code != 200:
                return []
            data = (r.json() or {}).get("data", {}) or {}
            if not data:
                return []
            hits = [Hit(self.name, "stealer", seed, {
                "stealer_family": data.get("stealerFamily"),
                "computer_name": data.get("computerName"),
                "date_compromised": data.get("date_compromised"),
                "top_passwords": data.get("top_passwords", []),
                "top_logins": data.get("top_logins", []),
            })]
            for p in (data.get("top_passwords") or [])[:5]:
                hits.append(Hit(self.name, "password", p, {"via": seed}))
            return hits
        except Exception:
            return []
