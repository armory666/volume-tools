import httpx
from core.models import Hit

class BreachEngine:
    name = "breach"
    accepts = ("email",)
    free = True
    pillar = "breach"

    async def query(self, seed, kind):
        if kind != "email":
            return []
        
        hits = []
        
        # 1. Hudson Rock (Stealer Logs)
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.get(
                    "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
                    params={"email": seed}
                )
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    if d:
                        hits.append(Hit(self.name, "stealer_log", seed, {
                            "family": d.get("stealerFamily"),
                            "machine": d.get("computerName"),
                            "av": d.get("antiviruses", []),
                            "passwords": d.get("top_passwords", []),
                            "logins": d.get("top_logins", [])
                        }))
        except Exception:
            pass

        # 2. LeakCheck (Anonymous Free Tier Lookup)
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                # Leakcheck allows 1 free anonymous search per IP via this endpoint
                r = await c.get(f"https://leakcheck.io/api/public?check={seed}")
                if r.status_code == 200:
                    d = r.json()
                    if d.get("found"):
                        for src in d.get("sources", [])[:5]:
                            hits.append(Hit(self.name, "leakcheck_db", seed, {
                                "database": src.get("name"),
                                "date": src.get("date")
                            }))
        except Exception:
            pass

        return hits
