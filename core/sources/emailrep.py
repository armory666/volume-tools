import httpx
from core.models import Hit

class EmailRep:
    name = "emailrep"
    accepts = ("email",)
    free = True
    pillar = "email"

    async def query(self, seed, kind):
        if kind != "email": return []
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"https://emailrep.io/{seed}", headers={"User-Agent": "volume.tools"})
            if r.status_code == 200:
                d = r.json()
                return [Hit(self.name, "reputation", seed, {
                    "reputation": d.get("reputation"),
                    "suspicious": d.get("suspicious"),
                    "references": d.get("references"),
                    "profiles": d.get("details", {}).get("profiles", [])
                })]
        except Exception: return []
        return []
