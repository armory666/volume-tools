import httpx
from core.models import Hit

class HIBPWeb:
    name = "hibp"
    accepts = ("email",)
    free = True
    pillar = "breach"

    async def query(self, seed, kind):
        if kind != "email":
            return []
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{seed}",
                    headers={"User-Agent": "volume.tools"}
                )
            if r.status_code == 404:
                return [Hit(self.name, "hibp_status", seed, {"breached": False})]
            if r.status_code == 200:
                breaches = r.json()
                return [Hit(self.name, "hibp_breach", seed, {
                    "breached": True,
                    "count": len(breaches),
                    "breaches": [b.get("Name") for b in breaches[:20]],
                })]
            return []
        except Exception:
            return []
