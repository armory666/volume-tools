import httpx, os
from core.models import Hit

STEAM_KEY = os.environ.get("STEAM_API_KEY", "")

class Steam:
    name = "steam"
    accepts = ("username",)
    free = True
    pillar = "discord"

    async def query(self, seed, kind):
        if kind != "username" or not STEAM_KEY: return []
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/?key={STEAM_KEY}&vanityurl={seed}")
            if r.status_code == 200 and r.json().get("response", {}).get("success") == 1:
                steamid = r.json()["response"]["steamid"]
                return [Hit(self.name, "steam_account", steamid, {"username": seed})]
        except Exception: return []
        return []
