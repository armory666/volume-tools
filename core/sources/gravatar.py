import hashlib, httpx
from core.models import Hit

class Gravatar:
    name = "gravatar"
    accepts = ("email",)
    free = True
    pillar = "email"

    async def query(self, seed, kind):
        if kind != "email":
            return []
        h = hashlib.md5(seed.strip().lower().encode()).hexdigest()
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"https://www.gravatar.com/avatar/{h}.json")
            if r.status_code != 200:
                return []
            e = r.json().get("entry", [{}])[0]
            return [Hit(self.name, "profile", seed, {
                "display_name": e.get("displayName"),
                "name": e.get("name"),
                "about": e.get("aboutMe"),
                "urls": [u.get("value") for u in e.get("urls", [])],
                "location": e.get("currentLocation"),
            })]
        except Exception:
            return []
