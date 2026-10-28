import httpx
from core.models import Hit

class DiscordInvite:
    name = "discord_invite"
    accepts = ("discord_invite", "domain")
    free = True
    pillar = "discord"

    async def query(self, seed, kind):
        code = seed.split("/")[-1].split("?")[0]
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"https://discord.com/api/v9/invites/{code}?with_counts=true")
            if r.status_code == 200:
                d = r.json()
                g = d.get("guild", {})
                return [Hit(self.name, "discord_guild", g.get("id", code), {
                    "name": g.get("name"),
                    "member_count": d.get("approximate_member_count"),
                    "online_count": d.get("approximate_presence_count"),
                    "description": g.get("description")
                })]
        except Exception: return []
        return []
