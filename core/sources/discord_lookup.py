import httpx, re
from core.models import Hit

class DiscordLookup:
    name = "discord_lookup"
    accepts = ("discord_id",)
    free = True
    pillar = "discord"

    async def query(self, seed, kind):
        if kind != "discord_id":
            return []
        if not re.match(r"^\d{17,19}$", str(seed)):
            return [Hit(self.name, "error", seed, {"reason": "not a valid discord snowflake"})]
        try:
            async with httpx.AsyncClient(
                timeout=15,
                headers={"User-Agent": "DiscordBot (https://volume.tools, 1.0)"},
            ) as c:
                r = await c.get(f"https://discord.com/api/v10/users/{seed}")
            if r.status_code == 404:
                return [Hit(self.name, "error", seed, {"reason": "user not found or no mutual server"})]
            if r.status_code != 200:
                return [Hit(self.name, "error", seed, {"reason": f"api {r.status_code}"})]
            d = r.json()
            return [Hit(self.name, "discord_user", seed, {
                "username": d.get("username"),
                "global_name": d.get("global_name"),
                "avatar": d.get("avatar"),
                "bot": d.get("bot", False),
                "public_flags": d.get("public_flags"),
                "accent_color": d.get("accent_color"),
                "banner": d.get("banner"),
            })]
        except Exception as e:
            return [Hit(self.name, "error", seed, {"reason": str(e)[:100]})]
