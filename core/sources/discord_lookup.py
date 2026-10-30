import os, httpx, re
from core.models import Hit

BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")

class DiscordLookup:
    name = "discord_lookup"
    accepts = ("discord_id",)
    free = True
    pillar = "discord"

    async def query(self, seed, kind):
        if kind != "discord_id":
            return []

        if not re.match(r"^\d{17,19}$", str(seed)):
            return [Hit(self.name, "error", seed, {"reason": "invalid snowflake (17-19 digits)"})]

        if BOT_TOKEN:
            try:
                async with httpx.AsyncClient(timeout=15) as c:
                    r = await c.get(
                        f"https://discord.com/api/v10/users/{seed}",
                        headers={
                            "Authorization": f"Bot {BOT_TOKEN}",
                            "User-Agent": "DiscordBot (https://volume.tools, 2.0)"
                        }
                    )
                if r.status_code == 200:
                    d = r.json()
                    return [Hit(self.name, "discord_user", seed, {
                        "username": d.get("username"),
                        "global_name": d.get("global_name"),
                        "avatar": d.get("avatar"),
                        "banner": d.get("banner"),
                        "accent_color": d.get("accent_color"),
                        "bot": d.get("bot", False),
                        "public_flags": d.get("public_flags"),
                        "verified": d.get("verified", False),
                        "auth": "bot",
                    })]
                elif r.status_code == 429:
                    return [Hit(self.name, "error", seed, {"reason": "rate limited by Discord — try in 30s"})]
                elif r.status_code != 404:
                    return [Hit(self.name, "error", seed, {"reason": f"bot api {r.status_code}"})]
            except Exception as e:
                print(f"[discord_lookup] bot error: {e}")

        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(
                    f"https://discord.com/api/v10/users/{seed}",
                    headers={"User-Agent": "DiscordBot (https://volume.tools, 2.0)"}
                )
            if r.status_code == 200:
                d = r.json()
                return [Hit(self.name, "discord_user", seed, {
                    "username": d.get("username"),
                    "global_name": d.get("global_name"),
                    "avatar": d.get("avatar"),
                    "bot": d.get("bot", False),
                    "auth": "anonymous",
                })]
            if r.status_code == 404:
                return [Hit(self.name, "error", seed, {
                    "reason": "user not found or no mutual server" + ("" if BOT_TOKEN else " — add DISCORD_BOT_TOKEN for wider coverage")
                })]
            return [Hit(self.name, "error", seed, {"reason": f"api {r.status_code}"})]
        except Exception as e:
            return [Hit(self.name, "error", seed, {"reason": str(e)[:100]})]
