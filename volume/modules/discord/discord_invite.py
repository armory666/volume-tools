import re
from urllib.parse import urlparse

from volume.core import sources
from volume.core.module_base import BaseModule


INVITE_RE = re.compile(r"(?:discord\.gg/|discord(?:app)?\.com/invite/)([A-Za-z0-9-]+)", re.I)


class DiscordInvite(BaseModule):
    @property
    def id(self):
        return "discord_invite"

    @property
    def label(self):
        return "Discord Invite Lookup"

    @property
    def category(self):
        return "DISCORD"

    @property
    def description(self):
        return "Resolve an invite to its server, channel, members and expiry"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["invite"]

    @property
    def input_prompts(self):
        return {"invite": "Invite code or URL (discord.gg/example)"}

    def _code(self, value: str) -> str:
        value = (value or "").strip()
        match = INVITE_RE.search(value)
        if match:
            return match.group(1)
        if "://" in value:
            return (urlparse(value).path or "").strip("/").split("/")[-1]
        return value.strip("/").split("/")[-1]

    def run(self, case, **kwargs):
        code = self._code(kwargs.get("invite"))
        if not code:
            return self.result(rows=[("Error", "No invite code provided")], status="error")

        response = sources.discord_invite(code)
        if response.get("status") == "not_found":
            return self.result(
                title=f"Discord Invite: {code}",
                source="Discord API",
                status="not_found",
                rows=[("Invite", code), ("Result", "Invite is invalid, expired or revoked")],
            )
        if response.get("status") != "ok":
            return self.result(
                title=f"Discord Invite: {code}",
                source="Discord API",
                status=response.get("status", "error"),
                rows=[("Invite", code), ("Error", response.get("error") or "Lookup failed")],
            )

        data = response.get("data") or {}
        guild = data.get("guild") or {}
        channel = data.get("channel") or {}
        inviter = data.get("inviter") or {}
        rows = [
            ("Invite", data.get("code", code)),
            ("Server", guild.get("name", "-")),
            ("Server ID", guild.get("id", "-")),
            ("Description", (guild.get("description") or "-")[:300]),
            ("Channel", f"#{channel.get('name', '-')} ({channel.get('type', '-')})"),
            ("Members", f"{data.get('approximate_member_count', '-')}"),
            ("Online", f"{data.get('approximate_presence_count', '-')}"),
            ("Inviter", inviter.get("username", "-")),
            ("Expires", data.get("expires_at") or "never"),
            ("Features", ", ".join(guild.get("features") or []) or "-"),
            ("Verification", str(guild.get("verification_level", "-"))),
            ("Nitro boost tier", str(guild.get("premium_tier", "-"))),
        ]
        if guild.get("icon"):
            rows.append(("Icon", f"https://cdn.discordapp.com/icons/{guild.get('id')}/{guild['icon']}.png"))

        return self.result(
            title=f"Discord Invite: {guild.get('name', code)}",
            source="Discord Invite API",
            confidence="high",
            rows=rows,
            guild_id=guild.get("id"),
            inviter=inviter.get("username"),
        )

    def pivots(self, result):
        pivots = []
        if result.get("guild_id"):
            pivots.append(("discord_guild", result["guild_id"]))
        if result.get("inviter"):
            pivots.append(("username", result["inviter"]))
        return pivots
