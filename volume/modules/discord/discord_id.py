from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule


class DiscordID(BaseModule):
    @property
    def id(self):
        return "discord_id"

    @property
    def label(self):
        return "Discord ID / Snowflake"

    @property
    def category(self):
        return "DISCORD"

    @property
    def description(self):
        return "Decode a snowflake and optionally resolve the public user profile"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 1

    @property
    def requires_key(self):
        return ("discord",)

    @property
    def inputs(self):
        return ["user_id"]

    @property
    def input_prompts(self):
        return {"user_id": "Discord user ID (17-20 digit snowflake)"}

    def run(self, case, **kwargs):
        raw = (kwargs.get("user_id") or "").strip().strip("<>@!")
        if not raw:
            return self.result(rows=[("Error", "No user ID provided")], status="error")
        if not raw.isdigit():
            return self.result(rows=[("Error", "Discord IDs are numeric snowflakes")], status="error")

        info = sources.snowflake_info(raw)
        if not info:
            return self.result(rows=[("Error", "Could not decode snowflake")], status="error")

        rows = [
            ("User ID", info["id"]),
            ("Created", info["created"]),
            ("Account age", f"{info['age_days']:,} days"),
            ("Worker", str(info["worker"])),
            ("Process", str(info["process"])),
            ("Increment", str(info["increment"])),
        ]

        token = config.get_key("discord")
        if token:
            response = sources.discord_user(raw, token)
            if response.get("status") == "ok":
                user = response.get("data") or {}
                rows.extend([
                    ("Username", user.get("username", "-")),
                    ("Display name", user.get("global_name") or "-"),
                    ("Bot", "yes" if user.get("bot") else "no"),
                    ("Avatar", user.get("avatar") or "default"),
                    ("Banner", user.get("banner") or "none"),
                    ("Accent color", str(user.get("accent_color") or "-")),
                ])
            elif response.get("status") == "not_found":
                rows.append(("Profile", "user not found"))
            else:
                rows.append(("Profile", f"lookup failed · {response.get('error') or response.get('status')}"))
        else:
            rows.append(("Profile", "set DISCORD_API_KEY (bot token) to resolve the public profile"))

        return self.result(
            title=f"Discord ID: {info['id']}",
            source="Discord snowflake + API",
            confidence="high",
            rows=rows,
            created=info["created"],
            user_id=info["id"],
        )

    def pivots(self, result):
        user_id = result.get("user_id")
        return [("discord_id", user_id)] if user_id else []
