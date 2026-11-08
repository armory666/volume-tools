"""Discord-category extensions: Roblox pivots, name history and search."""

from urllib.parse import quote

from volume.core import config, sources
from volume.core.module_base import BaseModule
from volume.modules.connector_utils import connector_base, flatten, response_error


class DiscordToRoblox(BaseModule):
    @property
    def id(self):
        return "discord_roblox"

    @property
    def label(self):
        return "Discord → Roblox"

    @property
    def category(self):
        return "DISCORD"

    @property
    def description(self):
        return "Decode a Discord ID and resolve a linked Roblox profile"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["discord_id"]

    @property
    def optional_inputs(self):
        return {"roblox_username": ""}

    @property
    def input_prompts(self):
        return {
            "discord_id": "Discord user ID (snowflake)",
            "roblox_username": "Roblox username (optional, if known)",
        }

    def run(self, case, **kwargs):
        discord_id = str(kwargs.get("discord_id") or "").strip().strip("<>@!")
        roblox_username = (kwargs.get("roblox_username") or "").strip()
        if not discord_id:
            return self.result(rows=[("Error", "No Discord ID provided")], status="error")

        snowflake = sources.snowflake_info(discord_id)
        rows = [("Discord ID", discord_id)]
        if snowflake:
            rows.extend([
                ("Account created", snowflake.get("created", "")[:19]),
                ("Age (days)", str(snowflake.get("age_days"))),
            ])

        if roblox_username:
            user = sources.roblox_user_by_username(roblox_username)
            if user:
                rows.extend([
                    ("Roblox username", user.get("name") or roblox_username),
                    ("Roblox display name", user.get("displayName") or "-"),
                    ("Roblox ID", str(user.get("id") or "-")),
                    ("Roblox profile", f"https://www.roblox.com/users/{user.get('id')}/profile"),
                    ("Roblox created", (user.get("created") or "-")[:19]),
                    ("Roblox banned", str(user.get("isBanned"))),
                ])
                return self.result(
                    title=f"Discord → Roblox: {roblox_username}",
                    source="Discord snowflake + Roblox public API",
                    confidence="high",
                    rows=rows,
                    discord_id=discord_id,
                )
            rows.append(("Roblox", f"No user named '{roblox_username}'"))

        map_base = connector_base("roblox_map", "")
        if map_base:
            response = sources.net.get(
                f"{map_base.rstrip('/')}/discord/{quote(discord_id, safe='')}",
                source="roblox",
            )
            if response.get("status") == "ok":
                rows.append(("Mapping service", map_base))
                rows.extend(flatten(response.get("data"), limit=40))
                return self.result(
                    title=f"Discord → Roblox: {discord_id}",
                    source="configured mapping service",
                    confidence="medium",
                    rows=rows,
                    discord_id=discord_id,
                )
            rows.append(("Mapping service", f"unavailable ({response_error(response)})"))

        rows.extend([
            ("Mapping", "No public Discord→Roblox mapping exists."),
            ("Next step", "Provide roblox_username, or configure ROBLOX_MAP_URL with your mapping API."),
            ("Roblox search", f"https://www.roblox.com/search/users?keyword={quote(discord_id, safe='')}"),
        ])
        return self.result(
            title=f"Discord → Roblox: {discord_id}",
            source="Discord snowflake",
            confidence="low",
            rows=rows,
            discord_id=discord_id,
        )

    def pivots(self, result):
        return [("discord", result.get("discord_id"))] if result.get("discord_id") else []


class DiscordPreviousNames(BaseModule):
    @property
    def id(self):
        return "discord_prev_names"

    @property
    def label(self):
        return "Discord Previous Names"

    @property
    def category(self):
        return "DISCORD"

    @property
    def description(self):
        return "Resolve a Discord user and query a configured name-history service"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("discord",)

    @property
    def inputs(self):
        return ["user_id"]

    def run(self, case, **kwargs):
        user_id = str(kwargs.get("user_id") or "").strip().strip("<>@!")
        if not user_id:
            return self.result(rows=[("Error", "No Discord user ID provided")], status="error")
        rows = [("Discord ID", user_id)]
        snowflake = sources.snowflake_info(user_id)
        if snowflake:
            rows.append(("Account created", snowflake.get("created", "")[:19]))

        token = config.get_key("discord")
        if token:
            response = sources.discord_user(user_id, token)
            if response.get("status") == "ok" and isinstance(response.get("data"), dict):
                data = response["data"]
                rows.extend([
                    ("Username", data.get("username") or "-"),
                    ("Display name", data.get("global_name") or "-"),
                    ("Bot", str(data.get("bot"))),
                    ("Avatar", f"https://cdn.discordapp.com/avatars/{user_id}/{data.get('avatar')}.png" if data.get("avatar") else "-"),
                ])
            else:
                rows.append(("Discord API", f"unavailable ({response_error(response)})"))

        history_base = connector_base("discord_history", "")
        if history_base:
            response = sources.net.get(
                f"{history_base.rstrip('/')}/user/{quote(user_id, safe='')}/names",
                source="discord",
                headers={"X-API-Key": config.get_key("discord_history") or ""},
            )
            if response.get("status") == "ok":
                rows.append(("History service", history_base))
                rows.extend(flatten(response.get("data"), limit=50))
            else:
                rows.append(("History service", f"unavailable ({response_error(response)})"))
        elif not token:
            return self.key_required(
                ("discord",),
                help_url="https://discord.com/developers/docs",
                title=f"Discord Previous Names: {user_id}",
                extra_rows=[("Note", "Set DISCORD_API_KEY (bot token) and/or DISCORD_HISTORY_URL.")],
            )
        else:
            rows.append((
                "Previous names",
                "The Discord API does not expose name history. Configure DISCORD_HISTORY_URL.",
            ))

        return self.result(
            title=f"Discord Previous Names: {user_id}",
            source="Discord API + configured history service",
            confidence="medium",
            rows=rows,
            user_id=user_id,
        )

    def pivots(self, result):
        return [("discord", result.get("user_id"))] if result.get("user_id") else []


class DiscordSearch(BaseModule):
    @property
    def id(self):
        return "discord_search"

    @property
    def label(self):
        return "Discord Search"

    @property
    def category(self):
        return "DISCORD"

    @property
    def description(self):
        return "Search members of a guild with a configured Discord bot token"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("discord",)

    @property
    def inputs(self):
        return ["query"]

    @property
    def optional_inputs(self):
        return {"guild_id": ""}

    @property
    def input_prompts(self):
        return {"query": "Username / nickname fragment", "guild_id": "Discord guild (server) ID"}

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip()
        guild_id = str(kwargs.get("guild_id") or "").strip()
        if not query:
            return self.result(rows=[("Error", "No search query provided")], status="error")
        token = config.get_key("discord")
        if not token:
            return self.key_required(
                ("discord",),
                help_url="https://discord.com/developers/docs",
                title=f"Discord Search: {query}",
                extra_rows=[("Note", "Set DISCORD_API_KEY to a bot token with the Guild Members intent.")],
            )
        if not guild_id:
            return self.result(
                title=f"Discord Search: {query}",
                status="error",
                rows=[
                    ("Query", query),
                    ("Error", "guild_id is required for Discord member search."),
                    ("Note", "Use --arg guild_id=123456789012345678."),
                ],
            )
        response = sources.net.get(
            f"https://discord.com/api/v10/guilds/{quote(guild_id, safe='')}/members/search",
            source="discord",
            headers={"Authorization": f"Bot {token}"},
            params={"query": query, "limit": 25},
        )
        if response.get("status") != "ok":
            return self.result(
                title=f"Discord Search: {query}",
                source="Discord API",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Query", query), ("Guild", guild_id), ("Error", response_error(response))],
            )
        members = response.get("data")
        if not isinstance(members, list):
            members = []
        rows = [("Query", query), ("Guild", guild_id), ("Matches", str(len(members)))]
        for member in members[:25]:
            user = member.get("user") or {}
            rows.append((
                user.get("username") or member.get("nick") or "member",
                f"id={user.get('id')} · nick={member.get('nick') or '-'} · "
                f"joined={str(member.get('joined_at') or '-')[:10]}",
            ))
        return self.result(
            title=f"Discord Search: {query}",
            source="Discord API",
            confidence="high",
            rows=rows,
        )


class DiscordHistory(BaseModule):
    @property
    def id(self):
        return "discord_history"

    @property
    def label(self):
        return "Discord History"

    @property
    def category(self):
        return "DISCORD"

    @property
    def description(self):
        return "Account age and configured message/name history for a Discord user"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 50

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("discord",)

    @property
    def inputs(self):
        return ["user_id"]

    def run(self, case, **kwargs):
        user_id = str(kwargs.get("user_id") or "").strip().strip("<>@!")
        if not user_id:
            return self.result(rows=[("Error", "No Discord user ID provided")], status="error")
        rows = [("Discord ID", user_id)]
        snowflake = sources.snowflake_info(user_id)
        if snowflake:
            rows.extend([
                ("Account created", snowflake.get("created", "")[:19]),
                ("Age (days)", str(snowflake.get("age_days"))),
                ("Worker", str(snowflake.get("worker"))),
                ("Process", str(snowflake.get("process"))),
                ("Increment", str(snowflake.get("increment"))),
            ])

        history_base = connector_base("discord_history", "")
        if history_base:
            response = sources.net.get(
                f"{history_base.rstrip('/')}/user/{quote(user_id, safe='')}",
                source="discord",
                headers={"X-API-Key": config.get_key("discord_history") or ""},
            )
            if response.get("status") == "ok":
                rows.append(("History service", history_base))
                rows.extend(flatten(response.get("data"), limit=60))
            else:
                rows.append(("History service", f"unavailable ({response_error(response)})"))
        else:
            token = config.get_key("discord")
            if token:
                response = sources.discord_user(user_id, token)
                if response.get("status") == "ok" and isinstance(response.get("data"), dict):
                    data = response["data"]
                    rows.extend([
                        ("Username", data.get("username") or "-"),
                        ("Display name", data.get("global_name") or "-"),
                    ])
                else:
                    rows.append(("Discord API", f"unavailable ({response_error(response)})"))
            else:
                return self.key_required(
                    ("discord",),
                    help_url="https://discord.com/developers/docs",
                    title=f"Discord History: {user_id}",
                    extra_rows=[
                        ("Note", "Set DISCORD_API_KEY (bot token) and/or DISCORD_HISTORY_URL."),
                        ("Note", "Discord does not expose global message history through the public API."),
                    ],
                )
            rows.append((
                "Message history",
                "Not available from Discord's public API. Configure DISCORD_HISTORY_URL.",
            ))

        return self.result(
            title=f"Discord History: {user_id}",
            source="Discord snowflake + configured history service",
            confidence="medium",
            rows=rows,
            user_id=user_id,
        )

    def pivots(self, result):
        return [("discord", result.get("user_id"))] if result.get("user_id") else []
