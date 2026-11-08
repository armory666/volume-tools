import re
from urllib.parse import quote

from volume.core import net
from volume.core.module_base import BaseModule


class UsernameSearch(BaseModule):
    @property
    def id(self):
        return "username_search"

    @property
    def label(self):
        return "Username Search"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Sweep public profiles across developer, social and gaming sites"

    @property
    def order(self):
        return 60

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["username"]

    def _sites(self, username: str):
        q = quote(username, safe="")
        return [
            ("GitHub", "get", f"https://api.github.com/users/{q}", "json"),
            ("GitLab", "get", f"https://gitlab.com/api/v4/users?username={q}", "list"),
            ("Reddit", "get", f"https://www.reddit.com/user/{q}/about.json", "json"),
            ("Keybase", "get", f"https://keybase.io/_/api/1.0/user/lookup.json?username={q}", "json"),
            ("Codeberg", "get", f"https://codeberg.org/api/v1/users/{q}", "json"),
            ("Bitbucket", "get", f"https://api.bitbucket.org/2.0/users/{q}", "json"),
            ("Docker Hub", "get", f"https://hub.docker.com/v2/users/{q}/", "json"),
            ("PyPI", "get", f"https://pypi.org/user/{q}/", "html"),
            ("npm", "get", f"https://registry.npmjs.org/-/user/org.couchdb.user:{q}", "json"),
            ("Hacker News", "get", f"https://hacker-news.firebaseio.com/v0/user/{q}.json", "json"),
            ("Lichess", "get", f"https://lichess.org/api/user/{q}", "json"),
            ("Chess.com", "get", f"https://api.chess.com/pub/player/{q}", "json"),
            ("Steam", "get", f"https://steamcommunity.com/id/{q}?xml=1", "xml"),
            ("Roblox", "post", "https://users.roblox.com/v1/usernames/users", "roblox"),
            ("HackerOne", "get", f"https://hackerone.com/{q}", "html"),
        ]

    def _found(self, site, kind, response):
        """True = found, False = definitely not found, None = could not tell."""
        status = response.get("status")
        if status == "not_found":
            return False
        if status != "ok":
            return None
        data = response.get("data")

        if kind == "list":
            return isinstance(data, list) and len(data) > 0
        if kind == "roblox":
            return bool((data or {}).get("data")) if isinstance(data, dict) else False
        if kind == "xml":
            return "<steamID64>" in str(data)
        if kind == "html":
            body = str(data)
            if site == "PyPI":
                return "Page not found" not in body and "404" not in body[:400]
            if site == "HackerOne":
                return "Page not found" not in body and "hackerone.com" in body.lower()
            return None
        if kind == "json":
            if data is None:
                return False
            if site == "Keybase":
                them = (data or {}).get("them") if isinstance(data, dict) else None
                return isinstance(them, list) and len(them) > 0
            if site == "Hacker News":
                return data is not None
            if isinstance(data, dict) and data.get("message") == "Not Found":
                return False
            return bool(data)
        return None

    def run(self, case, **kwargs):
        username = (kwargs.get("username") or "").strip().lstrip("@")
        if not username:
            return self.result(rows=[("Error", "No username provided")], status="error")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
            return self.result(
                rows=[("Error", "Username may only contain letters, numbers, dot, dash, underscore")],
                status="error",
            )

        rows = []
        found = []
        for site, method, url, kind in self._sites(username):
            if method == "post":
                response = net.post(
                    url, json={"usernames": [username], "excludeBannedUsers": True}
                )
            else:
                response = net.get(url)
            state = self._found(site, kind, response)
            if state is True:
                found.append(site)
                rows.append((site, f"FOUND  {url}"))
            elif state is False:
                rows.append((site, "not found"))
            else:
                reason = response.get("error") or response.get("status") or "unknown"
                rows.append((site, f"unknown ({str(reason)[:60]})"))

        return self.result(
            title=f"Username Search: {username}",
            source="public profile checks",
            confidence="medium",
            rows=[("Username", username), ("Found", f"{len(found)}/{len(rows)}")]
            + rows,
            found=found,
        )

    def pivots(self, result):
        username = result.get("title", "").replace("Username Search: ", "").strip()
        return [("username", username)] if username else []
