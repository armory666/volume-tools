from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class GitHubRecon(BaseModule):
    @property
    def id(self):
        return "github_recon"

    @property
    def label(self):
        return "GitHub Recon"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Profile, repos, orgs and recent public activity"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 65

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["username"]

    def run(self, case, **kwargs):
        username = (kwargs.get("username") or "").strip().lstrip("@")
        if not username:
            return self.result(rows=[("Error", "No username provided")], status="error")

        response = sources.github_user(username)
        if response.get("status") == "not_found":
            return self.result(
                title=f"GitHub: {username}",
                rows=[("Result", "User not found")],
                status="not_found",
            )
        if response.get("status") != "ok" or not isinstance(response.get("data"), dict):
            return self.result(
                title=f"GitHub: {username}",
                source="GitHub API",
                status=response.get("status", "error"),
                rows=[("Error", response.get("error") or "GitHub lookup failed")],
            )

        user = response["data"]
        rows = [
            ("Login", user.get("login", username)),
            ("Name", user.get("name") or "-"),
            ("Company", user.get("company") or "-"),
            ("Location", user.get("location") or "-"),
            ("Bio", (user.get("bio") or "-")[:200]),
            ("Blog", user.get("blog") or "-"),
            ("Email", user.get("email") or "-"),
            ("Twitter", user.get("twitter_username") or "-"),
            ("Public repos", str(user.get("public_repos", 0))),
            ("Gists", str(user.get("public_gists", 0))),
            ("Followers", str(user.get("followers", 0))),
            ("Following", str(user.get("following", 0))),
            ("Created", str(user.get("created_at", "-"))[:10]),
            ("Updated", str(user.get("updated_at", "-"))[:10]),
        ]

        repos_response = sources.github_repos(username, limit=12)
        repos = repos_response.get("data") if repos_response.get("status") == "ok" else []
        if isinstance(repos, list):
            repos = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)
            rows.append(("Top repos", str(len(repos))))
            for repo in repos[:10]:
                rows.append(
                    (
                        repo.get("name", "-"),
                        f"{repo.get('language') or '?'} · ★{repo.get('stargazers_count', 0)} "
                        f"· updated {str(repo.get('updated_at', ''))[:10]}",
                    )
                )

        orgs_response = sources.github_orgs(username)
        orgs = orgs_response.get("data") if orgs_response.get("status") == "ok" else []
        if isinstance(orgs, list) and orgs:
            rows.append(("Orgs", ", ".join(o.get("login", "?") for o in orgs[:10])))

        events_response = sources.github_events(username)
        events = events_response.get("data") if events_response.get("status") == "ok" else []
        if isinstance(events, list) and events:
            recent = []
            for event in events[:6]:
                repo = (event.get("repo") or {}).get("name", "?")
                recent.append(f"{event.get('type', '?')} @ {repo}")
            rows.append(("Recent activity", "; ".join(recent)))

        return self.result(
            title=f"GitHub: {username}",
            source="GitHub REST API",
            confidence="high",
            rows=rows,
            profile=user,
        )

    def pivots(self, result):
        user = result.get("profile") or {}
        pivots = []
        if user.get("login"):
            pivots.append(("username", user["login"]))
        if user.get("email"):
            pivots.append(("email", user["email"]))
        if user.get("blog") and indicators.is_domain(indicators.normalize_domain(user["blog"])):
            pivots.append(("domain", indicators.normalize_domain(user["blog"])))
        return pivots
