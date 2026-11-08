"""Key-gated lookup connectors.

These modules never ship private data.  They call a source you configure with
your own key/URL and return clear setup instructions when it is missing.
"""

from volume.core import config, sources
from volume.core.module_base import BaseModule
from volume.modules.connector_utils import connector_base, flatten, response_error


class NazAPI(BaseModule):
    @property
    def id(self):
        return "nazapi"

    @property
    def label(self):
        return "nazAPI"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Query a configured nazAPI endpoint for identity and contact intelligence"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 150

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("nazapi",)

    @property
    def inputs(self):
        return ["query"]

    @property
    def optional_inputs(self):
        return {"kind": "search"}

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip()
        kind = (kwargs.get("kind") or "search").strip()
        if not query:
            return self.result(rows=[("Error", "No query provided")], status="error")
        key = self.api_key("nazapi")
        if not key:
            return self.key_required(
                ("nazapi",),
                help_url="https://t.me/stomponheads",
                title=f"nazAPI: {query}",
                extra_rows=[("Note", "Private connector. Configure NAZAPI_API_KEY and NAZAPI_URL.")],
            )
        base = connector_base("nazapi", "https://api.nazapi.local")
        response = sources.nazapi_search(query, key, base=base, kind=kind)
        if response.get("status") != "ok":
            return self.result(
                title=f"nazAPI: {query}",
                source="nazAPI",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Query", query), ("Error", response_error(response))],
            )
        return self.result(
            title=f"nazAPI: {query}",
            source=f"nazAPI ({base})",
            confidence="medium",
            rows=[("Query", query), ("Kind", kind)] + flatten(response.get("data"), limit=70),
        )


class XboxProfile(BaseModule):
    @property
    def id(self):
        return "xbox_profile"

    @property
    def label(self):
        return "Xbox Profile"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Xbox gamertag profile through a configured XAPI/OpenXBL-compatible key"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 160

    @property
    def credit_cost(self):
        return 2

    @property
    def requires_key(self):
        return ("xbox",)

    @property
    def inputs(self):
        return ["gamertag"]

    def run(self, case, **kwargs):
        gamertag = (kwargs.get("gamertag") or "").strip()
        if not gamertag:
            return self.result(rows=[("Error", "No gamertag provided")], status="error")
        key = self.api_key("xbox")
        if not key:
            return self.key_required(
                ("xbox",),
                help_url="https://xapi.us/",
                title=f"Xbox Profile: {gamertag}",
                extra_rows=[("Note", "Requires an XAPI/OpenXBL key in XBOX_API_KEY.")],
            )
        base = connector_base("xbox", "https://xapi.us/v2")
        response = sources.xbox_lookup(gamertag, key, base=base)
        if response.get("status") != "ok":
            return self.result(
                title=f"Xbox Profile: {gamertag}",
                source="Xbox API",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Gamertag", gamertag), ("Error", response_error(response))],
            )
        return self.result(
            title=f"Xbox Profile: {gamertag}",
            source="Xbox API",
            confidence="high",
            rows=[("Gamertag", gamertag)] + flatten(response.get("data"), limit=70),
        )


class GHunt(BaseModule):
    @property
    def id(self):
        return "ghunt"

    @property
    def label(self):
        return "GHunt (Google Account)"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Google account intelligence through a self-hosted GHunt-compatible API"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 170

    @property
    def credit_cost(self):
        return 4

    @property
    def requires_key(self):
        return ("ghunt",)

    @property
    def inputs(self):
        return ["email"]

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip().lower()
        if not email:
            return self.result(rows=[("Error", "No email provided")], status="error")
        key = self.api_key("ghunt")
        if not key:
            return self.key_required(
                ("ghunt",),
                help_url="https://github.com/mxrch/GHunt",
                title=f"GHunt: {email}",
                extra_rows=[("Note", "Self-host GHunt and set GHUNT_API_KEY + GHUNT_URL.")],
            )
        base = connector_base("ghunt", "https://api.ghunt.local")
        response = sources.ghunt_lookup(email, key, base=base)
        if response.get("status") != "ok":
            return self.result(
                title=f"GHunt: {email}",
                source="GHunt",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Email", email), ("Error", response_error(response))],
            )
        return self.result(
            title=f"GHunt: {email}",
            source=f"GHunt ({base})",
            confidence="medium",
            rows=[("Email", email)] + flatten(response.get("data"), limit=70),
            email=email,
        )

    def pivots(self, result):
        return [("email", result.get("email"))] if result.get("email") else []


class EmailRepConnector(BaseModule):
    @property
    def id(self):
        return "emailrep_lookup"

    @property
    def label(self):
        return "EmailRep Lookup"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Email reputation, profiles, deliverability and domain age via EmailRep"

    @property
    def order(self):
        return 180

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["email"]

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip().lower()
        if not email:
            return self.result(rows=[("Error", "No email provided")], status="error")
        data = sources.emailrep(email, config.get_key("emailrep"))
        if not data:
            return self.result(
                title=f"EmailRep: {email}",
                source="EmailRep",
                status="source_down",
                rows=[("Email", email), ("Result", "No data (rate limited or unavailable)")],
            )
        return self.result(
            title=f"EmailRep: {email}",
            source="EmailRep",
            confidence="medium",
            rows=[("Email", email)] + flatten(data, limit=60),
            email=email,
        )

    def pivots(self, result):
        return [("email", result.get("email"))] if result.get("email") else []
