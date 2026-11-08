"""Leaks-category modules.

Private stealer-log / credential sources are explicit key-gated connectors.  No
private data is bundled and missing configuration is refunded by the UI/CLI.
"""

from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule
from volume.modules.connector_utils import connector_base, flatten, response_error


def _leakix_rows(response, limit=60):
    if response.get("status") != "ok":
        return [("LeakIX", f"unavailable ({response_error(response)})")]
    data = response.get("data")
    rows = []
    if isinstance(data, dict):
        items = data.get("Results") or data.get("results") or data.get("data") or []
        if not isinstance(items, list):
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []
    rows.append(("LeakIX results", str(len(items))))
    for item in items[:12]:
        if not isinstance(item, dict):
            rows.append(("LeakIX", str(item)[:300]))
            continue
        title = item.get("summary") or item.get("event_source") or item.get("host") or "result"
        detail = " · ".join(
            str(item.get(key))
            for key in ("host", "ip", "port", "severity", "date", "event_type")
            if item.get(key)
        )
        rows.append((str(title)[:80], detail[:400]))
    return rows


class LeakIndex(BaseModule):
    @property
    def id(self):
        return "leak_index"

    @property
    def label(self):
        return "Leak Index"

    @property
    def category(self):
        return "LEAKS"

    @property
    def description(self):
        return "Search the public HIBP breach catalogue and LeakIX leak index"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["query"]

    @property
    def input_prompts(self):
        return {"query": "Domain, email or keyword"}

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip().lower()
        if not query:
            return self.result(rows=[("Error", "No query provided")], status="error")

        domain = indicators.normalize_domain(query)
        rows = [("Query", query)]
        catalogue = sources.hibp_breaches_public()
        if catalogue.get("status") == "ok" and isinstance(catalogue.get("data"), list):
            breaches = catalogue["data"]
            matched = []
            for breach in breaches:
                haystack = " ".join(
                    str(breach.get(field) or "")
                    for field in ("Name", "Title", "Domain", "Description")
                ).lower()
                if query in haystack:
                    matched.append(breach)
            matched.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)
            rows.append(("HIBP catalogue", f"{len(matched)} match(es) of {len(breaches):,}"))
            for breach in matched[:20]:
                rows.append((
                    breach.get("Name") or breach.get("Title") or "breach",
                    f"{breach.get('BreachDate', '?')} · {breach.get('Domain') or '-'} · "
                    f"{int(breach.get('PwnCount') or 0):,} accounts · "
                    f"{', '.join((breach.get('DataClasses') or [])[:6])}",
                ))
        else:
            rows.append(("HIBP catalogue", f"unavailable ({response_error(catalogue)})"))

        leakix_key = config.get_key("leakix")
        if indicators.is_domain(domain):
            response = sources.leakix_domain(domain, leakix_key)
        else:
            response = sources.leakix_search("leak", query, leakix_key)
        rows.extend(_leakix_rows(response))
        if not leakix_key:
            rows.append(("LeakIX key", "optional; set LEAKIX_API_KEY for full results"))

        return self.result(
            title=f"Leak Index: {query}",
            source="HIBP catalogue + LeakIX",
            confidence="medium",
            rows=rows,
            query=query,
        )


class StealerLogs(BaseModule):
    @property
    def id(self):
        return "stealer_logs"

    @property
    def label(self):
        return "Stealer Logs"

    @property
    def category(self):
        return "LEAKS"

    @property
    def description(self):
        return "Search a configured stealer-log index for an email, username or domain"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 4

    @property
    def requires_key(self):
        return ("stealer",)

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
        key = self.api_key("stealer")
        if not key:
            return self.key_required(
                ("stealer",),
                help_url="https://t.me/stomponheads",
                title=f"Stealer Logs: {query}",
                extra_rows=[("Note", "Configure STEALER_API_KEY and STEALER_URL for your log index.")],
            )
        base = connector_base("stealer", "https://api.stealerlogs.local")
        response = sources.stealer_search(query, key, base=base, kind=kind)
        if response.get("status") != "ok":
            return self.result(
                title=f"Stealer Logs: {query}",
                source="stealer-log connector",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Query", query), ("Error", response_error(response))],
            )
        return self.result(
            title=f"Stealer Logs: {query}",
            source=f"stealer-log connector ({base})",
            confidence="medium",
            rows=[("Query", query), ("Kind", kind)] + flatten(response.get("data"), limit=80),
            query=query,
        )


class StealerlogInvestigation(BaseModule):
    @property
    def id(self):
        return "stealerlog_investigation"

    @property
    def label(self):
        return "Stealerlog Investigation"

    @property
    def category(self):
        return "LEAKS"

    @property
    def description(self):
        return "Pivot across a configured stealer-log corpus by email, username or domain"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 5

    @property
    def requires_key(self):
        return ("stealer",)

    @property
    def inputs(self):
        return ["query"]

    @property
    def optional_inputs(self):
        return {"kind": "investigation"}

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip()
        kind = (kwargs.get("kind") or "investigation").strip()
        if not query:
            return self.result(rows=[("Error", "No query provided")], status="error")
        key = self.api_key("stealer")
        if not key:
            return self.key_required(
                ("stealer",),
                help_url="https://t.me/stomponheads",
                title=f"Stealerlog Investigation: {query}",
                extra_rows=[("Note", "Configure STEALER_API_KEY and STEALER_URL for your corpus.")],
            )
        base = connector_base("stealer", "https://api.stealerlogs.local")
        response = sources.stealer_search(query, key, base=base, kind=kind)
        if response.get("status") != "ok":
            return self.result(
                title=f"Stealerlog Investigation: {query}",
                source="stealer-log connector",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Query", query), ("Error", response_error(response))],
            )
        rows = [
            ("Query", query),
            ("Kind", kind),
            ("Warning", "Handle stealer-log data as sensitive personal data."),
        ] + flatten(response.get("data"), limit=90)
        return self.result(
            title=f"Stealerlog Investigation: {query}",
            source=f"stealer-log connector ({base})",
            confidence="medium",
            rows=rows,
            query=query,
        )


class CredentialSearch(BaseModule):
    @property
    def id(self):
        return "credential_search"

    @property
    def label(self):
        return "Credential Search"

    @property
    def category(self):
        return "LEAKS"

    @property
    def description(self):
        return "Check an email against HIBP and a configured stealer/credential index"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 4

    @property
    def requires_key(self):
        return ("hibp", "stealer")

    @property
    def inputs(self):
        return ["query"]

    @property
    def input_prompts(self):
        return {"query": "Email address, username or domain"}

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip().lower()
        if not query:
            return self.result(rows=[("Error", "No query provided")], status="error")

        rows = [("Query", query)]
        used = []
        hibp_key = config.get_key("hibp")
        if hibp_key and indicators.is_email(query):
            breaches = sources.hibp_breaches(query, hibp_key)
            data = breaches.get("data")
            if isinstance(data, list):
                used.append("HIBP")
                rows.append(("HIBP breaches", str(len(data))))
                for breach in data[:15]:
                    rows.append((
                        breach.get("Name", "breach"),
                        f"{breach.get('BreachDate', '?')} · {', '.join((breach.get('DataClasses') or [])[:6])}",
                    ))
            elif breaches.get("status") == "not_found":
                used.append("HIBP")
                rows.append(("HIBP breaches", "none found"))
            else:
                rows.append(("HIBP", f"unavailable ({response_error(breaches)})"))

        stealer_key = config.get_key("stealer")
        if stealer_key:
            used.append("stealer index")
            base = connector_base("stealer", "https://api.stealerlogs.local")
            response = sources.stealer_search(query, stealer_key, base=base, kind="credential")
            if response.get("status") == "ok":
                rows.extend(flatten(response.get("data"), limit=60))
            else:
                rows.append(("Stealer index", f"unavailable ({response_error(response)})"))

        if not used:
            return self.key_required(
                ("hibp", "stealer"),
                help_url="https://haveibeenpwned.com/API/Key",
                title=f"Credential Search: {query}",
                extra_rows=[
                    ("Note", "Set HIBP_API_KEY and/or STEALER_API_KEY + STEALER_URL."),
                ],
            )
        rows.append(("Sources used", ", ".join(used)))
        return self.result(
            title=f"Credential Search: {query}",
            source=" + ".join(used),
            confidence="medium",
            rows=rows,
            query=query,
        )


class KittyDB(BaseModule):
    @property
    def id(self):
        return "kitty_db"

    @property
    def label(self):
        return "Kitty DB"

    @property
    def category(self):
        return "LEAKS"

    @property
    def description(self):
        return "Query a configured Kitty DB-compatible index"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 50

    @property
    def credit_cost(self):
        return 5

    @property
    def requires_key(self):
        return ("kitty",)

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
        key = self.api_key("kitty")
        if not key:
            return self.key_required(
                ("kitty",),
                help_url="https://t.me/stomponheads",
                title=f"Kitty DB: {query}",
                extra_rows=[("Note", "Configure KITTY_API_KEY and KITTY_URL for your Kitty DB index.")],
            )
        base = connector_base("kitty", "https://api.kittydb.local")
        response = sources.kitty_search(query, key, base=base, kind=kind)
        if response.get("status") != "ok":
            return self.result(
                title=f"Kitty DB: {query}",
                source="Kitty DB connector",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Query", query), ("Error", response_error(response))],
            )
        return self.result(
            title=f"Kitty DB: {query}",
            source=f"Kitty DB connector ({base})",
            confidence="medium",
            rows=[("Query", query), ("Kind", kind)] + flatten(response.get("data"), limit=80),
            query=query,
        )
