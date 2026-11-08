import re
from collections import Counter
from urllib.parse import urlparse

from volume.core import indicators, sources
from volume.core.module_base import BaseModule


INTERESTING = re.compile(
    r"(admin|login|signin|api|backup|config|\.env|\.git|phpinfo|upload|debug|"
    r"test|dev|staging|old|wp-admin|server-status|\.sql|\.bak|\.zip|\.tar|"
    r"\.log|\.json|\.xml|dashboard|internal|private)",
    re.I,
)


class WaybackIntel(BaseModule):
    @property
    def id(self):
        return "wayback_intel"

    @property
    def label(self):
        return "Wayback Machine Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Historic snapshots, first/last seen and interesting archived paths"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 75

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["domain"]

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain or not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")

        summary = sources.wayback_summary(domain)
        if not summary.get("ok"):
            return self.result(
                title=f"Wayback: {domain}",
                source="Wayback CDX",
                status="not_found",
                rows=[("Domain", domain), ("Result", summary.get("error") or "No archived snapshots")],
            )

        captures = summary["captures"]
        timestamps = sorted(c["timestamp"] for c in captures if c.get("timestamp"))
        hosts = Counter(urlparse(c["url"]).hostname or "?" for c in captures)
        statuses = Counter(str(c.get("status")) for c in captures)
        mimes = Counter(c.get("mime") or "?" for c in captures)
        interesting = []
        seen = set()
        for capture in captures:
            url = capture["url"]
            if INTERESTING.search(url) and url not in seen:
                seen.add(url)
                interesting.append(url)

        def fmt(ts):
            ts = str(ts)
            return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts

        rows = [
            ("Domain", domain),
            ("Snapshots", str(summary["count"])),
            ("First capture", fmt(timestamps[0]) if timestamps else "-"),
            ("Last capture", fmt(timestamps[-1]) if timestamps else "-"),
            ("Hosts", ", ".join(f"{h} ({n})" for h, n in hosts.most_common(8))),
            ("Status codes", ", ".join(f"{s}:{n}" for s, n in statuses.most_common(6))),
            ("MIME types", ", ".join(f"{m}:{n}" for m, n in mimes.most_common(5))),
        ]
        if interesting:
            rows.append(("Interesting paths", str(len(interesting))))
            for url in interesting[:30]:
                rows.append(("  archived", url[:160]))
        else:
            rows.append(("Interesting paths", "none matched"))

        return self.result(
            title=f"Wayback: {domain}",
            source="Wayback Machine CDX API",
            confidence="medium",
            rows=rows,
            interesting=interesting[:100],
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("Wayback: ", "").strip()
        return [("domain", domain)] if domain else []
