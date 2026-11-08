from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class BreachDomain(BaseModule):
    @property
    def id(self):
        return "breach_domain"

    @property
    def label(self):
        return "Domain Breach Exposure"

    @property
    def category(self):
        return "BREACH"

    @property
    def description(self):
        return "Breaches that exposed accounts on a domain (HIBP catalogue)"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("hibp",)

    @property
    def inputs(self):
        return ["domain"]

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain or not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")

        key = self.api_key("hibp")
        if not key:
            return self.key_required(
                ("hibp",),
                help_url="https://haveibeenpwned.com/API/Key",
                title=f"Breach Domain: {domain}",
            )

        response = sources.hibp_all_breaches(key)
        if response.get("status") != "ok":
            return self.result(
                title=f"Breach Domain: {domain}",
                source="Have I Been Pwned",
                status=response.get("status", "error"),
                rows=[("Error", response.get("error") or "HIBP request failed")],
            )

        breaches = response.get("data") or []
        if not isinstance(breaches, list):
            breaches = []
        matched = [
            b for b in breaches
            if str(b.get("Domain", "")).lower().strip(".") == domain
            or str(b.get("Domain", "")).lower().endswith("." + domain)
        ]
        matched.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)

        total_accounts = sum(int(b.get("PwnCount") or 0) for b in matched)
        rows = [
            ("Domain", domain),
            ("Breaches", str(len(matched))),
            ("Accounts exposed", f"{total_accounts:,}"),
            ("Catalogue size", f"{len(breaches):,} breaches"),
        ]
        for breach in matched[:30]:
            data_classes = ", ".join(breach.get("DataClasses", [])[:8])
            flags = []
            if breach.get("IsVerified"):
                flags.append("verified")
            if breach.get("IsSensitive"):
                flags.append("sensitive")
            if breach.get("IsFabricated"):
                flags.append("fabricated")
            rows.append(
                (
                    f"{breach.get('Name', '?')} ({breach.get('BreachDate', '?')})",
                    f"{int(breach.get('PwnCount') or 0):,} accounts · {data_classes} "
                    f"[{', '.join(flags) or 'unverified'}]",
                )
            )
        if not matched:
            rows.append(("Result", "No catalogue breach lists this domain directly."))

        return self.result(
            title=f"Breach Domain: {domain}",
            source="Have I Been Pwned breach catalogue",
            confidence="high",
            rows=rows,
            breaches=len(matched),
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("Breach Domain: ", "").strip()
        return [("domain", domain)] if domain else []
