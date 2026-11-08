"""Breach-category modules: account exposure and website breach monitoring."""

from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule
from volume.modules.connector_utils import response_error


class BreachIntel(BaseModule):
    @property
    def id(self):
        return "breach_intel"

    @property
    def label(self):
        return "Breach Intel"

    @property
    def category(self):
        return "BREACH"

    @property
    def description(self):
        return "Full HIBP breach and paste exposure for an email address"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 5

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("hibp",)

    @property
    def inputs(self):
        return ["email"]

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip().lower()
        if not indicators.is_email(email):
            return self.result(rows=[("Error", f"Not a valid email: {email or '-'}")], status="error")
        key = self.api_key("hibp")
        if not key:
            return self.key_required(
                ("hibp",),
                help_url="https://haveibeenpwned.com/API/Key",
                title=f"Breach Intel: {email}",
            )

        breaches = sources.hibp_breaches(email, key)
        pastes = sources.hibp_pastes(email, key)
        rows = [("Email", email)]
        if breaches.get("status") == "not_found":
            rows.append(("Breaches", "none found"))
        elif breaches.get("status") == "ok" and isinstance(breaches.get("data"), list):
            data = breaches["data"]
            rows.append(("Breaches", str(len(data))))
            data.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)
            for breach in data[:25]:
                flags = []
                if breach.get("IsVerified"):
                    flags.append("verified")
                if breach.get("IsSensitive"):
                    flags.append("sensitive")
                if breach.get("IsFabricated"):
                    flags.append("fabricated")
                rows.append((
                    breach.get("Name", "breach"),
                    f"{breach.get('BreachDate', '?')} · {breach.get('Domain') or '-'} · "
                    f"{int(breach.get('PwnCount') or 0):,} accounts · "
                    f"{', '.join((breach.get('DataClasses') or [])[:8])} "
                    f"[{', '.join(flags) or 'unverified'}]",
                ))
        else:
            rows.append(("Breaches", f"unavailable ({response_error(breaches)})"))

        if pastes.get("status") == "not_found":
            rows.append(("Pastes", "none found"))
        elif pastes.get("status") == "ok" and isinstance(pastes.get("data"), list):
            rows.append(("Pastes", str(len(pastes["data"]))))
            for paste in pastes["data"][:10]:
                rows.append((
                    paste.get("Source") or "paste",
                    f"{paste.get('Date') or '?'} · {paste.get('Title') or '-'} · "
                    f"{int(paste.get('EmailCount') or 0):,} emails",
                ))
        else:
            rows.append(("Pastes", f"unavailable ({response_error(pastes)})"))

        return self.result(
            title=f"Breach Intel: {email}",
            source="Have I Been Pwned",
            confidence="high",
            rows=rows,
            email=email,
        )

    def pivots(self, result):
        return [("email", result.get("email"))] if result.get("email") else []


class WebsiteBreachMonitor(BaseModule):
    @property
    def id(self):
        return "website_breach_monitor"

    @property
    def label(self):
        return "Website Breach Monitor"

    @property
    def category(self):
        return "BREACH"

    @property
    def description(self):
        return "Monitor whether a website/domain appears in the HIBP breach catalogue"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["domain"]

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")

        catalogue = sources.hibp_breaches_public()
        if catalogue.get("status") != "ok" or not isinstance(catalogue.get("data"), list):
            return self.result(
                title=f"Website Breach Monitor: {domain}",
                source="Have I Been Pwned catalogue",
                status="source_down",
                rows=[("Domain", domain), ("Error", response_error(catalogue))],
            )

        breaches = catalogue["data"]
        matched = [
            breach for breach in breaches
            if str(breach.get("Domain") or "").lower().strip(".") == domain
            or str(breach.get("Domain") or "").lower().endswith("." + domain)
        ]
        matched.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)
        accounts = sum(int(b.get("PwnCount") or 0) for b in matched)
        rows = [
            ("Domain", domain),
            ("Breaches", str(len(matched))),
            ("Accounts exposed", f"{accounts:,}"),
            ("Catalogue", f"{len(breaches):,} breaches"),
        ]
        for breach in matched[:25]:
            rows.append((
                breach.get("Name") or "breach",
                f"{breach.get('BreachDate', '?')} · {int(breach.get('PwnCount') or 0):,} accounts · "
                f"{', '.join((breach.get('DataClasses') or [])[:8])}",
            ))
        if not matched:
            rows.append(("Result", "This domain is not listed in the HIBP catalogue."))

        leakix_key = config.get_key("leakix")
        leakix = sources.leakix_domain(domain, leakix_key)
        if leakix.get("status") == "ok":
            data = leakix.get("data")
            if isinstance(data, list):
                rows.append(("LeakIX findings", str(len(data))))
                for item in data[:8]:
                    if isinstance(item, dict):
                        rows.append((
                            str(item.get("summary") or item.get("event_source") or "LeakIX")[:80],
                            f"{item.get('host') or '-'} · {item.get('severity') or '-'} · {item.get('date') or '-'}",
                        ))
        elif leakix.get("status") != "not_found":
            rows.append(("LeakIX", f"unavailable ({response_error(leakix)})"))

        return self.result(
            title=f"Website Breach Monitor: {domain}",
            source="HIBP catalogue + LeakIX",
            confidence="high" if matched else "medium",
            rows=rows,
            domain=domain,
        )

    def pivots(self, result):
        return [("domain", result.get("domain"))] if result.get("domain") else []
