from concurrent.futures import ThreadPoolExecutor

from volume.core import indicators, sources, webintel
from volume.core.module_base import BaseModule


# CNAME suffixes of services that are commonly hijacked when a record is left
# dangling, plus the response body fingerprints they return for unclaimed names.
TAKEOVER_SERVICES = {
    "github.io": ("GitHub Pages", (
        "there isn't a github pages site here",
        "for root urls (like http://example.com/) you must provide an index.html file",
    )),
    "herokuapp.com": ("Heroku", ("no such app", "there's nothing here, yet.")),
    "s3.amazonaws.com": ("Amazon S3", ("nosuchbucket", "the specified bucket does not exist")),
    "azurewebsites.net": ("Azure App Service", ("404 web site not found",)),
    "cloudfront.net": ("CloudFront", ("bad request", "error: the request could not be satisfied")),
    "bitbucket.io": ("Bitbucket", ("repository not found",)),
    "myshopify.com": ("Shopify", ("sorry, this shop is currently unavailable",)),
    "tumblr.com": ("Tumblr", ("there's nothing here.",)),
    "wordpress.com": ("WordPress.com", ("does not exist",)),
    "fastly.net": ("Fastly", ("fastly error: unknown domain",)),
    "netlify.app": ("Netlify", ("not found - request id",)),
    "ghost.io": ("Ghost", ("domain error",)),
    "readme.io": ("ReadMe", ("project doesnt exist... yet!",)),
    "statuspage.io": ("Statuspage", ("you are being redirected",)),
    "unbouncepages.com": ("Unbounce", ("the requested url was not found",)),
    "zendesk.com": ("Zendesk", ("help center closed",)),
    "helpscoutdocs.com": ("Help Scout", ("no settings were found",)),
    "pantheonsite.io": ("Pantheon", ("404 error unknown site",)),
    "teamwork.com": ("Teamwork", ("oops - we didn't find your site.",)),
    "uservoice.com": ("UserVoice", ("this uservoice subdomain is currently available!",)),
    "surveymonkey.com": ("SurveyMonkey", ("page not found",)),
    "smugmug.com": ("SmugMug", ("page not found",)),
    "cargocollective.com": ("Cargo", ("404 not found",)),
    "feedpress.me": ("FeedPress", ("the feed has not been found.",)),
}


class SubdomainTakeover(BaseModule):
    @property
    def id(self):
        return "subdomain_takeover"

    @property
    def label(self):
        return "Subdomain Takeover"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "Find dangling CNAMEs pointing at unclaimed cloud and SaaS services"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 55

    @property
    def credit_cost(self):
        return 4

    @property
    def inputs(self):
        return ["domain"]

    @property
    def optional_inputs(self):
        return {"limit": "80"}

    @property
    def input_prompts(self):
        return {
            "domain": "Root domain (example.com)",
            "limit": "How many CT subdomains to check (max 150)",
        }

    def _service_for(self, target: str):
        target = (target or "").rstrip(".").lower()
        for suffix, (name, needles) in TAKEOVER_SERVICES.items():
            if target == suffix or target.endswith("." + suffix):
                return name, needles
        return None, ()

    def _check(self, host: str):
        cnames = sources.resolve_host(host, "CNAME", lifetime=3.5)
        if not cnames:
            return None
        target = str(cnames[0]).rstrip(".").lower()
        service, needles = self._service_for(target)
        if not service:
            return None
        response, _ = webintel.fetch(f"http://{host}", timeout=6.0)
        body = webintel.body_text(response).lower() if response.get("status") == "ok" else ""
        evidence = next((needle for needle in needles if needle in body), "")
        return {
            "host": host,
            "cname": target,
            "service": service,
            "evidence": evidence,
            "vulnerable": bool(evidence),
            "code": response.get("code"),
        }

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain or not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")
        try:
            limit = max(1, min(150, int(kwargs.get("limit") or 80)))
        except (TypeError, ValueError):
            limit = 80

        subdomains = sources.subdomains_from_crt(domain)
        hosts = sorted(subdomains)[:limit]

        checked = []
        if hosts:
            with ThreadPoolExecutor(max_workers=10) as pool:
                for item in pool.map(self._check, hosts):
                    if item:
                        checked.append(item)

        checked.sort(key=lambda item: (not item["vulnerable"], item["host"]))
        vulnerable = [item for item in checked if item["vulnerable"]]
        service_hosted = [item for item in checked if not item["vulnerable"]]

        rows = [
            ("Domain", domain),
            ("CT subdomains", str(len(subdomains))),
            ("Hosts checked", str(len(hosts))),
            ("CNAMEs to takeover-prone services", str(len(checked))),
            ("Dangling / vulnerable", str(len(vulnerable))),
        ]

        for item in vulnerable:
            rows.append(
                (
                    item["host"],
                    f"VULNERABLE · CNAME {item['cname']} ({item['service']}) · "
                    f"fingerprint '{item['evidence'][:60]}'",
                )
            )
        if service_hosted:
            rows.append(("Service-hosted (no fingerprint)", str(len(service_hosted))))
            for item in service_hosted[:20]:
                rows.append((item["host"], f"CNAME {item['cname']} ({item['service']}) · HTTP {item['code']}"))

        if not hosts:
            rows.append(("Result", "No subdomains returned by certificate transparency."))
        elif not checked:
            rows.append(("Result", "No CNAMEs to known takeover-prone services were found."))
        elif not vulnerable:
            rows.append(("Result", "No dangling takeover fingerprints matched (not a guarantee)."))

        risk = min(100, len(vulnerable) * 35)
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Takeover: {domain}",
            source="crt.sh + DNS CNAME + service fingerprints",
            confidence="high" if checked else "medium",
            rows=rows,
            risk=risk,
            vulnerable=[item["host"] for item in vulnerable],
            cnames=checked,
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("Takeover: ", "").strip()
        pivots = [("domain", domain)] if domain else []
        for host in (result.get("vulnerable") or [])[:50]:
            pivots.append(("domain", host))
        return pivots
