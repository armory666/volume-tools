from concurrent.futures import ThreadPoolExecutor

from volume.core import indicators, sources
from volume.core.module_base import BaseModule


COMMON = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "mx", "ns1", "ns2",
    "api", "app", "apps", "dev", "staging", "stage", "test", "qa", "uat",
    "admin", "portal", "login", "auth", "sso", "vpn", "remote", "gateway",
    "cdn", "static", "assets", "media", "img", "files", "download", "uploads",
    "blog", "shop", "store", "support", "help", "docs", "status", "monitor",
    "git", "gitlab", "jenkins", "ci", "build", "docker", "registry", "k8s",
    "db", "mysql", "postgres", "redis", "mongo", "backup", "old", "new",
    "internal", "intranet", "corp", "office", "owa", "autodiscover",
]


class SubdomainEnum(BaseModule):
    @property
    def id(self):
        return "subdomain_enum"

    @property
    def label(self):
        return "Subdomain Enumeration"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Certificate transparency plus common-name DNS brute force"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 3

    @property
    def inputs(self):
        return ["domain"]

    @property
    def optional_inputs(self):
        return {"brute": "yes"}

    @property
    def input_prompts(self):
        return {
            "domain": "Root domain (example.com)",
            "brute": "Also brute-force common names? (yes/no)",
        }

    def _resolve(self, host):
        ips = sources.resolve_host(host, "A", lifetime=3.5)
        if not ips:
            ips = sources.resolve_host(host, "AAAA", lifetime=3.5)
        return host, ips

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain or not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")

        crt_names = sources.subdomains_from_crt(domain)
        candidates = set(crt_names)
        brute_enabled = (kwargs.get("brute") or "yes").strip().lower() not in ("no", "n", "false", "0")
        if brute_enabled:
            candidates.update(f"{name}.{domain}" for name in COMMON)

        candidates = sorted(candidates)[:120]
        resolved = []
        with ThreadPoolExecutor(max_workers=12) as pool:
            for host, ips in pool.map(self._resolve, candidates):
                if ips:
                    resolved.append((host, ips))

        resolved.sort()
        rows = [
            ("Domain", domain),
            ("CT names", str(len(crt_names))),
            ("Brute names", str(len(COMMON)) if brute_enabled else "disabled"),
            ("Checked", str(len(candidates))),
            ("Resolved", str(len(resolved))),
        ]
        for host, ips in resolved[:60]:
            rows.append((host, ", ".join(ips[:3])))
        if len(resolved) > 60:
            rows.append(("...", f"{len(resolved) - 60} more resolved hosts"))
        if not resolved:
            rows.append(("Result", "No live subdomains found in this pass"))

        return self.result(
            title=f"Subdomains: {domain}",
            source="crt.sh + DNS",
            confidence="high" if resolved else "low",
            rows=rows,
            subdomains=[h for h, _ in resolved],
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("Subdomains: ", "").strip()
        pivots = [("domain", domain)] if domain else []
        for host in (result.get("subdomains") or [])[:40]:
            pivots.append(("domain", host))
        return pivots
