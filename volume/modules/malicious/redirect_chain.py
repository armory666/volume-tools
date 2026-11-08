from urllib.parse import urlparse

from volume.core import indicators, webintel
from volume.core.module_base import BaseModule


class RedirectChain(BaseModule):
    @property
    def id(self):
        return "redirect_chain"

    @property
    def label(self):
        return "Redirect Chain"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "Trace every hop, cross-domain jumps and HTTP downgrades"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["url"]

    def run(self, case, **kwargs):
        url = indicators.normalize_url(kwargs.get("url"))
        if not url or not indicators.is_url(url):
            return self.result(rows=[("Error", f"Not a valid URL: {url or '-'}")], status="error")

        chain = webintel.redirect_chain(url)
        if not chain:
            return self.result(rows=[("Error", "Could not fetch URL")], status="source_down")

        hosts = [indicators.url_host(hop["url"]) for hop in chain]
        cross_domain = any(host and host != hosts[0] for host in hosts[1:])
        downgrade = any(
            chain[i]["url"].startswith("https://") and chain[i + 1]["url"].startswith("http://")
            for i in range(len(chain) - 1)
        )
        shortener = hosts[0] in indicators.SHORTENERS
        risk = 0
        if cross_domain:
            risk += 15
        if downgrade:
            risk += 25
        if shortener:
            risk += 20
        if len(chain) > 5:
            risk += 15
        final = chain[-1]
        if final.get("code") and final["code"] >= 400:
            risk += 15

        rows = [
            ("Input", url),
            ("Hops", str(max(0, len(chain) - 1))),
            ("Final URL", final["url"]),
            ("Final status", str(final.get("code", "-"))),
            ("Cross-domain", "yes" if cross_domain else "no"),
            ("HTTPS downgrade", "YES" if downgrade else "no"),
            ("Shortener", "yes" if shortener else "no"),
        ]
        for idx, hop in enumerate(chain, 1):
            rows.append(
                (
                    f"Hop {idx}",
                    f"{hop.get('code', '-')}  {hop['url'][:150]}"
                    + (f"  ->  {hop['location'][:100]}" if hop.get("location") else ""),
                )
            )
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Redirects: {hosts[0] or url}",
            source="HTTP redirect trace",
            confidence="high",
            rows=rows,
            final_url=final["url"],
            risk=risk,
        )

    def pivots(self, result):
        host = indicators.url_host(result.get("final_url") or "")
        return [("domain", host)] if host else []
