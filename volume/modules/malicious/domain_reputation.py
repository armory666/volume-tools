from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule


class DomainReputation(BaseModule):
    @property
    def id(self):
        return "domain_reputation"

    @property
    def label(self):
        return "Domain Reputation"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "URLhaus host history, VirusTotal verdicts and categories for a domain"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 45

    @property
    def credit_cost(self):
        return 2

    @property
    def requires_key(self):
        return ("vt",)

    @property
    def inputs(self):
        return ["domain"]

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain or not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")

        rows = [("Domain", domain)]
        risk = 0
        signals = []

        # URLhaus host history
        urlhaus_key = config.get_key("urlhaus") or config.get_key("abusech")
        response = sources.urlhaus_host(domain, urlhaus_key)
        data = response.get("data") if response.get("status") == "ok" else None
        if isinstance(data, dict) and data.get("query_status") == "ok":
            urls = data.get("urls") or []
            online = sum(1 for u in urls if str(u.get("url_status", "")).lower() == "online")
            threats = sorted({str(u.get("threat") or "?") for u in urls})
            tags = sorted({str(t) for u in urls for t in (u.get("tags") or [])})
            rows.append(("URLhaus entries", str(len(urls))))
            rows.append(("URLhaus online", str(online)))
            rows.append(("Threats", ", ".join(threats) or "-"))
            if tags:
                rows.append(("Tags", ", ".join(tags[:15])))
            if urls:
                risk += min(50, 25 + len(urls) * 3)
                signals.append(f"URLhaus x{len(urls)}")
            for item in urls[:10]:
                rows.append(
                    (
                        "URLhaus URL",
                        f"{str(item.get('url') or '-')[:110]} · {item.get('url_status') or '-'} · "
                        f"{str(item.get('date_added') or '')[:10]}",
                    )
                )
        elif isinstance(data, dict) and data.get("query_status") == "no_results":
            rows.append(("URLhaus", "no entries"))
        else:
            rows.append(("URLhaus", f"unavailable · {response.get('error') or response.get('status')}"))

        # VirusTotal
        vt_key = config.get_key("vt")
        if vt_key:
            vt = sources.vt_domain(domain, vt_key)
            if vt.get("status") == "ok":
                attributes = ((vt.get("data") or {}).get("data") or {}).get("attributes") or {}
                stats = attributes.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                suspicious = int(stats.get("suspicious") or 0)
                harmless = int(stats.get("harmless") or 0)
                total = malicious + suspicious + harmless + int(stats.get("undetected") or 0)
                reputation = attributes.get("reputation")
                rows.append(("VirusTotal", f"{malicious} malicious / {suspicious} suspicious / {total} engines"))
                rows.append(("VT reputation", str(reputation if reputation is not None else "-")))
                categories = attributes.get("categories") or {}
                if categories:
                    rows.append(("VT categories", ", ".join(sorted(set(categories.values())))[:200]))
                if malicious:
                    risk += min(55, 20 + malicious * 3)
                    signals.append(f"VT malicious x{malicious}")
                elif suspicious:
                    risk += 10
                try:
                    if reputation is not None and int(reputation) < 0:
                        risk += min(15, abs(int(reputation)) // 5)
                except (TypeError, ValueError):
                    pass
                ranks = attributes.get("popularity_ranks") or {}
                if isinstance(ranks, dict):
                    popular = [
                        f"{key}:{value.get('rank')}"
                        for key, value in ranks.items()
                        if isinstance(value, dict) and value.get("rank") is not None
                    ]
                    if popular:
                        rows.append(("Popularity", ", ".join(popular[:5])))
            elif vt.get("status") == "not_found":
                rows.append(("VirusTotal", "domain not in dataset"))
            else:
                rows.append(("VirusTotal", f"error · {vt.get('error') or vt.get('status')}"))
        else:
            rows.append(("VirusTotal", "not configured (VT_API_KEY)"))

        # DNS presence
        addresses = sources.resolve_host(domain, "A")
        if addresses:
            rows.append(("A records", ", ".join(addresses[:6])))
        else:
            rows.append(("A records", "none / unresolvable"))

        risk = min(100, risk)
        rows.append(("Signals", ", ".join(signals) if signals else "none"))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Domain Reputation: {domain}",
            source="URLhaus + VirusTotal + DNS",
            confidence="high" if signals else "medium",
            rows=rows,
            risk=risk,
            flagged=bool(signals),
            addresses=addresses,
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("Domain Reputation: ", "").strip()
        pivots = [("domain", domain)] if domain else []
        for ip in (result.get("addresses") or [])[:10]:
            pivots.append(("ip", ip))
        return pivots
