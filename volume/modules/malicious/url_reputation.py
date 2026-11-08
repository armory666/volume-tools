from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule


class URLReputation(BaseModule):
    @property
    def id(self):
        return "url_reputation"

    @property
    def label(self):
        return "URL Reputation"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "URLhaus, OpenPhish, Google Safe Browsing and VirusTotal verdicts"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 50

    @property
    def credit_cost(self):
        return 2

    @property
    def requires_key(self):
        return ("gsb", "vt")

    @property
    def inputs(self):
        return ["url"]

    def run(self, case, **kwargs):
        url = indicators.normalize_url(kwargs.get("url"))
        if not url or not indicators.is_url(url):
            return self.result(rows=[("Error", f"Not a valid URL: {url or '-'}")], status="error")

        host = indicators.url_host(url)
        rows = [("URL", url), ("Host", host)]
        verdicts = []
        risk = 0

        # URLhaus
        urlhaus_key = config.get_key("urlhaus")
        response = sources.urlhaus_lookup(url, urlhaus_key)
        data = response.get("data") if response.get("status") == "ok" else None
        if isinstance(data, dict) and data.get("query_status") == "ok":
            threats = data.get("threat") or "-"
            tags = ", ".join(data.get("tags") or []) or "-"
            rows.append(("URLhaus", f"LISTED · {threats} · {tags}"))
            verdicts.append("URLhaus")
            risk += 35
        elif isinstance(data, dict) and data.get("query_status") == "no_results":
            rows.append(("URLhaus", "not listed"))
        else:
            rows.append(("URLhaus", "unavailable"))

        # OpenPhish
        try:
            if sources.openphish_check(url):
                rows.append(("OpenPhish", "LISTED"))
                verdicts.append("OpenPhish")
                risk += 35
            else:
                rows.append(("OpenPhish", "not listed"))
        except Exception:
            rows.append(("OpenPhish", "unavailable"))

        # Google Safe Browsing
        gsb_key = config.get_key("gsb") or config.get_key("google_safebrowsing")
        if gsb_key:
            result = sources.safe_browsing(url, gsb_key)
            if result.get("ok"):
                matches = result.get("matches") or []
                if matches:
                    types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
                    rows.append(("Safe Browsing", "MATCH · " + ", ".join(types)))
                    verdicts.append("Safe Browsing")
                    risk += 40
                else:
                    rows.append(("Safe Browsing", "clean"))
            else:
                rows.append(("Safe Browsing", f"error · {result.get('error')}"))
        else:
            rows.append(("Safe Browsing", "not configured (GSB_API_KEY)"))

        # VirusTotal
        vt_key = config.get_key("vt")
        if vt_key:
            vt_response = sources.vt_url(url, vt_key)
            if vt_response.get("status") == "ok":
                attributes = ((vt_response.get("data") or {}).get("data") or {}).get("attributes") or {}
                stats = attributes.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                suspicious = int(stats.get("suspicious") or 0)
                harmless = int(stats.get("harmless") or 0)
                total = malicious + suspicious + harmless + int(stats.get("undetected") or 0)
                rows.append(("VirusTotal", f"{malicious} malicious / {suspicious} suspicious / {total} engines"))
                if malicious:
                    verdicts.append("VirusTotal")
                    risk += min(45, 15 + malicious * 3)
                categories = attributes.get("categories") or {}
                if categories:
                    rows.append(("VT categories", ", ".join(sorted(set(categories.values())))[:180]))
            elif vt_response.get("status") == "not_found":
                rows.append(("VirusTotal", "not in dataset"))
            else:
                rows.append(("VirusTotal", f"error · {vt_response.get('error') or vt_response.get('status')}"))
        else:
            rows.append(("VirusTotal", "not configured (VT_API_KEY)"))

        # Host context
        try:
            db = sources.internetdb(host) if indicators.is_ip(host) else {}
            if db.get("ports"):
                rows.append(("Open ports", ", ".join(str(p) for p in db["ports"][:12])))
        except Exception:
            pass

        rows.append(("Verdicts", ", ".join(verdicts) if verdicts else "no public feed flagged this URL"))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"URL Reputation: {host or url}",
            source="URLhaus + OpenPhish + Safe Browsing + VirusTotal",
            confidence="high" if verdicts else "medium",
            rows=rows,
            risk=risk,
            flagged=bool(verdicts),
        )

    def pivots(self, result):
        host = indicators.url_host(result.get("title", "").replace("URL Reputation: ", ""))
        return [("domain", host)] if host else []
