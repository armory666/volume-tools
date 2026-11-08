from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class DNSBLCheck(BaseModule):
    @property
    def id(self):
        return "dnsbl_check"

    @property
    def label(self):
        return "DNSBL / Blocklist Check"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "Check an IP against Spamhaus, SpamCop, Barracuda and other DNSBLs"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["ip"]

    def run(self, case, **kwargs):
        ip = (kwargs.get("ip") or "").strip()
        if not ip or not indicators.is_ip(ip):
            return self.result(rows=[("Error", f"Not a valid IP: {ip or '-'}")], status="error")
        if indicators.is_private_ip(ip):
            return self.result(
                title=f"DNSBL: {ip}",
                rows=[("IP", ip), ("Result", "Private/reserved address - not queryable")],
                status="skipped",
            )

        hits = sources.dnsbl_hits(ip)
        listed = [h for h in hits if h.get("listed") is True]
        clean = [h for h in hits if h.get("listed") is False]
        unknown = [h for h in hits if h.get("listed") is None]

        rows = [
            ("IP", ip),
            ("Lists checked", str(len(hits))),
            ("Listed", str(len(listed))),
            ("Clean", str(len(clean))),
            ("Unavailable", str(len(unknown))),
        ]
        for hit in hits:
            if hit.get("listed") is True:
                codes = ", ".join(hit.get("codes") or []) or "listed"
                rows.append((hit["label"], f"LISTED · {hit.get('reason') or codes}"))
            elif hit.get("listed") is False:
                rows.append((hit["label"], "clean"))
            else:
                rows.append((hit["label"], f"unavailable · {hit.get('reason')}"))

        return self.result(
            title=f"DNSBL: {ip}",
            source="Spamhaus ZEN + SpamCop + Barracuda + SORBS + SpamRats",
            confidence="high",
            rows=rows,
            listed=len(listed),
            blacklisted=bool(listed),
        )

    def pivots(self, result):
        ip = result.get("title", "").replace("DNSBL: ", "").strip()
        return [("ip", ip)] if ip else []
