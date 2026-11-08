from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class ASNIntel(BaseModule):
    @property
    def id(self):
        return "asn_intel"

    @property
    def label(self):
        return "ASN / BGP Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "ASN ownership, announced prefixes, peers and upstreams"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 35

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["target"]

    @property
    def input_prompts(self):
        return {"target": "IP address or ASN (e.g. 1.1.1.1 or AS13335)"}

    def run(self, case, **kwargs):
        target = (kwargs.get("target") or "").strip()
        if not target:
            return self.result(rows=[("Error", "Provide an IP or ASN")], status="error")

        if target.upper().startswith("AS") or target.isdigit():
            return self._asn(target)
        if indicators.is_ip(target):
            return self._ip(target)
        return self.result(rows=[("Error", f"Not an IP or ASN: {target}")], status="error")

    def _ip(self, ip):
        data = sources.bgpview_ip(ip)
        if not data:
            return self.result(
                title=f"ASN Intel: {ip}",
                rows=[("IP", ip), ("Error", "No BGP data returned")],
                status="error",
            )
        prefixes = data.get("prefixes") or []
        asns = []
        rows = [("IP", ip), ("Prefixes", str(len(prefixes)))]
        for prefix in prefixes[:8]:
            asn = prefix.get("asn") or {}
            asns.append(asn)
            rows.append(
                (
                    prefix.get("prefix", "-"),
                    f"AS{asn.get('asn', '-')} {asn.get('name', '')} "
                    f"({asn.get('country_code', '-')})",
                )
            )
        allocation = data.get("rir_allocation") or {}
        if allocation:
            rows.append(("RIR", allocation.get("rir_name", "-")))
            rows.append(("Allocated", str(allocation.get("date_allocated", "-"))[:10]))
        if asns:
            primary = asns[0]
            rows.append(("Primary ASN", f"AS{primary.get('asn', '-')} {primary.get('name', '')}"))
        return self.result(
            title=f"ASN Intel: {ip}",
            source="BGPView",
            confidence="high",
            rows=rows,
            asns=[a.get("asn") for a in asns if a.get("asn")],
        )

    def _asn(self, target):
        asn = target.upper().replace("AS", "")
        data = sources.bgpview_asn(asn)
        if not data:
            return self.result(
                title=f"ASN Intel: AS{asn}",
                rows=[("ASN", f"AS{asn}"), ("Error", "No ASN data returned")],
                status="error",
            )
        prefixes = data.get("prefixes") or []
        peers = data.get("peers") or []
        upstreams = data.get("upstreams") or []
        downstreams = data.get("downstreams") or []
        rows = [
            ("ASN", f"AS{data.get('asn', asn)}"),
            ("Name", data.get("name", "-")),
            ("Description", (data.get("description_full") or data.get("description_short") or "-")[:180]),
            ("Country", data.get("country_code", "-")),
            ("Website", data.get("website", "-")),
            ("Email", data.get("email", "-")),
            ("Prefixes", str(len(prefixes))),
            ("Peers", str(len(peers))),
            ("Upstreams", str(len(upstreams))),
            ("Downstreams", str(len(downstreams))),
        ]
        for prefix in prefixes[:10]:
            rows.append(("Prefix", prefix.get("prefix", "-")))
        for peer in peers[:6]:
            rows.append(("Peer", f"AS{peer.get('asn', '-')} {peer.get('name', '')}"))
        return self.result(
            title=f"ASN Intel: AS{asn}",
            source="BGPView",
            confidence="high",
            rows=rows,
            asn=data.get("asn", asn),
        )

    def pivots(self, result):
        return []
