from volume.core import indicators, sources
from volume.core.module_base import BaseModule


KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
    "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
    "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
    "k": "jil", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}

TLD_SWAPS = ("com", "net", "org", "co", "io", "info", "xyz", "top", "shop", "app")


class Typosquat(BaseModule):
    @property
    def id(self):
        return "typosquat"

    @property
    def label(self):
        return "Typosquat / Lookalike"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "Generate lookalike domains and check which ones resolve"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 80

    @property
    def credit_cost(self):
        return 4

    @property
    def inputs(self):
        return ["domain"]

    def _variants(self, domain: str) -> list:
        domain = domain.lower().strip(".")
        labels = domain.split(".")
        if len(labels) < 2:
            return []
        name = ".".join(labels[:-1])
        tld = labels[-1]
        variants = set()

        # Omission
        for i in range(len(name)):
            variants.add(name[:i] + name[i + 1:])
        # Transposition
        for i in range(len(name) - 1):
            variants.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
        # Duplication
        for i in range(len(name)):
            variants.add(name[:i] + name[i] + name[i:])
        # Keyboard proximity
        for i, ch in enumerate(name):
            for near in KEYBOARD.get(ch, ""):
                variants.add(name[:i] + near + name[i + 1:])
        # Homoglyph / hyphen injection
        for brand, look in (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l")):
            if brand in name:
                variants.add(name.replace(brand, look, 1))
        if len(name) <= 18:
            variants.add("-".join(name))
        for i in range(1, min(4, len(name))):
            variants.add(name[:i] + "-" + name[i:])

        out = set()
        for variant in variants:
            variant = variant.strip("-.")
            if not variant or variant == name or len(variant) < 3:
                continue
            if not all(ch.isalnum() or ch == "-" for ch in variant):
                continue
            out.add(f"{variant}.{tld}")
            for other in TLD_SWAPS:
                if other != tld:
                    out.add(f"{variant}.{other}")
        return sorted(out)[:180]

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not domain or not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")

        variants = self._variants(domain)
        if not variants:
            return self.result(rows=[("Error", "Could not generate variants")], status="error")

        live = []
        for candidate in variants:
            ips = sources.resolve_host(candidate, "A", lifetime=2.5)
            if ips:
                live.append((candidate, ips))
        live.sort()

        rows = [
            ("Domain", domain),
            ("Variants checked", str(len(variants))),
            ("Resolving lookalikes", str(len(live))),
        ]
        for candidate, ips in live[:80]:
            rows.append((candidate, ", ".join(ips[:2])))
        if len(live) > 80:
            rows.append(("...", f"{len(live) - 80} more"))
        if not live:
            rows.append(("Result", "No resolving lookalikes found in this pass"))
        else:
            rows.append(("Note", "Resolving is not proof of abuse; verify ownership and content."))

        return self.result(
            title=f"Typosquat: {domain}",
            source="DNS permutation sweep",
            confidence="medium",
            rows=rows,
            lookalikes=[c for c, _ in live],
        )

    def pivots(self, result):
        domain = result.get("title", "").replace("Typosquat: ", "").strip()
        pivots = [("domain", domain)] if domain else []
        for candidate in (result.get("lookalikes") or [])[:40]:
            pivots.append(("domain", candidate))
        return pivots
