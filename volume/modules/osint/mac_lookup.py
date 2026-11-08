import re

from volume.core import sources
from volume.core.module_base import BaseModule


class MACLookup(BaseModule):
    @property
    def id(self):
        return "mac_lookup"

    @property
    def label(self):
        return "MAC / OUI Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Normalize a MAC address, decode its flags and resolve the OUI vendor"

    @property
    def order(self):
        return 25

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["mac"]

    @property
    def input_prompts(self):
        return {"mac": "MAC address (aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff or 12 hex chars)"}

    def _normalize(self, value: str):
        digits = "".join(ch for ch in (value or "") if ch in "0123456789abcdefABCDEF")
        if len(digits) not in (12, 16):
            return None
        digits = digits.upper()
        octets = [digits[i:i + 2] for i in range(0, len(digits), 2)]
        return digits, ":".join(octets)

    def run(self, case, **kwargs):
        raw = (kwargs.get("mac") or "").strip()
        normalized = self._normalize(raw)
        if not normalized:
            return self.result(
                rows=[("Error", f"Not a MAC address: {raw or '-'}")],
                status="error",
            )

        digits, formatted = normalized
        first = int(digits[:2], 16)
        multicast = bool(first & 0x01)
        locally_administered = bool(first & 0x02)
        oui = digits[:6]
        nic = digits[6:12]

        rows = [
            ("Input", raw),
            ("Normalized", formatted),
            ("OUI", f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"),
            ("NIC part", nic),
            ("Length", f"{len(digits) * 4} bits"),
            ("Multicast bit", "set (group address)" if multicast else "clear (unicast)"),
            (
                "Local bit",
                "set (locally administered / randomized)" if locally_administered
                else "clear (globally unique OUI)",
            ),
        ]

        vendor = "-"
        response = sources.mac_vendor(digits)
        if response.get("status") == "ok":
            text = response.get("data")
            vendor = re.sub(r"\s+", " ", str(text or "")).strip()[:120] or "-"
            rows.append(("Vendor", vendor))
        elif response.get("status") == "not_found":
            rows.append(("Vendor", "not found in the IEEE OUI registry"))
        else:
            rows.append(("Vendor", f"lookup failed · {response.get('error') or response.get('status')}"))

        if locally_administered:
            rows.append(("Note", "A set local bit usually means a privacy/randomized MAC (phones, VMs)."))
        if len(digits) == 16:
            rows.append(("Note", "64-bit identifier (EUI-64) detected."))

        return self.result(
            title=f"MAC: {formatted}",
            source="IEEE OUI (macvendors.com)",
            confidence="high" if vendor not in ("-",) else "medium",
            rows=rows,
            mac=formatted,
            oui=oui,
            vendor=vendor,
            randomized=locally_administered,
        )

    def pivots(self, result):
        return [("mac", result["mac"])] if result.get("mac") else []
