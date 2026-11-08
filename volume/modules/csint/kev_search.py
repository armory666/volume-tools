from volume.core import sources
from volume.core.module_base import BaseModule


class KEVSearch(BaseModule):
    @property
    def id(self):
        return "kev_search"

    @property
    def label(self):
        return "CISA KEV Search"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "Search the known-exploited vulnerability catalogue by vendor, product or CVE"

    @property
    def order(self):
        return 25

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["keyword"]

    @property
    def input_prompts(self):
        return {"keyword": "Vendor, product, keyword or CVE (citrix, fortinet, CVE-2024-3400)"}

    def run(self, case, **kwargs):
        keyword = (kwargs.get("keyword") or "").strip()
        if not keyword:
            return self.result(rows=[("Error", "No keyword provided")], status="error")

        matches = sources.kev_matches(keyword, limit=30)
        rows = [("Keyword", keyword), ("Matches", str(len(matches)))]
        if not matches:
            rows.append(("Result", "No known-exploited vulnerabilities matched."))
            return self.result(
                title=f"KEV: {keyword}",
                source="CISA KEV",
                confidence="high",
                rows=rows,
                status="not_found",
            )

        ransomware = 0
        for item in matches:
            cve = str(item.get("cveID") or "?")
            vendor = item.get("vendorProject") or "?"
            product = item.get("product") or "?"
            name = item.get("vulnerabilityName") or "?"
            added = str(item.get("dateAdded") or "-")[:10]
            due = str(item.get("dueDate") or "-")[:10]
            ransom = item.get("knownRansomwareCampaignUse") or "Unknown"
            if str(ransom).lower() == "known":
                ransomware += 1
            rows.append(
                (
                    cve,
                    f"{vendor} · {product} · {name}  [added {added}, due {due}, ransomware {ransom}]",
                )
            )

        rows.append(("Known ransomware use", str(ransomware)))
        rows.append(("Note", "KEV listing means exploitation has been observed in the wild."))

        return self.result(
            title=f"KEV: {keyword}",
            source="CISA Known Exploited Vulnerabilities",
            confidence="high",
            rows=rows,
            kev=len(matches),
            ransomware=ransomware,
        )

    def pivots(self, result):
        pivots = []
        for row in result.get("rows") or []:
            key = str(row[0])
            if key.upper().startswith("CVE-"):
                pivots.append(("cve", key))
        return pivots
