import re

from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class CVELookup(BaseModule):
    @property
    def id(self):
        return "cve_lookup"

    @property
    def label(self):
        return "CVE / Vulnerability Intel"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "CVSS, CWE, EPSS-style context, CISA KEV and known-exploited status"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["cve"]

    @property
    def input_prompts(self):
        return {"cve": "CVE ID (CVE-2024-3400) or keyword (apache rce)"}

    def _cvss(self, metrics: dict) -> tuple:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            entry = entries[0]
            data = entry.get("cvssData") or {}
            return (
                data.get("baseScore"),
                data.get("baseSeverity") or entry.get("baseSeverity"),
                data.get("vectorString", ""),
            )
        return None, None, ""

    def _cve_report(self, cve: str):
        response = sources.nvd_cve(cve)
        if response.get("status") != "ok":
            return self.result(
                title=f"CVE: {cve}",
                source="NVD",
                status=response.get("status", "error"),
                rows=[("Error", response.get("error") or "NVD lookup failed")],
            )

        vulns = (response.get("data") or {}).get("vulnerabilities") or []
        if not vulns:
            return self.result(
                title=f"CVE: {cve}",
                source="NVD",
                status="not_found",
                rows=[("CVE", cve), ("Result", "Not found in NVD")],
            )

        item = vulns[0].get("cve") or {}
        descriptions = item.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        metrics = item.get("metrics") or {}
        score, severity, vector = self._cvss(metrics)
        weaknesses = []
        for weakness in item.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))
        references = [r.get("url", "") for r in item.get("references") or []]
        cpes = []
        for config in item.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    criteria = match.get("criteria", "")
                    if criteria:
                        cpes.append(criteria)

        kev = sources.kev_index().get(cve.upper()) or {}
        published = str(item.get("published", ""))[:10]
        modified = str(item.get("lastModified", ""))[:10]

        risk = 0
        try:
            risk = int(float(score or 0) * 10)
        except (TypeError, ValueError):
            risk = 0
        if kev:
            risk += 25

        rows = [
            ("CVE", cve.upper()),
            ("Published", published or "-"),
            ("Modified", modified or "-"),
            ("Status", item.get("vulnStatus", "-")),
            ("CVSS", f"{score} ({severity})" if score is not None else "not scored"),
            ("Vector", vector or "-"),
            ("CWE", ", ".join(sorted(set(weaknesses))) or "-"),
            ("CISA KEV", "YES - known exploited" if kev else "not listed"),
            ("Description", description[:600] or "-"),
            ("References", str(len(references))),
        ]
        if kev:
            rows.append(("KEV name", kev.get("vulnerabilityName", "-")))
            rows.append(("KEV added", str(kev.get("dateAdded", "-"))[:10]))
            rows.append(("KEV due", str(kev.get("dueDate", "-"))[:10]))
            rows.append(("Known ransomware", kev.get("knownRansomwareCampaignUse", "-")))
        for cpe in cpes[:10]:
            rows.append(("Affected", cpe[:160]))
        for reference in references[:10]:
            rows.append(("Reference", reference[:160]))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"CVE: {cve.upper()}",
            source="NIST NVD + CISA KEV",
            confidence="high",
            rows=rows,
            risk=risk,
            score=score,
            kev=bool(kev),
        )

    def _search(self, keyword: str):
        response = sources.nvd_search(keyword, limit=15)
        if response.get("status") != "ok":
            return self.result(
                title=f"CVE Search: {keyword}",
                source="NVD",
                status=response.get("status", "error"),
                rows=[("Error", response.get("error") or "NVD search failed")],
            )
        vulns = (response.get("data") or {}).get("vulnerabilities") or []
        rows = [("Keyword", keyword), ("Results", str(len(vulns)))]
        for entry in vulns:
            item = entry.get("cve") or {}
            cve_id = item.get("id", "?")
            score, severity, _ = self._cvss(item.get("metrics") or {})
            descriptions = item.get("descriptions") or []
            text = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
            )
            rows.append(
                (
                    cve_id,
                    f"CVSS {score if score is not None else '-'} ({severity or 'n/a'}) · {text[:140]}",
                )
            )
        if not vulns:
            rows.append(("Result", "No CVEs matched"))
        return self.result(
            title=f"CVE Search: {keyword}",
            source="NIST NVD keyword search",
            confidence="medium",
            rows=rows,
        )

    def run(self, case, **kwargs):
        query = (kwargs.get("cve") or "").strip()
        if not query:
            return self.result(rows=[("Error", "No CVE or keyword provided")], status="error")
        if indicators.is_cve(query) or re.fullmatch(r"\d{4}-\d{4,7}", query):
            cve = query.upper() if query.upper().startswith("CVE-") else f"CVE-{query}"
            return self._cve_report(cve)
        return self._search(query)

    def pivots(self, result):
        cve = result.get("title", "").replace("CVE: ", "").replace("CVE Search: ", "").strip()
        return [("cve", cve)] if indicators.is_cve(cve) else []
