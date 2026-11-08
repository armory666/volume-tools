from volume.core import indicators, webintel
from volume.core.module_base import BaseModule


class HTTPHeadersAudit(BaseModule):
    @property
    def id(self):
        return "http_headers_audit"

    @property
    def label(self):
        return "HTTP Headers Audit"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "Security-header grade, cookie flags, info leaks, tech and WAF fingerprint"

    @property
    def order(self):
        return 15

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["url"]

    @property
    def input_prompts(self):
        return {"url": "URL or host (https://example.com)"}

    def _grade(self, present: int, total: int, critical_missing: int) -> str:
        if total <= 0:
            return "-"
        ratio = present / total
        score = ratio * 100 - critical_missing * 12
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        if score >= 20:
            return "E"
        return "F"

    def run(self, case, **kwargs):
        raw = (kwargs.get("url") or "").strip()
        url = indicators.normalize_url(raw)
        if not url or not indicators.is_url(url):
            return self.result(rows=[("Error", f"Not a valid URL: {raw or '-'}")], status="error")

        response, final_url = webintel.fetch(url, timeout=12.0)
        if response.get("status") != "ok":
            return self.result(
                title=f"Headers: {indicators.url_host(url)}",
                source="HTTP fetch",
                status=response.get("status", "error"),
                rows=[("URL", url), ("Error", response.get("error") or "Request failed")],
            )

        headers = webintel.header_map(response)
        body = webintel.body_text(response)
        header_rows, present, total = webintel.security_header_rows(headers)
        cookies = webintel.cookie_rows(response)
        leaks = webintel.info_leak_rows(headers)
        tech = webintel.detect_tech(headers, body)
        waf = webintel.detect_waf(headers, body)

        critical = [
            name for name in (
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
            )
            if not headers.get(name)
        ]
        grade = self._grade(present, total, len(critical))

        rows = [
            ("URL", final_url or url),
            ("HTTP", str(response.get("code", "-"))),
            ("Server", headers.get("server", "-")[:120]),
            ("WAF / CDN", waf or "not detected"),
            ("Tech", ", ".join(tech[:12]) or "-"),
            ("Grade", f"{grade}  ({present}/{total} headers, {len(critical)} critical missing)"),
        ]
        rows.extend(header_rows)

        if cookies:
            rows.append(("Cookies", str(len(cookies))))
            rows.extend(cookies[:12])
        else:
            rows.append(("Cookies", "none set"))

        if leaks:
            rows.extend(leaks)
        else:
            rows.append(("Info leaks", "none in response headers"))

        risk = 0
        risk += len(critical) * 12
        risk += sum(1 for row in cookies if "no Secure" in row[1] or "no HttpOnly" in row[1]) * 4
        risk += len(leaks) * 3
        if "unsafe-inline" in (headers.get("content-security-policy") or ""):
            risk += 5
        risk = min(100, risk)
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Headers: {indicators.url_host(final_url or url)}",
            source="live HTTP response",
            confidence="high",
            rows=rows,
            risk=risk,
            grade=grade,
            present=present,
            total=total,
            missing=critical,
        )

    def pivots(self, result):
        host = indicators.url_host(result.get("title", "").replace("Headers: ", ""))
        return [("domain", host)] if host else []
