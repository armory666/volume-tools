from volume.core import indicators, webintel
from volume.core.module_base import BaseModule


class TechFingerprint(BaseModule):
    @property
    def id(self):
        return "tech_fingerprint"

    @property
    def label(self):
        return "Tech / WAF Fingerprint"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "Server, CMS, framework, CDN/WAF, cookies and security headers"

    @property
    def order(self):
        return 30

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

        response, url = webintel.fetch(url)
        if response.get("status") != "ok":
            return self.result(
                title=f"Tech: {indicators.url_host(url)}",
                status=response.get("status", "error"),
                rows=[("URL", url), ("Error", response.get("error") or "Request failed")],
            )

        headers = webintel.header_map(response)
        body = webintel.body_text(response)
        page = webintel.parse_page(body, url)
        tech = webintel.detect_tech(headers, body)
        waf = webintel.detect_waf(headers, body)
        header_rows, present, total = webintel.security_header_rows(headers)
        leak_rows = webintel.info_leak_rows(headers)
        cookies = webintel.cookie_rows(response)

        rows = [
            ("URL", response.get("url", url)),
            ("HTTP", str(response.get("code", "-"))),
            ("Title", webintel.page_title(body) or "-"),
            ("Server", headers.get("server", "-")),
            ("Powered by", headers.get("x-powered-by", "-")),
            ("CDN / WAF", waf),
            ("Generator", page.get("generator") or "-"),
            ("Tech stack", ", ".join(tech) or "not identified"),
            ("Scripts", f"{page['scripts']} ({page['external_scripts']} external)"),
            ("Forms", f"{len(page['forms'])} ({page['password_forms']} password)"),
            ("Iframes", str(page["iframes"])),
            ("Content-Type", headers.get("content-type", "-")),
        ]
        rows.extend(header_rows)
        rows.extend(leak_rows)
        for name, flags in cookies[:8]:
            rows.append((f"Cookie {name}", flags))

        return self.result(
            title=f"Tech: {indicators.url_host(url)}",
            source="HTTP fingerprint",
            confidence="high" if tech else "medium",
            rows=rows,
            tech=tech,
            waf=waf,
            headers_present=present,
        )

    def pivots(self, result):
        host = indicators.url_host(result.get("title", "").replace("Tech: ", ""))
        return [("domain", host)] if host else []
