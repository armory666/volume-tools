import re
from urllib.parse import urlparse

from volume.core import config, indicators, sources, webintel
from volume.core.module_base import BaseModule


class WebScanner(BaseModule):
    @property
    def id(self):
        return "web_scanner"

    @property
    def label(self):
        return "Web / URL Scanner"

    @property
    def category(self):
        return "MALICIOUS"

    @property
    def description(self):
        return "Headers, TLS, cookies, tech, redirects and safe-browsing checks"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["url"]

    @property
    def optional_inputs(self):
        return {"mode": "quick"}

    @property
    def input_prompts(self):
        return {
            "url": "URL to scan",
            "mode": "Mode (quick passive or deep full scan)",
        }

    def _normalize(self, value: str) -> str:
        return indicators.normalize_url(value)

    def _safe_browsing(self, url: str):
        key = config.get_key("gsb") or config.get_key("google_safebrowsing")
        if not key:
            return "not configured (set GSB_API_KEY)", 0
        result = sources.safe_browsing(url, key)
        if not result.get("ok"):
            return f"lookup failed ({result.get('error')})", 0
        matches = result.get("matches") or []
        if not matches:
            return "clean", 0
        threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return "MATCH: " + ", ".join(threats), 25

    def _quick_scan(self, url: str, parsed):
        response, url = webintel.fetch(url)
        if response.get("status") != "ok":
            return self.result(
                title=f"Web Scanner: {parsed.hostname}",
                source="HTTP",
                confidence="low",
                status=response.get("status", "error"),
                rows=[("URL", url), ("Error", response.get("error") or "Request failed")],
            )

        headers = webintel.header_map(response)
        body = webintel.body_text(response)
        title = webintel.page_title(body) or "-"
        tech = webintel.detect_tech(headers, body)
        waf = webintel.detect_waf(headers, body)
        header_rows, present, total = webintel.security_header_rows(headers)
        cookie_rows = webintel.cookie_rows(response)
        leak_rows = webintel.info_leak_rows(headers)
        safe, risk = self._safe_browsing(url)

        rows = [
            ("Mode", "quick (passive)"),
            ("Final URL", response.get("url", url)),
            ("HTTP", str(response.get("code", "-"))),
            ("Server", headers.get("server", "-")),
            ("Powered by", headers.get("x-powered-by", "-")),
            ("Content-Type", headers.get("content-type", "-")),
            ("Page title", title),
            ("WAF / CDN", waf),
            ("Tech stack", ", ".join(tech[:10]) or "-"),
        ]
        rows.extend(header_rows)
        rows.extend(leak_rows)
        if cookie_rows:
            rows.append(("Cookies", f"{len(cookie_rows)} set"))
            rows.extend((f"Cookie {name}", flags) for name, flags in cookie_rows[:8])
        rows.append(("Safe Browsing", safe))
        if present <= 2:
            risk += 20
        if leak_rows:
            risk += 5
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Web Scanner: {parsed.hostname}",
            source="HTTP headers + TLS + Safe Browsing",
            confidence="medium",
            rows=rows,
            risk=risk,
        )

    def _deep_scan(self, url: str, parsed):
        response, url = webintel.fetch(url)
        if response.get("status") != "ok":
            return self.result(
                title=f"Web Scanner: {parsed.hostname}",
                source="HTTP",
                confidence="low",
                status=response.get("status", "error"),
                rows=[("URL", url), ("Error", response.get("error") or "Request failed")],
            )

        headers = webintel.header_map(response)
        body = webintel.body_text(response)
        page = webintel.parse_page(body, url)
        title = webintel.page_title(body) or "-"
        tech = webintel.detect_tech(headers, body)
        waf = webintel.detect_waf(headers, body)
        header_rows, present, total = webintel.security_header_rows(headers)
        cookie_rows = webintel.cookie_rows(response)
        leak_rows = webintel.info_leak_rows(headers)
        safe, risk = self._safe_browsing(url)

        rows = [
            ("Mode", "deep (passive + page analysis)"),
            ("Final URL", response.get("url", url)),
            ("HTTP", str(response.get("code", "-"))),
            ("Server", headers.get("server", "-")),
            ("Powered by", headers.get("x-powered-by", "-")),
            ("Page title", title),
            ("WAF / CDN", waf),
            ("Tech stack", ", ".join(tech[:12]) or "-"),
            ("External scripts", f"{page['external_scripts']} ({', '.join(page['external_script_hosts'][:5]) or '-'})"),
            ("Inline scripts", str(page["inline_scripts"])),
            ("Iframes", f"{page['iframes']} ({page['external_iframes'] or '-'})"),
            ("Forms", f"{len(page['forms'])} total, {page['password_forms']} password"),
            ("External form actions", ", ".join(page["external_form_actions"]) or "-"),
            ("Meta generator", page["generator"] or "-"),
        ]
        rows.extend(header_rows)
        rows.extend(leak_rows)
        if cookie_rows:
            rows.extend((f"Cookie {name}", flags) for name, flags in cookie_rows[:10])

        # Redirect chain
        chain = webintel.redirect_chain(url)
        if len(chain) > 1:
            rows.append(("Redirects", f"{len(chain) - 1} hop(s)"))
            for hop in chain[:6]:
                rows.append((f"  {hop['code']}", hop["url"][:120]))

        # robots.txt / security.txt
        robots = webintel.robots(parsed.hostname)
        rows.append(("robots.txt", f"found ({len(robots.get('disallows', []))} rules)" if robots.get("found") else "not found"))
        if robots.get("sensitive"):
            rows.append(("Sensitive paths", ", ".join(robots["sensitive"][:6])))
            risk += 10
        sec_txt = webintel.security_txt(parsed.hostname)
        rows.append(("security.txt", "found" if sec_txt.get("found") else "not found"))

        # TLS
        if parsed.scheme == "https":
            cert = sources.tls_certificate(parsed.hostname)
            if cert.get("ok"):
                rows.append(("TLS", f"{cert['protocol']} · {cert['cipher'][0] if cert.get('cipher') else '-'}"))
                rows.append(("Cert issuer", (cert["issuer"].get("organizationName") or cert["issuer"].get("commonName") or "-")))
                rows.append(("Cert expires", f"{cert['not_after']} ({cert['days_left']} days)"))
                if not cert.get("verified"):
                    risk += 15
                if cert.get("days_left") is not None and cert["days_left"] < 15:
                    risk += 10

        rows.append(("Safe Browsing", safe))
        if page["password_forms"] and parsed.scheme != "https":
            risk += 25
            rows.append(("Warning", "Password form served over plain HTTP"))
        if page["external_form_actions"]:
            risk += 10
        if present <= 2:
            risk += 20
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"Deep Web Scan: {parsed.hostname}",
            source="HTTP + HTML + TLS + Safe Browsing",
            confidence="high",
            rows=rows,
            risk=risk,
        )

    def run(self, case, **kwargs):
        url = self._normalize(kwargs.get("url"))
        if not url:
            return self.result(rows=[("Error", "No URL provided")], status="error")

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return self.result(rows=[("Error", f"Invalid URL: {url}")], status="error")

        mode = (kwargs.get("mode") or "quick").strip().lower()
        if mode in ("d", "deep", "full", "active", "adv", "advanced"):
            return self._deep_scan(url, parsed)
        return self._quick_scan(url, parsed)

    def pivots(self, result):
        host = indicators.url_host(result.get("title", "").split(": ", 1)[-1])
        return [("domain", host)] if host else []
