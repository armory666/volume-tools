"""Reusable web/HTTP intelligence helpers (headers, tech, HTML, redirects)."""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from volume.core import indicators, net

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
}

INFO_LEAK_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET version",
    "x-generator": "Generator",
    "via": "Via",
}

# (name, header needles, body needles)
TECH_SIGNATURES = [
    ("WordPress", ("x-powered-by: wordpress",), ("wp-content", "wp-includes", "wp-json")),
    ("Drupal", (), ("sites/default/files", "drupal.js", "drupal-settings-json")),
    ("Joomla", (), ("/media/system/js/", "joomla", "com_content")),
    ("Magento", (), ("mage/cookies", "magento", "static/version")),
    ("PrestaShop", (), ("prestashop", "var prestashop")),
    ("Shopify", (), ("cdn.shopify.com", "shopify.theme", "shopify-section")),
    ("Wix", (), ("wixstatic.com", "wix.com", "wix-code")),
    ("Squarespace", (), ("squarespace.com", "static1.squarespace")),
    ("Webflow", (), ("webflow.com", "data-wf-page")),
    ("Ghost", (), ("ghost.org", "ghost-url")),
    ("Next.js", (), ("__NEXT_DATA__", "/_next/static")),
    ("React", (), ("react-dom", "data-reactroot", "__react")),
    ("Vue.js", (), ("vue.js", "vue.min.js", "data-v-")),
    ("Angular", (), ("ng-version", "angular.min.js")),
    ("Svelte", (), ("svelte", "__svelte")),
    ("jQuery", (), ("jquery.min.js", "jquery.js")),
    ("Bootstrap", (), ("bootstrap.min.css", "bootstrap.min.js")),
    ("Tailwind CSS", (), ("tailwind",)),
    ("Laravel", ("set-cookie: laravel_session", "set-cookie: xsrf-token"), ("laravel",)),
    ("Django", (), ("csrfmiddlewaretoken", "__admin", "django")),
    ("Ruby on Rails", (), ("csrf-token", "_rails", "action_dispatch")),
    ("ASP.NET", ("x-aspnet-version", "x-powered-by: asp.net"), ("__viewstate", "aspnet")),
    ("PHP", ("x-powered-by: php", "set-cookie: phpsessid"), ("phpsessid",)),
    ("Express", ("x-powered-by: express",), ()),
    ("Flask", (), ("werkzeug",)),
    ("Cloudflare", ("cf-ray", "server: cloudflare"), ("cdn-cgi/",)),
    ("Fastly", ("x-served-by", "x-fastly"), ()),
    ("Akamai", ("x-akamai", "akamai-grn"), ()),
    ("Amazon CloudFront", ("x-amz-cf-id", "x-amz-cf-pop"), ()),
    ("Nginx", ("server: nginx",), ()),
    ("Apache", ("server: apache",), ()),
    ("IIS", ("server: microsoft-iis",), ()),
    ("LiteSpeed", ("server: litespeed",), ()),
    ("Caddy", ("server: caddy",), ()),
    ("Google Analytics", (), ("googletagmanager.com", "google-analytics.com", "gtag(")),
    ("Google reCAPTCHA", (), ("recaptcha/api.js", "g-recaptcha")),
    ("Cloudflare Turnstile", (), ("challenges.cloudflare.com/turnstile",)),
    ("Sentry", (), ("sentry.io", "sentry-dsn")),
    ("Stripe", (), ("js.stripe.com",)),
    ("HubSpot", (), ("hs-scripts.com", "hubspot")),
    ("Intercom", (), ("intercom.io", "intercomsettings")),
    ("Zendesk", (), ("zendesk.com", "zdassets.com")),
    ("Hotjar", (), ("hotjar.com", "hj(")),
    ("Segment", (), ("segment.com/analytics", "analytics.js")),
]


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.links = []
        self.iframes = []
        self.metas = []
        self.forms = []
        self.comments = []
        self._in_script = False
        self._script_text = []

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            self._in_script = True
            self.scripts.append(attrs)
        elif tag == "link":
            self.links.append(attrs)
        elif tag == "iframe":
            self.iframes.append(attrs)
        elif tag == "meta":
            self.metas.append(attrs)
        elif tag == "form":
            self.forms.append({"attrs": attrs, "inputs": []})
        elif tag == "input" and self.forms:
            self.forms[-1]["inputs"].append(attrs)

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._script_text.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip()[:200])


def fetch(url, **kw):
    normalized = indicators.normalize_url(url)
    return net.get(normalized, **kw), normalized


def header_map(response) -> dict:
    return {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}


def body_text(response) -> str:
    data = response.get("data")
    if isinstance(data, str):
        return data
    if isinstance(data, (dict, list)):
        return str(data)
    return ""


def page_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def meta_generator(body: str) -> str:
    match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        body or "",
        re.I,
    )
    return match.group(1).strip()[:120] if match else ""


def detect_tech(headers: dict, body: str) -> list:
    blob = (body or "").lower()
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    found = []
    for name, header_needles, body_needles in TECH_SIGNATURES:
        if any(n in header_blob for n in header_needles) or any(
            n in blob for n in body_needles
        ):
            found.append(name)
    generator = meta_generator(body)
    if generator and generator.lower() not in [f.lower() for f in found]:
        found.append(generator)
    return found


def detect_waf(headers: dict, body: str) -> str:
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    blob = (body or "").lower()
    checks = [
        ("Cloudflare", ("cf-ray", "cf-cache-status", "server: cloudflare")),
        ("Akamai", ("x-akamai", "akamai-grn")),
        ("Imperva / Incapsula", ("x-iinfo", "incap_ses", "visid_incap")),
        ("Sucuri", ("x-sucuri-id", "sucuri")),
        ("AWS WAF / CloudFront", ("x-amz-cf-id", "awselb")),
        ("F5 BIG-IP", ("bigipserver", "x-wa-info")),
        ("Fastly", ("x-fastly", "x-served-by")),
        ("Barracuda", ("barra_counter_session", "barracuda")),
    ]
    for name, needles in checks:
        if any(n in header_blob for n in needles):
            return name
    if "attention required! | cloudflare" in blob or "cf-error-details" in blob:
        return "Cloudflare (challenge page)"
    if "access denied" in blob and "incapsula" in blob:
        return "Imperva / Incapsula"
    return "not detected"


def parse_page(body: str, base_url: str) -> dict:
    parser = _PageParser()
    try:
        parser.feed(body or "")
    except Exception:
        pass
    base_host = indicators.url_host(base_url)

    def external(url):
        if not url:
            return False
        if url.startswith(("data:", "javascript:", "#", "mailto:")):
            return False
        host = urlparse(urljoin(base_url, url)).hostname or ""
        return bool(host) and host.lower() != base_host

    scripts = [s for s in parser.scripts]
    external_scripts = [s for s in scripts if external(s.get("src", ""))]
    inline_scripts = [s for s in scripts if not s.get("src")]
    forms = []
    for form in parser.forms:
        action = form["attrs"].get("action", "")
        password = any(i.get("type", "").lower() == "password" for i in form["inputs"])
        forms.append(
            {
                "action": action,
                "external": external(action),
                "password": password,
                "inputs": len(form["inputs"]),
                "method": (form["attrs"].get("method") or "get").lower(),
            }
        )
    iframes = [i.get("src", "") for i in parser.iframes if i.get("src")]
    return {
        "scripts": len(scripts),
        "inline_scripts": len(inline_scripts),
        "external_scripts": len(external_scripts),
        "external_script_hosts": sorted(
            {
                (urlparse(urljoin(base_url, s.get("src", ""))).hostname or "").lower()
                for s in external_scripts
            }
            - {""}
        )[:12],
        "iframes": len(iframes),
        "external_iframes": [i for i in iframes if external(i)][:8],
        "forms": forms,
        "password_forms": sum(1 for f in forms if f["password"]),
        "external_form_actions": [f["action"] for f in forms if f["external"]][:8],
        "links": len(parser.links),
        "comments": parser.comments[:6],
        "generator": meta_generator(body),
        "script_text": " ".join(parser._script_text)[:20000],
    }


def security_header_rows(headers: dict):
    rows = []
    present = 0
    for header, label in SECURITY_HEADERS.items():
        value = headers.get(header)
        if value:
            present += 1
            note = value[:120]
            if header == "content-security-policy" and (
                "unsafe-inline" in value or "unsafe-eval" in value
            ):
                note += "  [weak: unsafe-inline/eval]"
            if header == "strict-transport-security":
                match = re.search(r"max-age=(\d+)", value)
                if match and int(match.group(1)) < 15552000:
                    note += "  [short max-age]"
            rows.append((label, note))
        else:
            rows.append((label, "MISSING"))
    rows.append(("Security headers", f"{present}/{len(SECURITY_HEADERS)} present"))
    return rows, present, len(SECURITY_HEADERS)


def cookie_rows(response) -> list:
    rows = []
    for name, value in response.get("header_items") or []:
        if name.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in value.split(";")]
        cookie_name = parts[0].split("=", 1)[0][:60]
        lower = value.lower()
        flags = []
        if "secure" not in lower:
            flags.append("no Secure")
        if "httponly" not in lower:
            flags.append("no HttpOnly")
        if "samesite" not in lower:
            flags.append("no SameSite")
        rows.append((cookie_name, ", ".join(flags) if flags else "Secure, HttpOnly, SameSite"))
    return rows


def info_leak_rows(headers: dict) -> list:
    rows = []
    for header, label in INFO_LEAK_HEADERS.items():
        if headers.get(header):
            rows.append((f"Leaks {label}", headers[header][:120]))
    return rows


def redirect_chain(url: str, max_hops: int = 10) -> list:
    chain = []
    current = indicators.normalize_url(url)
    seen = set()
    for _ in range(max_hops):
        if not current or current in seen:
            break
        seen.add(current)
        response = net.get(current, follow_redirects=False)
        code = response.get("code") or 0
        headers = header_map(response)
        location = headers.get("location", "")
        chain.append(
            {
                "url": current,
                "code": code,
                "location": location,
                "status": response.get("status"),
            }
        )
        if code in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        break
    return chain


def robots(host: str) -> dict:
    host = host.strip().strip("/")
    response = net.get(f"https://{host}/robots.txt")
    if response.get("status") != "ok":
        return {"found": False}
    text = body_text(response)
    disallows, allows, sitemaps = [], [], []
    for line in text.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("disallow:"):
            disallows.append(line.split(":", 1)[1].strip())
        elif lower.startswith("allow:"):
            allows.append(line.split(":", 1)[1].strip())
        elif lower.startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    sensitive_terms = (
        "admin", "login", "api", "backup", "config", "private", "internal",
        "test", "dev", "staging", ".git", ".env", "phpmyadmin", "wp-admin",
        "upload", "debug", "server-status",
    )
    sensitive = sorted(
        {
            path
            for path in disallows
            if path and any(term in path.lower() for term in sensitive_terms)
        }
    )
    return {
        "found": True,
        "disallows": disallows[:60],
        "allows": allows[:20],
        "sitemaps": sitemaps[:10],
        "sensitive": sensitive[:20],
        "length": len(text),
    }


def security_txt(host: str) -> dict:
    host = host.strip().strip("/")
    response = net.get(f"https://{host}/.well-known/security.txt")
    if response.get("status") != "ok":
        return {"found": False}
    text = body_text(response)
    fields = {}
    for line in text.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    return {"found": True, "fields": fields, "length": len(text)}
