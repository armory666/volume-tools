import re

from volume.core.module_base import BaseModule


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)

REFANG = [
    (re.compile(r"hxxps", re.I), "https"),
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)|\sdot\s", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)|\sat\s", re.I), "@"),
    (re.compile(r"\[/\]"), "/"),
]


def _defang(value: str) -> str:
    value = re.sub(r"^https", "hxxps", value, flags=re.I)
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    return value.replace(".", "[.]")


class IOCDefang(BaseModule):
    @property
    def id(self):
        return "ioc_defang"

    @property
    def label(self):
        return "IOC Defang / Refang"

    @property
    def category(self):
        return "INVESTIGATION"

    @property
    def description(self):
        return "Make indicators safe to share, or restore defanged text for pivoting"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 0

    @property
    def inputs(self):
        return ["text"]

    @property
    def input_prompts(self):
        return {"text": "Paste indicators or defanged text"}

    @property
    def multiline_inputs(self):
        return ("text",)

    def run(self, case, **kwargs):
        text = str(kwargs.get("text") or "")
        if not text.strip():
            return self.result(rows=[("Error", "No text provided")], status="error")

        refanged = text
        for pattern, replacement in REFANG:
            refanged = pattern.sub(replacement, refanged)

        urls = sorted({_defang(u.rstrip(".,;:!?)\\]}>\"'")) for u in URL_RE.findall(refanged)})
        emails = sorted({_defang(e) for e in EMAIL_RE.findall(refanged)})
        ips = sorted({i for i in IPV4_RE.findall(refanged)})
        domains = sorted(
            {
                _defang(d)
                for d in DOMAIN_RE.findall(refanged)
                if d.lower() not in {u.split("://", 1)[-1].split("/", 1)[0].lower() for u in URL_RE.findall(refanged)}
            }
        )

        rows = [
            ("Input length", f"{len(text)} chars"),
            ("URLs", str(len(urls))),
            ("Emails", str(len(emails))),
            ("IPs", str(len(ips))),
            ("Domains", str(len(domains))),
        ]
        for url in urls:
            rows.append(("Defanged URL", url))
        for email in emails:
            rows.append(("Defanged email", email))
        for ip in ips:
            rows.append(("Defanged IP", ip.replace(".", "[.]")))
        for domain in domains:
            rows.append(("Defanged domain", domain))

        if not any((urls, emails, ips, domains)):
            rows.append(("Result", "No indicators found; showing refanged text only."))
            rows.append(("Refanged", refanged[:1500]))
        else:
            rows.append(("Refanged preview", refanged[:600]))

        return self.result(
            title="IOC Defang / Refang",
            source="local transformation",
            confidence="high",
            rows=rows,
            defanged={"url": urls, "email": emails, "ip": ips, "domain": domains},
            refanged=refanged,
        )

    def pivots(self, result):
        defanged = result.get("defanged") or {}
        pivots = []
        for value in defanged.get("domain", [])[:30]:
            pivots.append(("domain", value.replace("[.]", ".")))
        for value in defanged.get("ip", [])[:30]:
            pivots.append(("ip", value))
        for value in defanged.get("email", [])[:30]:
            pivots.append(("email", value.replace("[.]", ".").replace("[@]", "@")))
        return pivots
