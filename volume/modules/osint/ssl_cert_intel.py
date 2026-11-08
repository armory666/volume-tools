from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class SSLCertIntel(BaseModule):
    @property
    def id(self):
        return "ssl_cert_intel"

    @property
    def label(self):
        return "TLS Certificate Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Certificate subject, issuer, SANs, validity and chain trust"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 70

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["host"]

    @property
    def input_prompts(self):
        return {"host": "Host or URL (example.com)"}

    def run(self, case, **kwargs):
        raw = (kwargs.get("host") or "").strip()
        host = indicators.url_host(raw) if "://" in raw else indicators.normalize_domain(raw)
        if not host:
            return self.result(rows=[("Error", "No host provided")], status="error")

        cert = sources.tls_certificate(host)
        if not cert.get("ok"):
            return self.result(
                title=f"TLS: {host}",
                rows=[("Host", host), ("Error", cert.get("error") or "TLS handshake failed")],
                status="error",
            )

        subject = cert["subject"]
        issuer = cert["issuer"]
        sans = cert["sans"]
        rows = [
            ("Host", host),
            ("Subject CN", subject.get("commonName", "-")),
            ("Subject Org", subject.get("organizationName", "-")),
            ("Issuer CN", issuer.get("commonName", "-")),
            ("Issuer Org", issuer.get("organizationName", "-")),
            ("Verified", "yes" if cert.get("verified") else f"NO ({cert.get('verify_error', '')[:80]})"),
            ("Valid from", cert.get("not_before", "-")),
            ("Valid until", cert.get("not_after", "-")),
            ("Days left", str(cert.get("days_left", "-"))),
            ("Protocol", cert.get("protocol", "-")),
            ("Cipher", (cert.get("cipher") or ["-"])[0]),
            ("Serial", cert.get("serial", "-")),
            ("SHA-256", cert.get("sha256", "-")),
            ("SANs", f"{len(sans)} names"),
        ]
        for name in sans[:30]:
            rows.append(("SAN", name))

        warnings = []
        if not cert.get("verified"):
            warnings.append("Certificate is not trusted by the system store")
        if subject.get("commonName") and subject.get("commonName") == issuer.get("commonName"):
            warnings.append("Self-signed certificate")
        if cert.get("days_left") is not None and cert["days_left"] < 0:
            warnings.append("Certificate expired")
        elif cert.get("days_left") is not None and cert["days_left"] < 15:
            warnings.append("Certificate expires soon")
        if any(name.startswith("*.") for name in sans):
            warnings.append("Wildcard certificate")
        if warnings:
            rows.append(("Warnings", "; ".join(warnings)))

        return self.result(
            title=f"TLS: {host}",
            source="TLS handshake",
            confidence="high",
            rows=rows,
            sans=sans,
            verified=cert.get("verified"),
        )

    def pivots(self, result):
        pivots = []
        for name in (result.get("sans") or [])[:30]:
            name = str(name).lower().lstrip("*.")
            if indicators.is_domain(name):
                pivots.append(("domain", name))
        return pivots
