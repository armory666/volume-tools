from volume.core import indicators, sources
from volume.core.module_base import BaseModule


class TLSScan(BaseModule):
    @property
    def id(self):
        return "tls_scan"

    @property
    def label(self):
        return "TLS / SSL Scanner"

    @property
    def category(self):
        return "CSINT"

    @property
    def description(self):
        return "Protocol versions, cipher, certificate validity and trust chain"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 50

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
                source="TLS handshake",
                status="error",
                rows=[("Host", host), ("Error", cert.get("error") or "Handshake failed")],
            )

        protocols = sources.tls_protocols(host)
        rows = [
            ("Host", host),
            ("Protocol", cert.get("protocol", "-")),
            ("Cipher", (cert.get("cipher") or ["-"])[0]),
            ("Verified", "yes" if cert.get("verified") else "NO"),
        ]
        if not cert.get("verified"):
            rows.append(("Verify error", cert.get("verify_error", "")[:180]))

        for label in ("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"):
            info = protocols.get(label)
            if info is None:
                rows.append((label, "not supported by this Python/OpenSSL"))
            elif info.get("supported"):
                cipher = info.get("cipher")
                rows.append((label, f"supported · {cipher[0] if cipher else '-'}"))
            else:
                rows.append((label, "not supported"))

        subject = cert.get("subject") or {}
        issuer = cert.get("issuer") or {}
        rows.extend([
            ("Subject CN", subject.get("commonName", "-")),
            ("Subject Org", subject.get("organizationName", "-")),
            ("Issuer CN", issuer.get("commonName", "-")),
            ("Issuer Org", issuer.get("organizationName", "-")),
            ("Valid from", cert.get("not_before", "-")),
            ("Valid until", cert.get("not_after", "-")),
            ("Days left", str(cert.get("days_left", "-"))),
            ("Serial", cert.get("serial", "-")),
            ("SHA-256", cert.get("sha256", "-")),
            ("SANs", str(len(cert.get("sans") or []))),
        ])
        for name in (cert.get("sans") or [])[:25]:
            rows.append(("SAN", name))

        findings = []
        risk = 0
        if (protocols.get("TLS 1.0") or {}).get("supported"):
            findings.append("TLS 1.0 enabled (deprecated)")
            risk += 25
        if (protocols.get("TLS 1.1") or {}).get("supported"):
            findings.append("TLS 1.1 enabled (deprecated)")
            risk += 20
        if not (protocols.get("TLS 1.3") or {}).get("supported"):
            findings.append("TLS 1.3 not supported")
            risk += 5
        if not cert.get("verified"):
            findings.append("Certificate not trusted")
            risk += 30
        if cert.get("days_left") is not None and cert["days_left"] < 0:
            findings.append("Certificate expired")
            risk += 30
        elif cert.get("days_left") is not None and cert["days_left"] < 15:
            findings.append("Certificate expires soon")
            risk += 10
        if subject.get("commonName") and subject.get("commonName") == issuer.get("commonName"):
            findings.append("Self-signed certificate")
            risk += 20
        for finding in findings:
            rows.append(("Finding", finding))
        rows.append(("Risk", f"{indicators.risk_label(risk)} ({risk}/100)"))

        return self.result(
            title=f"TLS: {host}",
            source="TLS handshake + certificate",
            confidence="high",
            rows=rows,
            risk=risk,
            protocols={k: (v or {}).get("supported") for k, v in protocols.items()},
        )

    def pivots(self, result):
        host = result.get("title", "").replace("TLS: ", "").strip()
        return [("domain", host)] if host else []
