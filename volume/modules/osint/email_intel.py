import hashlib
import re

import dns.resolver

from volume.core.module_base import BaseModule
from volume.core import net


DISPOSABLE = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "sharklasers.com",
    "getnada.com", "dispostable.com", "trashmail.com", "fakeinbox.com",
    "maildrop.cc", "mintemail.com", "mytemp.email", "spamgourmet.com",
}


class EmailIntel(BaseModule):
    @property
    def id(self):
        return "email_intel"

    @property
    def label(self):
        return "Email Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Email validation, MX, disposable and Gravatar checks"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["email"]

    def _mx(self, domain: str) -> list:
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=6)
            return [f"{a.preference} {a.exchange}" for a in answers]
        except Exception:
            return []

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}", email):
            return {"title": "Email Intel", "rows": [("Error", f"Not a valid email: {email}")]}

        domain = email.rsplit("@", 1)[-1].lower()
        mx = self._mx(domain)

        gravatar_hash = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar = net.get(f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404")
        has_gravatar = gravatar.get("status") == "ok"

        rows = [
            ("Email", email),
            ("Domain", domain),
            ("Syntax", "valid"),
            ("MX", ", ".join(mx) or "none found"),
            ("Disposable", "yes" if domain in DISPOSABLE else "no"),
            ("Gravatar", "found" if has_gravatar else "not found"),
        ]
        if not mx:
            rows.append(("Warning", "No MX record: this domain may not receive mail."))
        elif mx == ["0 ."]:
            rows.append(("Warning", "Null MX record: this domain explicitly does not accept email."))

        return {
            "module": self.id,
            "title": f"Email Intel: {email}",
            "source": "DNS + Gravatar",
            "confidence": "medium" if mx else "low",
            "status": "ok",
            "rows": rows,
        }

    def pivots(self, result):
        email = result.get("title", "").replace("Email Intel: ", "").strip()
        pivots = [("email", email)] if email else []
        if "@" in email:
            pivots.append(("domain", email.rsplit("@", 1)[-1]))
        return pivots
