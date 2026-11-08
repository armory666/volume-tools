import math
import re

from volume.core import sources
from volume.core.module_base import BaseModule


class PasswordPwned(BaseModule):
    @property
    def id(self):
        return "password_pwned"

    @property
    def label(self):
        return "Password Exposure"

    @property
    def category(self):
        return "BREACH"

    @property
    def description(self):
        return "Check a password against Pwned Passwords using k-anonymity (no key)"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["password"]

    @property
    def secret_inputs(self):
        return ("password",)

    @property
    def input_prompts(self):
        return {"password": "Password to check (never stored or sent in full)"}

    def _strength(self, password):
        length = len(password)
        classes = sum(
            bool(re.search(pattern, password))
            for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
        )
        pool = 0
        if re.search(r"[a-z]", password):
            pool += 26
        if re.search(r"[A-Z]", password):
            pool += 26
        if re.search(r"\d", password):
            pool += 10
        if re.search(r"[^A-Za-z0-9]", password):
            pool += 33
        entropy = length * math.log2(pool) if pool else 0
        if entropy >= 80 and classes >= 3:
            label = "strong"
        elif entropy >= 50:
            label = "moderate"
        else:
            label = "weak"
        return label, round(entropy, 1), classes

    def run(self, case, **kwargs):
        password = kwargs.get("password") or ""
        if not password:
            return self.result(rows=[("Error", "No password provided")], status="error")

        label, entropy, classes = self._strength(password)
        result = sources.pwned_password(password)
        if not result.get("ok"):
            return self.result(
                title="Password Exposure",
                source="Pwned Passwords",
                status="source_down",
                rows=[
                    ("Error", result.get("error") or "Lookup failed"),
                    ("Strength", f"{label} ({entropy} bits)"),
                ],
            )

        count = int(result.get("count") or 0)
        rows = [
            ("Pwned", "YES" if count else "no"),
            ("Appearances", f"{count:,}" if count else "0"),
            ("Strength", f"{label} ({entropy} bits, {classes} character classes)"),
            ("Length", str(len(password))),
            ("Method", f"k-anonymity · SHA-1 prefix {result.get('prefix')}… (full hash never sent)"),
        ]
        if count:
            rows.append(("Risk", "This password is in public breach corpora. Do not reuse it."))
            rows.append(("Action", "Change it everywhere it is used and enable MFA."))
        else:
            rows.append(("Note", "Not found in Pwned Passwords. Absence is not a guarantee."))
        if label == "weak":
            rows.append(("Advice", "Use 16+ characters or a passphrase manager."))

        return self.result(
            title="Password Exposure",
            source="Have I Been Pwned · Pwned Passwords",
            confidence="high",
            rows=rows,
            pwned=bool(count),
            count=count,
        )

    def pivots(self, result):
        return []
