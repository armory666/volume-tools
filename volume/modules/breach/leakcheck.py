from urllib.parse import quote

from volume.core.module_base import BaseModule
from volume.core import config, net


class LeakCheck(BaseModule):
    @property
    def id(self):
        return "leak_check"

    @property
    def label(self):
        return "Breach Check (HIBP)"

    @property
    def category(self):
        return "BREACH"

    @property
    def description(self):
        return "Breach exposure for an email via Have I Been Pwned"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 2

    @property
    def requires_key(self):
        return ("hibp",)

    @property
    def inputs(self):
        return ["email"]

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip()
        if not email:
            return {"title": "Breach Check", "rows": [("Error", "No email provided")]}

        api_key = config.get_key("hibp")
        if not api_key:
            return {
                "module": self.id,
                "title": f"Breach Check: {email}",
                "source": "Have I Been Pwned",
                "confidence": "low",
                "status": "skipped",
                "rows": [
                    ("Result", "No HIBP API key configured."),
                    ("Setup", "Set HIBP_API_KEY in .env or add {\"hibp\": \"...\"} to data/keys.json."),
                    ("Get a key", "https://haveibeenpwned.com/API/Key"),
                ],
            }

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='@')}?truncateResponse=false"
        response = net.get(url, source="hibp", headers={
            "hibp-api-key": api_key,
            "User-Agent": "volume-osint",
        })

        if response.get("status") == "not_found":
            return {
                "module": self.id,
                "title": f"Breach Check: {email}",
                "source": "Have I Been Pwned",
                "confidence": "high",
                "status": "ok",
                "rows": [("Email", email), ("Breaches", "0 (not found in any known breach)")],
            }

        if response.get("status") != "ok":
            return {
                "module": self.id,
                "title": f"Breach Check: {email}",
                "source": "Have I Been Pwned",
                "confidence": "low",
                "status": response.get("status", "error"),
                "rows": [("Error", response.get("error") or "HIBP request failed")],
            }

        breaches = response.get("data") or []
        if not isinstance(breaches, list):
            breaches = []
        breaches.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)

        rows = [("Email", email), ("Breaches", str(len(breaches)))]
        for breach in breaches:
            name = breach.get("Name", "Unknown")
            date = breach.get("BreachDate", "?")
            count = breach.get("PwnCount", 0)
            data_classes = ", ".join(breach.get("DataClasses", [])[:6])
            rows.append((f"{name} ({date})", f"{count:,} accounts · {data_classes}"))

        return {
            "module": self.id,
            "title": f"Breach Check: {email}",
            "source": "Have I Been Pwned",
            "confidence": "high",
            "status": "ok",
            "rows": rows,
        }

    def pivots(self, result):
        email = result.get("title", "").replace("Breach Check: ", "").strip()
        return [("email", email)] if email else []
