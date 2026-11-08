import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from volume.core.module_base import BaseModule


class PhoneIntel(BaseModule):
    @property
    def id(self):
        return "phone_intel"

    @property
    def label(self):
        return "Phone Intel"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Carrier, region, type and timezone from a phone number"

    @property
    def order(self):
        return 50

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["phone"]

    @property
    def optional_inputs(self):
        return {"region": "US"}

    def run(self, case, **kwargs):
        raw = (kwargs.get("phone") or "").strip()
        region = (kwargs.get("region") or "US").strip().upper()

        try:
            number = phonenumbers.parse(raw, None if raw.startswith("+") else region)
        except Exception as e:
            return {"title": "Phone Intel", "rows": [("Error", f"Could not parse number: {e}")]}

        valid = phonenumbers.is_valid_number(number)
        possible = phonenumbers.is_possible_number(number)
        number_type = phonenumbers.number_type(number)
        type_names = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium rate",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal number",
            phonenumbers.PhoneNumberType.PAGER: "pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
        }

        rows = [
            ("Input", raw),
            ("E.164", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)),
            ("International", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)),
            ("National", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)),
            ("Country", phonenumbers.region_code_for_number(number) or "-"),
            ("Valid", "yes" if valid else "no"),
            ("Possible", "yes" if possible else "no"),
            ("Type", type_names.get(number_type, "unknown")),
            ("Carrier", carrier.name_for_number(number, "en") or "-"),
            ("Location", geocoder.description_for_number(number, "en") or "-"),
            ("Timezone", ", ".join(timezone.time_zones_for_number(number)) or "-"),
        ]

        return {
            "module": self.id,
            "title": f"Phone Intel: {phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)}",
            "source": "phonenumbers",
            "confidence": "high" if valid else "low",
            "status": "ok",
            "rows": rows,
        }

    def pivots(self, result):
        phone = result.get("title", "").replace("Phone Intel: ", "").strip()
        return [("phone", phone)] if phone else []
