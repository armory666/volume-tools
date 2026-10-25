from core.models import Hit

class PhoneNumbers:
    name = "phonenumbers"
    accepts = ("phone",)
    free = True
    pillar = "phone"

    async def query(self, seed, kind):
        if kind != "phone":
            return []
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone
            n = phonenumbers.parse(seed, None)
            return [Hit(self.name, "phone_info", seed, {
                "valid": phonenumbers.is_valid_number(n),
                "carrier": carrier.name_for_number(n, "en"),
                "region": geocoder.description_for_number(n, "en"),
                "timezones": list(timezone.time_zones_for_number(n)),
                "formatted": phonenumbers.format_number(
                    n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            })]
        except Exception:
            return []
