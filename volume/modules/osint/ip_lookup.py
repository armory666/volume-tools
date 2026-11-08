import ipaddress
from urllib.parse import quote

from volume.core.module_base import BaseModule
from volume.core import net


class IPLookup(BaseModule):
    @property
    def id(self):
        return "ip_lookup"

    @property
    def label(self):
        return "IP Geolocation"

    @property
    def category(self):
        return "OSINT"

    @property
    def description(self):
        return "Geo, ISP, ASN and timezone for an IP address"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["ip"]

    def run(self, case, **kwargs):
        ip = (kwargs.get("ip") or "").strip()
        if not ip:
            return {"title": "IP Geolocation", "rows": [("Error", "No IP provided")]}

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"title": "IP Geolocation", "rows": [("Error", f"Not a valid IP address: {ip}")]}

        fields = "status,message,query,country,regionName,city,zip,lat,lon,timezone,isp,org,as"
        response = net.get(f"http://ip-api.com/json/{quote(ip)}?fields={fields}")
        if response.get("status") != "ok":
            return {
                "title": "IP Geolocation",
                "rows": [("Error", response.get("error") or "API failed")],
            }

        data = response.get("data") or {}
        if not isinstance(data, dict) or data.get("status") != "success":
            message = data.get("message") if isinstance(data, dict) else "Invalid API response"
            return {
                "module": self.id,
                "title": f"IP Intel: {ip}",
                "source": "ip-api.com",
                "confidence": "low",
                "status": "error",
                "rows": [("Error", message or "Lookup failed")],
            }

        return {
            "module": self.id,
            "title": f"IP Intel: {ip}",
            "source": "ip-api.com",
            "confidence": "high",
            "status": "ok",
            "ip": ip,
            "rows": [
                ("IP", data.get("query")),
                ("ISP", data.get("isp")),
                ("Org", data.get("org")),
                ("ASN", data.get("as")),
                ("Country", data.get("country")),
                ("Region", data.get("regionName")),
                ("City", data.get("city")),
                ("ZIP", data.get("zip")),
                ("Timezone", data.get("timezone")),
                ("Coordinates", f"{data.get('lat')}, {data.get('lon')}"),
            ],
        }

    def pivots(self, result):
        ip = result.get("ip") or result.get("title", "").replace("IP Intel: ", "")
        return [("ip", ip)] if ip else []
