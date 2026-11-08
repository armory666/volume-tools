"""GeoSINT-category modules: addresses, vehicles, images and IP geography."""

import datetime
import hashlib
import io
import mimetypes
import os
import re
from pathlib import Path
from urllib.parse import quote

from volume.core import indicators, sources
from volume.core.module_base import BaseModule
from volume.modules.connector_utils import flatten, response_error


class AddressLookup(BaseModule):
    @property
    def id(self):
        return "address_lookup"

    @property
    def label(self):
        return "Address Lookup"

    @property
    def category(self):
        return "GEOSINT"

    @property
    def description(self):
        return "Forward and reverse geocoding with OpenStreetMap Nominatim"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["query"]

    @property
    def input_prompts(self):
        return {"query": "Address, place name, or 'lat,lon'"}

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip()
        if not query:
            return self.result(rows=[("Error", "No address provided")], status="error")

        coord = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)\s*", query)
        rows = [("Query", query)]
        if coord:
            lat, lon = coord.group(1), coord.group(2)
            data = sources.nominatim_reverse(lat, lon)
            if not data:
                return self.result(
                    title=f"Address Lookup: {lat}, {lon}",
                    source="OpenStreetMap Nominatim",
                    status="not_found",
                    rows=rows + [("Result", "No reverse-geocode result")],
                )
            address = data.get("address") or {}
            rows.extend([
                ("Mode", "reverse geocode"),
                ("Address", data.get("display_name") or "-"),
                ("Latitude", lat),
                ("Longitude", lon),
                ("Type", data.get("type") or "-"),
                ("Class", data.get("class") or "-"),
                ("OSM", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"),
            ])
            for key, value in address.items():
                rows.append((f"Address · {key}", str(value)))
            return self.result(
                title=f"Address Lookup: {lat}, {lon}",
                source="OpenStreetMap Nominatim",
                confidence="high",
                rows=rows,
            )

        results = sources.nominatim_search(query, limit=5)
        rows.append(("Results", str(len(results))))
        for item in results:
            rows.append((
                (item.get("display_name") or "result")[:100],
                f"{item.get('lat')}, {item.get('lon')} · {item.get('type') or '-'} · "
                f"https://www.openstreetmap.org/?mlat={item.get('lat')}&mlon={item.get('lon')}",
            ))
        if not results:
            rows.append(("Result", "No matching address or place."))
        return self.result(
            title=f"Address Lookup: {query}",
            source="OpenStreetMap Nominatim",
            confidence="high" if results else "low",
            status="ok" if results else "not_found",
            rows=rows,
        )


class IPInfo(BaseModule):
    @property
    def id(self):
        return "ip_info"

    @property
    def label(self):
        return "IP Info"

    @property
    def category(self):
        return "GEOSINT"

    @property
    def description(self):
        return "Geolocation, ASN, reverse DNS and passive port information for an IP"

    @property
    def order(self):
        return 20

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["ip"]

    def run(self, case, **kwargs):
        ip = (kwargs.get("ip") or "").strip()
        if not indicators.is_ip(ip):
            return self.result(rows=[("Error", f"Not a valid IP: {ip or '-'}")], status="error")
        geo = sources.ip_geo(ip)
        reverse = sources.reverse_dns(ip)
        internetdb = sources.internetdb(ip)
        rows = [
            ("IP", ip),
            ("Reverse DNS", reverse or "-"),
            ("City", geo.get("city") or "-"),
            ("Region", geo.get("regionName") or geo.get("region") or "-"),
            ("Country", geo.get("country") or geo.get("country_name") or "-"),
            ("Coordinates", f"{geo.get('lat')}, {geo.get('lon')}" if geo.get("lat") else geo.get("loc") or "-"),
            ("ISP / org", geo.get("isp") or geo.get("org") or "-"),
            ("ASN", geo.get("as") or geo.get("asn") or "-"),
            ("Timezone", geo.get("timezone") or "-"),
            ("Open ports", ", ".join(map(str, internetdb.get("ports") or [])) or "-"),
            ("Hostnames", ", ".join(map(str, internetdb.get("hostnames") or [])) or "-"),
            ("Provider", geo.get("_provider") or "-"),
        ]
        return self.result(
            title=f"IP Info: {ip}",
            source="ip-api + InternetDB",
            confidence="high" if geo else "low",
            rows=rows,
            ip=ip,
        )

    def pivots(self, result):
        return [("ip", result.get("ip"))] if result.get("ip") else []


def _gps_to_decimal(values):
    try:
        degrees, minutes, seconds = (float(v) for v in values)
        return degrees + minutes / 60 + seconds / 3600
    except Exception:
        return None


class ImageMetadata(BaseModule):
    @property
    def id(self):
        return "image_metadata"

    @property
    def label(self):
        return "Image Metadata"

    @property
    def category(self):
        return "GEOSINT"

    @property
    def description(self):
        return "EXIF, GPS, dimensions and hashes for a local image or image URL"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["source"]

    @property
    def input_prompts(self):
        return {"source": "Local image path or https:// image URL"}

    def _load(self, source):
        if source.startswith(("http://", "https://")):
            import httpx

            response = httpx.get(source, timeout=20.0, follow_redirects=True)
            response.raise_for_status()
            return response.content, source
        path = Path(source).expanduser()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        return path.read_bytes(), str(path)

    def run(self, case, **kwargs):
        source = (kwargs.get("source") or "").strip()
        if not source:
            return self.result(rows=[("Error", "No image path or URL provided")], status="error")
        try:
            raw, label = self._load(source)
        except Exception as exc:
            return self.result(rows=[("Error", f"{type(exc).__name__}: {exc}")], status="error")

        rows = [
            ("Source", label),
            ("Size", f"{len(raw):,} bytes"),
            ("SHA-256", hashlib.sha256(raw).hexdigest()),
            ("MD5", hashlib.md5(raw).hexdigest()),
            ("MIME (guess)", mimetypes.guess_type(label)[0] or "-"),
        ]
        try:
            from PIL import Image, ExifTags
        except ImportError:
            rows.append(("EXIF", "Pillow not installed: pip install pillow"))
            return self.result(
                title="Image Metadata",
                source="local/remote file",
                confidence="low",
                rows=rows,
            )

        try:
            image = Image.open(io.BytesIO(raw))
            rows.extend([
                ("Format", image.format or "-"),
                ("Mode", image.mode or "-"),
                ("Dimensions", f"{image.width} × {image.height}"),
            ])
            exif = image.getexif()
            if not exif:
                rows.append(("EXIF", "no EXIF metadata"))
            else:
                gps = {}
                for tag_id, value in exif.items():
                    tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag == "GPSInfo":
                        gps = value
                        continue
                    text = str(value)
                    if len(text) > 500:
                        text = text[:500] + "…"
                    rows.append((f"EXIF · {tag}", text))
                if gps:
                    try:
                        gps_tags = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps.items()}
                        lat = _gps_to_decimal(gps_tags.get("GPSLatitude"))
                        lon = _gps_to_decimal(gps_tags.get("GPSLongitude"))
                        if lat is not None and lon is not None:
                            if str(gps_tags.get("GPSLatitudeRef", "N")).upper() == "S":
                                lat = -lat
                            if str(gps_tags.get("GPSLongitudeRef", "E")).upper() == "W":
                                lon = -lon
                            rows.append(("GPS", f"{lat:.6f}, {lon:.6f}"))
                            rows.append((
                                "GPS map",
                                f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
                            ))
                    except Exception:
                        pass
        except Exception as exc:
            rows.append(("Image parse", f"failed ({type(exc).__name__}: {exc})"))

        return self.result(
            title="Image Metadata",
            source="EXIF + file hashes",
            confidence="high",
            rows=rows,
        )


class CarsOwners(BaseModule):
    @property
    def id(self):
        return "cars_owners"

    @property
    def label(self):
        return "Cars & Owners"

    @property
    def category(self):
        return "GEOSINT"

    @property
    def description(self):
        return "UK vehicle enquiry (DVLA) via a configured API key"

    @property
    def min_tier(self):
        return "DETECTIVE"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 3

    @property
    def requires_key(self):
        return ("dvla",)

    @property
    def inputs(self):
        return ["plate"]

    @property
    def input_prompts(self):
        return {"plate": "UK registration plate (e.g. AB12 CDE)"}

    def run(self, case, **kwargs):
        plate = re.sub(r"\s+", "", (kwargs.get("plate") or "")).upper()
        if not plate:
            return self.result(rows=[("Error", "No registration plate provided")], status="error")
        key = self.api_key("dvla")
        if not key:
            return self.key_required(
                ("dvla",),
                help_url="https://developer-portal.driver-vehicle-licensing.api.gov.uk/",
                title=f"Cars & Owners: {plate}",
                extra_rows=[
                    ("Note", "Vehicle data only; owner data is not exposed by DVLA."),
                    ("Legal", "Use only for lawful purposes with a legitimate interest."),
                ],
            )
        response = sources.dvla_vehicle(plate, key)
        if response.get("status") != "ok":
            return self.result(
                title=f"Cars & Owners: {plate}",
                source="DVLA Vehicle Enquiry",
                status="source_down" if response.get("status") == "source_down" else "error",
                rows=[("Plate", plate), ("Error", response_error(response))],
            )
        data = response.get("data")
        rows = [("Plate", plate)]
        rows.extend(flatten(data, limit=60))
        return self.result(
            title=f"Cars & Owners: {plate}",
            source="DVLA Vehicle Enquiry",
            confidence="high",
            rows=rows,
        )
