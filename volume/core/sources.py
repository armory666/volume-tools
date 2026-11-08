"""Thin, reusable clients for public intelligence sources.

Every function is defensive: network/API failures are returned as data instead
of raising, so modules can always render a useful result.
"""

import base64
import datetime
import hashlib
import socket
import ssl
from urllib.parse import quote, urljoin, urlparse

from volume.core import config, indicators, net

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _ok(response) -> bool:
    return isinstance(response, dict) and response.get("status") == "ok"


def _data(response):
    return response.get("data") if _ok(response) else None


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


# ---------------------------------------------------------------------------
# RDAP / WHOIS
# ---------------------------------------------------------------------------

RDAP_DOMAIN = "https://rdap.org/domain/{target}"
RDAP_IP = "https://rdap.org/ip/{target}"


def rdap_domain(domain: str) -> dict:
    return net.get(RDAP_DOMAIN.format(target=quote(domain, safe="")), source="rdap")


def rdap_ip(ip: str) -> dict:
    return net.get(RDAP_IP.format(target=quote(ip, safe="")), source="rdap")


def _vcard_name(entity: dict) -> str:
    vcard = entity.get("vcardArray") or []
    if len(vcard) > 1 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if item and item[0] in ("fn", "org") and len(item) > 3:
                return str(item[3])
    return entity.get("handle", "") or ""


def _entity_emails(entity: dict) -> list:
    out = []
    vcard = entity.get("vcardArray") or []
    if len(vcard) > 1 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if item and item[0] == "email" and len(item) > 3:
                out.append(str(item[3]))
    return out


def rdap_summary(data: dict) -> dict:
    data = _as_dict(data)
    summary = {
        "handle": data.get("handle", ""),
        "name": data.get("name", ""),
        "registrar": "",
        "registrar_id": "",
        "abuse_email": "",
        "created": "",
        "updated": "",
        "expires": "",
        "status": _as_list(data.get("status")),
        "nameservers": [],
        "entities": [],
    }
    for ns in _as_list(data.get("nameservers")):
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            summary["nameservers"].append(str(name).lower())
    for event in _as_list(data.get("events")):
        action = event.get("eventAction")
        date = str(event.get("eventDate", ""))[:10]
        if action == "registration":
            summary["created"] = date
        elif action == "last changed":
            summary["updated"] = date
        elif action == "expiration":
            summary["expires"] = date
    for entity in _as_list(data.get("entities")):
        roles = entity.get("roles") or []
        name = _vcard_name(entity)
        if name:
            summary["entities"].append(f"{name} ({', '.join(roles)})" if roles else name)
        if "registrar" in roles:
            summary["registrar"] = name or entity.get("handle", "")
            summary["registrar_id"] = entity.get("handle", "")
        emails = _entity_emails(entity)
        if emails and ("abuse" in roles or not summary["abuse_email"]):
            summary["abuse_email"] = emails[0]
        for sub in _as_list(entity.get("entities")):
            sub_emails = _entity_emails(sub)
            if sub_emails and not summary["abuse_email"]:
                summary["abuse_email"] = sub_emails[0]
    return summary


# ---------------------------------------------------------------------------
# Certificate transparency / subdomains
# ---------------------------------------------------------------------------


def crt_sh(query: str, timeout: float = 25.0) -> list:
    url = f"https://crt.sh/?q=%25.{quote(query, safe='')}&output=json"
    response = net.get(url, source="crt", timeout=timeout)
    data = _data(response)
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "id": item.get("id"),
                "name": (item.get("name_value") or "").strip(),
                "issuer": (item.get("issuer_name") or "").strip(),
                "not_before": item.get("not_before", ""),
                "not_after": item.get("not_after", ""),
            }
        )
    return out


def subdomains_from_crt(domain: str) -> list:
    domain = indicators.normalize_domain(domain)
    names = set()
    for cert in crt_sh(domain):
        for name in str(cert.get("name", "")).splitlines():
            name = name.strip().lower().lstrip("*.").strip(".")
            if name and name.endswith("." + domain) and name != domain:
                names.add(name)
    return sorted(names)


# ---------------------------------------------------------------------------
# Shodan InternetDB / BGPView
# ---------------------------------------------------------------------------


def internetdb(ip: str) -> dict:
    response = net.get(f"https://internetdb.shodan.io/{quote(ip, safe='')}", source="shodan")
    if response.get("status") == "not_found":
        return {}
    return _as_dict(_data(response))


def bgpview_ip(ip: str) -> dict:
    data = _data(net.get(f"https://api.bgpview.io/ip/{quote(ip, safe='')}", source="bgpview"))
    return _as_dict(data)


def bgpview_asn(asn: str) -> dict:
    asn = str(asn).upper().replace("AS", "")
    data = _data(net.get(f"https://api.bgpview.io/asn/{quote(asn, safe='')}", source="bgpview"))
    return _as_dict(data)


# ---------------------------------------------------------------------------
# DNS blocklists
# ---------------------------------------------------------------------------

DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("psbl.surriel.com", "PSBL"),
    ("spam.dnsbl.sorbs.net", "SORBS Spam"),
    ("dyna.spamrats.com", "SpamRats Dyna"),
    ("noptr.spamrats.com", "SpamRats NoPtr"),
    ("bl.0spam.org", "0spam"),
]


def _spamhaus_reason(code: str) -> str:
    return {
        "127.0.0.2": "SBL listed",
        "127.0.0.3": "SBL CSS listed",
        "127.0.0.4": "XBL listed",
        "127.0.0.9": "SBL DROP listed",
        "127.0.0.10": "PBL listed",
        "127.0.0.11": "PBL listed",
    }.get(code, "listed")


def dnsbl_hits(ip: str, zones=None) -> list:
    import dns.resolver

    reverse = indicators.reverse_ip(ip)
    if not reverse:
        return []
    hits = []
    for zone, label in zones or DNSBL_ZONES:
        query = f"{reverse}.{zone}"
        try:
            answers = dns.resolver.resolve(query, "A", lifetime=4)
            codes = sorted({str(a) for a in answers})
            reason = _spamhaus_reason(codes[0]) if zone.endswith("spamhaus.org") and codes else "listed"
            hits.append(
                {"zone": zone, "label": label, "listed": True, "codes": codes, "reason": reason}
            )
        except dns.resolver.NXDOMAIN:
            hits.append({"zone": zone, "label": label, "listed": False, "codes": [], "reason": "clean"})
        except Exception as exc:
            hits.append(
                {"zone": zone, "label": label, "listed": None, "codes": [],
                 "reason": f"unavailable ({type(exc).__name__})"}
            )
    return hits


# ---------------------------------------------------------------------------
# Have I Been Pwned
# ---------------------------------------------------------------------------


def _hibp_headers(key: str) -> dict:
    return {"hibp-api-key": key, "User-Agent": "volume-osint"}


def hibp_breaches(email: str, key: str) -> dict:
    return net.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        f"{quote(email, safe='@')}?truncateResponse=false",
        source="hibp",
        headers=_hibp_headers(key),
    )


def hibp_all_breaches(key: str) -> dict:
    return net.get_cached(
        "https://haveibeenpwned.com/api/v3/breaches",
        ttl=3600,
        source="hibp",
        headers=_hibp_headers(key),
    )


def hibp_pastes(email: str, key: str) -> dict:
    return net.get(
        f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email, safe='@')}",
        source="hibp",
        headers=_hibp_headers(key),
    )


def pwned_password(password: str) -> dict:
    """HIBP k-anonymity range query. The full password/hash never leaves the host."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    response = net.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true", "User-Agent": "volume-osint"},
    )
    if not _ok(response):
        return {"ok": False, "count": 0, "error": response.get("error") or "Pwned Passwords unavailable"}
    count = 0
    for line in str(response.get("data") or "").splitlines():
        candidate, _, times = line.partition(":")
        if candidate.strip().upper() == suffix:
            try:
                count = int(times.strip())
            except ValueError:
                count = 0
            break
    return {"ok": True, "count": count, "prefix": prefix}


# ---------------------------------------------------------------------------
# Google Safe Browsing / URLhaus / OpenPhish
# ---------------------------------------------------------------------------


def safe_browsing(url: str, key: str) -> dict:
    payload = {
        "client": {"clientId": "volume-osint", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    response = net.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
        source="default",
        json=payload,
    )
    if not _ok(response):
        return {"ok": False, "error": response.get("error") or "Safe Browsing failed", "matches": []}
    matches = _as_dict(response.get("data")).get("matches") or []
    return {"ok": True, "matches": matches, "error": ""}


def urlhaus_lookup(url: str, key: str = "") -> dict:
    headers = {"Auth-Key": key} if key else {}
    response = net.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        source="urlhaus",
        data={"url": url},
        headers=headers,
    )
    return response


def urlhaus_host(host: str, key: str = "") -> dict:
    headers = {"Auth-Key": key} if key else {}
    return net.post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        source="urlhaus",
        data={"host": host},
        headers=headers,
    )


def openphish_feed() -> set:
    response = net.get_cached("https://openphish.com/feed.txt", ttl=900, source="openphish")
    if not _ok(response):
        return set()
    text = str(response.get("data") or "")
    return {line.strip() for line in text.splitlines() if line.strip().startswith("http")}


def malwarebazaar_hash(file_hash: str, key: str = "") -> dict:
    headers = {"Auth-Key": key} if key else {}
    return net.post(
        "https://mb-api.abuse.ch/api/v1/",
        source="urlhaus",
        data={"query": "get_info", "hash": file_hash},
        headers=headers,
    )


def threatfox_search(ioc: str, key: str = "") -> dict:
    headers = {"Auth-Key": key} if key else {}
    return net.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        source="urlhaus",
        data={"query": "search_ioc", "search_term": ioc},
        headers=headers,
    )


def openphish_check(url: str) -> bool:
    feed = openphish_feed()
    if not feed:
        return False
    normalized = indicators.normalize_url(url).rstrip("/")
    if normalized in {u.rstrip("/") for u in feed}:
        return True
    host = indicators.url_host(url)
    return any((indicators.url_host(u) or "") == host for u in feed) if host else False


# ---------------------------------------------------------------------------
# VirusTotal / AbuseIPDB / GreyNoise
# ---------------------------------------------------------------------------


def _vt_get(path: str, key: str) -> dict:
    return net.get(
        f"https://www.virustotal.com/api/v3/{path}",
        source="virustotal",
        headers={"x-apikey": key},
    )


def vt_file(file_hash: str, key: str) -> dict:
    return _vt_get(f"files/{quote(file_hash, safe='')}", key)


def vt_url(url: str, key: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _vt_get(f"urls/{url_id}", key)


def vt_ip(ip: str, key: str) -> dict:
    return _vt_get(f"ip_addresses/{quote(ip, safe='')}", key)


def vt_domain(domain: str, key: str) -> dict:
    return _vt_get(f"domains/{quote(domain, safe='')}", key)


def abuseipdb(ip: str, key: str) -> dict:
    return net.get(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip, safe='')}&maxAgeInDays=90",
        source="abuseipdb",
        headers={"Key": key, "Accept": "application/json"},
    )


def greynoise(ip: str, key: str = "") -> dict:
    headers = {"key": key} if key else {}
    return net.get(
        f"https://api.greynoise.io/v3/community/{quote(ip, safe='')}",
        source="greynoise",
        headers=headers,
    )


# ---------------------------------------------------------------------------
# NVD / CIRCL / CISA KEV
# ---------------------------------------------------------------------------


def _nvd_headers() -> dict:
    """NVD allows an apiKey header for higher rate limits (optional)."""
    key = config.get_key("nvd") or config.get_key("nvd_api_key")
    return {"apiKey": key} if key else {}


def nvd_cve(cve: str) -> dict:
    return net.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?cveId={quote(cve, safe='')}",
        source="nvd",
        headers=_nvd_headers(),
        timeout=25.0,
    )


def nvd_search(keyword: str, limit: int = 10) -> dict:
    return net.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={quote(keyword, safe='')}&resultsPerPage={int(limit)}",
        source="nvd",
        headers=_nvd_headers(),
        timeout=25.0,
    )


def circl_cve(cve: str) -> dict:
    return net.get(f"https://cve.circl.lu/api/cve/{quote(cve, safe='')}", source="circl")


def cisa_kev() -> dict:
    response = net.get_cached(
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json",
        ttl=6 * 3600,
        source="kev",
        timeout=30.0,
    )
    return _as_dict(_data(response))


def kev_index() -> dict:
    data = cisa_kev()
    out = {}
    for item in _as_list(data.get("vulnerabilities")):
        cve = str(item.get("cveID", "")).upper()
        if cve:
            out[cve] = item
    return out


# ---------------------------------------------------------------------------
# GitHub / Wayback
# ---------------------------------------------------------------------------


def _github_headers() -> dict:
    """GitHub tokens raise the rate limit from 60 to 5000 requests/hour (optional)."""
    token = config.get_key("github") or config.get_key("github_token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def github_user(username: str) -> dict:
    return net.get(
        f"https://api.github.com/users/{quote(username, safe='')}",
        source="github",
        headers=_github_headers(),
    )


def github_repos(username: str, limit: int = 10) -> dict:
    return net.get(
        f"https://api.github.com/users/{quote(username, safe='')}/repos"
        f"?sort=updated&per_page={int(limit)}",
        source="github",
        headers=_github_headers(),
    )


def github_orgs(username: str) -> dict:
    return net.get(
        f"https://api.github.com/users/{quote(username, safe='')}/orgs",
        source="github",
        headers=_github_headers(),
    )


def github_events(username: str) -> dict:
    return net.get(
        f"https://api.github.com/users/{quote(username, safe='')}/events/public"
        "?per_page=30",
        source="github",
        headers=_github_headers(),
    )


def wayback_summary(domain: str, limit: int = 4000) -> dict:
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={quote(domain, safe='')}/*&output=json"
        f"&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit={int(limit)}"
    )
    response = net.get(url, source="wayback", timeout=35.0)
    rows = _data(response)
    if not isinstance(rows, list) or len(rows) < 2:
        return {"ok": False, "count": 0, "error": response.get("error") or "No snapshots"}
    header = rows[0]
    index = {name: i for i, name in enumerate(header)}
    captures = []
    for row in rows[1:]:
        try:
            captures.append(
                {
                    "timestamp": row[index.get("timestamp", 0)],
                    "url": row[index.get("original", 1)],
                    "status": row[index.get("statuscode", 2)],
                    "mime": row[index.get("mimetype", 3)],
                }
            )
        except Exception:
            continue
    return {"ok": True, "count": len(captures), "captures": captures, "error": ""}


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def _grab_cert(host: str, port: int, context: ssl.SSLContext, timeout: float):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            der = tls.getpeercert(binary_form=True)
            return {
                "cert": cert or {},
                "der": der or b"",
                "version": tls.version(),
                "cipher": tls.cipher(),
            }


def tls_certificate(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    host = (host or "").strip().strip(".")
    if not host:
        return {"ok": False, "error": "No host"}
    verified = True
    verify_error = ""
    try:
        data = _grab_cert(host, port, ssl.create_default_context(), timeout)
    except ssl.SSLCertVerificationError as exc:
        verified = False
        verify_error = str(exc)
        try:
            data = _grab_cert(host, port, ssl._create_unverified_context(), timeout)
        except Exception as exc2:
            return {"ok": False, "error": f"{type(exc2).__name__}: {exc2}"}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    cert = data["cert"] or {}
    subject = {k: v for item in cert.get("subject", []) for k, v in item}
    issuer = {k: v for item in cert.get("issuer", []) for k, v in item}
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind in ("DNS", "IP")]
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    days_left = None
    if not_after:
        try:
            expires = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(not_after), tz=datetime.timezone.utc
            )
            days_left = (expires - datetime.datetime.now(datetime.timezone.utc)).days
        except Exception:
            days_left = None
    fingerprint = hashlib.sha256(data["der"]).hexdigest() if data["der"] else ""
    return {
        "ok": True,
        "host": host,
        "port": port,
        "verified": verified,
        "verify_error": verify_error,
        "subject": subject,
        "issuer": issuer,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "serial": cert.get("serialNumber", ""),
        "version": cert.get("version", ""),
        "protocol": data["version"],
        "cipher": data["cipher"],
        "sha256": fingerprint,
        "error": "",
    }


def tls_protocols(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    host = (host or "").strip().strip(".")
    results = {}
    versions = [
        ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for label, version in versions:
        if version is None:
            results[label] = None
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            data = _grab_cert(host, port, context, timeout)
            results[label] = {"supported": True, "cipher": data["cipher"]}
        except Exception:
            results[label] = {"supported": False, "cipher": None}
    return results


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------


def discord_invite(code: str) -> dict:
    return net.get(
        f"https://discord.com/api/v10/invites/{quote(code, safe='')}"
        "?with_counts=true&with_expiration=true",
        source="discord",
    )


def discord_user(user_id: str, token: str = "") -> dict:
    if not token:
        return {}
    return net.get(
        f"https://discord.com/api/v10/users/{quote(str(user_id), safe='')}",
        source="discord",
        headers={"Authorization": f"Bot {token}"},
    )


def snowflake_info(snowflake: str) -> dict:
    try:
        value = int(str(snowflake).strip())
    except (TypeError, ValueError):
        return {}
    if value <= 0:
        return {}
    timestamp_ms = (value >> 22) + 1420070400000
    created = datetime.datetime.fromtimestamp(timestamp_ms / 1000, tz=datetime.timezone.utc)
    age_days = (datetime.datetime.now(datetime.timezone.utc) - created).days
    return {
        "id": str(value),
        "created": created.isoformat(),
        "age_days": age_days,
        "worker": (value & 0x3E0000) >> 17,
        "process": (value & 0x1F000) >> 12,
        "increment": value & 0xFFF,
    }


# ---------------------------------------------------------------------------
# Small shared parsers
# ---------------------------------------------------------------------------


def extract_domain(value: str) -> str:
    value = (value or "").strip()
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    return indicators.normalize_domain(value)


def resolve_host(host: str, rdtype: str = "A", lifetime: float = 4.0) -> list:
    import dns.resolver

    try:
        return [str(a) for a in dns.resolver.resolve(host, rdtype, lifetime=lifetime)]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# MAC vendor / crypto / KEV search
# ---------------------------------------------------------------------------


def mac_vendor(mac: str) -> dict:
    """Look up an OUI vendor. macvendors.com returns plain text."""
    digits = "".join(ch for ch in str(mac or "") if ch in "0123456789abcdefABCDEF")
    if len(digits) < 6:
        return {"status": "error", "error": "MAC is too short"}
    prefix = digits[:6]
    return net.get(f"https://api.macvendors.com/{prefix}", source="default", timeout=12.0)


def blockchair(chain: str, address: str) -> dict:
    """Blockchair address dashboard. chain = bitcoin | ethereum | dogecoin ..."""
    chain = (chain or "bitcoin").strip().lower()
    return net.get(
        f"https://api.blockchair.com/{quote(chain, safe='')}/dashboards/address/"
        f"{quote(address, safe='')}",
        source="default",
        timeout=25.0,
    )


def kev_matches(keyword: str, limit: int = 25) -> list:
    """Search the cached CISA KEV catalogue by vendor/product/name/CVE."""
    needle = (keyword or "").strip().lower()
    if not needle:
        return []
    out = []
    for cve, item in kev_index().items():
        blob = " ".join(
            str(item.get(field) or "")
            for field in (
                "cveID", "vendorProject", "product", "vulnerabilityName",
                "shortDescription", "requiredAction",
            )
        ).lower()
        if needle in blob:
            out.append(item)
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------------------
# IP enrichment
# ---------------------------------------------------------------------------


def ip_api(ip: str) -> dict:
    fields = (
        "status,message,query,country,countryCode,region,regionName,city,zip,"
        "lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,reverse"
    )
    data = _data(net.get(f"http://ip-api.com/json/{quote(ip, safe='')}?fields={fields}", source="ipapi"))
    return _as_dict(data)


def ipinfo(ip: str) -> dict:
    data = _data(net.get(f"https://ipinfo.io/{quote(ip, safe='')}/json", source="ipinfo"))
    return _as_dict(data)


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def ip_geo(ip: str) -> dict:
    """Best-effort combined geo result (ip-api first, ipinfo fallback)."""
    primary = ip_api(ip)
    if primary.get("status") == "success":
        primary["_provider"] = "ip-api.com"
        return primary
    fallback = ipinfo(ip)
    if fallback and not fallback.get("bogon"):
        fallback["_provider"] = "ipinfo.io"
    return fallback


# ---------------------------------------------------------------------------
# Geocoding (OpenStreetMap Nominatim)
# ---------------------------------------------------------------------------


def nominatim_search(query: str, limit: int = 5) -> list:
    response = net.get(
        "https://nominatim.openstreetmap.org/search"
        f"?q={quote(query, safe='')}&format=jsonv2&addressdetails=1&limit={int(limit)}",
        source="nominatim",
        headers={"User-Agent": "volume-osint/3.1"},
    )
    return _as_list(_data(response))


def nominatim_reverse(lat: str, lon: str) -> dict:
    response = net.get(
        "https://nominatim.openstreetmap.org/reverse"
        f"?lat={quote(str(lat), safe='')}&lon={quote(str(lon), safe='')}"
        "&format=jsonv2&addressdetails=1",
        source="nominatim",
        headers={"User-Agent": "volume-osint/3.1"},
    )
    return _as_dict(_data(response))


# ---------------------------------------------------------------------------
# General web search (DuckDuckGo Instant Answer + result links)
# ---------------------------------------------------------------------------


def duckduckgo(query: str) -> dict:
    response = net.get(
        "https://api.duckduckgo.com/"
        f"?q={quote(query, safe='')}&format=json&no_html=1&skip_disambig=1",
        source="duckduckgo",
    )
    return _as_dict(_data(response))


# ---------------------------------------------------------------------------
# Steam / Roblox / Telegram
# ---------------------------------------------------------------------------


def steam_profile(vanity: str) -> dict:
    """Public Steam profile XML works without an API key."""
    vanity = (vanity or "").strip().strip("/")
    if vanity.isdigit():
        url = f"https://steamcommunity.com/profiles/{quote(vanity, safe='')}/?xml=1"
    else:
        url = f"https://steamcommunity.com/id/{quote(vanity, safe='')}/?xml=1"
    response = net.get(url, source="steam", timeout=20.0)
    text = str(response.get("data") or "")
    if response.get("status") != "ok" or "<profile>" not in text:
        return {"ok": False, "error": response.get("error") or "Steam profile not found", "xml": text}
    return {"ok": True, "xml": text, "error": ""}


def roblox_user_by_username(username: str) -> dict:
    response = net.post(
        "https://users.roblox.com/v1/usernames/users",
        source="roblox",
        json={"usernames": [username], "excludeBannedUsers": False},
    )
    data = _as_dict(_data(response))
    users = _as_list(data.get("data"))
    return _as_dict(users[0]) if users else {}


def roblox_user_by_id(user_id: str) -> dict:
    return _as_dict(_data(net.get(
        f"https://users.roblox.com/v1/users/{quote(str(user_id), safe='')}",
        source="roblox",
    )))


def roblox_search(keyword: str, limit: int = 10) -> list:
    data = _as_dict(_data(net.get(
        "https://users.roblox.com/v1/users/search"
        f"?keyword={quote(keyword, safe='')}&limit={int(limit)}",
        source="roblox",
    )))
    return _as_list(data.get("data"))


def telegram_preview(username: str) -> dict:
    username = (username or "").strip().lstrip("@").strip("/")
    response = net.get(f"https://t.me/s/{quote(username, safe='')}", source="telegram", timeout=20.0)
    return {
        "ok": response.get("status") == "ok",
        "status": response.get("status"),
        "html": str(response.get("data") or ""),
        "error": response.get("error") or "",
    }


# ---------------------------------------------------------------------------
# Leak / breach sources
# ---------------------------------------------------------------------------


def hibp_breaches_public() -> dict:
    """The full HIBP breach catalogue is public (no API key required)."""
    return net.get_cached(
        "https://haveibeenpwned.com/api/v3/breaches",
        ttl=3600,
        source="hibp",
        headers={"User-Agent": "volume-osint/3.1"},
    )


def leakix_domain(domain: str, key: str = "") -> dict:
    headers = {"api-key": key, "Accept": "application/json"} if key else {"Accept": "application/json"}
    return net.get(
        f"https://leakix.net/api/domain/{quote(domain, safe='')}",
        source="leakix",
        headers=headers,
    )


def leakix_search(scope: str, query: str, key: str = "") -> dict:
    headers = {"api-key": key, "Accept": "application/json"} if key else {"Accept": "application/json"}
    return net.get(
        f"https://leakix.net/api/search/{quote(scope, safe='')}/{quote(query, safe='')}",
        source="leakix",
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Gravatar / Email reputation
# ---------------------------------------------------------------------------


def gravatar_profile(email: str) -> dict:
    digest = hashlib.md5((email or "").strip().lower().encode("utf-8")).hexdigest()
    response = net.get(f"https://www.gravatar.com/{digest}.json", source="gravatar")
    return _as_dict(_data(response))


def emailrep(email: str, key: str = "") -> dict:
    headers = {"Key": key} if key else {}
    response = net.get(
        f"https://emailrep.io/{quote(email, safe='')}",
        source="emailrep",
        headers=headers,
    )
    return _as_dict(_data(response))


# ---------------------------------------------------------------------------
# Key-gated / self-hosted connectors
# ---------------------------------------------------------------------------


def _connector_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def nazapi_search(query: str, key: str, base: str = "", kind: str = "search") -> dict:
    base = (base or "https://api.nazapi.local").strip()
    response = net.get(
        _connector_url(base, kind),
        source="nazapi",
        headers={"Authorization": f"Bearer {key}", "X-API-Key": key},
        params={"q": query},
    )
    return response


def kitty_search(query: str, key: str, base: str = "", kind: str = "search") -> dict:
    base = (base or "https://api.kittydb.local").strip()
    response = net.get(
        _connector_url(base, kind),
        source="kitty",
        headers={"Authorization": f"Bearer {key}", "X-API-Key": key},
        params={"q": query},
    )
    return response


def stealer_search(query: str, key: str, base: str = "", kind: str = "search") -> dict:
    base = (base or "https://api.stealerlogs.local").strip()
    response = net.get(
        _connector_url(base, kind),
        source="stealer",
        headers={"Authorization": f"Bearer {key}", "X-API-Key": key},
        params={"q": query},
    )
    return response


def xbox_lookup(gamertag: str, key: str, base: str = "https://xapi.us/v2") -> dict:
    response = net.get(
        f"{base.rstrip('/')}/{quote(gamertag, safe='')}/profile",
        source="xbox",
        headers={"X-Auth": key},
    )
    return response


def ghunt_lookup(email: str, key: str, base: str = "") -> dict:
    """Query a self-hosted GHunt-compatible endpoint, never a bundled cookie."""
    base = (base or "https://api.ghunt.local").strip()
    response = net.post(
        _connector_url(base, "search"),
        source="ghunt",
        headers={"Authorization": f"Bearer {key}", "X-API-Key": key},
        json={"email": email},
    )
    return response


def dvla_vehicle(plate: str, key: str) -> dict:
    return net.post(
        "https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles",
        source="dvla",
        headers={"x-api-key": key, "Content-Type": "application/json"},
        json={"registrationNumber": plate},
    )


# ---------------------------------------------------------------------------
# CNAME / DNS chains
# ---------------------------------------------------------------------------


def cname_chain(host: str, max_depth: int = 10) -> list:
    """Follow a CNAME chain, returning (host, target) pairs."""
    import dns.resolver

    chain = []
    current = (host or "").strip().strip(".").lower()
    seen = set()
    for _ in range(max_depth):
        if not current or current in seen:
            break
        seen.add(current)
        try:
            answers = dns.resolver.resolve(current, "CNAME", lifetime=5)
            target = str(answers[0]).strip(".").lower()
        except Exception:
            break
        chain.append((current, target))
        current = target
    return chain

