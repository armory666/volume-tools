"""Lookup-category modules: identity, email, phone, IP, domains and accounts."""

import datetime
import getpass
import os
import platform
import re
import socket
import time
from pathlib import Path
from urllib.parse import quote

import dns.resolver

from volume.core import config, indicators, sources
from volume.core.module_base import BaseModule


DISPOSABLE = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "sharklasers.com",
    "getnada.com", "dispostable.com", "trashmail.com", "fakeinbox.com",
    "maildrop.cc", "mintemail.com", "mytemp.email", "spamgourmet.com",
}


def _dns(domain, rdtype, lifetime=5.0):
    try:
        return [str(r) for r in dns.resolver.resolve(domain, rdtype, lifetime=lifetime)]
    except Exception:
        return []


class LiveEmailIntel(BaseModule):
    @property
    def id(self):
        return "live_email_intel"

    @property
    def label(self):
        return "Live Email Intel"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Live MX, SPF/DMARC, Gravatar, reputation and breach checks for an email"

    @property
    def order(self):
        return 10

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["email"]

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip().lower()
        if not indicators.is_email(email):
            return self.result(
                rows=[("Error", f"Not a valid email: {email or '-'}")], status="error"
            )
        local, _, domain = email.partition("@")
        mx = _dns(domain, "MX")
        txt = _dns(domain, "TXT")
        dmarc = _dns(f"_dmarc.{domain}", "TXT")
        spf = next((t for t in txt if "v=spf1" in t.lower()), "")
        dmarc_record = next((t for t in dmarc if "v=dmarc1" in t.lower()), "")
        gravatar = sources.gravatar_profile(email)
        reputation = sources.emailrep(email, config.get_key("emailrep"))

        rows = [
            ("Email", email),
            ("Local part", local),
            ("Domain", domain),
            ("Syntax", "valid"),
            ("Disposable", "yes" if domain in DISPOSABLE else "no"),
            ("MX", ", ".join(mx) or "none"),
            ("SPF", spf[:220] if spf else "missing"),
            ("DMARC", dmarc_record[:220] if dmarc_record else "missing"),
        ]
        if gravatar:
            entry = (gravatar.get("entry") or [{}])[0] if isinstance(gravatar.get("entry"), list) else {}
            rows.append(("Gravatar", entry.get("displayName") or "profile exists"))
            rows.append(("Gravatar URL", f"https://www.gravatar.com/{entry.get('hash', '')}"))
        else:
            rows.append(("Gravatar", "no profile"))
        if reputation:
            rows.append(("EmailRep", f"{reputation.get('reputation', '?')} · suspicious={reputation.get('suspicious', '?')}"))
            if reputation.get("profiles"):
                rows.append(("Profiles", ", ".join(map(str, reputation.get("profiles") or []))[:300]))
        else:
            rows.append(("EmailRep", "no data (set EMAILREP_API_KEY for higher limits)"))

        hibp_key = config.get_key("hibp")
        if hibp_key:
            breaches = sources.hibp_breaches(email, hibp_key)
            data = breaches.get("data")
            if isinstance(data, list):
                rows.append(("Breaches", str(len(data))))
                for breach in data[:8]:
                    rows.append((
                        breach.get("Name", "breach"),
                        f"{breach.get('BreachDate', '?')} · {', '.join((breach.get('DataClasses') or [])[:5])}",
                    ))
            elif breaches.get("status") == "not_found":
                rows.append(("Breaches", "none found"))
            else:
                rows.append(("Breaches", f"unavailable ({breaches.get('error') or breaches.get('status')})"))
        else:
            rows.append(("Breaches", "set HIBP_API_KEY for breach checks"))

        status = "ok" if mx else "not_found"
        return self.result(
            title=f"Live Email Intel: {email}",
            source="DNS + Gravatar + EmailRep + HIBP",
            confidence="high" if mx else "low",
            status=status,
            rows=rows,
            email=email,
        )

    def pivots(self, result):
        return [("email", result.get("email"))] if result.get("email") else []


class LivePhoneIntel(BaseModule):
    @property
    def id(self):
        return "live_phone_intel"

    @property
    def label(self):
        return "Live Phone Intel"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Carrier, region, line type and live validation for a phone number"

    @property
    def order(self):
        return 20

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
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone

        raw = (kwargs.get("phone") or "").strip()
        region = (kwargs.get("region") or "US").strip().upper()
        try:
            number = phonenumbers.parse(raw, None if raw.startswith("+") else region)
        except Exception as exc:
            return self.result(rows=[("Error", f"Could not parse number: {exc}")], status="error")

        valid = phonenumbers.is_valid_number(number)
        possible = phonenumbers.is_possible_number(number)
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
        e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
        rows = [
            ("Input", raw),
            ("E.164", e164),
            ("International", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)),
            ("National", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)),
            ("Country", phonenumbers.region_code_for_number(number) or "-"),
            ("Valid", "yes" if valid else "no"),
            ("Possible", "yes" if possible else "no"),
            ("Type", type_names.get(phonenumbers.number_type(number), "unknown")),
            ("Carrier", carrier.name_for_number(number, "en") or "-"),
            ("Location", geocoder.description_for_number(number, "en") or "-"),
            ("Timezone", ", ".join(timezone.time_zones_for_number(number)) or "-"),
        ]

        numverify_key = config.get_key("numverify")
        if numverify_key:
            response = sources.net.get(
                "http://apilayer.net/api/validate",
                source="default",
                params={"access_key": numverify_key, "number": e164, "format": 1},
            )
            data = response.get("data") if response.get("status") == "ok" else None
            if isinstance(data, dict):
                rows.extend([
                    ("Live valid", str(data.get("valid"))),
                    ("Live carrier", data.get("carrier") or "-"),
                    ("Line type", data.get("line_type") or "-"),
                    ("Live location", data.get("location") or "-"),
                ])
            else:
                rows.append(("Live validation", f"unavailable ({response.get('error') or response.get('status')})"))
        else:
            rows.append(("Live validation", "set NUMVERIFY_API_KEY for carrier/line validation"))

        return self.result(
            title=f"Live Phone Intel: {e164}",
            source="phonenumbers" + (" + numverify" if numverify_key else ""),
            confidence="high" if valid else "low",
            rows=rows,
            phone=e164,
        )

    def pivots(self, result):
        return [("phone", result.get("phone"))] if result.get("phone") else []


class LiveUsernameIntel(BaseModule):
    @property
    def id(self):
        return "live_username_intel"

    @property
    def label(self):
        return "Live Username Intel"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Live profile sweep across developer, social, gaming and creator sites"

    @property
    def order(self):
        return 30

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["username"]

    def _sites(self, username):
        q = quote(username, safe="")
        return [
            ("GitHub", f"https://api.github.com/users/{q}", "json"),
            ("GitLab", f"https://gitlab.com/api/v4/users?username={q}", "list"),
            ("Reddit", f"https://www.reddit.com/user/{q}/about.json", "json"),
            ("Keybase", f"https://keybase.io/_/api/1.0/user/lookup.json?username={q}", "json"),
            ("Codeberg", f"https://codeberg.org/api/v1/users/{q}", "json"),
            ("Bitbucket", f"https://api.bitbucket.org/2.0/users/{q}", "json"),
            ("Docker Hub", f"https://hub.docker.com/v2/users/{q}/", "json"),
            ("PyPI", f"https://pypi.org/user/{q}/", "html"),
            ("npm", f"https://registry.npmjs.org/-/user/org.couchdb.user:{q}", "json"),
            ("Hacker News", f"https://hacker-news.firebaseio.com/v0/user/{q}.json", "json"),
            ("Lichess", f"https://lichess.org/api/user/{q}", "json"),
            ("Chess.com", f"https://api.chess.com/pub/player/{q}", "json"),
            ("Steam", f"https://steamcommunity.com/id/{q}?xml=1", "xml"),
            ("Twitch", f"https://www.twitch.tv/{q}", "html"),
            ("Kaggle", f"https://www.kaggle.com/{q}", "html"),
            ("HackerOne", f"https://hackerone.com/{q}", "html"),
        ]

    def _found(self, site, kind, response):
        if response.get("status") == "not_found":
            return False
        if response.get("status") != "ok":
            return None
        data = response.get("data")
        if kind == "list":
            return isinstance(data, list) and bool(data)
        if kind == "xml":
            return "<steamID64>" in str(data)
        if kind == "html":
            body = str(data)
            if "Page not found" in body or "404 Not Found" in body[:400]:
                return False
            if site == "Twitch":
                return "channel-info" in body or "og:title" in body
            if site == "Kaggle":
                return "profile" in body.lower() and "not found" not in body.lower()[:500]
            if site == "HackerOne":
                return "hackerone.com" in body.lower() and "not found" not in body.lower()[:500]
            return None
        if kind == "json":
            if data is None:
                return False
            if site == "Keybase":
                them = (data or {}).get("them") if isinstance(data, dict) else None
                return isinstance(them, list) and bool(them)
            if site == "Hacker News":
                return data is not None
            if isinstance(data, dict) and data.get("message") == "Not Found":
                return False
            return bool(data)
        return None

    def run(self, case, **kwargs):
        username = (kwargs.get("username") or "").strip().lstrip("@")
        if not username:
            return self.result(rows=[("Error", "No username provided")], status="error")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
            return self.result(
                rows=[("Error", "Username may only contain letters, numbers, dot, dash, underscore")],
                status="error",
            )

        rows = [("Username", username)]
        found = []
        for site, url, kind in self._sites(username):
            response = sources.net.get(url)
            state = self._found(site, kind, response)
            if state is True:
                found.append(site)
                rows.append((site, f"FOUND  {url}"))
            elif state is False:
                rows.append((site, "not found"))
            else:
                rows.append((site, f"unknown ({str(response.get('error') or response.get('status'))[:50]})"))

        roblox = sources.roblox_user_by_username(username)
        if roblox:
            found.append("Roblox")
            rows.append(("Roblox", f"FOUND  https://www.roblox.com/users/{roblox.get('id')}/profile"))
        else:
            rows.append(("Roblox", "not found"))

        return self.result(
            title=f"Live Username Intel: {username}",
            source="public profile checks",
            confidence="medium",
            rows=rows[:2] + [("Found", f"{len(found)}/{len(rows) - 2}")] + rows[2:],
            found=found,
            username=username,
        )

    def pivots(self, result):
        return [("username", result.get("username"))] if result.get("username") else []


class DomainSearch(BaseModule):
    @property
    def id(self):
        return "domain_search"

    @property
    def label(self):
        return "Domain Search"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "RDAP registration, DNS records, nameservers and certificate-transparency subdomains"

    @property
    def order(self):
        return 40

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["domain"]

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")

        rdap_response = sources.rdap_domain(domain)
        rdap = sources.rdap_summary(rdap_response.get("data") or {}) if rdap_response.get("status") == "ok" else {}
        a = _dns(domain, "A")
        aaaa = _dns(domain, "AAAA")
        mx = _dns(domain, "MX")
        ns = _dns(domain, "NS")
        txt = _dns(domain, "TXT")
        subs = sources.subdomains_from_crt(domain)

        rows = [
            ("Domain", domain),
            ("A", ", ".join(a) or "-"),
            ("AAAA", ", ".join(aaaa) or "-"),
            ("MX", ", ".join(mx) or "-"),
            ("NS", ", ".join(ns) or "-"),
            ("TXT", " | ".join(t[:180] for t in txt) or "-"),
            ("Registrar", rdap.get("registrar") or "-"),
            ("Created", rdap.get("created") or "-"),
            ("Expires", rdap.get("expires") or "-"),
            ("Updated", rdap.get("updated") or "-"),
            ("Status", ", ".join(rdap.get("status") or []) or "-"),
            ("Nameservers", ", ".join(rdap.get("nameservers") or []) or ", ".join(ns) or "-"),
            ("Subdomains (CT)", str(len(subs))),
        ]
        for name in subs[:40]:
            rows.append(("Subdomain", name))
        if not (a or aaaa or mx or ns):
            rows.append(("Warning", "No DNS records returned; domain may not exist."))

        return self.result(
            title=f"Domain Search: {domain}",
            source="RDAP + DNS + crt.sh",
            confidence="high" if (a or aaaa) else "low",
            rows=rows,
            domain=domain,
        )

    def pivots(self, result):
        return [("domain", result.get("domain"))] if result.get("domain") else []


class IPLookupLive(BaseModule):
    @property
    def id(self):
        return "ip_lookup_live"

    @property
    def label(self):
        return "IP Lookup"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Live geolocation, ASN, reverse DNS, open ports and reputation for an IP"

    @property
    def order(self):
        return 50

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
        bgp = sources.bgpview_ip(ip)
        asn = (bgp.get("asn") or {}) if isinstance(bgp, dict) else {}

        rows = [
            ("IP", ip),
            ("Reverse DNS", reverse or "-"),
            ("Country", geo.get("country") or geo.get("country_name") or "-"),
            ("Region", geo.get("regionName") or geo.get("region") or "-"),
            ("City", geo.get("city") or "-"),
            ("Coordinates", f"{geo.get('lat')}, {geo.get('lon')}" if geo.get("lat") else geo.get("loc") or "-"),
            ("ISP", geo.get("isp") or geo.get("org") or "-"),
            ("Organisation", geo.get("org") or geo.get("asn") or "-"),
            ("ASN", geo.get("as") or (f"AS{asn.get('asn')} {asn.get('name', '')}" if asn else "-")),
            ("Timezone", geo.get("timezone") or "-"),
            ("Proxy / hosting", f"proxy={geo.get('proxy', '?')} hosting={geo.get('hosting', '?')}"),
            ("Open ports", ", ".join(map(str, internetdb.get("ports") or [])) or "-"),
            ("Hostnames", ", ".join(map(str, internetdb.get("hostnames") or [])) or "-"),
            ("CVEs", ", ".join(map(str, internetdb.get("vulns") or [])) or "-"),
            ("Tags", ", ".join(map(str, internetdb.get("tags") or [])) or "-"),
            ("Provider", geo.get("_provider") or "-"),
        ]
        return self.result(
            title=f"IP Lookup: {ip}",
            source="ip-api + InternetDB + BGPView",
            confidence="high" if geo else "low",
            rows=rows,
            ip=ip,
        )

    def pivots(self, result):
        return [("ip", result.get("ip"))] if result.get("ip") else []


class MachineViewer(BaseModule):
    @property
    def id(self):
        return "machine_viewer"

    @property
    def label(self):
        return "Machine Viewer"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Local machine profile: OS, CPU, RAM, disks, network and uptime"

    @property
    def order(self):
        return 60

    @property
    def credit_cost(self):
        return 0

    @property
    def inputs(self):
        return []

    def run(self, case, **kwargs):
        import psutil

        rows = [
            ("Hostname", socket.gethostname()),
            ("User", getpass.getuser()),
            ("Platform", platform.platform()),
            ("System", f"{platform.system()} {platform.release()}"),
            ("Machine", platform.machine()),
            ("Processor", platform.processor() or "-"),
            ("Python", platform.python_version()),
            ("MAC", f"{':'.join(f'{b:02x}' for b in __import__('uuid').getnode().to_bytes(6, 'big'))}"),
        ]
        try:
            rows.append(("CPU cores", str(psutil.cpu_count(logical=True))))
            rows.append(("CPU load", f"{psutil.cpu_percent(interval=0.3):.0f}%"))
            memory = psutil.virtual_memory()
            rows.append(("RAM", f"{memory.used / 2**30:.1f} / {memory.total / 2**30:.1f} GB ({memory.percent:.0f}%)"))
            boot = datetime.datetime.fromtimestamp(psutil.boot_time())
            rows.append(("Booted", boot.isoformat(timespec="seconds")))
            rows.append(("Uptime", str(datetime.datetime.now() - boot).split(".")[0]))
            for name, usage in psutil.disk_partitions(all=False)[:6]:
                try:
                    disk = psutil.disk_usage(name)
                    rows.append((f"Disk {name}", f"{disk.used / 2**30:.1f} / {disk.total / 2**30:.1f} GB ({disk.percent:.0f}%)"))
                except Exception:
                    continue
        except Exception:
            pass

        try:
            for name, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if getattr(addr, "family", None) == socket.AF_INET and not addr.address.startswith("127."):
                        rows.append((f"IPv4 {name}", addr.address))
        except Exception:
            pass

        public = sources.net.get("https://api.ipify.org?format=json", source="default")
        if public.get("status") == "ok" and isinstance(public.get("data"), dict):
            rows.append(("Public IP", public["data"].get("ip") or "-"))

        return self.result(
            title="Machine Viewer",
            source="local system",
            confidence="high",
            rows=rows,
        )


class GeneralSearch(BaseModule):
    @property
    def id(self):
        return "general_search"

    @property
    def label(self):
        return "General Search"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Instant answers and direct search-engine pivots for any query"

    @property
    def order(self):
        return 70

    @property
    def credit_cost(self):
        return 0

    @property
    def inputs(self):
        return ["query"]

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip()
        if not query:
            return self.result(rows=[("Error", "No query provided")], status="error")

        data = sources.duckduckgo(query)
        rows = [("Query", query)]
        if data.get("AbstractText"):
            rows.append(("Abstract", data["AbstractText"][:600]))
            if data.get("AbstractURL"):
                rows.append(("Source", data["AbstractURL"]))
        if data.get("Answer"):
            rows.append(("Answer", str(data["Answer"])[:400]))
        if data.get("Definition"):
            rows.append(("Definition", str(data["Definition"])[:400]))
        related = data.get("RelatedTopics") or []
        count = 0
        for item in related:
            if isinstance(item, dict) and item.get("Text") and item.get("FirstURL"):
                rows.append(("Related", f"{item['Text'][:140]} — {item['FirstURL']}"))
                count += 1
                if count >= 10:
                    break
        if count == 0:
            rows.append(("Related", "No instant-answer topics."))
        rows.extend([
            ("Google", f"https://www.google.com/search?q={quote(query)}"),
            ("Bing", f"https://www.bing.com/search?q={quote(query)}"),
            ("DuckDuckGo", f"https://duckduckgo.com/?q={quote(query)}"),
            ("Yandex", f"https://yandex.com/search/?text={quote(query)}"),
            ("GitHub", f"https://github.com/search?q={quote(query)}"),
            ("Reddit", f"https://www.reddit.com/search/?q={quote(query)}"),
        ])
        return self.result(
            title=f"General Search: {query}",
            source="DuckDuckGo Instant Answer",
            confidence="medium",
            rows=rows,
        )


class FileSearch(BaseModule):
    @property
    def id(self):
        return "file_search"

    @property
    def label(self):
        return "File Search"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Search local file names (and optionally contents) under a chosen folder"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 80

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["pattern"]

    @property
    def optional_inputs(self):
        return {"path": str(Path.home()), "contents": "no"}

    def run(self, case, **kwargs):
        pattern = (kwargs.get("pattern") or "").strip()
        root = (kwargs.get("path") or str(Path.home())).strip()
        contents = str(kwargs.get("contents") or "no").strip().lower() in ("yes", "y", "true", "1")
        if not pattern:
            return self.result(rows=[("Error", "No file pattern provided")], status="error")
        base = Path(root).expanduser()
        if not base.exists() or not base.is_dir():
            return self.result(rows=[("Error", f"Folder not found: {base}")], status="error")

        needle = pattern.lower()
        rows = [("Pattern", pattern), ("Root", str(base)), ("Content search", "yes" if contents else "no")]
        matches = []
        try:
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in {
                    "node_modules", "__pycache__", "AppData", "Windows", "Program Files",
                }][:40]
                if len(matches) >= 60:
                    break
                for filename in filenames:
                    if needle in filename.lower():
                        matches.append(Path(dirpath) / filename)
                    elif contents:
                        path = Path(dirpath) / filename
                        try:
                            if path.stat().st_size > 2_000_000:
                                continue
                            if needle in path.read_text(encoding="utf-8", errors="ignore").lower():
                                matches.append(path)
                        except Exception:
                            continue
                    if len(matches) >= 60:
                        break
        except Exception as exc:
            rows.append(("Warning", f"Search stopped: {exc}"))

        rows.append(("Matches", str(len(matches))))
        for path in matches[:60]:
            try:
                stat = path.stat()
                rows.append((
                    path.name,
                    f"{path}  ·  {stat.st_size / 1024:.1f} KB  ·  "
                    f"{datetime.datetime.fromtimestamp(stat.st_mtime):%Y-%m-%d %H:%M}",
                ))
            except Exception:
                rows.append((path.name, str(path)))
        if not matches:
            rows.append(("Result", "No matching files."))
        return self.result(
            title=f"File Search: {pattern}",
            source="local filesystem",
            confidence="high",
            rows=rows,
        )


class SteamProfile(BaseModule):
    @property
    def id(self):
        return "steam_profile"

    @property
    def label(self):
        return "Steam Profile"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Public Steam profile, vanity URL, creation date, status and VAC bans"

    @property
    def order(self):
        return 90

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["vanity"]

    @property
    def input_prompts(self):
        return {"vanity": "Steam vanity name or 17-digit SteamID64"}

    def run(self, case, **kwargs):
        vanity = (kwargs.get("vanity") or "").strip()
        if not vanity:
            return self.result(rows=[("Error", "No Steam vanity/ID provided")], status="error")
        result = sources.steam_profile(vanity)
        if not result.get("ok"):
            return self.result(
                title=f"Steam Profile: {vanity}",
                source="Steam Community",
                status="not_found",
                rows=[("Steam", vanity), ("Result", result.get("error") or "Profile not found")],
            )
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(result["xml"])
        except Exception as exc:
            return self.result(rows=[("Error", f"Could not parse Steam XML: {exc}")], status="error")
        fields = [
            ("SteamID64", "steamID64"), ("SteamID", "steamID"), ("Persona", "steamID"),
            ("Real name", "realname"), ("Summary", "summary"), ("Location", "location"),
            ("Status", "onlineState"), ("State message", "stateMessage"), ("Created", "memberSince"),
            ("Friends", "friendsCount"), ("VAC bans", "vacBanned"), ("Trade ban", "tradeBanState"),
            ("Limited account", "isLimitedAccount"), ("Profile URL", "customURL"),
        ]
        rows = []
        for label, tag in fields:
            node = root.find(tag)
            if node is not None and node.text:
                value = node.text.strip()
                if tag == "customURL":
                    value = f"https://steamcommunity.com/id/{value}"
                rows.append((label, value))
        steam_id = root.findtext("steamID64") or vanity
        if not any(label == "Profile URL" for label, _ in rows):
            rows.append(("Profile URL", f"https://steamcommunity.com/profiles/{steam_id}"))
        return self.result(
            title=f"Steam Profile: {root.findtext('steamID') or vanity}",
            source="Steam Community XML",
            confidence="high",
            rows=rows,
            steam_id=steam_id,
        )

    def pivots(self, result):
        return [("steam", result.get("steam_id"))] if result.get("steam_id") else []


class SubdomainSearch(BaseModule):
    @property
    def id(self):
        return "subdomains"

    @property
    def label(self):
        return "Subdomain Search"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Certificate-transparency and DNS subdomain discovery"

    @property
    def order(self):
        return 100

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["domain"]

    def run(self, case, **kwargs):
        domain = indicators.normalize_domain(kwargs.get("domain"))
        if not indicators.is_domain(domain):
            return self.result(rows=[("Error", f"Not a valid domain: {domain or '-'}")], status="error")
        names = sources.subdomains_from_crt(domain)
        rows = [("Domain", domain), ("Subdomains", str(len(names)))]
        resolved = 0
        for name in names[:80]:
            addresses = _dns(name, "A", lifetime=3)
            if addresses:
                resolved += 1
            rows.append((name, ", ".join(addresses) or "no A record"))
        rows.insert(2, ("Resolving", str(resolved)))
        if not names:
            rows.append(("Result", "No subdomains found in certificate transparency."))
        return self.result(
            title=f"Subdomains: {domain}",
            source="crt.sh + DNS",
            confidence="medium",
            rows=rows,
            domain=domain,
            subdomains=names,
        )

    def pivots(self, result):
        return [("domain", name) for name in (result.get("subdomains") or [])[:50]]


class CNAMELookup(BaseModule):
    @property
    def id(self):
        return "cname_lookup"

    @property
    def label(self):
        return "CNAME Lookup"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Follow a CNAME chain, resolve the final target and flag dangling records"

    @property
    def order(self):
        return 110

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["host"]

    def run(self, case, **kwargs):
        host = (kwargs.get("host") or "").strip().strip(".").lower()
        if not host:
            return self.result(rows=[("Error", "No host provided")], status="error")
        chain = sources.cname_chain(host)
        final = chain[-1][1] if chain else host
        a = _dns(final, "A")
        aaaa = _dns(final, "AAAA")
        rows = [("Host", host), ("CNAME hops", str(len(chain)))]
        for index, (source, target) in enumerate(chain, 1):
            rows.append((f"Hop {index}", f"{source} → {target}"))
        rows.extend([
            ("Final target", final),
            ("A", ", ".join(a) or "-"),
            ("AAAA", ", ".join(aaaa) or "-"),
        ])
        if chain and not (a or aaaa):
            rows.append(("Warning", "CNAME chain does not resolve. Possible dangling record / takeover."))
        if not chain:
            rows.append(("Result", "No CNAME record; host is not aliased."))
        return self.result(
            title=f"CNAME Lookup: {host}",
            source="DNS",
            confidence="high" if chain else "low",
            rows=rows,
            host=host,
        )

    def pivots(self, result):
        return [("domain", result.get("host"))] if result.get("host") else []


class EmailIntelligence(BaseModule):
    @property
    def id(self):
        return "email_intelligence"

    @property
    def label(self):
        return "Email Intelligence"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Deep email OSINT: mail security, gravatar, reputation, breaches and role accounts"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 120

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["email"]

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip().lower()
        if not indicators.is_email(email):
            return self.result(rows=[("Error", f"Not a valid email: {email or '-'}")], status="error")
        local, _, domain = email.partition("@")
        mx = _dns(domain, "MX")
        txt = _dns(domain, "TXT")
        dmarc = _dns(f"_dmarc.{domain}", "TXT")
        selectors = ["default", "google", "selector1", "selector2", "k1", "mail"]
        dkim = []
        for selector in selectors:
            records = _dns(f"{selector}._domainkey.{domain}", "TXT")
            if records:
                dkim.append(selector)
        role_accounts = {
            "admin", "administrator", "support", "info", "sales", "contact", "billing",
            "security", "abuse", "postmaster", "webmaster", "noreply", "no-reply",
        }
        gravatar = sources.gravatar_profile(email)
        reputation = sources.emailrep(email, config.get_key("emailrep"))
        rows = [
            ("Email", email),
            ("Domain", domain),
            ("Local part", local),
            ("Role account", "yes" if local in role_accounts else "no"),
            ("Disposable", "yes" if domain in DISPOSABLE else "no"),
            ("MX", ", ".join(mx) or "none"),
            ("SPF", next((t for t in txt if "v=spf1" in t.lower()), "missing")[:240]),
            ("DMARC", next((t for t in dmarc if "v=dmarc1" in t.lower()), "missing")[:240]),
            ("DKIM selectors", ", ".join(dkim) or "not found"),
            ("Gravatar", "profile exists" if gravatar else "no profile"),
            ("EmailRep reputation", str((reputation or {}).get("reputation", "n/a"))),
        ]
        hibp_key = config.get_key("hibp")
        if hibp_key:
            breaches = sources.hibp_breaches(email, hibp_key)
            data = breaches.get("data")
            if isinstance(data, list):
                rows.append(("Breaches", str(len(data))))
                for breach in data[:12]:
                    rows.append((breach.get("Name", "breach"), f"{breach.get('BreachDate', '?')} · {', '.join((breach.get('DataClasses') or [])[:6])}"))
            elif breaches.get("status") == "not_found":
                rows.append(("Breaches", "none found"))
            else:
                rows.append(("Breaches", f"unavailable ({breaches.get('error') or breaches.get('status')})"))
        else:
            rows.append(("Breaches", "set HIBP_API_KEY for breach checks"))
        return self.result(
            title=f"Email Intelligence: {email}",
            source="DNS + Gravatar + EmailRep + HIBP",
            confidence="high" if mx else "low",
            rows=rows,
            email=email,
        )

    def pivots(self, result):
        return [("email", result.get("email"))] if result.get("email") else []


class Holehe(BaseModule):
    @property
    def id(self):
        return "holehe"

    @property
    def label(self):
        return "Holehe (Email Registrations)"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Check where an email is registered using public endpoints and an optional self-hosted holehe API"

    @property
    def min_tier(self):
        return "PREMIUM"

    @property
    def order(self):
        return 130

    @property
    def credit_cost(self):
        return 2

    @property
    def inputs(self):
        return ["email"]

    def _local_checks(self, email, local):
        q = quote(local, safe="")
        checks = [
            ("GitHub", f"https://api.github.com/users/{q}", "json"),
            ("Reddit", f"https://www.reddit.com/user/{q}/about.json", "json"),
            ("Keybase", f"https://keybase.io/_/api/1.0/user/lookup.json?username={q}", "json"),
            ("Pinterest", f"https://www.pinterest.com/{q}/", "html"),
            ("Tumblr", f"https://{q}.tumblr.com/", "html"),
            ("Steam", f"https://steamcommunity.com/id/{q}?xml=1", "xml"),
        ]
        rows = []
        for site, url, kind in checks:
            response = sources.net.get(url)
            if response.get("status") == "not_found":
                rows.append((site, "not registered"))
            elif response.get("status") != "ok":
                rows.append((site, f"unknown ({response.get('error') or response.get('status')})"))
            else:
                data = response.get("data")
                if kind == "json":
                    found = bool(data) and not (isinstance(data, dict) and data.get("message") == "Not Found")
                elif kind == "xml":
                    found = "<steamID64>" in str(data)
                else:
                    found = "not found" not in str(data).lower()[:500]
                rows.append((site, "registered" if found else "not registered"))
        return rows

    def run(self, case, **kwargs):
        email = (kwargs.get("email") or "").strip().lower()
        if not indicators.is_email(email):
            return self.result(rows=[("Error", f"Not a valid email: {email or '-'}")], status="error")
        local = email.split("@", 1)[0]

        api_key = config.get_key("holehe")
        api_url = config.get_key("holehe_url")
        if api_key and api_url:
            response = sources.net.post(
                api_url.rstrip("/") + "/check",
                source="holehe",
                headers={"Authorization": f"Bearer {api_key}", "X-API-Key": api_key},
                json={"email": email},
            )
            if response.get("status") == "ok":
                data = response.get("data") or {}
                rows = [("Email", email), ("Source", "self-hosted holehe API")]
                if isinstance(data, dict):
                    for site, state in data.items():
                        rows.append((str(site), "registered" if state else "not registered"))
                else:
                    rows.append(("Result", str(data)[:500]))
                return self.result(
                    title=f"Holehe: {email}",
                    source="self-hosted holehe",
                    confidence="high",
                    rows=rows,
                    email=email,
                )
            rows = [("Email", email), ("API", f"unavailable ({response.get('error') or response.get('status')})")]

        rows = [("Email", email), ("Mode", "local public-endpoint checks")]
        rows.extend(self._local_checks(email, local))
        rows.append(("Note", "For full holehe coverage, configure HOLEHE_API_URL and HOLEHE_API_KEY."))
        return self.result(
            title=f"Holehe: {email}",
            source="local registration probes",
            confidence="medium",
            rows=rows,
            email=email,
        )

    def pivots(self, result):
        return [("email", result.get("email"))] if result.get("email") else []


class TelegramSearch(BaseModule):
    @property
    def id(self):
        return "telegram_search"

    @property
    def label(self):
        return "Telegram Search"

    @property
    def category(self):
        return "LOOKUP"

    @property
    def description(self):
        return "Public Telegram channel preview and optional Bot API chat lookup"

    @property
    def order(self):
        return 140

    @property
    def credit_cost(self):
        return 1

    @property
    def inputs(self):
        return ["query"]

    @property
    def input_prompts(self):
        return {"query": "Telegram @username, channel name or search phrase"}

    def run(self, case, **kwargs):
        query = (kwargs.get("query") or "").strip().lstrip("@")
        if not query:
            return self.result(rows=[("Error", "No Telegram query provided")], status="error")

        rows = [("Query", query)]
        if re.fullmatch(r"[A-Za-z0-9_]{4,64}", query):
            preview = sources.telegram_preview(query)
            if preview.get("ok"):
                html = preview.get("html") or ""
                title = re.search(r"<meta property=\"og:title\" content=\"([^\"]+)\"", html)
                description = re.search(r"<meta property=\"og:description\" content=\"([^\"]+)\"", html)
                rows.append(("Channel", f"https://t.me/{query}"))
                rows.append(("Title", title.group(1) if title else "-"))
                rows.append(("Description", description.group(1)[:300] if description else "-"))
                subscribers = re.search(r"([\d\s.,]+)\s+(?:subscribers|members)", html, re.I)
                rows.append(("Members", subscribers.group(1).strip() if subscribers else "-"))
            else:
                rows.append(("Preview", f"unavailable ({preview.get('error') or preview.get('status')})"))

            token = config.get_key("telegram")
            if token:
                response = sources.net.get(
                    f"https://api.telegram.org/bot{token}/getChat",
                    source="telegram",
                    params={"chat_id": f"@{query}"},
                )
                data = response.get("data") if response.get("status") == "ok" else None
                if isinstance(data, dict) and data.get("ok"):
                    chat = data.get("result") or {}
                    rows.append(("Chat ID", str(chat.get("id"))))
                    rows.append(("Chat type", chat.get("type") or "-"))
                    rows.append(("Chat title", chat.get("title") or chat.get("username") or "-"))
                else:
                    rows.append(("Bot API", "chat not found or token invalid"))

        rows.extend([
            ("Search", f"https://t.me/s/{quote(query)}"),
            ("Telegram search", f"https://t.me/{quote(query)}"),
            ("Google", f"https://www.google.com/search?q=site%3At.me+{quote(query)}"),
        ])
        if not re.fullmatch(r"[A-Za-z0-9_]{4,64}", query):
            rows.append(("Note", "Enter an @username for a channel preview, or use the search links above."))
        return self.result(
            title=f"Telegram Search: {query}",
            source="t.me public preview" + (" + Bot API" if config.get_key("telegram") else ""),
            confidence="medium",
            rows=rows,
        )
