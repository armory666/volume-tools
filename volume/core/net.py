import threading
import time

import httpx


class Bucket:
    def __init__(self, rate: float, per: float = 1.0):
        self.rate = rate
        self.per = per
        self.tokens = rate
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.rate, self.tokens + (now - self.last) * (self.rate / self.per))
            self.last = now
            if self.tokens < 1:
                time.sleep((1 - self.tokens) * (self.per / self.rate))
                self.tokens = 0
            else:
                self.tokens -= 1


_buckets = {
    "default": Bucket(3, 1.0),
    "hibp": Bucket(1, 1.5),
    "discord": Bucket(5, 1.0),
    "github": Bucket(1, 1.0),
    "nvd": Bucket(1, 2.0),
    "circl": Bucket(2, 1.0),
    "crt": Bucket(1, 2.0),
    "shodan": Bucket(2, 1.0),
    "rdap": Bucket(2, 1.0),
    "wayback": Bucket(1, 1.0),
    "bgpview": Bucket(1, 1.0),
    "urlhaus": Bucket(1, 1.0),
    "virustotal": Bucket(1, 4.0),
    "abuseipdb": Bucket(1, 1.0),
    "greynoise": Bucket(1, 1.0),
    "openphish": Bucket(1, 5.0),
    "kev": Bucket(1, 10.0),
    "ipapi": Bucket(1, 1.0),
    "ipinfo": Bucket(1, 1.0),
    "nominatim": Bucket(1, 1.2),
    "leakix": Bucket(1, 2.0),
    "steam": Bucket(1, 1.0),
    "roblox": Bucket(2, 1.0),
    "telegram": Bucket(1, 1.0),
    "duckduckgo": Bucket(1, 1.0),
    "gravatar": Bucket(2, 1.0),
    "holehe": Bucket(2, 1.0),
    "nazapi": Bucket(1, 2.0),
    "kitty": Bucket(1, 2.0),
    "stealer": Bucket(1, 2.0),
    "xbox": Bucket(1, 2.0),
    "ghunt": Bucket(1, 2.0),
    "dvla": Bucket(1, 2.0),
    "emailrep": Bucket(1, 2.0),
    "urlscan": Bucket(1, 2.0),
}

_client = httpx.Client(
    timeout=15.0,
    follow_redirects=True,
    headers={"User-Agent": "volume/3.1 (+https://github.com/volume)"},
)

_cache = {}
_cache_lock = threading.Lock()


def _scrub(url: str) -> str:
    for marker in ("key=", "apikey=", "api_key=", "token=", "Auth-Key="):
        if marker in url:
            head, _, _ = url.partition(marker)
            return head + marker + "***"
    return url


def _handle(r):
    if r.status_code == 429:
        try:
            wait = float(r.headers.get("Retry-After", 2))
        except (TypeError, ValueError):
            wait = 2
        return ("retry", wait)
    if r.status_code >= 500:
        return ("retry", 2)
    if r.status_code == 404:
        return ("not_found", "Target not found.")
    if r.status_code == 403:
        return ("forbidden", "Access denied (key invalid, quota reached or source blocked).")
    if r.status_code == 401:
        return ("key_invalid", "Auth failed (missing or invalid API key).")
    if r.status_code >= 400:
        return ("error", f"HTTP {r.status_code}: {r.text[:160]}")
    return ("ok", None)


def _request(method: str, url: str, source: str, retries: int, **kw) -> dict:
    bucket = _buckets.get(source, _buckets["default"])
    last_err = None
    for attempt in range(retries):
        bucket.acquire()
        try:
            r = _client.request(method, url, **kw)
        except httpx.HTTPError as e:
            last_err = str(e)
            time.sleep(2 ** attempt)
            continue

        verdict, wait_or_msg = _handle(r)

        if verdict == "retry":
            last_err = f"HTTP {r.status_code}"
            time.sleep(wait_or_msg if wait_or_msg else 2 ** attempt)
            continue
        if verdict != "ok":
            return {
                "status": verdict,
                "code": r.status_code,
                "url": _scrub(str(r.url)),
                "error": wait_or_msg,
                "headers": dict(r.headers),
                "header_items": list(r.headers.multi_items()),
            }

        try:
            data = r.json()
        except ValueError:
            data = r.text
        return {
            "status": "ok",
            "code": r.status_code,
            "url": _scrub(str(r.url)),
            "data": data,
            "headers": dict(r.headers),
            "header_items": list(r.headers.multi_items()),
        }

    return {
        "status": "source_down",
        "url": _scrub(url),
        "error": last_err or "Retries exhausted",
    }


def get(url: str, source: str = "default", **kw) -> dict:
    return _request("GET", url, source, 3, **kw)


def head(url: str, source: str = "default", **kw) -> dict:
    return _request("HEAD", url, source, 2, **kw)


def post(url: str, source: str = "default", **kw) -> dict:
    return _request("POST", url, source, 3, **kw)


def get_json(url: str, source: str = "default", **kw):
    response = get(url, source=source, **kw)
    if response.get("status") != "ok":
        return None, response
    data = response.get("data")
    if not isinstance(data, (dict, list)):
        return None, response
    return data, response


def get_cached(url: str, ttl: int = 300, source: str = "default", **kw) -> dict:
    """GET with a small process-wide TTL cache (feeds, KEV catalogue, etc.)."""
    now = time.monotonic()
    with _cache_lock:
        entry = _cache.get(url)
        if entry and (now - entry[0]) < ttl:
            return entry[1]
    response = get(url, source=source, **kw)
    if response.get("status") == "ok":
        with _cache_lock:
            _cache[url] = (now, response)
    return response


def clear_cache():
    with _cache_lock:
        _cache.clear()
