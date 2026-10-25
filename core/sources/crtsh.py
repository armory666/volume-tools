import httpx
from core.models import Hit

class Crtsh:
    name = "crtsh"
    accepts = ("ip", "domain")
    free = True
    pillar = "iptrace"

    async def query(self, seed, kind):
        if kind not in ("ip", "domain"):
            return []
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get("https://crt.sh/",
                                params={"q": seed, "output": "json"})
            if r.status_code != 200 or not r.text.startswith("["):
                return []
            hosts = set()
            for rec in r.json()[:50]:
                for h in (rec.get("name_value") or "").split("\n"):
                    if h.strip():
                        hosts.add(h.strip())
            return [Hit(self.name, "tls_hostnames", seed, {
                "hostnames": sorted(hosts)[:50], "count": len(hosts),
            })] if hosts else []
        except Exception:
            return []
