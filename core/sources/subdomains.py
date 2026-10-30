import httpx, asyncio
from core.models import Hit

class Subdomains:
    name = "subdomains"
    accepts = ("domain",)
    free = True
    pillar = "iptrace"

    async def _crtsh(self, domain):
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
            if r.status_code != 200:
                return set()
            names = set()
            for rec in r.json():
                for n in (rec.get("name_value") or "").split("\n"):
                    n = n.strip().lower()
                    if n and n.endswith(domain) and "*" not in n:
                        names.add(n)
            return names
        except Exception:
            return set()

    async def _hackertarget(self, domain):
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
            if r.status_code != 200:
                return set()
            names = set()
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts and parts[0].strip():
                    names.add(parts[0].strip().lower())
            return names
        except Exception:
            return set()

    async def _otx(self, domain):
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
            if r.status_code != 200:
                return set()
            names = set()
            for rec in r.json().get("passive_dns", []):
                h = rec.get("hostname")
                if h and domain in h:
                    names.add(h.lower())
            return names
        except Exception:
            return set()

    async def query(self, seed, kind):
        if kind != "domain":
            return []
        results = await asyncio.gather(
            self._crtsh(seed), self._hackertarget(seed), self._otx(seed)
        )
        combined = set()
        for r in results:
            combined |= r
        if not combined:
            return []
        return [Hit(self.name, "subdomain", sub, {"source": "aggregated", "total_found": len(combined)})
                for sub in sorted(combined)[:200]]
