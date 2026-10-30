import httpx
from core.models import Hit

class Wayback:
    name = "wayback"
    accepts = ("domain",)
    free = True
    pillar = "iptrace"

    async def query(self, seed, kind):
        if kind != "domain":
            return []
        try:
            async with httpx.AsyncClient(timeout=25) as c:
                r = await c.get(
                    "http://web.archive.org/cdx/search/cdx",
                    params={
                        "url": f"{seed}/*",
                        "output": "json",
                        "fl": "original,timestamp,statuscode",
                        "collapse": "urlkey",
                        "limit": "500"
                    }
                )
            if r.status_code != 200:
                return []
            data = r.json()
            if len(data) < 2:
                return []
            urls = data[1:]
            return [Hit(self.name, "wayback_snapshot", seed, {
                "total": len(urls),
                "sample": [u[0] for u in urls[:20]],
                "oldest": urls[0][1] if urls else None,
                "newest": urls[-1][1] if urls else None,
            })]
        except Exception:
            return []
