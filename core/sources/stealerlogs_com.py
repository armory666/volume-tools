import os, httpx
from core.models import Hit

KEY = os.environ.get("STEALERLOGS_KEY", "")

class StealerLogsCom:
    name = "stealerlogs"
    accepts = ("email", "username", "ip")
    free = False
    pillar = "stealer"

    async def query(self, seed, kind):
        if not KEY:
            return []
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.get(
                    "https://stealerlogs.com/api/search",
                    params={"q": seed, "type": kind},
                    headers={"Authorization": f"Bearer {KEY}"},
                )
            if r.status_code != 200:
                return []
            d = r.json()
            hits = []
            for log in d.get("results", [])[:10]:
                hits.append(Hit(self.name, "stealer_log", log.get("email") or seed, {
                    "machine_id": log.get("machine_id"),
                    "origin": log.get("origin"),
                    "password": log.get("password"),
                    "malware": log.get("malware_family"),
                    "date": log.get("post_date"),
                    "log_id": log.get("id"),
                }))
            return hits
        except Exception:
            return []
