import os, httpx, json
from core.models import Hit

KEY = os.environ.get("OSINTSX_KEY", "")

class OsintSx:
    name = "osintsx"
    accepts = ("email", "username", "phone")
    free = False
    pillar = "email"

    async def query(self, seed, kind):
        if not KEY:
            return []
        hits = []
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                async with c.stream(
                    "POST",
                    "https://api.osint.sx/search",
                    headers={"x-api-key": KEY, "content-type": "application/json"},
                    json={"moduleType": kind, "identifier": seed},
                ) as resp:
                    if resp.status_code != 200:
                        return []
                    async for line in resp.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except Exception:
                            continue
                        if "result" in evt and evt.get("className"):
                            hits.append(Hit(self.name, "osint_hit", evt["className"], {
                                "module": evt["className"],
                                "result": str(evt["result"])[:200],
                            }))
        except Exception:
            pass
        return hits[:15]
