import asyncio
from core.models import Hit

class Holehe:
    name = "holehe"
    accepts = ("email",)
    free = True
    pillar = "email"

    async def query(self, seed, kind):
        if kind != "email":
            return []
        try:
            proc = await asyncio.create_subprocess_exec(
                "holehe", seed, "--only-used", "--no-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
            hits = []
            for line in out.decode(errors="ignore").splitlines():
                if "[+]" in line:
                    site = line.split("[+]")[1].strip().split(" ")[0]
                    if site:
                        hits.append(Hit(self.name, "account", site, {"via": seed}))
            return hits
        except Exception:
            return []
