import asyncio, shutil
from core.models import Hit

class Holehe:
    name = "holehe"
    accepts = ("email",)
    free = True
    pillar = "email"

    async def query(self, seed, kind):
        if kind != "email":
            return []
        holehe_bin = shutil.which("holehe")
        if not holehe_bin:
            return []
        try:
            proc = await asyncio.create_subprocess_exec(
                holehe_bin, seed, "--only-used", "--no-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0:
                print(f"[holehe] exit {proc.returncode}: {err.decode()[:200]}")
                return []
            hits = []
            for line in out.decode(errors="ignore").splitlines():
                # Holehe uses [+] for found, [x] for not found, [-] for not used
                if "[+]" in line:
                    site = line.split("[+]")[1].strip().split(" ")[0]
                    if site:
                        hits.append(Hit(self.name, "account", site, {"via": seed}))
            print(f"[holehe] {seed}: {len(hits)} accounts found")
            return hits
        except asyncio.TimeoutError:
            print(f"[holehe] timeout for {seed}")
            return []
        except Exception as e:
            print(f"[holehe] error: {e}")
            return []
