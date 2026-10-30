import httpx
from core.models import Hit

class PGP:
    name = "pgp"
    accepts = ("email",)
    free = True
    pillar = "email"

    async def query(self, seed, kind):
        if kind != "email":
            return []
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.get(
                    "https://keys.openpgp.org/vks/v1/by-email/" + seed,
                    headers={"Accept": "application/json"}
                )
            if r.status_code == 200:
                return [Hit(self.name, "pgp_key", seed, {"found": True, "source": "keys.openpgp.org"})]
        except Exception:
            pass

        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.get(
                    "https://keyserver.ubuntu.com/pks/lookup",
                    params={"op": "get", "search": seed}
                )
            if r.status_code == 200 and "BEGIN PGP" in r.text:
                return [Hit(self.name, "pgp_key", seed, {"found": True, "source": "keyserver.ubuntu.com"})]
        except Exception:
            pass

        return []
