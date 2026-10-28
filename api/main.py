import os
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from core.pivot import fan_out
from core.tier import init_db, get_or_create, get_user, tier_of

app = FastAPI(title="volume.tools", docs_url=None, redoc_url=None)
init_db()

class Query(BaseModel):
    seed: str
    kind: str

KINDS = {"email", "username", "ip", "hash", "phone",
         "discord_id", "discord_username", "discord_invite", "domain"}

def current_user(x_api_key: str = Header(default=""),
                 x_telegram_id: str = Header(default="")):
    if x_api_key:
        u = get_user(uid=x_api_key)
        if u: return u
    if x_telegram_id:
        return get_or_create(tg=int(x_telegram_id))
    return get_or_create(tg=None, email=None)

@app.post("/api/pivot")
async def pivot(q: Query, user=Depends(current_user)):
    if q.kind not in KINDS:
        raise HTTPException(400, "bad kind")
    try:
        hits = await fan_out(q.seed, q.kind, user)
    except PermissionError as e:
        raise HTTPException(402, str(e))
    return {
        "tool": "volume.tools", "seed": q.seed, "kind": q.kind,
        "tier": tier_of(user), "count": len(hits),
        "hits": [{"source": h.source, "kind": h.kind,
                  "pillar": h.meta.get("pillar", "misc"),
                  "value": h.value, "meta": _clean(h.meta)} for h in hits],
    }

def _clean(m):
    return {k: (sorted(v) if isinstance(v, set) else v) for k, v in m.items()}

@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"tier": tier_of(user), "paid_until": user.get("paid_until"),
            "telegram_id": user.get("telegram_id")}

@app.get("/health")
def health():
    import core.sources as s
    return {"ok": True, "tool": "volume.tools",
            "sources": [getattr(x, "name", x.__name__) for x in s.REGISTRY]}

# --- SPA ROUTING ---

@app.get("/")
def home():
    return FileResponse("web/home.html")

@app.get("/app")
def app_console():
    return FileResponse("web/index.html")

# Static assets (CSS/JS/icons if you add them later)
app.mount("/static", StaticFiles(directory="web"), name="static")
