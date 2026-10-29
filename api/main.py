import os, random, datetime
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from core.pivot import fan_out
from core.tier import (
    init_db, get_or_create, get_user, tier_of,
    create_session, get_session_user, revoke_session,
)

app = FastAPI(title="volume.tools", docs_url=None, redoc_url=None)
init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Query(BaseModel):
    seed: str
    kind: str

class LoginReq(BaseModel):
    email: str

class VerifyReq(BaseModel):
    email: str
    code: str

class ClaimReq(BaseModel):
    code: str

KINDS = {"email", "username", "ip", "hash", "phone",
         "discord_id", "discord_username", "discord_invite", "domain"}

_PENDING = {}

def current_user(
    x_api_key: str = Header(default=""),
    x_telegram_id: str = Header(default=""),
    authorization: str = Header(default=""),
):
    token = authorization.replace("Bearer ", "").strip()
    if token:
        u = get_session_user(token)
        if u: return u
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
            "telegram_id": user.get("telegram_id"), "email": user.get("email")}

@app.get("/api/health")
def health():
    import core.sources as s
    return {"ok": True, "tool": "volume.tools",
            "sources": [getattr(x, "name", x.__name__) for x in s.REGISTRY]}

@app.post("/api/auth/request")
async def auth_request(req: LoginReq):
    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "invalid email")
    code = str(random.randint(100000, 999999))
    _PENDING[email] = {
        "code": code,
        "expires": (datetime.datetime.utcnow() + datetime.timedelta(minutes=10)).isoformat(),
    }
    print(f"[auth] code for {email}: {code}")
    return {"ok": True, "code": code, "note": "beta mode — code returned for testing"}

@app.post("/api/auth/verify")
async def auth_verify(req: VerifyReq):
    email = req.email.strip().lower()
    pending = _PENDING.get(email)
    if not pending:
        raise HTTPException(400, "no code requested")
    if pending["expires"] < datetime.datetime.utcnow().isoformat():
        _PENDING.pop(email, None)
        raise HTTPException(400, "code expired")
    if pending["code"] != req.code.strip():
        raise HTTPException(400, "wrong code")
    _PENDING.pop(email, None)
    user = get_user(email=email) or get_or_create(email=email)
    token = create_session(user["id"])
    return {"ok": True, "token": token, "user": {"tier": tier_of(user), "email": email}}

@app.post("/api/auth/logout")
async def auth_logout(authorization: str = Header(default="")):
    token = authorization.replace("Bearer ", "").strip()
    revoke_session(token)
    return {"ok": True}

@app.get("/api/referrals/me")
def my_referral(user=Depends(current_user)):
    from core.tier import get_or_create_referral, get_referral_stats
    code = get_or_create_referral(user["id"])
    stats = get_referral_stats(user["id"])
    return {"code": code, "stats": stats}

@app.post("/api/referrals/claim")
def claim_referral(req: ClaimReq, user=Depends(current_user)):
    from core.tier import claim_referral_code
    if not req.code.strip():
        raise HTTPException(400, "no code provided")
    ok, msg = claim_referral_code(user["id"], user.get("email") or "", req.code)
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg}

@app.get("/")
def home():
    return FileResponse("web/home.html")

@app.get("/login")
def login_page():
    return FileResponse("web/login.html")

@app.get("/dashboard")
def dashboard_page():
    return FileResponse("web/dashboard.html")

@app.get("/app")
def app_console():
    return FileResponse("web/index.html")

@app.get("/upgrade")
def upgrade():
    bot = os.environ.get("VolumeTools_Bot", "VolumeTools_Bot")
    return RedirectResponse(f"https://t.me/{bot}?start=upgrade")

app.mount("/static", StaticFiles(directory="web"), name="static")
