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

@app.post("/api/breach/export")
async def breach_export(req: BreachReq, user=Depends(current_user)):
    if tier_of(user) not in ("premium", "admin"):
        raise HTTPException(402, "breach export requires premium")
    from core.sources.breach import BreachEngine
    from core.sources.h8mail import H8Mail
    seed = req.email.strip()
    if not seed:
        raise HTTPException(400, "no email")
    engine_hits = await BreachEngine().query(seed, "email")
    h8_hits = await H8Mail().query(seed, "email")
    all_hits = engine_hits + h8_hits
    if not all_hits:
        raise HTTPException(404, "no hits for this email")

    lines = []
    lines.append("=" * 64)
    lines.append(f"VOLUME.TOOLS — BREACH REPORT")
    lines.append(f"Query:     {seed}")
    lines.append(f"Generated: {datetime.datetime.utcnow().isoformat()} UTC")
    lines.append(f"Operator:  {user.get('email') or user.get('telegram_id') or 'anonymous'}")
    lines.append("=" * 64)
    lines.append("")

    by_source = {}
    for h in all_hits:
        by_source.setdefault(h.source, []).append(h)

    for source, hits in by_source.items():
        lines.append(f"── {source.upper()} ({len(hits)} hits) ──")
        for h in hits:
            lines.append(f"  [{h.kind}] {h.value}")
            for k, v in (h.meta or {}).items():
                if k in ("sources", "pillar", "confidence"):
                    continue
                if isinstance(v, list):
                    if not v: continue
                    lines.append(f"    {k}:")
                    for item in v:
                        lines.append(f"      - {item}")
                else:
                    if v is None or v == "": continue
                    lines.append(f"    {k}: {v}")
            lines.append("")
        lines.append("")

    lines.append("=" * 64)
    lines.append(f"Total records:    {len(all_hits)}")
    lines.append(f"Sources involved: {', '.join(sorted(by_source.keys()))}")
    lines.append(f"Attribution:      Every hit traces to a named source above.")
    lines.append("=" * 64)

    report = "\n".join(lines)
    return {"report": report, "count": len(all_hits), "filename": f"volume_breach_{seed.split('@')[0]}.txt"}
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

class RedeemReq(BaseModel):
    key: str

@app.post("/api/redeem")
def api_redeem(req: RedeemReq, user=Depends(current_user)):
    from core.tier import redeem_key
    if not req.key.strip():
        raise HTTPException(400, "no key provided")
    ok, msg = redeem_key(user["id"], req.key.strip().upper())
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg, "tier": "premium"}

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
