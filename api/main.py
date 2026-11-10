"""VOLUME web API.

FastAPI application that exposes the Python module catalogue, email OTP auth,
passkeys, access keys, cases, watchlists and an admin surface.
"""

import csv
import io
import json
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api import accounts, db, modules_api, passkeys, security, settings
from volume.core import catalog as core_catalog
from volume.core import emailer

db.init()

app = FastAPI(title="VOLUME API", version=settings.VERSION, docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.WEB_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


@app.exception_handler(accounts.AuthError)
async def auth_error_handler(_request: Request, exc: accounts.AuthError):
    return JSONResponse(
        status_code=exc.status,
        content={"error": exc.message, "code": exc.code},
    )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EmailRequest(BaseModel):
    email: str
    referral: str = ""


class VerifyRequest(BaseModel):
    email: str
    code: str
    remember: bool = False


class KeyRequest(BaseModel):
    key: str


class MagicRequest(BaseModel):
    token: str


class MagicEmailRequest(BaseModel):
    email: str


class PivotRequest(BaseModel):
    seed: str = Field(min_length=1, max_length=512)
    kind: str = Field(default="email", max_length=40)
    case_id: str = ""


class RunRequest(BaseModel):
    module: str
    seed: str = Field(min_length=1, max_length=512)
    case_id: str = ""


class BreachRequest(BaseModel):
    email: str
    case_id: str = ""


class CaseRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    seed: str = ""
    kind: str = ""


class WatchRequest(BaseModel):
    label: str = ""
    seed: str = Field(min_length=1, max_length=512)
    kind: str = "email"


class SnapshotRequest(BaseModel):
    seed: str = ""
    kind: str = ""
    payload: dict = Field(default_factory=dict)


class PasskeyRegisterRequest(BaseModel):
    credential: dict
    label: str = ""


class PasskeyLoginRequest(BaseModel):
    email: str
    credential: dict


class AdminUserPatch(BaseModel):
    tier: Optional[str] = None
    credits: Optional[int] = None


class AdminModulePatch(BaseModel):
    enabled: Optional[bool] = None
    note: Optional[str] = None


class MintKeysRequest(BaseModel):
    count: int = 1
    tier: str = "premium"
    credits: int = 100
    label: str = ""


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def bearer_token(request: Request) -> str:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return (request.headers.get("x-volume-token") or "").strip()


def current_user(request: Request) -> dict:
    token = bearer_token(request)
    user = accounts.session_user(token) if token else None
    if not user:
        raise accounts.AuthError("Sign in to continue.", 401, "unauthorized")
    return user


def optional_user(request: Request) -> Optional[dict]:
    token = bearer_token(request)
    return accounts.session_user(token) if token else None


def admin_guard(
    request: Request,
    x_admin_key: str = Header(default="", alias="X-Admin-Key"),
) -> dict:
    if settings.ADMIN_KEY and security.constant_time_equal(x_admin_key, settings.ADMIN_KEY):
        return {"id": "admin-key", "email": "admin-key", "tier": "admin", "credits": 0}
    user = current_user(request)
    if not accounts.is_admin(user):
        raise accounts.AuthError("Administrator access required.", 403, "forbidden")
    return user


def validate_seed(seed: str, kind: str) -> str:
    seed = (seed or "").strip()
    if not seed:
        raise accounts.AuthError("Enter a target to search.", 422, "missing_seed")
    if len(seed) > 512:
        raise accounts.AuthError("That value is too long.", 422, "seed_too_long")
    kind = (kind or "email").strip().lower()
    if kind and kind not in modules_api.KIND_MODULES:
        raise accounts.AuthError(f"Unsupported lookup type: {kind}", 422, "invalid_kind")
    pattern = modules_api.SEED_PATTERNS.get(kind)
    if pattern and not pattern.match(seed):
        raise accounts.AuthError(f"That does not look like a valid {kind}.", 422, "invalid_seed")
    return seed


def resolve_seed(seed: str, kind: str) -> tuple[str, str]:
    """Validate a pivot seed, auto-detecting the type when the chip is wrong."""
    seed = (seed or "").strip()
    if not seed:
        raise accounts.AuthError("Enter a target to search.", 422, "missing_seed")
    if len(seed) > 512:
        raise accounts.AuthError("That value is too long.", 422, "seed_too_long")
    kind = (kind or "email").strip().lower()
    if kind not in modules_api.KIND_MODULES:
        kind = "email"
    pattern = modules_api.SEED_PATTERNS.get(kind)
    if pattern and not pattern.match(seed):
        kind = modules_api.detect_kind(seed, kind)
        if kind not in modules_api.KIND_MODULES:
            kind = "email"
        pattern = modules_api.SEED_PATTERNS.get(kind)
        if pattern and not pattern.match(seed):
            if kind == "email":
                kind = "username"
            else:
                raise accounts.AuthError(
                    f"That does not look like a valid {kind}.", 422, "invalid_seed"
                )
    return seed, kind


def owned_case(user: dict, case_id: str) -> dict:
    if not case_id:
        raise accounts.AuthError("Case not found.", 404, "case_not_found")
    row = db.query_one("SELECT * FROM cases WHERE id = ? AND user_id = ?", (case_id, user["id"]))
    if not row:
        raise accounts.AuthError("Case not found.", 404, "case_not_found")
    return row


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------

@app.get("/api/health")
@app.get("/health", include_in_schema=False)
def health():
    reason = db.fallback_reason()
    payload = {
        "ok": True,
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "database": db.backend(),
        "database_ok": db.healthy(),
        "modules": len(modules_api.REGISTRY),
        "email": emailer.config()["provider"],
    }
    if reason:
        payload["database_fallback"] = reason
    return payload


@app.get("/api/config")
def public_config():
    email_config = emailer.config()
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "email_provider": email_config["provider"],
        "email_configured": email_config["configured"],
        "passkey_rp_id": settings.WEBAUTHN_RP_ID,
        "quota": {"free": settings.TIER_LIMITS["free"]},
        "resend_after": settings.OTP_RESEND_SECONDS,
        "otp_ttl": settings.OTP_TTL_MINUTES * 60,
        "magic_ttl": settings.MAGIC_TTL_MINUTES * 60,
        "referral_reward": settings.REFERRAL_CREDITS,
    }


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@app.post("/api/auth/request")
def auth_request(payload: EmailRequest, request: Request):
    result = accounts.request_code(
        payload.email, security.client_ip(request), payload.referral
    )
    return result


@app.post("/api/auth/verify")
def auth_verify(payload: VerifyRequest, request: Request):
    token, user = accounts.verify_code(
        payload.email, payload.code, request, remember=payload.remember
    )
    return {"token": token, "user": accounts.public_user(user)}


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    token = bearer_token(request)
    if token:
        accounts.revoke_session(token)
    return {"ok": True}


@app.get("/api/auth/session")
def auth_session(request: Request):
    user = optional_user(request)
    if not user:
        return {"authenticated": False}
    return {"authenticated": True, "user": accounts.public_user(user)}


@app.post("/api/auth/key")
def auth_key(payload: KeyRequest, request: Request):
    """Sign in with an access key instead of email.

    Requires an existing workspace, so the key is redeemed against the account
    that owns the signed-in session or the email supplied alongside it.
    """
    user = optional_user(request)
    if not user:
        raise accounts.AuthError(
            "Sign in with email first, then redeem the key in the dashboard.",
            401,
            "unauthorized",
        )
    result = accounts.redeem_access_key(user, payload.key, security.client_ip(request))
    return {"ok": True, **result, "user": accounts.public_user(accounts.get_user(user["id"]))}


@app.post("/api/auth/key-login")
def auth_key_login(payload: KeyRequest, request: Request):
    """Sign in with an access key without an existing session."""
    token, user = accounts.key_login(payload.key, request)
    return {"token": token, "user": accounts.public_user(user)}


@app.post("/api/auth/magic/request")
def magic_request(payload: EmailRequest, request: Request):
    return accounts.request_magic_link(payload.email, security.client_ip(request))


@app.post("/api/auth/magic")
def magic_exchange(payload: MagicRequest, request: Request):
    token = accounts.consume_magic_token(payload.token, request)
    return {"token": token}


@app.get("/api/auth/magic/consume")
def magic_consume(request: Request, token: str = Query(default="")):
    try:
        session = accounts.consume_magic_token(token, request)
    except accounts.AuthError as exc:
        return HTMLResponse(
            f"<!doctype html><meta charset='utf-8'><title>VOLUME</title>"
            f"<body style='background:#080b09;color:#e9f3ec;font-family:monospace;"
            f"display:grid;place-items:center;height:100vh;margin:0'>"
            f"<div style='text-align:center'><p>{exc.message}</p>"
            f"<a style='color:#6ee7a8' href='/login.html'>Back to sign in</a></div></body>",
            status_code=exc.status,
        )
    safe = json.dumps(session)
    return HTMLResponse(
        "<!doctype html><meta charset='utf-8'><title>VOLUME</title>"
        "<body style='background:#080b09;color:#e9f3ec;font-family:monospace;"
        "display:grid;place-items:center;height:100vh;margin:0'>"
        "<div>Signing you in…</div>"
        "<script>localStorage.setItem('volume_token', " + safe + ");"
        "location.replace('/app');</script></body>"
    )


# ---------------------------------------------------------------------------
# Passkeys
# ---------------------------------------------------------------------------

@app.get("/api/passkeys")
def list_passkeys(user: dict = Depends(current_user)):
    return {"passkeys": passkeys.passkeys_for(user["id"])}


@app.post("/api/auth/passkey/register/begin")
def passkey_register_begin(user: dict = Depends(current_user)):
    return {"options": passkeys.begin_registration(user)}


@app.post("/api/auth/passkey/register/complete")
def passkey_register_complete(payload: PasskeyRegisterRequest, user: dict = Depends(current_user)):
    return passkeys.complete_registration(user, payload.credential, payload.label)


@app.post("/api/auth/passkey/login/begin")
def passkey_login_begin(payload: EmailRequest):
    return {"options": passkeys.begin_login(payload.email)}


@app.post("/api/auth/passkey/login/complete")
def passkey_login_complete(payload: PasskeyLoginRequest, request: Request):
    token, user = passkeys.complete_login(payload.email, payload.credential, request)
    return {"token": token, "user": accounts.public_user(user)}


@app.delete("/api/passkeys/{passkey_id}")
def passkey_delete(passkey_id: str, user: dict = Depends(current_user)):
    if not passkeys.delete_passkey(user, passkey_id):
        raise accounts.AuthError("Passkey not found.", 404, "not_found")
    return {"ok": True, "passkeys": passkeys.passkeys_for(user["id"])}


# ---------------------------------------------------------------------------
# Profile, sessions, referrals
# ---------------------------------------------------------------------------

@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    return accounts.public_user(user)


@app.get("/api/sessions")
def sessions(request: Request, user: dict = Depends(current_user)):
    return {
        "sessions": accounts.list_sessions(user["id"], bearer_token(request)),
        "passkeys": passkeys.passkeys_for(user["id"]),
    }


@app.delete("/api/sessions/{session_id}")
def session_revoke(session_id: str, user: dict = Depends(current_user)):
    if not accounts.revoke_session_by_id(user["id"], session_id):
        raise accounts.AuthError("Session not found.", 404, "not_found")
    return {"ok": True}


@app.get("/api/referrals/me")
def referrals(user: dict = Depends(current_user)):
    return accounts.referral_summary(user)


@app.post("/api/redeem")
def redeem(payload: KeyRequest, request: Request, user: dict = Depends(current_user)):
    result = accounts.redeem_access_key(user, payload.key, security.client_ip(request))
    result["user"] = accounts.public_user(accounts.get_user(user["id"]))
    return result


# ---------------------------------------------------------------------------
# Modules and lookups
# ---------------------------------------------------------------------------

@app.get("/api/modules")
def modules(user: Optional[dict] = Depends(optional_user)):
    return modules_api.catalog(user)


@app.post("/api/run")
def run_single(payload: RunRequest, request: Request, user: dict = Depends(current_user)):
    seed = validate_seed(payload.seed, _kind_for_module(payload.module))
    allowed, retry = security.rate_limit(f"run:{user['id']}", 40, 60)
    if not allowed:
        raise accounts.AuthError(f"Slow down. Retry in {retry}s.", 429, "rate_limited")
    case = owned_case(user, payload.case_id) if payload.case_id else None
    charge = accounts.consume_lookup(user, 1)
    result = modules_api.run_module(payload.module, seed, user)
    run_id = modules_api.persist_run(
        case["id"] if case else "", user["id"], seed, _kind_for_module(payload.module), result, result
    )
    accounts.audit(user["email"], "module.run", payload.module, security.client_ip(request))
    return {"run_id": run_id, **result, "charge": charge}


def _kind_for_module(module_id: str) -> str:
    module = modules_api.REGISTRY.get(module_id)
    if module and module.inputs:
        value = module.inputs[0]
        if value in modules_api.KIND_MODULES:
            return value
    for kind, ids in modules_api.KIND_MODULES.items():
        if module_id in ids:
            return kind
    return ""


@app.post("/api/pivot")
def pivot(payload: PivotRequest, request: Request, user: dict = Depends(current_user)):
    seed, kind = resolve_seed(payload.seed, payload.kind)
    allowed, retry = security.rate_limit(f"pivot:{user['id']}", 20, 60)
    if not allowed:
        raise accounts.AuthError(f"Slow down. Retry in {retry}s.", 429, "rate_limited")
    case = owned_case(user, payload.case_id) if payload.case_id else None
    charge = accounts.consume_lookup(user, 1)
    result = modules_api.pivot(seed, kind, user)
    result["charge"] = charge
    if case:
        modules_api.persist_run(
            case["id"], user["id"], seed, kind, {"module": "pivot", "status": "ok"}, result
        )
    accounts.audit(user["email"], "pivot.run", f"{kind}:{seed[:80]}", security.client_ip(request))
    return result


@app.post("/api/pivot/stream")
async def pivot_stream(payload: PivotRequest, request: Request, user: dict = Depends(current_user)):
    seed, kind = resolve_seed(payload.seed, payload.kind)
    allowed, retry = security.rate_limit(f"pivot:{user['id']}", 20, 60)
    if not allowed:
        raise accounts.AuthError(f"Slow down. Retry in {retry}s.", 429, "rate_limited")
    case = owned_case(user, payload.case_id) if payload.case_id else None
    accounts.consume_lookup(user, 1)
    accounts.audit(user["email"], "pivot.stream", f"{kind}:{seed[:80]}", security.client_ip(request))
    stream = modules_api.stream_pivot(seed, kind, user, case["id"] if case else "")
    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/breach")
def breach(payload: BreachRequest, request: Request, user: dict = Depends(current_user)):
    seed = validate_seed(payload.email, "email")
    allowed, retry = security.rate_limit(f"breach:{user['id']}", 20, 60)
    if not allowed:
        raise accounts.AuthError(f"Slow down. Retry in {retry}s.", 429, "rate_limited")
    case = owned_case(user, payload.case_id) if payload.case_id else None
    charge = accounts.consume_lookup(user, 1)
    result = modules_api.breach(seed, user)
    result["charge"] = charge
    if case:
        modules_api.persist_run(
            case["id"], user["id"], seed, "email", {"module": "breach", "status": "ok"}, result
        )
    accounts.audit(user["email"], "breach.run", seed[:80], security.client_ip(request))
    return result


@app.post("/api/graph")
def graph(payload: PivotRequest, user: dict = Depends(current_user)):
    seed, kind = resolve_seed(payload.seed, payload.kind)
    result = modules_api.pivot(seed, kind, user)
    return {"graph": result["graph"], "count": result["count"], "kind": kind}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@app.get("/api/cases")
def list_cases(user: dict = Depends(current_user)):
    rows = db.query(
        "SELECT c.*, (SELECT COUNT(*) FROM runs r WHERE r.case_id = c.id) AS run_count "
        "FROM cases c WHERE c.user_id = ? ORDER BY c.updated DESC",
        (user["id"],),
    )
    return {"cases": rows}


@app.post("/api/cases")
def create_case(payload: CaseRequest, user: dict = Depends(current_user)):
    now = security.iso()
    case_id = security.new_id("case_")
    db.execute(
        "INSERT INTO cases (id, user_id, name, seed, kind, created, updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case_id, user["id"], payload.name.strip(), payload.seed.strip(), payload.kind, now, now),
    )
    accounts.audit(user["email"], "case.create", payload.name[:120])
    return {"case": db.query_one("SELECT * FROM cases WHERE id = ?", (case_id,))}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str, user: dict = Depends(current_user)):
    case = owned_case(user, case_id)
    runs = db.query(
        "SELECT id, module, status, seed, kind, created FROM runs "
        "WHERE case_id = ? ORDER BY created ASC",
        (case_id,),
    )
    return {"case": case, "runs": runs}


@app.delete("/api/cases/{case_id}")
def delete_case(case_id: str, user: dict = Depends(current_user)):
    owned_case(user, case_id)
    db.execute("DELETE FROM runs WHERE case_id = ? AND user_id = ?", (case_id, user["id"]))
    db.execute("DELETE FROM cases WHERE id = ? AND user_id = ?", (case_id, user["id"]))
    return {"ok": True}


@app.post("/api/cases/{case_id}/snapshot")
def snapshot_case(case_id: str, payload: SnapshotRequest, user: dict = Depends(current_user)):
    case = owned_case(user, case_id)
    run_id = modules_api.persist_run(
        case["id"],
        user["id"],
        payload.seed,
        payload.kind,
        {
            "module": "snapshot",
            "status": "ok",
            "title": f"Saved {payload.kind or 'lookup'} snapshot",
        },
        payload.payload,
    )
    accounts.audit(user["email"], "case.snapshot", payload.seed[:80])
    return {"ok": True, "run_id": run_id, "case": case}


@app.get("/api/cases/{case_id}/export")
def export_case(case_id: str, fmt: str = Query(default="json", alias="format"), user: dict = Depends(current_user)):
    case = owned_case(user, case_id)
    runs = db.query(
        "SELECT * FROM runs WHERE case_id = ? AND user_id = ? ORDER BY created ASC",
        (case_id, user["id"]),
    )
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["created", "module", "status", "seed", "kind", "payload"])
        for row in runs:
            writer.writerow(
                [row["created"], row["module"], row["status"], row["seed"], row["kind"], row["payload"]]
            )
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{case["name"][:40]}.csv"'
            },
        )
    payload = {
        "case": case,
        "runs": [
            {
                **{k: row[k] for k in ("id", "module", "status", "seed", "kind", "created")},
                "payload": json.loads(row["payload"]) if row["payload"] else None,
            }
            for row in runs
        ],
        "exported": security.iso(),
    }
    return Response(
        content=json.dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{case["name"][:40]}.json"'
        },
    )


# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------

@app.get("/api/watchlists")
def list_watchlists(user: dict = Depends(current_user)):
    rows = db.query(
        "SELECT * FROM watchlists WHERE user_id = ? ORDER BY created DESC", (user["id"],)
    )
    return {"watchlists": rows}


@app.post("/api/watchlists")
def create_watchlist(payload: WatchRequest, user: dict = Depends(current_user)):
    seed = validate_seed(payload.seed, payload.kind)
    existing = db.query_one(
        "SELECT * FROM watchlists WHERE user_id = ? AND seed = ? AND kind = ?",
        (user["id"], seed, payload.kind),
    )
    if existing:
        raise accounts.AuthError("You already watch that target.", 409, "duplicate")
    watch_id = security.new_id("wat_")
    db.execute(
        "INSERT INTO watchlists (id, user_id, label, seed, kind, created, last_checked, "
        "last_count, last_new, snapshot) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, 0, NULL)",
        (
            watch_id,
            user["id"],
            (payload.label or seed)[:120],
            seed,
            payload.kind,
            security.iso(),
        ),
    )
    return {"watchlist": db.query_one("SELECT * FROM watchlists WHERE id = ?", (watch_id,))}


@app.delete("/api/watchlists/{watch_id}")
def delete_watchlist(watch_id: str, user: dict = Depends(current_user)):
    db.execute("DELETE FROM watchlists WHERE id = ? AND user_id = ?", (watch_id, user["id"]))
    db.execute("DELETE FROM watch_events WHERE watch_id = ? AND user_id = ?", (watch_id, user["id"]))
    return {"ok": True}


@app.post("/api/watchlists/{watch_id}/check")
def check_watchlist(watch_id: str, user: dict = Depends(current_user)):
    watch = db.query_one(
        "SELECT * FROM watchlists WHERE id = ? AND user_id = ?", (watch_id, user["id"])
    )
    if not watch:
        raise accounts.AuthError("Watch not found.", 404, "not_found")
    accounts.consume_lookup(user, 1)
    result = modules_api.pivot(watch["seed"], watch["kind"], user)
    values = {(hit.get("kind"), hit.get("value")) for hit in result["hits"]}
    previous = set()
    if watch.get("snapshot"):
        try:
            previous = {tuple(item) for item in json.loads(watch["snapshot"])}
        except Exception:
            previous = set()
    fresh = [list(item) for item in values - previous]
    db.execute(
        "UPDATE watchlists SET last_checked = ?, last_count = ?, last_new = ?, snapshot = ? "
        "WHERE id = ?",
        (
            security.iso(),
            len(values),
            len(fresh) if previous else 0,
            json.dumps([list(item) for item in values])[:200000],
            watch_id,
        ),
    )
    if previous and fresh:
        db.execute(
            "INSERT INTO watch_events (id, watch_id, user_id, created, summary) VALUES (?, ?, ?, ?, ?)",
            (
                security.new_id("wev_"),
                watch_id,
                user["id"],
                security.iso(),
                json.dumps({"new": len(fresh), "sample": fresh[:5]})[:4000],
            ),
        )
    return {
        "count": len(values),
        "new": len(fresh) if previous else 0,
        "hits": result["hits"],
        "checked": security.iso(),
    }


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.get("/api/admin/overview")
def admin_overview(_admin: dict = Depends(admin_guard)):
    users = db.query_one("SELECT COUNT(*) AS n FROM users") or {"n": 0}
    sessions = db.query_one(
        "SELECT COUNT(*) AS n FROM sessions WHERE revoked = 0"
    ) or {"n": 0}
    runs = db.query_one("SELECT COUNT(*) AS n FROM runs") or {"n": 0}
    cases = db.query_one("SELECT COUNT(*) AS n FROM cases") or {"n": 0}
    disabled = db.query_one(
        "SELECT COUNT(*) AS n FROM module_flags WHERE enabled = 0"
    ) or {"n": 0}
    return {
        "users": users["n"],
        "sessions": sessions["n"],
        "runs": runs["n"],
        "cases": cases["n"],
        "modules": len(modules_api.REGISTRY),
        "modules_disabled": disabled["n"],
        "database": db.backend(),
        "email": emailer.config(),
        "version": settings.VERSION,
    }


@app.get("/api/admin/users")
def admin_users(_admin: dict = Depends(admin_guard), limit: int = Query(default=100, le=500)):
    rows = db.query(
        "SELECT u.*, (SELECT COUNT(*) FROM runs r WHERE r.user_id = u.id) AS run_count "
        "FROM users u ORDER BY u.created DESC LIMIT ?",
        (limit,),
    )
    return {"users": rows}


@app.patch("/api/admin/users/{user_id}")
def admin_patch_user(user_id: str, payload: AdminUserPatch, admin: dict = Depends(admin_guard)):
    user = accounts.get_user(user_id)
    if not user:
        raise accounts.AuthError("User not found.", 404, "not_found")
    if payload.tier:
        if payload.tier.lower() not in settings.TIER_ORDER:
            raise accounts.AuthError("Unknown tier.", 422, "invalid_tier")
        db.execute("UPDATE users SET tier = ? WHERE id = ?", (payload.tier.lower(), user_id))
    if payload.credits is not None:
        accounts.grant_credits(user_id, int(payload.credits), "admin", admin.get("email", "admin"))
    accounts.audit(
        admin.get("email", "admin"),
        "admin.user.patch",
        f"{user_id} tier={payload.tier} credits={payload.credits}",
    )
    return {"user": accounts.get_user(user_id)}


@app.get("/api/admin/modules")
def admin_modules(_admin: dict = Depends(admin_guard)):
    return modules_api.catalog(None)


@app.patch("/api/admin/modules/{module_id}")
def admin_patch_module(module_id: str, payload: AdminModulePatch, admin: dict = Depends(admin_guard)):
    if module_id not in modules_api.REGISTRY:
        raise accounts.AuthError("Unknown module.", 404, "not_found")
    existing = db.query_one("SELECT * FROM module_flags WHERE module_id = ?", (module_id,))
    enabled = payload.enabled if payload.enabled is not None else (
        bool(existing["enabled"]) if existing else True
    )
    note = payload.note if payload.note is not None else (existing["note"] if existing else "")
    if existing:
        db.execute(
            "UPDATE module_flags SET enabled = ?, note = ?, updated = ? WHERE module_id = ?",
            (1 if enabled else 0, note, security.iso(), module_id),
        )
    else:
        db.execute(
            "INSERT INTO module_flags (module_id, enabled, note, updated) VALUES (?, ?, ?, ?)",
            (module_id, 1 if enabled else 0, note, security.iso()),
        )
    accounts.audit(
        admin.get("email", "admin"),
        "admin.module.flag",
        f"{module_id} enabled={enabled}",
    )
    return {"module_id": module_id, "enabled": enabled, "note": note}


@app.get("/api/admin/audit")
def admin_audit(_admin: dict = Depends(admin_guard), limit: int = Query(default=100, le=1000)):
    return {
        "entries": db.query(
            "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
        )
    }


@app.post("/api/admin/keys")
def admin_mint_keys(payload: MintKeysRequest, admin: dict = Depends(admin_guard)):
    if payload.tier.lower() not in settings.TIER_ORDER:
        raise accounts.AuthError("Unknown tier.", 422, "invalid_tier")
    created = []
    now = security.iso()
    for _ in range(max(1, min(payload.count, 25))):
        raw = security.generate_access_key()
        key_id = security.new_id("key_")
        db.execute(
            "INSERT INTO access_keys (id, key_hash, label, tier, credits, created, expires, "
            "redeemed_by, redeemed_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
            (
                key_id,
                security.digest(raw),
                payload.label[:120],
                payload.tier.lower(),
                max(0, payload.credits),
                now,
            ),
        )
        created.append(
            {
                "id": key_id,
                "key": raw,
                "tier": payload.tier.lower(),
                "credits": max(0, payload.credits),
                "label": payload.label,
            }
        )
    accounts.audit(
        admin.get("email", "admin"),
        "admin.keys.mint",
        f"count={len(created)} tier={payload.tier}",
    )
    return {"keys": created}


@app.get("/api/admin/keys")
def admin_list_keys(_admin: dict = Depends(admin_guard)):
    rows = db.query(
        "SELECT id, label, tier, credits, created, redeemed_by, redeemed_at FROM access_keys "
        "ORDER BY created DESC LIMIT 200"
    )
    return {"keys": rows}


# ---------------------------------------------------------------------------
# Static web app
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def root():
    return FileResponse(settings.WEB_DIR / "home.html")


@app.get("/app", include_in_schema=False)
@app.get("/app/", include_in_schema=False)
def app_page():
    return FileResponse(settings.WEB_DIR / "index.html")


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(settings.WEB_DIR / "login.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page():
    return FileResponse(settings.WEB_DIR / "dashboard.html")


@app.get("/1995", include_in_schema=False)
def legacy_page():
    return FileResponse(settings.WEB_DIR / "1995.html")


app.mount("/", StaticFiles(directory=str(settings.WEB_DIR), html=True), name="web")
