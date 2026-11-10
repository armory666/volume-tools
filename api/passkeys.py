"""WebAuthn passkey registration and sign-in."""

import base64
import datetime
import hashlib
import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from api import accounts, db, security, settings


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _challenge_bytes(raw: str) -> bytes:
    return _unb64(raw)


def _save_challenge(subject: str, kind: str, challenge: str) -> None:
    db.execute(
        "DELETE FROM challenges WHERE subject = ? AND kind = ?", (subject, kind)
    )
    db.execute(
        "INSERT INTO challenges (id, subject, kind, challenge, expires) VALUES (?, ?, ?, ?, ?)",
        (
            security.new_id("chl_"),
            subject,
            kind,
            challenge,
            security.iso(
                security.utcnow() + datetime.timedelta(minutes=5)
            ),
        ),
    )


def _load_challenge(subject: str, kind: str) -> bytes:
    row = db.query_one(
        "SELECT * FROM challenges WHERE subject = ? AND kind = ?", (subject, kind)
    )
    if not row or security.expired(row["expires"]):
        raise accounts.AuthError("This passkey request expired. Try again.", 400, "challenge_expired")
    db.execute("DELETE FROM challenges WHERE id = ?", (row["id"],))
    return _challenge_bytes(row["challenge"])


def passkeys_for(user_id: str) -> list[dict]:
    rows = db.query(
        "SELECT id, credential_id, label, transports, created, last_used "
        "FROM passkeys WHERE user_id = ? ORDER BY created DESC",
        (user_id,),
    )
    return [
        {
            "id": row["id"],
            "label": row["label"] or "Passkey",
            "created": row["created"],
            "last_used": row["last_used"],
        }
        for row in rows
    ]


def begin_registration(user: dict) -> dict:
    rows = db.query("SELECT credential_id FROM passkeys WHERE user_id = ?", (user["id"],))
    exclude = [
        PublicKeyCredentialDescriptor(id=_unb64(row["credential_id"])) for row in rows
    ]
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=hashlib.sha256(user["id"].encode()).digest()[:16],
        user_name=user["email"],
        user_display_name=user["email"],
        exclude_credentials=exclude,
    )
    data = json.loads(options_to_json(options))
    _save_challenge(user["id"], "register", data["challenge"])
    return data


def complete_registration(user: dict, credential: dict, label: str = "") -> dict:
    challenge = _load_challenge(user["id"], "register")
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGINS,
            require_user_verification=False,
        )
    except Exception as exc:
        raise accounts.AuthError(f"Passkey registration failed: {exc}", 400, "passkey_failed")

    credential_id = _b64(verified.credential_id)
    if db.query_one("SELECT id FROM passkeys WHERE credential_id = ?", (credential_id,)):
        raise accounts.AuthError("That passkey is already registered.", 409, "passkey_exists")

    now = security.iso()
    db.execute(
        "INSERT INTO passkeys (id, user_id, credential_id, public_key, sign_count, "
        "transports, label, created, last_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            security.new_id("pky_"),
            user["id"],
            credential_id,
            _b64(verified.credential_public_key),
            int(verified.sign_count or 0),
            json.dumps((credential or {}).get("response", {}).get("transports") or []),
            (label or "Passkey")[:60],
            now,
            now,
        ),
    )
    accounts.audit(user["email"], "passkey.register", label[:120])
    return {"ok": True, "passkeys": passkeys_for(user["id"])}


def begin_login(email: str) -> dict:
    email = accounts.normalize_email(email)
    user = accounts.get_user_by_email(email)
    rows = (
        db.query("SELECT credential_id FROM passkeys WHERE user_id = ?", (user["id"],))
        if user
        else []
    )
    if not rows:
        raise accounts.AuthError("No passkey is registered for that email.", 404, "no_passkey")
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=_unb64(row["credential_id"])) for row in rows
        ],
    )
    data = json.loads(options_to_json(options))
    _save_challenge(email, "login", data["challenge"])
    return data


def complete_login(email: str, credential: dict, request) -> tuple[str, dict]:
    email = accounts.normalize_email(email)
    user = accounts.get_user_by_email(email)
    if not user:
        raise accounts.AuthError("No account for that email.", 404, "no_account")
    credential_id = (credential or {}).get("id") or (credential or {}).get("rawId") or ""
    row = db.query_one(
        "SELECT * FROM passkeys WHERE user_id = ? AND credential_id = ?",
        (user["id"], credential_id),
    )
    if not row:
        raise accounts.AuthError("Unknown passkey.", 404, "unknown_passkey")

    challenge = _load_challenge(email, "login")
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGINS,
            credential_public_key=_unb64(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"] or 0),
            require_user_verification=False,
        )
    except Exception as exc:
        accounts.audit(email, "passkey.login.failed", str(exc)[:200], security.client_ip(request))
        raise accounts.AuthError(f"Passkey sign-in failed: {exc}", 401, "passkey_failed")

    db.execute(
        "UPDATE passkeys SET sign_count = ?, last_used = ? WHERE id = ?",
        (int(verified.new_sign_count or 0), security.iso(), row["id"]),
    )
    token = accounts.issue_session(user, request, remember=True)
    accounts.audit(email, "passkey.login", row["label"] or "", security.client_ip(request))
    return token, user


def delete_passkey(user: dict, passkey_id: str) -> bool:
    return (
        db.execute(
            "DELETE FROM passkeys WHERE id = ? AND user_id = ?", (passkey_id, user["id"])
        )
        > 0
    )
