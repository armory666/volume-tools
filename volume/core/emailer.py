"""Transactional email for VOLUME.

Three providers sit behind one interface:

* ``console`` - prints the message to stderr (local development default)
* ``smtp``    - any SMTP relay, including a Gmail app password
* ``resend``  - https://resend.com

Set ``VOLUME_EMAIL_PROVIDER`` and the matching credentials.  Nothing in this
module logs a one-time code unless the console provider is active.
"""

import html
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

import httpx

APP_NAME = "VOLUME"
BRAND = "#6ee7a8"
INK = "#e9f3ec"
MUTED = "#93a29a"
CARD = "#0d1310"
PAGE = "#080b09"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def provider() -> str:
    return (os.getenv("VOLUME_EMAIL_PROVIDER") or "console").strip().lower()


def sender() -> tuple[str, str]:
    raw = (os.getenv("VOLUME_EMAIL_FROM") or "VOLUME <no-reply@volume.tools>").strip()
    name, address = parseaddr(raw)
    return (name or APP_NAME, address or raw)


def reply_to() -> str:
    return (os.getenv("VOLUME_EMAIL_REPLY_TO") or "").strip()


def config() -> dict:
    name, address = sender()
    current = provider()
    if current == "console":
        configured = True
    elif current == "smtp":
        configured = bool(os.getenv("VOLUME_SMTP_HOST"))
    elif current == "resend":
        configured = bool(os.getenv("RESEND_API_KEY"))
    else:
        configured = False
    return {
        "provider": current,
        "configured": configured,
        "from_name": name,
        "from_address": address,
    }


# ---------------------------------------------------------------------------
# Transport adapters
# ---------------------------------------------------------------------------

def _send_console(to: str, subject: str, text: str) -> dict:
    banner = "=" * 68
    print(banner, file=sys.stderr)
    print(f"[email:console] to={to}", file=sys.stderr)
    print(f"[email:console] subject={subject}", file=sys.stderr)
    print(text, file=sys.stderr)
    print(banner, file=sys.stderr)
    return {"ok": True, "provider": "console", "id": None}


def _send_smtp(to: str, subject: str, text: str, html_body: str) -> dict:
    host = (os.getenv("VOLUME_SMTP_HOST") or "").strip()
    if not host:
        return {"ok": False, "provider": "smtp", "error": "VOLUME_SMTP_HOST is not set"}
    try:
        port = int(os.getenv("VOLUME_SMTP_PORT") or 587)
    except ValueError:
        port = 587
    user = (os.getenv("VOLUME_SMTP_USER") or "").strip()
    password = os.getenv("VOLUME_SMTP_PASSWORD") or ""
    use_ssl = (os.getenv("VOLUME_SMTP_SSL") or "").lower() in {"1", "true", "yes"}
    use_tls = (os.getenv("VOLUME_SMTP_TLS") or "1").lower() not in {"0", "false", "no"}

    name, address = sender()
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((name, address))
    message["To"] = to
    if reply_to():
        message["Reply-To"] = reply_to()
    message.set_content(text)
    message.add_alternative(html_body, subtype="html")

    try:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
                if user:
                    server.login(user, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if user:
                    server.login(user, password)
                server.send_message(message)
        return {"ok": True, "provider": "smtp", "id": None}
    except Exception as exc:  # pragma: no cover - depends on external relay
        return {"ok": False, "provider": "smtp", "error": str(exc)}


def _send_resend(to: str, subject: str, text: str, html_body: str) -> dict:
    key = (os.getenv("RESEND_API_KEY") or "").strip()
    if not key:
        return {"ok": False, "provider": "resend", "error": "RESEND_API_KEY is not set"}
    name, address = sender()
    payload = {
        "from": formataddr((name, address)),
        "to": [to],
        "subject": subject,
        "text": text,
        "html": html_body,
    }
    if reply_to():
        payload["reply_to"] = reply_to()
    try:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {key}"},
            json=payload,
            timeout=20,
        )
        if response.status_code >= 400:
            return {
                "ok": False,
                "provider": "resend",
                "error": f"{response.status_code}: {response.text[:300]}",
            }
        data = response.json() if response.content else {}
        return {"ok": True, "provider": "resend", "id": data.get("id")}
    except Exception as exc:  # pragma: no cover - network dependent
        return {"ok": False, "provider": "resend", "error": str(exc)}


def send(to: str, subject: str, text: str, html_body: str = "") -> dict:
    to = (to or "").strip()
    if not to:
        return {"ok": False, "provider": provider(), "error": "missing recipient"}
    if not html_body:
        html_body = f"<pre style=\"font-family:monospace\">{html.escape(text)}</pre>"
    current = provider()
    if current == "console":
        return _send_console(to, subject, text)
    if current == "smtp":
        return _send_smtp(to, subject, text, html_body)
    if current == "resend":
        return _send_resend(to, subject, text, html_body)
    return {"ok": False, "provider": current, "error": f"unknown provider {current!r}"}


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

def _layout(title: str, intro: str, body: str, footer: str = "") -> str:
    safe_title = html.escape(title)
    return f"""\
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{PAGE};color:{INK};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{PAGE};padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:{CARD};border:1px solid #1b2a20;border-radius:14px;overflow:hidden;">
        <tr><td style="padding:26px 30px 8px 30px;">
          <div style="font-size:11px;letter-spacing:0.28em;color:{BRAND};text-transform:uppercase;font-weight:700;">{APP_NAME}</div>
          <h1 style="margin:14px 0 6px 0;font-size:22px;line-height:1.3;color:{INK};">{safe_title}</h1>
          <p style="margin:0;color:{MUTED};font-size:14px;line-height:1.6;">{intro}</p>
        </td></tr>
        <tr><td style="padding:18px 30px 10px 30px;">{body}</td></tr>
        <tr><td style="padding:10px 30px 28px 30px;color:{MUTED};font-size:12px;line-height:1.6;border-top:1px solid #16211a;margin-top:20px;">
          {footer or 'If you did not request this email you can safely ignore it.'}
        </td></tr>
      </table>
      <div style="max-width:520px;margin:14px auto 0 auto;color:#5c6b62;font-size:11px;text-align:center;">
        {APP_NAME} security intelligence · automated message
      </div>
    </td></tr>
  </table>
</body>
</html>"""


def _code_block(code: str) -> str:
    digits = "".join(
        f'<span style="display:inline-block;width:38px;height:48px;line-height:48px;'
        f'margin:0 4px;border:1px solid #294436;border-radius:8px;background:#0a120d;'
        f'color:{BRAND};font-size:24px;font-weight:700;text-align:center;'
        f'font-family:ui-monospace,SFMono-Regular,Menlo,monospace;">{html.escape(ch)}</span>'
        for ch in code
    )
    return f'<div style="text-align:center;padding:10px 0 4px 0;">{digits}</div>'


def otp_message(code: str, ttl_minutes: int) -> tuple[str, str, str]:
    subject = f"{APP_NAME} sign-in code: {code}"
    text = (
        f"Your {APP_NAME} sign-in code is {code}.\n\n"
        f"It expires in {ttl_minutes} minutes and can only be used once.\n"
        "If you did not try to sign in, ignore this email and consider rotating your credentials.\n"
    )
    body = f"""
      {_code_block(code)}
      <p style="margin:10px 0 0 0;text-align:center;color:{MUTED};font-size:13px;">
        Expires in {ttl_minutes} minutes · single use
      </p>
    """
    return subject, text, _layout("Your sign-in code", "Enter this code to finish signing in.", body)


def magic_message(url: str, ttl_minutes: int) -> tuple[str, str, str]:
    subject = f"{APP_NAME} sign-in link"
    text = (
        f"Use this link to sign in to {APP_NAME}:\n\n{url}\n\n"
        f"It expires in {ttl_minutes} minutes and can only be used once.\n"
    )
    body = f"""
      <p style="margin:0 0 18px 0;">
        <a href="{html.escape(url)}" style="display:inline-block;background:{BRAND};color:#04150c;
           text-decoration:none;font-weight:700;font-size:14px;padding:12px 22px;border-radius:9px;">
          Sign in to {APP_NAME}
        </a>
      </p>
      <p style="margin:0;color:{MUTED};font-size:12px;word-break:break-all;">{html.escape(url)}</p>
    """
    return subject, text, _layout("Your sign-in link", "One click and you are in.", body)


def welcome_message(email: str, tier: str, credits: int) -> tuple[str, str, str]:
    subject = f"Welcome to {APP_NAME}"
    text = (
        f"Your {APP_NAME} workspace is ready.\n\n"
        f"Account: {email}\nTier: {tier.upper()}\nCredits: {credits}\n\n"
        "Open the console to run your first lookup.\n"
    )
    body = f"""
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="font-size:14px;">
        <tr><td style="padding:6px 0;color:{MUTED};">Account</td><td align="right" style="padding:6px 0;">{html.escape(email)}</td></tr>
        <tr><td style="padding:6px 0;color:{MUTED};">Tier</td><td align="right" style="padding:6px 0;color:{BRAND};">{html.escape(tier.upper())}</td></tr>
        <tr><td style="padding:6px 0;color:{MUTED};">Credits</td><td align="right" style="padding:6px 0;">{credits}</td></tr>
      </table>
    """
    return subject, text, _layout("Workspace ready", "Your account has been provisioned.", body)


def quota_message(email: str, used: int, limit: int, tier: str) -> tuple[str, str, str]:
    subject = f"{APP_NAME}: {used}/{limit} lookups used today"
    text = (
        f"You have used {used} of {limit} daily lookups on the {tier.upper()} tier.\n\n"
        "Upgrade or redeem a key in the dashboard to keep going.\n"
    )
    body = f"""
      <p style="margin:0 0 16px 0;font-size:28px;color:{BRAND};font-weight:700;">{used} / {limit}</p>
      <p style="margin:0;color:{MUTED};font-size:13px;">Daily lookups used on the {html.escape(tier.upper())} tier.</p>
    """
    return subject, text, _layout("Approaching your daily limit", "Quota nearly exhausted.", body)


# ---------------------------------------------------------------------------
# Convenience senders
# ---------------------------------------------------------------------------

def send_otp(to: str, code: str, ttl_minutes: int = 10) -> dict:
    subject, text, body = otp_message(code, ttl_minutes)
    return send(to, subject, text, body)


def send_magic_link(to: str, url: str, ttl_minutes: int = 15) -> dict:
    subject, text, body = magic_message(url, ttl_minutes)
    return send(to, subject, text, body)


def send_welcome(to: str, tier: str, credits: int) -> dict:
    subject, text, body = welcome_message(to, tier, credits)
    return send(to, subject, text, body)


def send_quota_warning(to: str, used: int, limit: int, tier: str) -> dict:
    subject, text, body = quota_message(to, used, limit, tier)
    return send(to, subject, text, body)
