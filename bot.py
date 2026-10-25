import os, json, re, asyncio
import datetime
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice,
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, PreCheckoutQueryHandler,
    MessageHandler, ContextTypes, filters,
)
from core.tier import (
    init_db, get_or_create, grant_premium, tier_of, usage_today, TIERS, db,
)
from core.pivot import fan_out

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
LAST = {}
init_db()

# --- PUT YOUR TELEGRAM ID HERE ---
# Message @userinfobot on Telegram to get it.
ADMIN_ID = 8984546896  
YOUR_USERNAME = "stomponheads" # without the @

PILLAR_EMOJI = {"discord":"🎮","stealer":"🦠","breach":"🔓","iptrace":"🌐",
                "email":"📧","username":"👤","phone":"📱","misc":"•"}

HELP = """*volume.tools* — osint pivot

/pivot <seed>     auto-detect
/email <addr>     email
/user <handle>    username
/ip <addr>        ip trace
/phone <num>      phone
/domain <d>       domain
/export           last result json
/upgrade          premium · 200/day, all sources
/status           tier + usage
/help             this
"""

def detect_kind(seed):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", seed): return "ip"
    if re.match(r"^\d{17,19}$", seed): return "discord_id"
    if re.match(r"^\+?[\d\s\-()]{7,}$", seed): return "phone"
    if "@" in seed and "." in seed.split("@")[-1]: return "email"
    if "." in seed and not seed.startswith("http"): return "domain"
    return "username"

def fmt(data):
    hits = data.get("hits", [])
    if not hits: return "no hits."
    by = {}
    for h in hits: by.setdefault(h["pillar"], []).append(h)
    lines = [f"*{data['kind']}* `{data['seed']}` — {data['count']} hits"]
    for p, hs in by.items():
        e = PILLAR_EMOJI.get(p, "•")
        lines.append(f"\n{e} *{p}* · {len(hs)}")
        for h in hs[:5]:
            lines.append(f"  `{str(h['value'])[:80]}`")
        if len(hs) > 5:
            lines.append(f"  _…+{len(hs)-5}_")
    return "\n".join(lines)[:3900]

def _clean(m):
    return {k: (sorted(v) if isinstance(v, set) else v) for k, v in m.items()}

async def run(update, seed, kind):
    user = get_or_create(tg=update.effective_chat.id)
    msg = await update.message.reply_text(f"fanning out · `{kind}`")
    try:
        hits = await fan_out(seed, kind, user)
    except PermissionError as e:
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton("⭐ unlock premium", callback_data="buy_month")
        ]])
        await msg.edit_text(f"*free tier limit*\n\n{str(e)}\n\n"
            "_premium: 200/day, all sources_",
            parse_mode="Markdown", reply_markup=kb)
        return
    except Exception as e:
        await msg.edit_text(f"error · {str(e)[:200]}")
        return
    data = {
        "tool": "volume.tools", "seed": seed, "kind": kind,
        "tier": tier_of(user), "count": len(hits),
        "hits": [{"source": h.source, "kind": h.kind,
                  "pillar": h.meta.get("pillar", "misc"),
                  "value": h.value, "meta": _clean(h.meta)} for h in hits],
    }
    LAST[update.effective_chat.id] = data
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("📥 json", callback_data="exp_json")
    ]]) if data["hits"] else None
    await msg.edit_text(fmt(data), parse_mode="Markdown", reply_markup=kb)

async def cmd_start(u, c):
    if c.args and c.args[0] == "upgrade":
        await cmd_upgrade(u, c); return
    await u.message.reply_text(HELP, parse_mode="Markdown")

async def cmd_help(u, c):
    await u.message.reply_text(HELP, parse_mode="Markdown")

async def cmd_pivot(u, c):
    if not c.args:
        await u.message.reply_text("usage: /pivot <seed>"); return
    s = " ".join(c.args)
    await run(u, s, detect_kind(s))

def mk(kind):
    async def h(u, c):
        if not c.args:
            await u.message.reply_text(f"usage: /{kind} <val>"); return
        await run(u, " ".join(c.args), kind)
    return h

async def cmd_auto(u, c):
    t = (u.message.text or "").strip()
    if not t or t.startswith("/"): return
    await run(u, t, detect_kind(t))

async def cmd_export(u, c):
    d = LAST.get(u.effective_chat.id)
    if not d:
        await u.message.reply_text("nothing to export."); return
    fn = f"volume_{d['kind']}.json"
    await u.message.reply_document(
        document=json.dumps(d, indent=2).encode(), filename=fn)

async def on_exp(u, c):
    q = u.callback_query; await q.answer()
    d = LAST.get(q.message.chat.id)
    if not d:
        await q.edit_message_text("expired."); return
    await q.message.reply_document(
        document=json.dumps(d, indent=2).encode(),
        filename=f"volume_{d['kind']}.json")

async def cmd_status(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    t = tier_of(user)
    used = usage_today(user["id"])
    lim = TIERS[t]["daily"]
    await u.message.reply_text(
        f"*tier* `{t}`\n*used today* `{used}/{lim}`\n"
        f"*paid until* `{user.get('paid_until') or '—'}`",
        parse_mode="Markdown")

# --- ADMIN & TESTING COMMANDS ---

async def cmd_makeadmin(u, c):
    if u.effective_chat.id != ADMIN_ID:
        await u.message.reply_text("no.")
        return
    user = get_or_create(tg=u.effective_chat.id)
    with db() as conn:
        conn.execute("UPDATE users SET tier='admin' WHERE id=?", (user["id"],))
    await u.message.reply_text("✅ you are now admin.")

async def cmd_givepremium(u, c):
    if u.effective_chat.id != ADMIN_ID:
        return
    if not c.args:
        await u.message.reply_text("usage: /givepremium <telegram_id>")
        return
    try:
        target_tg = int(c.args[0])
    except ValueError:
        await u.message.reply_text("invalid ID.")
        return
        
    target_user = get_or_create(tg=target_tg)
    paid_until = grant_premium(target_user["id"], days=30, provider="manual")
    await u.message.reply_text(f"✅ gifted premium to {target_tg} until {paid_until}")

async def cmd_testreceipt(u, c):
    if u.effective_chat.id != ADMIN_ID:
        await u.message.reply_text("no.")
        return
    user = get_or_create(tg=u.effective_chat.id)
    await send_receipt(
        u, c, user, 
        days=30, 
        amount=100, 
        charge_id="TEST_CHARGE_123456789", 
        paid_until="2024-12-31"
    )

async def cmd_testlimit(u, c):
    if u.effective_chat.id != ADMIN_ID:
        await u.message.reply_text("no.")
        return
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("⭐ unlock premium", callback_data="buy_month")
    ]])
    await u.message.reply_text(
        f"*free tier limit*\n\ndaily limit reached (5). upgrade for more.\n\n"
        "_premium: 200/day, all sources_",
        parse_mode="Markdown", reply_markup=kb)

# --------------------------------

async def cmd_upgrade(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if user["tier"] == "premium" and user["paid_until"]:
        await u.message.reply_text(
            f"*already premium* until `{user['paid_until']}`",
            parse_mode="Markdown"); return
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("⭐ 100 stars · 1 month", callback_data="buy_month")],
        [InlineKeyboardButton("⭐ 800 stars · 1 year",  callback_data="buy_year")],
    ])
    await u.message.reply_text(
        "*volume.tools premium*\n\n"
        "• 200 queries/day (was 5)\n"
        "• all sources (was 6)\n"
        "• json export\n"
        "• pay in stars — instant, no card\n",
        parse_mode="Markdown", reply_markup=kb)

async def on_buy(u, c):
    q = u.callback_query; await q.answer()
    if q.data == "buy_month":
        stars, days, lab = 100, 30, "1 month"
    elif q.data == "buy_year":
        stars, days, lab = 800, 365, "1 year"
    else:
        return
    await q.message.reply_invoice(
        title="volume.tools premium",
        description=f"premium tier · {lab}",
        payload=f"premium_{days}d",
        provider_token="", currency="XTR",
        prices=[LabeledPrice(lab, stars)])

async def on_pre(u, c):
    await u.pre_checkout_query.answer(ok=True)

async def on_paid(u, c):
    sp = u.message.successful_payment
    user = get_or_create(tg=u.effective_chat.id)
    days = 365 if "365" in sp.invoice_payload else 30
    
    paid_until = grant_premium(
        user["id"], days=days, provider="stars",
        provider_id=sp.telegram_payment_charge_id,
        amount=sp.total_amount)
    
    await send_receipt(u, c, user, days, sp.total_amount, sp.telegram_payment_charge_id, paid_until)

async def send_receipt(u, c, user, days, amount, charge_id, paid_until):
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    order_id = charge_id[-10:].upper()
    plan_name = "1 Year Premium" if days == 365 else "1 Month Premium"

    receipt = (
        f"🧾 **VOLUME.TOOLS**\n"
        f"**Payment Receipt**\n\n"
        f"> **Status:** ✅ Paid\n"
        f"> **Date:** `{timestamp}`\n"
        f"> **Order ID:** `{order_id}`\n\n"
        f"**Account Details**\n"
        f"> **Telegram ID:** `{user['telegram_id']}`\n"
        f"> **Username:** @{u.effective_chat.username or 'none'}\n\n"
        f"**Subscription**\n"
        f"> **Plan:** {plan_name}\n"
        f"> **Amount:** {amount} Stars\n"
        f"> **Expires:** `{paid_until}`\n\n"
        f"_Please save this message. If the bot resets, forward this receipt to @{YOUR_USERNAME} for manual restoration._"
    )

    await u.message.reply_text(receipt, parse_mode="Markdown")

    if u.effective_chat.id != ADMIN_ID:
        try:
            await c.bot.send_message(
                chat_id=ADMIN_ID,
                text=f"💰 **NEW SALE**\nUser: @{u.effective_chat.username or 'none'}\nID: `{u.effective_chat.id}`\nOrder: `{order_id}`\nAmount: {amount} Stars\nPlan: {plan_name}",
                parse_mode="Markdown"
            )
        except Exception:
            pass

def build_app():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("pivot", cmd_pivot))
    app.add_handler(CommandHandler("export", cmd_export))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("upgrade", cmd_upgrade))
    app.add_handler(CommandHandler("makeadmin", cmd_makeadmin))
    app.add_handler(CommandHandler("givepremium", cmd_givepremium))
    app.add_handler(CommandHandler("testreceipt", cmd_testreceipt))
    app.add_handler(CommandHandler("testlimit", cmd_testlimit))
    
    for k in ("email", "username", "user", "ip", "phone", "domain"):
        mapping = {"user": "username"}
        app.add_handler(CommandHandler(k, mk(mapping.get(k, k))))
        
    app.add_handler(CallbackQueryHandler(on_exp, pattern="^exp_json$"))
    app.add_handler(CallbackQueryHandler(on_buy, pattern="^buy_"))
    app.add_handler(PreCheckoutQueryHandler(on_pre))
    app.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, on_paid))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_auto))
    return app

async def run_web():
    import uvicorn
    from api.main import app as fastapi_app
    config = uvicorn.Config(fastapi_app, host="0.0.0.0",
                            port=int(os.environ.get("PORT", 8000)),
                            log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

async def main():
    tg_app = build_app()
    await tg_app.initialize()
    await tg_app.start()
    await tg_app.updater.start_polling()
    web_task = asyncio.create_task(run_web())
    print("volume.tools up — bot polling, web on port", os.environ.get("PORT", 8000))
    try:
        await web_task
    finally:
        await tg_app.updater.stop()
        await tg_app.stop()
        await tg_app.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
