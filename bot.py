import os, json, re, asyncio, time, datetime
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice,
    BotCommand, BotCommandScopeChat, WebAppInfo
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, PreCheckoutQueryHandler,
    MessageHandler, ContextTypes, filters,
)
from core.tier import (
    init_db, get_or_create, get_user, grant_premium, tier_of, usage_today, TIERS, db,
    create_key, redeem_key, create_admin_key, redeem_admin_key, revoke_admin_keys,
    tier_of_admin_safe,
)

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
init_db()

ADMIN_ID = 8984546896
OWNER_ID = 8984546896
YOUR_USERNAME = "stomponheads"
VERSION = "v3.0.0"
WEB_URL = "https://volume-tools-web.vercel.app"

def owner_only(func):
    async def wrapper(u, c):
        if u.effective_chat.id != OWNER_ID:
            await u.message.reply_text(
                "🔒 <b>Owner only.</b>\n\n<i>This command is locked to the platform owner.</i>",
                parse_mode="HTML"
            )
            return
        return await func(u, c)
    return wrapper

HELP = """<b>VOLUME.TOOLS — PAYMENT TERMINAL</b>
<i>The investigation console lives on the web.</i>

<b>🌐 Access</b>
<a href="{web}/login">Sign in</a> · <a href="{web}/dashboard">Dashboard</a> · <a href="{web}/app">Console</a>

<b>💎 Account</b>
/upgrade · buy or manage premium
/redeem · activate a key
/status · check your tier
/help · this menu

<b>Premium unlocks:</b>
> 200 pivots per day
> all 15 sources
> deep breach engine
> case workspace
> json + csv exports

<b>Pricing</b>
> 100 Stars · 1 month
> 800 Stars · 1 year
""".format(web=WEB_URL)

USER_COMMANDS = [
    ("start", "start · payment info"),
    ("upgrade", "buy premium"),
    ("redeem", "redeem a premium key"),
    ("status", "check your tier"),
    ("help", "help"),
]

ADMIN_COMMANDS = USER_COMMANDS + [
    ("genkey", "mint a premium key"),
    ("genadminkey", "mint an admin key"),
    ("revokealladmins", "demote all admins except owner"),
    ("givepremium", "grant premium to a user id"),
    ("revoke", "revoke premium from a user id"),
    ("broadcast", "message all users"),
    ("stats", "daily metrics"),
    ("top", "recent activity"),
    ("ping", "check latency"),
    ("starbalance", "bot star balance"),
    ("testreceipt", "preview the receipt"),
    ("makeadmin", "promote yourself to admin"),
]

# ============================================================
# START / HELP
# ============================================================

async def cmd_start(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    t = tier_of(user)
    lines = [
        f"🌐 <b>VOLUME.TOOLS</b> {VERSION}",
        f"<i>Payment terminal · the console lives on the web</i>",
        "",
        f"<blockquote><b>Your tier:</b> <code>{t.upper()}</code>",
    ]
    if user.get("paid_until"):
        lines.append(f"<b>Expires:</b> <code>{user['paid_until']}</code>")
    lines.append("</blockquote>")
    lines.append("")
    lines.append(f"<b>Console:</b> <a href=\"{WEB_URL}/app\">{WEB_URL}/app</a>")
    lines.append(f"<b>Dashboard:</b> <a href=\"{WEB_URL}/dashboard\">{WEB_URL}/dashboard</a>")
    lines.append("")
    if t == "free":
        lines.append("<i>Upgrade to premium to unlock 200 pivots/day, all sources, and the deep breach engine.</i>")
    else:
        lines.append("<i>Premium active. All sources unlocked.</i>")

    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("💎 upgrade" if t == "free" else "⭐ manage premium", callback_data="menu_upgrade")],
        [InlineKeyboardButton("🌐 open console", url=f"{WEB_URL}/app")],
    ])
    await u.message.reply_text("\n".join(lines), parse_mode="HTML", reply_markup=kb, disable_web_page_preview=True)

async def cmd_help(u, c):
    await u.message.reply_text(HELP.format(web=WEB_URL), parse_mode="HTML", disable_web_page_preview=True)

async def on_upgrade_menu(u, c):
    q = u.callback_query
    await q.answer()
    # Route to the same cmd_upgrade logic
    user = get_or_create(tg=u.effective_chat.id)
    t = tier_of(user)
    if t == "premium" and user.get("paid_until"):
        await q.message.reply_text(
            f"💎 <b>Premium active</b>\n\nExpires: <code>{user['paid_until']}</code>\n\n<i>To extend, buy again — days add up.</i>",
            parse_mode="HTML"
        )
        return
    await cmd_upgrade(u, c)

# ============================================================
# STATUS
# ============================================================

async def cmd_status(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    t = tier_of_admin_safe(user, ADMIN_ID)
    used = usage_today(user["id"])
    lim = TIERS[t]["daily"]
    status = (
        f"🟢 <b>ACCOUNT STATUS</b>\n\n"
        f"<b>Account</b>\n"
        f"<blockquote><b>ID:</b> <code>{user['telegram_id']}</code>\n"
        f"<b>Tier:</b> <code>{t.upper()}</code>\n"
        f"<b>Quota:</b> <code>{used}/{lim}</code>\n"
        f"<b>Expires:</b> <code>{user.get('paid_until') or 'N/A'}</code></blockquote>\n\n"
        f"<b>Links</b>\n"
        f"<blockquote><a href=\"{WEB_URL}/app\">console</a> · <a href=\"{WEB_URL}/dashboard\">dashboard</a></blockquote>"
    )
    await u.message.reply_text(status, parse_mode="HTML", disable_web_page_preview=True)

# ============================================================
# REDEEM
# ============================================================

async def cmd_redeem(u, c):
    if not c.args:
        await u.message.reply_text(
            "Usage: <code>/redeem &lt;key&gt;</code>\n\n"
            "<i>Keys look like</i> <code>PERM-XXXX-XXXX-XXXX</code> <i>or</i> <code>ADMIN-XXXX-XXXX-XXXX</code>.\n\n"
            "<b>Note:</b> it's usually easier to redeem on the site — open the dashboard and paste it there.\n"
            f"<a href=\"{WEB_URL}/dashboard\">Open dashboard</a>",
            parse_mode="HTML",
            disable_web_page_preview=True
        )
        return
    user = get_or_create(tg=u.effective_chat.id)
    key = c.args[0].strip().upper()

    if key.startswith("ADMIN-"):
        ok, msg = redeem_admin_key(user["id"], key)
    else:
        ok, msg = redeem_key(user["id"], key)

    if ok:
        await u.message.reply_text(
            f"✅ <b>Key Redeemed</b>\n\n{msg}\n\n"
            f"<i>You now have access on the web.</i>\n"
            f"<a href=\"{WEB_URL}/app\">Open console</a>",
            parse_mode="HTML",
            disable_web_page_preview=True
        )
    else:
        await u.message.reply_text(f"❌ <b>Error</b>\n\n{msg}", parse_mode="HTML")

# ============================================================
# UPGRADE / STARS PAYMENT
# ============================================================

async def cmd_upgrade(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if user["tier"] == "premium" and user.get("paid_until"):
        await u.message.reply_text(
            f"💎 <b>Premium active</b>\n\nExpires: <code>{user['paid_until']}</code>",
            parse_mode="HTML"
        )
        return

    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("⭐ 100 Stars · 1 month", callback_data="buy_month")],
        [InlineKeyboardButton("⭐ 800 Stars · 1 year",  callback_data="buy_year")],
    ])
    await u.message.reply_text(
        "💎 <b>VOLUME.TOOLS PREMIUM</b>\n\n"
        "<blockquote>200 pivots per day (was 15)\n"
        "all 15 sources unlocked\n"
        "deep breach & stealer logs\n"
        "case workspace\n"
        "json + csv exports\n"
        "permanent key — survives resets</blockquote>\n\n"
        f"<i>Pay instantly with Telegram Stars. You'll get a key to redeem on the site.</i>",
        parse_mode="HTML",
        reply_markup=kb
    )

async def on_buy(u, c):
    q = u.callback_query
    await q.answer()
    if q.data == "buy_month":
        stars, days, lab = 100, 30, "1 Month"
    elif q.data == "buy_year":
        stars, days, lab = 800, 365, "1 Year"
    else:
        return
    await q.message.reply_invoice(
        title="volume.tools premium",
        description=f"Premium Tier · {lab}",
        payload=f"premium_{days}d",
        provider_token="",
        currency="XTR",
        prices=[LabeledPrice(lab, stars)]
    )

async def on_pre(u, c):
    await u.pre_checkout_query.answer(ok=True)

async def on_paid(u, c):
    sp = u.message.successful_payment
    user = get_or_create(tg=u.effective_chat.id)
    days = 365 if "365" in sp.invoice_payload else 30
    new_key = create_key("premium")
    paid_until = grant_premium(
        user["id"],
        days=days,
        provider="stars",
        provider_id=sp.telegram_payment_charge_id,
        amount=sp.total_amount
    )
    await send_receipt(u, c, user, days, sp.total_amount, sp.telegram_payment_charge_id, paid_until, new_key)

async def send_receipt(u, c, user, days, amount, charge_id, paid_until, key=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    order_id = charge_id[-10:].upper()
    plan_name = "1 Year Premium" if days == 365 else "1 Month Premium"

    key_section = ""
    if key:
        key_section = (
            f"\n<b>Your Access Key</b>\n"
            f"<code>{key}</code>\n\n"
            f"<b>How to activate on the site:</b>\n"
            f"1. Go to <a href=\"{WEB_URL}/login\">the login page</a>\n"
            f"2. Sign in with your email\n"
            f"3. Open the dashboard → paste your key → premium unlocks\n\n"
            f"<i>Keep this key. It's your permanent proof of purchase.</i>\n"
        )

    receipt = (
        f"🧾 <b>VOLUME.TOOLS</b>\n"
        f"<b>Payment Receipt</b>\n\n"
        f"<blockquote><b>Status:</b> ✅ Paid\n"
        f"<b>Date:</b> <code>{timestamp}</code>\n"
        f"<b>Order ID:</b> <code>{order_id}</code></blockquote>\n\n"
        f"<b>Account</b>\n"
        f"<blockquote><b>Telegram ID:</b> <code>{user['telegram_id']}</code>\n"
        f"<b>Username:</b> @{u.effective_chat.username or 'none'}</blockquote>\n\n"
        f"<b>Subscription</b>\n"
        f"<blockquote><b>Plan:</b> {plan_name}\n"
        f"<b>Amount:</b> {amount} Stars\n"
        f"<b>Expires:</b> <code>{paid_until}</code></blockquote>\n"
        f"{key_section}\n"
        f"<i>Please save this message. If the bot resets, your key is still valid.</i>"
    )
    await u.message.reply_text(receipt, parse_mode="HTML", disable_web_page_preview=True)

    if u.effective_chat.id != ADMIN_ID:
        try:
            await c.bot.send_message(
                chat_id=ADMIN_ID,
                text=(
                    f"💰 <b>NEW SALE</b>\n"
                    f"User: @{u.effective_chat.username or 'none'}\n"
                    f"ID: <code>{u.effective_chat.id}</code>\n"
                    f"Key: <code>{key}</code>\n"
                    f"Amount: {amount} Stars\n"
                    f"Plan: {plan_name}"
                ),
                parse_mode="HTML"
            )
        except Exception:
            pass

# ============================================================
# ADMIN — KEY MINTING
# ============================================================

@owner_only
async def cmd_genkey(u, c):
    if not c.args:
        await u.message.reply_text(
            "Usage: <code>/genkey &lt;amount&gt;</code>\nExample: <code>/genkey 5</code>",
            parse_mode="HTML"
        )
        return
    try:
        amount = int(c.args[0])
    except ValueError:
        await u.message.reply_text("Invalid amount. Example: <code>/genkey 5</code>", parse_mode="HTML")
        return
    if amount < 1 or amount > 20:
        await u.message.reply_text("Amount must be between 1 and 20.", parse_mode="HTML")
        return
    try:
        keys = [f"<code>{create_key('premium')}</code>" for _ in range(amount)]
        await u.message.reply_text(
            f"🔑 <b>Generated {amount} Permanent Premium Keys</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            + "\n".join(keys) +
            f"\n\n<i>Redeem via bot: /redeem &lt;key&gt;</i>\n"
            f"<i>Or on the site: </i><a href=\"{WEB_URL}/dashboard\">{WEB_URL}/dashboard</a>",
            parse_mode="HTML",
            disable_web_page_preview=True
        )
    except Exception as e:
        await u.message.reply_text(f"⚠️ Error: {str(e)}", parse_mode="HTML")

@owner_only
async def cmd_genadminkey(u, c):
    try:
        days = int(c.args[0]) if c.args and c.args[0].isdigit() else 30
        k = create_admin_key(days)
        await u.message.reply_text(
            f"🔑 <b>Admin Key Generated</b>\n<code>{k}</code>\n\n"
            f"<b>Duration:</b> {days} days\n"
            f"<b>Usage:</b> <code>/redeemadmin {k}</code>",
            parse_mode="HTML"
        )
    except Exception as e:
        await u.message.reply_text(f"⚠️ Error: {str(e)}", parse_mode="HTML")

async def cmd_redeemadmin(u, c):
    if not c.args:
        await u.message.reply_text("Usage: <code>/redeemadmin &lt;key&gt;</code>", parse_mode="HTML")
        return
    try:
        user = get_or_create(tg=u.effective_chat.id)
        ok, msg = redeem_admin_key(user["id"], c.args[0].strip().upper())
        if ok:
            await u.message.reply_text(
                f"✅ <b>Admin access granted</b>\n\n{msg}",
                parse_mode="HTML"
            )
        else:
            await u.message.reply_text(f"❌ <b>Error</b>\n\n{msg}", parse_mode="HTML")
    except Exception as e:
        await u.message.reply_text(f"⚠️ System error: {str(e)}", parse_mode="HTML")

@owner_only
async def cmd_revokealladmins(u, c):
    try:
        revoke_admin_keys()
        await u.message.reply_text("🔒 <b>All admin keys revoked.</b>", parse_mode="HTML")
    except Exception as e:
        await u.message.reply_text(f"⚠️ Error: {str(e)}", parse_mode="HTML")

# ============================================================
# ADMIN — TIER MANAGEMENT
# ============================================================

async def cmd_makeadmin(u, c):
    if u.effective_chat.id != ADMIN_ID:
        return
    user = get_or_create(tg=u.effective_chat.id)
    with db() as conn:
        conn.execute("UPDATE users SET tier='admin' WHERE id=%s", (user["id"],))
    await u.message.reply_text("✅ Admin access granted.")

@owner_only
async def cmd_givepremium(u, c):
    if not c.args:
        await u.message.reply_text("Usage: <code>/givepremium &lt;telegram_id&gt;</code>", parse_mode="HTML")
        return
    try:
        target_tg = int(c.args[0])
    except ValueError:
        await u.message.reply_text("Invalid id.", parse_mode="HTML")
        return
    target_user = get_or_create(tg=target_tg)
    paid_until = grant_premium(target_user["id"], days=30, provider="manual")
    await u.message.reply_text(
        f"✅ Premium granted to <code>{target_tg}</code> until {paid_until}",
        parse_mode="HTML"
    )

@owner_only
async def cmd_revoke(u, c):
    if not c.args:
        await u.message.reply_text("Usage: <code>/revoke &lt;telegram_id&gt;</code>", parse_mode="HTML")
        return
    try:
        target = int(c.args[0])
    except ValueError:
        await u.message.reply_text("Invalid id.", parse_mode="HTML")
        return
    with db() as conn:
        conn.execute("UPDATE users SET tier='free', paid_until=NULL WHERE telegram_id=%s", (target,))
    await u.message.reply_text(f"✅ Revoked premium for <code>{target}</code>", parse_mode="HTML")

@owner_only
async def cmd_broadcast(u, c):
    if not c.args:
        await u.message.reply_text("Usage: <code>/broadcast &lt;message&gt;</code>", parse_mode="HTML")
        return
    msg_text = " ".join(c.args)
    with db() as conn:
        users = conn.execute(
            "SELECT DISTINCT telegram_id FROM users WHERE telegram_id IS NOT NULL"
        ).fetchall()
    count = 0
    status_msg = await u.message.reply_text("Broadcasting...", parse_mode="HTML")
    for row in users:
        try:
            await c.bot.send_message(
                chat_id=row["telegram_id"],
                text=f"📢 <b>Update</b>\n\n{msg_text}",
                parse_mode="HTML"
            )
            count += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass
    await status_msg.edit_text(f"✅ Broadcast sent to {count} users.", parse_mode="HTML")

# ============================================================
# ADMIN — TELEMETRY
# ============================================================

async def cmd_ping(u, c):
    t0 = time.time()
    msg = await u.message.reply_text("⏳ Pinging...", parse_mode="HTML")
    latency = int((time.time() - t0) * 1000)
    t1 = time.time()
    with db() as conn:
        conn.execute("SELECT 1").fetchone()
    db_latency = int((time.time() - t1) * 1000)
    await msg.edit_text(
        f"🏓 <b>Pong!</b>\n"
        f"<blockquote><b>Telegram:</b> <code>{latency}ms</code>\n"
        f"<b>Database:</b> <code>{db_latency}ms</code></blockquote>",
        parse_mode="HTML"
    )

async def cmd_stats(u, c):
    if u.effective_chat.id != ADMIN_ID:
        return
    today = datetime.date.today().isoformat()
    with db() as conn:
        total_users = conn.execute("SELECT COUNT(*) as n FROM users").fetchone()["n"]
        premium_users = conn.execute(
            "SELECT COUNT(*) as n FROM users WHERE tier='premium' OR tier='admin'"
        ).fetchone()["n"]
        q_today = conn.execute(
            "SELECT COALESCE(SUM(queries),0) as n FROM usage WHERE day=%s", (today,)
        ).fetchone()["n"]
        total_keys = conn.execute("SELECT COUNT(*) as n FROM keys").fetchone()["n"]
        redeemed_keys = conn.execute(
            "SELECT COUNT(*) as n FROM keys WHERE redeemed_at IS NOT NULL"
        ).fetchone()["n"]
    await u.message.reply_text(
        f"📊 <b>METRICS</b>\n\n"
        f"<b>Users</b>\n"
        f"<blockquote><b>Total:</b> {total_users}\n"
        f"<b>Paid:</b> {premium_users}</blockquote>\n\n"
        f"<b>Activity</b>\n"
        f"<blockquote><b>Queries today:</b> {q_today}</blockquote>\n\n"
        f"<b>Keys</b>\n"
        f"<blockquote><b>Generated:</b> {total_keys}\n"
        f"<b>Redeemed:</b> {redeemed_keys}</blockquote>",
        parse_mode="HTML"
    )

async def cmd_top(u, c):
    if u.effective_chat.id != ADMIN_ID:
        return
    with db() as conn:
        rows = conn.execute(
            "SELECT kind, COUNT(*) as n FROM history GROUP BY kind ORDER BY n DESC LIMIT 5"
        ).fetchall() if _table_exists("history") else []
    if not rows:
        await u.message.reply_text("no activity data yet.", parse_mode="HTML")
        return
    text = "🔥 <b>Top Pivot Types</b>\n━━━━━━━━━━━━━━━━━━━━\n"
    for i, r in enumerate(rows, 1):
        text += f"{i}. <code>{r['kind']}</code> — {r['n']} pivots\n"
    await u.message.reply_text(text, parse_mode="HTML")

def _table_exists(name):
    with db() as conn:
        try:
            conn.execute(f"SELECT 1 FROM {name} LIMIT 1")
            return True
        except Exception:
            return False

async def cmd_starbalance(u, c):
    if u.effective_chat.id != ADMIN_ID:
        return
    try:
        balance = await c.bot.get_my_star_balance()
        await u.message.reply_text(
            f"⭐ <b>Stars Balance:</b> <code>{balance.amount}</code>",
            parse_mode="HTML"
        )
    except Exception as e:
        await u.message.reply_text(f"Error: {e}")

async def cmd_testreceipt(u, c):
    if u.effective_chat.id != ADMIN_ID:
        return
    user = get_or_create(tg=u.effective_chat.id)
    await send_receipt(
        u, c, user,
        days=30, amount=100,
        charge_id="TEST_CHARGE_123456",
        paid_until="2026-12-31",
        key="PERM-TEST-DEMO-1234"
    )

# ============================================================
# STARTUP
# ============================================================

async def on_startup(app: Application):
    banner = (
        f"🚀 <b>VOLUME.TOOLS {VERSION}</b>\n"
        f"<b>Payment Terminal Online</b>\n\n"
        f"• bot handles payments + admin only\n"
        f"• console lives at {WEB_URL}/app\n"
        f"• keys activated on the dashboard"
    )
    try:
        await app.bot.send_message(chat_id=ADMIN_ID, text=banner, parse_mode="HTML", disable_web_page_preview=True)
    except Exception:
        pass

def build_app():
    app = Application.builder().token(TOKEN).post_init(on_startup).build()

    # Public
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("upgrade", cmd_upgrade))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("redeem", cmd_redeem))

    # Admin
    app.add_handler(CommandHandler("makeadmin", cmd_makeadmin))
    app.add_handler(CommandHandler("givepremium", cmd_givepremium))
    app.add_handler(CommandHandler("genkey", cmd_genkey))
    app.add_handler(CommandHandler("genadminkey", cmd_genadminkey))
    app.add_handler(CommandHandler("redeemadmin", cmd_redeemadmin))
    app.add_handler(CommandHandler("revoke", cmd_revoke))
    app.add_handler(CommandHandler("revokealladmins", cmd_revokealladmins))
    app.add_handler(CommandHandler("broadcast", cmd_broadcast))
    app.add_handler(CommandHandler("ping", cmd_ping))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("top", cmd_top))
    app.add_handler(CommandHandler("starbalance", cmd_starbalance))
    app.add_handler(CommandHandler("testreceipt", cmd_testreceipt))

    # Callbacks
    app.add_handler(CallbackQueryHandler(on_buy, pattern="^buy_"))
    app.add_handler(CallbackQueryHandler(on_upgrade_menu, pattern="^menu_upgrade$"))
    app.add_handler(PreCheckoutQueryHandler(on_pre))
    app.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, on_paid))

    return app

# ============================================================
# WEB SERVER — runs in same process
# ============================================================

async def run_web():
    import uvicorn
    from api.main import app as fastapi_app
    config = uvicorn.Config(
        fastapi_app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        log_level="info"
    )
    server = uvicorn.Server(config)
    await server.serve()

# ============================================================
# MAIN
# ============================================================

async def main():
    tg_app = build_app()
    await tg_app.initialize()

    try:
        await tg_app.bot.set_my_commands(
            [BotCommand(cmd, desc) for cmd, desc in USER_COMMANDS]
        )
        await tg_app.bot.set_my_commands(
            [BotCommand(cmd, desc) for cmd, desc in ADMIN_COMMANDS],
            scope=BotCommandScopeChat(chat_id=ADMIN_ID)
        )
        print(f"✅ command menus synced for {ADMIN_ID}")
    except Exception as e:
        print(f"⚠️ failed to sync command menus: {e}")

    await tg_app.start()
    await tg_app.updater.start_polling()

    web_task = asyncio.create_task(run_web())
    print(f"volume.tools up — bot polling, web on port {os.environ.get('PORT', 8000)}")

    try:
        await web_task
    finally:
        await tg_app.updater.stop()
        await tg_app.stop()
        await tg_app.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
