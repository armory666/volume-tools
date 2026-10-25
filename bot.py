import os, json, re, asyncio, time, datetime
import httpx
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice,
    BotCommand, BotCommandScopeChat
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, PreCheckoutQueryHandler,
    MessageHandler, ContextTypes, filters,
)
from core.tier import (
    init_db, get_or_create, grant_premium, tier_of, usage_today, TIERS, db,
)
from core.pivot import fan_out
from core.sources.breach import BreachEngine
from core.sources.h8mail import H8Mail
import core.sources as s

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
LAST = {}
init_db()

# --- CONFIGURATION ---
ADMIN_ID = 123456789  # PUT YOUR TELEGRAM ID HERE
YOUR_USERNAME = "YourTelegramHandle" # WITHOUT THE @

PILLAR_EMOJI = {"discord":"🎮","stealer":"🦠","breach":"🔓","iptrace":"🌐",
                "email":"📧","username":"👤","phone":"📱","roblox":"🟥","misc":"•"}

HELP = """*volume.tools* — osint pivot

/pivot <seed>     auto-detect
/email <addr>     email
/user <handle>    username
/ip <addr>        ip trace
/phone <num>      phone
/domain <d>       domain
/breach <email>   deep breach & stealer logs
/export           last result json
/upgrade          premium · 200/day, all sources
/status           tier + usage
/help             this
"""

USER_COMMANDS = [
    ("start", "start the bot"),
    ("pivot", "auto-detect and pivot"),
    ("email", "email pivot"),
    ("user", "username pivot"),
    ("ip", "ip trace"),
    ("phone", "phone pivot"),
    ("domain", "domain pivot"),
    ("breach", "deep breach & stealer logs"),
    ("history", "last 10 pivots"),
    ("summary", "summarize last result"),
    ("export", "export last result as json"),
    ("status", "show tier and usage"),
    ("upgrade", "buy premium"),
    ("help", "show help message")
]

ADMIN_COMMANDS = USER_COMMANDS + [
    ("stats", "show bot usage statistics"),
    ("top", "top 5 searched artifacts"),
    ("ping", "check bot latency"),
    ("starbalance", "check bot stars balance"),
    ("broadcast", "send a message to all users"),
    ("givepremium", "gift premium to a user ID"),
    ("revoke", "remove premium from a user"),
    ("testreceipt", "preview the payment receipt"),
    ("testlimit", "preview the free tier limit"),
    ("sources", "list active osint sources"),
    ("makeadmin", "set yourself as admin")
]

# --- SETUP & UTILS ---

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

def init_history_table():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                seed TEXT NOT NULL,
                kind TEXT NOT NULL,
                count INTEGER,
                created_at TEXT NOT NULL
            )
        """)

init_history_table()

async def save_history(user_id, seed, kind, count):
    with db() as conn:
        conn.execute(
            "INSERT INTO history(id, user_id, seed, kind, count, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (str(__import__("uuid").uuid4()), user_id, seed, kind, count,
             datetime.datetime.utcnow().isoformat())
        )
        conn.execute("""
            DELETE FROM history WHERE id NOT IN (
                SELECT id FROM history WHERE user_id=? ORDER BY created_at DESC LIMIT 10
            ) AND user_id=?
        """, (user_id, user_id))

# --- MENU PANEL ---

def main_menu():
    kb = [
        [InlineKeyboardButton("📧 Email", callback_data="menu_email"),
         InlineKeyboardButton("👤 Username", callback_data="menu_username")],
        [InlineKeyboardButton("🌐 IP Trace", callback_data="menu_ip"),
         InlineKeyboardButton("📱 Phone", callback_data="menu_phone")],
        [InlineKeyboardButton("🎮 Discord", callback_data="menu_discord"),
         InlineKeyboardButton("🟥 Roblox", callback_data="menu_roblox")],
        [InlineKeyboardButton("🦠 Breach Check", callback_data="menu_breach")],
        [InlineKeyboardButton("📊 History", callback_data="menu_history"),
         InlineKeyboardButton("💎 Upgrade", callback_data="menu_upgrade")],
    ]
    return InlineKeyboardMarkup(kb)

async def on_menu_click(u, c):
    q = u.callback_query
    await q.answer()
    action = q.data.replace("menu_", "")
    
    if action == "history":
        await cmd_history(u, c); return
    if action == "upgrade":
        await cmd_upgrade(u, c); return
    
    prompts = {
        "email": "send an email address. example: `target@example.com`",
        "username": "send a username. example: `n0cturn`",
        "ip": "send an IP. example: `1.1.1.1`",
        "phone": "send a phone number. example: `+15551234567`",
        "discord": "send a Discord ID. example: `850123456789012345`",
        "roblox": "send a Roblox username. example: `Roblox`",
        "breach": "send an email address to scan stealer logs and breaches."
    }
    
    await q.edit_message_text(
        f"*{action} pivot*\n\n{prompts.get(action, 'send your query')}\n\n"
        f"_or type /{action} <query> directly._",
        parse_mode="Markdown"
    )

# --- PIVOT LOGIC ---

async def roblox_lookup(seed):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                "https://users.roblox.com/v1/usernames/users",
                json={"usernames": [seed], "excludeBannedUsers": False}
            )
        if r.status_code != 200: return []
        d = r.json().get("data", [])
        if not d: return []
        u = d[0]
        return [{"source": "roblox", "kind": "roblox_user", "value": seed,
                 "meta": {"id": u.get("id"), "display": u.get("displayName"),
                          "name": u.get("name")}, "pillar": "roblox"}]
    except Exception:
        return []

async def run(update, seed, kind):
    user = get_or_create(tg=update.effective_chat.id)
    msg = await update.message.reply_text(f"fanning out · `{kind}`")
    
    if kind == "roblox":
        hits = await roblox_lookup(seed)
        if hits:
            data = {"tool": "volume.tools", "seed": seed, "kind": "roblox",
                    "tier": tier_of(user), "count": len(hits), "hits": hits}
        else:
            await msg.edit_text("no roblox user found."); return
    else:
        try:
            raw = await fan_out(seed, kind, user)
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
            "tier": tier_of(user), "count": len(raw),
            "hits": [{"source": h.source, "kind": h.kind,
                      "pillar": h.meta.get("pillar", "misc"),
                      "value": h.value, "meta": _clean(h.meta)} for h in raw],
        }
    
    LAST[update.effective_chat.id] = data
    await save_history(user["id"], seed, kind, data["count"])
    
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("📥 json", callback_data="exp_json"),
        InlineKeyboardButton("📊 summary", callback_data="do_summary")
    ]]) if data["hits"] else None
    await msg.edit_text(fmt(data), parse_mode="Markdown", reply_markup=kb)

async def on_summary_click(u, c):
    q = u.callback_query
    await q.answer()
    d = LAST.get(q.message.chat.id)
    if not d: return
    hits = d.get("hits", [])
    by = {}
    for h in hits: by.setdefault(h["pillar"], []).append(h)
    lines = [f"*summary* · `{d['seed']}`\n"]
    for p, hs in sorted(by.items(), key=lambda x: -len(x[1])):
        lines.append(f"• {p}: {len(hs)}")
    await q.edit_message_text("\n".join(lines), parse_mode="Markdown")

# --- CORE COMMANDS ---

async def cmd_start(u, c):
    if c.args and c.args[0] == "upgrade":
        await cmd_upgrade(u, c); return
    await u.message.reply_text(HELP, parse_mode="Markdown")
    await u.message.reply_text("Quick actions:", reply_markup=main_menu())

async def cmd_help(u, c):
    await u.message.reply_text(HELP, parse_mode="Markdown")
    await u.message.reply_text("Quick actions:", reply_markup=main_menu())

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

async def cmd_summary(u, c):
    d = LAST.get(u.effective_chat.id)
    if not d:
        await u.message.reply_text("nothing to summarize. run a pivot first.")
        return
    hits = d.get("hits", [])
    if not hits:
        await u.message.reply_text("last pivot had no hits.")
        return
    by = {}
    for h in hits: by.setdefault(h["pillar"], []).append(h)
    lines = [f"*summary* · `{d['seed']}` ({d['kind']})\n"]
    lines.append(f"total: {len(hits)} hits across {len(by)} pillars\n")
    for p, hs in sorted(by.items(), key=lambda x: -len(x[1])):
        lines.append(f"• {p}: {len(hs)}")
    await u.message.reply_text("\n".join(lines), parse_mode="Markdown")

async def cmd_history(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    with db() as conn:
        rows = conn.execute(
            "SELECT seed, kind, count, created_at FROM history "
            "WHERE user_id=? ORDER BY created_at DESC LIMIT 10",
            (user["id"],)
        ).fetchall()
    if not rows:
        await u.message.reply_text("no history yet. run a pivot first.")
        return
    lines = ["*last 10 pivots:*\n"]
    for r in rows:
        lines.append(f"`{r['kind']}` `{r['seed']}` — {r['count']} hits")
    await u.message.reply_text("\n".join(lines), parse_mode="Markdown")

async def cmd_status(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    t = tier_of(user)
    used = usage_today(user["id"])
    lim = TIERS[t]["daily"]
    await u.message.reply_text(
        f"*tier* `{t}`\n*used today* `{used}/{lim}`\n"
        f"*paid until* `{user.get('paid_until') or '—'}`",
        parse_mode="Markdown")

# --- DEEP BREACH ---

async def cmd_breach(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if tier_of(user) not in ("premium", "admin"):
        await u.message.reply_text(
            "*premium required*\n\n"
            "The Deep Breach & Stealer engine is a premium feature.\n"
            "Use /upgrade to unlock it.",
            parse_mode="Markdown")
        return

    if not c.args:
        await u.message.reply_text("usage: /breach <email>"); return
        
    seed = " ".join(c.args)
    msg = await u.message.reply_text(f"scanning breach databases for `{seed}`...")
    
    hits_engine = await BreachEngine().query(seed, "email")
    hits_h8 = await H8Mail().query(seed, "email")
    all_hits = hits_engine + hits_h8
    
    if not all_hits:
        await msg.edit_text("no breaches or stealer logs found.")
        return
        
    lines = [f"🦠 *Deep Breach Report* · `{seed}`\n"]
    
    for h in all_hits:
        if h.kind == "stealer_log":
            lines.append(f"**Infostealer Malware Detected**")
            lines.append(f"• Family: `{h.meta['family']}`")
            lines.append(f"• Computer: `{h.meta['machine']}`")
            if h.meta.get('passwords'):
                lines.append(f"• Passwords: `{', '.join(h.meta['passwords'][:3])}`")
            lines.append("")
        elif h.kind == "leakcheck_db":
            lines.append(f"**Database Breach**")
            lines.append(f"• Name: `{h.meta['database']}`")
            lines.append(f"• Date: `{h.meta['date']}`")
            lines.append("")
        elif h.kind == "h8_breach":
            lines.append(f"**h8mail Source**")
            lines.append(f"• Database: `{h.value}`")
            lines.append("")
            
    text = "\n".join(lines)
    if len(text) > 4000:
        text = text[:4000] + "\n\n_...truncated._"
    await msg.edit_text(text, parse_mode="Markdown")

# --- ADMIN COMMANDS ---

async def cmd_makeadmin(u, c):
    if u.effective_chat.id != ADMIN_ID:
        await u.message.reply_text("no."); return
    user = get_or_create(tg=u.effective_chat.id)
    with db() as conn:
        conn.execute("UPDATE users SET tier='admin' WHERE id=?", (user["id"],))
    await u.message.reply_text("✅ you are now admin.")

async def cmd_givepremium(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    if not c.args:
        await u.message.reply_text("usage: /givepremium <telegram_id>"); return
    try:
        target_tg = int(c.args[0])
    except ValueError:
        await u.message.reply_text("invalid ID."); return
    target_user = get_or_create(tg=target_tg)
    paid_until = grant_premium(target_user["id"], days=30, provider="manual")
    await u.message.reply_text(f"✅ gifted premium to {target_tg} until {paid_until}")

async def cmd_revoke(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    if not c.args:
        await u.message.reply_text("usage: /revoke <telegram_id>"); return
    target = int(c.args[0])
    with db() as conn:
        conn.execute("UPDATE users SET tier='free', paid_until=NULL WHERE telegram_id=?", (target,))
    await u.message.reply_text(f"✅ revoked premium for `{target}`", parse_mode="Markdown")

async def cmd_broadcast(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    if not c.args:
        await u.message.reply_text("usage: /broadcast <message>"); return
    msg_text = " ".join(c.args)
    with db() as conn:
        users = conn.execute("SELECT DISTINCT telegram_id FROM users WHERE telegram_id IS NOT NULL").fetchall()
    count = 0
    status_msg = await u.message.reply_text(f"Broadcasting to {len(users)} users...")
    for row in users:
        tg_id = row["telegram_id"]
        try:
            await c.bot.send_message(chat_id=tg_id, text=f"📢 **Announcement**\n\n{msg_text}", parse_mode="Markdown")
            count += 1
            await asyncio.sleep(0.05) 
        except Exception:
            pass
    await status_msg.edit_text(f"✅ Broadcast sent to {count} users.")

async def cmd_ping(u, c):
    t0 = time.time()
    msg = await u.message.reply_text("pong...")
    latency = int((time.time() - t0) * 1000)
    t1 = time.time()
    with db() as conn: conn.execute("SELECT 1").fetchone()
    db_latency = int((time.time() - t1) * 1000)
    await msg.edit_text(
        f"🏓 **Pong!**\n• Telegram: `{latency}ms`\n• Database: `{db_latency}ms`\n• Status: Online",
        parse_mode="Markdown")

async def cmd_stats(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    today = datetime.date.today().isoformat()
    with db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        premium_users = conn.execute("SELECT COUNT(*) FROM users WHERE tier='premium' OR tier='admin'").fetchone()[0]
        q_today = conn.execute("SELECT SUM(queries) FROM usage WHERE day=?", (today,)).fetchone()[0] or 0
        q_all = conn.execute("SELECT SUM(queries) FROM usage").fetchone()[0] or 0
    await u.message.reply_text(
        f"📊 **VOLUME.TOOLS STATS**\n\n"
        f"**Users**\n• Total Registered: `{total_users}`\n• Paid/Admin: `{premium_users}`\n\n"
        f"**Queries**\n• Today: `{q_today}`\n• All Time: `{q_all}`",
        parse_mode="Markdown")

async def cmd_top(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    with db() as conn:
        rows = conn.execute(
            "SELECT seed, kind, COUNT(*) as hits FROM history GROUP BY seed, kind ORDER BY hits DESC LIMIT 5"
        ).fetchall()
    if not rows:
        await u.message.reply_text("no history recorded yet."); return
    lines = ["🔥 **Top 5 Searched Artifacts**\n"]
    for i, r in enumerate(rows, 1):
        lines.append(f"{i}. `{r['kind']}` · `{r['seed']}` ({r['hits']} times)")
    await u.message.reply_text("\n".join(lines), parse_mode="Markdown")

async def cmd_sources(u, c):
    names = [getattr(x, "name", x.__name__) for x in s.REGISTRY]
    await u.message.reply_text(
        f"🔌 **Active Sources ({len(names)})**\n\n" + "\n".join(f"• `{n}`" for n in names),
        parse_mode="Markdown")

async def cmd_testreceipt(u, c):
    if u.effective_chat.id != ADMIN_ID:
        await u.message.reply_text("no."); return
    user = get_or_create(tg=u.effective_chat.id)
    await send_receipt(u, c, user, days=30, amount=100, charge_id="TEST_CHARGE_123456789", paid_until="2024-12-31")

async def cmd_testlimit(u, c):
    if u.effective_chat.id != ADMIN_ID:
        await u.message.reply_text("no."); return
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("⭐ unlock premium", callback_data="buy_month")
    ]])
    await u.message.reply_text(
        f"*free tier limit*\n\ndaily limit reached (5). upgrade for more.\n\n_premium: 200/day, all sources_",
        parse_mode="Markdown", reply_markup=kb)

async def cmd_starbalance(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    try:
        balance = await c.bot.get_my_star_balance()
        await u.message.reply_text(
            f"⭐ **Stars Balance**\n\n"
            f"Available: `{balance.amount} Stars`",
            parse_mode="Markdown"
        )
    except Exception as e:
        await u.message.reply_text(f"Error fetching balance: {e}")

# --- PAYMENTS ---

async def cmd_upgrade(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if user["tier"] == "premium" and user["paid_until"]:
        await u.message.reply_text(f"*already premium* until `{user['paid_until']}`", parse_mode="Markdown"); return
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("⭐ 100 stars · 1 month", callback_data="buy_month")],
        [InlineKeyboardButton("⭐ 800 stars · 1 year",  callback_data="buy_year")],
    ])
    await u.message.reply_text(
        "*volume.tools premium*\n\n"
        "• 200 queries/day (was 5)\n"
        "• all sources (was 6)\n"
        "• deep breach & stealer logs\n"
        "• json export\n"
        "• pay in stars — instant, no card\n",
        parse_mode="Markdown", reply_markup=kb)

async def on_buy(u, c):
    q = u.callback_query; await q.answer()
    if q.data == "buy_month": stars, days, lab = 100, 30, "1 month"
    elif q.data == "buy_year": stars, days, lab = 800, 365, "1 year"
    else: return
    await q.message.reply_invoice(
        title="volume.tools premium", description=f"premium tier · {lab}",
        payload=f"premium_{days}d", provider_token="", currency="XTR",
        prices=[LabeledPrice(lab, stars)])

async def on_pre(u, c):
    await u.pre_checkout_query.answer(ok=True)

async def on_paid(u, c):
    sp = u.message.successful_payment
    user = get_or_create(tg=u.effective_chat.id)
    days = 365 if "365" in sp.invoice_payload else 30
    paid_until = grant_premium(user["id"], days=days, provider="stars", provider_id=sp.telegram_payment_charge_id, amount=sp.total_amount)
    await send_receipt(u, c, user, days, sp.total_amount, sp.telegram_payment_charge_id, paid_until)

async def send_receipt(u, c, user, days, amount, charge_id, paid_until):
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    order_id = charge_id[-10:].upper()
    plan_name = "1 Year Premium" if days == 365 else "1 Month Premium"
    receipt = (
        f"🧾 **VOLUME.TOOLS**\n**Payment Receipt**\n\n"
        f"> **Status:** ✅ Paid\n> **Date:** `{timestamp}`\n> **Order ID:** `{order_id}`\n\n"
        f"**Account Details**\n> **Telegram ID:** `{user['telegram_id']}`\n> **Username:** @{u.effective_chat.username or 'none'}\n\n"
        f"**Subscription**\n> **Plan:** {plan_name}\n> **Amount:** {amount} Stars\n> **Expires:** `{paid_until}`\n\n"
        f"_Please save this message. If the bot resets, forward this receipt to @{YOUR_USERNAME} for manual restoration._"
    )
    await u.message.reply_text(receipt, parse_mode="Markdown")
    if u.effective_chat.id != ADMIN_ID:
        try:
            await c.bot.send_message(
                chat_id=ADMIN_ID,
                text=f"💰 **NEW SALE**\nUser: @{u.effective_chat.username or 'none'}\nID: `{u.effective_chat.id}`\nOrder: `{order_id}`\nAmount: {amount} Stars\nPlan: {plan_name}",
                parse_mode="Markdown")
        except Exception: pass

# --- APP SETUP ---

async def on_startup(app: Application):
    banner = (
        "🚀 **VOLUME.TOOLS v1.3.0**\n**System Online**\n\n"
        "• Added /starbalance telemetry\n"
        "• Admin Suite Complete\n\n_Waiting for incoming queries._"
    )
    try: await app.bot.send_message(chat_id=ADMIN_ID, text=banner, parse_mode="Markdown")
    except Exception: pass

def build_app():
    app = Application.builder().token(TOKEN).post_init(on_startup).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("pivot", cmd_pivot))
    app.add_handler(CommandHandler("export", cmd_export))
    app.add_handler(CommandHandler("summary", cmd_summary))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("upgrade", cmd_upgrade))
    app.add_handler(CommandHandler("breach", cmd_breach))
    
    app.add_handler(CommandHandler("makeadmin", cmd_makeadmin))
    app.add_handler(CommandHandler("givepremium", cmd_givepremium))
    app.add_handler(CommandHandler("revoke", cmd_revoke))
    app.add_handler(CommandHandler("broadcast", cmd_broadcast))
    app.add_handler(CommandHandler("ping", cmd_ping))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("top", cmd_top))
    app.add_handler(CommandHandler("sources", cmd_sources))
    app.add_handler(CommandHandler("testreceipt", cmd_testreceipt))
    app.add_handler(CommandHandler("testlimit", cmd_testlimit))
    app.add_handler(CommandHandler("starbalance", cmd_starbalance))
    
    for k in ("email", "username", "user", "ip", "phone", "domain", "roblox"):
        mapping = {"user": "username"}
        app.add_handler(CommandHandler(k, mk(mapping.get(k, k))))
        
    app.add_handler(CallbackQueryHandler(on_menu_click, pattern="^menu_"))
    app.add_handler(CallbackQueryHandler(on_summary_click, pattern="^do_summary$"))
    app.add_handler(CallbackQueryHandler(on_exp, pattern="^exp_json$"))
    app.add_handler(CallbackQueryHandler(on_buy, pattern="^buy_"))
    app.add_handler(PreCheckoutQueryHandler(on_pre))
    app.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, on_paid))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_auto))
    return app

async def run_web():
    import uvicorn
    from api.main import app as fastapi_app
    config = uvicorn.Config(fastapi_app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

async def main():
    tg_app = build_app()
    await tg_app.initialize()
    try:
        await tg_app.bot.set_my_commands([BotCommand(cmd, desc) for cmd, desc in USER_COMMANDS])
        await tg_app.bot.set_my_commands([BotCommand(cmd, desc) for cmd, desc in ADMIN_COMMANDS], scope=BotCommandScopeChat(chat_id=ADMIN_ID))
        print(f"✅ Admin menu synced for ID {ADMIN_ID}")
    except Exception as e:
        print(f"⚠️ Failed to sync command menus: {e}")

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
