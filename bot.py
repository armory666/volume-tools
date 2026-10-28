import os, json, re, asyncio, time, datetime
import httpx
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice,
    BotCommand, BotCommandScopeChat, WebAppInfo
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

TOKEN = os.environ["8890799273:AAGDmBhZ_z7xwW8oU2jxoocHqTzG-qE98II"]
LAST = {}
init_db()

# --- CONFIGURATION ---
ADMIN_ID = 8984546896
YOUR_USERNAME = "stomponheads"
VERSION = "v1.0"
WEB_APP_URL = "https://volume-tools-2.onrender.com" # <-- CHANGE THIS

PILLAR_EMOJI = {"discord":"🎮","stealer":"🦠","breach":"🔓","iptrace":"🌐",
                "email":"📧","username":"👤","phone":"📱","roblox":"🟥","misc":"•"}

HELP = """**VOLUME.TOOLS — INVESTIGATION CONSOLE**
_Professional OSINT Pivot Engine_

**🎯 Identity Pivots**
`/email <addr>` · Find accounts and profiles
`/user <handle>` · Trace usernames
`/phone <num>` · Carrier and region data

**🌐 Network Pivots**
`/ip <addr>` · Geolocation, ASN, and open ports
`/domain <d>` · TLS certificates and infrastructure

**🦠 Deep Intelligence** (Premium)
`/breach <email>` · Infostealer logs and database dumps

**🛠️ Utility**
`/status` · Check your tier and quota
`/upgrade` · Unlock premium access
`/history` · View your last 10 searches
"""

USER_COMMANDS = [
    ("start", "start the console"), ("pivot", "auto-detect and pivot"),
    ("email", "email pivot"), ("user", "username pivot"),
    ("ip", "ip trace"), ("phone", "phone pivot"),
    ("domain", "domain pivot"), ("breach", "deep breach & stealer logs"),
    ("history", "last 10 pivots"), ("status", "system status & usage"),
    ("upgrade", "unlock premium"), ("help", "command directory")
]

ADMIN_COMMANDS = USER_COMMANDS + [
    ("stats", "show bot usage statistics"), ("top", "top 5 searched artifacts"),
    ("ping", "check bot latency"), ("starbalance", "check bot stars balance"),
    ("broadcast", "send a message to all users"), ("givepremium", "gift premium to a user ID"),
    ("revoke", "remove premium from a user"), ("testreceipt", "preview the payment receipt"),
    ("testlimit", "preview the free tier limit"), ("sources", "list active osint sources"),
    ("makeadmin", "set yourself as admin")
]

# --- SETUP & UTILS ---

def detect_kind(seed):
    seed = seed.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", seed): return "ip"
    if re.match(r"^\d{17,19}$", seed): return "discord_id"
    email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", seed)
    if email_match: return "email"
    if re.match(r"^\+?[\d\s\-()]{7,}$", seed): return "phone"
    if "." in seed and not seed.startswith("http") and " " not in seed: return "domain"
    return "username"

def init_history_table():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL, seed TEXT NOT NULL,
                kind TEXT NOT NULL, count INTEGER, created_at TEXT NOT NULL
            )
        """)

init_history_table()

async def save_history(user_id, seed, kind, count):
    with db() as conn:
        conn.execute("INSERT INTO history(id, user_id, seed, kind, count, created_at) VALUES(?,?,?,?,?,?)",
            (str(__import__("uuid").uuid4()), user_id, seed, kind, count, datetime.datetime.utcnow().isoformat()))
        conn.execute("DELETE FROM history WHERE id NOT IN (SELECT id FROM history WHERE user_id=? ORDER BY created_at DESC LIMIT 10) AND user_id=?", (user_id, user_id))

# --- RENDER HELPERS ---

def build_result_page(data, page=0):
    hits = data.get("hits", [])
    lines = [f"🔍 **{data['kind'].upper()} SEARCH** · `{data['seed']}`\n> **Total Hits:** {data['count']}\n"]
    if not hits: return "No results found.", None
    start = page * 5
    end = start + 5
    for h in hits[start:end]:
        e = PILLAR_EMOJI.get(h["pillar"], "•")
        conf = h.get("meta", {}).get("confidence", 10)
        badge = " 🟢" if conf >= 30 else (" 🟡" if conf >= 20 else "")
        srcs = ", ".join(h.get("meta", {}).get("sources", []))
        lines.append(f"{e} **{h['pillar'].capitalize()}**{badge}")
        lines.append(f"  • `{str(h['value'])[:80]}`")
        lines.append(f"  _via: {srcs}_")
        lines.append("")
    text = "\n".join(lines)
    kb = []
    nav = []
    if page > 0: nav.append(InlineKeyboardButton("◀ Prev", callback_data=f"page_{page-1}"))
    if end < len(hits): nav.append(InlineKeyboardButton("Next ▶", callback_data=f"page_{page+1}"))
    if nav: kb.append(nav)
    kb.append([InlineKeyboardButton("📥 Export JSON", callback_data="exp_json"), InlineKeyboardButton("📊 Summarize", callback_data="do_summary")])
    return text, InlineKeyboardMarkup(kb)

def main_menu():
    kb = [
        [InlineKeyboardButton("📧 Email", callback_data="menu_email"), InlineKeyboardButton("👤 Username", callback_data="menu_username")],
        [InlineKeyboardButton("🌐 IP Trace", callback_data="menu_ip"), InlineKeyboardButton("📱 Phone", callback_data="menu_phone")],
        [InlineKeyboardButton("🎮 Discord", callback_data="menu_discord"), InlineKeyboardButton("🟥 Roblox", callback_data="menu_roblox")],
        [InlineKeyboardButton("🦠 Deep Breach", callback_data="menu_breach")],
        [InlineKeyboardButton("📊 History", callback_data="menu_history"), InlineKeyboardButton("💎 Upgrade", callback_data="menu_upgrade")],
        [InlineKeyboardButton("🚀 Open Web Console", web_app=WebAppInfo(url=WEB_APP_URL))]
    ]
    return InlineKeyboardMarkup(kb)

# --- PAGINATION HANDLERS ---

async def on_page_click(u, c):
    q = u.callback_query
    await q.answer()
    page = int(q.data.split("_")[1])
    data = LAST.get(q.message.chat.id)
    if not data: return
    text, kb = build_result_page(data, page)
    await q.edit_message_text(text, parse_mode="Markdown", reply_markup=kb)

# --- PIVOT LOGIC ---

async def roblox_lookup(seed):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post("https://users.roblox.com/v1/usernames/users", json={"usernames": [seed], "excludeBannedUsers": False})
        if r.status_code != 200: return []
        d = r.json().get("data", [])
        if not d: return []
        u = d[0]
        return [{"source": "roblox", "kind": "roblox_user", "value": seed, "meta": {"id": u.get("id"), "display": u.get("displayName"), "name": u.get("name")}, "pillar": "roblox"}]
    except Exception: return []

async def run(update, seed, kind):
    user = get_or_create(tg=update.effective_chat.id)
    msg = await update.message.reply_text(f"⏳ **Fanning out** · `{kind}` · `{seed}`", parse_mode="Markdown")
    
    if kind == "roblox":
        hits = await roblox_lookup(seed)
        if hits: data = {"tool": "volume.tools", "seed": seed, "kind": "roblox", "tier": tier_of(user), "count": len(hits), "hits": hits}
        else: await msg.edit_text("❌ No Roblox user found."); return
    else:
        try:
            raw = await fan_out(seed, kind, user)
        except PermissionError as e:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("💎 Upgrade to Premium", callback_data="buy_month")]])
            await msg.edit_text(f"🔒 **Limit Reached**\n\n{str(e)}\n\n_Upgrade for 200 daily queries._", parse_mode="Markdown", reply_markup=kb); return
        except Exception as e:
            await msg.edit_text(f"⚠️ **System Error** · `{str(e)[:100]}`", parse_mode="Markdown"); return
        
        data = {
            "tool": "volume.tools", "seed": seed, "kind": kind, "tier": tier_of(user), "count": len(raw),
            "hits": [{"source": h.source, "kind": h.kind, "pillar": h.meta.get("pillar", "misc"), "value": h.value, "meta": {k: (sorted(v) if isinstance(v, set) else v) for k, v in h.meta.items()}} for h in raw],
        }
    
    LAST[update.effective_chat.id] = data
    await save_history(user["id"], seed, kind, data["count"])
    
    text, kb = build_result_page(data, page=0)
    await msg.edit_text(text, parse_mode="Markdown", reply_markup=kb)

async def on_menu_click(u, c):
    q = u.callback_query; await q.answer()
    action = q.data.replace("menu_", "")
    if action == "history": await cmd_history(u, c); return
    if action == "upgrade": await cmd_upgrade(u, c); return
    prompts = {"email": "Enter an email address. Example: `target@example.com`", "username": "Enter a username. Example: `n0cturn`", "ip": "Enter an IP address. Example: `1.1.1.1`", "phone": "Enter a phone number. Example: `+15551234567`", "discord": "Enter a Discord ID. Example: `850123456789012345`", "roblox": "Enter a Roblox username. Example: `Roblox`", "breach": "Enter an email to scan stealer logs and breaches."}
    await q.edit_message_text(f"**{action.capitalize()} Pivot**\n\n{prompts.get(action, 'Send your query')}\n\n_Or type `/{action} <query>` directly._", parse_mode="Markdown")

async def on_summary_click(u, c):
    q = u.callback_query; await q.answer()
    d = LAST.get(q.message.chat.id)
    if not d: return
    hits = d.get("hits", [])
    by = {}
    for h in hits: by.setdefault(h["pillar"], []).append(h)
    lines = [f"📊 **Intelligence Summary** · `{d['seed']}`\n"]
    for p, hs in sorted(by.items(), key=lambda x: -len(x[1])): lines.append(f"• **{p.capitalize()}**: {len(hs)} hits")
    await q.edit_message_text("\n".join(lines), parse_mode="Markdown")

# --- CORE COMMANDS ---

async def cmd_start(u, c):
    if c.args and c.args[0] == "upgrade": await cmd_upgrade(u, c); return
    user = get_or_create(tg=u.effective_chat.id); t = tier_of(user)
    welcome = f"🌐 **VOLUME.TOOLS** {VERSION}\n_Professional OSINT Console_\n\n> **Account Tier:** `{t.upper()}`\n> **System Status:** 🟢 Online\n\nSend a target below or use the `/` menu."
    await u.message.reply_text(welcome, parse_mode="Markdown")
    await u.message.reply_text("**Quick Actions:**", reply_markup=main_menu(), parse_mode="Markdown")

async def cmd_help(u, c): await u.message.reply_text(HELP, parse_mode="Markdown"); await u.message.reply_text("**Quick Actions:**", reply_markup=main_menu(), parse_mode="Markdown")
async def cmd_pivot(u, c):
    if not c.args: await u.message.reply_text("Usage: `/pivot <target>`", parse_mode="Markdown"); return
    s = " ".join(c.args); await run(u, s, detect_kind(s))
def mk(kind):
    async def h(u, c):
        if not c.args: await u.message.reply_text(f"Usage: `/{kind} <target>`", parse_mode="Markdown"); return
        await run(u, " ".join(c.args), kind)
    return h
async def cmd_auto(u, c):
    t = (u.message.text or "").strip()
    if not t or t.startswith("/"): return
    await run(u, t, detect_kind(t))
async def cmd_export(u, c):
    d = LAST.get(u.effective_chat.id)
    if not d: await u.message.reply_text("No recent data to export."); return
    fn = f"volume_{d['kind']}_{d['seed']}.json"; await u.message.reply_document(document=json.dumps(d, indent=2).encode(), filename=fn)
async def on_exp(u, c):
    q = u.callback_query; await q.answer(); d = LAST.get(q.message.chat.id)
    if not d: await q.edit_message_text("Export expired."); return
    await q.message.reply_document(document=json.dumps(d, indent=2).encode(), filename=f"volume_{d['kind']}.json")
async def cmd_history(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    with db() as conn: rows = conn.execute("SELECT seed, kind, count, created_at FROM history WHERE user_id=? ORDER BY created_at DESC LIMIT 10", (user["id"],)).fetchall()
    if not rows: await u.message.reply_text("No recent searches."); return
    lines = ["📊 **Recent Investigations**\n"]
    for r in rows: lines.append(f"• `{r['kind']}` · `{r['seed']}` ({r['count']} hits)")
    await u.message.reply_text("\n".join(lines), parse_mode="Markdown")
async def cmd_status(u, c):
    user = get_or_create(tg=u.effective_chat.id); t = tier_of(user); used = usage_today(user["id"]); lim = TIERS[t]["daily"]
    status = f"🟢 **SYSTEM ONLINE**\n\n**Account**\n> **ID:** `{user['telegram_id']}`\n> **Tier:** `{t.upper()}`\n> **Quota:** `{used}/{lim}`\n> **Expires:** `{user.get('paid_until') or 'N/A'}`\n\n**Global Status**\n> **Latency:** 🟢 Nominal\n> **Sources:** 🟢 10 Active"
    await u.message.reply_text(status, parse_mode="Markdown")
async def cmd_breach(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if tier_of(user) not in ("premium", "admin"): await u.message.reply_text("🔒 **Premium Feature**\n\nThe Deep Breach & Stealer engine is reserved for Premium users.\nUse /upgrade to unlock it.", parse_mode="Markdown"); return
    if not c.args: await u.message.reply_text("Usage: `/breach <email>`", parse_mode="Markdown"); return
    seed = " ".join(c.args); msg = await u.message.reply_text(f"🦠 **Scanning breach databases** · `{seed}`", parse_mode="Markdown")
    hits_engine = await BreachEngine().query(seed, "email"); hits_h8 = await H8Mail().query(seed, "email"); all_hits = hits_engine + hits_h8
    if not all_hits: await msg.edit_text("✅ **Clean** · No stealer logs or breaches found."); return
    lines = [f"🦠 **Deep Breach Report** · `{seed}`\n"]
    for h in all_hits:
        if h.kind == "stealer_log":
            lines.append(f"⚠️ **Infostealer Malware**"); lines.append(f"> Family: `{h.meta['family']}`"); lines.append(f"> Computer: `{h.meta['machine']}`")
            if h.meta.get('passwords'): lines.append(f"> Passwords: `{', '.join(h.meta['passwords'][:3])}`")
            lines.append("")
        elif h.kind == "leakcheck_db":
            lines.append(f"🔓 **Database Breach**"); lines.append(f"> Name: `{h.meta['database']}`"); lines.append(f"> Date: `{h.meta['date']}`"); lines.append("")
        elif h.kind == "h8_breach":
            lines.append(f"🔓 **h8mail Source**"); lines.append(f"> Database: `{h.value}`"); lines.append("")
    text = "\n".join(lines)
    if len(text) > 4000: text = text[:4000] + "\n\n_...truncated._"
    await msg.edit_text(text, parse_mode="Markdown")

# --- ADMIN COMMANDS ---

async def cmd_makeadmin(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    user = get_or_create(tg=u.effective_chat.id)
    with db() as conn: conn.execute("UPDATE users SET tier='admin' WHERE id=?", (user["id"],))
    await u.message.reply_text("✅ Admin access granted.")
async def cmd_givepremium(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    if not c.args: await u.message.reply_text("Usage: `/givepremium <id>`", parse_mode="Markdown"); return
    try: target_tg = int(c.args[0])
    except ValueError: return
    target_user = get_or_create(tg=target_tg); paid_until = grant_premium(target_user["id"], days=30, provider="manual")
    await u.message.reply_text(f"✅ Premium granted to `{target_tg}` until {paid_until}")
async def cmd_revoke(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    if not c.args: return
    target = int(c.args[0])
    with db() as conn: conn.execute("UPDATE users SET tier='free', paid_until=NULL WHERE telegram_id=?", (target,))
    await u.message.reply_text(f"✅ Revoked premium for `{target}`", parse_mode="Markdown")
async def cmd_broadcast(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    if not c.args: return
    msg_text = " ".join(c.args)
    with db() as conn: users = conn.execute("SELECT DISTINCT telegram_id FROM users WHERE telegram_id IS NOT NULL").fetchall()
    count = 0; status_msg = await u.message.reply_text(f"Broadcasting...")
    for row in users:
        try: await c.bot.send_message(chat_id=row["telegram_id"], text=f"📢 **Update**\n\n{msg_text}", parse_mode="Markdown"); count += 1; await asyncio.sleep(0.05) 
        except Exception: pass
    await status_msg.edit_text(f"✅ Broadcast sent to {count} users.")
async def cmd_ping(u, c):
    t0 = time.time(); msg = await u.message.reply_text("⏳ Pinging..."); latency = int((time.time() - t0) * 1000); t1 = time.time()
    with db() as conn: conn.execute("SELECT 1").fetchone()
    db_latency = int((time.time() - t1) * 1000)
    await msg.edit_text(f"🏓 **Pong!**\n> Telegram: `{latency}ms`\n> Database: `{db_latency}ms`", parse_mode="Markdown")
async def cmd_stats(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    today = datetime.date.today().isoformat()
    with db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        premium_users = conn.execute("SELECT COUNT(*) FROM users WHERE tier='premium' OR tier='admin'").fetchone()[0]
        q_today = conn.execute("SELECT SUM(queries) FROM usage WHERE day=?", (today,)).fetchone()[0] or 0
    await u.message.reply_text(f"📊 **Daily Metrics**\n> Users: `{total_users}`\n> Paid: `{premium_users}`\n> Queries Today: `{q_today}`", parse_mode="Markdown")
async def cmd_top(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    with db() as conn: rows = conn.execute("SELECT seed, kind, COUNT(*) as hits FROM history GROUP BY seed, kind ORDER BY hits DESC LIMIT 5").fetchall()
    if not rows: return
    lines = ["🔥 **Top Targets**\n"]
    for i, r in enumerate(rows, 1): lines.append(f"{i}. `{r['kind']}` · `{r['seed']}` ({r['hits']})")
    await u.message.reply_text("\n".join(lines), parse_mode="Markdown")
async def cmd_sources(u, c):
    names = [getattr(x, "name", x.__name__) for x in s.REGISTRY]
    await u.message.reply_text(f"🔌 **Active Sources**\n" + "\n".join(f"• `{n}`" for n in names), parse_mode="Markdown")
async def cmd_testreceipt(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    user = get_or_create(tg=u.effective_chat.id)
    await send_receipt(u, c, user, days=30, amount=100, charge_id="TEST_CHARGE", paid_until="2024-12-31")
async def cmd_testlimit(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("💎 Upgrade", callback_data="buy_month")]])
    await u.message.reply_text("🔒 **Limit Reached**\n\nUpgrade to continue.", parse_mode="Markdown", reply_markup=kb)
async def cmd_starbalance(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    try:
        balance = await c.bot.get_my_star_balance()
        await u.message.reply_text(f"⭐ **Stars Balance:** `{balance.amount}`", parse_mode="Markdown")
    except Exception as e: await u.message.reply_text(f"Error: {e}")

# --- PAYMENTS ---

async def cmd_upgrade(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if user["tier"] == "premium" and user["paid_until"]: await u.message.reply_text(f"💎 **Already Premium**\nExpires: `{user['paid_until']}`", parse_mode="Markdown"); return
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("⭐ 100 Stars / 1 Month", callback_data="buy_month")], [InlineKeyboardButton("⭐ 800 Stars / 1 Year",  callback_data="buy_year")]])
    await u.message.reply_text("💎 **VOLUME.TOOLS PREMIUM**\n\n> 200 queries/day (was 5)\n> All sources (was 6)\n> Deep breach & stealer logs\n> JSON export\n\n_Instant activation via Telegram Stars._", parse_mode="Markdown", reply_markup=kb)
async def on_buy(u, c):
    q = u.callback_query; await q.answer()
    if q.data == "buy_month": stars, days, lab = 100, 30, "1 Month"
    elif q.data == "buy_year": stars, days, lab = 800, 365, "1 Year"
    else: return
    await q.message.reply_invoice(title="volume.tools premium", description=f"Premium Tier · {lab}", payload=f"premium_{days}d", provider_token="", currency="XTR", prices=[LabeledPrice(lab, stars)])
async def on_pre(u, c): await u.pre_checkout_query.answer(ok=True)
async def on_paid(u, c):
    sp = u.message.successful_payment; user = get_or_create(tg=u.effective_chat.id); days = 365 if "365" in sp.invoice_payload else 30
    paid_until = grant_premium(user["id"], days=days, provider="stars", provider_id=sp.telegram_payment_charge_id, amount=sp.total_amount)
    await send_receipt(u, c, user, days, sp.total_amount, sp.telegram_payment_charge_id, paid_until)
async def send_receipt(u, c, user, days, amount, charge_id, paid_until):
    now = datetime.datetime.now(datetime.timezone.utc); timestamp = now.strftime("%Y-%m-%d %H:%M UTC"); order_id = charge_id[-10:].upper(); plan_name = "1 Year Premium" if days == 365 else "1 Month Premium"
    receipt = f"🧾 **VOLUME.TOOLS**\n**Payment Receipt**\n\n> **Status:** ✅ Paid\n> **Date:** `{timestamp}`\n> **Order ID:** `{order_id}`\n\n**Account Details**\n> **Telegram ID:** `{user['telegram_id']}`\n> **Username:** @{u.effective_chat.username or 'none'}\n\n**Subscription**\n> **Plan:** {plan_name}\n> **Amount:** {amount} Stars\n> **Expires:** `{paid_until}`\n\n_Please save this message. If the bot resets, forward this receipt to @{YOUR_USERNAME} for manual restoration._"
    await u.message.reply_text(receipt, parse_mode="Markdown")
    if u.effective_chat.id != ADMIN_ID:
        try: await c.bot.send_message(chat_id=ADMIN_ID, text=f"💰 **NEW SALE**\nUser: @{u.effective_chat.username or 'none'}\nID: `{u.effective_chat.id}`\nOrder: `{order_id}`\nAmount: {amount} Stars\nPlan: {plan_name}", parse_mode="Markdown")
        except Exception: pass

# --- APP SETUP ---

async def on_startup(app: Application):
    banner = f"🚀 **VOLUME.TOOLS {VERSION}**\n**System Online**\n\n• Web App Link Added\n• Pagination UI Added"
    try: await app.bot.send_message(chat_id=ADMIN_ID, text=banner, parse_mode="Markdown")
    except Exception: pass

def build_app():
    app = Application.builder().token(TOKEN).post_init(on_start
