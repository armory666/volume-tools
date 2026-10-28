import os, json, re, asyncio, time, datetime, httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice, BotCommand, BotCommandScopeChat, WebAppInfo
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, PreCheckoutQueryHandler, MessageHandler, ContextTypes, filters
from core.tier import init_db, get_or_create, grant_premium, tier_of, usage_today, TIERS, db, create_key, redeem_key, create_admin_key, redeem_admin_key, revoke_admin_keys, tier_of_admin_safe
from core.pivot import fan_out
from core.sources.breach import BreachEngine
from core.sources.h8mail import H8Mail
from core.discord_tools import check_discord_username, check_username_batch, check_vanity, validate_token, get_token_info
import core.sources as s

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
LAST = {}
init_db()

ADMIN_ID = 8984546896
YOUR_USERNAME = "stomponheads"
VERSION = "v2.1.0"
WEB_APP_URL = "https://volume-tools-2.onrender.com"

PILLAR_EMOJI = {"discord":"🎮","stealer":"🦠","breach":"🔓","iptrace":"🌐","email":"📧","username":"👤","phone":"📱","roblox":"🟥","misc":"•"}

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

**💎 Key System**
`/redeem <key>` · Unlock premium with a key

**🎮 Discord Tools**
`/namecheck <user>` · Check username availability
`/namebulk <u1,u2>` · Check multiple usernames
`/vanity <code>` · Check server vanity URL
`/check <token>` · Validate a Discord token

**🛠️ Utility**
`/status` · Check your tier and quota
`/upgrade` · Unlock premium access
`/history` · View your last 10 searches
"""

USER_COMMANDS = [
    ("start", "start the console"), ("pivot", "auto-detect and pivot"), ("email", "email pivot"), 
    ("user", "username pivot"), ("ip", "ip trace"), ("phone", "phone pivot"), ("domain", "domain pivot"), 
    ("breach", "deep breach & stealer logs"), ("namecheck", "check discord username"), 
    ("namebulk", "bulk username check"), ("vanity", "check discord vanity"), ("check", "validate discord token"), 
    ("redeem", "redeem a premium key"), ("history", "last 10 pivots"), ("status", "system status & usage"), 
    ("upgrade", "unlock premium"), ("help", "command directory")
]

ADMIN_COMMANDS = USER_COMMANDS + [
    ("genkey", "generate a premium key"), ("genadminkey", "generate a temp admin key"), 
    ("revokealladmins", "demote all admins except owner"), ("stats", "show bot usage statistics"), 
    ("top", "top 5 searched artifacts"), ("ping", "check bot latency"), ("starbalance", "check bot stars balance"), 
    ("broadcast", "send a message to all users"), ("givepremium", "gift premium to a user ID"), 
    ("revoke", "remove premium from a user"), ("testreceipt", "preview the payment receipt"), 
    ("testlimit", "preview the free tier limit"), ("sources", "list active osint sources"), 
    ("makeadmin", "set yourself as admin")
]

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
        conn.execute("CREATE TABLE IF NOT EXISTS history (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, seed TEXT NOT NULL, kind TEXT NOT NULL, count INTEGER, created_at TEXT NOT NULL)")

init_history_table()

async def save_history(user_id, seed, kind, count):
    with db() as conn:
        conn.execute("INSERT INTO history(id, user_id, seed, kind, count, created_at) VALUES(?,?,?,?,?,?)", (str(__import__("uuid").uuid4()), user_id, seed, kind, count, datetime.datetime.utcnow().isoformat()))
        conn.execute("DELETE FROM history WHERE id NOT IN (SELECT id FROM history WHERE user_id=? ORDER BY created_at DESC LIMIT 10) AND user_id=?", (user_id, user_id))

def build_result_page(data, page=0):
    hits = data.get("hits", [])
    if not hits: return "❌ <b>No results found.</b>", None
    text = f"🔍 <b>{data['kind'].upper()} PIVOT</b>\n<code>{data['seed']}</code>\n━━━━━━━━━━━━━━━━━━━━\n<b>{data['count']}</b> total hits across {len(set(h['pillar'] for h in hits))} pillars.\n\n"
    start = page * 5
    end = start + 5
    for h in hits[start:end]:
        e = PILLAR_EMOJI.get(h["pillar"], "•")
        conf = h.get("meta", {}).get("confidence", 10)
        badge = "🟢" if conf >= 30 else ("🟡" if conf >= 20 else "⚪")
        srcs = ", ".join(h.get("meta", {}).get("sources", []))
        text += f"{e} <b>{h['pillar'].capitalize()}</b> {badge}\n  └ <code>{str(h['value'])[:100]}</code>\n  <i>via {srcs}</i>\n\n"
    text += f"━━━━━━━━━━━━━━━━━━━━\n<i>Page {page + 1} · Tier: {data.get('tier', 'free').upper()}</i>"
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

async def on_page_click(u, c):
    q = u.callback_query; await q.answer()
    page = int(q.data.split("_")[1])
    data = LAST.get(q.message.chat.id)
    if not data: return
    text, kb = build_result_page(data, page)
    await q.edit_message_text(text, parse_mode="HTML", reply_markup=kb)

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
    msg = await update.message.reply_text(f"⏳ <b>Fanning out</b> · <code>{kind}</code> · <code>{seed}</code>", parse_mode="HTML")
    if kind == "roblox":
        hits = await roblox_lookup(seed)
        if hits: data = {"tool": "volume.tools", "seed": seed, "kind": "roblox", "tier": tier_of(user), "count": len(hits), "hits": hits}
        else: await msg.edit_text("❌ <b>No Roblox user found.</b>", parse_mode="HTML"); return
    else:
        try:
            raw = await fan_out(seed, kind, user)
        except PermissionError as e:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("💎 Upgrade to Premium", callback_data="buy_month")]])
            await msg.edit_text(f"🔒 <b>Limit Reached</b>\n\n{str(e)}\n\n<i>Upgrade for 200 daily queries.</i>", parse_mode="HTML", reply_markup=kb); return
        except Exception as e:
            await msg.edit_text(f"⚠️ <b>System Error</b> · <code>{str(e)[:100]}</code>", parse_mode="HTML"); return
        data = {"tool": "volume.tools", "seed": seed, "kind": kind, "tier": tier_of(user), "count": len(raw), "hits": [{"source": h.source, "kind": h.kind, "pillar": h.meta.get("pillar", "misc"), "value": h.value, "meta": {k: (sorted(v) if isinstance(v, set) else v) for k, v in h.meta.items()}} for h in raw]}
    LAST[update.effective_chat.id] = data
    await save_history(user["id"], seed, kind, data["count"])
    text, kb = build_result_page(data, page=0)
    await msg.edit_text(text, parse_mode="HTML", reply_markup=kb)

async def on_menu_click(u, c):
    q = u.callback_query; await q.answer()
    action = q.data.replace("menu_", "")
    if action == "history": await cmd_history(u, c); return
    if action == "upgrade": await cmd_upgrade(u, c); return
    prompts = {"email": "Enter an email address. Example: <code>target@example.com</code>", "username": "Enter a username. Example: <code>n0cturn</code>", "ip": "Enter an IP address. Example: <code>1.1.1.1</code>", "phone": "Enter a phone number. Example: <code>+15551234567</code>", "discord": "Enter a Discord ID. Example: <code>850123456789012345</code>", "roblox": "Enter a Roblox username. Example: <code>Roblox</code>", "breach": "Enter an email to scan stealer logs and breaches."}
    await q.edit_message_text(f"<b>{action.capitalize()} Pivot</b>\n\n{prompts.get(action, 'Send your query')}\n\n<i>Or type /{action} &lt;query&gt; directly.</i>", parse_mode="HTML")

async def on_summary_click(u, c):
    q = u.callback_query; await q.answer()
    d = LAST.get(q.message.chat.id)
    if not d: return
    hits = d.get("hits", [])
    by = {}
    for h in hits: by.setdefault(h["pillar"], []).append(h)
    text = f"📊 <b>Intelligence Summary</b>\n<code>{d['seed']}</code>\n━━━━━━━━━━━━━━━━━━━━\n"
    for p, hs in sorted(by.items(), key=lambda x: -len(x[1])): text += f"• <b>{p.capitalize()}</b>: {len(hs)} hits\n"
    await q.edit_message_text(text, parse_mode="HTML")

async def cmd_start(u, c):
    if c.args and c.args[0] == "upgrade": await cmd_upgrade(u, c); return
    user = get_or_create(tg=u.effective_chat.id); t = tier_of(user)
    welcome = f"🌐 <b>VOLUME.TOOLS</b> {VERSION}\n<i>Professional OSINT Console</i>\n\n<blockquote><b>Account Tier:</b> <code>{t.upper()}</code>\n<b>System Status:</b> 🟢 Online</blockquote>\nSend a target below or use the menu."
    await u.message.reply_text(welcome, parse_mode="HTML")
    await u.message.reply_text("<b>Quick Actions:</b>", reply_markup=main_menu(), parse_mode="HTML")

async def cmd_help(u, c): 
    await u.message.reply_text(HELP, parse_mode="Markdown"); 
    await u.message.reply_text("<b>Quick Actions:</b>", reply_markup=main_menu(), parse_mode="HTML")

async def cmd_pivot(u, c):
    if not c.args: await u.message.reply_text("Usage: <code>/pivot &lt;target&gt;</code>", parse_mode="HTML"); return
    s = " ".join(c.args); await run(u, s, detect_kind(s))

def mk(kind):
    async def h(u, c):
        if not c.args: await u.message.reply_text(f"Usage: <code>/{kind} &lt;target&gt;</code>", parse_mode="HTML"); return
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
    text = "📊 <b>Recent Investigations</b>\n━━━━━━━━━━━━━━━━━━━━\n"
    for r in rows: text += f"• <code>{r['kind']}</code> · <code>{r['seed']}</code> ({r['count']} hits)\n"
    await u.message.reply_text(text, parse_mode="HTML")

async def cmd_status(u, c):
    user = get_or_create(tg=u.effective_chat.id); t = tier_of_admin_safe(user, ADMIN_ID); used = usage_today(user["id"]); lim = TIERS[t]["daily"]
    status = f"🟢 <b>SYSTEM ONLINE</b>\n\n<b>Account</b>\n<blockquote><b>ID:</b> <code>{user['telegram_id']}</code>\n<b>Tier:</b> <code>{t.upper()}</code>\n<b>Quota:</b> <code>{used}/{lim}</code>\n<b>Expires:</b> <code>{user.get('paid_until') or 'N/A'}</code></blockquote>\n<b>Global Status</b>\n<blockquote><b>Latency:</b> 🟢 Nominal\n<b>Sources:</b> 🟢 15 Active</blockquote>"
    await u.message.reply_text(status, parse_mode="HTML")

async def cmd_breach(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if tier_of(user) not in ("premium", "admin"): await u.message.reply_text("🔒 <b>Premium Feature</b>\n\nThe Deep Breach engine is reserved for Premium users.\nUse /upgrade to unlock it.", parse_mode="HTML"); return
    if not c.args: await u.message.reply_text("Usage: <code>/breach &lt;email&gt;</code>", parse_mode="HTML"); return
    seed = " ".join(c.args); msg = await u.message.reply_text(f"🦠 <b>Scanning breach databases</b> · <code>{seed}</code>", parse_mode="HTML")
    hits_engine = await BreachEngine().query(seed, "email"); hits_h8 = await H8Mail().query(seed, "email"); all_hits = hits_engine + hits_h8
    if not all_hits: await msg.edit_text("✅ <b>Clean</b> · No stealer logs or breaches found.", parse_mode="HTML"); return
    text = f"🦠 <b>Deep Breach Report</b> · <code>{seed}</code>\n━━━━━━━━━━━━━━━━━━━━\n"
    for h in all_hits:
        if h.kind == "stealer_log":
            text += f"⚠️ <b>Infostealer Malware</b>\n<blockquote><b>Family:</b> <code>{h.meta['family']}</code>\n<b>Computer:</b> <code>{h.meta['machine']}</code>"
            if h.meta.get('passwords'): text += f"\n<b>Passwords:</b> <code>{', '.join(h.meta['passwords'][:3])}</code>"
            text += "</blockquote>\n"
        elif h.kind == "leakcheck_db":
            text += f"🔓 <b>Database Breach</b>\n<blockquote><b>Name:</b> <code>{h.meta['database']}</code>\n<b>Date:</b> <code>{h.meta['date']}</code></blockquote>\n"
        elif h.kind == "h8_breach":
            text += f"🔓 <b>h8mail Source</b>\n<blockquote><b>Database:</b> <code>{h.value}</code></blockquote>\n"
    if len(text) > 4000: text = text[:4000] + "\n\n<i>...truncated.</i>"
    await msg.edit_text(text, parse_mode="HTML")

async def cmd_namecheck(u, c):
    if not c.args: await u.message.reply_text("Usage: <code>/namecheck &lt;username&gt;</code>", parse_mode="HTML"); return
    msg = await u.message.reply_text(f"🔍 Checking <code>@{c.args[0]}</code>...", parse_mode="HTML")
    status, detail = await check_discord_username(c.args[0])
    if status == "AVAILABLE": await msg.edit_text(f"🟢 <b>Available</b>\n\n{detail}", parse_mode="HTML")
    elif status == "TAKEN": await msg.edit_text(f"🔴 <b>Taken</b>\n\n{detail}", parse_mode="HTML")
    elif status == "INVALID": await msg.edit_text(f"⚠️ <b>Invalid Format</b>\n\n{detail}", parse_mode="HTML")
    else: await msg.edit_text(f"❌ <b>{status}</b>\n\n{detail}", parse_mode="HTML")

async def cmd_namebulk(u, c):
    if not c.args: await u.message.reply_text("Usage: <code>/namebulk &lt;user1,user2&gt;</code>", parse_mode="HTML"); return
    usernames = [x.strip() for x in " ".join(c.args).split(",") if x.strip()]
    if len(usernames) > 10: await u.message.reply_text("Max 10 usernames per check.", parse_mode="HTML"); return
    msg = await u.message.reply_text(f"🔍 Checking {len(usernames)} usernames...", parse_mode="HTML")
    results = await check_username_batch(usernames)
    text = "📊 <b>Username Check Results</b>\n━━━━━━━━━━━━━━━━━━━━\n"
    for uname, status in results:
        emoji = "🟢" if status == "AVAILABLE" else ("🔴" if status == "TAKEN" else "⚠️")
        text += f"{emoji} <code>@{uname}</code> — {status.capitalize()}\n"
    await msg.edit_text(text, parse_mode="HTML")

async def cmd_vanity(u, c):
    if not c.args: await u.message.reply_text("Usage: <code>/vanity &lt;code&gt;</code>", parse_mode="HTML"); return
    code = c.args[0]; msg = await u.message.reply_text(f"🔍 Checking vanity <code>{code}</code>...", parse_mode="HTML")
    status, detail = await check_vanity(code)
    if status == "AVAILABLE": await msg.edit_text(f"🟢 <b>Vanity Available</b>\n\n<code>discord.gg/{code}</code> is untaken.", parse_mode="HTML")
    elif status == "TERMINATED": await msg.edit_text(f"🔴 <b>Terminated</b>\n\n{detail}", parse_mode="HTML")
    elif status == "TAKEN": await msg.edit_text(f"🔒 <b>Vanity Taken</b>\n\n{detail}", parse_mode="HTML")
    else: await msg.edit_text(f"⚠️ {detail}", parse_mode="HTML")

async def cmd_check(u, c):
    if not c.args: await u.message.reply_text("Usage: <code>/check &lt;token&gt;</code>", parse_mode="HTML"); return
    msg = await u.message.reply_text("⏳ Validating token...", parse_mode="HTML")
    is_valid, detail = await validate_token(c.args[0])
    await msg.edit_text(f"{'✅' if is_valid else '❌'} <b>Token Check</b>\n\n{detail}", parse_mode="HTML")

async def cmd_redeem(u, c):
    if not c.args: await u.message.reply_text("Usage: <code>/redeem &lt;key&gt;</code>", parse_mode="HTML"); return
    user = get_or_create(tg=u.effective_chat.id); success, msg = redeem_key(user["id"], c.args[0].strip().upper())
    if success: await u.message.reply_text(f"✅ <b>Key Redeemed</b>\n\n{msg}\n\nYou now have Premium access.", parse_mode="HTML")
    else: await u.message.reply_text(f"❌ <b>Error</b>\n\n{msg}", parse_mode="HTML")

async def cmd_genkey(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    if len(c.args) < 2: await u.message.reply_text("Usage: <code>/genkey &lt;amount&gt; &lt;duration&gt;</code>\nExample: <code>/genkey 5 30d</code>", parse_mode="HTML"); return
    try: amount = int(c.args[0]); duration_str = c.args[1]
    except ValueError: await u.message.reply_text("Invalid amount. Example: <code>/genkey 5 30d</code>", parse_mode="HTML"); return
    if amount < 1 or amount > 10: await u.message.reply_text("Amount must be between 1 and 10.", parse_mode="HTML"); return
    from core.tier import parse_duration
    days = parse_duration(duration_str)
    if not days: await u.message.reply_text("Invalid duration. Use d, w, m, or y. Example: <code>30d</code>", parse_mode="HTML"); return
    keys = [f"<code>{create_key(None, days)}</code>" for _ in range(amount)]
    await u.message.reply_text(f"🔑 <b>Generated {amount} Keys</b>\n<b>Duration:</b> {days} days\n━━━━━━━━━━━━━━━━━━━━\n" + "\n".join(keys) + "\n\n<i>Users redeem with /redeem &lt;key&gt;</i>", parse_mode="HTML")

async def cmd_genadminkey(u, c):
    if u.effective_chat.id != ADMIN_ID: 
        await u.message.reply_text("❌ Unauthorized. Only the owner can generate admin keys.")
        return
    days = int(c.args[0]) if c.args and c.args[0].isdigit() else 30
    from core.tier import create_admin_key
    k = create_admin_key(days)
    await u.message.reply_text(
        f"🔑 <b>Admin Key Generated</b>\n"
        f"<code>{k}</code>\n\n"
        f"<b>Duration:</b> {days} days\n"
        f"<b>Usage:</b> <code>/redeemadmin {k}</code>",
        parse_mode="HTML"
    )

async def cmd_redeemadmin(u, c):
    if not c.args: await u.message.reply_text("Usage: <code>/redeemadmin &lt;key&gt;</code>", parse_mode="HTML"); return
    user = get_or_create(tg=u.effective_chat.id)
    ok, msg = redeem_admin_key(user["id"], c.args[0].strip().upper())
    if ok: await u.message.reply_text(f"✅ <b>Admin granted</b>\n\nExpires: <code>{msg}</code>", parse_mode="HTML")
    else: await u.message.reply_text(f"❌ <b>Error</b>\n\n{msg}", parse_mode="HTML")

async def cmd_revokealladmins(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    revoke_admin_keys()
    await u.message.reply_text("🔒 <b>All admin keys revoked.</b>", parse_mode="HTML")

async def cmd_makeadmin(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    user = get_or_create(tg=u.effective_chat.id)
    with db() as conn: conn.execute("UPDATE users SET tier='admin' WHERE id=?", (user["id"],))
    await u.message.reply_text("✅ Admin access granted.")

async def cmd_givepremium(u, c):
    if u.effective_chat.id != ADMIN_ID or not c.args: return
    try: target_tg = int(c.args[0])
    except ValueError: return
    target_user = get_or_create(tg=target_tg); paid_until = grant_premium(target_user["id"], days=30, provider="manual")
    await u.message.reply_text(f"✅ Premium granted to <code>{target_tg}</code> until {paid_until}", parse_mode="HTML")

async def cmd_revoke(u, c):
    if u.effective_chat.id != ADMIN_ID or not c.args: return
    target = int(c.args[0])
    with db() as conn: conn.execute("UPDATE users SET tier='free', paid_until=NULL WHERE telegram_id=?", (target,))
    await u.message.reply_text(f"✅ Revoked premium for <code>{target}</code>", parse_mode="HTML")

async def cmd_broadcast(u, c):
    if u.effective_chat.id != ADMIN_ID or not c.args: return
    msg_text = " ".join(c.args)
    with db() as conn: users = conn.execute("SELECT DISTINCT telegram_id FROM users WHERE telegram_id IS NOT NULL").fetchall()
    count = 0; status_msg = await u.message.reply_text("Broadcasting...", parse_mode="HTML")
    for row in users:
        try: await c.bot.send_message(chat_id=row["telegram_id"], text=f"📢 <b>Update</b>\n\n{msg_text}", parse_mode="HTML"); count += 1; await asyncio.sleep(0.05) 
        except Exception: pass
    await status_msg.edit_text(f"✅ Broadcast sent to {count} users.", parse_mode="HTML")

async def cmd_ping(u, c):
    t0 = time.time(); msg = await u.message.reply_text("⏳ Pinging...", parse_mode="HTML"); latency = int((time.time() - t0) * 1000); t1 = time.time()
    with db() as conn: conn.execute("SELECT 1").fetchone()
    db_latency = int((time.time() - t1) * 1000)
    await msg.edit_text(f"🏓 <b>Pong!</b>\n<blockquote><b>Telegram:</b> <code>{latency}ms</code>\n<b>Database:</b> <code>{db_latency}ms</code></blockquote>", parse_mode="HTML")

async def cmd_stats(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    today = datetime.date.today().isoformat()
    with db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        premium_users = conn.execute("SELECT COUNT(*) FROM users WHERE tier='premium' OR tier='admin'").fetchone()[0]
        q_today = conn.execute("SELECT SUM(queries) FROM usage WHERE day=?", (today,)).fetchone()[0] or 0
    await u.message.reply_text(f"📊 <b>Daily Metrics</b>\n<blockquote><b>Users:</b> {total_users}\n<b>Paid:</b> {premium_users}\n<b>Queries Today:</b> {q_today}</blockquote>", parse_mode="HTML")

async def cmd_top(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    with db() as conn: rows = conn.execute("SELECT seed, kind, COUNT(*) as hits FROM history GROUP BY seed, kind ORDER BY hits DESC LIMIT 5").fetchall()
    if not rows: return
    text = "🔥 <b>Top Targets</b>\n━━━━━━━━━━━━━━━━━━━━\n"
    for i, r in enumerate(rows, 1): text += f"{i}. <code>{r['kind']}</code> · <code>{r['seed']}</code> ({r['hits']})\n"
    await u.message.reply_text(text, parse_mode="HTML")

async def cmd_sources(u, c):
    names = [getattr(x, "name", x.__name__) for x in s.REGISTRY]
    await u.message.reply_text(f"🔌 <b>Active Sources</b>\n" + "\n".join(f"• <code>{n}</code>" for n in names), parse_mode="HTML")

async def cmd_testreceipt(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    user = get_or_create(tg=u.effective_chat.id)
    await send_receipt(u, c, user, days=30, amount=100, charge_id="TEST_CHARGE", paid_until="2024-12-31", key="VOL-TEST-KEY-1234")

async def cmd_testlimit(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("💎 Upgrade", callback_data="buy_month")]])
    await u.message.reply_text("🔒 <b>Limit Reached</b>\n\nUpgrade to continue.", parse_mode="HTML", reply_markup=kb)

async def cmd_starbalance(u, c):
    if u.effective_chat.id != ADMIN_ID: return
    try:
        balance = await c.bot.get_my_star_balance()
        await u.message.reply_text(f"⭐ <b>Stars Balance:</b> <code>{balance.amount}</code>", parse_mode="HTML")
    except Exception as e: await u.message.reply_text(f"Error: {e}")

async def cmd_upgrade(u, c):
    user = get_or_create(tg=u.effective_chat.id)
    if user["tier"] == "premium" and user["paid_until"]: await u.message.reply_text(f"💎 <b>Already Premium</b>\nExpires: <code>{user['paid_until']}</code>", parse_mode="HTML"); return
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("⭐ 100 Stars / 1 Month", callback_data="buy_month")], [InlineKeyboardButton("⭐ 800 Stars / 1 Year",  callback_data="buy_year")]])
    await u.message.reply_text("💎 <b>VOLUME.TOOLS PREMIUM</b>\n\n<blockquote>200 queries/day (was 15)\nAll sources (was 6)\nDeep breach & stealer logs\nJSON export\nPermanent key system</blockquote>\n<i>Instant activation via Telegram Stars.</i>", parse_mode="HTML", reply_markup=kb)

async def on_buy(u, c):
    q = u.callback_query; await q.answer()
    if q.data == "buy_month": stars, days, lab = 100, 30, "1 Month"
    elif q.data == "buy_year": stars, days, lab = 800, 365, "1 Year"
    else: return
    await q.message.reply_invoice(title="volume.tools premium", description=f"Premium Tier · {lab}", payload=f"premium_{days}d", provider_token="", currency="XTR", prices=[LabeledPrice(lab, stars)])

async def on_pre(u, c): await u.pre_checkout_query.answer(ok=True)

async def on_paid(u, c):
    sp = u.message.successful_payment
    user = get_or_create(tg=u.effective_chat.id)
    days = 365 if "365" in sp.invoice_payload else 30
    new_key = create_key(user["id"], days)
    paid_until = grant_premium(user["id"], days=days, provider="stars", provider_id=sp.telegram_payment_charge_id, amount=sp.total_amount)
    await send_receipt(u, c, user, days, sp.total_amount, sp.telegram_payment_charge_id, paid_until, new_key)

async def send_receipt(u, c, user, days, amount, charge_id, paid_until, key=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    order_id = charge_id[-10:].upper()
    plan_name = "1 Year Premium" if days == 365 else "1 Month Premium"
    key_section = ""
    if key: key_section = f"\n<b>Your Access Key</b>\n<code>{key}</code>\n<i>Keep this safe. Redeem it anytime with /redeem {key}.</i>\n"
    receipt = (
        f"🧾 <b>VOLUME.TOOLS</b>\n<b>Payment Receipt</b>\n\n"
        f"<blockquote><b>Status:</b> ✅ Paid\n<b>Date:</b> <code>{timestamp}</code>\n<b>Order ID:</b> <code>{order_id}</code></blockquote>\n\n"
        f"<b>Account Details</b>\n<blockquote><b>Telegram ID:</b> <code>{user['telegram_id']}</code>\n<b>Username:</b> @{u.effective_chat.username or 'none'}</blockquote>\n\n"
        f"<b>Subscription</b>\n<blockquote><b>Plan:</b> {plan_name}\n<b>Amount:</b> {amount} Stars\n<b>Expires:</b> <code>{paid_until}</code></blockquote>\n"
        f"{key_section}\n<i>Please save this message. If the bot resets, your key is still valid.</i>"
    )
    await u.message.reply_text(receipt, parse_mode="HTML")
    if u.effective_chat.id != ADMIN_ID:
        try:
            await c.bot.send_message(chat_id=ADMIN_ID, text=f"💰 <b>NEW SALE</b>\nUser: @{u.effective_chat.username or 'none'}\nID: <code>{u.effective_chat.id}</code>\nKey: <code>{key}</code>\nAmount: {amount} Stars\nPlan: {plan_name}", parse_mode="HTML")
        except Exception: pass

async def on_startup(app: Application):
    banner = f"🚀 <b>VOLUME.TOOLS {VERSION}</b>\n<b>System Online</b>\n\n• Key System Active\n• Pagination UI Active\n• Web App Linked"
    try: await app.bot.send_message(chat_id=ADMIN_ID, text=banner, parse_mode="HTML")
    except Exception: pass

def build_app():
    app = Application.builder().token(TOKEN).post_init(on_startup).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("pivot", cmd_pivot))
    app.add_handler(CommandHandler("export", cmd_export))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("upgrade", cmd_upgrade))
    app.add_handler(CommandHandler("breach", cmd_breach))
    app.add_handler(CommandHandler("redeem", cmd_redeem))
    app.add_handler(CommandHandler("makeadmin", cmd_makeadmin))
    app.add_handler(CommandHandler("givepremium", cmd_givepremium))
    app.add_handler(CommandHandler("genkey", cmd_genkey))
    app.add_handler(CommandHandler("revoke", cmd_revoke))
    app.add_handler(CommandHandler("broadcast", cmd_broadcast))
    app.add_handler(CommandHandler("ping", cmd_ping))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("top", cmd_top))
    app.add_handler(CommandHandler("sources", cmd_sources))
    app.add_handler(CommandHandler("testreceipt", cmd_testreceipt))
    app.add_handler(CommandHandler("testlimit", cmd_testlimit))
    app.add_handler(CommandHandler("starbalance", cmd_starbalance))
    app.add_handler(CommandHandler("namecheck", cmd_namecheck))
    app.add_handler(CommandHandler("namebulk", cmd_namebulk))
    app.add_handler(CommandHandler("vanity", cmd_vanity))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("genadminkey", cmd_genadminkey))
    app.add_handler(CommandHandler("redeemadmin", cmd_redeemadmin))
    app.add_handler(CommandHandler("revokealladmins", cmd_revokealladmins))
    for k in ("email", "username", "user", "ip", "phone", "domain", "roblox"):
        app.add_handler(CommandHandler(k, mk({"user": "username"}.get(k, k))))
    app.add_handler(CallbackQueryHandler(on_menu_click, pattern="^menu_"))
    app.add_handler(CallbackQueryHandler(on_summary_click, pattern="^do_summary$"))
    app.add_handler(CallbackQueryHandler(on_exp, pattern="^exp_json$"))
    app.add_handler(CallbackQueryHandler(on_buy, pattern="^buy_"))
    app.add_handler(CallbackQueryHandler(on_page_click, pattern="^page_"))
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
