"""Offline smoke test for VOLUME.

Run from anywhere:

    python volume/tests/smoke.py

It uses a throw-away VOLUME_HOME so your real cases and licenses are untouched.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

HOME = Path(tempfile.mkdtemp(prefix="volume-smoke-"))
os.environ["VOLUME_HOME"] = str(HOME)
os.environ["VOLUME_FOUNDER"] = "armory"
os.environ["VOLUME_FOUNDER_TOKEN"] = "smoke-founder-token"

from volume.core import (  # noqa: E402
    accounts,
    auth,
    config,
    database,
    exporter,
    licensing,
    roles,
)
from volume.modules import load_all_modules  # noqa: E402

PASS = []
FAIL = []


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  ok   {name}")
    else:
        FAIL.append(f"{name} {detail}".strip())
        print(f"  FAIL {name} {detail}")


def main():
    print(f"VOLUME smoke test  (home: {HOME})")
    database.init_db()

    hwid = config.get_hwid()
    check("hwid is stable and 24 chars", len(hwid) == 24 and hwid == config.get_hwid())

    # --- free license ------------------------------------------------------
    free_key = auth.ensure_free_license(hwid)
    free = auth.validate_key(free_key, hwid)
    check("free license valid", free.get("valid"), free.get("reason"))
    check("free tier is FREE", free.get("tier") == "FREE")
    check("free starts at 25 credits", free.get("credits") == 25, free.get("credits"))
    check("free is not unlimited", not free.get("unlimited"))

    # --- accounts ----------------------------------------------------------
    check("captcha matches case-insensitively", accounts.captcha_ok("ABCDEF", "abcdef"))
    check("captcha rejects wrong code", not accounts.captcha_ok("ABCDEF", "ABCDEG"))
    check("weak password rejected", not accounts.validate_password("short")[0])
    check("reserved username rejected", not accounts.validate_username("admin")[0])
    check("bad username rejected", not accounts.validate_username("a b")[0])

    reg = accounts.register("SmokeUser", "correct horse battery", hwid, bio="smoke tester")
    check("account registers", reg.get("ok"), reg.get("error"))
    account_key = reg.get("key") or ""
    check("account key is VOL key", account_key.startswith("VOL-"), account_key)
    check("account username preserved", reg.get("username") == "SmokeUser")
    check("account key validates", auth.validate_key(account_key, hwid).get("valid"))

    duplicate = accounts.register("smokeuser", "correct horse battery", hwid)
    check("username is unique case-insensitively", not duplicate.get("ok"), duplicate)

    bad_login = accounts.authenticate("SmokeUser", "wrong password", hwid)
    check("wrong password rejected", not bad_login.get("ok"), bad_login)
    good_login = accounts.authenticate("SmokeUser", "correct horse battery", hwid)
    check("password login works", good_login.get("ok"), good_login.get("error"))
    check("password login returns key", good_login.get("info", {}).get("key") == account_key)

    profile = accounts.public_profile("smokeuser")
    check("profile lookup is case-insensitive", profile.get("username") == "SmokeUser", profile)
    check("profile hides password hash", "password_hash" not in profile)
    check("profile has rarity/search fields", "created" in profile and "bio" in profile)
    found = accounts.search_profiles("smoke")
    check("profile search finds account", any(p["username"] == "SmokeUser" for p in found))
    check("account stats count", accounts.stats().get("total", 0) >= 1)

    # --- roles and founder ------------------------------------------------
    check("role hierarchy ordered", roles.role_rank("member") < roles.role_rank("admin") < roles.role_rank("founder"))
    check("founder can grant admin", roles.can_grant("founder", "admin"))
    check("admin can grant manager", roles.can_grant("admin", "manager"))
    check("admin cannot grant admin", not roles.can_grant("admin", "admin"))
    check("member cannot grant roles", not roles.can_grant("member", "moderator"))
    check("founder role is never grantable", not roles.can_grant("founder", "founder"))
    check("assignable roles exclude founder", "founder" not in roles.assignable_roles("founder"))
    check("founder configured", accounts.founder_configured())

    check("founder name needs token", not accounts.validate_username("armory")[0])
    check("founder name allowed with token flag", accounts.validate_username("armory", allow_founder=True)[0])
    bad_founder = accounts.register("armory", "founder password 1", hwid, founder_token="wrong")
    check("founder registration rejects bad token", not bad_founder.get("ok"), bad_founder)
    founder_reg = accounts.register(
        "armory", "founder password 1", hwid, founder_token="smoke-founder-token"
    )
    check("founder registers with token", founder_reg.get("ok"), founder_reg.get("error"))
    check("founder role assigned", founder_reg.get("role") == "founder", founder_reg)
    founder_key = founder_reg.get("key") or ""
    founder_info = auth.validate_key(founder_key, hwid)
    check("founder key is admin", founder_info.get("admin"))
    check("founder key is unlimited", founder_info.get("unlimited"))
    check("founder key reports founder role", founder_info.get("founder") and founder_info.get("role") == "founder")

    check("claim founder rejects bad token", not accounts.claim_founder("SmokeUser", "nope").get("ok"))
    claimed = accounts.claim_founder("SmokeUser", "smoke-founder-token")
    check("claim founder promotes account", claimed.get("ok"), claimed)
    check("claimed account is founder", accounts.get_account("SmokeUser").get("role") == "founder")
    check("only one founder kept", accounts.get_account("armory").get("role") == "admin")
    restored = accounts.claim_founder("armory", "smoke-founder-token")
    check("founder can be reclaimed", restored.get("ok"), restored)
    check("restored founder role", accounts.get_account("armory").get("role") == "founder")

    grant = accounts.grant_admin("SmokeUser", actor="armory", actor_role="founder")
    check("founder grants permanent admin", grant.get("ok") and grant.get("role") == "admin", grant)
    smoke_info = auth.validate_key(account_key, hwid)
    check("admin role follows the key", smoke_info.get("admin") and smoke_info.get("role") == "admin")
    check("admin account is unlimited", smoke_info.get("unlimited"))

    mod_reg = accounts.register("ModUser", "moderator password 1", hwid)
    check("second account registers", mod_reg.get("ok"), mod_reg.get("error"))
    mod_key = mod_reg.get("key") or ""
    promoted = accounts.set_role("ModUser", "manager", actor="SmokeUser", actor_role="admin")
    check("admin can set manager", promoted.get("ok") and promoted.get("role") == "manager", promoted)
    check("admin cannot grant admin", not accounts.set_role(
        "ModUser", "admin", actor="SmokeUser", actor_role="admin"
    ).get("ok"))
    check("member cannot grant roles", not accounts.set_role(
        "ModUser", "moderator", actor="ModUser", actor_role="member"
    ).get("ok"))

    issued = accounts.issue_key(
        "ModUser", tier="LIFETIME", days=0, actor="armory"
    )
    check("founder issues a key", issued.get("ok"), issued)
    check("issued key validates", auth.validate_key(issued.get("key", ""), hwid).get("valid"))
    check("issued key is lifetime", auth.validate_key(issued.get("key", ""), hwid).get("tier") == "LIFETIME")
    check("old key is revoked", not auth.validate_key(mod_key, hwid).get("valid"))
    check("issued key linked to account", accounts.account_for_key(issued.get("key", "")).get("username") == "ModUser")

    banned = accounts.set_banned("ModUser", True, actor="armory", actor_role="founder")
    check("founder can ban", banned.get("ok"), banned)
    check("banned login rejected", not accounts.authenticate("ModUser", "moderator password 1", hwid).get("ok"))
    check("banned key rejected", not auth.validate_key(issued.get("key", ""), hwid).get("valid"))
    restored_user = accounts.set_banned("ModUser", False, actor="armory", actor_role="founder")
    check("founder can unban", restored_user.get("ok"), restored_user)
    check("unbanned key works again", auth.validate_key(issued.get("key", ""), hwid).get("valid"))
    check("founder cannot be banned", not accounts.set_banned(
        "armory", True, actor="armory", actor_role="founder"
    ).get("ok"))

    # --- tier gates --------------------------------------------------------
    check(
        "free cannot use DETECTIVE modules",
        not licensing.tier_allows("FREE", "DETECTIVE"),
    )
    check(
        "premium can use PREMIUM modules",
        licensing.tier_allows("PREMIUM", "PREMIUM"),
    )
    check(
        "free can export json",
        licensing.export_allowed("FREE", "json"),
    )
    check(
        "free cannot export html",
        not licensing.export_allowed("FREE", "html"),
    )
    check(
        "premium can export html",
        licensing.export_allowed("PREMIUM", "html"),
    )

    # --- credit spend / refund --------------------------------------------
    spend = auth.spend_credits(free_key, 5, reason="smoke", hwid=hwid)
    check("spend 5 credits", spend.get("ok") and spend.get("remaining") == 20, spend)
    refund = auth.add_credits(free_key, 5, reason="smoke refund", actor="smoke")
    check("refund 5 credits", refund.get("ok") and refund.get("remaining") == 25, refund)

    broke = auth.spend_credits(free_key, 10_000, reason="smoke", hwid=hwid)
    check("overspend is rejected", not broke.get("ok"), broke)

    # --- generated premium key --------------------------------------------
    premium_key = auth.generate_key(tier="PREMIUM", days=30, note="smoke")
    premium = auth.validate_key(premium_key, hwid)
    check("premium key valid", premium.get("valid"), premium.get("reason"))
    check("premium tier", premium.get("tier") == "PREMIUM")
    check("premium credits", premium.get("credits") == 500, premium.get("credits"))
    check("premium is not admin", not premium.get("admin"))

    spend = auth.spend_credits(premium_key, 10, reason="smoke", hwid=hwid)
    check("premium spend", spend.get("ok") and spend.get("remaining") == 490, spend)

    # --- HWID binding ------------------------------------------------------
    other = auth.validate_key(premium_key, "DEADBEEFDEADBEEFDEADBEEF")
    check("premium rejects other hwid", not other.get("valid"))
    check("hwid mismatch reason", "HWID" in (other.get("reason") or ""))

    # --- ghost / lifetime --------------------------------------------------
    ghost_key = auth.ensure_ghost_license(hwid)
    ghost = auth.validate_key(ghost_key, hwid)
    check("ghost key is lifetime", ghost.get("tier") == "LIFETIME")
    check("ghost is admin", ghost.get("admin"))
    check("ghost is unlimited", ghost.get("unlimited"))
    ghost_spend = auth.spend_credits(ghost_key, 999, reason="smoke", hwid=hwid)
    check("unlimited spend ok", ghost_spend.get("ok") and ghost_spend.get("remaining") is None)

    # --- modules -----------------------------------------------------------
    modules = load_all_modules()
    check("at least 70 modules", len(modules) >= 70, len(modules))
    check("unique module ids", len(modules) == len(set(modules)))
    missing = [
        mid for mid, mod in modules.items()
        if not all(getattr(mod, attr, None) is not None for attr in ("id", "label", "category"))
    ]
    check("all modules have identity", not missing, missing)

    categories = {mod.category for mod in modules.values()}
    for category in (
        "LOOKUP", "OSINT", "LEAKS", "GEOSINT", "BREACH",
        "MALICIOUS", "CSINT", "DISCORD", "INVESTIGATION",
    ):
        check(f"category {category} populated", category in categories)

    required_ids = {
        "live_email_intel", "live_phone_intel", "live_username_intel",
        "domain_search", "ip_lookup_live", "machine_viewer", "breach_intel",
        "stealerlog_investigation", "website_breach_monitor", "file_search",
        "discord_roblox", "discord_prev_names", "stealer_logs", "leak_index",
        "credential_search", "kitty_db", "general_search", "nazapi",
        "email_intelligence", "cars_owners", "discord_search",
        "telegram_search", "address_lookup", "image_metadata", "ip_info",
        "steam_profile", "xbox_profile", "discord_history", "holehe",
        "subdomains", "ghunt", "cname_lookup",
    }
    absent = sorted(required_ids - set(modules))
    check("all requested modules registered", not absent, absent)

    free_ids = [m.id for m in modules.values() if m.min_tier == "FREE"]
    locked_ids = [m.id for m in modules.values() if m.min_tier != "FREE"]
    check("free tier has modules", len(free_ids) >= 20, len(free_ids))
    check("paid tiers gate modules", len(locked_ids) >= 10, len(locked_ids))

    # --- offline module runs ----------------------------------------------
    case = database.CaseManager(name="SMOKE", analyst="smoke")
    parse = modules["auto_parse"]
    parsed = parse.run(
        case,
        text=(
            "Contact analyst@example.com or +1 415 555 0100. "
            "Host 8.8.8.8 and https://example.com/login. "
            "Hash 44d88612fea8a8f36de82e1278abb02f and CVE-2021-44228."
        ),
    )
    check("auto_parse returns rows", bool(parsed.get("rows")))
    check("auto_parse status ok", parsed.get("status") == "ok")
    fid = case.add_finding(parsed, query="smoke")
    for ent_type, value in parse.pivots(parsed):
        case.link_entity(fid, ent_type, value)

    timeline = modules["case_timeline"].run(case)
    check("case_timeline sees the finding", any("auto_parse" in str(row) for row in timeline["rows"]))
    graph = modules["entity_graph"].run(case)
    check("entity_graph returns entities", bool(graph.get("rows")))

    defanged = modules["ioc_defang"].run(
        case, text="hxxps://evil[.]com/a and bad[@]evil[.]com and 1[.]2[.]3[.]4"
    )
    check("ioc_defang refangs", "https://evil.com/a" in defanged.get("refanged", ""))
    check("ioc_defang lists indicators", bool(defanged.get("defanged")))

    search = modules["case_search"].run(case, keyword="auto_parse")
    check("case_search finds module", search.get("findings", 0) >= 1, search.get("findings"))
    empty = modules["case_search"].run(case, keyword="zzz-no-such-token")
    check("case_search handles no matches", empty.get("status") == "not_found")

    # --- exports -----------------------------------------------------------
    for fmt in ("json", "txt", "csv", "md"):
        path = exporter.export_case(case, fmt)
        check(f"export {fmt}", path.exists() and path.stat().st_size > 0, path)
    html_path = exporter.export_case(case, "html")
    check("export html", html_path.exists() and html_path.stat().st_size > 0, html_path)

    try:
        import reportlab  # noqa: F401
        pdf_path = exporter.export_case(case, "pdf")
        check("export pdf", pdf_path.exists() and pdf_path.stat().st_size > 0, pdf_path)
    except ImportError:
        print("  skip export pdf (reportlab not installed)")

    # --- session -----------------------------------------------------------
    auth.save_session(premium_key, hwid)
    session = auth.check_session()
    check("session resumes", bool(session and session.get("valid")))
    auth.clear_session()
    check("session clears", auth.check_session() is None)

    case.close()

    print()
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for item in FAIL:
            print(f"  - {item}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        shutil.rmtree(HOME, ignore_errors=True)
    raise SystemExit(code)
