import argparse
import getpass
import hmac
import importlib.util
import json
import platform
import sys

from rich.panel import Panel
from rich.table import Table

from volume.core import accounts, auth, catalog, community, config, database, licensing, roles
from volume.modules import load_all_modules
from volume.ui import theme
from volume.ui.app import run_app
from volume.ui.input import choose_device
from volume.ui.theme import credits_text, role_badge, tier_badge

# Result statuses that must not consume credits.
REFUNDABLE = {"error", "key_required", "source_down", "skipped"}
# Result statuses worth persisting to a case.
SAVEABLE = {"ok", "not_found"}


# ---------------------------------------------------------------------------
# license / account display
# ---------------------------------------------------------------------------


def _show_license(info):
    info = info or {}
    username = info.get("username") or accounts.account_for_key(info.get("key", "")).get("username")
    role = info.get("role") or "member"
    if role == "member" and info.get("admin"):
        role = "admin"
    theme.console.print(Panel(
        f"{tier_badge(info.get('tier', 'FREE'))}  {role_badge(role)}\n\n"
        f"[dim]Account[/]   [bold white]{username or 'guest'}[/]\n"
        f"[dim]Credits[/]   [bold white]{credits_text(info)}[/]\n"
        f"[dim]Key[/]       {info.get('key', '-')}\n"
        f"[dim]HWID[/]      {config.get_hwid()}\n"
        f"[dim]Device[/]    {config.get_device_name()}\n"
        f"[dim]Expires[/]   {info.get('expires') or 'never'}"
        + (
            f"  [dim]({info.get('days_left')} day(s) left)[/]"
            if info.get("days_left") is not None else ""
        ),
        title="[bold green]LICENSE[/]",
        border_style="green",
    ))


def _contacts_panel(title="CONTACT IF YOU NEED HELP"):
    table = Table(expand=True, box=None)
    table.add_column("Role", style="cyan", width=14)
    table.add_column("Name", style="bold white", width=14)
    table.add_column("Telegram", style="green")
    for role, name, url in community.contact_rows():
        table.add_row(role, name, url)
    return Panel(
        table,
        title=f"[bold green]{title}[/]",
        subtitle="[dim]Founder armory · Co-owner wounds · Head manager worthless · "
                 "Manager Pavement · Council Raken[/]",
        border_style="green",
    )


def _show_contacts():
    theme.console.print(_contacts_panel())


def _print_profile(profile):
    if not profile:
        theme.console.print("[red]No such profile.[/]")
        return
    table = Table(expand=True)
    table.add_column("Field", style="cyan", width=18)
    table.add_column("Value", style="white")
    table.add_row("Username", profile.get("username") or "-")
    table.add_row("Role", role_badge(profile.get("role") or "member"))
    table.add_row("Tier", tier_badge(profile.get("tier", "FREE")))
    table.add_row("Credits", "unlimited" if profile.get("unlimited") else str(profile.get("credits")))
    table.add_row("Bio", profile.get("bio") or "-")
    table.add_row("Created", (profile.get("created") or "-")[:19])
    table.add_row("Last login", (profile.get("last_login") or "-")[:19])
    table.add_row("Cases", str(profile.get("cases", 0)))
    table.add_row("Findings", str(profile.get("findings", 0)))
    table.add_row("Key suffix", f"…{profile.get('key_suffix') or '----'}")
    table.add_row("Profile URL", profile.get("profile_url") or "-")
    if profile.get("banned"):
        table.add_row("State", "[red]suspended[/]")
    theme.console.print(Panel(
        table,
        title=f"[bold green]PROFILE · {profile.get('username')}[/]",
        border_style="green",
    ))


def _profile_command(args):
    if args.profile:
        profile = accounts.public_profile(args.profile)
        if not profile:
            _err(f"No profile for '{args.profile}'.", args.json)
            return 1
        if args.json:
            print(json.dumps(profile, indent=2, default=str))
        else:
            _print_profile(profile)
        return 0

    if args.search_users:
        results = accounts.search_profiles(args.search_users, limit=25)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
            return 0
        table = Table(title=f"Profiles matching '{args.search_users}'", expand=True)
        table.add_column("Username", style="bold white")
        table.add_column("Role", style="cyan")
        table.add_column("Tier", style="yellow")
        table.add_column("Bio", style="dim")
        for profile in results:
            table.add_row(
                profile.get("username") or "-",
                profile.get("role") or "member",
                profile.get("tier") or "FREE",
                (profile.get("bio") or "-")[:80],
            )
        if not results:
            table.add_row("-", "-", "-", "No matching usernames or bios.")
        theme.console.print(table)
        return 0

    if args.list_users:
        results = accounts.list_accounts(limit=200)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
            return 0
        table = Table(title="VOLUME accounts", expand=True)
        table.add_column("Username", style="bold white")
        table.add_column("Role", style="cyan")
        table.add_column("Tier", style="yellow")
        table.add_column("Created", style="dim")
        for profile in results:
            table.add_row(
                profile.get("username") or "-",
                profile.get("role") or "member",
                profile.get("tier") or "FREE",
                (profile.get("created") or "-")[:10],
            )
        theme.console.print(table)
        return 0
    return 0


# ---------------------------------------------------------------------------
# founder / admin CLI
# ---------------------------------------------------------------------------


def _cli_actor(args):
    """Resolve the acting account from --key or the saved session."""
    key = (args.key or "").strip()
    if not key:
        session = auth.check_session()
        if session and session.get("valid"):
            key = session.get("key") or ""
    if not key:
        return "", "member"
    info = auth.validate_key(key, config.get_hwid())
    account = accounts.account_for_key(info.get("key") or key)
    if account:
        return account["username"], roles.normalize_role(account.get("role"))
    # A standalone LIFETIME key has legacy admin powers.
    return "", "admin" if info.get("admin") else "member"


def _cli_admin(args):
    json_mode = bool(args.json)
    actor, actor_role = _cli_actor(args)

    def emit(result):
        if json_mode:
            print(json.dumps(result, indent=2, default=str))
        elif result.get("ok"):
            theme.console.print(f"[green]{result.get('message') or 'OK'}[/]")
            if result.get("key"):
                theme.console.print(f"[bold white]Key:[/] [bold green]{result['key']}[/]")
        else:
            theme.console.print(f"[red]{result.get('error') or 'Failed.'}[/]")
        return 0 if result.get("ok") else 1

    if args.claim_founder:
        token = (args.founder_token or config.get_founder_token() or "").strip()
        if not token:
            return emit({
                "ok": False,
                "error": "Pass --founder-token or set VOLUME_FOUNDER_TOKEN.",
            })
        result = accounts.claim_founder(args.claim_founder, token, actor=actor or "")
        if result.get("ok"):
            result["message"] = f"{result['username']} is now the founder."
        return emit(result)

    if not roles.is_admin(actor_role):
        return emit({
            "ok": False,
            "error": (
                "Admin access required. Pass --key with an admin/founder key, "
                "or sign in first."
            ),
        })

    if args.set_role:
        username, role = args.set_role
        result = accounts.set_role(
            username, role, actor=actor or "cli", actor_role=actor_role
        )
        if result.get("ok"):
            result["message"] = f"{result['username']} is now {result['role']}."
        return emit(result)

    if args.issue_key:
        result = accounts.issue_key(
            args.issue_key,
            tier=args.issue_tier,
            days=args.issue_days,
            credits=args.issue_credits,
            actor=actor or "cli",
        )
        if result.get("ok"):
            result["message"] = (
                f"Issued a {result['tier']} key to {result['username']}."
            )
        return emit(result)

    if args.ban:
        result = accounts.set_banned(
            args.ban, True, actor=actor or "cli", actor_role=actor_role
        )
        if result.get("ok"):
            result["message"] = f"Suspended {result['username']}."
        return emit(result)

    if args.unban:
        result = accounts.set_banned(
            args.unban, False, actor=actor or "cli", actor_role=actor_role
        )
        if result.get("ok"):
            result["message"] = f"Restored {result['username']}."
        return emit(result)

    return emit({"ok": False, "error": "No admin action given."})


# ---------------------------------------------------------------------------
# interactive account / license flow
# ---------------------------------------------------------------------------


def _ask_secret(label: str) -> str:
    theme.console.print(label, end="")
    try:
        theme.console.file.flush()
    except Exception:
        pass
    try:
        return getpass.getpass("")
    except Exception:
        try:
            return theme.console.input("")
        except EOFError:
            return ""


def _is_ghost_attempt(entered, hwid):
    ghost = config.get_ghost_key()
    if ghost and hmac.compare_digest(entered, ghost):
        return True
    return entered.strip().upper() == f"GHOST-{hwid[:10]}"


def _ghost_license(hwid):
    key = auth.ensure_ghost_license(hwid)
    return auth.validate_key(key, hwid)


def _register_account(hwid):
    console = theme.console
    console.clear()
    console.print(Panel(
        "[bold green]CREATE YOUR VOLUME KEY[/]\n\n"
        "Pick a unique username and a password.  Your username is permanent and\n"
        "cannot be claimed by anyone else, so choose carefully.\n\n"
        "[dim]A free license key is generated for this device.  You will need the\n"
        "key to sign in on another device, so keep it safe.[/]",
        border_style="green",
    ))

    for _attempt in range(4):
        username = console.input("[bold green]username>[/] ").strip()
        if not username:
            console.print("[yellow]Cancelled.[/]")
            return None

        is_founder = username.lower() == config.get_founder_name().lower()
        ok, reason = accounts.validate_username(username, allow_founder=is_founder)
        if not ok:
            console.print(f"[red]{reason}[/]")
            continue

        founder_token = ""
        if is_founder:
            console.print(
                "[bold yellow]Founder account detected.[/] "
                "[dim]Enter the VOLUME_FOUNDER_TOKEN from .env.[/]"
            )
            founder_token = _ask_secret("[bold green]founder token>[/] ")
            if not founder_token:
                console.print("[yellow]Cancelled.[/]")
                return None

        password = _ask_secret("[bold green]password>[/] ")
        if not password:
            console.print("[yellow]Cancelled.[/]")
            return None
        confirm = _ask_secret("[bold green]confirm password>[/] ")
        if password != confirm:
            console.print("[red]Passwords do not match. Try again.[/]")
            continue

        code = accounts.new_captcha()
        console.print(Panel(
            f"[bold white]{code}[/]",
            title="[bold green]CAPTCHA[/]",
            subtitle="[dim]Type the characters above (case-insensitive)[/]",
            border_style="green",
        ))
        answer = console.input("[bold green]captcha>[/] ").strip()
        if not accounts.captcha_ok(code, answer):
            console.print("[red]Captcha incorrect. Try again.[/]")
            continue

        result = accounts.register(username, password, hwid, founder_token=founder_token)
        if not result.get("ok"):
            console.print(f"[red]{result.get('error') or 'Registration failed.'}[/]")
            continue

        key = result["key"]
        auth.save_session(key, hwid)
        auth.audit(username, "account_created", f"key={key}")
        console.print(Panel(
            f"[bold green]Your key:[/] [bold white]{key}[/]\n\n"
            "[bold red]SAVE THIS KEY NOW.[/]  It is the only way to recover your\n"
            "account on another device.  If you lose it you will be locked out.\n\n"
            f"[dim]Username:[/] [bold white]{result['username']}[/]\n"
            f"[dim]Role:[/] {role_badge(result.get('role') or 'member')}\n"
            f"[dim]Tier:[/] {tier_badge(result.get('tier'))}  "
            f"[dim]Credits:[/] [bold white]{credits_text(result.get('info'))}[/]",
            title="[bold green]ACCOUNT CREATED[/]",
            border_style="green",
        ))
        _show_contacts()
        console.print("[dim]Press Enter to continue.[/]")
        try:
            console.input("")
        except EOFError:
            pass
        info = result.get("info") or auth.validate_key(key, hwid)
        role = roles.normalize_role(result.get("role") or "member")
        info.update({
            "username": result["username"],
            "role": role,
            "founder": roles.is_founder(role),
            "staff": roles.is_staff(role),
            "admin": bool(info.get("admin")) or roles.is_admin(role),
            "account": True,
        })
        return info
    return None


def _password_login(hwid):
    console = theme.console
    console.clear()
    console.print(Panel(
        "[bold green]SIGN IN WITH YOUR ACCOUNT[/]\n\n"
        "[dim]Password sign-in only works on the device that created the account.\n"
        "On another device, use your license key instead.[/]",
        border_style="green",
    ))
    username = console.input("[bold green]username>[/] ").strip()
    if not username:
        return None
    password = _ask_secret("[bold green]password>[/] ")
    if not password:
        return None
    result = accounts.authenticate(username, password, hwid)
    if not result.get("ok"):
        console.print(f"[red]{result.get('error') or 'Sign-in failed.'}[/]")
        if result.get("key"):
            console.print(f"[dim]Your key suffix: …{str(result['key'])[-4:]}[/]")
        return None
    info = result.get("info") or {}
    auth.save_session(info.get("key"), hwid)
    return info


def _login(hwid, forced_key=None):
    console = theme.console

    if forced_key:
        if _is_ghost_attempt(forced_key, hwid):
            return _ghost_license(hwid), "ghost key"
        info = auth.validate_key(forced_key, hwid)
        if info.get("valid"):
            auth.save_session(info["key"], hwid)
            return info, "key"
        console.print(f"[red]Invalid key: {info.get('reason') or 'rejected'}[/]")
        return None, "invalid"

    session = auth.check_session()
    if session and session.get("valid"):
        account = accounts.account_for_key(session.get("key"))
        if account:
            session["username"] = account["username"]
            session["role"] = account.get("role") or "member"
        return session, "session"

    if not sys.stdin.isatty():
        console.print(
            "[red]No active license.[/] Pass [bold]--key KEY[/] or run "
            "interactively to create an account and free key."
        )
        return None, "no-license"

    console.print(Panel(
        "[bold green]LICENSE / ACCESS[/]\n\n"
        "[bold white]Enter[/] to create a free account and key\n"
        "[bold white]l[/] to sign in with your username and password\n"
        "[bold white]q[/] to quit\n\n"
        "[dim]Already have a key? Paste it (VOL-XXXX-XXXX-XXXX).\n"
        f"Free tier: {licensing.TIERS['FREE']['credits']} credits, "
        f"+{licensing.TIERS['FREE']['daily']}/day up to "
        f"{licensing.TIERS['FREE']['max_credits']}. Some modules are locked.[/]",
        border_style="green",
    ))
    _show_contacts()

    for _ in range(5):
        try:
            entered = console.input("\n[bold green]key / Enter=create / l=sign in / q=quit>[/] ").strip()
        except EOFError:
            return None, "no-license"

        if not entered:
            info = _register_account(hwid)
            if info:
                return info, "account"
            continue
        if entered.lower() == "l":
            info = _password_login(hwid)
            if info:
                return info, "password"
            continue
        if entered.lower() in ("q", "quit", "exit"):
            return None, "quit"
        if _is_ghost_attempt(entered, hwid):
            return _ghost_license(hwid), "ghost key"
        info = auth.validate_key(entered, hwid)
        if info.get("valid"):
            auth.save_session(info["key"], hwid)
            return info, "key"
        console.print(f"[red]{info.get('reason') or 'Invalid key'}[/]")

    console.print("[yellow]Too many attempts.[/]")
    return None, "locked"


# ---------------------------------------------------------------------------
# module / CLI display
# ---------------------------------------------------------------------------


def _list_modules(modules):
    table = Table(title="VOLUME modules", expand=True)
    table.add_column("Category", style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Tool", style="bold white")
    table.add_column("Tier", style="yellow")
    table.add_column("Cost", style="green", width=5)
    table.add_column("Description", style="dim")
    for mod in sorted(modules.values(), key=catalog.sort_key):
        table.add_row(
            catalog.category_label(mod.category), mod.id, mod.label, mod.min_tier,
            str(mod.credit_cost), mod.description,
        )
    theme.console.print(table)


def _module_catalog(modules):
    return [
        {
            "id": mod.id,
            "label": mod.label,
            "category": mod.category,
            "category_label": catalog.category_label(mod.category),
            "description": mod.description,
            "min_tier": mod.min_tier,
            "credit_cost": mod.credit_cost,
            "inputs": list(mod.inputs),
            "optional_inputs": dict(mod.optional_inputs),
            "input_prompts": dict(mod.input_prompts),
            "requires_key": list(mod.requires_key),
        }
        for mod in sorted(modules.values(), key=catalog.sort_key)
    ]


def _tiers():
    console = theme.console
    table = Table(title="VOLUME tiers", expand=True)
    table.add_column("Tier", style="cyan")
    table.add_column("Credits", style="white")
    table.add_column("Label", style="dim")
    for name, credits, label in licensing.tier_summary():
        table.add_row(name, credits, label)
    console.print(table)

    exports = Table(title="Export gates", expand=True)
    exports.add_column("Format", style="cyan")
    exports.add_column("Minimum tier", style="white")
    for fmt, tier in licensing.EXPORT_TIERS.items():
        exports.add_row(fmt.upper(), tier)
    console.print(exports)


def _doctor():
    console = theme.console
    modules = load_all_modules()
    hwid = config.get_hwid()

    deps = [
        ("rich", "UI"),
        ("httpx", "HTTP"),
        ("dotenv", "config"),
        ("dns", "DNS"),
        ("phonenumbers", "phone parsing"),
        ("psutil", "system stats"),
        ("PIL", "image metadata"),
        ("reportlab", "PDF export"),
    ]
    dep_rows = []
    missing = []
    for name, purpose in deps:
        found = importlib.util.find_spec(name) is not None
        dep_rows.append((name, "installed" if found else f"MISSING ({purpose})"))
        if not found:
            missing.append(name)

    keys = [
        "hibp", "vt", "abusech", "urlhaus", "abuseipdb", "greynoise",
        "gsb", "nvd", "github", "discord", "discord_history", "roblox_map",
        "leakix", "nazapi", "kitty", "stealer", "xbox", "ghunt", "dvla",
        "emailrep", "numverify", "telegram", "holehe",
    ]
    configured = [name for name in keys if config.get_key(name)]

    table = Table(expand=True)
    table.add_column("Check", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Python", platform.python_version())
    table.add_row("Platform", f"{platform.system()} {platform.release()}")
    table.add_row("Package", str(config.ROOT_DIR))
    table.add_row("VOLUME_HOME", str(config.ROOT_DIR))
    table.add_row("HWID", hwid)
    table.add_row("Device", config.get_device_name())
    table.add_row("Modules", str(len(modules)))
    table.add_row("Categories", ", ".join(sorted({catalog.category_label(m.category) for m in modules.values()})))
    table.add_row("Cases DB", "ok" if config.DB_CASES.exists() else "missing")
    table.add_row("Auth DB", "ok" if config.DB_AUTH.exists() else "missing")
    table.add_row("API keys set", ", ".join(configured) if configured else "none")
    table.add_row("Ghost key", "configured" if config.get_ghost_key() else "not set")
    table.add_row(
        "Founder",
        f"{config.get_founder_name()} · token "
        + ("set" if accounts.founder_configured() else "NOT SET"),
    )
    table.add_row("Missing deps", ", ".join(missing) if missing else "none")
    try:
        account_stats = accounts.stats()
        table.add_row(
            "Accounts",
            f"{account_stats['total']} total · {account_stats['banned']} suspended",
        )
    except Exception:
        table.add_row("Accounts", "unavailable")

    console.print(Panel(table, title="[bold green]VOLUME DOCTOR[/]", border_style="green"))

    dep_table = Table(expand=True)
    dep_table.add_column("Dependency", style="cyan")
    dep_table.add_column("Status", style="white")
    for name, status in dep_rows:
        dep_table.add_row(name, status)
    console.print(Panel(dep_table, title="[dim]DEPENDENCIES[/]", border_style="green"))

    session = auth.check_session()
    if session and session.get("valid"):
        console.print(
            f"[dim]Session:[/] {tier_badge(session.get('tier'))}  "
            f"·  credits {credits_text(session)}"
        )
    else:
        console.print("[dim]Session:[/] none (run interactively to sign in or create a key)")
    required_missing = [name for name in missing if name != "reportlab"]
    return 1 if required_missing else 0


# ---------------------------------------------------------------------------
# Scriptable mode: --run MODULE_ID --arg key=value
# ---------------------------------------------------------------------------


def _err(message, json_mode=False):
    if json_mode:
        print(json.dumps({"ok": False, "error": message}), file=sys.stdout)
    else:
        theme.console.print(f"[red]{message}[/]")


def _parse_args(pairs):
    values = {}
    for pair in pairs or []:
        if "=" not in pair:
            return None, f"Bad --arg '{pair}'. Use key=value."
        key, _, value = pair.partition("=")
        key = key.strip()
        if not key:
            return None, f"Bad --arg '{pair}'. Empty key."
        values[key] = value
    return values, None


def _cli_run(args, modules):
    json_mode = bool(args.json)
    hwid = config.get_hwid()

    # --- authentication (quiet) -------------------------------------------
    if args.key:
        if _is_ghost_attempt(args.key, hwid):
            info = _ghost_license(hwid)
        else:
            info = auth.validate_key(args.key, hwid)
        if not info or not info.get("valid"):
            reason = (info or {}).get("reason") or "invalid key"
            _err(f"License rejected: {reason}", json_mode)
            return 2
        auth.save_session(info["key"], hwid)
    else:
        session = auth.check_session()
        if session and session.get("valid"):
            info = session
        else:
            _err(
                "No license available. Pass --key KEY, or run interactively "
                "to create a free account and key.",
                json_mode,
            )
            return 2

    if not info or not info.get("valid"):
        _err("No valid license available.", json_mode)
        return 2

    mod = modules.get(args.run)
    if mod is None:
        _err(f"Unknown module '{args.run}'. Run --list-modules to see IDs.", json_mode)
        return 5

    tier = info.get("tier", "FREE")
    is_admin = bool(info.get("admin"))
    unlimited = bool(info.get("unlimited"))

    if not licensing.tier_allows(tier, mod.min_tier) and not is_admin:
        _err(
            f"'{mod.label}' requires {mod.min_tier} tier; you are {tier}. "
            f"Use --key to activate a higher tier.",
            json_mode,
        )
        return 3

    # --- inputs ------------------------------------------------------------
    provided, error = _parse_args(args.arg)
    if error:
        _err(error, json_mode)
        return 6

    inputs = {}
    missing = []
    for field in mod.inputs:
        if field in provided and str(provided[field]).strip():
            inputs[field] = provided[field]
        else:
            missing.append(field)
    if missing:
        prompts = getattr(mod, "input_prompts", {}) or {}
        hints = "; ".join(f"{f} ({prompts.get(f, f)})" for f in missing)
        _err(f"Missing required input(s): {hints}", json_mode)
        return 6

    for field, default in (getattr(mod, "optional_inputs", {}) or {}).items():
        inputs[field] = provided.get(field, str(default))

    # Pass through any extra args so modules can use ad-hoc options.
    for field, value in provided.items():
        inputs.setdefault(field, value)

    # --- credits -----------------------------------------------------------
    cost = max(0, int(mod.credit_cost or 0))
    spent = 0
    if cost and not unlimited:
        if int(info.get("credits") or 0) < cost:
            _err(
                f"Not enough credits: '{mod.label}' costs {cost}, "
                f"balance is {info.get('credits')}. Free tier refills "
                f"+{licensing.TIERS['FREE']['daily']}/day.",
                json_mode,
            )
            return 4
        spend = auth.spend_credits(
            info["key"], cost, reason=f"cli:{mod.id}", hwid=hwid
        )
        if not spend.get("ok"):
            _err(spend.get("error") or "Could not spend credits.", json_mode)
            return 4
        spent = cost
        info = auth.get_license(info["key"], hwid)

    # --- optional case (opened before run so case-aware modules work) ------
    case_name = args.case or ("CLI" if args.save else None)
    case = None
    if case_name:
        try:
            case = database.CaseManager(name=case_name, analyst=args.analyst)
        except Exception as exc:
            _err(f"Could not open case '{case_name}': {exc}", json_mode)
            return 7

    # --- run ---------------------------------------------------------------
    try:
        result = mod.run(case, **inputs)
    except Exception as exc:  # keep CLI resilient
        result = {
            "module": mod.id,
            "title": mod.label,
            "source": "module",
            "confidence": "low",
            "status": "error",
            "rows": [("Error", f"{type(exc).__name__}: {exc}")],
        }

    status = str(result.get("status", "ok"))
    refunded = False
    if status in REFUNDABLE and spent and not unlimited:
        auth.add_credits(
            info["key"], spent, reason=f"refund: {status}", actor=info["key"]
        )
        info = auth.get_license(info["key"], hwid)
        refunded = True

    # --- optional persistence ---------------------------------------------
    saved = None
    if case is not None and status in SAVEABLE and result.get("rows"):
        try:
            query = str(inputs.get(mod.inputs[0], ""))[:200] if mod.inputs else ""
            finding_id = case.add_finding(result, query=query)
            for ent_type, value in mod.pivots(result) or []:
                case.link_entity(finding_id, ent_type, value)
            saved = {"case": case.name, "case_id": case.id, "finding_id": finding_id}
        except Exception as exc:
            saved = {"error": f"{type(exc).__name__}: {exc}"}
    if case is not None:
        case.close()

    # --- output ------------------------------------------------------------
    if json_mode:
        payload = dict(result)
        payload["rows"] = [list(row) for row in result.get("rows") or []]
        payload.update({
            "ok": status not in REFUNDABLE,
            "tier": info.get("tier"),
            "credit_cost": cost,
            "credits_remaining": info.get("credits"),
            "refunded": refunded,
            "saved": saved,
        })
        print(json.dumps(payload, indent=2, default=str))
    else:
        from volume.ui.app import _show_result
        _show_result(result)
        if cost:
            note = "refunded" if refunded else f"spent {cost}"
            theme.console.print(
                f"[dim]Credits: {note} · balance {credits_text(info)}[/]"
            )
        if saved:
            theme.console.print(f"[dim]Saved to case '{saved.get('case')}'.[/]")

    return 0 if status not in REFUNDABLE else 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="volume",
        description="VOLUME - OSINT / CSINT / security intelligence console",
    )
    parser.add_argument("--pc", action="store_true", help="force the PC dashboard layout")
    parser.add_argument("--mobile", action="store_true", help="force the compact mobile layout")
    parser.add_argument("--key", help="activate a license key for this run")
    parser.add_argument("--no-session", action="store_true", help="ignore the saved session")
    parser.add_argument("--list-modules", action="store_true", help="print the module catalogue and exit")
    parser.add_argument("--tiers", action="store_true", help="print tier and export gates and exit")
    parser.add_argument("--doctor", action="store_true", help="run environment and dependency checks")
    parser.add_argument("--version", action="store_true", help="print the version and exit")

    accounts_group = parser.add_argument_group("accounts")
    accounts_group.add_argument("--profile", metavar="USERNAME", help="show a public profile")
    accounts_group.add_argument("--search-users", metavar="QUERY", help="search usernames and bios")
    accounts_group.add_argument("--list-users", action="store_true", help="list registered accounts")

    admin_group = parser.add_argument_group("founder / admin")
    admin_group.add_argument(
        "--claim-founder", metavar="USERNAME",
        help="promote an existing account to founder using the founder token",
    )
    admin_group.add_argument(
        "--founder-token", metavar="TOKEN", default="",
        help="founder token (or set VOLUME_FOUNDER_TOKEN)",
    )
    admin_group.add_argument(
        "--set-role", nargs=2, metavar=("USERNAME", "ROLE"),
        help="set an account role: member, moderator, manager or admin",
    )
    admin_group.add_argument(
        "--issue-key", metavar="USERNAME",
        help="mint and assign a new key to an account",
    )
    admin_group.add_argument(
        "--issue-tier", default="PREMIUM",
        help="tier for --issue-key (default PREMIUM)",
    )
    admin_group.add_argument(
        "--issue-days", type=int, default=0,
        help="days until expiry for --issue-key (0 = never)",
    )
    admin_group.add_argument(
        "--issue-credits", type=int, default=None,
        help="credit override for --issue-key",
    )
    admin_group.add_argument("--ban", metavar="USERNAME", help="suspend an account")
    admin_group.add_argument("--unban", metavar="USERNAME", help="restore a suspended account")

    cli = parser.add_argument_group("scriptable mode")
    cli.add_argument("--run", metavar="MODULE_ID", help="run one module non-interactively and exit")
    cli.add_argument(
        "--arg", action="append", metavar="KEY=VALUE",
        help="module input (repeatable, e.g. --arg domain=example.com)",
    )
    cli.add_argument("--case", metavar="NAME", help="open/create a case and save the finding")
    cli.add_argument("--analyst", default="cli", help="analyst name for --case/--save")
    cli.add_argument(
        "--save", action="store_true",
        help="save the finding to a case (default name: CLI) without --case",
    )
    cli.add_argument("--json", action="store_true", help="machine-readable JSON output")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    console = theme.console

    if args.version:
        if args.json:
            print(json.dumps({"name": config.APP_NAME, "version": config.VERSION}))
        else:
            console.print(f"VOLUME {config.VERSION}")
        return 0

    database.init_db()

    if args.no_session:
        auth.clear_session()

    if args.profile or args.search_users or args.list_users:
        return _profile_command(args)

    if args.claim_founder or args.set_role or args.issue_key or args.ban or args.unban:
        return _cli_admin(args)

    if args.doctor:
        return _doctor()

    if args.tiers:
        _tiers()
        return 0

    modules = load_all_modules()

    if args.list_modules:
        if args.json:
            print(json.dumps(_module_catalog(modules), indent=2, default=str))
        else:
            _list_modules(modules)
        return 0

    if args.run:
        return _cli_run(args, modules)

    console.print(theme.LOGO)

    hwid = config.get_hwid()
    license_info, source = _login(hwid, forced_key=args.key)
    if license_info is None:
        return 2

    auth.audit(license_info.get("key", "-"), "login", f"source={source}")
    console.print(f"\n[dim]Signed in via {source}.[/]")
    _show_license(license_info)

    console.print(f" [dim]{len(modules)} modules loaded.[/]")

    if args.pc:
        mode = "pc"
    elif args.mobile:
        mode = "mobile"
    else:
        mode = choose_device()

    try:
        run_app(None, license_info, modules, mode=mode)
    finally:
        auth.audit(license_info.get("key", "-"), "logout", "clean exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
