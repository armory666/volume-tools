import hmac

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from volume.core import (
    accounts,
    auth,
    catalog,
    community,
    config,
    database,
    exporter,
    licensing,
    roles,
)
from volume.ui.input import read_block, read_key
from volume.ui.layout import create_layout
from volume.ui.theme import (
    credits_text,
    get_tab_list,
    mask_key,
    risk_color,
    role_badge,
    status_color,
    tier_badge,
)

console = Console()

REFUNDABLE = {"error", "key_required", "source_down", "skipped"}
SAVEABLE = {"ok", "not_found"}


# ---------------------------------------------------------------------------
# small console helpers
# ---------------------------------------------------------------------------


def _prompt(text: str):
    console.print(text, end="")
    try:
        console.file.flush()
    except Exception:
        pass


def _ask_line(label: str, password: bool = False) -> str:
    _prompt(label)
    if password:
        import getpass
        try:
            return getpass.getpass("")
        except Exception:
            pass
    try:
        return console.input("")
    except EOFError:
        return ""


def _ask_int(label: str, default=None):
    raw = _ask_line(label).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _pause(text: str = "Press any key to return..."):
    _prompt(f"\n[dim]{text}[/] ")
    read_key()


def _confirm(text: str) -> bool:
    _prompt(f"{text} [dim](y/N)[/] ")
    key = read_key()
    console.print()
    return key.lower() == "y"


def _display_role(info):
    role = (info or {}).get("role") or "member"
    if role == "member" and (info or {}).get("admin"):
        return "admin"
    return role


def _refresh_license(license_info):
    if not license_info or not license_info.get("key"):
        return license_info
    fresh = auth.get_license(license_info["key"], config.get_hwid())
    license_info.update(fresh)
    return license_info


# ---------------------------------------------------------------------------
# result rendering
# ---------------------------------------------------------------------------


def _show_result(result):
    if not isinstance(result, dict):
        result = {
            "title": "Error",
            "source": "module",
            "confidence": "low",
            "status": "error",
            "rows": [("Error", "Module returned an invalid result")],
        }

    rows = result.get("rows") or []
    if not isinstance(rows, (list, tuple)):
        rows = [("Error", "Malformed rows")]

    table = Table(expand=True, padding=(0, 2))
    table.add_column("Key", style="cyan", no_wrap=False)
    table.add_column("Value", style="white", overflow="fold")
    for row in rows:
        try:
            key, value = row
        except Exception:
            key, value = "Value", row
        table.add_row(str(key), str(value))

    status = str(result.get("status", "ok"))
    confidence = str(result.get("confidence", "unknown"))
    risk = result.get("risk")
    border = status_color(status)
    if risk is not None and status == "ok":
        border = risk_color(risk)

    subtitle = f"Source: {result.get('source', 'unknown')}  ·  Confidence: {confidence}  ·  Status: {status}"
    if risk is not None:
        subtitle += f"  ·  Risk: {risk}/100"

    console.print(Panel(
        table,
        title=f"[bold green]{result.get('title', 'Result')}[/]",
        subtitle=subtitle,
        border_style=border,
    ))
    for warning in result.get("warnings") or []:
        console.print(f"[yellow]! {warning}[/]")


# ---------------------------------------------------------------------------
# module execution
# ---------------------------------------------------------------------------


def _refund(license_info, amount, reason):
    if not amount or not license_info or license_info.get("unlimited"):
        return
    key = license_info.get("key")
    if not key:
        return
    auth.add_credits(key, amount, reason=f"refund: {reason}", actor=key)
    _refresh_license(license_info)


def _collect_inputs(mod):
    inputs = {}
    prompts = getattr(mod, "input_prompts", {}) or {}
    multiline = tuple(getattr(mod, "multiline_inputs", ()) or ())
    secret = tuple(getattr(mod, "secret_inputs", ()) or ())

    for field in mod.inputs:
        label = prompts.get(field, field.replace("_", " ").title())
        if field in multiline:
            value = read_block(
                f"[bold green]{label}[/] [dim](paste, then a blank line to run)[/]"
            )
        elif field in secret:
            value = _ask_line(f"[bold green]{label}[/]: ", password=True)
        else:
            value = _ask_line(f"[bold green]{label}[/]: ")
        if not str(value or "").strip():
            console.print("[yellow]Cancelled.[/]")
            _pause()
            return None
        inputs[field] = str(value).strip() if field not in multiline else str(value)

    for field, default in (getattr(mod, "optional_inputs", {}) or {}).items():
        label = prompts.get(field, field.replace("_", " ").title())
        value = _ask_line(f"[bold green]{label}[/] [dim]({default})[/]: ").strip()
        inputs[field] = value or str(default)

    return inputs


def _run_module(mod, case, license_info):
    tier = (license_info or {}).get("tier", "FREE")
    is_admin = bool((license_info or {}).get("admin"))
    unlimited = bool((license_info or {}).get("unlimited"))

    if not licensing.tier_allows(tier, mod.min_tier) and not is_admin:
        console.print(Panel(
            f"[bold red]ACCESS DENIED[/]\n\n"
            f"[bold white]{mod.label}[/] requires [bold]{mod.min_tier}[/] tier.\n"
            f"Your tier: {tier_badge(tier)}\n"
            f"Credit cost: [cyan]{mod.credit_cost}[/]\n\n"
            f"[dim]Press k to open the license screen and activate a key.[/]",
            border_style="red",
        ))
        _pause()
        return license_info

    cost = max(0, int(mod.credit_cost or 0))
    if not unlimited:
        credits = int((license_info or {}).get("credits") or 0)
        if credits < cost:
            console.print(Panel(
                f"[bold red]NOT ENOUGH CREDITS[/]\n\n"
                f"{mod.label} costs [cyan]{cost}[/] credit(s).\n"
                f"Balance: [bold]{credits}[/]  ·  Free tier refills "
                f"[bold]+{licensing.TIERS['FREE']['daily']}/day[/] up to "
                f"[bold]{licensing.TIERS['FREE']['max_credits']}[/].\n\n"
                f"[dim]Press k to activate a higher tier or top up.[/]",
                border_style="red",
            ))
            _pause()
            return license_info

    inputs = _collect_inputs(mod)
    if inputs is None:
        return license_info

    spent = 0
    if cost and not unlimited:
        spend = auth.spend_credits(
            license_info["key"], cost, reason=f"module:{mod.id}", hwid=config.get_hwid()
        )
        if not spend.get("ok"):
            console.print(f"[red]{spend.get('error') or 'Could not spend credits'}[/]")
            _pause()
            return license_info
        spent = cost
        _refresh_license(license_info)
        console.print(f"[dim]Spent {cost} credit(s) · {credits_text(license_info)} left[/]")

    console.print(f"\n[dim]Running {mod.label}...[/]")
    try:
        result = mod.run(case, **inputs)
    except Exception as exc:
        result = {
            "module": mod.id,
            "title": mod.label,
            "source": "module",
            "confidence": "low",
            "status": "error",
            "rows": [("Error", f"{type(exc).__name__}: {exc}")],
        }

    status = str(result.get("status", "ok"))
    if status in REFUNDABLE:
        _refund(license_info, spent, status)
        spent = 0

    if case and result.get("rows") and status in SAVEABLE:
        query = ""
        if mod.inputs:
            query = str(inputs.get(mod.inputs[0], ""))[:200]
        try:
            finding_id = case.add_finding(result, query=query)
            for ent_type, value in mod.pivots(result) or []:
                case.link_entity(finding_id, ent_type, value)
        except Exception as exc:
            console.print(f"[yellow]Could not save finding: {exc}[/]")

    console.clear()
    _show_result(result)
    if spent == 0 and cost and not unlimited:
        console.print("[dim]Credits for this run were refunded.[/]")
    _pause()
    return license_info


def _quick_extract(case, license_info, modules):
    mod = modules.get("auto_parse") or next(
        (m for m in modules.values() if m.id == "auto_parse"), None
    )
    if not mod:
        console.print("[yellow]Auto parser module is not loaded.[/]")
        _pause()
        return license_info
    return _run_module(mod, case, license_info)


# ---------------------------------------------------------------------------
# cases
# ---------------------------------------------------------------------------


def _new_case(case):
    console.clear()
    console.print(Panel(
        "[bold green]NEW INVESTIGATION CASE[/]\n\n"
        "[dim]Name the case. You can rename it later.[/]",
        border_style="green",
    ))
    name = _ask_line("[bold green]Case name[/]: ").strip()
    if not name:
        console.print("[yellow]Cancelled.[/]")
        _pause()
        return case

    default_analyst = case.analyst if case else "anonymous"
    analyst = _ask_line(f"[bold green]Analyst[/] [dim]({default_analyst})[/]: ").strip()
    analyst = analyst or default_analyst

    try:
        new_case = database.CaseManager(name=name, analyst=analyst)
    except Exception as exc:
        console.print(f"[red]Could not create case: {exc}[/]")
        _pause()
        return case

    if case:
        case.close()

    console.print(Panel(
        f"[bold green]Case:[/] {new_case.name}\n"
        f"[bold green]Case ID:[/] {new_case.id}\n"
        f"[bold green]Analyst:[/] {new_case.analyst}",
        title="[bold green]CASE READY[/]",
        border_style="green",
    ))
    _pause()
    return new_case


def _browse_cases(case):
    rows = database.list_cases()
    console.clear()
    if not rows:
        console.print("[yellow]No cases saved yet. Press n on the Cases tab to create one.[/]")
        _pause()
        return case

    page = 0
    per_page = 9
    pages = max(1, (len(rows) + per_page - 1) // per_page)

    while True:
        chunk = rows[page * per_page:(page + 1) * per_page]
        table = Table(expand=True)
        table.add_column("#", style="bold green", width=3)
        table.add_column("ID", style="dim", width=5)
        table.add_column("Case", style="bold white")
        table.add_column("Analyst", style="dim")
        table.add_column("Findings", style="cyan", width=9)
        table.add_column("Updated", style="dim")
        for idx, row in enumerate(chunk, 1):
            table.add_row(
                str(idx),
                str(row["id"]),
                row["name"],
                row["analyst"] or "-",
                str(row.get("findings", 0)),
                (row.get("updated") or row.get("created") or "")[:10],
            )
        console.print(Panel(
            table,
            title=f"[bold green]OPEN A CASE[/]  [dim]page {page + 1}/{pages}[/]",
            border_style="green",
        ))
        console.print("[dim]1-9 open  ·  [ / ] page  ·  Enter cancel[/]")
        _prompt("[bold green]case #>[/] ")
        key = read_key()
        console.print()

        if key in ("\r", "\n", ""):
            return case
        if key == "[":
            page = max(0, page - 1)
            console.clear()
            continue
        if key == "]":
            page = min(pages - 1, page + 1)
            console.clear()
            continue
        if not key.isdigit() or key == "0":
            continue

        idx = int(key) - 1
        if not 0 <= idx < len(chunk):
            continue

        row = chunk[idx]
        try:
            new_case = database.CaseManager(name=row["name"], analyst=row["analyst"])
        except Exception as exc:
            console.print(f"[red]Could not open case: {exc}[/]")
            _pause()
            return case

        if case:
            case.close()
        console.print(Panel(
            f"[bold green]Opened:[/] {new_case.name}  [dim](#{new_case.id})[/]",
            border_style="green",
        ))
        _pause()
        return new_case


def _default_case(license_info=None):
    analyst = (license_info or {}).get("username") or "analyst"
    try:
        return database.CaseManager(name="WORKSPACE", analyst=analyst)
    except Exception:
        return None


def _contacts_panel():
    table = Table(expand=True, box=None)
    table.add_column("Role", style="cyan", width=14)
    table.add_column("Name", style="bold white", width=14)
    table.add_column("Telegram", style="green")
    for role, name, url in community.contact_rows():
        table.add_row(role, name, url)
    return Panel(
        table,
        title="[bold green]CONTACT IF YOU NEED HELP[/]",
        subtitle="[dim]Save your key. Support cannot recover a lost key.[/]",
        border_style="green",
    )


def _delete_case(case):
    if case is None:
        return case
    console.clear()
    console.print(Panel(
        "[bold red]DELETE CASE[/]\n\n"
        "[dim]This deletes the case, all findings and all entity links.[/]\n"
        f"Case: {case.name} (ID: {case.id})",
        border_style="red",
    ))
    if not _confirm("[bold green]Type y to confirm deletion[/]"):
        console.print("[yellow]Deletion cancelled.[/]")
        _pause()
        return case

    deleted = case.delete_case()
    try:
        case.close()
    except Exception:
        pass
    if deleted:
        console.print(Panel(
            "[bold green]Case deleted.[/]",
            title="[bold green]DELETED[/]",
            border_style="green",
        ))
    else:
        console.print("[red]Could not delete case.[/]")
    _pause()
    return _default_case()


def _case_stats(case):
    if case is None:
        return
    console.clear()
    stats = case.stats()
    table = Table(expand=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Case", case.name)
    table.add_row("Case ID", str(case.id))
    table.add_row("Analyst", case.analyst or "-")
    table.add_row("Findings", str(stats["findings"]))
    table.add_row("Unique entities", str(stats["entities"]))
    table.add_row("First finding", stats.get("first") or "-")
    table.add_row("Last finding", stats.get("last") or "-")
    table.add_row("Modules used", ", ".join(f"{k}×{v}" for k, v in stats["modules"].items()) or "-")
    table.add_row("Tags", getattr(case, "tags", "") or "-")
    table.add_row("Notes", (getattr(case, "notes", "") or "-")[:500])
    console.print(Panel(table, title="[bold green]CASE STATS[/]", border_style="green"))
    _pause()


def _case_meta(case):
    if case is None:
        return case
    console.clear()
    console.print(Panel(
        "[bold green]CASE METADATA[/]\n\n"
        "[dim]Edit notes, tags and analyst. Leave blank to keep the current value.[/]",
        border_style="green",
    ))
    notes = _ask_line(f"[bold green]Notes[/] [dim]({getattr(case, 'notes', '')[:60] or 'none'})[/]: ").strip()
    tags = _ask_line(f"[bold green]Tags[/] [dim]({getattr(case, 'tags', '') or 'none'})[/]: ").strip()
    analyst = _ask_line(f"[bold green]Analyst[/] [dim]({case.analyst})[/]: ").strip()
    try:
        case.update(
            notes=notes if notes else None,
            tags=tags if tags else None,
            analyst=analyst if analyst else None,
        )
        console.print("[bold green]Case updated.[/]")
    except Exception as exc:
        console.print(f"[red]Could not update case: {exc}[/]")
    _pause()
    return case


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


def _export_case(case, license_info):
    if case is None:
        console.print("[yellow]No case is open.[/]")
        _pause()
        return
    tier = (license_info or {}).get("tier", "FREE")
    console.clear()
    lines = []
    for key, (ext, label) in exporter.FORMATS.items():
        if licensing.export_allowed(tier, ext):
            lines.append(f"[bold]{key}[/]  {label}")
        else:
            lines.append(
                f"[dim]{key}  {label}  (requires {licensing.EXPORT_TIERS.get(ext, 'PREMIUM')})[/]"
            )
    console.print(Panel(
        "[bold green]EXPORT CASE[/]\n\n" + "\n".join(lines) +
        f"\n\n[dim]Your tier: {tier}. HTML/PDF require PREMIUM.[/]",
        border_style="green",
    ))
    _prompt("[bold green]format>[/] ")
    key = read_key()
    console.print()

    if key not in exporter.FORMATS:
        return
    ext = exporter.FORMATS[key][0]
    if not licensing.export_allowed(tier, ext):
        console.print(
            f"[red]{ext.upper()} export requires "
            f"{licensing.EXPORT_TIERS.get(ext, 'PREMIUM')} tier.[/]"
        )
        _pause()
        return

    try:
        path = exporter.export_case(case, ext)
    except ImportError:
        console.print("[red]PDF export needs reportlab: pip install reportlab[/]")
        _pause()
        return
    except Exception as exc:
        console.print(f"[red]Export failed: {exc}[/]")
        _pause()
        return

    console.print(Panel(
        f"[bold green]Exported:[/] {path}\n"
        f"[dim]{len(case.get_findings())} finding(s) · {ext.upper()}[/]",
        title="[bold green]EXPORT COMPLETE[/]",
        border_style="green",
    ))
    _pause()


# ---------------------------------------------------------------------------
# license screen
# ---------------------------------------------------------------------------


def _activate_key(license_info):
    console.clear()
    console.print(Panel(
        "[bold green]ACTIVATE LICENSE[/]\n\n"
        "[dim]Enter a VOL-XXXX-XXXX-XXXX key. The key binds to this device on first use.[/]\n"
        "[dim]Leave blank to cancel.[/]",
        border_style="green",
    ))
    entered = _ask_line("[bold green]Key[/]: ").strip()
    if not entered:
        return license_info

    hwid = config.get_hwid()
    ghost = config.get_ghost_key()
    key = entered
    if ghost and hmac.compare_digest(entered, ghost):
        key = auth.ensure_ghost_license(hwid)
        console.print("[dim]Ghost admin key accepted.[/]")

    info = auth.validate_key(key, hwid)
    if not info.get("valid"):
        console.print(f"[red]Invalid: {info.get('reason') or 'key rejected'}[/]")
        _pause()
        return license_info

    auth.save_session(key, hwid)
    auth.audit(key, "session_activate", f"tier={info.get('tier')}")
    console.print(Panel(
        f"{tier_badge(info.get('tier'))}  {role_badge(info.get('role') or 'member')}\n"
        f"[dim]Credits[/] [bold]{credits_text(info)}[/]\n"
        f"[dim]Expires[/] {info.get('expires') or 'never'}",
        title="[bold green]LICENSE ACTIVE[/]",
        border_style="green",
    ))
    _pause()
    return info


def _profile_table(profile):
    table = Table(expand=True)
    table.add_column("Field", style="cyan", width=18)
    table.add_column("Value", style="white")
    table.add_row("Username", profile.get("username") or "-")
    table.add_row("Role", profile.get("role") or "member")
    table.add_row("Tier", tier_badge(profile.get("tier", "FREE")))
    table.add_row(
        "Credits",
        "unlimited" if profile.get("unlimited") else str(profile.get("credits")),
    )
    table.add_row("Bio", profile.get("bio") or "-")
    table.add_row("Created", (profile.get("created") or "-")[:19])
    table.add_row("Last login", (profile.get("last_login") or "-")[:19])
    table.add_row("Cases", str(profile.get("cases", 0)))
    table.add_row("Findings", str(profile.get("findings", 0)))
    table.add_row("Key suffix", f"…{profile.get('key_suffix') or '----'}")
    table.add_row("Profile URL", profile.get("profile_url") or "-")
    if profile.get("banned"):
        table.add_row("State", "[red]suspended[/]")
    return table


def _search_users_screen():
    while True:
        console.clear()
        query = _ask_line(
            "[bold green]Search username or bio[/] [dim](blank = recent accounts)[/]: "
        ).strip()
        if not query:
            profiles = accounts.list_accounts(limit=18)
        else:
            profiles = accounts.search_profiles(query, limit=18)

        if not profiles:
            console.print("[yellow]No matching profiles.[/]")
            _pause()
            return

        table = Table(expand=True)
        table.add_column("#", style="bold green", width=3)
        table.add_column("Username", style="bold white")
        table.add_column("Role", style="cyan")
        table.add_column("Tier", style="yellow")
        table.add_column("Bio", style="dim")
        for idx, profile in enumerate(profiles, 1):
            table.add_row(
                str(idx),
                profile.get("username") or "-",
                profile.get("role") or "member",
                profile.get("tier") or "FREE",
                (profile.get("bio") or "-")[:70],
            )
        title = f"[bold green]PROFILES[/]  [dim]{query or 'recent accounts'}[/]"
        console.print(Panel(table, title=title, border_style="green"))
        console.print("[dim]1-9 view profile  ·  s search again  ·  Enter back[/]")
        _prompt("[bold green]profile #>[/] ")
        key = read_key()
        console.print()

        if key in ("\r", "\n", ""):
            return
        if key == "s":
            continue
        if not key.isdigit() or key == "0":
            continue
        idx = int(key) - 1
        if 0 <= idx < len(profiles):
            console.clear()
            profile = accounts.public_profile(profiles[idx]["username"])
            console.print(Panel(
                _profile_table(profile),
                title=f"[bold green]PROFILE · {profile.get('username')}[/]",
                border_style="green",
            ))
            _pause()


def _edit_bio(license_info):
    account = accounts.account_for_key((license_info or {}).get("key", ""))
    if not account:
        console.print("[yellow]This license is not linked to an account.[/]")
        _pause()
        return
    console.clear()
    current = accounts.get_account(account["username"]).get("bio") or ""
    console.print(Panel(
        f"[bold green]EDIT BIO[/]\n\n[dim]Current:[/] {current or 'none'}\n"
        "[dim]Up to 400 characters. Blank clears the bio.[/]",
        border_style="green",
    ))
    bio = _ask_line("[bold green]bio[/]: ").strip()
    if accounts.update_profile(account["username"], bio=bio):
        auth.audit(account["username"], "profile_bio", bio[:120])
        console.print("[bold green]Bio updated.[/]")
    else:
        console.print("[red]Could not update bio.[/]")
    _pause()


def _profile_screen(license_info):
    while True:
        console.clear()
        account = accounts.account_for_key((license_info or {}).get("key", ""))
        if account:
            profile = accounts.public_profile(account["username"])
            console.print(Panel(
                _profile_table(profile),
                title=f"[bold green]MY PROFILE · {profile.get('username')}[/]",
                border_style="green",
            ))
        else:
            console.print(Panel(
                "[bold yellow]This license is not linked to an account.[/]\n\n"
                "[dim]Restart VOLUME and create an account to claim a username.[/]",
                border_style="yellow",
            ))
        console.print(_contacts_panel())
        console.print("[dim]e edit bio  ·  f find users  ·  Enter back[/]")
        _prompt("[bold green]profile>[/] ")
        key = read_key()
        console.print()

        if key in ("\r", "\n", ""):
            return
        if key == "e":
            _edit_bio(license_info)
        elif key == "f":
            _search_users_screen()


def _license_screen(license_info):
    while True:
        console.clear()
        info = license_info or {}
        tier = info.get("tier", "FREE")
        key = info.get("key", "-")
        account = accounts.account_for_key(key)
        table = Table(expand=True)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Account", account.get("username") or "guest")
        table.add_row("Role", role_badge(_display_role(info)))
        table.add_row("Tier", tier_badge(tier))
        table.add_row("Credits", credits_text(info))
        table.add_row("Key", key)
        table.add_row("HWID", config.get_hwid())
        table.add_row("Device", config.get_device_name())
        table.add_row("Bound", "yes" if info.get("hwid_bound") else "no")
        table.add_row("Created", info.get("created") or "-")
        table.add_row("Expires", info.get("expires") or "never")
        table.add_row("Days left", str(info.get("days_left")) if info.get("days_left") is not None else "-")
        table.add_row("Daily refill", str(info.get("daily_credits") or 0))
        table.add_row("Admin", "yes" if info.get("admin") else "no")
        table.add_row("Valid", "yes" if info.get("valid") else f"no ({info.get('reason')})")
        table.add_row("Note", info.get("note") or "-")

        ledger_rows = auth.recent_ledger(info.get("key", ""), 8) if info.get("key") else []
        body = [table]
        if ledger_rows:
            ledger = Table(expand=True)
            ledger.add_column("When", style="dim", width=20)
            ledger.add_column("Delta", style="cyan", width=7)
            ledger.add_column("Balance", style="white", width=9)
            ledger.add_column("Reason", style="dim")
            for entry in ledger_rows:
                delta = entry.get("delta") or 0
                ledger.add_row(
                    (entry.get("created") or "")[:19],
                    f"{delta:+d}",
                    str(entry.get("balance")),
                    entry.get("reason") or "-",
                )
            body.append(Panel(ledger, title="[dim]RECENT CREDIT LEDGER[/]", border_style="green"))

        console.print(Panel(
            body[0],
            title="[bold green]LICENSE / CREDITS[/]",
            border_style="green",
        ))
        for extra in body[1:]:
            console.print(extra)
        console.print(
            "[dim]c change key  ·  p my profile  ·  f find users  ·  "
            "a founder code  ·  l log out  ·  Enter back[/]"
        )
        _prompt("[bold green]license>[/] ")
        key_pressed = read_key()
        console.print()

        if key_pressed in ("\r", "\n", ""):
            return license_info
        if key_pressed == "c":
            license_info = _activate_key(license_info)
            continue
        if key_pressed == "a":
            license_info = _founder_code_screen(license_info)
            continue
        if key_pressed == "p":
            _profile_screen(license_info)
            continue
        if key_pressed == "f":
            _search_users_screen()
            continue
        if key_pressed == "l":
            auth.clear_session()
            console.print("[dim]Session cleared. Restart to re-authenticate.[/]")
            _pause()
            return license_info


def _founder_code_screen(license_info):
    """Promote the signed-in account to founder with VOLUME_FOUNDER_TOKEN."""
    console.clear()
    account = accounts.account_for_key((license_info or {}).get("key", ""))
    if not account:
        console.print(Panel(
            "[bold yellow]Sign in with an account before claiming founder.[/]\n\n"
            "[dim]Create an account first (Enter on the license screen), then\n"
            "use this code to promote it.[/]",
            border_style="yellow",
        ))
        _pause()
        return license_info

    console.print(Panel(
        "[bold green]FOUNDER CODE[/]\n\n"
        "[dim]Enter the VOLUME_FOUNDER_TOKEN from .env. This makes the account\n"
        "the permanent founder: full admin, all modules, unlimited credits.\n"
        "There is only ever one founder.[/]",
        border_style="green",
    ))
    token = _ask_line("[bold green]founder token[/]: ", password=True).strip()
    if not token:
        return license_info

    result = accounts.claim_founder(account["username"], token)
    if result.get("ok"):
        console.print(Panel(
            f"[bold green]Founder access granted to {result.get('username')}.[/]\n"
            "[dim]Re-open the license screen to see the updated role.[/]",
            border_style="green",
        ))
        _refresh_license(license_info)
    else:
        console.print(f"[red]{result.get('error') or 'Founder code rejected.'}[/]")
    _pause()
    return license_info


# ---------------------------------------------------------------------------
# admin
# ---------------------------------------------------------------------------


def _print_keys(rows):
    table = Table(expand=True)
    table.add_column("Key", style="bold green")
    table.add_column("Tier", style="cyan")
    table.add_column("Credits", style="white", width=9)
    table.add_column("HWID", style="dim", width=18)
    table.add_column("Expires", style="dim", width=12)
    table.add_column("State", style="yellow", width=10)
    table.add_column("Note", style="dim")
    for info in rows:
        state = "revoked" if info.get("revoked") else ("expired" if info.get("expired") else "active")
        table.add_row(
            info.get("key", "-"),
            info.get("tier", "-"),
            licensing.format_credits(info),
            (info.get("hwid") or "-")[:18],
            (info.get("expires") or "never")[:10],
            state,
            (info.get("note") or "")[:24],
        )
    console.print(Panel(table, title="[bold green]LICENSE KEYS[/]", border_style="green"))


def _actor(license_info):
    """Resolve the acting account name and role for admin actions."""
    info = license_info or {}
    account = accounts.account_for_key(info.get("key", ""))
    name = (account or {}).get("username") or info.get("key", "admin")
    role = (account or {}).get("role") or (
        "founder" if info.get("founder") else "admin" if info.get("admin") else "member"
    )
    return name, roles.normalize_role(role)


def _account_table(profiles, show_key=False):
    table = Table(expand=True)
    table.add_column("#", style="bold green", width=3)
    table.add_column("Username", style="bold white")
    table.add_column("Role", style="cyan")
    table.add_column("Tier", style="yellow")
    table.add_column("State", style="red", width=8)
    table.add_column("Created", style="dim", width=12)
    if show_key:
        table.add_column("Key", style="dim")
    for idx, profile in enumerate(profiles, 1):
        state = "banned" if profile.get("banned") else "active"
        row = [
            str(idx),
            profile.get("username") or "-",
            profile.get("role") or "member",
            profile.get("tier") or "FREE",
            state,
            (profile.get("created") or "")[:10],
        ]
        if show_key:
            row.append(f"…{profile.get('key_suffix') or '----'}")
        table.add_row(*row)
    return table


def _admin_accounts_screen(license_info):
    """Founder/admin account management: roles, bans and key issuing."""
    actor, actor_role = _actor(license_info)
    grants = roles.assignable_roles(actor_role)

    while True:
        console.clear()
        profiles = accounts.list_accounts(limit=20)
        console.print(Panel(
            _account_table(profiles),
            title="[bold green]ACCOUNTS[/]",
            border_style="green",
        ))
        console.print(
            "[dim]1 list  2 view  3 set role  4 grant admin  5 revoke admin  "
            "6 ban  7 unban  8 issue key  9 reset key  ·  Enter back[/]"
        )
        console.print(
            f"[dim]Your role: {role_badge(actor_role)}  ·  "
            f"can grant: {', '.join(grants) or 'none'}[/]"
        )
        _prompt("[bold green]account>[/] ")
        choice = read_key()
        console.print()

        if choice in ("\r", "\n", ""):
            return license_info

        if choice == "1":
            console.clear()
            console.print(Panel(
                _account_table(accounts.list_accounts(limit=100), show_key=True),
                title="[bold green]ALL ACCOUNTS[/]",
                border_style="green",
            ))
            _pause()
            continue

        username = _ask_line("[bold green]Username[/]: ").strip()
        if not username:
            continue

        if choice == "2":
            profile = accounts.public_profile(username)
            console.clear()
            if profile:
                console.print(Panel(
                    _profile_table(profile),
                    title=f"[bold green]ACCOUNT · {profile.get('username')}[/]",
                    border_style="green",
                ))
            else:
                console.print(f"[red]No account '{username}'.[/]")
            _pause()
            continue

        if choice == "3":
            if not grants:
                console.print("[red]You cannot grant roles.[/]")
                _pause()
                continue
            console.print(f"[dim]Assignable roles: {', '.join(grants)}[/]")
            new_role = _ask_line("[bold green]New role[/]: ").strip()
            result = accounts.set_role(username, new_role, actor=actor, actor_role=actor_role)
            console.print(
                f"[green]{result.get('username')} is now {result.get('role')}.[/]"
                if result.get("ok") else f"[red]{result.get('error')}[/]"
            )
            _pause()
            continue

        if choice in ("4", "5"):
            if not roles.is_founder(actor_role):
                console.print("[red]Only the founder can grant or revoke admin.[/]")
                _pause()
                continue
            verb = "Give admin to" if choice == "4" else "Remove admin from"
            if not _confirm(f"{verb} {username}?"):
                continue
            result = (
                accounts.grant_admin(username, actor=actor, actor_role=actor_role)
                if choice == "4"
                else accounts.revoke_admin(username, actor=actor, actor_role=actor_role)
            )
            console.print(
                f"[green]{result.get('username')} is now {result.get('role')}.[/]"
                if result.get("ok") else f"[red]{result.get('error')}[/]"
            )
            _pause()
            continue

        if choice in ("6", "7"):
            result = accounts.set_banned(
                username, choice == "6", actor=actor, actor_role=actor_role
            )
            console.print(
                f"[green]{'Suspended' if choice == '6' else 'Restored'} "
                f"{result.get('username')}.[/]"
                if result.get("ok") else f"[red]{result.get('error')}[/]"
            )
            _pause()
            continue

        if choice == "8":
            console.print("[dim]1 FREE  2 PREMIUM  3 DETECTIVE  4 INDUSTRIAL  5 LIFETIME[/]")
            tier_key = _ask_line("[bold green]Tier[/] [dim](2)[/]: ").strip() or "2"
            tier = {
                "1": "FREE", "2": "PREMIUM", "3": "DETECTIVE",
                "4": "INDUSTRIAL", "5": "LIFETIME",
            }.get(tier_key, "PREMIUM")
            days = _ask_int("[bold green]Days[/] [dim](0 = never)[/]: ", 0) or 0
            credits = _ask_int("[bold green]Credits[/] [dim](blank = default)[/]: ", None)
            note = _ask_line("[bold green]Note[/]: ").strip()
            result = accounts.issue_key(
                username, tier=tier, days=days, credits=credits, note=note, actor=actor
            )
            if result.get("ok"):
                console.print(Panel(
                    f"[bold white]Account:[/] {result['username']}\n"
                    f"[bold white]New key:[/] [bold green]{result['key']}[/]\n"
                    f"[bold white]Tier:[/] {result['tier']}\n"
                    f"[bold white]Days:[/] {'never' if not days else days}\n"
                    f"[dim]Previous key revoked. Give the new key to the user.[/]",
                    title="[bold green]KEY ISSUED[/]",
                    border_style="green",
                ))
            else:
                console.print(f"[red]{result.get('error')}[/]")
            _pause()
            continue

        if choice == "9":
            if not _confirm(f"Reissue the key for {username}?"):
                continue
            result = accounts.reissue_key(username, actor=actor)
            if result.get("ok"):
                console.print(Panel(
                    f"[bold white]Account:[/] {result['username']}\n"
                    f"[bold white]New key:[/] [bold green]{result['key']}[/]\n"
                    f"[bold white]Tier:[/] {result['tier']}",
                    title="[bold green]KEY REISSUED[/]",
                    border_style="green",
                ))
            else:
                console.print(f"[red]{result.get('error')}[/]")
            _pause()
            continue


def _admin_issue_key_screen(license_info):
    actor, _actor_role = _actor(license_info)
    console.clear()
    console.print(Panel(
        "[bold green]ISSUE KEY TO ACCOUNT[/]\n\n"
        "[dim]Mints a fresh key for an existing account and revokes their old one.[/]",
        border_style="green",
    ))
    username = _ask_line("[bold green]Username[/]: ").strip()
    if not username:
        return license_info
    console.print("[dim]1 FREE  2 PREMIUM  3 DETECTIVE  4 INDUSTRIAL  5 LIFETIME[/]")
    tier_key = _ask_line("[bold green]Tier[/] [dim](2)[/]: ").strip() or "2"
    tier = {
        "1": "FREE", "2": "PREMIUM", "3": "DETECTIVE",
        "4": "INDUSTRIAL", "5": "LIFETIME",
    }.get(tier_key, "PREMIUM")
    days = _ask_int("[bold green]Days[/] [dim](0 = never)[/]: ", 0) or 0
    credits = _ask_int("[bold green]Credits[/] [dim](blank = default)[/]: ", None)
    note = _ask_line("[bold green]Note[/]: ").strip()
    result = accounts.issue_key(
        username, tier=tier, days=days, credits=credits, note=note, actor=actor
    )
    if result.get("ok"):
        console.print(Panel(
            f"[bold white]Account:[/] {result['username']}\n"
            f"[bold white]New key:[/] [bold green]{result['key']}[/]\n"
            f"[bold white]Tier:[/] {result['tier']}\n"
            f"[bold white]Days:[/] {'never' if not days else days}\n"
            f"[dim]Previous key revoked. Give the new key to the user.[/]",
            title="[bold green]KEY ISSUED[/]",
            border_style="green",
        ))
    else:
        console.print(f"[red]{result.get('error')}[/]")
    _pause()
    return license_info


def _admin_flow(license_info, choice):
    actor, actor_role = _actor(license_info)

    if choice == "1":
        console.clear()
        console.print(Panel(
            "[bold green]GENERATE KEY[/]\n\n"
            "1 FREE   2 PREMIUM   3 DETECTIVE   4 INDUSTRIAL   5 LIFETIME",
            border_style="green",
        ))
        _prompt("[bold green]tier>[/] ")
        tier_key = read_key()
        console.print()
        tier = {
            "1": "FREE", "2": "PREMIUM", "3": "DETECTIVE",
            "4": "INDUSTRIAL", "5": "LIFETIME",
        }.get(tier_key)
        if not tier:
            return license_info
        days = _ask_int("[bold green]Days until expiry[/] [dim](0 = never)[/]: ", 30) or 0
        credits = _ask_int("[bold green]Credit override[/] [dim](blank = tier default)[/]: ", None)
        note = _ask_line("[bold green]Note[/]: ").strip()
        assignee = _ask_line(
            "[bold green]Assign to username[/] [dim](blank = standalone key)[/]: "
        ).strip()
        if assignee:
            result = accounts.issue_key(
                assignee, tier=tier, days=days, credits=credits, note=note, actor=actor
            )
            if not result.get("ok"):
                console.print(f"[red]{result.get('error')}[/]")
                _pause()
                return license_info
            new_key = result["key"]
        else:
            try:
                new_key = auth.generate_key(tier=tier, days=days, credits=credits, note=note)
            except Exception as exc:
                console.print(f"[red]Could not generate key: {exc}[/]")
                _pause()
                return license_info
        console.print(Panel(
            f"[bold white]Key:[/] [bold green]{new_key}[/]\n"
            f"[bold white]Tier:[/] {tier}\n"
            f"[bold white]Credits:[/] {credits if credits is not None else licensing.TIERS[tier]['credits']}\n"
            f"[bold white]Days:[/] {'never expires' if days == 0 else days}"
            + (f"\n[bold white]Assigned to:[/] {assignee}" if assignee else ""),
            title="[bold green]KEY GENERATED[/]",
            border_style="green",
        ))
        _pause()
        return license_info

    if choice == "2":
        console.clear()
        _print_keys(auth.list_keys(limit=30, include_device=True))
        _pause()
        return license_info

    if choice in ("3", "4"):
        console.clear()
        label = "ADD CREDITS" if choice == "3" else "SET CREDITS"
        console.print(Panel(f"[bold green]{label}[/]", border_style="green"))
        key = _ask_line("[bold green]Key[/]: ").strip()
        amount = _ask_int("[bold green]Amount[/]: ", 0) or 0
        if not key:
            return license_info
        result = (
            auth.add_credits(key, amount, actor=actor)
            if choice == "3"
            else auth.set_credits(key, amount, actor=actor)
        )
        console.print(
            f"[green]OK · balance {result.get('remaining')}[/]"
            if result.get("ok") else f"[red]{result.get('error')}[/]"
        )
        _pause()
        return license_info

    if choice == "5":
        console.clear()
        console.print(Panel(
            "[bold green]REVOKE / UNREVOKE[/]\n\n"
            "[bold]r[/] revoke   [bold]u[/] unrevoke",
            border_style="green",
        ))
        _prompt("[bold green]action>[/] ")
        action = read_key()
        console.print()
        key = _ask_line("[bold green]Key[/]: ").strip()
        if not key or action not in ("r", "u"):
            return license_info
        ok = auth.revoke_key(key, actor=actor) if action == "r" else auth.unrevoke_key(key, actor=actor)
        console.print("[green]Done.[/]" if ok else "[red]Key not found.[/]")
        _pause()
        return license_info

    if choice == "6":
        console.clear()
        console.print(Panel("[bold green]RESET HWID BINDING[/]", border_style="green"))
        key = _ask_line("[bold green]Key[/]: ").strip()
        if not key:
            return license_info
        ok = auth.reset_hwid(key, actor=actor)
        console.print("[green]HWID cleared; next use re-binds.[/]" if ok else "[red]Key not found.[/]")
        _pause()
        return license_info

    if choice == "7":
        console.clear()
        console.print(Panel("[bold red]DELETE KEY[/]", border_style="red"))
        key = _ask_line("[bold green]Key[/]: ").strip()
        if not key:
            return license_info
        if not _confirm(f"Delete {key} permanently?"):
            return license_info
        ok = auth.delete_key(key, actor=actor)
        console.print("[green]Deleted.[/]" if ok else "[red]Could not delete (device keys are protected).[/]")
        _pause()
        return license_info

    if choice == "8":
        console.clear()
        stats = auth.stats()
        table = Table(expand=True)
        table.add_column("Tier", style="cyan")
        table.add_column("Keys", style="white")
        table.add_column("Credits", style="white")
        for tier in licensing.TIER_ORDER:
            data = stats["tiers"].get(tier) or {}
            table.add_row(tier, str(data.get("count", 0)), str(data.get("credits", 0)))
        table.add_row("FREE devices", str(stats.get("devices", 0)), "-")
        console.print(Panel(table, title="[bold green]LICENSE STATS[/]", border_style="green"))
        _pause()
        return license_info

    if choice == "9":
        console.clear()
        rows = auth.recent_audit(25)
        table = Table(expand=True)
        table.add_column("When", style="dim", width=20)
        table.add_column("Actor", style="cyan", width=18)
        table.add_column("Action", style="white", width=18)
        table.add_column("Detail", style="dim")
        for row in rows:
            table.add_row(
                (row.get("ts") or "")[:19],
                (row.get("actor") or "-")[:18],
                row.get("action") or "-",
                (row.get("detail") or "")[:80],
            )
        console.print(Panel(table, title="[bold green]AUDIT LOG[/]", border_style="green"))
        _pause()
        return license_info

    if choice == "a":
        return _admin_accounts_screen(license_info)

    if choice == "i":
        return _admin_issue_key_screen(license_info)

    return license_info


# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------


def _help():
    console.clear()
    console.print(Panel(
        "[bold]NAVIGATION[/]\n"
        "[bold]n / p[/]        next / previous tab (arrows too)\n"
        "[bold]c u o e g b[/]  Cases / Lookup / OSINT / Leaks / GeoSINT / Breaches\n"
        "[bold]m s d i[/]      Malicious / CSINT / Discord / Investigation\n"
        "[bold][ / ][/]       previous / next tool page\n"
        "[bold]1-9[/]         run a tool from the current page\n"
        "[bold]x[/]           quick paste / auto-extract indicators\n"
        "[bold]k[/]           license, credits, profile and key activation\n"
        "[bold]f[/]           search user profiles (username rarity)\n"
        "[bold]v[/]           switch mobile / PC layout\n"
        "[bold]r[/]           redraw\n"
        "[bold]l[/]           log out\n"
        "[bold]q[/]           quit\n\n"
        "[bold green]CASES TAB[/]\n"
        "[bold]n[/]           new case\n"
        "[bold]b[/]           browse / open a saved case\n"
        "[bold]d[/]           delete the current case\n"
        "[bold]e[/]           export (JSON/TXT/CSV/MD free; HTML/PDF premium)\n"
        "[bold]s[/]           case statistics\n"
        "[bold]t[/]           edit notes / tags / analyst\n\n"
        "[bold green]LICENSE / ACCOUNT[/]\n"
        "[bold]a[/]           founder code (promote this account to founder)\n\n"
        "[bold green]ADMIN TAB (admins & founder)[/]\n"
        "1 generate  2 list  3 add credits  4 set credits  5 revoke\n"
        "6 reset HWID  7 delete  8 stats  9 audit\n"
        "[bold]a[/]           accounts: roles, ban/unban, issue or reset keys\n"
        "[bold]i[/]           issue a key straight to an account\n\n"
        "[dim]The founder can grant permanent admin. Admins can grant manager and\n"
        "below. Founder is claimed only with VOLUME_FOUNDER_TOKEN.[/]\n\n"
        "[dim]Credits are spent before a module runs and refunded automatically when a\n"
        "source is down, a key is missing, or the module errors.[/]",
        title="[bold green]HELP[/]",
        border_style="green",
    ))
    _pause()


# ---------------------------------------------------------------------------
# main loop
# ---------------------------------------------------------------------------


def run_app(case, license_info, modules, mode="auto"):
    if case is None:
        case = _default_case(license_info)
        if case is None:
            console.print("[yellow]Could not open the workspace case.[/]")

    if mode not in ("mobile", "pc"):
        mode = "mobile" if console.size.width < 100 else "pc"

    is_admin = bool((license_info or {}).get("admin"))
    tabs = get_tab_list(is_admin)
    tab_idx = tabs.index("OSINT") if "OSINT" in tabs else 0
    pages = {}

    shortcuts = {
        "c": "CASES",
        "u": "LOOKUP",
        "o": "OSINT",
        "e": "LEAKS",
        "g": "GEOSINT",
        "b": "BREACHES",
        "m": "MALICIOUS",
        "s": "CSINT",
        "d": "DISCORD",
        "i": "INVESTIGATION",
    }
    if is_admin:
        shortcuts["a"] = "ADMIN"

    try:
        while True:
            tabs = get_tab_list(is_admin)
            if tab_idx >= len(tabs):
                tab_idx = 0
            active_tab = tabs[tab_idx]

            if active_tab in ("CASES", "ADMIN"):
                page_count = 1
                page = 0
            else:
                page_count = catalog.page_count(modules, active_tab)
                page = max(0, min(pages.get(active_tab, 0), page_count - 1))
                pages[active_tab] = page

            console.clear()
            console.print(create_layout(
                active_tab, case, license_info, modules, is_admin,
                pulse_state=0, compact=(mode == "mobile"),
                page=page, page_count=page_count,
            ))
            _prompt("\n[bold green]vol>[/] ")
            key = read_key()
            console.print()

            if key in ("q", "\x03"):
                return
            if key == "l":
                auth.clear_session()
                console.print("[dim]Session cleared.[/]")
                return
            if key == "k":
                license_info = _license_screen(license_info)
                _refresh_license(license_info)
                is_admin = bool(license_info.get("admin"))
                continue
            if key == "f":
                _search_users_screen()
                continue
            if key == "v":
                mode = "pc" if mode == "mobile" else "mobile"
                continue
            if key == "?":
                _help()
                continue
            if key == "x":
                license_info = _quick_extract(case, license_info, modules)
                continue
            if key in ("r", "\r", "\n", ""):
                continue
            if key in ("n", "\t", "right", "down"):
                tab_idx = (tab_idx + 1) % len(tabs)
                continue
            if key in ("p", "left", "up"):
                tab_idx = (tab_idx - 1) % len(tabs)
                continue
            if key == "[":
                if active_tab not in ("CASES", "ADMIN"):
                    pages[active_tab] = max(0, pages.get(active_tab, 0) - 1)
                continue
            if key == "]":
                if active_tab not in ("CASES", "ADMIN"):
                    pages[active_tab] = min(
                        page_count - 1, pages.get(active_tab, 0) + 1
                    )
                continue

            if active_tab == "CASES":
                if key == "n":
                    case = _new_case(case)
                elif key == "b":
                    case = _browse_cases(case)
                elif key == "d":
                    case = _delete_case(case)
                elif key == "e":
                    _export_case(case, license_info)
                elif key == "s":
                    _case_stats(case)
                elif key == "t":
                    case = _case_meta(case)
                continue

            if active_tab == "ADMIN":
                if (key.isdigit() and key != "0") or key in ("a", "i"):
                    license_info = _admin_flow(license_info, key)
                    _refresh_license(license_info)
                    is_admin = bool(license_info.get("admin"))
                continue

            if key in shortcuts:
                target = shortcuts[key]
                if target in tabs:
                    tab_idx = tabs.index(target)
                continue

            if not key.isdigit() or key == "0":
                continue

            page_modules = catalog.page_slice(modules, active_tab, page)
            idx = int(key) - 1
            if 0 <= idx < len(page_modules):
                license_info = _run_module(page_modules[idx], case, license_info)
            else:
                console.print(f"[yellow]No tool {key} on this page.[/]")
                _pause()
    except KeyboardInterrupt:
        return
    finally:
        if case:
            case.close()
