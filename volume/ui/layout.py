import datetime

import psutil
from rich.align import Align
from rich.console import Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from volume.core import catalog, config, licensing
from volume.ui.theme import (
    LOGO,
    credits_text,
    get_pulse_color,
    get_tab_list,
    get_tabs,
    console,
    role_badge,
    tier_badge,
    tier_color,
)


_smoothed_cpu = None


def _stats():
    """Sample CPU over a short interval and smooth it so the number doesn't jump on every redraw."""
    global _smoothed_cpu
    try:
        raw = psutil.cpu_percent(interval=0.1)
    except Exception:
        raw = 0.0
    if _smoothed_cpu is None:
        _smoothed_cpu = raw
    else:
        _smoothed_cpu = (_smoothed_cpu * 0.6) + (raw * 0.4)
    try:
        ram = psutil.virtual_memory().percent
    except Exception:
        ram = 0.0
    return _smoothed_cpu, ram


def _tier_of(license_info):
    return (license_info or {}).get("tier", "FREE")


def _tools_table(active_tab, modules, border_color, compact=False, page=0):
    page_modules = catalog.page_slice(modules, active_tab, page)

    if compact:
        table = Table(show_header=True, expand=True, box=None, pad_edge=False)
        table.add_column("ID", style="dim", width=3)
        table.add_column("Tool", style="bold white")
        table.add_column("Cost", style="cyan", width=5)
    else:
        table = Table(show_header=True, expand=True, box=None)
        table.add_column("ID", style="dim", width=4)
        table.add_column("Tool", style="bold white")
        table.add_column("Cost", style="cyan", width=7)
        table.add_column("Tier", style="yellow", width=12)
        table.add_column("Description", style="dim")

    for idx, mod in enumerate(page_modules, 1):
        cost = "free" if not mod.credit_cost else str(mod.credit_cost)
        if compact:
            table.add_row(str(idx), mod.label, cost)
        else:
            table.add_row(
                str(idx),
                mod.label,
                cost,
                mod.min_tier,
                mod.description or "Execute module",
            )

    if not page_modules:
        table.add_row("", Text("No modules here yet. Press o for OSINT.", style="dim"))
    return table


def _cases_table(case, border_color, compact=False):
    table = Table(show_header=True, expand=True, box=None, pad_edge=not compact)
    table.add_column("ID", style=border_color, width=4)
    table.add_column("Module", style="white")
    table.add_column("Target", style="dim white")
    if not compact:
        table.add_column("Confidence", style="dim white")
        table.add_column("Date", style="dim white")

    rows = case.get_findings() if case else []
    for finding in rows[-25:]:
        if compact:
            table.add_row(str(finding["id"]), finding["module"], finding["query"] or "-")
        else:
            table.add_row(
                str(finding["id"]),
                finding["module"],
                finding["query"] or "-",
                finding["confidence"] or "-",
                (finding["retrieved_at"] or "")[:10],
            )

    if not rows:
        table.add_row("", Text("No findings yet. Press o then 1 to run a tool.", style="dim"))
    return table


def _admin_table(border_color):
    return Text.from_markup(
        f"[bold {border_color}]KEY / LICENSE ADMIN[/]\n\n"
        f"[bold {border_color}]1[/]  Generate a key\n"
        f"[bold {border_color}]2[/]  List keys\n"
        f"[bold {border_color}]3[/]  Add credits\n"
        f"[bold {border_color}]4[/]  Set credits\n"
        f"[bold {border_color}]5[/]  Revoke / unrevoke key\n"
        f"[bold {border_color}]6[/]  Reset HWID binding\n"
        f"[bold {border_color}]7[/]  Delete key\n"
        f"[bold {border_color}]8[/]  License stats\n"
        f"[bold {border_color}]9[/]  Audit log\n\n"
        f"[bold {border_color}]a[/]  Accounts / roles / ban\n"
        f"[bold {border_color}]i[/]  Issue a key to an account\n\n"
        f"[dim]Founder can grant admin permanently. All admin actions are audited.[/]"
    )


def _content(active_tab, case, modules, border_color, compact=False, page=0):
    if active_tab == "ADMIN":
        return _admin_table(border_color)
    if active_tab == "CASES":
        return _cases_table(case, border_color, compact)
    return _tools_table(active_tab, modules, border_color, compact, page)


def _license_line(license_info, border_color, compact=False):
    info = license_info or {}
    tier = _tier_of(info)
    badge = tier_badge(tier)
    role = info.get("role") or "member"
    if role == "member" and info.get("admin"):
        role = "admin"
    if role != "member":
        badge = f"{badge} {role_badge(role)}"
    credits = credits_text(info)
    if compact:
        return f"{badge} [dim]credits[/] [bold white]{credits}[/]"
    key = info.get("key") or "-"
    hwid = (info.get("hwid") or "")[:16] or "-"
    days = info.get("days_left")
    expiry = "never" if not info.get("expires") else f"{days} day(s)" if days is not None else "-"
    return (
        f"{badge}\n"
        f"[dim]Credits[/] [bold white]{credits}[/]\n"
        f"[dim]Key[/] {key}\n"
        f"[dim]HWID[/] {hwid}\n"
        f"[dim]Expires[/] {expiry}"
    )


def _compact_layout(active_tab, case, license_info, modules, is_admin, pulse_state, page=0, page_count=1):
    border_color = get_pulse_color(pulse_state)
    cpu, ram = _stats()
    now = datetime.datetime.now().strftime("%H:%M:%S")
    tier = _tier_of(license_info)

    case_name = case.name if case else "WORKSPACE"
    analyst = case.analyst if case else "analyst"
    header = Panel(
        f"[bold {border_color}]VOLUME[/]  [dim]MOBILE[/]  {tier_badge(tier)}  [dim]{now}[/]\n"
        f"[dim]CASE[/] {case_name}  [dim]BY[/] {analyst}  [dim]CPU[/] {cpu:.0f}%  [dim]RAM[/] {ram:.0f}%\n"
        f"{_license_line(license_info, border_color, compact=True)}",
        border_style=border_color,
        padding=(0, 1),
    )

    tabs = get_tab_list(is_admin)
    pos = tabs.index(active_tab) + 1 if active_tab in tabs else 0
    tab_line = Panel(
        f"[bold black on {border_color}] {active_tab} [/] [dim]{pos}/{len(tabs)}   n/p = tab[/]",
        border_style=border_color,
        padding=(0, 1),
    )

    body_title = f"CASES - {case.name}" if active_tab == "CASES" and case else active_tab
    if active_tab not in ("CASES", "ADMIN"):
        body_title = f"{body_title}  [{page + 1}/{page_count}]"
    body = Panel(
        _content(active_tab, case, modules, border_color, compact=True, page=page),
        title=f"[bold {border_color}]{body_title}[/]",
        border_style=border_color,
        padding=(0, 1),
    )

    if active_tab == "CASES":
        hint = "n new  b open  d delete  e export  s stats  k license  q quit"
    elif active_tab == "ADMIN":
        hint = "1-9 admin  a accounts  i issue  n/p tabs  k license  q quit"
    elif active_tab == "INVESTIGATION":
        hint = "x paste  1-9 run  [ ] page  k license  q quit"
    else:
        hint = "1-9 run  [ ] page  n/p tabs  u/o/e/g/b jump  f find  k license  q quit"

    footer = Panel(
        f"[dim]{hint}[/]",
        border_style=border_color,
        padding=(0, 1),
    )
    return Group(header, tab_line, body, footer)


def _wide_layout(active_tab, case, license_info, modules, is_admin, pulse_state, page=0, page_count=1):
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=8),
        Layout(name="main"),
        Layout(name="footer", size=3),
    )
    layout["main"].split_row(
        Layout(name="sidebar", size=38),
        Layout(name="body"),
    )

    border_color = get_pulse_color(pulse_state)
    tier = _tier_of(license_info)

    # --- SIDEBAR ---
    cpu, ram = _stats()
    case_stats = case.stats() if case else {"findings": 0, "entities": 0}
    status_text = (
        f"{_license_line(license_info, border_color)}\n\n"
        f"[bold {border_color}]CASE:[/] {case.name if case else 'WORKSPACE'}\n"
        f"[bold {border_color}]ANALYST:[/] {case.analyst if case else 'analyst'}\n"
        f"[dim]Findings[/] {case_stats['findings']}  [dim]Entities[/] {case_stats['entities']}\n"
        f"[bold {border_color}]VIEW:[/] PC\n\n"
        f"[dim]CPU LOAD:[/] [{border_color}]{cpu:.0f}%[/]\n"
        f"[dim]RAM USAGE:[/] [{border_color}]{ram:.0f}%[/]"
    )
    layout["sidebar"].update(Panel(
        status_text,
        title=f"[bold {border_color}]SYSTEM STATUS[/]",
        border_style=border_color,
    ))

    # --- HEADER ---
    now = datetime.datetime.now().strftime("%H:%M:%S")
    header_grid = Table.grid(expand=True)
    header_grid.add_column(justify="center")
    header_grid.add_column(justify="right", width=24)
    header_grid.add_row(
        Text.from_markup(LOGO),
        Text.from_markup(
            f"\n[{border_color}]● API [ONLINE][/]\n[dim]{now}  ·  v{config.VERSION}[/]"
        ),
    )
    layout["header"].update(header_grid)

    # --- BODY (TABS & MODULES) ---
    tab_panel = Panel(
        Align.center(get_tabs(active_tab, is_admin)),
        border_style=border_color,
        height=3,
    )
    body_title = f"CASES - {case.name}" if active_tab == "CASES" and case else active_tab
    if active_tab not in ("CASES", "ADMIN"):
        body_title = f"{body_title}  ·  page {page + 1}/{page_count}"
    body_panel = Panel(
        _content(active_tab, case, modules, border_color, compact=False, page=page),
        title=f"[dim {border_color}]──────────────── {body_title} ────────────────[/]",
        border_style=border_color,
        padding=(1, 2),
    )

    layout["body"].split_column(
        Layout(tab_panel, size=3),
        Layout(body_panel),
    )

    # --- FOOTER ---
    if active_tab == "CASES":
        footer_text = (
            f"[bold {border_color}]\\[N]ew | \\[B]rowse | \\[D]elete | \\[E]xport | "
            f"\\[S]tats | \\[K]ey | \\[Q]uit[/]"
        )
    elif active_tab == "ADMIN":
        footer_text = (
            f"[bold {border_color}]\\[1-9] Admin | \\[A]ccounts | \\[I]ssue key | "
            f"\\[N/P] Tabs | \\[K] License | \\[Q]uit[/]"
        )
    else:
        footer_text = (
            f"[bold {border_color}]\\[N/P] Tabs | \\[1-9] Run | \\[ ] Page | "
            f"\\[U] Lookup | \\[O] OSINT | \\[E] Leaks | \\[G] GeoSINT | "
            f"\\[B] Breaches | \\[F] Find | \\[K] License | \\[Q]uit[/]"
        )
    layout["footer"].update(Panel(Align.center(footer_text), border_style=border_color))

    return layout


def create_layout(active_tab, case, license_info, modules, is_admin, pulse_state,
                  compact=None, page=0, page_count=1):
    if compact is None:
        compact = console.size.width < 100
    if compact:
        return _compact_layout(
            active_tab, case, license_info, modules, is_admin, pulse_state, page, page_count
        )
    return _wide_layout(
        active_tab, case, license_info, modules, is_admin, pulse_state, page, page_count
    )
