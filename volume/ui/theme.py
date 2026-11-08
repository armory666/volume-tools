from rich.console import Console
from rich.text import Text

from volume.core import config, licensing, roles

console = Console()

# Gradient logo (Green to Blue)
LOGO = r"""
 [bold #00ff00]██╗   ██╗ ██████╗ ██╗     ██╗   ██╗███╗   ███╗███████╗
 [bold #00ee88]██║   ██║██╔═══██╗██║     ██║   ██║████╗ ████║██╔════╝
 [bold #00ccaa]██║   ██║██║   ██║██║     ██║   ██║██╔████╔██║█████╗  
 [bold #0099cc]╚██╗ ██╔╝██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══╝  
 [bold #0066ff] ╚████╔╝ ╚██████╔╝███████╗╚██████╔╝██║ ╚═╝ ██║███████╗
 [bold #0033ff]  ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝[/]
"""

BASE_TABS = [
    "CASES",
    "LOOKUP",
    "OSINT",
    "LEAKS",
    "GEOSINT",
    "BREACHES",
    "MALICIOUS",
    "CSINT",
    "DISCORD",
    "INVESTIGATION",
]

TIER_COLORS = {name: data["color"] for name, data in licensing.TIERS.items()}


def get_tab_list(is_admin: bool = False) -> list:
    tabs = list(BASE_TABS)
    if is_admin:
        tabs.append("ADMIN")
    return tabs


def get_tabs(active_tab: str, is_admin: bool = False) -> str:
    tabs = get_tab_list(is_admin)
    parts = []
    for tab in tabs:
        if tab == active_tab:
            parts.append(f"[bold black on #00ff00] ▶ {tab} ◀ [/]")
        else:
            parts.append(f" [dim #00aaff]{tab}[/] ")
    return " | ".join(parts)


def get_pulse_color(state: int) -> str:
    colors = ["#00ff00", "#00ee88", "#00ccaa", "#0099cc", "#0066ff"]
    return colors[state % len(colors)]


def tier_color(tier: str) -> str:
    return licensing.tier_color(tier)


def tier_badge(tier: str) -> str:
    tier = licensing.normalize_tier(tier)
    color = tier_color(tier)
    return f"[bold black on {color}] {tier} [/]"


def role_badge(role: str) -> str:
    role = roles.normalize_role(role)
    color = roles.role_color(role)
    return f"[bold black on {color}] {roles.role_label(role)} [/]"


def credits_text(info: dict) -> str:
    if not info:
        return "n/a"
    return licensing.format_credits(info)


def status_color(status: str) -> str:
    return {
        "ok": "green",
        "not_found": "yellow",
        "skipped": "yellow",
        "key_required": "yellow",
        "source_down": "red",
        "error": "red",
    }.get(str(status or "").lower(), "white")


def risk_color(score) -> str:
    try:
        score = int(score)
    except (TypeError, ValueError):
        return "white"
    if score >= 75:
        return "bold red"
    if score >= 50:
        return "red"
    if score >= 25:
        return "yellow"
    return "green"


def mask_key(key: str) -> str:
    return config.mask_key(key)
