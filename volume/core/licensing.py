"""Tier definitions, credit allowances and feature gates."""

TIER_ORDER = ["FREE", "PREMIUM", "DETECTIVE", "INDUSTRIAL", "LIFETIME"]

TIERS = {
    "FREE": {
        "rank": 1,
        "credits": 25,
        "max_credits": 25,
        "daily": 5,
        "color": "white",
        "unlimited": False,
        "label": "Free",
    },
    "PREMIUM": {
        "rank": 2,
        "credits": 500,
        "max_credits": 500,
        "daily": 0,
        "color": "cyan",
        "unlimited": False,
        "label": "Premium",
    },
    "DETECTIVE": {
        "rank": 3,
        "credits": 2500,
        "max_credits": 2500,
        "daily": 0,
        "color": "magenta",
        "unlimited": False,
        "label": "Detective",
    },
    "INDUSTRIAL": {
        "rank": 4,
        "credits": 10000,
        "max_credits": 10000,
        "daily": 0,
        "color": "yellow",
        "unlimited": False,
        "label": "Industrial",
    },
    "LIFETIME": {
        "rank": 5,
        "credits": 0,
        "max_credits": 0,
        "daily": 0,
        "color": "bright_green",
        "unlimited": True,
        "label": "Lifetime / Admin",
    },
}

# Which export formats each tier may use.
EXPORT_TIERS = {
    "json": "FREE",
    "txt": "FREE",
    "csv": "FREE",
    "md": "FREE",
    "html": "PREMIUM",
    "pdf": "PREMIUM",
}


def normalize_tier(tier: str) -> str:
    tier = (tier or "FREE").strip().upper()
    return tier if tier in TIERS else "FREE"


def tier_rank(tier: str) -> int:
    return TIERS[normalize_tier(tier)]["rank"]


def tier_allows(user_tier: str, required_tier: str) -> bool:
    return tier_rank(user_tier) >= tier_rank(required_tier)


def is_unlimited(tier: str) -> bool:
    return bool(TIERS[normalize_tier(tier)]["unlimited"])


def defaults(tier: str) -> dict:
    return dict(TIERS[normalize_tier(tier)])


def tier_color(tier: str) -> str:
    return TIERS[normalize_tier(tier)]["color"]


def export_allowed(tier: str, fmt: str) -> bool:
    return tier_allows(tier, EXPORT_TIERS.get(fmt, "FREE"))


def format_credits(info: dict) -> str:
    if not info:
        return "-"
    if info.get("unlimited"):
        return "unlimited"
    credits = info.get("credits")
    if credits is None:
        return "-"
    cap = info.get("max_credits") or 0
    return f"{credits}/{cap}" if cap else str(credits)


def tier_summary() -> list:
    rows = []
    for name in TIER_ORDER:
        t = TIERS[name]
        if t["unlimited"]:
            credits = "unlimited"
        else:
            daily = f" (+{t['daily']}/day)" if t["daily"] else ""
            credits = f"{t['credits']}{daily}"
        rows.append((name, credits, t["label"]))
    return rows
