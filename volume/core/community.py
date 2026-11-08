"""VOLUME community / support contacts.

Kept in the core package (not the UI) so the same list can be rendered by the
TUI today and by the web front-end later.
"""

CONTACTS = [
    ("Founder", "armory", "https://t.me/stomponheads"),
    ("Co-owner", "wounds", "https://t.me/burneds"),
    ("Head manager", "worthless", "https://t.me/SaddestTies"),
    ("Manager", "Pavement", "https://t.me/ifuckinghatethisplanet"),
    ("Council", "Raken", "https://t.me/zxkfhc"),
]

SUPPORT_NOTE = "Contact if you need help"


def contact_rows():
    """Return (role, name, url) tuples for tables."""
    return list(CONTACTS)


def contact_lines():
    """Plain lines used by CLI help / docs."""
    return [f"{role}: {name} ({url})" for role, name, url in CONTACTS]
