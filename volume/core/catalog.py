"""Module catalogue helpers: ordering, categories and pagination.

Internal categories are stable identifiers used by modules.  The UI can show a
friendlier label (for example ``BREACH`` is presented as ``BREACHES``) without
renaming every module.
"""

CATEGORY_ORDER = [
    "CASES",
    "LOOKUP",
    "OSINT",
    "LEAKS",
    "GEOSINT",
    "BREACH",
    "MALICIOUS",
    "CSINT",
    "DISCORD",
    "INVESTIGATION",
]

# UI label -> internal category.  Anything not listed maps to itself.
CATEGORY_ALIASES = {
    "BREACHES": "BREACH",
}

# Internal category -> UI label.
CATEGORY_LABELS = {
    "BREACH": "BREACHES",
}

PER_PAGE = 9


def normalize_category(category: str) -> str:
    category = (category or "").strip().upper()
    return CATEGORY_ALIASES.get(category, category)


def category_label(category: str) -> str:
    internal = normalize_category(category)
    return CATEGORY_LABELS.get(internal, internal)


def sort_key(module):
    category = module.category
    cat_index = CATEGORY_ORDER.index(category) if category in CATEGORY_ORDER else 99
    try:
        order = int(getattr(module, "order", 100))
    except Exception:
        order = 100
    return (cat_index, order, module.label.lower())


def category_modules(modules, category):
    internal = normalize_category(category)
    mods = [m for m in modules.values() if m.category == internal]
    return sorted(mods, key=sort_key)


def page_count(modules, category):
    total = len(category_modules(modules, category))
    return max(1, (total + PER_PAGE - 1) // PER_PAGE)


def page_slice(modules, category, page=0):
    mods = category_modules(modules, category)
    page = max(0, int(page or 0))
    start = page * PER_PAGE
    return mods[start:start + PER_PAGE]
