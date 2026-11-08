"""Shared helpers for modules that talk to JSON APIs or self-hosted connectors."""

from volume.core import config


def flatten(value, prefix="", limit=80, depth=0):
    """Flatten nested JSON into (key, value) rows for the result table."""
    rows = []

    def walk(node, path, level):
        if len(rows) >= limit:
            return
        if level > 4:
            rows.append((path or "value", str(node)[:400]))
            return
        if isinstance(node, dict):
            if not node:
                rows.append((path or "value", "{}"))
                return
            for key, item in node.items():
                child = f"{path}.{key}" if path else str(key)
                walk(item, child, level + 1)
        elif isinstance(node, (list, tuple)):
            if not node:
                rows.append((path or "value", "[]"))
                return
            for idx, item in enumerate(node[:30], 1):
                child = f"{path}[{idx}]" if path else f"[{idx}]"
                walk(item, child, level + 1)
        else:
            text = str(node)
            if len(text) > 600:
                text = text[:600] + "…"
            rows.append((path or "value", text))

    walk(value, prefix, depth)
    return rows[:limit]


def connector_base(name, default=""):
    """Read a connector base URL from keys.json / environment."""
    return (
        config.get_key(f"{name}_url")
        or config.get_key(f"{name}_base")
        or default
    )


def response_error(response):
    if not isinstance(response, dict):
        return "No response"
    return (
        response.get("error")
        or response.get("status")
        or f"HTTP {response.get('code', '?')}"
    )
