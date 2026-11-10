"""Bridge between the Python module catalogue and the web API."""

import asyncio
import concurrent.futures
import json
import re
import time

from api import accounts, db, security, settings
from volume.core import catalog as core_catalog
from volume.modules import load_all_modules

REGISTRY = load_all_modules()

PILLARS = {
    "LOOKUP": "account",
    "OSINT": "account",
    "LEAKS": "leak",
    "BREACH": "breach",
    "CSINT": "csint",
    "MALICIOUS": "malicious",
    "DISCORD": "discord",
    "GEOSINT": "geosint",
    "INVESTIGATION": "investigation",
}

# Seed kind -> modules, in display order. Availability is decided at runtime by
# tier, module flags and whether the required provider keys are present.
KIND_MODULES = {
    "email": [
        "live_email_intel",
        "email_intel",
        "email_intelligence",
        "emailrep_lookup",
        "holehe",
        "ghunt",
        "leak_check",
        "breach_intel",
    ],
    "phone": ["live_phone_intel", "phone_intel"],
    "username": [
        "live_username_intel",
        "username_search",
        "github_recon",
        "steam_profile",
        "xbox_profile",
    ],
    "domain": [
        "domain_search",
        "domain_intel",
        "dns_intel",
        "subdomains",
        "subdomain_enum",
        "cname_lookup",
        "website_breach_monitor",
        "domain_reputation",
        "typosquat",
        "wayback_intel",
        "ssl_cert_intel",
    ],
    "ip": [
        "ip_lookup_live",
        "ip_lookup",
        "ip_info",
        "shodan_host",
        "dnsbl_check",
        "ip_reputation",
        "asn_intel",
    ],
    "url": ["web_scanner", "redirect_chain", "tech_fingerprint", "url_reputation", "phishing_analyzer"],
    "hash": ["hash_intel"],
    "discord_id": ["discord_id", "discord_roblox", "discord_prev_names", "discord_history"],
    "user_id": ["discord_id", "discord_roblox", "discord_prev_names", "discord_history"],
    "discord_username": ["discord_search", "discord_prev_names"],
    "invite": ["discord_invite"],
}

BREACH_MODULES = ["leak_check", "breach_intel", "breach_domain", "website_breach_monitor"]

SEED_PATTERNS = {
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "ip": re.compile(r"^[0-9a-fA-F:.]+$"),
    "domain": re.compile(r"^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$"),
    "url": re.compile(r"^https?://", re.I),
    "hash": re.compile(r"^[A-Fa-f0-9]{32,64}$"),
}

IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV6 = re.compile(r"^[0-9a-fA-F:]*:[0-9a-fA-F:]+$")
PHONE = re.compile(r"^\+?[0-9][0-9\s().-]{5,}$")


def detect_kind(seed: str, fallback: str = "email") -> str:
    """Best-effort guess of what the operator pasted.

    The console keeps a type chip selected, but people routinely paste a target
    first. Guessing here means an IP still works while "Email" is highlighted.
    """
    seed = (seed or "").strip()
    if not seed:
        return fallback
    if SEED_PATTERNS["email"].match(seed):
        return "email"
    if SEED_PATTERNS["url"].match(seed):
        return "url"
    if IPV4.match(seed) or IPV6.match(seed):
        return "ip"
    if re.match(r"^[A-Fa-f0-9]{32,64}$", seed):
        return "hash"
    if re.match(r"^CVE-\d{4}-\d{4,}$", seed, re.I):
        return "cve"
    if seed.isdigit() and 15 <= len(seed) <= 21:
        return "discord_id"
    if re.match(r"^VOL-", seed, re.I):
        return fallback
    if PHONE.match(seed) and sum(ch.isdigit() for ch in seed) >= 7:
        return "phone"
    if re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$", seed):
        return "domain"
    if seed.startswith("@"):
        return "username"
    return fallback


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def module_flags() -> dict[str, dict]:
    rows = db.query("SELECT module_id, enabled, note, updated FROM module_flags")
    return {row["module_id"]: row for row in rows}


def module_enabled(module_id: str, flags: dict | None = None) -> bool:
    flags = flags if flags is not None else module_flags()
    row = flags.get(module_id)
    return True if row is None else bool(row["enabled"])


def key_ready(module) -> bool:
    required = tuple(module.requires_key or ())
    if not required:
        return True
    from volume.core import config

    return all(bool(config.get_key(name)) for name in required)


def tier_allowed(user: dict, module) -> bool:
    if accounts.is_admin(user):
        return True
    return accounts.tier_rank(user.get("tier")) >= accounts.tier_rank(module.min_tier)


def catalog_entry(module, user: dict | None = None, flags: dict | None = None) -> dict:
    flags = flags if flags is not None else module_flags()
    enabled = module_enabled(module.id, flags)
    ready = key_ready(module)
    allowed = tier_allowed(user, module) if user else module.min_tier == "FREE"
    return {
        "id": module.id,
        "label": module.label,
        "category": module.category,
        "category_label": core_catalog.category_label(module.category),
        "description": module.description,
        "tier": module.min_tier,
        "credit_cost": module.credit_cost,
        "inputs": list(module.inputs),
        "optional_inputs": dict(module.optional_inputs),
        "requires_key": list(module.requires_key),
        "enabled": enabled,
        "key_ready": ready,
        "available": enabled and ready and allowed,
        "locked_reason": (
            None
            if enabled and ready and allowed
            else "disabled"
            if not enabled
            else "missing_key"
            if not ready
            else "tier"
        ),
    }


def catalog(user: dict | None = None) -> dict:
    flags = module_flags()
    entries = [catalog_entry(module, user, flags) for module in REGISTRY.values()]
    entries.sort(
        key=lambda item: (
            core_catalog.CATEGORY_ORDER.index(item["category"])
            if item["category"] in core_catalog.CATEGORY_ORDER
            else 99,
            item["label"],
        )
    )
    by_category: dict[str, list] = {}
    for entry in entries:
        by_category.setdefault(entry["category"], []).append(entry)
    return {
        "count": len(entries),
        "available": sum(1 for entry in entries if entry["available"]),
        "categories": [
            {"id": name, "label": core_catalog.category_label(name), "modules": items}
            for name, items in by_category.items()
        ],
        "modules": entries,
    }


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _rows(result: dict) -> list[tuple[str, str]]:
    pairs = []
    for row in result.get("rows") or []:
        if isinstance(row, dict):
            pairs.append((str(row.get("key") or row.get("k") or ""), row.get("value") or row.get("v") or ""))
        elif isinstance(row, (list, tuple)) and len(row) >= 2:
            pairs.append((str(row[0]), row[1]))
    return pairs


def _slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")
    return value or "result"


def _stringify(value) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def hits_from_result(module, result: dict) -> list[dict]:
    pillar = PILLARS.get(module.category, module.category.lower())
    rows = _rows(result)
    status = result.get("status") or "ok"
    source = result.get("source") or module.label
    confidence = result.get("confidence") or "medium"
    hits: list[dict] = []
    for key, value in rows:
        text = _stringify(value).strip()
        if not text or text.lower() in {"none", "null", "undefined"}:
            continue
        hits.append(
            {
                "pillar": pillar,
                "kind": _slug(key),
                "value": text[:500],
                "source": source,
                "meta": {
                    "module": module.id,
                    "module_label": module.label,
                    "confidence": confidence,
                    "status": status,
                },
            }
        )
    if not hits:
        hits.append(
            {
                "pillar": pillar,
                "kind": "status",
                "value": status.replace("_", " "),
                "source": source,
                "meta": {
                    "module": module.id,
                    "module_label": module.label,
                    "confidence": confidence,
                    "status": status,
                    "note": (result.get("title") or "").strip(),
                },
            }
        )
    return hits[: settings.MAX_ROWS_PER_MODULE]


def run_module(module_id: str, seed: str, user: dict | None = None) -> dict:
    module = REGISTRY.get(module_id)
    if not module:
        return {"module": module_id, "status": "not_found", "error": "Unknown module", "hits": []}
    if not module_enabled(module_id):
        return {"module": module_id, "status": "disabled", "error": "Module disabled by an operator", "hits": []}
    if user is not None and not tier_allowed(user, module):
        return {"module": module_id, "status": "locked", "error": f"Requires {module.min_tier}", "hits": []}

    kwargs = {}
    if module.inputs:
        kwargs[module.inputs[0]] = seed
    started = time.perf_counter()
    try:
        result = module.run(None, **kwargs)
        if not isinstance(result, dict):
            result = {"status": "error", "rows": [], "title": str(result)}
    except Exception as exc:  # a failing provider must not break the whole pivot
        result = {
            "status": "error",
            "rows": [],
            "title": f"{type(exc).__name__}: {exc}"[:300],
            "source": "runtime",
        }
    elapsed = round((time.perf_counter() - started) * 1000)
    return {
        "module": module.id,
        "label": module.label,
        "category": module.category,
        "status": result.get("status") or "ok",
        "title": result.get("title") or module.label,
        "source": result.get("source") or module.label,
        "confidence": result.get("confidence") or "medium",
        "ms": elapsed,
        "hits": hits_from_result(module, result),
        "rows": [{"key": key, "value": _stringify(value)[:1000]} for key, value in _rows(result)][
            : settings.MAX_ROWS_PER_MODULE
        ],
    }


def select_modules(kind: str, user: dict | None, limit: int | None = None) -> list:
    ids = KIND_MODULES.get((kind or "").strip().lower(), [])
    flags = module_flags()
    chosen = []
    seen = set()
    for module_id in ids:
        module = REGISTRY.get(module_id)
        if not module or module.id in seen:
            continue
        seen.add(module.id)
        if not module_enabled(module.id, flags):
            continue
        if not key_ready(module):
            continue
        if user is not None and not tier_allowed(user, module):
            continue
        chosen.append(module)
    if limit:
        chosen = chosen[:limit]
    return chosen


def dedupe_hits(hits: list[dict], cap: int = 80) -> list[dict]:
    seen = set()
    unique = []
    for hit in hits:
        key = (hit.get("kind"), (hit.get("value") or "").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(hit)
        if len(unique) >= cap:
            break
    return unique


def pivot(seed: str, kind: str, user: dict) -> dict:
    modules = select_modules(kind, user)
    hits: list[dict] = []
    modules_run = 0
    pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=min(settings.MAX_PARALLEL_MODULES, max(1, len(modules)))
    )
    futures = {pool.submit(run_module, module.id, seed, user): module for module in modules}
    deadline = time.monotonic() + settings.PIVOT_TIMEOUT_SECONDS
    try:
        for future in concurrent.futures.as_completed(
            futures, timeout=settings.PIVOT_TIMEOUT_SECONDS
        ):
            if time.monotonic() > deadline:
                break
            try:
                result = future.result(timeout=0.5)
            except Exception:
                continue
            modules_run += 1
            hits.extend(result.get("hits") or [])
    except concurrent.futures.TimeoutError:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    unique = dedupe_hits(hits)
    return {
        "seed": seed,
        "kind": kind,
        "hits": unique,
        "count": len(unique),
        "modules": [module.id for module in modules],
        "modules_run": modules_run,
        "graph": graph_from_hits(seed, kind, unique),
    }


def breach(seed: str, user: dict) -> dict:
    hits: list[dict] = []
    modules_run = 0
    for module_id in BREACH_MODULES:
        module = REGISTRY.get(module_id)
        if not module or not module_enabled(module_id) or not key_ready(module):
            continue
        if not tier_allowed(user, module):
            continue
        result = run_module(module_id, seed, user)
        modules_run += 1
        hits.extend(result.get("hits") or [])
    unique = dedupe_hits(hits)
    return {
        "seed": seed,
        "kind": "email",
        "hits": unique,
        "count": len(unique),
        "modules_run": modules_run,
    }


def graph_from_hits(seed: str, kind: str, hits: list[dict], cap: int = 40) -> dict:
    nodes = [
        {
            "id": f"root:{seed}",
            "label": seed[:28],
            "group": "root",
            "kind": kind,
            "value": seed,
        }
    ]
    edges = []
    seen = {f"root:{seed}"}
    modules = {}
    for hit in hits:
        if len(nodes) >= cap:
            break
        module_id = (hit.get("meta") or {}).get("module") or hit.get("source") or "module"
        module_node = f"module:{module_id}"
        if module_node not in seen:
            seen.add(module_node)
            modules[module_id] = True
            nodes.append(
                {
                    "id": module_node,
                    "label": (hit.get("meta") or {}).get("module_label") or module_id,
                    "group": "module",
                    "kind": "module",
                    "value": module_id,
                }
            )
            edges.append({"from": f"root:{seed}", "to": module_node, "label": "ran"})
        value = (hit.get("value") or "").strip()
        node_id = f"hit:{hit.get('kind')}:{value[:80]}"
        if not value or node_id in seen:
            continue
        seen.add(node_id)
        nodes.append(
            {
                "id": node_id,
                "label": value[:28],
                "group": hit.get("pillar") or "result",
                "kind": hit.get("kind"),
                "value": value,
            }
        )
        edges.append(
            {
                "from": module_node,
                "to": node_id,
                "label": hit.get("kind") or "",
            }
        )
    return {"nodes": nodes, "edges": edges}


async def stream_pivot(seed: str, kind: str, user: dict, case_id: str = ""):
    """Yield server-sent events as each module finishes."""
    modules = select_modules(kind, user)
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    async def worker(module):
        try:
            result = await loop.run_in_executor(None, run_module, module.id, seed, user)
        except Exception as exc:
            result = {
                "module": module.id,
                "label": module.label,
                "status": "error",
                "error": str(exc),
                "hits": [],
            }
        await queue.put(result)

    tasks = [asyncio.create_task(worker(module)) for module in modules]
    collected: list[dict] = []
    modules_run = 0
    deadline = time.monotonic() + settings.PIVOT_TIMEOUT_SECONDS + 5
    try:
        for _ in modules:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                result = await asyncio.wait_for(queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            modules_run += 1
            collected.extend(result.get("hits") or [])
            payload = {k: v for k, v in result.items() if k != "hits"}
            payload["hits"] = result.get("hits") or []
            yield _sse("module", payload)
            if case_id:
                try:
                    persist_run(case_id, user["id"], seed, kind, result, payload)
                except Exception:
                    pass
        unique = dedupe_hits(collected)
        yield _sse(
            "done",
            {
                "seed": seed,
                "kind": kind,
                "hits": unique,
                "count": len(unique),
                "modules_run": modules_run,
                "graph": graph_from_hits(seed, kind, unique),
            },
        )
    finally:
        for task in tasks:
            task.cancel()


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def persist_run(case_id: str, user_id: str, seed: str, kind: str, result: dict, payload: dict) -> str:
    run_id = security.new_id("run_")
    db.execute(
        "INSERT INTO runs (id, case_id, user_id, seed, kind, module, status, payload, created) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            case_id or None,
            user_id,
            seed,
            kind,
            result.get("module"),
            result.get("status"),
            json.dumps(payload, ensure_ascii=False)[:200000],
            security.iso(),
        ),
    )
    if case_id:
        db.execute("UPDATE cases SET updated = ? WHERE id = ?", (security.iso(), case_id))
    return run_id
