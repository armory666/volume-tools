import asyncio
from core.sources import REGISTRY
from core.tier import allowed_sources, bump_usage, check

async def fan_out(seed, kind, user):
    ok, err = check(user, kind)
    if not ok:
        raise PermissionError(err)
    sources = [s for s in allowed_sources(user, REGISTRY)
               if getattr(s, "free", True) and kind in s.accepts]
    if not sources:
        return []
    results = await asyncio.gather(
        *(s().query(seed, kind) for s in sources), return_exceptions=True)
    hits = []
    for src, r in zip(sources, results):
        if isinstance(r, Exception) or not r:
            continue
        for h in r:
            h.meta["pillar"] = getattr(src, "pillar", "misc")
            hits.append(h)
    bump_usage(user["id"])
    return dedupe(hits)

def dedupe(hits):
    seen = {}
    for h in hits:
        key = (h.kind, h.value)
        if key in seen:
            seen[key].meta.setdefault("sources", set()).add(h.source)
        else:
            h.meta["sources"] = {h.source}
            seen[key] = h
    return sorted(seen.values(), key=lambda h: -len(h.meta["sources"]))
