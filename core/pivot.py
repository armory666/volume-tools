import asyncio
from core.sources import REGISTRY
from core.tier import allowed_sources, bump_usage, check, tier_of

async def safe_query(source, seed, kind):
    try:
        # 15 second timeout per source to prevent hanging
        return await asyncio.wait_for(source().query(seed, kind), timeout=15.0)
    except asyncio.TimeoutError:
        print(f"[{source.name}] Timeout")
        return []
    except Exception as e:
        print(f"[{source.name}] Error: {e}")
        return []

async def fan_out(seed, kind, user, depth=1, max_depth=2):
    ok, err = check(user, kind)
    if not ok: 
        raise PermissionError(err)
        
    # Get allowed sources based on user tier
    sources = [s for s in allowed_sources(user, REGISTRY) if getattr(s, "free", True) and kind in s.accepts]
    if not sources: 
        return []
        
    # Run queries safely in parallel
    tasks = [safe_query(src, seed, kind) for src in sources]
    results = await asyncio.gather(*tasks)
        
    hits = []
    for src, r in zip(sources, results):
        if not r: 
            continue
        for h in r:
            h.meta["pillar"] = getattr(src, "pillar", "misc")
            hits.append(h)
            
    deduped = dedupe(hits)
    
    # RECURSIVE PIVOT: Only for Premium and Admin
    # Free tier stays at depth 1 to save their 15 daily queries
    if depth < max_depth and tier_of(user) in ("premium", "admin"):
        new_pivots = set()
        for h in deduped:
            if h.kind == "account": 
                new_pivots.add((h.value, "username"))
            elif h.kind == "stealer" and "top_logins" in h.meta:
                for login in h.meta["top_logins"][:1]:
                    new_pivots.add((login, "username"))
                    
        if new_pivots:
            # Limit to 3 recursive branches to prevent API bans
            recursive_tasks = [fan_out(p_seed, p_kind, user, depth+1, max_depth) for p_seed, p_kind in list(new_pivots)[:3]]
            recursive_results = await asyncio.gather(*recursive_tasks, return_exceptions=True)
            for r in recursive_results:
                if isinstance(r, list): 
                    hits.extend(r)
                    
    bump_usage(user["id"])
    return dedupe(hits)

def dedupe(hits):
    seen = {}
    for h in hits:
        key = (h.kind, h.value)
        if key in seen:
            seen[key].meta.setdefault("sources", set()).add(h.source)
            seen[key].meta["confidence"] = len(seen[key].meta["sources"]) * 10
        else:
            h.meta["sources"] = {h.source}
            h.meta["confidence"] = 10
            seen[key] = h
            
    # Sort by confidence (most corroborated first), then alphabetically
    return sorted(seen.values(), key=lambda h: (-h.meta["confidence"], h.value))
