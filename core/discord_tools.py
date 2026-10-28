import httpx, re, random, string

async def check_discord_username(username: str):
    if not re.match(r"^[a-z0-9._]{2,32}$", username.lower()):
        return "INVALID", "Usernames must be 2-32 chars, lowercase letters, numbers, dots, or underscores."
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post("https://discord.com/api/v9/unique-username/username-attempt-unauthed", json={"username": username.lower()})
    if r.status_code == 200:
        data = r.json()
        if data.get("taken") is True:
            return "TAKEN", f"The username `@{username}` is already taken."
        else:
            return "AVAILABLE", f"The username `@{username}` is available!"
    elif r.status_code == 429:
        return "RATELIMIT", "Rate limited by Discord. Try again in a minute."
    else:
        return "ERROR", f"Discord API returned {r.status_code}"

async def check_username_batch(usernames: list):
    results = []
    async with httpx.AsyncClient(timeout=15) as c:
        for u in usernames:
            u = u.strip().lower()
            try:
                r = await c.post("https://discord.com/api/v9/unique-username/username-attempt-unauthed", json={"username": u})
                if r.status_code == 200:
                    taken = r.json().get("taken")
                    results.append((u, "TAKEN" if taken else "AVAILABLE"))
                elif r.status_code == 429:
                    results.append((u, "RATE_LIMIT"))
                    break
                else:
                    results.append((u, "ERROR"))
            except Exception:
                results.append((u, "ERROR"))
    return results

async def check_vanity(code: str):
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://discord.com/api/v9/invites/{code}?with_counts=true")
    if r.status_code == 404:
        return "AVAILABLE", "This vanity is untaken."
    if r.status_code == 200:
        data = r.json()
        guild = data.get("guild", {})
        if not guild:
            return "TERMINATED", "This invite points to a deleted or banned server."
        return "TAKEN", f"**Server:** {guild.get('name')}\n**ID:** `{guild.get('id')}`\n**Members:** {data.get('approximate_member_count')}"
    return "ERROR", f"Discord API returned {r.status_code}"

async def validate_token(token: str):
    headers = {"Authorization": token}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get("https://discord.com/api/v9/users/@me", headers=headers)
    if r.status_code == 200:
        d = r.json()
        return True, f"**Valid**\nUser: `{d.get('username')}`\nID: `{d.get('id')}`\nEmail: `{d.get('email')}`"
    elif r.status_code == 401:
        return False, "Invalid or locked token."
    else:
        return False, f"Discord API Error: {r.status_code}"

async def get_token_info(token: str):
    headers = {"Authorization": token}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get("https://discord.com/api/v9/users/@me", headers=headers)
        if r.status_code != 200: return None
        d = r.json()
        try:
            b = await c.get("https://discord.com/api/v9/users/@me/billing/payment-sources", headers=headers)
            billing = b.json() if b.status_code == 200 else []
        except:
            billing = []
        return {"username": d.get("username"), "id": d.get("id"), "email": d.get("email"), "phone": d.get("phone"), "nitro": d.get("premium_type"), "billing_cards": len(billing)}
