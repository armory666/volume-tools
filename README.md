# VOLUME

A Windows-friendly OSINT / CSINT / security-intelligence console. It runs as a
single Python package, keeps its own case database, and gates tools behind
HWID-bound license keys, accounts, tiers and a credit economy.

```
 ██╗   ██╗ ██████╗ ██╗     ██╗   ██╗███╗   ███╗███████╗
 ██║   ██║██╔═══██╗██║     ██║   ██║████╗ ████║██╔════╝
 ██║   ██║██║   ██║██║     ██║   ██║██╔████╔██║█████╗
 ╚██╗ ██╔╝██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══╝
  ╚████╔╝ ╚██████╔╝███████╗╚██████╔╝██║ ╚═╝ ██║███████╗
   ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
```

- **73 modules** across LOOKUP, OSINT, LEAKS, GEOSINT, BREACHES, MALICIOUS,
  CSINT, DISCORD and INVESTIGATION
- **Accounts** — unique usernames, password sign-in, captcha, public profiles and
  username search (rarity check)
- **Free key on sign-up** — every new account gets a `VOL-…` key bound to the
  device; the key is the portable credential for other machines
- **Tiered access** — FREE, PREMIUM, DETECTIVE, INDUSTRIAL, LIFETIME
- **Credits** — spent before a run, automatically refunded when a source is down,
  a key is missing, or the module errors
- **HWID binding** — a key locks to the first device that uses it
- **Case management** — findings, entity pivots, timelines, exports
- **Interactive TUI** — full PC dashboard and a compact mobile layout
- **Scriptable CLI** — `--run`, `--arg`, `--case`, `--json`
- **Web-ready core** — accounts, licensing, credits, cases and sources are
  UI-independent so a web front-end can reuse them

> Only use VOLUME against systems and data you are authorised to investigate.
> You are responsible for how you use it.

---

## Requirements

- Windows 10/11 (also works on Linux/macOS)
- Python **3.11+** (tested on 3.14)
- No WSL required

## Install

```bat
cd C:\Users\almig\Downloads\volume-tools
python -m pip install -r requirements.txt
```

Optional: copy `.env.example` to `.env` and add the API keys you have. Every key
is optional — modules degrade gracefully and tell you what would unlock more.

## Run

From the **repository root**:

```bat
cd C:\Users\almig\Downloads\volume-tools
python -m volume.main --pc
```

Or double-click `volume\run.bat` (it handles the working directory for you).

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--pc` / `--mobile` | Force a layout instead of auto-detecting |
| `--key KEY` | Activate a license for this run |
| `--no-session` | Ignore the saved session |
| `--list-modules` | Print the module catalogue and exit |
| `--tiers` | Print tier credits and export gates |
| `--doctor` | Check Python, dependencies, keys, paths and module loading |
| `--version` | Print the version and exit |
| `--profile USER` | Print a public profile |
| `--search-users QUERY` | Search usernames and bios |
| `--list-users` | List registered accounts |

---

## Accounts and the free key

On first launch you are shown the license screen. Press **Enter** to create an
account and a free key:

1. Choose a **unique username** (3–20 letters, numbers or underscore). Usernames
   are unique case-insensitively and cannot be claimed by anyone else, so choose
   carefully. Reserved names (`admin`, `support`, `volume`, staff names, …) are
   rejected.
2. Choose a **password** (8–128 characters).
3. Solve a **captcha**.
4. VOLUME creates a FREE license, binds it to your HWID, and shows the key.

> **Save the key.** It is the only way to recover your account on another
> device. If you lose it you will be locked out.

The username `armory` is the founder account. Registering it requires the secret
`VOLUME_FOUNDER_TOKEN` from `.env`; without that token the name cannot be
claimed. See [Founder, roles and admin access](#founder-roles-and-admin-access).

After registration:

- **Password sign-in** (`l` on the license screen) works on the original device.
- **Key sign-in** works on any device (the key binds to the first HWID that uses
  it).
- `f` anywhere in the UI opens the profile search; type a username fragment and
  see matching accounts, tiers and bios.
- `k` opens the license screen, then `p` opens your profile (edit bio with `e`,
  search users with `f`).

### Community contacts

Support contacts are shown during registration and in the profile screen:

| Role | Name | Telegram |
| --- | --- | --- |
| Founder | armory | https://t.me/stomponheads |
| Co-owner | wounds | https://t.me/burneds |
| Head manager | worthless | https://t.me/SaddestTies |
| Manager | Pavement | https://t.me/ifuckinghatethisplanet |
| Council | Raken | https://t.me/zxkfhc |

---

## Licensing, tiers and credits

New accounts receive a FREE license key:

```
VOL-XXXX-XXXX-XXXX
```

| Tier | Rank | Credits | Daily refill | Notes |
| --- | --- | --- | --- | --- |
| FREE | 1 | 25 | +5/day (cap 25) | Core tools; some modules locked |
| PREMIUM | 2 | 500 | — | Unlocks most paid modules + HTML/PDF |
| DETECTIVE | 3 | 2,500 | — | Adds attack-surface, stealer-log and private connectors |
| INDUSTRIAL | 4 | 10,000 | — | High-volume investigations |
| LIFETIME | 5 | unlimited | — | Admin panel, all modules, all exports |

### How credits work

1. The cost is checked and **spent before** the module runs.
2. If the result is `error`, `key_required`, `source_down` or `skipped`, the cost
   is **refunded automatically**.
3. Successful and `not_found` results keep the charge.
4. FREE credits refill by `+5` per day, capped at 25.
5. Every spend/refund is written to a per-key credit ledger.

### Export gating

| Format | Minimum tier |
| --- | --- |
| JSON, TXT, CSV, Markdown | FREE |
| HTML, PDF | PREMIUM (PDF also needs `reportlab`) |

### HWID binding

`HWID` is a SHA-256 fingerprint of stable machine identifiers. A key binds to the
first device that activates it; activating elsewhere is rejected. Admins can
reset a binding from the ADMIN tab.

### Founder, roles and admin access

Every account has a permanent **role**, independent of its license tier:

```
member < moderator < manager < admin < founder
```

| Role | Powers |
| --- | --- |
| `member` | Normal tools and credits |
| `moderator` | Staff badge |
| `manager` | Staff badge |
| `admin` | ADMIN tab, all modules, unlimited credits, may grant `manager` and below |
| `founder` | Everything, plus may grant/revoke `admin`; there is exactly one |

The founder role is claimed in one of three ways, always with
`VOLUME_FOUNDER_TOKEN`:

1. **Register the founder username** (`armory` by default) on the create-key
   screen and enter the founder token when prompted.
2. **Promote an existing account** from the license screen with `a` (founder
   code), or from the CLI with `--claim-founder USERNAME`.
3. Set `VOLUME_FOUNDER=armory` and `VOLUME_FOUNDER_TOKEN=<long random secret>` in
   `.env` before first launch.

Generate a strong token with:

```bat
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then put it in `.env` and restart VOLUME. `--doctor` shows whether the founder
token is configured.

Founder and admin status is resolved from the account, so it follows the key to
any device and survives tier changes. Both roles bypass tier gates and have
unlimited credits. The founder can grant permanent admin; admins can grant
`manager` and below. Nobody can grant `founder` through role management.

### Admin / ghost access

Set `VOLUME_GHOST_KEY` in `.env`. Entering that value at the key prompt creates a
`GHOST-<hwid>` LIFETIME license with unlimited credits and the ADMIN tab. If the
variable is unset, no ghost access is possible. The ghost key is a break-glass
credential; day-to-day staff access should use account roles.

---

## Module catalogue

Categories are shown in the UI as `LOOKUP`, `OSINT`, `LEAKS`, `GEOSINT`,
`BREACHES`, `MALICIOUS`, `CSINT`, `DISCORD` and `INVESTIGATION`. The internal
category for BREACHES is `BREACH`.

### LOOKUP

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `live_email_intel` | Live Email Intel | FREE | 1 |
| `live_phone_intel` | Live Phone Intel | FREE | 1 |
| `live_username_intel` | Live Username Intel | FREE | 1 |
| `domain_search` | Domain Search | FREE | 1 |
| `ip_lookup_live` | IP Lookup | FREE | 1 |
| `machine_viewer` | Machine Viewer | FREE | 0 |
| `general_search` | General Search | FREE | 0 |
| `file_search` | File Search | PREMIUM | 1 |
| `steam_profile` | Steam Profile | FREE | 1 |
| `subdomains` | Subdomain Search | FREE | 1 |
| `cname_lookup` | CNAME Lookup | FREE | 1 |
| `email_intelligence` | Email Intelligence | PREMIUM | 2 |
| `holehe` | Holehe (Email Registrations) | PREMIUM | 2 |
| `telegram_search` | Telegram Search | FREE | 1 |
| `emailrep_lookup` | EmailRep Lookup | FREE | 1 |
| `nazapi` | nazAPI | DETECTIVE | 3 |
| `xbox_profile` | Xbox Profile | DETECTIVE | 2 |
| `ghunt` | GHunt (Google Account) | DETECTIVE | 4 |

### OSINT

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `domain_intel` | Domain / DNS Intel | FREE | 1 |
| `dns_intel` | DNS Deep Intel | FREE | 1 |
| `subdomain_enum` | Subdomain Enumeration | PREMIUM | 3 |
| `ip_lookup` | IP Geolocation | FREE | 1 |
| `asn_intel` | ASN / BGP Intel | PREMIUM | 2 |
| `mac_lookup` | MAC / OUI Intel | FREE | 1 |
| `email_intel` | Email Intel | FREE | 1 |
| `phone_intel` | Phone Intel | FREE | 1 |
| `username_search` | Username Search | FREE | 1 |
| `github_recon` | GitHub Recon | PREMIUM | 2 |
| `ssl_cert_intel` | TLS Certificate Intel | PREMIUM | 2 |
| `wayback_intel` | Wayback Machine Intel | PREMIUM | 2 |

### LEAKS

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `leak_index` | Leak Index | PREMIUM | 2 |
| `stealer_logs` | Stealer Logs | DETECTIVE | 4 |
| `stealerlog_investigation` | Stealerlog Investigation | DETECTIVE | 5 |
| `credential_search` | Credential Search | DETECTIVE | 4 |
| `kitty_db` | Kitty DB | DETECTIVE | 5 |

> Stealer-log and Kitty DB modules are **key-gated connectors**. They never ship
> private data; you point them at an index you are authorised to use.

### GEOSINT

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `address_lookup` | Address Lookup | FREE | 1 |
| `ip_info` | IP Info | FREE | 1 |
| `image_metadata` | Image Metadata | FREE | 1 |
| `cars_owners` | Cars & Owners | DETECTIVE | 3 |

`cars_owners` uses the DVLA Vehicle Enquiry API. It returns vehicle data, not
owner data, and requires a lawful purpose.

### BREACHES

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `breach_intel` | Breach Intel | PREMIUM | 3 |
| `leak_check` | Breach Check (HIBP) | FREE | 2 |
| `password_pwned` | Password Exposure | FREE | 1 |
| `website_breach_monitor` | Website Breach Monitor | FREE | 1 |
| `breach_domain` | Domain Breach Exposure | PREMIUM | 3 |

### MALICIOUS

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `web_scanner` | Web / URL Scanner | FREE | 2 |
| `redirect_chain` | Redirect Chain | FREE | 1 |
| `tech_fingerprint` | Tech / WAF Fingerprint | FREE | 1 |
| `domain_reputation` | Domain Reputation | PREMIUM | 2 |
| `email_header_analyzer` | Email Header Analyzer | PREMIUM | 2 |
| `url_reputation` | URL Reputation | PREMIUM | 2 |
| `phishing_analyzer` | Phishing Analyzer | PREMIUM | 2 |
| `hash_intel` | Hash / Malware Intel | PREMIUM | 2 |
| `typosquat` | Typosquat / Lookalike | DETECTIVE | 4 |

### CSINT

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `cve_lookup` | CVE / Vulnerability Intel | PREMIUM | 2 |
| `shodan_host` | Shodan InternetDB | PREMIUM | 2 |
| `ip_reputation` | IP Reputation | PREMIUM | 3 |
| `dnsbl_check` | DNSBL / Blocklist Check | FREE | 1 |
| `http_headers_audit` | HTTP Headers Audit | FREE | 1 |
| `kev_search` | CISA KEV Search | FREE | 1 |
| `tls_scan` | TLS / SSL Scanner | PREMIUM | 2 |
| `attack_surface` | Attack Surface Map | DETECTIVE | 5 |
| `subdomain_takeover` | Subdomain Takeover | DETECTIVE | 4 |

### DISCORD

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `discord_id` | Discord ID / Snowflake | FREE | 1 |
| `discord_invite` | Discord Invite Lookup | FREE | 1 |
| `discord_roblox` | Discord → Roblox | PREMIUM | 2 |
| `discord_prev_names` | Discord Previous Names | DETECTIVE | 3 |
| `discord_search` | Discord Search | DETECTIVE | 3 |
| `discord_history` | Discord History | DETECTIVE | 3 |

`discord_search` needs a bot token and a `guild_id`. `discord_prev_names` and
`discord_history` need a bot token and/or a configured history service; Discord
does not expose global message history through its public API.

### INVESTIGATION

| ID | Tool | Tier | Cost |
| --- | --- | --- | --- |
| `auto_parse` | Auto Format / Paster | FREE | 0 |
| `case_timeline` | Case Timeline | FREE | 0 |
| `entity_graph` | Entity Graph / Pivots | FREE | 0 |
| `case_search` | Case Search | FREE | 0 |
| `ioc_defang` | IOC Defang / Refang | FREE | 0 |

---

## Interactive controls

| Key | Action |
| --- | --- |
| `n` / `p`, arrows | Next / previous tab |
| `c u o e g b` | Jump to Cases / Lookup / OSINT / Leaks / GeoSINT / Breaches |
| `m s d i` | Jump to Malicious / CSINT / Discord / Investigation |
| `[` / `]` | Previous / next tool page (9 tools per page) |
| `1`–`9` | Run a tool on the current page |
| `x` | Paste text and auto-extract indicators |
| `k` | License, credits, profile and key activation |
| `f` | Search user profiles (username rarity) |
| `v` | Toggle mobile / PC layout |
| `?` | Help |
| `l` | Log out |
| `q` | Quit |

On the **CASES** tab: `n` new case, `b` browse/open, `d` delete, `e` export,
`s` stats, `t` edit notes/tags/analyst.

On the **license** screen: `c` change key, `p` my profile, `f` find users,
`a` founder code, `l` log out. On the **profile** screen: `e` edit bio,
`f` find users.

The **ADMIN** tab (admins and founder): `1` generate key, `2` list keys, `3`
add credits, `4` set credits, `5` revoke/unrevoke, `6` reset HWID, `7` delete,
`8` license stats, `9` audit log, `a` accounts (roles, ban/unban, issue or reset
keys), `i` issue a key straight to an account.

---

## Scriptable CLI

Run a single module without the TUI. Non-interactive runs need a valid session
or `--key`; they never auto-create a license:

```bat
python -m volume.main --run domain_intel --arg domain=example.com
python -m volume.main --run ip_lookup --arg ip=8.8.8.8 --json
python -m volume.main --run cve_lookup --arg cve=CVE-2021-44228 --json
python -m volume.main --run web_scanner --arg url=https://example.com --case "ACME recon"
python -m volume.main --run ioc_defang --arg "text=hxxps://evil[.]com/login" --json
python -m volume.main --run live_email_intel --arg email=analyst@example.com --key VOL-XXXX-XXXX-XXXX
```

Flags:

| Flag | Meaning |
| --- | --- |
| `--run MODULE_ID` | Module to execute |
| `--arg KEY=VALUE` | Input value (repeatable) |
| `--case NAME` | Open/create a case and save the finding |
| `--save` | Save the finding to a case named `CLI` |
| `--analyst NAME` | Analyst name for the case (default `cli`) |
| `--json` | Machine-readable output (nothing else on stdout) |
| `--key KEY` | License to use for this run |

Founder / admin flags (the actor is taken from `--key` or the saved session, so
pass the founder's or an admin's key):

| Flag | Meaning |
| --- | --- |
| `--claim-founder USERNAME` | Promote an account to founder (needs the founder token) |
| `--founder-token TOKEN` | Founder token, or set `VOLUME_FOUNDER_TOKEN` |
| `--set-role USERNAME ROLE` | Set `member`, `moderator`, `manager` or `admin` |
| `--issue-key USERNAME` | Mint and assign a fresh key (revokes the old one) |
| `--issue-tier TIER` | Tier for `--issue-key` (default `PREMIUM`) |
| `--issue-days N` | Days until expiry for `--issue-key` (0 = never) |
| `--issue-credits N` | Credit override for `--issue-key` |
| `--ban USERNAME` / `--unban USERNAME` | Suspend or restore an account |

```bat
python -m volume.main --claim-founder armory --founder-token SECRET
python -m volume.main --key VOL-XXXX-XXXX-XXXX --set-role wounds admin
python -m volume.main --key VOL-XXXX-XXXX-XXXX --issue-key wounds --issue-tier LIFETIME --issue-days 0
python -m volume.main --key VOL-XXXX-XXXX-XXXX --ban spammer
```

Tier gates, credit spending and automatic refunds apply exactly as they do in
the TUI. Exit codes: `0` ok, `1` module returned a refundable status, `2` auth,
`3` tier denied, `4` insufficient credits, `5` unknown module, `6` bad input,
`7` case error.

Discover module IDs and required inputs:

```bat
python -m volume.main --list-modules
python -m volume.main --list-modules --json
python -m volume.main --profile Sm0ke
python -m volume.main --search-users smoke
```

---

## API keys and connectors

Add keys to `.env` (copy `.env.example`) or `data/keys.json`. Everything is
optional; a missing key produces a clear `key_required` result and the credit is
refunded.

| Variable | Unlocks |
| --- | --- |
| `HIBP_API_KEY` | Breach Intel, Credential Search |
| `VT_API_KEY` | VirusTotal URL/file/IP/domain reputation |
| `ABUSECH_API_KEY` | MalwareBazaar + ThreatFox |
| `URLHAUS_API_KEY` | URLhaus Auth-Key |
| `ABUSEIPDB_API_KEY` | Abuse confidence scores |
| `GREYNOISE_API_KEY` | GreyNoise classification |
| `GSB_API_KEY` | Google Safe Browsing |
| `NVD_API_KEY` | Higher NVD rate limits |
| `GITHUB_TOKEN` | Higher GitHub rate limits |
| `DISCORD_API_KEY` | Discord profile, member search and history lookups |
| `DISCORD_HISTORY_URL` | Self-hosted Discord name/message history service |
| `ROBLOX_MAP_URL` | Self-hosted Discord→Roblox mapping service |
| `LEAKIX_API_KEY` | Higher LeakIX limits |
| `EMAILREP_API_KEY` | Higher EmailRep limits |
| `NUMVERIFY_API_KEY` | Live phone/carrier validation |
| `TELEGRAM` | Telegram Bot API `getChat` lookup |
| `HOLEHE_API_KEY` / `HOLEHE_API_URL` | Self-hosted holehe API |
| `NAZAPI_API_KEY` / `NAZAPI_URL` | nazAPI connector |
| `KITTY_API_KEY` / `KITTY_URL` | Kitty DB connector |
| `STEALER_API_KEY` / `STEALER_URL` | Stealer-log index connector |
| `XBOX_API_KEY` | Xbox profile connector (XAPI/OpenXBL) |
| `GHUNT_API_KEY` / `GHUNT_URL` | Self-hosted GHunt connector |
| `DVLA_API_KEY` | DVLA vehicle enquiry |
| `VOLUME_GHOST_KEY` | Ghost LIFETIME/admin access |
| `VOLUME_FOUNDER` | Founder username (default `armory`) |
| `VOLUME_FOUNDER_TOKEN` | Secret required to register or claim the founder |

`data/keys.json` accepts the same lowercase names:

```json
{
  "hibp": "...",
  "leakix": "...",
  "nazapi": "...",
  "nazapi_url": "https://your-nazapi.example",
  "stealer": "...",
  "stealer_url": "https://your-log-index.example"
}
```

Private/paid sources are explicit connectors, not bundled data. Only query
sources and data you are legally authorised to access.

---

## Web roadmap

The core is intentionally UI-independent so VOLUME can become a website without
rewriting the business logic:

- `core/accounts.py` — registration, PBKDF2 authentication, captcha, profiles
  and username search
- `core/auth.py` — keys, HWID binding, credits, sessions and audit
- `core/database.py` — cases, findings, entities and accounts
- `core/sources.py` / `core/net.py` — rate-limited source clients and cache

A web front-end can be added as FastAPI + PostgreSQL + Redis + JWT, with
Stripe/OAuth for paid tiers, while reusing these services. The current SQLite
schema and `accounts.public_profile()` / `accounts.search_profiles()` responses
are already shaped for JSON APIs.

---

## Project layout

```
volume-tools/
├─ README.md
├─ requirements.txt
├─ .env.example
├─ web/                    # static front-end (Vercel)
└─ volume/
   ├─ main.py              # entrypoint, registration/login, scriptable CLI
   ├─ run.bat              # Windows launcher
   ├─ core/
   │  ├─ config.py         # paths, .env, HWID, key lookup
   │  ├─ database.py       # cases, findings, entities, accounts
   │  ├─ accounts.py       # usernames, PBKDF2, captcha, profiles, search
   │  ├─ community.py      # support contacts
   │  ├─ licensing.py      # tiers, credit allowances, export gates
   │  ├─ auth.py           # keys, HWID binding, credits, sessions, audit
   │  ├─ module_base.py    # module contract + result helpers
   │  ├─ net.py            # rate-limited HTTP client with cache
   │  ├─ sources.py        # public intelligence source clients/connectors
   │  ├─ webintel.py       # HTTP/HTML/TLS/robots helpers
   │  ├─ indicators.py     # indicator parsing/validation/risk labels
   │  ├─ catalog.py        # categories, aliases + pagination
   │  └─ exporter.py       # JSON/TXT/CSV/MD/HTML/PDF
   ├─ modules/
   │  ├─ lookup/ osint/ leaks/ geosint/ breach/ malicious/ csint/ discord/ investigation/
   │  └─ connector_utils.py   # shared JSON flattening / connector helpers
   ├─ ui/
   │  ├─ theme.py input.py layout.py app.py
   ├─ data/                # cases.db, auth.db, keys.json, session.json
   ├─ exports/             # generated reports
   ├─ logs/
   └─ tests/smoke.py
```

Runtime state lives next to the package. Override the location with
`VOLUME_HOME`.

---

## Tests

Offline smoke test (uses a temporary `VOLUME_HOME`, so your real data is safe):

```bat
cd C:\Users\almig\Downloads\volume-tools
python volume\tests\smoke.py
```

It checks HWID stability, account registration/login/profile search, license
tiers, credit spend/refund, HWID binding, ghost/admin access, the founder token
and role hierarchy, permanent role grants, key issuing and bans, module loading,
all categories, required module IDs, tier gates, exports and sessions.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `ModuleNotFoundError: volume` | Run from the repo root: `cd C:\Users\almig\Downloads\volume-tools` |
| `rich` / `httpx` missing | `python -m pip install -r requirements.txt` |
| PDF export fails | `python -m pip install reportlab` |
| Lost your key | It cannot be recovered; support contacts are shown at sign-up |
| Key rejected on another PC | Keys bind to the first HWID; admin can reset the binding |
| Not enough credits | FREE refills +5/day (cap 25); activate a paid tier |
| Module says `key_required` | Add the matching API key to `.env`; credits are refunded |
| Garbled box characters | Use Windows Terminal; set `PYTHONIOENCODING=utf-8` |
| Piped stdin exits immediately | The TUI needs a terminal; use `--run ... --json` for scripting |

---

## Web API and console

The repository now ships a FastAPI backend that runs the same 73 Python modules
as the CLI. The static pages in `web/` are served by the API in local
development, and the Vercel deployment forwards `/api/*` to Render.

```powershell
cd C:\Users\almig\Downloads\volume-tools
python -m pip install -r requirements.txt
python -m uvicorn api.main:app --reload --port 8000
```

Open <http://localhost:8000/login>. In the default console email mode the
six-digit code is printed to the terminal (and shown on the login screen as a
local-development hint). No credentials are required to run locally.

### Endpoints

| Area | Endpoints |
| --- | --- |
| Auth | `POST /api/auth/request`, `POST /api/auth/verify`, `POST /api/auth/logout`, `GET /api/auth/session` |
| Access keys | `POST /api/auth/key-login`, `POST /api/auth/key`, `POST /api/redeem` |
| Magic links | `POST /api/auth/magic/request`, `GET /api/auth/magic/consume` |
| Passkeys | `GET /api/passkeys`, `POST /api/auth/passkey/register/begin|complete`, `POST /api/auth/passkey/login/begin|complete` |
| Account | `GET /api/me`, `GET /api/sessions`, `DELETE /api/sessions/{id}`, `GET /api/referrals/me` |
| Modules | `GET /api/modules`, `POST /api/run`, `POST /api/pivot`, `POST /api/pivot/stream`, `POST /api/breach`, `POST /api/graph` |
| Cases | `GET|POST /api/cases`, `GET|DELETE /api/cases/{id}`, `POST /api/cases/{id}/snapshot`, `GET /api/cases/{id}/export?format=csv|json` |
| Watchlists | `GET|POST /api/watchlists`, `DELETE /api/watchlists/{id}`, `POST /api/watchlists/{id}/check` |
| Admin | `GET /api/admin/overview`, `GET|PATCH /api/admin/users`, `GET|PATCH /api/admin/modules`, `GET /api/admin/audit`, `GET|POST /api/admin/keys` |

Every lookup requires a session, is charged against the daily quota and the
credit balance, and is written to the audit log. Modules can be switched off
per-module from the admin console; disabled modules disappear from pivots.

### Email

`volume/core/emailer.py` implements three providers behind one function:

| `VOLUME_EMAIL_PROVIDER` | Required settings |
| --- | --- |
| `console` (default) | none - codes print to the server log |
| `smtp` | `VOLUME_SMTP_HOST`, `VOLUME_SMTP_PORT`, `VOLUME_SMTP_USER`, `VOLUME_SMTP_PASSWORD`, `VOLUME_EMAIL_FROM` |
| `resend` | `RESEND_API_KEY`, `VOLUME_EMAIL_FROM` (verified domain) |

Only console mode can echo the code back to the login page (`dev_code`), and
only when `VOLUME_DEV_CODES=true`. Leave that flag off anywhere public: the code
is always written to the server log, which is enough for local testing. The
SMTP and Resend paths send hashed, expiring, single-use codes by email and never
return them in a response.

### Deployment

1. Push the repository.
2. Create a Render service from `render.yaml` (or use the start command
   `uvicorn api.main:app --host 0.0.0.0 --port $PORT`).
3. Create a Neon Postgres database and set `DATABASE_URL` on Render.
4. Set `VOLUME_PUBLIC_URL`, `VOLUME_WEB_ORIGINS`, `VOLUME_ADMIN_EMAILS`, and the
   email provider secrets.
5. If Render gives the service a different hostname than
   `volume-api.onrender.com`, update the `/api/:path*` rewrite in
   `web/vercel.json` to match.
6. Set the Vercel project's `VOLUME_API_BASE` is not needed when the rewrite is
   correct; all pages fall back to same-origin `/api`.

Never commit `.env`, provider keys, database URLs, or admin secrets.
