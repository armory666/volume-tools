from .holehe import Holehe
from .hudsonrock import HudsonRock
from .hudsonrock_phone import HudsonRockPhone
from .gravatar import Gravatar
from .ipapi import IpApi
from .internetdb import InternetDB
from .bgphe import BgpHe
from .crtsh import Crtsh
from .phonenumbers_lib import PhoneNumbers
from .breach import BreachEngine
from .h8mail import H8Mail
from .discord_invite import DiscordInvite
from .discord_lookup import DiscordLookup
from .telegram_osint import TelegramOSINT
from .instagram_osint import InstagramOSINT

REGISTRY = [
    Holehe, HudsonRock, HudsonRockPhone, Gravatar,
    IpApi, InternetDB, BgpHe, Crtsh,
    PhoneNumbers, BreachEngine, H8Mail,
    DiscordInvite, DiscordLookup,
    TelegramOSINT, InstagramOSINT,
]
