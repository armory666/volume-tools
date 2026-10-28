from .holehe import Holehe
from .hudsonrock import HudsonRock
from .gravatar import Gravatar
from .ipapi import IpApi
from .internetdb import InternetDB
from .bgphe import BgpHe
from .crtsh import Crtsh
from .phonenumbers_lib import PhoneNumbers
from .breach import BreachEngine
from .h8mail import H8Mail
from .discord_invite import DiscordInvite
from .horus import Horus
from .stealerlogs_com import StealerLogsCom
from .osint_sx import OsintSx

REGISTRY = [
    Holehe, HudsonRock, Gravatar,
    IpApi, InternetDB, BgpHe, Crtsh,
    PhoneNumbers, BreachEngine, H8Mail, DiscordInvite,
    Horus, StealerLogsCom, OsintSx,
]
