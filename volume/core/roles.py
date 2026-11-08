"""Role hierarchy and staff permissions.

Roles live on accounts (``accounts.role``) and are independent of the license
tier: a FREE key can still belong to an admin or the founder.  This module is
UI-independent so the TUI, CLI and a future web front-end share one policy.

Hierarchy (lowest to highest)::

    member < moderator < manager < admin < founder

Rules:
* ``founder`` is unique and is only claimed with ``VOLUME_FOUNDER_TOKEN``.
* A founder can grant/revoke ``admin`` and every role below it.
* An admin can grant/revoke ``manager`` and every role below it.
* Nobody can grant ``founder`` through role management.
"""

ROLE_ORDER = ["member", "moderator", "manager", "admin", "founder"]

ROLE_LABELS = {
    "member": "Member",
    "moderator": "Moderator",
    "manager": "Manager",
    "admin": "Admin",
    "founder": "Founder",
}

ROLE_COLORS = {
    "member": "white",
    "moderator": "cyan",
    "manager": "yellow",
    "admin": "magenta",
    "founder": "bright_green",
}

ADMIN_ROLES = {"admin", "founder"}
STAFF_ROLES = {"moderator", "manager", "admin", "founder"}
ASSIGNABLE_ROLES = ["member", "moderator", "manager", "admin"]


def normalize_role(role) -> str:
    role = (role or "member").strip().lower()
    return role if role in ROLE_ORDER else "member"


def role_rank(role) -> int:
    return ROLE_ORDER.index(normalize_role(role))


def role_label(role) -> str:
    return ROLE_LABELS[normalize_role(role)]


def role_color(role) -> str:
    return ROLE_COLORS[normalize_role(role)]


def is_admin(role) -> bool:
    return normalize_role(role) in ADMIN_ROLES


def is_staff(role) -> bool:
    return normalize_role(role) in STAFF_ROLES


def is_founder(role) -> bool:
    return normalize_role(role) == "founder"


def can_grant(actor_role, target_role) -> bool:
    """Return True when ``actor_role`` may assign ``target_role``.

    ``founder`` is intentionally never grantable here; it is claimed with the
    founder token so there is always exactly one owner.
    """
    target = normalize_role(target_role)
    if target == "founder":
        return False
    return (
        role_rank(actor_role) >= role_rank("admin")
        and role_rank(actor_role) > role_rank(target)
    )


def assignable_roles(actor_role) -> list:
    """Roles the actor is allowed to hand out."""
    return [role for role in ASSIGNABLE_ROLES if can_grant(actor_role, role)]


def can_moderate(actor_role, target_role) -> bool:
    """True when the actor outranks the target enough to ban or edit them."""
    return (
        role_rank(actor_role) >= role_rank("admin")
        and role_rank(actor_role) > role_rank(target_role)
    )
