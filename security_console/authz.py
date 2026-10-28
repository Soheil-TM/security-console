"""Central authorization helpers (default-deny).

This module is the future policy surface for RBAC. It does **not** yet replace
scattered ``role == \"admin\"`` checks in HTTP handlers — wiring happens in a
later phase. Callers must pass scope facts (group lead, project lead); this
module never looks up usernames and never opens the database.

Schema note
-----------
Until a migration expands ``users.role`` and adds ``users.capabilities``, the
live database only stores ``admin`` / ``developer`` / ``viewer``. Target role
``super_admin`` and capability maps are recognized here when present on the
user dict (tests / future rows). Existing production rows without
``capabilities`` receive **no** admin capabilities from this module
(default-deny).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# Roles accepted by the users.role CHECK after the RBAC schema migration.
ROLES = ("super_admin", "admin", "developer", "viewer")
# Alias kept for older tests/docs — same as ROLES once schema is migrated.
CURRENT_DB_ROLES = ROLES

# Explicit admin-oriented capabilities. Unknown names never grant access.
CAPABILITIES = frozenset(
    {
        "users.manage",
        "users.reset_password",
        "groups.manage_all",
        "projects.manage_all",
        "connections.manage",
        "tool_access.manage",
        "sonar.setup",
        "adhoc.scan",
        "risk.accept_any",
        "audit.read",
    }
)

# Role-level abilities that are not stored in capabilities jsonb.
_SCAN_STARTERS = frozenset({"super_admin", "admin", "developer"})
_TRIAGE_WRITERS = frozenset({"super_admin", "admin", "developer"})


def role_of(user: Mapping[str, Any] | None) -> str:
    """Return the normalized role string, or empty when missing/unknown shape."""

    if not isinstance(user, Mapping):
        return ""
    return str(user.get("role") or "").strip()


def is_known_role(role: str) -> bool:
    """Return whether ``role`` is one of the target RBAC roles."""

    return role in ROLES


def is_super_admin(user: Mapping[str, Any] | None) -> bool:
    """Return whether the principal is a super admin (role only; no usernames)."""

    return role_of(user) == "super_admin"


def is_admin_role(user: Mapping[str, Any] | None) -> bool:
    """Return whether the principal has the org ``admin`` role (not super)."""

    return role_of(user) == "admin"


def _capability_enabled(value: Any) -> bool:
    """Return True only for unambiguous enable flags (default-deny otherwise).

    Strings such as ``\"0\"`` / ``\"false\"`` / ``\"true\"`` are rejected so a
    loosely typed JSON payload cannot grant access by accident.
    """

    return value is True or value == 1


def capabilities_of(user: Mapping[str, Any] | None) -> frozenset[str]:
    """Return the granted capability set from the user record.

    Accepts ``capabilities`` as a mapping of name→enabled flag, or an
    iterable of names. Unknown names are dropped. Missing/empty → empty set
    (deny).
    """

    if not isinstance(user, Mapping):
        return frozenset()
    raw = user.get("capabilities")
    if raw is None:
        return frozenset()
    if isinstance(raw, Mapping):
        names = [
            str(key) for key, value in raw.items() if _capability_enabled(value)
        ]
    elif isinstance(raw, (str, bytes)):
        return frozenset()
    elif isinstance(raw, Iterable):
        names = [str(item) for item in raw]
    else:
        return frozenset()
    return frozenset(name for name in names if name in CAPABILITIES)


def effective_capability_names(user: Mapping[str, Any] | None) -> list[str]:
    """Return sorted known capability names effective for API clients."""

    if is_super_admin(user):
        return sorted(CAPABILITIES)
    return sorted(capabilities_of(user))


def has_cap(user: Mapping[str, Any] | None, capability: str) -> bool:
    """Return whether ``user`` holds ``capability`` (default-deny).

    ``super_admin`` is treated as holding every known capability. All other
    roles — including legacy ``admin`` with an empty capabilities map — are
    denied unless the capability is explicitly present. Unknown capability
    names never succeed.
    """

    if capability not in CAPABILITIES:
        return False
    if is_super_admin(user):
        return True
    return capability in capabilities_of(user)


def can_manage_users(user: Mapping[str, Any] | None) -> bool:
    """Users CRUD / list."""

    return has_cap(user, "users.manage")


def can_manage_connections(user: Mapping[str, Any] | None) -> bool:
    """Integrations create/patch/delete/test."""

    return has_cap(user, "connections.manage")


def can_setup_sonar(user: Mapping[str, Any] | None) -> bool:
    """``/api/sonar/setup`` mutations and reads."""

    return has_cap(user, "sonar.setup")


def can_adhoc_scan(user: Mapping[str, Any] | None) -> bool:
    """Start a scan with no project attachment."""

    return has_cap(user, "adhoc.scan")


def can_read_audit(user: Mapping[str, Any] | None) -> bool:
    """Read append-only audit events."""

    return has_cap(user, "audit.read")


def can_manage_all_groups(user: Mapping[str, Any] | None) -> bool:
    """List/edit every group without membership."""

    return has_cap(user, "groups.manage_all")


def can_manage_all_projects(user: Mapping[str, Any] | None) -> bool:
    """List/edit every project without membership."""

    return has_cap(user, "projects.manage_all")


def bypasses_project_scope(user: Mapping[str, Any] | None) -> bool:
    """Platform-wide project/scan visibility (not a bare admin role grant)."""

    return (
        is_super_admin(user)
        or can_manage_all_projects(user)
        or can_manage_all_groups(user)
    )


def can_start_scan_by_role(user: Mapping[str, Any] | None) -> bool:
    """Role gate for starting scans (tool flags stay in ``access.py``)."""

    return role_of(user) in _SCAN_STARTERS


def can_write_triage_by_role(user: Mapping[str, Any] | None) -> bool:
    """Role gate for investigate disposition writes (scope checked separately)."""

    return role_of(user) in _TRIAGE_WRITERS


def is_group_lead(
    *,
    lead_group_ids: Iterable[int] | None,
    group_id: int,
) -> bool:
    """Return whether the principal leads ``group_id`` only.

    Lead is never a global role: membership facts must be supplied by the
    caller. Empty/missing/invalid lead sets deny (never raise into allow).
    """

    if group_id is None:
        return False
    try:
        want = int(group_id)
    except (TypeError, ValueError):
        return False
    leads: set[int] = set()
    for item in lead_group_ids or []:
        try:
            leads.add(int(item))
        except (TypeError, ValueError):
            continue
    return want in leads


def can_edit_group(
    user: Mapping[str, Any] | None,
    *,
    group_id: int,
    lead_group_ids: Iterable[int] | None = None,
) -> bool:
    """Edit a group: ``groups.manage_all`` or lead of that group only.

    Lead path requires a triage-writer role (``super_admin`` / ``admin`` /
    ``developer``). A ``viewer`` lead flag does not authorize edits.
    """

    if has_cap(user, "groups.manage_all"):
        return True
    if not can_write_triage_by_role(user):
        return False
    return is_group_lead(lead_group_ids=lead_group_ids, group_id=group_id)

def can_edit_project(
    user: Mapping[str, Any] | None,
    *,
    lead_of_attached_group: bool = False,
) -> bool:
    """Edit a project: ``projects.manage_all`` or lead of an attached group."""

    if has_cap(user, "projects.manage_all"):
        return True
    return bool(lead_of_attached_group) and can_write_triage_by_role(user)


def can_accept_risk(
    user: Mapping[str, Any] | None,
    *,
    leads_project: bool = False,
) -> bool:
    """Accept risk on a project: ``risk.accept_any`` or scoped project lead.

    Viewers never accept. Developers/admins without the capability need
    ``leads_project`` from the caller (group that owns the project).
    """

    if has_cap(user, "risk.accept_any"):
        return True
    if role_of(user) not in {"admin", "developer"}:
        return False
    return bool(leads_project)


def can_reset_password(
    actor: Mapping[str, Any] | None,
    target: Mapping[str, Any] | None,
) -> bool:
    """Password reset policy without username hardcoding.

    - ``super_admin`` may reset any account (including another super_admin).
    - ``users.reset_password`` may reset non-super_admin targets only.
    - Nobody else may reset another account.
    """

    if not isinstance(actor, Mapping) or not isinstance(target, Mapping):
        return False
    if is_super_admin(actor):
        return True
    if not has_cap(actor, "users.reset_password"):
        return False
    return not is_super_admin(target)


def would_remove_last_super_admin(
    target: Mapping[str, Any] | None,
    *,
    other_active_super_admin_count: int,
    new_role: str | None = None,
    new_disabled: bool | None = None,
) -> bool:
    """Return True when the change would leave zero active super_admins.

    ``other_active_super_admin_count`` is the number of *other* currently
    active ``super_admin`` rows (excluding ``target``). Used for demote,
    disable, or delete decisions. Pure function — no DB I/O.
    """

    if not is_super_admin(target):
        return False
    # Non-positive counts fail closed as "no other active super_admins".
    try:
        others = int(other_active_super_admin_count)
    except (TypeError, ValueError):
        others = 0
    if others > 0:
        return False
    if new_role is None and new_disabled is None:
        # Delete (or unspecified mutate that removes the account).
        return True
    role = role_of(target) if new_role is None else str(new_role).strip()
    disabled = bool(target.get("disabled")) if new_disabled is None else bool(new_disabled)
    stays = role == "super_admin" and not disabled
    return not stays


def deny_reason_missing_cap(capability: str) -> str:
    """Stable client-facing denial message (never echoes capability names)."""

    del capability  # unused; kept for call-site stability
    return "You do not have permission."
