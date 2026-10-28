"""Unit tests for the centralized RBAC helpers (no database, no HTTP)."""

from __future__ import annotations

from security_console import authz


def _user(role: str, **extra: object) -> dict[str, object]:
    row: dict[str, object] = {"id": 1, "role": role, "username": "u"}
    row.update(extra)
    return row


def test_known_roles_include_target_set() -> None:
    assert authz.ROLES == ("super_admin", "admin", "developer", "viewer")
    assert authz.CURRENT_DB_ROLES == authz.ROLES
    assert authz.is_known_role("super_admin")
    assert authz.is_known_role("viewer")
    assert not authz.is_known_role("gate")
    assert not authz.is_known_role("")


def test_default_deny_without_capabilities() -> None:
    admin = _user("admin")
    developer = _user("developer")
    viewer = _user("viewer")
    for principal in (admin, developer, viewer, None, {}):
        assert authz.has_cap(principal, "users.manage") is False
        assert authz.can_manage_users(principal) is False
        assert authz.can_setup_sonar(principal) is False
        assert authz.can_adhoc_scan(principal) is False
        assert authz.can_manage_connections(principal) is False
        assert authz.can_read_audit(principal) is False


def test_unknown_capability_never_grants() -> None:
    privileged = _user("admin", capabilities={"users.manage": True, "not.a.cap": True})
    assert authz.has_cap(privileged, "not.a.cap") is False
    assert "not.a.cap" not in authz.capabilities_of(privileged)
    assert authz.has_cap(_user("super_admin"), "not.a.cap") is False


def test_super_admin_has_every_known_capability() -> None:
    principal = _user("super_admin", capabilities={})
    for name in authz.CAPABILITIES:
        assert authz.has_cap(principal, name) is True
    assert authz.is_super_admin(principal) is True
    assert authz.is_admin_role(principal) is False


def test_admin_only_gets_explicit_capabilities() -> None:
    pack = {
        "users.manage": True,
        "users.reset_password": True,
        "groups.manage_all": True,
        "projects.manage_all": True,
        "connections.manage": True,
        "tool_access.manage": True,
        "sonar.setup": True,
        "adhoc.scan": True,
        "risk.accept_any": True,
        "audit.read": True,
    }
    admin = _user("admin", capabilities=pack)
    for name in authz.CAPABILITIES:
        assert authz.has_cap(admin, name) is True
    partial = _user("admin", capabilities=["users.manage", "sonar.setup"])
    assert authz.can_manage_users(partial) is True
    assert authz.can_setup_sonar(partial) is True
    assert authz.can_adhoc_scan(partial) is False
    assert authz.can_manage_connections(partial) is False


def test_capabilities_accept_mapping_or_iterable_only() -> None:
    assert authz.capabilities_of(_user("admin", capabilities="users.manage")) == frozenset()
    assert authz.capabilities_of(_user("admin", capabilities=None)) == frozenset()
    assert authz.capabilities_of(
        _user("admin", capabilities={"users.manage": False, "sonar.setup": 1})
    ) == frozenset({"sonar.setup"})
    # Ambiguous string flags must not grant (\"0\" is truthy in Python).
    assert authz.capabilities_of(
        _user(
            "admin",
            capabilities={
                "users.manage": "0",
                "sonar.setup": "false",
                "adhoc.scan": "true",
                "audit.read": True,
            },
        )
    ) == frozenset({"audit.read"})


def test_unknown_role_is_denied_everywhere() -> None:
    unknown = _user("gate")
    weird = _user("Super_Admin")  # case-sensitive; not a known role
    for principal in (unknown, weird, _user(""), None, "not-a-mapping", 42):
        assert authz.has_cap(principal, "users.manage") is False  # type: ignore[arg-type]
        assert authz.can_start_scan_by_role(principal) is False  # type: ignore[arg-type]
        assert authz.can_write_triage_by_role(principal) is False  # type: ignore[arg-type]
        assert authz.can_accept_risk(principal, leads_project=True) is False  # type: ignore[arg-type]
        assert (
            authz.can_edit_group(principal, group_id=1, lead_group_ids={1})  # type: ignore[arg-type]
            is False
        )


def test_scan_and_triage_role_gates() -> None:
    assert authz.can_start_scan_by_role(_user("super_admin")) is True
    assert authz.can_start_scan_by_role(_user("admin")) is True
    assert authz.can_start_scan_by_role(_user("developer")) is True
    assert authz.can_start_scan_by_role(_user("viewer")) is False
    assert authz.can_write_triage_by_role(_user("viewer")) is False
    assert authz.can_write_triage_by_role(_user("developer")) is True


def test_lead_is_scoped_to_named_group_only() -> None:
    assert authz.is_group_lead(lead_group_ids={3, 9}, group_id=3) is True
    assert authz.is_group_lead(lead_group_ids={3, 9}, group_id=4) is False
    assert authz.is_group_lead(lead_group_ids=None, group_id=3) is False
    assert authz.is_group_lead(lead_group_ids=[], group_id=3) is False
    assert authz.is_group_lead(lead_group_ids={"3", 9}, group_id=3) is True
    # Invalid entries are skipped; must not raise or falsely grant.
    assert authz.is_group_lead(lead_group_ids={"x", None, 3}, group_id=3) is True
    assert authz.is_group_lead(lead_group_ids={"x", None}, group_id=3) is False
    assert authz.is_group_lead(lead_group_ids={3}, group_id="abc") is False  # type: ignore[arg-type]


def test_group_edit_requires_manage_all_or_that_group_lead() -> None:
    manager = _user("admin", capabilities={"groups.manage_all": True})
    lead_dev = _user("developer")
    other = _user("developer")
    viewer_lead = _user("viewer")
    assert authz.can_edit_group(manager, group_id=5, lead_group_ids=set()) is True
    assert (
        authz.can_edit_group(lead_dev, group_id=5, lead_group_ids={5}) is True
    )
    assert (
        authz.can_edit_group(lead_dev, group_id=5, lead_group_ids={8}) is False
    )
    assert authz.can_edit_group(other, group_id=5, lead_group_ids={}) is False
    # Lead of group A does not imply edit on group B.
    assert (
        authz.can_edit_group(lead_dev, group_id=2, lead_group_ids={5}) is False
    )
    # Viewer must not edit even when marked lead for that group.
    assert (
        authz.can_edit_group(viewer_lead, group_id=5, lead_group_ids={5})
        is False
    )
    # super_admin edits via manage_all, not via lead membership.
    assert (
        authz.can_edit_group(_user("super_admin"), group_id=5, lead_group_ids=set())
        is True
    )

def test_project_edit_and_risk_accept_respect_scope() -> None:
    any_risk = _user("admin", capabilities={"risk.accept_any": True})
    bare_admin = _user("admin")
    lead_dev = _user("developer")
    viewer = _user("viewer")
    assert authz.can_accept_risk(any_risk, leads_project=False) is True
    assert authz.can_accept_risk(_user("super_admin"), leads_project=False) is True
    # Legacy admin without risk.accept_any still needs project-lead scope.
    assert authz.can_accept_risk(bare_admin, leads_project=False) is False
    assert authz.can_accept_risk(bare_admin, leads_project=True) is True
    assert authz.can_accept_risk(lead_dev, leads_project=True) is True
    assert authz.can_accept_risk(lead_dev, leads_project=False) is False
    assert authz.can_accept_risk(viewer, leads_project=True) is False

    manage = _user("admin", capabilities={"projects.manage_all": True})
    assert authz.can_edit_project(manage, lead_of_attached_group=False) is True
    assert (
        authz.can_edit_project(lead_dev, lead_of_attached_group=True) is True
    )
    assert (
        authz.can_edit_project(lead_dev, lead_of_attached_group=False) is False
    )
    assert (
        authz.can_edit_project(viewer, lead_of_attached_group=True) is False
    )


def test_password_reset_policy_ignores_usernames() -> None:
    super_a = _user("super_admin", username="anyone")
    super_b = _user("super_admin", username="other")
    admin = _user(
        "admin",
        username="ops",
        capabilities={"users.reset_password": True},
    )
    bare_admin = _user("admin", username="admin")
    developer = _user("developer", username="dev")

    assert authz.can_reset_password(super_a, super_b) is True
    assert authz.can_reset_password(super_a, admin) is True
    assert authz.can_reset_password(admin, developer) is True
    assert authz.can_reset_password(admin, super_a) is False
    # Legacy username "admin" without capability must not gain reset rights here.
    assert authz.can_reset_password(bare_admin, developer) is False
    assert authz.can_reset_password(developer, admin) is False
    assert authz.can_reset_password(None, developer) is False
    assert authz.can_reset_password(admin, None) is False
    assert authz.can_reset_password("admin", developer) is False  # type: ignore[arg-type]


def test_last_super_admin_protection() -> None:
    only = _user("super_admin", disabled=False)
    assert (
        authz.would_remove_last_super_admin(
            only, other_active_super_admin_count=0
        )
        is True
    )
    assert (
        authz.would_remove_last_super_admin(
            only,
            other_active_super_admin_count=0,
            new_role="admin",
        )
        is True
    )
    assert (
        authz.would_remove_last_super_admin(
            only,
            other_active_super_admin_count=0,
            new_disabled=True,
        )
        is True
    )
    assert (
        authz.would_remove_last_super_admin(
            only,
            other_active_super_admin_count=0,
            new_role="super_admin",
            new_disabled=False,
        )
        is False
    )
    assert (
        authz.would_remove_last_super_admin(
            only, other_active_super_admin_count=1, new_role="admin"
        )
        is False
    )
    assert (
        authz.would_remove_last_super_admin(
            _user("admin"), other_active_super_admin_count=0
        )
        is False
    )
    # Negative / invalid counts fail closed as "no other super_admins".
    assert (
        authz.would_remove_last_super_admin(
            only, other_active_super_admin_count=-1, new_role="admin"
        )
        is True
    )
    assert (
        authz.would_remove_last_super_admin(
            only,
            other_active_super_admin_count="nope",  # type: ignore[arg-type]
            new_role="admin",
        )
        is True
    )


def test_no_username_literals_in_authz_source() -> None:
    """Runtime policy must not special-case inventory account names."""

    from pathlib import Path

    source = Path(authz.__file__).read_text(encoding="utf-8")
    assert "402iti002" not in source
    assert "405iti001" not in source
    assert "405itm001" not in source
    assert 'get("username")' not in source
    assert "user.get(\"username\")" not in source
    assert "['username']" not in source
