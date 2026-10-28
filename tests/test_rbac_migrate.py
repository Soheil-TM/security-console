"""RBAC schema/U1 migration and session compatibility on an isolated database.

These tests require ``DATABASE_URL`` pointing at a disposable database — never
the operational ``security_console_db``.
"""

from __future__ import annotations

import os

import pytest
from argon2 import PasswordHasher
from flask import Flask
from flask.testing import FlaskClient
from psycopg.types.json import Jsonb

from security_console import authz, db
from security_console.auth import install_auth, jwt_key
from security_console.rbac_migrate import (
    CONTINUITY_CAPABILITIES,
    RBAC_U1_FLAG,
    RbacMigrationError,
    U1_BY_ID,
    apply_rbac_u1,
)

_HASHER = PasswordHasher()

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL", "").strip(),
    reason="DATABASE_URL required for isolated RBAC migration tests",
)


@pytest.fixture(scope="module", autouse=True)
def _schema() -> None:
    db.prepare_database()


@pytest.fixture()
def clean_auth() -> None:
    db.reset_auth_tables()


def _insert_legacy(
    username: str,
    role: str = "admin",
    *,
    capabilities: dict | None = None,
) -> int:
    return db.insert_user(
        username,
        _HASHER.hash("correct-password-12"),
        role,
        allow_semgrep=True,
        allow_checkov=True,
        allow_sonar=True,
        allow_trivy=True,
        allow_sonar_ui=True,
        capabilities=capabilities if capabilities is not None else {},
    )


def test_u1_first_run_maps_ids_and_sets_flag(clean_auth: None) -> None:
    # Insert four accounts so ids become 1..4 (RESTART IDENTITY on truncate).
    for name in ("u1", "u2", "u3", "u4"):
        _insert_legacy(name, "admin")

    with db.connect() as conn:
        status = apply_rbac_u1(conn)
        conn.commit()
    assert status == "applied"

    rows = {int(user["id"]): user for user in db.list_users()}
    assert rows[1]["role"] == "super_admin"
    assert rows[2]["role"] == "super_admin"
    assert rows[3]["role"] == "admin"
    assert rows[4]["role"] == "admin"
    assert authz.capabilities_of(rows[3]) == frozenset(CONTINUITY_CAPABILITIES)
    assert authz.capabilities_of(rows[4]) == frozenset(CONTINUITY_CAPABILITIES)
    assert db.has_flag(RBAC_U1_FLAG) is True


def test_u1_second_run_is_idempotent(clean_auth: None) -> None:
    for name in ("u1", "u2", "u3", "u4"):
        _insert_legacy(name, "admin")
    with db.connect() as conn:
        assert apply_rbac_u1(conn) == "applied"
        conn.commit()
    # Tamper after flag is set — re-apply must not rewrite.
    with db.connect() as conn:
        conn.execute(
            "UPDATE users SET role = 'developer', capabilities = %s WHERE id = 3",
            (Jsonb({}),),
        )
        conn.commit()
    with db.connect() as conn:
        assert apply_rbac_u1(conn) == "skipped"
        conn.commit()
    row = db.find_user_by_id(3)
    assert row is not None
    assert row["role"] == "developer"


def test_u1_validation_failure_rolls_back(clean_auth: None) -> None:
    for name in ("u1", "u2", "u3", "u4"):
        _insert_legacy(name, "admin")
    with db.connect() as conn:
        # Force a bad post-update state by deleting supers mid-flight via
        # monkeypatch of validate — instead break mapping by renaming role
        # check: call apply then corrupt before validate by patching.
        original = apply_rbac_u1
        del original  # quiet linters about unused in some paths

    with db.connect() as conn:
        # Disable mapped supers after update by injecting failure: run updates
        # manually then validate path via apply on a connection where we
        # pre-set an impossible state — simulate by applying with id 1 disabled
        # and deleting the only other super after partial update.
        conn.execute(
            """
            UPDATE users SET role = 'super_admin', capabilities = '{}'::jsonb
            WHERE id IN (1, 2)
            """
        )
        conn.execute("UPDATE users SET disabled = true WHERE id IN (1, 2)")
        conn.execute(
            """
            UPDATE users SET role = 'admin', capabilities = %s WHERE id IN (3, 4)
            """,
            (Jsonb(CONTINUITY_CAPABILITIES),),
        )
        with pytest.raises(RbacMigrationError):
            # Flag not set; apply will re-update then validate — still no
            # active super_admin.
            apply_rbac_u1(conn)
        conn.rollback()

    assert db.has_flag(RBAC_U1_FLAG) is False
    # Rollback restored pre-transaction rows (all still admin, enabled).
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, role, disabled FROM users ORDER BY id"
        ).fetchall()
        conn.commit()
    assert [str(row["role"]) for row in rows] == [
        "admin",
        "admin",
        "admin",
        "admin",
    ]
    assert all(not row["disabled"] for row in rows)


def test_effective_capabilities_for_four_roles(clean_auth: None) -> None:
    super_id = _insert_legacy("super", "super_admin")
    admin_id = _insert_legacy(
        "ops",
        "admin",
        capabilities={"users.manage": True, "sonar.setup": True},
    )
    bare_admin = _insert_legacy("bare", "admin", capabilities={})
    dev = _insert_legacy("dev", "developer")
    viewer = _insert_legacy("view", "viewer")

    super_u = db.find_user_by_id(super_id)
    admin_u = db.find_user_by_id(admin_id)
    bare_u = db.find_user_by_id(bare_admin)
    dev_u = db.find_user_by_id(dev)
    view_u = db.find_user_by_id(viewer)
    assert super_u and admin_u and bare_u and dev_u and view_u

    assert set(authz.effective_capability_names(super_u)) == set(authz.CAPABILITIES)
    assert authz.effective_capability_names(admin_u) == [
        "sonar.setup",
        "users.manage",
    ]
    assert authz.effective_capability_names(bare_u) == []
    assert authz.effective_capability_names(dev_u) == []
    assert authz.effective_capability_names(view_u) == []
    assert authz.has_cap(bare_u, "users.manage") is False
    assert authz.has_cap(admin_u, "users.manage") is True


def test_last_super_admin_helpers(clean_auth: None) -> None:
    only = _insert_legacy("solo", "super_admin")
    user = db.find_user_by_id(only)
    assert user is not None
    assert (
        authz.would_remove_last_super_admin(
            user,
            other_active_super_admin_count=db.count_other_super_admins(only),
            new_role="admin",
        )
        is True
    )
    second = _insert_legacy("pair", "super_admin")
    assert db.count_other_super_admins(only) == 1
    assert (
        authz.would_remove_last_super_admin(
            user,
            other_active_super_admin_count=db.count_other_super_admins(only),
            new_role="admin",
        )
        is False
    )
    assert second > 0


def test_has_cap_ignores_username_entirely(clean_auth: None) -> None:
    actor = {
        "id": 1,
        "username": "admin",
        "role": "admin",
        "capabilities": {},
    }
    assert authz.has_cap(actor, "users.manage") is False
    assert authz.can_reset_password(actor, {"id": 2, "role": "developer"}) is False
    privileged = {
        "id": 3,
        "username": "not-special",
        "role": "admin",
        "capabilities": {"users.reset_password": True},
    }
    assert authz.can_reset_password(privileged, {"id": 2, "role": "developer"}) is True
    assert (
        authz.can_reset_password(privileged, {"id": 9, "role": "super_admin"})
        is False
    )


def test_session_and_me_survive_super_admin_role(clean_auth: None) -> None:
    user_id = _insert_legacy("boss", "super_admin")
    app = Flask(__name__)
    app.config["TESTING"] = True
    install_auth(app)
    client: FlaskClient = app.test_client()
    login = client.post(
        "/api/auth/login",
        json={"username": "boss", "password": "correct-password-12"},
    )
    assert login.status_code == 200
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    body = me.get_json()
    assert body["role"] == "super_admin"
    assert set(body["capabilities"]) == set(authz.CAPABILITIES)
    assert body["access"]["semgrep"] is True
    # Reload user as super_admin without bumping session_version — still valid.
    again = client.get("/api/auth/me")
    assert again.status_code == 200
    assert again.get_json()["id"] == user_id
    # jwt key still configured for this environment
    assert len(jwt_key()) >= 32


def test_prepare_database_runs_u1_inside_same_flow(clean_auth: None) -> None:
    for name in ("a", "b", "c", "d"):
        _insert_legacy(name, "admin")
    # Flag cleared by clean_auth; prepare_database should apply U1.
    db.prepare_database()
    assert db.has_flag(RBAC_U1_FLAG) is True
    assert db.find_user_by_id(1)["role"] == "super_admin"
    assert set(U1_BY_ID) == {1, 2, 3, 4}
