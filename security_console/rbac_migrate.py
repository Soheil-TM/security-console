"""One-time RBAC role/capability data migration (U1).

The mapping below is project-specific inventory keyed by stable user ``id``.
It must not be consulted by runtime authorization (``authz.py``).

DDL for ``super_admin`` / ``capabilities`` lives in ``db.MIGRATIONS`` /
``db.SCHEMA``. This module only performs the data step inside the caller's
transaction and records ``rbac_roles_u1_v1`` on the same connection.
"""

from __future__ import annotations

from typing import Any

from psycopg.types.json import Jsonb

from security_console import authz

# app_flags.name — set only after successful validation in the same txn.
RBAC_U1_FLAG = "rbac_roles_u1_v1"

# Continuity pack for org admins (ids 3 and 4). Explicit caps only — never
# implied by role == "admin" at runtime.
CONTINUITY_CAPABILITIES: dict[str, bool] = {
    name: True
    for name in (
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
    )
}

# id → (role, capabilities mapping). Empty caps for super_admin (ignored).
U1_BY_ID: dict[int, tuple[str, dict[str, bool]]] = {
    1: ("super_admin", {}),
    2: ("super_admin", {}),
    3: ("admin", dict(CONTINUITY_CAPABILITIES)),
    4: ("admin", dict(CONTINUITY_CAPABILITIES)),
}


class RbacMigrationError(RuntimeError):
    """U1 validation failed; the caller must roll back the transaction."""


def apply_rbac_u1(conn: Any) -> str:
    """Apply U1 role/capability mapping on ``conn`` (idempotent).

    Returns ``"skipped"`` when the flag is already present, otherwise
    ``"applied"``. Raises ``RbacMigrationError`` without writing the flag when
    validation fails so the surrounding transaction can roll back.
    """

    if _flag_present(conn, RBAC_U1_FLAG):
        return "skipped"

    for user_id, (role, caps) in U1_BY_ID.items():
        row = conn.execute(
            "SELECT id FROM users WHERE id = %s",
            (user_id,),
        ).fetchone()
        if row is None:
            continue
        conn.execute(
            """
            UPDATE users
            SET role = %s,
                capabilities = %s
            WHERE id = %s
            """,
            (role, Jsonb(caps), user_id),
        )

    _validate_u1(conn)
    conn.execute(
        """
        INSERT INTO app_flags (name)
        VALUES (%s)
        ON CONFLICT (name) DO NOTHING
        """,
        (RBAC_U1_FLAG,),
    )
    return "applied"


def _flag_present(conn: Any, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 AS found FROM app_flags WHERE name = %s",
        (name,),
    ).fetchone()
    return row is not None


def _validate_u1(conn: Any) -> None:
    """Fail closed if any present U1 row does not match the mapping."""

    for user_id, (want_role, want_caps) in U1_BY_ID.items():
        row = conn.execute(
            """
            SELECT id, role, capabilities, disabled
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        ).fetchone()
        if row is None:
            continue
        if str(row["role"]) != want_role:
            raise RbacMigrationError(
                f"rbac u1 validation failed for id={user_id}: role"
            )
        if want_role == "super_admin":
            # Caps column is ignored for super_admin at check time.
            continue
        got = authz.capabilities_of(
            {"role": row["role"], "capabilities": row["capabilities"]}
        )
        expected = frozenset(
            name for name, enabled in want_caps.items() if enabled
        )
        if got != expected:
            raise RbacMigrationError(
                f"rbac u1 validation failed for id={user_id}: capabilities"
            )

    # Inventory usernames must never appear in authz policy source.
    from pathlib import Path

    source = Path(authz.__file__).read_text(encoding="utf-8")
    for needle in ("402iti002", "405iti001", "405itm001"):
        if needle in source:
            raise RbacMigrationError("authz must not embed inventory usernames")

    # If any mapped super_admin row exists and is active, keep ≥1 active.
    active_supers = conn.execute(
        """
        SELECT count(*) AS n
        FROM users
        WHERE role = 'super_admin' AND disabled = false
        """
    ).fetchone()
    mapped_super_ids = [
        user_id
        for user_id, (role, _) in U1_BY_ID.items()
        if role == "super_admin"
    ]
    existing_mapped_super = conn.execute(
        """
        SELECT count(*) AS n
        FROM users
        WHERE id = ANY(%s)
        """,
        (mapped_super_ids,),
    ).fetchone()
    if (
        existing_mapped_super is not None
        and int(existing_mapped_super["n"]) > 0
        and active_supers is not None
        and int(active_supers["n"]) < 1
    ):
        raise RbacMigrationError(
            "rbac u1 validation failed: no active super_admin remains"
        )
