"""Postgres storage for console users, sessions, and login attempts."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.rows import dict_row

from security_console.secrets import read_secret as _read_secret

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS users (
        id bigserial PRIMARY KEY,
        username text NOT NULL UNIQUE,
        email text NOT NULL DEFAULT '',
        password_hash text NOT NULL,
        role text NOT NULL CHECK (role IN ('admin', 'developer', 'viewer')),
        disabled boolean NOT NULL DEFAULT false,
        allow_semgrep boolean NOT NULL DEFAULT true,
        allow_checkov boolean NOT NULL DEFAULT true,
        allow_sonar boolean NOT NULL DEFAULT false,
        allow_sonar_ui boolean NOT NULL DEFAULT false,
        allow_trivy boolean NOT NULL DEFAULT true,
        first_name text NOT NULL DEFAULT '',
        last_name text NOT NULL DEFAULT '',
        must_change_password boolean NOT NULL DEFAULT false,
        session_version integer NOT NULL DEFAULT 0,
        idle_timeout_minutes integer NOT NULL DEFAULT 15,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS app_flags (
        name text PRIMARY KEY
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id bigserial PRIMARY KEY,
        user_id bigint NOT NULL REFERENCES users (id),
        token_hash text NOT NULL UNIQUE,
        expires_at timestamptz NOT NULL,
        revoked_at timestamptz,
        last_activity_at timestamptz NOT NULL DEFAULT now(),
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS revoked_access (
        jti text PRIMARY KEY,
        expires_at timestamptz NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id bigserial PRIMARY KEY,
        ip text NOT NULL,
        succeeded boolean NOT NULL,
        attempted_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS login_attempts_ip_time
        ON login_attempts (ip, attempted_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS ingest_attempts (
        id bigserial PRIMARY KEY,
        ip text NOT NULL,
        succeeded boolean NOT NULL,
        attempted_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ingest_attempts_ip_time
        ON ingest_attempts (ip, attempted_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS project_groups (
        id bigserial PRIMARY KEY,
        name text NOT NULL UNIQUE,
        description text NOT NULL DEFAULT '',
        created_by bigint REFERENCES users (id) ON DELETE SET NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS group_projects (
        group_id bigint NOT NULL
            REFERENCES project_groups (id) ON DELETE CASCADE,
        project_key text NOT NULL,
        kind text NOT NULL CHECK (kind IN ('repo', 'image')),
        target text NOT NULL,
        PRIMARY KEY (group_id, project_key)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS group_members (
        group_id bigint NOT NULL
            REFERENCES project_groups (id) ON DELETE CASCADE,
        user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        lead boolean NOT NULL DEFAULT false,
        added_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (group_id, user_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS group_members_user
        ON group_members (user_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS group_events (
        id bigserial PRIMARY KEY,
        group_id bigint NOT NULL
            REFERENCES project_groups (id) ON DELETE CASCADE,
        actor text NOT NULL,
        action text NOT NULL,
        detail text NOT NULL DEFAULT '',
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS integrations (
        id bigserial PRIMARY KEY,
        kind text NOT NULL CHECK (kind IN ('gitlab', 'registry')),
        name text NOT NULL UNIQUE,
        base_url text NOT NULL,
        username text NOT NULL DEFAULT '',
        secret text NOT NULL DEFAULT '',
        ca_cert text NOT NULL DEFAULT '',
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
    )
    """,
)


@dataclass(frozen=True)
class DbSettings:
    """Connection settings. Passwords stay out of log messages."""

    app_host: str
    app_user: str
    app_password: str
    app_name: str
    bootstrap_host: str
    bootstrap_user: str
    bootstrap_password: str
    database_url: str


def read_secret(env_name: str, file_env: str) -> str:
    """Return a secret from a file when configured, otherwise from the env."""

    return _read_secret(env_name, file_env)


def load_settings() -> DbSettings:
    """Build connection settings from the environment or secret files."""

    return DbSettings(
        app_host=os.environ.get("CONSOLE_DB_HOST", "db"),
        app_user=os.environ.get("CONSOLE_DB_USER", "console"),
        app_password=read_secret(
            "CONSOLE_DB_PASSWORD",
            "CONSOLE_DB_PASSWORD_FILE",
        ),
        app_name=os.environ.get("CONSOLE_DB_NAME", "security_console_db"),
        bootstrap_host=os.environ.get("CONSOLE_DB_HOST", "db"),
        bootstrap_user=os.environ.get("CONSOLE_DB_BOOTSTRAP_USER", "console"),
        bootstrap_password=read_secret(
            "CONSOLE_DB_BOOTSTRAP_PASSWORD",
            "CONSOLE_DB_BOOTSTRAP_PASSWORD_FILE",
        ),
        database_url=os.environ.get("DATABASE_URL", "").strip(),
    )


def connect() -> psycopg.Connection[dict[str, Any]]:
    """Open one application connection. Caller closes it."""

    settings = load_settings()
    if settings.database_url:
        return psycopg.connect(
            settings.database_url,
            connect_timeout=5,
            row_factory=dict_row,
        )
    if not settings.app_password:
        raise RuntimeError("console database password is not configured")
    return psycopg.connect(
        host=settings.app_host,
        port=5432,
        user=settings.app_user,
        password=settings.app_password,
        dbname=settings.app_name,
        connect_timeout=5,
        row_factory=dict_row,
    )


def ensure_database() -> None:
    """Create the dedicated role and database when bootstrap credentials exist.

    Compose creates that role itself, so this step stays idle unless a
    bootstrap password is set. The running console then connects as ``console``.
    """

    settings = load_settings()
    if settings.database_url or not settings.bootstrap_password:
        return
    if not settings.app_password:
        raise RuntimeError("console database password is not configured")
    with psycopg.connect(
        host=settings.bootstrap_host,
        port=5432,
        user=settings.bootstrap_user,
        password=settings.bootstrap_password,
        dbname="postgres",
        connect_timeout=5,
        autocommit=True,
    ) as conn:
        role = conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s",
            (settings.app_user,),
        ).fetchone()
        password = _sql_literal(settings.app_password)
        if role is None:
            conn.execute(
                "CREATE ROLE "
                + _ident(settings.app_user)
                + " LOGIN PASSWORD "
                + password
            )
        else:
            conn.execute(
                "ALTER ROLE "
                + _ident(settings.app_user)
                + " PASSWORD "
                + password
            )
        database = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s",
            (settings.app_name,),
        ).fetchone()
        if database is None:
            conn.execute(
                "CREATE DATABASE "
                + _ident(settings.app_name)
                + " OWNER "
                + _ident(settings.app_user)
            )
        conn.execute(
            "REVOKE ALL ON DATABASE "
            + _ident(settings.app_name)
            + " FROM PUBLIC"
        )
        conn.execute(
            "GRANT CONNECT, TEMP ON DATABASE "
            + _ident(settings.app_name)
            + " TO "
            + _ident(settings.app_user)
        )


def _ident(value: str) -> str:
    """Quote a SQL identifier that is restricted to a safe alphabet."""

    if not value or any(ch not in "abcdefghijklmnopqrstuvwxyz_" for ch in value):
        raise RuntimeError("database identifier is not allowed")
    return value


def _sql_literal(value: str) -> str:
    """Return a standard SQL string literal.

    ``CREATE ROLE ... PASSWORD`` does not accept a bound parameter, so the
    password is escaped here and never concatenated raw.
    """

    if any(ord(ch) < 32 for ch in value):
        raise RuntimeError("database password contains a control character")
    return "'" + value.replace("'", "''") + "'"


MIGRATIONS = (
    """
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT ''
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS allow_semgrep boolean NOT NULL DEFAULT true
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS allow_checkov boolean NOT NULL DEFAULT true
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS allow_sonar boolean NOT NULL DEFAULT false
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS allow_trivy boolean NOT NULL DEFAULT true
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS must_change_password boolean
        NOT NULL DEFAULT false
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS session_version integer
        NOT NULL DEFAULT 0
    """,
    """
    DO $$
    DECLARE constraint_name text;
    BEGIN
        FOR constraint_name IN
            SELECT conname
            FROM pg_constraint
            WHERE conrelid = 'users'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) ILIKE '%role%'
        LOOP
            EXECUTE format(
                'ALTER TABLE users DROP CONSTRAINT %I',
                constraint_name
            );
        END LOOP;
    END $$
    """,
    """
    ALTER TABLE users
        ADD CONSTRAINT users_role_check
        CHECK (role IN ('admin', 'developer', 'viewer'))
    """,
    """
    UPDATE users
    SET allow_semgrep = true,
        allow_checkov = true,
        allow_sonar = true,
        allow_trivy = true
    WHERE role = 'admin'
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS allow_sonar_ui boolean NOT NULL DEFAULT false
    """,
    """
    UPDATE users SET allow_sonar_ui = true WHERE role = 'admin'
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS idle_timeout_minutes integer
        NOT NULL DEFAULT 15
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS first_name text NOT NULL DEFAULT ''
    """,
    """
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS last_name text NOT NULL DEFAULT ''
    """,
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'users_idle_timeout_check'
        ) THEN
            ALTER TABLE users
                ADD CONSTRAINT users_idle_timeout_check
                CHECK (idle_timeout_minutes IN (5, 15, 30, 60));
        END IF;
    END $$
    """,
    """
    ALTER TABLE refresh_tokens
        ADD COLUMN IF NOT EXISTS last_activity_at timestamptz
        NOT NULL DEFAULT now()
    """,
    """
    ALTER TABLE refresh_tokens
        ADD COLUMN IF NOT EXISTS created_at timestamptz
        NOT NULL DEFAULT now()
    """,
)


def prepare_database() -> None:
    """Create tables. Existing scan history on disk is left untouched."""

    ensure_database()
    with connect() as conn:
        for statement in SCHEMA:
            conn.execute(statement)
        for statement in MIGRATIONS:
            conn.execute(statement)
        conn.commit()


def count_users() -> int:
    """Return how many console accounts exist."""

    with connect() as conn:
        row = conn.execute("SELECT count(*) AS n FROM users").fetchone()
        conn.commit()
    if row is None:
        return 0
    return int(row["n"])


def insert_user(
    username: str,
    password_hash: str,
    role: str,
    email: str = "",
    allow_semgrep: bool = True,
    allow_checkov: bool = True,
    allow_sonar: bool = False,
    allow_trivy: bool = True,
    must_change_password: bool = False,
    allow_sonar_ui: bool = False,
    first_name: str = "",
    last_name: str = "",
) -> int:
    """Insert one account and return its id."""

    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO users (
                username, email, password_hash, role,
                allow_semgrep, allow_checkov, allow_sonar, allow_trivy,
                allow_sonar_ui, must_change_password, first_name, last_name
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                username,
                email,
                password_hash,
                role,
                allow_semgrep,
                allow_checkov,
                allow_sonar,
                allow_trivy,
                allow_sonar_ui,
                must_change_password,
                first_name,
                last_name,
            ),
        ).fetchone()
        conn.commit()
    if row is None:
        raise RuntimeError("user insert did not return an id")
    return int(row["id"])


def find_user(username: str) -> dict[str, Any] | None:
    """Return one account, including the password hash, or None."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, username, email, first_name, last_name,
                   password_hash, role, disabled,
                   allow_semgrep, allow_checkov, allow_sonar, allow_trivy,
                   allow_sonar_ui, must_change_password, session_version,
                   idle_timeout_minutes
            FROM users
            WHERE username = %s
            """,
            (username,),
        ).fetchone()
        conn.commit()
    return dict(row) if row else None


def find_user_by_id(user_id: int) -> dict[str, Any] | None:
    """Return one account without the password hash, or None."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, username, email, first_name, last_name, role, disabled,
                   allow_semgrep, allow_checkov, allow_sonar,
                   allow_trivy, allow_sonar_ui, must_change_password,
                   session_version, idle_timeout_minutes, created_at
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        ).fetchone()
        conn.commit()
    return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    """Return every account without password hashes."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, username, email, first_name, last_name, role, disabled,
                   allow_semgrep, allow_checkov, allow_sonar,
                   allow_trivy, allow_sonar_ui, created_at
            FROM users
            ORDER BY username
            """
        ).fetchall()
        conn.commit()
    return [dict(row) for row in rows]


def count_other_admins(user_id: int) -> int:
    """Count active admins other than this account."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT count(*) AS n
            FROM users
            WHERE role = 'admin' AND disabled = false AND id <> %s
            """,
            (user_id,),
        ).fetchone()
        conn.commit()
    if row is None:
        return 0
    return int(row["n"])


def update_user(
    user_id: int,
    username: str,
    email: str,
    role: str,
    disabled: bool,
    allow_semgrep: bool,
    allow_checkov: bool,
    allow_sonar: bool,
    allow_trivy: bool,
    password_hash: str | None,
    allow_sonar_ui: bool = False,
    first_name: str = "",
    last_name: str = "",
    must_change_password: bool = False,
) -> None:
    """Replace the editable fields of one account."""

    with connect() as conn:
        if password_hash is None:
            conn.execute(
                """
                UPDATE users
                SET username = %s, email = %s, role = %s, disabled = %s,
                    allow_semgrep = %s, allow_checkov = %s,
                    allow_sonar = %s, allow_trivy = %s,
                    allow_sonar_ui = %s,
                    first_name = %s, last_name = %s
                WHERE id = %s
                """,
                (
                    username,
                    email,
                    role,
                    disabled,
                    allow_semgrep,
                    allow_checkov,
                    allow_sonar,
                    allow_trivy,
                    allow_sonar_ui,
                    first_name,
                    last_name,
                    user_id,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE users
                SET username = %s, email = %s, role = %s, disabled = %s,
                    allow_semgrep = %s, allow_checkov = %s,
                    allow_sonar = %s, allow_trivy = %s,
                    allow_sonar_ui = %s,
                    first_name = %s, last_name = %s,
                    password_hash = %s,
                    must_change_password = %s,
                    session_version = session_version + 1
                WHERE id = %s
                """,
                (
                    username,
                    email,
                    role,
                    disabled,
                    allow_semgrep,
                    allow_checkov,
                    allow_sonar,
                    allow_trivy,
                    allow_sonar_ui,
                    first_name,
                    last_name,
                    password_hash,
                    must_change_password,
                    user_id,
                ),
            )
            _revoke_refresh_conn(conn, user_id)
        conn.commit()


def set_password_hash(user_id: int, password_hash: str) -> None:
    """Replace one password and end every existing session for that account."""

    with connect() as conn:
        conn.execute(
            """
            UPDATE users
            SET password_hash = %s,
                must_change_password = false,
                session_version = session_version + 1
            WHERE id = %s
            """,
            (password_hash, user_id),
        )
        _revoke_refresh_conn(conn, user_id)
        conn.commit()


def _revoke_refresh_conn(
    conn: psycopg.Connection[dict[str, Any]],
    user_id: int,
) -> None:
    """Revoke every live refresh token for one account on an open transaction."""

    conn.execute(
        """
        UPDATE refresh_tokens
        SET revoked_at = %s
        WHERE user_id = %s AND revoked_at IS NULL
        """,
        (datetime.now(UTC), user_id),
    )


def delete_user(user_id: int) -> None:
    """Remove an account and its refresh tokens."""

    with connect() as conn:
        conn.execute(
            "DELETE FROM refresh_tokens WHERE user_id = %s",
            (user_id,),
        )
        conn.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()


def recent_failures(ip: str) -> int:
    """Count failed logins for this address during the last minute."""

    cutoff = datetime.now(UTC) - timedelta(minutes=1)
    with connect() as conn:
        row = conn.execute(
            """
            SELECT count(*) AS n
            FROM login_attempts
            WHERE ip = %s AND succeeded = false AND attempted_at > %s
            """,
            (ip, cutoff),
        ).fetchone()
        conn.commit()
    if row is None:
        return 0
    return int(row["n"])


def recent_ingest(ip: str, *, failures_only: bool) -> int:
    """Count Falco ingest calls for this address during the last minute."""

    cutoff = datetime.now(UTC) - timedelta(minutes=1)
    query = """
        SELECT count(*) AS n
        FROM ingest_attempts
        WHERE ip = %s AND attempted_at > %s
    """
    params: list[Any] = [ip, cutoff]
    if failures_only:
        query += " AND succeeded = false"
    with connect() as conn:
        row = conn.execute(query, params).fetchone()
        conn.commit()
    if row is None:
        return 0
    return int(row["n"])


def record_ingest(ip: str, succeeded: bool) -> None:
    """Store one Falco ingest call and drop rows older than a day."""

    cutoff = datetime.now(UTC) - timedelta(days=1)
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO ingest_attempts (ip, succeeded)
            VALUES (%s, %s)
            """,
            (ip, succeeded),
        )
        conn.execute(
            "DELETE FROM ingest_attempts WHERE attempted_at < %s",
            (cutoff,),
        )
        conn.commit()


def record_attempt(ip: str, succeeded: bool) -> None:
    """Store one login attempt and drop rows older than a day."""

    cutoff = datetime.now(UTC) - timedelta(days=1)
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO login_attempts (ip, succeeded)
            VALUES (%s, %s)
            """,
            (ip, succeeded),
        )
        conn.execute(
            "DELETE FROM login_attempts WHERE attempted_at < %s",
            (cutoff,),
        )
        conn.commit()


def store_refresh(
    user_id: int,
    token_hash: str,
    expires_at: datetime,
    last_activity_at: datetime | None = None,
    created_at: datetime | None = None,
) -> int:
    """Persist a hashed refresh token and return its session id."""

    now = datetime.now(UTC)
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO refresh_tokens (
                user_id, token_hash, expires_at, last_activity_at, created_at
            )
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                user_id,
                token_hash,
                expires_at,
                last_activity_at or now,
                created_at or now,
            ),
        ).fetchone()
        conn.commit()
    if row is None:
        raise RuntimeError("refresh token insert did not return an id")
    return int(row["id"])


def take_refresh(token_hash: str) -> dict[str, Any] | None:
    """Revoke a refresh token and return it when it was still usable."""

    now = datetime.now(UTC)
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE refresh_tokens
            SET revoked_at = %s
            WHERE token_hash = %s
              AND revoked_at IS NULL
              AND expires_at > %s
            RETURNING id, user_id, expires_at, last_activity_at, created_at
            """,
            (now, token_hash, now),
        ).fetchone()
        conn.commit()
    return dict(row) if row else None


def get_session(session_id: int) -> dict[str, Any] | None:
    """Return one refresh session, including a revoked row."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, user_id, expires_at, revoked_at,
                   last_activity_at, created_at
            FROM refresh_tokens
            WHERE id = %s
            """,
            (session_id,),
        ).fetchone()
        conn.commit()
    return dict(row) if row else None


def touch_session(session_id: int) -> bool:
    """Record activity on a live session. A revoked row is left unchanged."""

    now = datetime.now(UTC)
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE refresh_tokens
            SET last_activity_at = %s
            WHERE id = %s AND revoked_at IS NULL AND expires_at > %s
            RETURNING id
            """,
            (now, session_id, now),
        ).fetchone()
        conn.commit()
    return row is not None


def revoke_session(session_id: int) -> None:
    """Revoke one refresh session. A missing row is ignored."""

    now = datetime.now(UTC)
    with connect() as conn:
        conn.execute(
            """
            UPDATE refresh_tokens
            SET revoked_at = %s
            WHERE id = %s AND revoked_at IS NULL
            """,
            (now, session_id),
        )
        conn.commit()


def set_idle_timeout(user_id: int, minutes: int) -> None:
    """Store the idle timeout chosen by this account."""

    with connect() as conn:
        conn.execute(
            """
            UPDATE users
            SET idle_timeout_minutes = %s
            WHERE id = %s
            """,
            (minutes, user_id),
        )
        conn.commit()


def revoke_refresh(token_hash: str) -> None:
    """Mark one refresh token revoked. Missing rows are ignored."""

    now = datetime.now(UTC)
    with connect() as conn:
        conn.execute(
            """
            UPDATE refresh_tokens
            SET revoked_at = %s
            WHERE token_hash = %s AND revoked_at IS NULL
            """,
            (now, token_hash),
        )
        conn.commit()


def revoke_access(jti: str, expires_at: datetime) -> None:
    """Remember an access token until it would have expired anyway."""

    with connect() as conn:
        conn.execute(
            """
            INSERT INTO revoked_access (jti, expires_at)
            VALUES (%s, %s)
            ON CONFLICT (jti) DO NOTHING
            """,
            (jti, expires_at),
        )
        conn.execute(
            "DELETE FROM revoked_access WHERE expires_at < %s",
            (datetime.now(UTC),),
        )
        conn.commit()


def access_revoked(jti: str) -> bool:
    """Return whether this access token id has been logged out."""

    with connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM revoked_access WHERE jti = %s",
            (jti,),
        ).fetchone()
        conn.commit()
    return row is not None


def has_flag(name: str) -> bool:
    """Return whether a one-time startup marker is stored."""

    with connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM app_flags WHERE name = %s",
            (name,),
        ).fetchone()
        conn.commit()
    return row is not None


def set_flag(name: str) -> None:
    """Store a one-time startup marker. Repeating it is harmless."""

    with connect() as conn:
        conn.execute(
            """
            INSERT INTO app_flags (name)
            VALUES (%s)
            ON CONFLICT (name) DO NOTHING
            """,
            (name,),
        )
        conn.commit()


def require_password_change(username: str, password_hash: str) -> None:
    """Set one account's password and require a change at the next sign-in.

    Startup does not call this. An upgrade must not overwrite an existing
    administrator password.
    """

    with connect() as conn:
        conn.execute(
            """
            UPDATE users
            SET password_hash = %s, must_change_password = true
            WHERE username = %s
            """,
            (password_hash, username),
        )
        conn.commit()


def group_project_keys(user_id: int) -> set[str]:
    """Return every project key in groups this account belongs to."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT p.project_key
            FROM group_projects AS p
            JOIN group_members AS m ON m.group_id = p.group_id
            WHERE m.user_id = %s
            """,
            (user_id,),
        ).fetchall()
        conn.commit()
    return {str(row["project_key"]) for row in rows}


def _group_ids_for(
    conn: psycopg.Connection[dict[str, Any]],
    user_id: int | None,
) -> list[int]:
    if user_id is None:
        rows = conn.execute(
            "SELECT id FROM project_groups ORDER BY name"
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT g.id
            FROM project_groups AS g
            JOIN group_members AS m ON m.group_id = g.id
            WHERE m.user_id = %s
            ORDER BY g.name
            """,
            (user_id,),
        ).fetchall()
    return [int(row["id"]) for row in rows]


def _load_group(
    conn: psycopg.Connection[dict[str, Any]],
    group_id: int,
) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, name, description, created_by, created_at
        FROM project_groups
        WHERE id = %s
        """,
        (group_id,),
    ).fetchone()
    if row is None:
        return None
    projects = conn.execute(
        """
        SELECT project_key, kind, target
        FROM group_projects
        WHERE group_id = %s
        ORDER BY kind, target
        """,
        (group_id,),
    ).fetchall()
    members = conn.execute(
        """
        SELECT u.id, u.username, u.role, m.lead
        FROM group_members AS m
        JOIN users AS u ON u.id = m.user_id
        WHERE m.group_id = %s
        ORDER BY u.username
        """,
        (group_id,),
    ).fetchall()
    events = conn.execute(
        """
        SELECT actor, action, detail, created_at
        FROM group_events
        WHERE group_id = %s
        ORDER BY id DESC
        LIMIT 8
        """,
        (group_id,),
    ).fetchall()
    loaded = dict(row)
    loaded["projects"] = [dict(item) for item in projects]
    loaded["members"] = [dict(item) for item in members]
    loaded["events"] = [dict(item) for item in events]
    return loaded


def list_groups(user_id: int | None) -> list[dict[str, Any]]:
    """Return every group, or only the groups one account belongs to."""

    with connect() as conn:
        groups = [
            loaded
            for group_id in _group_ids_for(conn, user_id)
            if (loaded := _load_group(conn, group_id)) is not None
        ]
        conn.commit()
    return groups


def get_group(group_id: int) -> dict[str, Any] | None:
    """Return one group with its projects, members, and recent events."""

    with connect() as conn:
        loaded = _load_group(conn, group_id)
        conn.commit()
    return loaded


def users_by_username(names: list[str]) -> list[dict[str, Any]]:
    """Return accounts whose usernames are in this list."""

    if not names:
        return []
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, username, role, disabled
            FROM users
            WHERE username = ANY(%s)
            """,
            (names,),
        ).fetchall()
        conn.commit()
    return [dict(row) for row in rows]


def insert_group(
    name: str,
    description: str,
    created_by: int,
    projects: list[dict[str, str]],
    members: list[tuple[int, bool]],
    actor: str,
    detail: str,
) -> int:
    """Create a group and return its id."""

    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO project_groups (name, description, created_by)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (name, description, created_by),
        ).fetchone()
        if row is None:
            raise RuntimeError("group insert did not return an id")
        group_id = int(row["id"])
        _write_group_children(conn, group_id, projects, members)
        _write_group_event(conn, group_id, actor, "created", detail)
        conn.commit()
    return group_id


def update_group(
    group_id: int,
    name: str,
    description: str,
    projects: list[dict[str, str]],
    members: list[tuple[int, bool]],
    actor: str,
    detail: str,
) -> None:
    """Replace a group's name, projects, and members."""

    with connect() as conn:
        conn.execute(
            """
            UPDATE project_groups
            SET name = %s, description = %s
            WHERE id = %s
            """,
            (name, description, group_id),
        )
        conn.execute(
            "DELETE FROM group_projects WHERE group_id = %s",
            (group_id,),
        )
        conn.execute(
            "DELETE FROM group_members WHERE group_id = %s",
            (group_id,),
        )
        _write_group_children(conn, group_id, projects, members)
        _write_group_event(conn, group_id, actor, "updated", detail)
        conn.commit()


def delete_group(group_id: int) -> None:
    """Delete a group. Members, projects, and events go with it."""

    with connect() as conn:
        conn.execute(
            "DELETE FROM project_groups WHERE id = %s",
            (group_id,),
        )
        conn.commit()


def _write_group_children(
    conn: psycopg.Connection[dict[str, Any]],
    group_id: int,
    projects: list[dict[str, str]],
    members: list[tuple[int, bool]],
) -> None:
    for project in projects:
        conn.execute(
            """
            INSERT INTO group_projects (group_id, project_key, kind, target)
            VALUES (%s, %s, %s, %s)
            """,
            (
                group_id,
                project["key"],
                project["kind"],
                project["target"],
            ),
        )
    for user_id, lead in members:
        conn.execute(
            """
            INSERT INTO group_members (group_id, user_id, lead)
            VALUES (%s, %s, %s)
            """,
            (group_id, user_id, lead),
        )


def _write_group_event(
    conn: psycopg.Connection[dict[str, Any]],
    group_id: int,
    actor: str,
    action: str,
    detail: str,
) -> None:
    conn.execute(
        """
        INSERT INTO group_events (group_id, actor, action, detail)
        VALUES (%s, %s, %s, %s)
        """,
        (group_id, actor, action, detail[:500]),
    )


def list_integrations() -> list[dict[str, Any]]:
    """Return saved connections without tokens or certificates."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, kind, name, base_url, username,
                   secret <> '' AS has_secret,
                   ca_cert <> '' AS has_ca
            FROM integrations
            ORDER BY name
            """
        ).fetchall()
        conn.commit()
    return [dict(row) for row in rows]


def integration_secrets() -> list[dict[str, Any]]:
    """Return connection secrets for the scanner. Callers must not log them."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, kind, base_url, username, secret, ca_cert
            FROM integrations
            """
        ).fetchall()
        conn.commit()
    return [dict(row) for row in rows]


def get_integration(integration_id: int) -> dict[str, Any] | None:
    """Return one connection, including its secret."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, kind, name, base_url, username, secret, ca_cert
            FROM integrations
            WHERE id = %s
            """,
            (integration_id,),
        ).fetchone()
        conn.commit()
    return dict(row) if row else None


def count_integrations() -> int:
    """Return how many connections are saved."""

    with connect() as conn:
        row = conn.execute("SELECT count(*) AS n FROM integrations").fetchone()
        conn.commit()
    if row is None:
        return 0
    return int(row["n"])


def insert_integration(
    kind: str,
    name: str,
    base_url: str,
    username: str,
    secret: str,
    ca_cert: str,
) -> int:
    """Insert one connection and return its id."""

    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO integrations (
                kind, name, base_url, username, secret, ca_cert
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (kind, name, base_url, username, secret, ca_cert),
        ).fetchone()
        conn.commit()
    if row is None:
        raise RuntimeError("integration insert did not return an id")
    return int(row["id"])


def update_integration(
    integration_id: int,
    kind: str,
    name: str,
    base_url: str,
    username: str,
    secret: str | None,
    ca_cert: str | None,
) -> None:
    """Replace one connection. A null secret or certificate is left as saved."""

    with connect() as conn:
        current = conn.execute(
            "SELECT secret, ca_cert FROM integrations WHERE id = %s",
            (integration_id,),
        ).fetchone()
        if current is None:
            conn.commit()
            return
        conn.execute(
            """
            UPDATE integrations
            SET kind = %s, name = %s, base_url = %s, username = %s,
                secret = %s, ca_cert = %s, updated_at = now()
            WHERE id = %s
            """,
            (
                kind,
                name,
                base_url,
                username,
                current["secret"] if secret is None else secret,
                current["ca_cert"] if ca_cert is None else ca_cert,
                integration_id,
            ),
        )
        conn.commit()


def delete_integration(integration_id: int) -> None:
    """Delete one connection."""

    with connect() as conn:
        conn.execute(
            "DELETE FROM integrations WHERE id = %s",
            (integration_id,),
        )
        conn.commit()


def user_leads_a_group(user_id: int) -> bool:
    """Return whether this account leads at least one group."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT 1 AS found
            FROM group_members
            WHERE user_id = %s AND lead = true
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        conn.commit()
    return row is not None


def reset_auth_tables() -> None:
    """Delete auth rows. Used by tests so each case starts empty."""

    with connect() as conn:
        conn.execute(
            "TRUNCATE refresh_tokens, revoked_access, login_attempts, "
            "ingest_attempts, users, app_flags RESTART IDENTITY CASCADE"
        )
        conn.commit()
