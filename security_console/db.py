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
        allow_trivy boolean NOT NULL DEFAULT true,
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
        app_host=os.environ.get("CONSOLE_DB_HOST", "sonarqube_db"),
        app_user=os.environ.get("CONSOLE_DB_USER", "console"),
        app_password=read_secret(
            "CONSOLE_DB_PASSWORD",
            "CONSOLE_DB_PASSWORD_FILE",
        ),
        app_name=os.environ.get("CONSOLE_DB_NAME", "security_console_db"),
        bootstrap_host=os.environ.get("CONSOLE_DB_HOST", "sonarqube_db"),
        bootstrap_user=os.environ.get("CONSOLE_DB_BOOTSTRAP_USER", "sonar"),
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

    The SonarQube Postgres superuser is used only for this step. The running
    console then connects as the limited ``console`` role.
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
        ADD COLUMN IF NOT EXISTS idle_timeout_minutes integer
        NOT NULL DEFAULT 15
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
) -> int:
    """Insert one account and return its id."""

    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO users (
                username, email, password_hash, role,
                allow_semgrep, allow_checkov, allow_sonar, allow_trivy,
                must_change_password
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                must_change_password,
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
            SELECT id, username, email, password_hash, role, disabled,
                   allow_semgrep, allow_checkov, allow_sonar, allow_trivy,
                   must_change_password, session_version, idle_timeout_minutes
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
            SELECT id, username, email, role, disabled,
                   allow_semgrep, allow_checkov, allow_sonar,
                   allow_trivy, must_change_password, session_version,
                   idle_timeout_minutes, created_at
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
            SELECT id, username, email, role, disabled,
                   allow_semgrep, allow_checkov, allow_sonar,
                   allow_trivy, created_at
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
) -> None:
    """Replace the editable fields of one account."""

    with connect() as conn:
        if password_hash is None:
            conn.execute(
                """
                UPDATE users
                SET username = %s, email = %s, role = %s, disabled = %s,
                    allow_semgrep = %s, allow_checkov = %s,
                    allow_sonar = %s, allow_trivy = %s
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
                    password_hash = %s,
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
                    password_hash,
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


def reset_auth_tables() -> None:
    """Delete auth rows. Used by tests so each case starts empty."""

    with connect() as conn:
        conn.execute(
            "TRUNCATE refresh_tokens, revoked_access, login_attempts, "
            "ingest_attempts, users, app_flags RESTART IDENTITY CASCADE"
        )
        conn.commit()
