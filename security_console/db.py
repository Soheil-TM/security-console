"""Postgres storage for console users, sessions, scans, and login attempts."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

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
    CREATE TABLE IF NOT EXISTS project_groups (
        id bigserial PRIMARY KEY,
        name text NOT NULL UNIQUE,
        description text NOT NULL DEFAULT '',
        created_by bigint REFERENCES users (id) ON DELETE SET NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS projects (
        id bigserial PRIMARY KEY,
        slug text NOT NULL UNIQUE,
        name text NOT NULL,
        description text NOT NULL DEFAULT '',
        created_by bigint REFERENCES users (id) ON DELETE SET NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS project_targets (
        project_id bigint NOT NULL
            REFERENCES projects (id) ON DELETE CASCADE,
        kind text NOT NULL CHECK (kind IN ('repo', 'image')),
        target text NOT NULL,
        target_key text NOT NULL,
        PRIMARY KEY (project_id, kind, target_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS project_targets_key
        ON project_targets (target_key)
    """,
    """
    CREATE TABLE IF NOT EXISTS group_projects (
        group_id bigint NOT NULL
            REFERENCES project_groups (id) ON DELETE CASCADE,
        project_id bigint NOT NULL
            REFERENCES projects (id) ON DELETE CASCADE,
        PRIMARY KEY (group_id, project_id)
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
    """
    CREATE TABLE IF NOT EXISTS scans (
        id text PRIMARY KEY,
        target text NOT NULL CHECK (target IN ('repo', 'image')),
        repo text NOT NULL DEFAULT '',
        image text NOT NULL DEFAULT '',
        project_id bigint REFERENCES projects (id) ON DELETE SET NULL,
        tools jsonb NOT NULL DEFAULT '[]'::jsonb,
        status text NOT NULL
            CHECK (status IN ('queued', 'running', 'done', 'failed')),
        phase text NOT NULL DEFAULT '',
        error text NOT NULL DEFAULT '',
        failure_reason text NOT NULL DEFAULT '',
        owner text NOT NULL DEFAULT '',
        guest text NOT NULL DEFAULT '',
        guest_ip text NOT NULL DEFAULT '',
        private boolean NOT NULL DEFAULT false,
        requested_sha text NOT NULL DEFAULT '',
        commit_sha text NOT NULL DEFAULT '',
        findings jsonb NOT NULL DEFAULT '[]'::jsonb,
        sonar jsonb,
        priority integer NOT NULL DEFAULT 0,
        created_at timestamptz NOT NULL DEFAULT now(),
        started_at timestamptz,
        finished_at timestamptz
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS scans_status_created
        ON scans (status, priority DESC, created_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_acceptances (
        id bigserial PRIMARY KEY,
        project_key text NOT NULL,
        baseline_scan_id text NOT NULL,
        current_scan_id text NOT NULL,
        commit_sha text NOT NULL DEFAULT '',
        accepted_by text NOT NULL,
        accepted_by_user_id bigint REFERENCES users (id) ON DELETE SET NULL,
        reason text NOT NULL,
        remaining_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
        baseline_severity jsonb NOT NULL DEFAULT '{}'::jsonb,
        current_severity jsonb NOT NULL DEFAULT '{}'::jsonb,
        fixed_count integer NOT NULL DEFAULT 0,
        new_count integer NOT NULL DEFAULT 0,
        remaining_count integer NOT NULL DEFAULT 0,
        created_at timestamptz NOT NULL DEFAULT now(),
        revoked_at timestamptz
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS risk_acceptances_project_time
        ON risk_acceptances (project_key, created_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS risk_acceptances_project_commit
        ON risk_acceptances (project_key, commit_sha)
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_dispositions (
        id bigserial PRIMARY KEY,
        project_key text NOT NULL,
        finding_key text NOT NULL,
        status text NOT NULL
            CHECK (status IN (
                'true_positive',
                'false_positive',
                'accepted_risk',
                'needs_review'
            )),
        reason text NOT NULL DEFAULT '',
        assignee_user_id bigint REFERENCES users (id) ON DELETE SET NULL,
        updated_by text NOT NULL DEFAULT '',
        updated_by_user_id bigint REFERENCES users (id) ON DELETE SET NULL,
        scan_id text NOT NULL DEFAULT '',
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (project_key, finding_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS finding_dispositions_project
        ON finding_dispositions (project_key)
    """,
    """
    CREATE INDEX IF NOT EXISTS finding_dispositions_assignee
        ON finding_dispositions (assignee_user_id)
        WHERE assignee_user_id IS NOT NULL
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
    """
    ALTER TABLE scans
        ADD COLUMN IF NOT EXISTS project_id bigint
        REFERENCES projects (id) ON DELETE SET NULL
    """,
    """
    CREATE INDEX IF NOT EXISTS scans_project_id
        ON scans (project_id)
    """,
    """
    ALTER TABLE risk_acceptances
        ADD COLUMN IF NOT EXISTS triage_snapshot jsonb
        NOT NULL DEFAULT '{}'::jsonb
    """,
)


def prepare_database() -> None:
    """Create tables. Scan rows may also exist as JSON files until migrated."""

    ensure_database()
    with connect() as conn:
        for statement in SCHEMA:
            conn.execute(statement)
        for statement in MIGRATIONS:
            conn.execute(statement)
        _migrate_legacy_group_projects(conn)
        conn.commit()


def _column_exists(
    conn: psycopg.Connection[dict[str, Any]],
    table: str,
    column: str,
) -> bool:
    row = conn.execute(
        """
        SELECT 1 AS found
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = %s
          AND column_name = %s
        LIMIT 1
        """,
        (table, column),
    ).fetchone()
    return row is not None


def _slugify_base(value: str) -> str:
    """Build a URL-safe slug stem from a name or target path."""

    text = value.strip().lower()
    for sep in ("/", ":", ".", "_", " "):
        text = text.replace(sep, "-")
    cleaned = "".join(ch if ch.isalnum() or ch == "-" else "" for ch in text)
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-")
    return cleaned[:60] or "project"


def _unique_slug(
    conn: psycopg.Connection[dict[str, Any]],
    base: str,
    taken: set[str],
) -> str:
    stem = _slugify_base(base)
    candidate = stem
    index = 2
    while candidate in taken:
        suffix = f"-{index}"
        candidate = (stem[: max(1, 60 - len(suffix))] + suffix).strip("-")
        index += 1
    taken.add(candidate)
    return candidate


def _migrate_legacy_group_projects(
    conn: psycopg.Connection[dict[str, Any]],
) -> None:
    """Turn legacy group_projects (key/kind/target) into projects + links."""

    if not _column_exists(conn, "group_projects", "project_key"):
        return
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT group_id, project_key, kind, target
            FROM group_projects
            ORDER BY group_id, kind, target
            """
        ).fetchall()
    ]
    existing_slugs = {
        str(row["slug"])
        for row in conn.execute("SELECT slug FROM projects").fetchall()
    }
    key_to_project: dict[str, int] = {
        str(row["target_key"]): int(row["project_id"])
        for row in conn.execute(
            "SELECT target_key, project_id FROM project_targets"
        ).fetchall()
    }
    links: set[tuple[int, int]] = set()
    for row in rows:
        target_key = str(row.get("project_key") or "")
        if not target_key:
            continue
        project_id = key_to_project.get(target_key)
        if project_id is None:
            kind = str(row.get("kind") or "repo")
            target = str(row.get("target") or "")
            leaf = target.rsplit("/", 1)[-1]
            if leaf.lower().endswith(".git"):
                leaf = leaf[:-4]
            if kind == "image":
                leaf = target.split("/")[-1] or target
            slug = _unique_slug(conn, leaf or target_key, existing_slugs)
            created = conn.execute(
                """
                INSERT INTO projects (slug, name, description)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (slug, leaf or slug, "Migrated from group attachment."),
            ).fetchone()
            if created is None:
                raise RuntimeError("project migration insert failed")
            project_id = int(created["id"])
            conn.execute(
                """
                INSERT INTO project_targets (project_id, kind, target, target_key)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (project_id, kind, target, target_key),
            )
            key_to_project[target_key] = project_id
            conn.execute(
                """
                UPDATE risk_acceptances
                SET project_key = %s
                WHERE project_key = %s
                """,
                (slug, target_key),
            )
            conn.execute(
                """
                UPDATE scans AS s
                SET project_id = %s
                WHERE s.project_id IS NULL
                  AND (
                    (s.target = 'image' AND lower('image:' || s.image) = %s)
                    OR (
                        s.target = 'repo'
                        AND lower(
                            rtrim(
                                CASE
                                    WHEN right(lower(s.repo), 4) = '.git'
                                    THEN left(s.repo, length(s.repo) - 4)
                                    ELSE s.repo
                                END,
                                '/'
                            )
                        ) = %s
                    )
                  )
                """,
                (project_id, target_key, target_key),
            )
        links.add((int(row["group_id"]), project_id))
    conn.execute(
        """
        CREATE TABLE group_projects_new (
            group_id bigint NOT NULL
                REFERENCES project_groups (id) ON DELETE CASCADE,
            project_id bigint NOT NULL
                REFERENCES projects (id) ON DELETE CASCADE,
            PRIMARY KEY (group_id, project_id)
        )
        """
    )
    for group_id, project_id in sorted(links):
        conn.execute(
            """
            INSERT INTO group_projects_new (group_id, project_id)
            VALUES (%s, %s)
            """,
            (group_id, project_id),
        )
    conn.execute("DROP TABLE group_projects")
    conn.execute("ALTER TABLE group_projects_new RENAME TO group_projects")


def _stamp(value: Any) -> str:
    """Format a timestamptz the way the scan API has always returned times."""

    if value is None:
        return ""
    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    text = str(value).strip()
    return text


def _parse_stamp(value: Any) -> datetime | None:
    """Parse the console's UTC stamp, or an ISO timestamptz string."""

    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(" UTC"):
        text = text[: -len(" UTC")]
        try:
            return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


_SCAN_SELECT = """
    SELECT s.id, s.target, s.repo, s.image, s.project_id, s.tools, s.status,
           s.phase, s.error, s.failure_reason, s.owner, s.guest, s.guest_ip,
           s.private, s.requested_sha, s.commit_sha, s.findings, s.sonar,
           s.priority, s.created_at, s.started_at, s.finished_at,
           p.slug AS project_slug, p.name AS project_name
    FROM scans AS s
    LEFT JOIN projects AS p ON p.id = s.project_id
"""


def scan_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """Turn a scans table row into the in-memory scan dict the API uses."""

    tools = row.get("tools") or []
    if isinstance(tools, str):
        tools = json.loads(tools)
    findings = row.get("findings") or []
    if isinstance(findings, str):
        findings = json.loads(findings)
    sonar = row.get("sonar")
    if isinstance(sonar, str):
        sonar = json.loads(sonar)
    item: dict[str, Any] = {
        "id": str(row["id"]),
        "target": str(row.get("target") or "repo"),
        "repo": str(row.get("repo") or ""),
        "image": str(row.get("image") or ""),
        "tools": list(tools),
        "status": str(row.get("status") or ""),
        "phase": str(row.get("phase") or ""),
        "error": str(row.get("error") or ""),
        "failure_reason": str(row.get("failure_reason") or ""),
        "owner": str(row.get("owner") or ""),
        "requested_sha": str(row.get("requested_sha") or ""),
        "commit_sha": str(row.get("commit_sha") or ""),
        "findings": list(findings),
        "sonar": sonar,
        "priority": int(row.get("priority") or 0),
        "created_at": _stamp(row.get("created_at")),
        "finished_at": _stamp(row.get("finished_at")),
        "started_at": _stamp(row.get("started_at")),
    }
    project_id = row.get("project_id")
    if project_id is not None:
        item["project_id"] = int(project_id)
    slug = str(row.get("project_slug") or "")
    if slug:
        item["project_slug"] = slug
        item["project_name"] = str(row.get("project_name") or slug)
    guest = str(row.get("guest") or "")
    if guest:
        item["guest"] = guest
        item["guest_ip"] = str(row.get("guest_ip") or "")
        item["private"] = bool(row.get("private"))
    return item


def list_scan_rows() -> list[dict[str, Any]]:
    """Return every stored scan as API dicts, newest first."""

    with connect() as conn:
        rows = conn.execute(
            _SCAN_SELECT + " ORDER BY s.created_at DESC"
        ).fetchall()
        conn.commit()
    return [scan_from_row(dict(row)) for row in rows]


def get_scan_row(scan_id: str) -> dict[str, Any] | None:
    """Return one scan, or None."""

    with connect() as conn:
        row = conn.execute(
            _SCAN_SELECT + " WHERE s.id = %s",
            (scan_id,),
        ).fetchone()
        conn.commit()
    return scan_from_row(dict(row)) if row else None


def count_queued_scans() -> int:
    """Return how many scans are waiting to run."""

    with connect() as conn:
        row = conn.execute(
            "SELECT count(*) AS n FROM scans WHERE status = 'queued'"
        ).fetchone()
        conn.commit()
    if row is None:
        return 0
    return int(row["n"])


def upsert_scan(item: dict[str, Any]) -> None:
    """Insert or replace one scan row from an API-shaped dict."""

    created = _parse_stamp(item.get("created_at")) or datetime.now(UTC)
    started = _parse_stamp(item.get("started_at"))
    finished = _parse_stamp(item.get("finished_at"))
    project_id = item.get("project_id")
    project_value = int(project_id) if project_id is not None else None
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (
                id, target, repo, image, project_id, tools, status, phase, error,
                failure_reason, owner, guest, guest_ip, private,
                requested_sha, commit_sha, findings, sonar, priority,
                created_at, started_at, finished_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s
            )
            ON CONFLICT (id) DO UPDATE SET
                target = EXCLUDED.target,
                repo = EXCLUDED.repo,
                image = EXCLUDED.image,
                project_id = EXCLUDED.project_id,
                tools = EXCLUDED.tools,
                status = EXCLUDED.status,
                phase = EXCLUDED.phase,
                error = EXCLUDED.error,
                failure_reason = EXCLUDED.failure_reason,
                owner = EXCLUDED.owner,
                guest = EXCLUDED.guest,
                guest_ip = EXCLUDED.guest_ip,
                private = EXCLUDED.private,
                requested_sha = EXCLUDED.requested_sha,
                commit_sha = EXCLUDED.commit_sha,
                findings = EXCLUDED.findings,
                sonar = EXCLUDED.sonar,
                priority = EXCLUDED.priority,
                created_at = EXCLUDED.created_at,
                started_at = EXCLUDED.started_at,
                finished_at = EXCLUDED.finished_at
            """,
            (
                str(item["id"]),
                str(item.get("target") or "repo"),
                str(item.get("repo") or ""),
                str(item.get("image") or ""),
                project_value,
                Jsonb(list(item.get("tools") or [])),
                str(item.get("status") or "queued"),
                str(item.get("phase") or ""),
                str(item.get("error") or ""),
                str(item.get("failure_reason") or ""),
                str(item.get("owner") or ""),
                str(item.get("guest") or ""),
                str(item.get("guest_ip") or ""),
                bool(item.get("private")),
                str(item.get("requested_sha") or ""),
                str(item.get("commit_sha") or ""),
                Jsonb(list(item.get("findings") or [])),
                Jsonb(item["sonar"]) if item.get("sonar") is not None else None,
                int(item.get("priority") or 0),
                created,
                started,
                finished,
            ),
        )
        conn.commit()


def delete_scan_row(scan_id: str) -> None:
    """Remove one scan row."""

    with connect() as conn:
        conn.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
        conn.commit()


def claim_next_queued() -> dict[str, Any] | None:
    """Mark the oldest queued scan as running when none is already running."""

    with connect() as conn:
        busy = conn.execute(
            "SELECT 1 AS found FROM scans WHERE status = 'running' LIMIT 1"
        ).fetchone()
        if busy is not None:
            conn.commit()
            return None
        row = conn.execute(
            """
            SELECT id FROM scans
            WHERE status = 'queued'
            ORDER BY priority DESC, created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        scan_id = str(row["id"])
        updated = conn.execute(
            """
            UPDATE scans
            SET status = 'running',
                started_at = now(),
                phase = CASE
                    WHEN target = 'image' THEN 'Trivy'
                    ELSE 'clone'
                END
            WHERE id = %s
            RETURNING id
            """,
            (scan_id,),
        ).fetchone()
        conn.commit()
    if updated is None:
        return None
    return get_scan_row(str(updated["id"]))


def fail_running_scans(message: str) -> list[str]:
    """Mark every running scan failed. Used when the console restarts."""

    with connect() as conn:
        rows = conn.execute(
            """
            UPDATE scans
            SET status = 'failed',
                phase = '',
                error = %s,
                finished_at = now()
            WHERE status = 'running'
            RETURNING id
            """,
            (message[:2000],),
        ).fetchall()
        conn.commit()
    return [str(row["id"]) for row in rows]


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
    """Return project slugs and target keys this account may access.

    Slugs identify first-class projects. Target keys keep legacy scan matching
    and GitLab/registry filters working against concrete repo/image refs.
    """

    with connect() as conn:
        slug_rows = conn.execute(
            """
            SELECT DISTINCT pr.slug
            FROM group_projects AS gp
            JOIN group_members AS m ON m.group_id = gp.group_id
            JOIN projects AS pr ON pr.id = gp.project_id
            WHERE m.user_id = %s
            """,
            (user_id,),
        ).fetchall()
        target_rows = conn.execute(
            """
            SELECT DISTINCT t.target_key
            FROM group_projects AS gp
            JOIN group_members AS m ON m.group_id = gp.group_id
            JOIN project_targets AS t ON t.project_id = gp.project_id
            WHERE m.user_id = %s
            """,
            (user_id,),
        ).fetchall()
        conn.commit()
    keys = {str(row["slug"]) for row in slug_rows}
    keys.update(str(row["target_key"]) for row in target_rows)
    return keys


def user_project_slugs(user_id: int) -> set[str]:
    """Return only the project slugs this account can see via groups."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT pr.slug
            FROM group_projects AS gp
            JOIN group_members AS m ON m.group_id = gp.group_id
            JOIN projects AS pr ON pr.id = gp.project_id
            WHERE m.user_id = %s
            """,
            (user_id,),
        ).fetchall()
        conn.commit()
    return {str(row["slug"]) for row in rows}


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
        SELECT pr.id, pr.slug, pr.name, pr.description
        FROM group_projects AS gp
        JOIN projects AS pr ON pr.id = gp.project_id
        WHERE gp.group_id = %s
        ORDER BY pr.name
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
    project_ids: list[int],
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
        _write_group_children(conn, group_id, project_ids, members)
        _write_group_event(conn, group_id, actor, "created", detail)
        conn.commit()
    return group_id


def update_group(
    group_id: int,
    name: str,
    description: str,
    project_ids: list[int],
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
        _write_group_children(conn, group_id, project_ids, members)
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
    project_ids: list[int],
    members: list[tuple[int, bool]],
) -> None:
    for project_id in project_ids:
        conn.execute(
            """
            INSERT INTO group_projects (group_id, project_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (group_id, int(project_id)),
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


def user_leads_project(user_id: int, project_key: str) -> bool:
    """Return whether this account leads a group that owns the project slug."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT 1 AS found
            FROM group_members AS m
            JOIN group_projects AS gp ON gp.group_id = m.group_id
            JOIN projects AS pr ON pr.id = gp.project_id
            WHERE m.user_id = %s AND m.lead = true AND pr.slug = %s
            LIMIT 1
            """,
            (user_id, project_key),
        ).fetchone()
        conn.commit()
    return row is not None


def user_leads_any_of_groups(user_id: int, group_ids: list[int]) -> bool:
    """Return whether the user leads at least one of the given groups."""

    if not group_ids:
        return False
    with connect() as conn:
        row = conn.execute(
            """
            SELECT 1 AS found
            FROM group_members
            WHERE user_id = %s AND lead = true AND group_id = ANY(%s)
            LIMIT 1
            """,
            (user_id, group_ids),
        ).fetchone()
        conn.commit()
    return row is not None


def _project_from_row(
    row: dict[str, Any],
    targets: list[dict[str, Any]],
    group_ids: list[int] | None = None,
) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "slug": str(row["slug"]),
        "name": str(row["name"]),
        "description": str(row.get("description") or ""),
        "created_by": row.get("created_by"),
        "created_at": _stamp(row.get("created_at")),
        "targets": [
            {
                "kind": str(item["kind"]),
                "target": str(item["target"]),
                "key": str(item["target_key"]),
            }
            for item in targets
        ],
        "group_ids": list(group_ids or []),
    }


def _load_project(
    conn: psycopg.Connection[dict[str, Any]],
    project_id: int,
) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, slug, name, description, created_by, created_at
        FROM projects
        WHERE id = %s
        """,
        (project_id,),
    ).fetchone()
    if row is None:
        return None
    targets = conn.execute(
        """
        SELECT kind, target, target_key
        FROM project_targets
        WHERE project_id = %s
        ORDER BY kind, target
        """,
        (project_id,),
    ).fetchall()
    groups = conn.execute(
        """
        SELECT group_id
        FROM group_projects
        WHERE project_id = %s
        ORDER BY group_id
        """,
        (project_id,),
    ).fetchall()
    return _project_from_row(
        dict(row),
        [dict(item) for item in targets],
        [int(item["group_id"]) for item in groups],
    )


def list_projects(user_id: int | None) -> list[dict[str, Any]]:
    """Return every project, or only those linked to the user's groups."""

    with connect() as conn:
        if user_id is None:
            rows = conn.execute(
                """
                SELECT id FROM projects ORDER BY name
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT DISTINCT pr.id
                FROM projects AS pr
                JOIN group_projects AS gp ON gp.project_id = pr.id
                JOIN group_members AS m ON m.group_id = gp.group_id
                WHERE m.user_id = %s
                ORDER BY pr.id
                """,
                (user_id,),
            ).fetchall()
        loaded = [
            project
            for row in rows
            if (project := _load_project(conn, int(row["id"]))) is not None
        ]
        loaded.sort(key=lambda item: str(item.get("name") or "").lower())
        conn.commit()
    return loaded


def get_project_by_slug(slug: str) -> dict[str, Any] | None:
    """Return one project by slug, or None."""

    with connect() as conn:
        row = conn.execute(
            "SELECT id FROM projects WHERE slug = %s",
            (slug,),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        loaded = _load_project(conn, int(row["id"]))
        conn.commit()
    return loaded


def get_project_by_id(project_id: int) -> dict[str, Any] | None:
    """Return one project by id, or None."""

    with connect() as conn:
        loaded = _load_project(conn, project_id)
        conn.commit()
    return loaded


def projects_by_slugs(slugs: list[str]) -> list[dict[str, Any]]:
    """Return projects whose slugs are in the list."""

    if not slugs:
        return []
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id FROM projects WHERE slug = ANY(%s)
            """,
            (slugs,),
        ).fetchall()
        loaded = [
            project
            for row in rows
            if (project := _load_project(conn, int(row["id"]))) is not None
        ]
        conn.commit()
    return loaded


def insert_project(
    *,
    slug: str,
    name: str,
    description: str,
    created_by: int,
    targets: list[dict[str, str]],
    group_ids: list[int],
) -> dict[str, Any]:
    """Create a project with targets and group links."""

    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO projects (slug, name, description, created_by)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (slug, name, description, created_by),
        ).fetchone()
        if row is None:
            raise RuntimeError("project insert did not return an id")
        project_id = int(row["id"])
        _write_project_children(conn, project_id, targets, group_ids)
        loaded = _load_project(conn, project_id)
        conn.commit()
    if loaded is None:
        raise RuntimeError("project insert could not be reloaded")
    return loaded


def update_project(
    project_id: int,
    *,
    slug: str,
    name: str,
    description: str,
    targets: list[dict[str, str]],
    group_ids: list[int],
) -> dict[str, Any] | None:
    """Replace a project's fields, targets, and group links."""

    with connect() as conn:
        conn.execute(
            """
            UPDATE projects
            SET slug = %s, name = %s, description = %s
            WHERE id = %s
            """,
            (slug, name, description, project_id),
        )
        conn.execute(
            "DELETE FROM project_targets WHERE project_id = %s",
            (project_id,),
        )
        conn.execute(
            "DELETE FROM group_projects WHERE project_id = %s",
            (project_id,),
        )
        _write_project_children(conn, project_id, targets, group_ids)
        loaded = _load_project(conn, project_id)
        conn.commit()
    return loaded


def delete_project(project_id: int) -> None:
    """Delete a project. Group links and targets go with it."""

    with connect() as conn:
        conn.execute("DELETE FROM projects WHERE id = %s", (project_id,))
        conn.commit()


def _write_project_children(
    conn: psycopg.Connection[dict[str, Any]],
    project_id: int,
    targets: list[dict[str, str]],
    group_ids: list[int],
) -> None:
    for item in targets:
        conn.execute(
            """
            INSERT INTO project_targets (project_id, kind, target, target_key)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (
                project_id,
                item["kind"],
                item["target"],
                item["key"],
            ),
        )
    for group_id in group_ids:
        conn.execute(
            """
            INSERT INTO group_projects (group_id, project_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (int(group_id), project_id),
        )


def project_match_keys(project: dict[str, Any]) -> set[str]:
    """Slug plus every target key that belongs to this project."""

    keys = {str(project.get("slug") or "")}
    for item in project.get("targets") or []:
        key = str(item.get("key") or "")
        if key:
            keys.add(key)
    return {key for key in keys if key}


_ACCEPTANCE_SELECT = """
    SELECT id, project_key, baseline_scan_id, current_scan_id,
           commit_sha, accepted_by, reason, remaining_keys,
           baseline_severity, current_severity,
           fixed_count, new_count, remaining_count,
           triage_snapshot, created_at, revoked_at
    FROM risk_acceptances
"""


def _acceptance_from_row(row: dict[str, Any]) -> dict[str, Any]:
    remaining = row.get("remaining_keys") or []
    if isinstance(remaining, str):
        remaining = json.loads(remaining)
    baseline_severity = row.get("baseline_severity") or {}
    if isinstance(baseline_severity, str):
        baseline_severity = json.loads(baseline_severity)
    current_severity = row.get("current_severity") or {}
    if isinstance(current_severity, str):
        current_severity = json.loads(current_severity)
    snapshot = row.get("triage_snapshot") or {}
    if isinstance(snapshot, str):
        snapshot = json.loads(snapshot)
    return {
        "id": int(row["id"]),
        "project_key": str(row.get("project_key") or ""),
        "baseline_scan_id": str(row.get("baseline_scan_id") or ""),
        "current_scan_id": str(row.get("current_scan_id") or ""),
        "commit_sha": str(row.get("commit_sha") or ""),
        "accepted_by": str(row.get("accepted_by") or ""),
        "reason": str(row.get("reason") or ""),
        "remaining_keys": list(remaining),
        "baseline_severity": dict(baseline_severity),
        "current_severity": dict(current_severity),
        "fixed_count": int(row.get("fixed_count") or 0),
        "new_count": int(row.get("new_count") or 0),
        "remaining_count": int(row.get("remaining_count") or 0),
        "triage_snapshot": dict(snapshot) if isinstance(snapshot, dict) else {},
        "created_at": _stamp(row.get("created_at")),
        "revoked_at": _stamp(row.get("revoked_at")),
        "active": row.get("revoked_at") is None,
    }


def insert_risk_acceptance(
    *,
    project_key: str,
    baseline_scan_id: str,
    current_scan_id: str,
    commit_sha: str,
    accepted_by: str,
    accepted_by_user_id: int,
    reason: str,
    remaining_keys: list[str],
    baseline_severity: dict[str, int],
    current_severity: dict[str, int],
    fixed_count: int,
    new_count: int,
    remaining_count: int,
    triage_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store one risk acceptance and return it."""

    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO risk_acceptances (
                project_key, baseline_scan_id, current_scan_id, commit_sha,
                accepted_by, accepted_by_user_id, reason, remaining_keys,
                baseline_severity, current_severity,
                fixed_count, new_count, remaining_count, triage_snapshot
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s
            )
            RETURNING id, project_key, baseline_scan_id, current_scan_id,
                      commit_sha, accepted_by, reason, remaining_keys,
                      baseline_severity, current_severity,
                      fixed_count, new_count, remaining_count,
                      triage_snapshot, created_at, revoked_at
            """,
            (
                project_key,
                baseline_scan_id,
                current_scan_id,
                commit_sha,
                accepted_by,
                accepted_by_user_id,
                reason,
                Jsonb(remaining_keys),
                Jsonb(baseline_severity),
                Jsonb(current_severity),
                fixed_count,
                new_count,
                remaining_count,
                Jsonb(triage_snapshot or {}),
            ),
        ).fetchone()
        conn.commit()
    if row is None:
        raise RuntimeError("risk acceptance insert did not return a row")
    return _acceptance_from_row(dict(row))


def list_risk_acceptances(project_key: str, *, limit: int = 20) -> list[dict[str, Any]]:
    """Return recent acceptances for one project, newest first."""

    with connect() as conn:
        rows = conn.execute(
            _ACCEPTANCE_SELECT
            + """
            WHERE project_key = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (project_key, max(1, min(limit, 100))),
        ).fetchall()
        conn.commit()
    return [_acceptance_from_row(dict(row)) for row in rows]


def latest_active_acceptance(
    project_key: str, *, commit_sha: str = ""
) -> dict[str, Any] | None:
    """Return the newest non-revoked acceptance, optionally for one commit."""

    with connect() as conn:
        if commit_sha:
            row = conn.execute(
                _ACCEPTANCE_SELECT
                + """
                WHERE project_key = %s
                  AND revoked_at IS NULL
                  AND lower(commit_sha) = lower(%s)
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (project_key, commit_sha),
            ).fetchone()
        else:
            row = conn.execute(
                _ACCEPTANCE_SELECT
                + """
                WHERE project_key = %s AND revoked_at IS NULL
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (project_key,),
            ).fetchone()
        conn.commit()
    return _acceptance_from_row(dict(row)) if row else None


def revoke_risk_acceptance(acceptance_id: int) -> None:
    """Mark one acceptance as revoked."""

    with connect() as conn:
        conn.execute(
            """
            UPDATE risk_acceptances
            SET revoked_at = now()
            WHERE id = %s AND revoked_at IS NULL
            """,
            (acceptance_id,),
        )
        conn.commit()


def _disposition_from_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "project_key": str(row.get("project_key") or ""),
        "finding_key": str(row.get("finding_key") or ""),
        "status": str(row.get("status") or ""),
        "reason": str(row.get("reason") or ""),
        "assignee_user_id": (
            int(row["assignee_user_id"])
            if row.get("assignee_user_id") is not None
            else None
        ),
        "assignee_username": str(row.get("assignee_username") or ""),
        "updated_by": str(row.get("updated_by") or ""),
        "updated_by_user_id": (
            int(row["updated_by_user_id"])
            if row.get("updated_by_user_id") is not None
            else None
        ),
        "scan_id": str(row.get("scan_id") or ""),
        "created_at": _stamp(row.get("created_at")),
        "updated_at": _stamp(row.get("updated_at")),
    }


def list_dispositions(project_key: str) -> dict[str, dict[str, Any]]:
    """Return dispositions for one project keyed by finding_key."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT d.id, d.project_key, d.finding_key, d.status, d.reason,
                   d.assignee_user_id, d.updated_by, d.updated_by_user_id,
                   d.scan_id, d.created_at, d.updated_at,
                   u.username AS assignee_username
            FROM finding_dispositions AS d
            LEFT JOIN users AS u ON u.id = d.assignee_user_id
            WHERE d.project_key = %s
            """,
            (project_key,),
        ).fetchall()
        conn.commit()
    return {
        str(row["finding_key"]): _disposition_from_row(dict(row)) for row in rows
    }


def upsert_disposition(
    *,
    project_key: str,
    finding_key: str,
    status: str,
    reason: str,
    assignee_user_id: int | None,
    updated_by: str,
    updated_by_user_id: int,
    scan_id: str,
) -> dict[str, Any]:
    """Insert or replace one finding disposition."""

    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO finding_dispositions (
                project_key, finding_key, status, reason, assignee_user_id,
                updated_by, updated_by_user_id, scan_id, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (project_key, finding_key) DO UPDATE SET
                status = EXCLUDED.status,
                reason = EXCLUDED.reason,
                assignee_user_id = EXCLUDED.assignee_user_id,
                updated_by = EXCLUDED.updated_by,
                updated_by_user_id = EXCLUDED.updated_by_user_id,
                scan_id = EXCLUDED.scan_id,
                updated_at = now()
            RETURNING id, project_key, finding_key, status, reason,
                      assignee_user_id, updated_by, updated_by_user_id,
                      scan_id, created_at, updated_at
            """,
            (
                project_key,
                finding_key,
                status,
                reason,
                assignee_user_id,
                updated_by,
                updated_by_user_id,
                scan_id,
            ),
        ).fetchone()
        username = ""
        if row is not None and row.get("assignee_user_id") is not None:
            user = conn.execute(
                "SELECT username FROM users WHERE id = %s",
                (int(row["assignee_user_id"]),),
            ).fetchone()
            if user is not None:
                username = str(user["username"] or "")
        conn.commit()
    if row is None:
        raise RuntimeError("disposition upsert did not return a row")
    loaded = dict(row)
    loaded["assignee_username"] = username
    return _disposition_from_row(loaded)


def list_project_assignees(project_key: str) -> list[dict[str, Any]]:
    """Return distinct members of groups that own this project slug."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT u.id, u.username, u.first_name, u.last_name, u.role
            FROM projects AS pr
            JOIN group_projects AS gp ON gp.project_id = pr.id
            JOIN group_members AS m ON m.group_id = gp.group_id
            JOIN users AS u ON u.id = m.user_id
            WHERE pr.slug = %s AND u.disabled = false
            ORDER BY u.username
            """,
            (project_key,),
        ).fetchall()
        conn.commit()
    return [
        {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "first_name": str(row.get("first_name") or ""),
            "last_name": str(row.get("last_name") or ""),
            "role": str(row.get("role") or ""),
        }
        for row in rows
    ]


def list_my_assignments(user_id: int) -> list[dict[str, Any]]:
    """Return open TP / Needs Review dispositions assigned to this user."""

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT d.id, d.project_key, d.finding_key, d.status, d.reason,
                   d.assignee_user_id, d.updated_by, d.updated_by_user_id,
                   d.scan_id, d.created_at, d.updated_at,
                   u.username AS assignee_username
            FROM finding_dispositions AS d
            LEFT JOIN users AS u ON u.id = d.assignee_user_id
            WHERE d.assignee_user_id = %s
              AND d.status IN ('true_positive', 'needs_review')
            ORDER BY d.updated_at DESC
            LIMIT 100
            """,
            (user_id,),
        ).fetchall()
        conn.commit()
    return [_disposition_from_row(dict(row)) for row in rows]


def user_in_project_groups(user_id: int, project_key: str) -> bool:
    """Return whether the user is a member of a group that owns the project."""

    with connect() as conn:
        row = conn.execute(
            """
            SELECT 1 AS found
            FROM projects AS pr
            JOIN group_projects AS gp ON gp.project_id = pr.id
            JOIN group_members AS m ON m.group_id = gp.group_id
            WHERE pr.slug = %s AND m.user_id = %s
            LIMIT 1
            """,
            (project_key, user_id),
        ).fetchone()
        conn.commit()
    return row is not None


def reset_auth_tables() -> None:
    """Delete auth rows. Used by tests so each case starts empty."""

    with connect() as conn:
        conn.execute(
            "TRUNCATE refresh_tokens, revoked_access, login_attempts, "
            "users, app_flags RESTART IDENTITY CASCADE"
        )
        conn.commit()


def reset_scan_table() -> None:
    """Delete scan rows. Used by queue tests."""

    with connect() as conn:
        conn.execute("TRUNCATE scans")
        conn.commit()
