"""SQLite storage for the CyberRescue Core (stdlib ``sqlite3`` only).

One file (``cyberrescue.db`` at the repo root by default, gitignored; override
with ``CYBERRESCUE_DB_PATH``). Tests use ``tmp_path`` or ``":memory:"``.

Design notes:
  * Foreign keys ON, WAL journal, busy timeout — safe for a single writer now,
    and for a few processes later (Phase 1b).
  * ``audit_events`` and ``event_links`` are append-only: SQLite triggers abort
    any UPDATE/DELETE. Mutable domain fields (incident status, veto status,
    approval consumption, ...) are always changed together with a new audit
    event, in one transaction (see ``store.py``).
  * Autocommit connection + explicit ``transaction()`` (BEGIN IMMEDIATE, or a
    SAVEPOINT when nested) so a domain row and its audit event commit or roll
    back together.
"""

from __future__ import annotations

import itertools
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[2]

TABLES = (
    "schema_meta", "actors", "assets", "incidents", "incident_aliases",
    "audit_events", "event_links", "evidence", "findings", "signoffs",
    "vetoes", "legal_holds", "action_requests", "policy_decisions",
    "approvals", "risk_snapshots",
)

_DDL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actors (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('agent', 'human', 'system')),
    role         TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    external_ref TEXT UNIQUE,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id        TEXT PRIMARY KEY,
    hostname        TEXT,
    role            TEXT,
    criticality     TEXT NOT NULL,
    network_segment TEXT,
    data_classes    TEXT NOT NULL DEFAULT '[]',
    provenance      TEXT NOT NULL DEFAULT 'simulated',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id               TEXT PRIMARY KEY,
    title            TEXT NOT NULL DEFAULT '',
    category         TEXT,
    severity         TEXT,
    status           TEXT NOT NULL,
    primary_asset_id TEXT REFERENCES assets(asset_id),
    recruited_roles  TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    closed_at        TEXT
);

CREATE TABLE IF NOT EXISTS incident_aliases (
    alias       TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    created_at  TEXT NOT NULL
);

-- The audit log. chain = incident_id, or '__system__' for events that belong
-- to no incident (actor registration, asset seeding).
CREATE TABLE IF NOT EXISTS audit_events (
    uid            TEXT PRIMARY KEY,
    chain          TEXT NOT NULL,
    incident_id    TEXT REFERENCES incidents(id),
    seq            INTEGER NOT NULL,
    ts             TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    actor_id       TEXT REFERENCES actors(id),
    source         TEXT NOT NULL,
    external_id    TEXT,
    protocol_type  TEXT,
    protocol_valid INTEGER,
    payload        TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL,
    UNIQUE (chain, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_external
    ON audit_events(source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_audit_incident ON audit_events(incident_id, seq);
CREATE INDEX IF NOT EXISTS ix_audit_type ON audit_events(event_type);

CREATE TABLE IF NOT EXISTS event_links (
    from_uid TEXT NOT NULL REFERENCES audit_events(uid),
    to_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    relation TEXT NOT NULL,
    PRIMARY KEY (from_uid, to_uid, relation)
);
CREATE INDEX IF NOT EXISTS ix_links_to ON event_links(to_uid);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS event_links_no_update
BEFORE UPDATE ON event_links
BEGIN SELECT RAISE(ABORT, 'event_links is append-only'); END;
CREATE TRIGGER IF NOT EXISTS event_links_no_delete
BEFORE DELETE ON event_links
BEGIN SELECT RAISE(ABORT, 'event_links is append-only'); END;

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    incident_id     TEXT NOT NULL REFERENCES incidents(id),
    author_actor_id TEXT REFERENCES actors(id),
    severity        TEXT,
    summary         TEXT NOT NULL DEFAULT '',
    event_uid       TEXT NOT NULL REFERENCES audit_events(uid),
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    finding_id  TEXT REFERENCES findings(id),
    kind        TEXT NOT NULL,
    content     TEXT NOT NULL,
    event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signoffs (
    id                TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES incidents(id),
    actor_id          TEXT NOT NULL REFERENCES actors(id),
    request_event_uid TEXT REFERENCES audit_events(uid),
    covered_actions   TEXT NOT NULL DEFAULT '[]',
    event_uid         TEXT NOT NULL REFERENCES audit_events(uid),
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vetoes (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    actor_id    TEXT NOT NULL REFERENCES actors(id),
    action      TEXT,
    asset_id    TEXT REFERENCES assets(asset_id),
    regulation  TEXT,
    reason      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL CHECK (status IN ('active', 'overridden', 'withdrawn')),
    event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_vetoes_incident ON vetoes(incident_id, status);

CREATE TABLE IF NOT EXISTS legal_holds (
    id                           TEXT PRIMARY KEY,
    asset_id                     TEXT NOT NULL REFERENCES assets(asset_id),
    incident_id                  TEXT REFERENCES incidents(id),
    rule_ids                     TEXT NOT NULL DEFAULT '[]',
    requires_human_authorization INTEGER NOT NULL DEFAULT 0,
    status                       TEXT NOT NULL CHECK (status IN ('active', 'released')),
    event_uid                    TEXT NOT NULL REFERENCES audit_events(uid),
    created_at                   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_holds_asset ON legal_holds(asset_id, status);

CREATE TABLE IF NOT EXISTS action_requests (
    id           TEXT PRIMARY KEY,
    incident_id  TEXT NOT NULL REFERENCES incidents(id),
    action       TEXT NOT NULL,
    asset_id     TEXT REFERENCES assets(asset_id),
    params       TEXT NOT NULL DEFAULT '{}',
    tier         INTEGER NOT NULL,
    requested_by TEXT REFERENCES actors(id),
    status       TEXT NOT NULL,
    event_uid    TEXT NOT NULL REFERENCES audit_events(uid),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_requests_incident ON action_requests(incident_id, status);

CREATE TABLE IF NOT EXISTS approvals (
    id                     TEXT PRIMARY KEY,
    incident_id            TEXT NOT NULL REFERENCES incidents(id),
    action                 TEXT NOT NULL,
    asset_id               TEXT REFERENCES assets(asset_id),
    approver_actor_id      TEXT NOT NULL REFERENCES actors(id),
    decision               TEXT NOT NULL CHECK (decision IN ('approve', 'deny')),
    overrides_hold         INTEGER NOT NULL DEFAULT 0,
    overrides_veto         INTEGER NOT NULL DEFAULT 0,
    reason                 TEXT NOT NULL DEFAULT '',
    expires_at             TEXT NOT NULL,
    consumed_by_request_id TEXT REFERENCES action_requests(id),
    consumed_at            TEXT,
    event_uid              TEXT NOT NULL REFERENCES audit_events(uid),
    created_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_approvals_scope ON approvals(incident_id, action, asset_id);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id                TEXT PRIMARY KEY,
    action_request_id TEXT NOT NULL REFERENCES action_requests(id),
    incident_id       TEXT NOT NULL REFERENCES incidents(id),
    outcome           TEXT NOT NULL CHECK (outcome IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')),
    rule_results      TEXT NOT NULL DEFAULT '[]',
    approval_id       TEXT REFERENCES approvals(id),
    policy_version    TEXT NOT NULL,
    snapshot_hash     TEXT NOT NULL,
    event_uid         TEXT NOT NULL REFERENCES audit_events(uid),
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_decisions_request ON policy_decisions(action_request_id);

CREATE TABLE IF NOT EXISTS risk_snapshots (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    level       TEXT NOT NULL,
    score       REAL,
    factors     TEXT NOT NULL DEFAULT '{}',
    method      TEXT NOT NULL,
    event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at  TEXT NOT NULL
);
"""


def default_db_path() -> Path:
    """``$CYBERRESCUE_DB_PATH`` if set, else ``<repo>/cyberrescue.db``."""
    env = os.getenv("CYBERRESCUE_DB_PATH")
    return Path(env) if env else REPO_ROOT / "cyberrescue.db"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open (and initialise) a Core database. ``":memory:"`` is supported."""
    target = str(path) if path is not None else str(default_db_path())
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, isolation_level=None)  # autocommit; we BEGIN explicitly
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    if target != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create all tables/indexes/triggers (idempotent) and record the version."""
    conn.executescript(_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )


def schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    return int(row["value"]) if row else 0


_savepoint_ids = itertools.count(1)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """All-or-nothing block. Nested calls use a SAVEPOINT."""
    if conn.in_transaction:
        name = f"sp_{next(_savepoint_ids)}"
        conn.execute(f"SAVEPOINT {name}")
        try:
            yield conn
        except BaseException:
            conn.execute(f"ROLLBACK TO {name}")
            conn.execute(f"RELEASE {name}")
            raise
        conn.execute(f"RELEASE {name}")
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
