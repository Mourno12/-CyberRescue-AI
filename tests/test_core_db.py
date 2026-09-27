"""CyberRescue Core — SQLite schema (cyberrescue/core/db.py)."""

import sqlite3

import pytest

from cyberrescue.core import db


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "core.db")
    yield c
    c.close()


def _insert_event(conn, uid="e1", seq=1):
    conn.execute(
        "INSERT INTO audit_events(uid, chain, incident_id, seq, ts, event_type, "
        "source, payload, prev_hash, hash) VALUES (?, '__system__', NULL, ?, "
        "'2026-01-01T00:00:00+00:00', 'TEST', 'test', '{}', 'p', 'h')",
        (uid, seq),
    )


def test_schema_creates_every_table_and_is_idempotent(conn):
    names = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert set(db.TABLES) <= names
    db.init_schema(conn)  # second run must not fail or duplicate
    assert conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0] == 1


def test_schema_version_recorded(conn):
    assert db.schema_version(conn) == db.SCHEMA_VERSION


def test_foreign_keys_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO incident_aliases(alias, incident_id, created_at) "
            "VALUES ('INC-X', 'INC-DOES-NOT-EXIST', 'now')")


def test_audit_events_cannot_be_updated_or_deleted(conn):
    _insert_event(conn)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_events SET payload = '{\"x\":1}' WHERE uid = 'e1'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_events WHERE uid = 'e1'")


def test_transaction_rolls_back_as_a_unit_and_nests(conn):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            _insert_event(conn, "e1", 1)
            with db.transaction(conn):  # nested -> savepoint
                _insert_event(conn, "e2", 2)
            raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0

    with db.transaction(conn):
        _insert_event(conn, "e1", 1)
        with pytest.raises(RuntimeError):
            with db.transaction(conn):
                _insert_event(conn, "e2", 2)
                raise RuntimeError("inner only")
    uids = [r["uid"] for r in conn.execute("SELECT uid FROM audit_events")]
    assert uids == ["e1"]
