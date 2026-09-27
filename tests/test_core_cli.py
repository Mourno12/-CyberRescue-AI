"""CyberRescue Core — CLI (python -m cyberrescue.core)."""

import json
import re
import sqlite3
from pathlib import Path

import pytest

from cyberrescue.core.cli import main

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cyberrescue" / "inc_c_transcript.json"


@pytest.fixture
def dbp(tmp_path):
    return str(tmp_path / "core.db")


def _run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def test_init_and_seed_assets(capsys, dbp):
    assert _run(capsys, "--db", dbp, "init")[0] == 0
    code, out = _run(capsys, "--db", dbp, "seed-assets")
    assert code == 0 and "seeded 8 new asset(s); 8 in inventory" in out
    assert "seeded 0 new" in _run(capsys, "--db", dbp, "seed-assets")[1]


def test_verify_exit_code_detects_tampering(capsys, dbp):
    _run(capsys, "--db", dbp, "seed-assets")
    code, out = _run(capsys, "--db", dbp, "verify")
    assert code == 0 and "__system__: OK" in out
    conn = sqlite3.connect(dbp)
    conn.execute("DROP TRIGGER audit_events_no_update")
    conn.execute("UPDATE audit_events SET payload = '{}' WHERE seq = 3")
    conn.commit()
    conn.close()
    code, out = _run(capsys, "--db", dbp, "verify")
    assert code == 1 and "TAMPERED" in out


def test_cli_end_to_end_gate(capsys, dbp, tmp_path):
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps({
        "agents": {"synthetic-agent-commander": "commander",
                   "synthetic-agent-compliance": "compliance",
                   "synthetic-agent-threat-intel": "threat_intel",
                   "synthetic-agent-triage": "triage"},
        "humans": {"synthetic-human-ciso": "ciso"}}))
    code, out = _run(capsys, "--db", dbp, "import-band", str(FIXTURE),
                     "--incident", "INC-C", "--roster", str(roster))
    assert code == 0 and "imported 14 message(s)" in out

    code, out = _run(capsys, "--db", dbp, "register-actor", "--kind", "agent",
                     "--role", "commander", "--ref", "band:synthetic-agent-commander")
    cmd = re.search(r"actor (\w+)", out).group(1)   # sticky: the imported commander
    code, out = _run(capsys, "--db", dbp, "register-actor", "--kind", "human",
                     "--role", "ciso", "--ref", "band:synthetic-human-ciso")
    ciso = re.search(r"actor (\w+)", out).group(1)

    req = ("--db", dbp, "request", "--incident", "INC-C", "--action", "wipe_host",
           "--asset", "srv-db-01", "--requester", cmd)
    code, out = _run(capsys, *req)
    assert "REQUIRE_APPROVAL" in out and "P8:" in out

    code, out = _run(capsys, "--db", dbp, "approve", "--incident", "INC-C", "--action",
                     "wipe_host", "--asset", "srv-db-01", "--approver", cmd, "--reason", "x")
    assert code == 2 and "must be a human" in out                 # agents cannot approve

    code, out = _run(capsys, "--db", dbp, "approve", "--incident", "INC-C", "--action",
                     "wipe_host", "--asset", "srv-db-01", "--approver", ciso,
                     "--reason", "accept evidence risk", "--override-hold", "--override-veto")
    assert code == 0 and "approve" in out
    code, out = _run(capsys, *req)
    assert code == 0 and out.startswith("[core] ALLOW")
    code, out = _run(capsys, "--db", dbp, "show", "--incident", "INC-C")
    assert "wipe_host" in out and "authorized" in out
    assert _run(capsys, "--db", dbp, "verify", "--incident", "INC-C")[0] == 0
