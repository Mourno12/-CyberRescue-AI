# CyberRescue Core — Phase 1a

The CyberRescue Core (`cyberrescue/core/`) is the deterministic source of truth
for CyberRescue AI. It is built **alongside** the original WarRoom
implementation (tag `warroom-baseline`), which stays untouched and runnable as
the reference / Band compatibility mode.

**Principle:** LLM agents are reasoning components. They *propose*; the Core
*records and decides*. No LLM output can create an approval or authorize an
action.

```text
Agent proposes action ─► CoreService.request_action ─► PolicyEngine (pure)
    ─► ALLOW / REQUIRE_APPROVAL / DENY ─► ACTION_AUTHORIZED ─► (Phase 4: executor
    ─► verification) ─► audit events, hash-chained
```

## Modules

| Module | Responsibility |
|---|---|
| `models.py` | Pydantic entities, enums, audit/link vocabulary, policy I/O |
| `ids.py` | General incident IDs, generated `INC-YYYYMMDD-NNNN`, `INC-A/B/C` aliases |
| `db.py` | SQLite schema (16 tables), FKs, indexes, append-only triggers, transactions |
| `audit.py` | Hash-chained audit log (per incident) + `verify()` |
| `store.py` | Domain persistence; every write paired with its audit event in one transaction |
| `state_machine.py` | Incident lifecycle with role-checked triggers |
| `catalog.py` | Tiered action catalogue |
| `holds.py` | Legal holds derived from `reg_rules.json` (parity-tested against the Compliance tool) |
| `policy.py` | The gate — pure, versioned (`policy-v1`) |
| `service.py` | `CoreService` — the single entry point and trust boundary |
| `ingest.py` | Protocol messages → Core records (runtime use of `shared.schemas.ProtocolMessage`) |
| `band_import.py` | Offline import of a saved Band room history |
| `cli.py` | `python -m cyberrescue.core …` |

Dependencies: Python stdlib (`sqlite3`, `hashlib`, …) + `pydantic`. The Core
never imports the Band SDK or an LLM client (enforced by `tests/test_core_isolation.py`).

## Trust boundary

1. **Approvals** are created only by `CoreService.grant_approval()`, from the id
   of a *registered* human actor whose role is an approver role (`ciso`, `dpo`,
   `general_counsel`). The ingestor has no code path to it (AST-checked in tests).
   A message containing `{"approved": true}` is stored in the audit payload and
   ignored.
2. **Identity comes from transport metadata** (Band `sender_id` / `sender_type`)
   mapped through an operator-supplied roster — never from message text. An
   unknown sender gets a powerless role (`unknown` / `observer`).
3. **Actors are re-loaded from the DB** on privileged calls; an in-memory
   `Actor(role="ciso")` object is not trusted.
4. **`ACTION` messages are claims** (`AGENT_ACTION_CLAIM`), never authorizations.
5. **Sign-offs** count only from recruited specialists; **vetoes** only from
   Compliance; anything else becomes `CLAIM_REJECTED`.
6. **Legal holds** are derived by code when an incident opens, so they bind even
   if the Compliance LLM never posts a veto.

## Policy rules (`policy-v1`)

| Rule | Effect | Condition |
|---|---|---|
| P0 | DENY | action not in catalogue |
| P1 | DENY | requester is not the Commander agent or a human operator/approver |
| P2 | DENY | incident missing or closed |
| P3 | DENY | host action with missing/unknown asset |
| P9 | DENY | a valid human approval record explicitly denies the action |
| P4 | needs approval | tier 2 without sign-off from every recruited specialist on the latest `SIGNOFF_REQUEST` covering it |
| P5 | needs approval | tier 2 on a high/critical asset (configurable) |
| P6 | needs approval | tier 3 (always) |
| P7 | approval with `overrides_veto` | an active Compliance veto covers the action |
| P8 | approval with `overrides_hold` + reason | destructive action on a host under a hold requiring human authorization |

Tiers: 1 `notify_stakeholders`, `preserve_disk_image` · 2 `isolate_host`
(+ `block_ip`, `disable_account`, `kill_process`, `quarantine_file`) · 3
`wipe_host` (+ `delete_file`, `restore_from_backup`, `notify_regulator`).

A valid approval is human, approver-role, exact scope (incident, action,
asset), unexpired, unconsumed. One approval must satisfy every demand; it is
consumed by the action it authorizes. Lifetime defaults to **60 minutes**
(`CYBERRESCUE_APPROVAL_TTL_MINUTES` or `PolicyConfig(approval_ttl_minutes=…)`).

This is intentionally **stricter than WarRoom**: containment on a high/critical
asset (e.g. isolating `srv-db-01`) needs a human.

## Incident lifecycle

```text
NEW ─BRIEF─► INVESTIGATING ─SIGNOFF_REQUEST─► AWAITING_SIGNOFF ─ACTION_AUTHORIZED─► RESPONDING
RESPONDING/… ─ESCALATION─► AWAITING_HUMAN ─HUMAN_RULING─► RESPONDING ─RESOLUTION─► RESOLVED
NEW ─CLOSE─► CLOSED_FALSE_POSITIVE
```

Triggers are role-checked (e.g. only Triage briefs/closes, only the Commander
escalates). Only a human may resolve an incident that is awaiting a human
ruling. Terminal states are frozen. Rejected triggers are audited as
`STATE_TRANSITION_REJECTED`.

## Audit trail

Each event: `uid, chain, incident_id, seq, ts, event_type, actor_id, source,
external_id, protocol_type, protocol_valid, payload, links, prev_hash, hash`,
with `hash = sha256(prev_hash ‖ canonical_json(body incl. links))`, one chain
per incident (`__system__` for global events). SQLite triggers reject UPDATE
and DELETE on the log.

Links point from a newer event to an older one:

```text
EVIDENCE ─supports─► FINDING ─derived_from─► PROTOCOL_MESSAGE
SIGNOFF / VETO ─responds_to─► SIGNOFF_REQUESTED
POLICY_DECISION ─evaluates─► ACTION_PROPOSED
POLICY_DECISION ─relied_on─► APPROVAL_GRANTED / SIGNOFF_RECORDED
POLICY_DECISION ─blocked_by─► VETO_RECORDED / LEGAL_HOLD_PLACED
ACTION_AUTHORIZED ─authorizes─► POLICY_DECISION,  ─consumes─► APPROVAL_GRANTED
Phase 4: ACTION_EXECUTED ─executes─► ACTION_AUTHORIZED; ACTION_VERIFIED ─verifies─► ACTION_EXECUTED
```

Limits: tamper-*evident*, not tamper-proof (a writer with raw file access can
drop triggers and recompute hashes), and truncating a chain's tail needs an
anchored head hash to detect. Both are planned for a later phase (HMAC key /
head hash in the exported report).

## Incident IDs

* New IDs: `INC-YYYYMMDD-NNNN` — they start with a digit, so WarRoom's
  `INC-[ABC]` regexes can never misread them.
* `INC-A`, `INC-B`, `INC-C` are aliases of `INC-A-2026-0039`, `INC-B-2026-0041`,
  `INC-C-2026-0042`; decorated references (`INC-C-2026-[BlackHaze…]`) resolve.
* WarRoom's own regexes are unchanged in Phase 1 (planned for Phase 3).

## CLI walkthrough

```powershell
$env:CYBERRESCUE_DB_PATH = "cyberrescue.db"        # gitignored
python -m cyberrescue.core init
python -m cyberrescue.core seed-assets
python -m cyberrescue.core import-band tests/fixtures/cyberrescue/inc_c_transcript.json `
    --incident INC-C --roster roster.json
python -m cyberrescue.core register-actor --kind human --role ciso --name "Dana" --ref band:<ciso-id>
python -m cyberrescue.core request --incident INC-C --action wipe_host --asset srv-db-01 --requester <commander-id>
python -m cyberrescue.core approve --incident INC-C --action wipe_host --asset srv-db-01 `
    --approver <ciso-id> --reason "..." --override-hold --override-veto
python -m cyberrescue.core verify
```

`roster.json` maps Band ids to roles:
`{"agents": {"<band-agent-id>": "commander", …}, "humans": {"<band-user-id>": "ciso"}}`.

## Compatibility with WarRoom

| Component | Effect of Phase 1a |
|---|---|
| Triage, Threat Intel, Compliance, Commander | unchanged — the Core reads their protocol output offline |
| Facilitator (`scripts/incident_driver.py`) | unchanged |
| Band mode | unchanged; no WarRoom module imports `cyberrescue` (tested) |
| `shared/schemas.py`, `protocol.md` | unchanged; `ProtocolMessage` is now used at runtime by `ingest.py` |
| Mock environment | read-only (asset seeding, hold derivation) |
| `actions_log.jsonl`, `regulatory_clocks.json` | untouched |
| Original 77 tests | unmodified and passing |

## Deliberately not in Phase 1a

Commander integration (Phase 1b, opt-in), Forensics agent, detection engine,
dashboard, executor/verification, SIEM/EDR integration, MITRE ATT&CK, risk
scoring (Phase 1 only *records* risk values), approval UI (CLI only).
Band `tool_call`/`tool_result` messages are skipped on import (a later phase can
turn tool results into evidence).
