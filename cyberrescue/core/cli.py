"""Command-line interface to the CyberRescue Core.

    python -m cyberrescue.core [--db PATH] init
    python -m cyberrescue.core seed-assets
    python -m cyberrescue.core register-actor --kind human --role ciso --name "Dana"
    python -m cyberrescue.core import-band room.json --incident INC-C --roster roster.json
    python -m cyberrescue.core request --incident INC-C --action wipe_host \
        --asset srv-db-01 --requester <actor-id>
    python -m cyberrescue.core approve --incident INC-C --action wipe_host \
        --asset srv-db-01 --approver <actor-id> --reason "..." [--override-hold] \
        [--override-veto] [--deny] [--ttl 60]
    python -m cyberrescue.core verify [--incident INC-C]
    python -m cyberrescue.core show --incident INC-C

The database defaults to ``$CYBERRESCUE_DB_PATH`` or ``<repo>/cyberrescue.db``.
``approve`` is the minimal Phase 1 human-approval path; it calls
``CoreService.grant_approval`` and is subject to all of its checks.
"""

from __future__ import annotations

import argparse
import sys

from cyberrescue.core import db
from cyberrescue.core.band_import import Roster, import_band_context
from cyberrescue.core.models import ApprovalDecision
from cyberrescue.core.service import ApprovalError, CoreError, CoreService


def _incident(svc: CoreService, ref: str) -> str:
    iid = svc.store.resolve_incident(ref)
    if iid is None:
        raise CoreError(f"no Core incident for {ref!r}")
    return iid


def _cmd_init(svc, args) -> int:
    print(f"[core] database ready (schema v{db.schema_version(svc.conn)})")
    return 0


def _cmd_seed(svc, args) -> int:
    n = svc.seed_assets_from_mock()
    print(f"[core] seeded {n} new asset(s); {len(svc.store.list_assets())} in inventory "
          "(provenance: simulated)")
    return 0


def _cmd_register(svc, args) -> int:
    a = svc.register_actor(args.kind, args.role, args.name or "", args.ref)
    print(f"[core] actor {a.id}  kind={a.kind.value} role={a.role} ref={a.external_ref}")
    return 0


def _cmd_import(svc, args) -> int:
    rep = import_band_context(svc, args.file, incident_ref=args.incident,
                              roster=Roster.from_file(args.roster))
    print(f"[core] {rep.incident_id}: imported {rep.imported} message(s) "
          f"({rep.protocol_valid} protocol, {rep.unstructured} unstructured, "
          f"{rep.human} human), {rep.duplicates} duplicate(s), "
          f"{rep.skipped_non_text} non-text skipped")
    return 0


def _cmd_request(svc, args) -> int:
    out = svc.request_action(_incident(svc, args.incident), args.action, args.asset,
                             args.requester, source="cli")
    d = out.decision
    print(f"[core] {d.outcome.value}: {args.action} on {args.asset or '-'} "
          f"(request {out.request.id}, policy {d.policy_version})")
    for reason in d.reasons:
        print(f"  - {reason}")
    if d.approval_id:
        print(f"  used approval {d.approval_id}")
    return 0


def _cmd_approve(svc, args) -> int:
    ap = svc.grant_approval(
        _incident(svc, args.incident), action=args.action, asset_id=args.asset,
        approver_actor_id=args.approver, reason=args.reason,
        decision=ApprovalDecision.DENY if args.deny else ApprovalDecision.APPROVE,
        overrides_hold=args.override_hold, overrides_veto=args.override_veto,
        ttl_minutes=args.ttl, source="cli")
    print(f"[core] {ap.decision.value} {ap.id}: {ap.action} on {ap.asset_id or '-'} "
          f"by {ap.approver_role}, expires {ap.expires_at}")
    return 0


def _cmd_verify(svc, args) -> int:
    results = ({args.incident: svc.verify_audit(_incident(svc, args.incident))}
               if args.incident else svc.audit.verify_all())
    ok = True
    for chain, res in results.items():
        print(f"[core] {chain}: {'OK' if res.ok else 'TAMPERED'} ({res.checked} events)")
        for e in res.errors:
            print(f"  - {e}")
        ok &= res.ok
    return 0 if ok else 1


def _cmd_show(svc, args) -> int:
    iid = _incident(svc, args.incident)
    inc = svc.store.get_incident(iid)
    print(f"{inc.id}  status={inc.status.value}  severity={inc.severity}  "
          f"asset={inc.primary_asset_id}  aliases={svc.store.aliases_of(iid)}")
    print(f"  recruited: {inc.recruited_roles}")
    for h in svc.store.active_holds(inc.primary_asset_id) if inc.primary_asset_id else []:
        print(f"  hold: {h.asset_id} {h.rule_ids} human_auth={h.requires_human_authorization}")
    for v in svc.store.active_vetoes(iid):
        print(f"  veto: {v.action or 'ALL tier-3'} ({v.regulation})")
    for r in svc.store.action_requests(iid):
        print(f"  action: {r.action:<20} {r.asset_id or '-':<12} {r.status.value}")
    print(f"  audit events: {len(svc.audit.events(iid))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m cyberrescue.core",
                                description="CyberRescue Core — deterministic IR source of truth.")
    p.add_argument("--db", default=None, help="SQLite path (default: $CYBERRESCUE_DB_PATH "
                   "or <repo>/cyberrescue.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create/upgrade the database").set_defaults(fn=_cmd_init)
    sub.add_parser("seed-assets", help="load the mock asset inventory").set_defaults(fn=_cmd_seed)

    r = sub.add_parser("register-actor", help="register an agent or human")
    r.add_argument("--kind", choices=["agent", "human"], required=True)
    r.add_argument("--role", required=True)
    r.add_argument("--name", default="")
    r.add_argument("--ref", default=None, help="external ref, e.g. band:<sender_id>")
    r.set_defaults(fn=_cmd_register)

    i = sub.add_parser("import-band", help="import a saved Band room history")
    i.add_argument("file")
    i.add_argument("--incident", required=True)
    i.add_argument("--roster", required=True, help="JSON/YAML: {agents: {id: role}, "
                   "humans: {id: role}}")
    i.set_defaults(fn=_cmd_import)

    q = sub.add_parser("request", help="ask the policy engine to authorize an action")
    q.add_argument("--incident", required=True)
    q.add_argument("--action", required=True)
    q.add_argument("--asset", default=None)
    q.add_argument("--requester", required=True, help="registered actor id")
    q.set_defaults(fn=_cmd_request)

    a = sub.add_parser("approve", help="record a human approval (or denial)")
    a.add_argument("--incident", required=True)
    a.add_argument("--action", required=True)
    a.add_argument("--asset", default=None)
    a.add_argument("--approver", required=True, help="registered HUMAN actor id")
    a.add_argument("--reason", required=True)
    a.add_argument("--deny", action="store_true")
    a.add_argument("--override-hold", action="store_true")
    a.add_argument("--override-veto", action="store_true")
    a.add_argument("--ttl", type=int, default=None, help="minutes (default from policy config)")
    a.set_defaults(fn=_cmd_approve)

    v = sub.add_parser("verify", help="verify audit hash chains")
    v.add_argument("--incident", default=None)
    v.set_defaults(fn=_cmd_verify)

    s = sub.add_parser("show", help="summarise an incident")
    s.add_argument("--incident", required=True)
    s.set_defaults(fn=_cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    svc = CoreService.open(args.db)
    try:
        return args.fn(svc, args)
    except (CoreError, ApprovalError, ValueError, KeyError, FileNotFoundError) as e:
        print(f"[core] error: {e}", file=sys.stderr)
        return 2
    finally:
        svc.conn.close()
