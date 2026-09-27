"""``CoreService`` — the single entry point to the CyberRescue Core.

Trust boundary (the reason this module exists):

* **Approvals** are created ONLY by ``grant_approval()``, which requires the id
  of a *registered* HUMAN actor with an approver role. There is no other path:
  the protocol ingestor never calls it, and LLM text such as
  ``{"approved": true}`` has no route into the approvals table.
* **Actors are re-loaded from the database by id** for every privileged call
  (``request_action``, ``grant_approval``), so a caller cannot hand in a
  fabricated ``Actor(role="ciso")`` object.
* **Sign-offs** count only from recruited specialist agents; **vetoes** only
  from the Compliance agent; anything else is recorded as ``CLAIM_REJECTED``.
* **Actions** are authorized only by the policy engine (``ACTION_AUTHORIZED``);
  an agent saying it acted is recorded as ``AGENT_ACTION_CLAIM`` and nothing
  more. Phase 1 has no executor — "authorized" is the end of the line.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cyberrescue.core import db
from cyberrescue.core.audit import AuditEvent, AuditLog, VerifyResult, utcnow
from cyberrescue.core.catalog import get_action, match_actions_in_text
from cyberrescue.core.holds import assess_holds
from cyberrescue.core.models import (
    ActionRequest,
    ActionStatus,
    ActionTier,
    Actor,
    ActorKind,
    Approval,
    ApprovalDecision,
    Asset,
    EventType,
    Finding,
    Incident,
    LegalHold,
    LinkRelation,
    PolicyDecision,
    PolicyOutcome,
    RiskSnapshot,
    SignOff,
    SignOffRequest,
    Veto,
)
from cyberrescue.core.policy import PolicyConfig, PolicyEngine
from cyberrescue.core.state_machine import TransitionResult, Trigger, next_status
from cyberrescue.core.store import CoreStore


class ApprovalError(PermissionError):
    """Raised when an approval request does not come from a valid approver."""


class CoreError(ValueError):
    """Raised on an invalid Core request (unknown incident, bad arguments)."""


@dataclass(frozen=True)
class ActionOutcome:
    request: ActionRequest
    decision: PolicyDecision
    authorization_event_uid: str | None = None

    @property
    def authorized(self) -> bool:
        return self.authorization_event_uid is not None


class CoreService:
    def __init__(self, conn: sqlite3.Connection, *, config: PolicyConfig | None = None,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self.conn = conn
        self.clock = clock
        self.config = config or PolicyConfig.from_env()
        self.engine = PolicyEngine(self.config)
        self.store = CoreStore(conn, clock)

    @classmethod
    def open(cls, path: str | Path | None = None, **kwargs: Any) -> CoreService:
        return cls(db.connect(path), **kwargs)

    @property
    def audit(self) -> AuditLog:
        return self.store.audit

    @property
    def system(self) -> Actor:
        return self.store.system_actor()

    # --- helpers --------------------------------------------------------------
    def _incident(self, incident_id: str) -> Incident:
        inc = self.store.get_incident(incident_id)
        if inc is None:
            raise CoreError(f"unknown incident {incident_id!r}")
        return inc

    def _registered(self, actor: Actor | str) -> Actor:
        actor_id = actor if isinstance(actor, str) else actor.id
        found = self.store.get_actor(actor_id)
        if found is None:
            raise ApprovalError(f"actor {actor_id!r} is not registered with the Core")
        return found

    # --- actors & assets --------------------------------------------------------
    def register_actor(self, kind: ActorKind | str, role: str, display_name: str = "",
                       external_ref: str | None = None) -> Actor:
        return self.store.register_actor(kind, role, display_name, external_ref,
                                         registered_by=self.system.id)

    def seed_assets_from_mock(self) -> int:
        """Load ``shared/mock_env/asset_inventory.json`` (provenance: simulated)."""
        from shared.mock_data import load_assets
        n = 0
        for a in load_assets():
            asset = Asset(**{k: v for k, v in a.items() if k in Asset.model_fields},
                          provenance="simulated")
            if self.store.get_asset(asset.asset_id) is None:
                self.store.add_asset(asset, actor_id=self.system.id)
                n += 1
        return n

    # --- incidents ----------------------------------------------------------------
    def open_incident(self, incident_id: str | None = None, *, title: str = "",
                      category: str | None = None, severity: str | None = None,
                      primary_asset_id: str | None = None,
                      recruited_roles: Iterable[str] = (), aliases: Iterable[str] = (),
                      opened_by: Actor | None = None, source: str = "core") -> Incident:
        """Open an incident; place any legal hold its primary asset requires."""
        with db.transaction(self.conn):
            inc = self.store.create_incident(
                incident_id=incident_id, title=title, category=category, severity=severity,
                primary_asset_id=primary_asset_id, recruited_roles=recruited_roles,
                aliases=aliases, opened_by=(opened_by or self.system).id, source=source)
            if primary_asset_id:
                self.place_holds_for(primary_asset_id, inc.id)
        return inc

    def place_holds_for(self, asset_id: str, incident_id: str | None) -> LegalHold | None:
        """Derive and record the legal hold an asset's data classes require."""
        asset = self.store.get_asset(asset_id)
        if asset is None:
            raise CoreError(f"unknown asset {asset_id!r}")
        h = assess_holds(asset)
        if not h.preservation_required:
            return None
        return self.store.add_hold(
            asset_id, incident_id=incident_id, rule_ids=list(h.preservation_rule_ids),
            requires_human_authorization=h.requires_human_authorization,
            actor_id=self.system.id)

    def apply_trigger(self, incident_id: str, trigger: Trigger | str, actor: Actor, *,
                      cause_uid: str | None = None, source: str = "core") -> TransitionResult:
        """Run the state machine; record the change or the rejection."""
        inc = self._incident(incident_id)
        res = next_status(inc.status, trigger, actor.kind, actor.role)
        trig = Trigger(trigger).value
        if not res.allowed:
            self.audit.append(
                EventType.STATE_TRANSITION_REJECTED, incident_id=incident_id,
                actor_id=actor.id, source=source,
                payload={"trigger": trig, "status": inc.status.value, "reason": res.reason},
                links=[(LinkRelation.CAUSED_BY, cause_uid)] if cause_uid else [])
        elif res.changed:
            self.store.set_status(incident_id, res.to_status, trigger=trig,
                                  actor_id=actor.id, cause_uid=cause_uid)
        return res

    # --- analysis records ---------------------------------------------------------
    def record_finding(self, incident_id: str, author: Actor, summary: str, *,
                       severity: str | None = None, evidence: Iterable[str] = (),
                       source_uid: str | None = None, source: str = "core") -> Finding:
        self._incident(incident_id)
        with db.transaction(self.conn):
            f = self.store.add_finding(incident_id, author_actor_id=author.id, summary=summary,
                                       severity=severity, source_uid=source_uid, source=source)
            for item in evidence:
                self.store.add_evidence(incident_id, content=str(item),
                                        kind="protocol_evidence", finding=f,
                                        actor_id=author.id, source_uid=source_uid,
                                        source=source)
        return f

    def reject_claim(self, incident_id: str, actor: Actor, claim: str, reason: str, *,
                     source_uid: str | None = None, source: str = "core") -> AuditEvent:
        return self.audit.append(
            EventType.CLAIM_REJECTED, incident_id=incident_id, actor_id=actor.id,
            source=source, payload={"claim": claim, "role": actor.role, "reason": reason},
            links=[(LinkRelation.CONCERNS, source_uid)] if source_uid else [])

    def record_action_claim(self, incident_id: str, actor: Actor, actions: list[str], *,
                            summary: str = "", source_uid: str | None = None,
                            source: str = "core") -> AuditEvent:
        """An agent SAYS it acted. Recorded for the audit trail; authorizes nothing."""
        return self.audit.append(
            EventType.AGENT_ACTION_CLAIM, incident_id=incident_id, actor_id=actor.id,
            source=source,
            payload={"claimed_actions": actions, "summary": summary,
                     "note": "claim only — not an authorization or an execution"},
            links=[(LinkRelation.DERIVED_FROM, source_uid)] if source_uid else [])

    def record_signoff_request(self, incident_id: str, actor: Actor, actions: list[str], *,
                               source_uid: str | None = None,
                               source: str = "core") -> SignOffRequest | None:
        inc = self._incident(incident_id)
        if not (actor.kind == ActorKind.AGENT and actor.role == "commander"):
            self.reject_claim(incident_id, actor, "SIGNOFF_REQUEST",
                              "only the Commander may request sign-off",
                              source_uid=source_uid, source=source)
            return None
        known = [a for a in dict.fromkeys(actions) if get_action(a)]
        with db.transaction(self.conn):
            req = self.store.add_signoff_request(incident_id, actor_id=actor.id, actions=known,
                                                 source_uid=source_uid, source=source)
            for name in known:
                spec = get_action(name)
                target = inc.primary_asset_id if spec.target == "host" else None
                self.store.add_action_request(
                    incident_id, action=name, asset_id=target, tier=int(spec.tier),
                    requested_by=actor.id,
                    params={"inferred_target": target is not None},
                    links=[(LinkRelation.DERIVED_FROM, req.event_uid)], source=source)
            self.apply_trigger(incident_id, Trigger.SIGNOFF_REQUEST, actor,
                               cause_uid=req.event_uid, source=source)
        return req

    def record_signoff(self, incident_id: str, actor: Actor, *, source_uid: str | None = None,
                       source: str = "core") -> SignOff | None:
        inc = self._incident(incident_id)
        if not (actor.kind == ActorKind.AGENT and actor.role in inc.specialists):
            self.reject_claim(incident_id, actor, "SIGNOFF",
                              f"{actor.kind.value}/{actor.role} is not a recruited specialist",
                              source_uid=source_uid, source=source)
            return None
        req = self.store.latest_signoff_request(incident_id)
        if req is None:
            self.reject_claim(incident_id, actor, "SIGNOFF", "no SIGNOFF_REQUEST to sign off",
                              source_uid=source_uid, source=source)
            return None
        return self.store.add_signoff(incident_id, actor=actor, request=req,
                                      source_uid=source_uid, source=source)

    def record_veto(self, incident_id: str, actor: Actor, *, text: str,
                    regulation: str | None = None, asset_id: str | None = None,
                    source_uid: str | None = None, source: str = "core") -> list[Veto]:
        """Record a Compliance veto, scoped to the tier-3 actions it names.

        A veto that names no tier-3 action is recorded with ``action=None``,
        which blocks EVERY tier-3 action on the incident (the cautious reading;
        per protocol §E.2 a veto never blocks non-destructive containment).
        """
        inc = self._incident(incident_id)
        if not (actor.kind == ActorKind.AGENT and actor.role == "compliance"
                and "compliance" in inc.recruited_roles):
            self.reject_claim(incident_id, actor, "VETO",
                              f"{actor.kind.value}/{actor.role} may not veto",
                              source_uid=source_uid, source=source)
            return []
        named = [a for a in match_actions_in_text(text)
                 if get_action(a).tier == ActionTier.DESTRUCTIVE]
        req = self.store.latest_signoff_request(incident_id)
        with db.transaction(self.conn):
            return [self.store.add_veto(
                incident_id, actor_id=actor.id, action=action, asset_id=asset_id,
                regulation=regulation, reason=text[:2000],
                request_uid=req.event_uid if req else None,
                source_uid=source_uid, source=source) for action in (named or [None])]

    def record_risk(self, incident_id: str, *, level: str, score: float | None = None,
                    factors: dict[str, Any] | None = None, method: str = "recorded",
                    actor: Actor | None = None) -> RiskSnapshot:
        """Store a risk value (Phase 1 records values only; no scoring logic)."""
        self._incident(incident_id)
        return self.store.add_risk(incident_id, level=level, score=score,
                                   factors=factors or {}, method=method,
                                   actor_id=(actor or self.system).id)

    # --- the gate -----------------------------------------------------------------
    def request_action(self, incident_id: str, action: str, asset_id: str | None,
                       requested_by: Actor | str, *, params: dict[str, Any] | None = None,
                       request_id: str | None = None, source: str = "core") -> ActionOutcome:
        """Propose an action and run it through the policy engine.

        ALLOW -> ACTION_AUTHORIZED (the approval used, if any, is consumed).
        REQUIRE_APPROVAL -> APPROVAL_REQUESTED. DENY -> request denied.
        """
        requester = self._registered(requested_by)
        self._incident(incident_id)
        spec = get_action(action)
        with db.transaction(self.conn):
            if request_id:
                req = self.store.get_action_request(request_id)
                if req is None or (req.incident_id, req.action, req.asset_id) != \
                        (incident_id, action, asset_id):
                    raise CoreError(f"request {request_id!r} does not match "
                                    f"({incident_id}, {action}, {asset_id})")
                if req.status not in (ActionStatus.PROPOSED, ActionStatus.REQUIRES_APPROVAL):
                    raise CoreError(f"request {request_id} is already {req.status.value}")
            else:
                req = self.store.add_action_request(
                    incident_id, action=action, asset_id=asset_id,
                    tier=int(spec.tier) if spec else -1, requested_by=requester.id,
                    params=params, source=source)
            snap = self.store.snapshot(incident_id, now=self.clock())
            decision = self.engine.evaluate(action=action, asset_id=asset_id,
                                            requester=requester, snapshot=snap)
            decision = self.store.add_policy_decision(req, decision, actor_id=self.system.id)
            auth_uid = None
            if decision.outcome == PolicyOutcome.ALLOW:
                approval = (self.store.get_approval(decision.approval_id)
                            if decision.approval_id else None)
                ev = self.store.authorize(req, decision, approval=approval,
                                          actor_id=self.system.id)
                auth_uid = ev.uid
                self.apply_trigger(incident_id, Trigger.ACTION_AUTHORIZED, self.system,
                                   cause_uid=ev.uid)
            elif decision.outcome == PolicyOutcome.REQUIRE_APPROVAL and any(
                    r.effect == "require_approval" and not r.satisfied
                    for r in decision.rule_results):
                # Only when a HUMAN approval is among what's missing; unmet
                # specialist sign-offs (P4) are not something a human can grant.
                self.audit.append(
                    EventType.APPROVAL_REQUESTED, incident_id=incident_id,
                    actor_id=self.system.id,
                    payload={"request_id": req.id, "action": action, "asset_id": asset_id,
                             "unmet_rules": decision.rules_failed,
                             "reasons": decision.reasons},
                    links=[(LinkRelation.CONCERNS, decision.event_uid)])
        return ActionOutcome(request=self.store.get_action_request(req.id),
                             decision=decision, authorization_event_uid=auth_uid)

    def grant_approval(self, incident_id: str, *, action: str, asset_id: str | None,
                       approver_actor_id: str, reason: str,
                       decision: ApprovalDecision | str = ApprovalDecision.APPROVE,
                       overrides_hold: bool = False, overrides_veto: bool = False,
                       ttl_minutes: int | None = None, request_id: str | None = None,
                       source: str = "core") -> Approval:
        """THE ONLY WAY TO CREATE AN APPROVAL.

        ``approver_actor_id`` must be a registered HUMAN actor whose role is in
        ``PolicyConfig.approver_roles``. Overrides and denials need a reason.
        The approval covers exactly (incident, action, asset), expires after
        ``ttl_minutes`` (default ``PolicyConfig.approval_ttl_minutes``), and is
        consumed by the first action it authorizes.
        """
        approver = self._registered(approver_actor_id)
        if approver.kind != ActorKind.HUMAN:
            raise ApprovalError(f"approver must be a human, got {approver.kind.value}")
        if approver.role not in self.config.approver_roles:
            raise ApprovalError(f"role {approver.role!r} may not approve actions "
                                f"(approvers: {list(self.config.approver_roles)})")
        inc = self._incident(incident_id)
        if inc.is_terminal:
            raise CoreError(f"incident {incident_id} is {inc.status.value}")
        if get_action(action) is None:
            raise CoreError(f"unknown action {action!r}")
        decision = ApprovalDecision(decision)
        if (overrides_hold or overrides_veto or decision == ApprovalDecision.DENY) \
                and not (reason or "").strip():
            raise ApprovalError("a written reason is required for overrides and denials")
        ttl = ttl_minutes if ttl_minutes is not None else self.config.approval_ttl_minutes
        if ttl <= 0:
            raise ApprovalError("approval lifetime must be positive")
        concerns = None
        if request_id:
            req = self.store.get_action_request(request_id)
            if req is None or (req.incident_id, req.action, req.asset_id) != \
                    (incident_id, action, asset_id):
                raise CoreError(f"request {request_id!r} does not match the approval scope")
            concerns = req.event_uid
        return self.store.add_approval(
            incident_id, action=action, asset_id=asset_id, approver=approver,
            decision=decision, reason=reason,
            expires_at=(self.clock() + timedelta(minutes=ttl)).isoformat(),
            overrides_hold=overrides_hold, overrides_veto=overrides_veto,
            concerns_uid=concerns, source=source)

    # --- audit ----------------------------------------------------------------------
    def verify_audit(self, incident_id: str | None = None) -> VerifyResult:
        return self.audit.verify(incident_id)
