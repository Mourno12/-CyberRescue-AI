"""CyberRescue Phase 2C — privilege escalation (PRIV-001) and exfiltration (DATA-001).

Neither pattern exists in the Phase 2B scenarios (decision D1 = a): these rules
are exercised with unit fixtures only.
"""

from cyberrescue.detection.model import Detection, Observation
from cyberrescue.detection.rules.privilege import NewPrivilegedAccount
from tests._detection_factory import Evidence, at


def results(rule, ev):
    return rule.evaluate(ev.view())


# --- PRIV-001 ------------------------------------------------------------------

def test_new_account_added_to_domain_admins():
    ev = Evidence()
    c = ev.account(at("10:00:00"), "srv-dc-01", 4720, "backup_adm")
    g = ev.account(at("10:02:00"), "srv-dc-01", 4728, "backup_adm", group="Domain Admins")
    lg = ev.auth(at("10:05:00"), "srv-db-01", 4624, "backup_adm", "srv-dc-01")
    [d] = results(NewPrivilegedAccount(), ev)
    assert isinstance(d, Detection) and d.supporting_evidence_ids == (c, g, lg)
    assert d.entities["group"] == "domain admins" and d.confidence == "high"


def test_new_account_in_ordinary_group_is_benign():
    ev = Evidence()
    ev.account(at("10:00:00"), "srv-dc-01", 4720, "newhire")
    ev.account(at("10:01:00"), "srv-dc-01", 4732, "newhire", group="Remote Desktop Users")
    assert results(NewPrivilegedAccount(), ev) == []


def test_account_creation_alone_and_late_group_change():
    ev = Evidence()
    ev.account(at("10:00:00"), "srv-dc-01", 4720, "temp1")
    assert results(NewPrivilegedAccount(), ev) == []
    ev.account(at("11:00:01"), "srv-dc-01", 4728, "temp1", group="Domain Admins")
    [r] = results(NewPrivilegedAccount(), ev)          # outside the hour: review only
    assert isinstance(r, Observation) and r.kind == "indicator_observed"


def test_existing_admin_change_is_an_observation_not_a_finding():
    ev = Evidence()
    ev.account(at("10:00:00"), "srv-dc-01", 4732, "jdoe", group="Administrators")
    [r] = results(NewPrivilegedAccount(), ev)
    assert isinstance(r, Observation) and "review, not a finding" in r.reason
