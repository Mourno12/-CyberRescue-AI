"""Run one scenario through the real pipeline in a temporary Core."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from cyberrescue.core.service import CoreService
from cyberrescue.detection.engine import detect
from cyberrescue.detection.model import DetectionReport
from cyberrescue.telemetry.catalog import DEFAULT_ROOT, ground_truth_relpath, scenario_info
from cyberrescue.telemetry.ground_truth import GroundTruth, load_ground_truth
from cyberrescue.telemetry.importer import import_scenario


@dataclass(frozen=True)
class ScenarioRun:
    key: str
    report: DetectionReport
    ground_truth: GroundTruth
    source_refs: dict[str, str]          # evidence id -> telemetry event id
    data_classes: dict[str, list[str]]   # host -> inventory data classes


def run_scenario(key: str, *, root: str | Path | None = None) -> ScenarioRun:
    """Import the committed scenario into a fresh Core, run detection (dry run),
    and load its ground truth. The Core is discarded afterwards."""
    from shared.mock_data import load_alert
    info = scenario_info(key)
    with tempfile.TemporaryDirectory(prefix="cyberrescue-eval-") as tmp:
        svc = CoreService.open(Path(tmp) / "eval.db")
        try:
            svc.seed_assets_from_mock()
            collector = svc.register_actor("system", "collector", "evaluation")
            alert = load_alert(info.incident_alias)
            svc.open_incident(alert["incident_id"], title=alert["title"],
                              primary_asset_id=alert["asset_id"])
            import_scenario(svc, info.key, collector_id=collector.id, root=root)
            report = detect(svc, info.incident_alias)
            refs = {e.id: e.source_ref for e in svc.list_evidence(info.incident_alias)}
            classes = {a.asset_id: list(a.data_classes) for a in svc.store.list_assets()}
        finally:
            svc.conn.close()
    gt = load_ground_truth(Path(root or DEFAULT_ROOT) / ground_truth_relpath(info))
    return ScenarioRun(key=info.key, report=report, ground_truth=gt, source_refs=refs,
                       data_classes=classes)
