"""
controller.py
=============
The autonomic loop. Argus is framed academically as a MAPE-K controller
(Monitor - Analyse - Plan - Execute, over shared Knowledge), which is the standard
reference model for self-healing / autonomic computing and gives your Design chapter
a recognised backbone to cite.

    Monitor   collect the current behaviour window + tail Wazuh alerts   (detector, sensors)
    Analyse   fuse signature + anomaly evidence into a breach decision    (detector.evaluate)
    Plan      choose the restore source                                   (healer._select_source)
    Execute   run the heal sequence                                       (healer.heal)
    Knowledge snapshots, manifests, golden baseline, metrics log          (shared state)

Two cooperating timers run in the main loop:
  * a fast detection tick (seconds) driving Monitor/Analyse/Execute,
  * a slow snapshot tick (10-20 min) driving the clone cadence.

`sensor_fn` is injected: on a real host it assembles the feature Window from access
logs + docker stats + FIM counts; in experiments the harness can drive it directly.
"""
from __future__ import annotations

import time
import uuid
from typing import Callable, Optional

from .anomaly import AnomalyDetector, Window
from .config import ArgusConfig
from .detector import Detector
from .healer import Healer
from .metrics import Incident, MetricsLog
from .snapshotter import Snapshotter


class ArgusController:
    def __init__(
        self,
        cfg: ArgusConfig,
        docker_ops,
        sensor_fn: Optional[Callable[[], Optional[Window]]] = None,
        anomaly: Optional[AnomalyDetector] = None,
    ):
        self.cfg = cfg
        self.dk = docker_ops
        self.sensor_fn = sensor_fn or (lambda: None)
        self.snapshotter = Snapshotter(cfg, docker_ops.copy_out)
        self.detector = Detector(cfg, anomaly)
        self.healer = Healer(cfg, docker_ops, self.snapshotter)
        self.metrics = MetricsLog(cfg.incidents_csv)
        self._breach_active = False

    # ---- one detection tick (also the unit the experiment harness calls) --
    def tick(self, t_attack: Optional[float] = None, scenario: str = "") -> Optional[Incident]:
        """
        Run Monitor -> Analyse; if a breach is confirmed, run Plan -> Execute and
        record the incident. `t_attack` (known only in experiments) lets us compute MTTD.
        Returns the Incident if one occurred, else None.
        """
        window = self.sensor_fn()
        event = self.detector.evaluate(window)
        if event is None:
            return None

        incident_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self._breach_active = True
        result = self.healer.heal(incident_id, event.detail)
        self._breach_active = False

        inc = Incident(
            incident_id=incident_id,
            scenario=scenario,
            t_attack=t_attack,
            t_detect=event.t_detect,
            t_restored=result.t_restored,
            t_promoted=result.t_promoted,
            detected_by=event.detected_by,
            false_positive=(t_attack is None),  # detection with no injected attack = FP
            restore_source=result.restore_source,
        )
        self.metrics.record(inc)
        return inc

    # ---- long-running daemon mode ----------------------------------------
    def run(self, detect_period_sec: float = 2.0) -> None:  # pragma: no cover
        last_snap = 0.0
        print("[argus] controller started; entering MAPE-K loop")
        while True:
            now = time.time()
            if now - last_snap >= self.cfg.snapshot_interval_sec:
                snap = self.snapshotter.take(breach_active=self._breach_active)
                print(f"[argus] snapshot {snap.path.name} clean={snap.clean}")
                last_snap = now
            inc = self.tick()
            if inc is not None:
                print(f"[argus] INCIDENT {inc.incident_id} detected_by={inc.detected_by} "
                      f"MTTR={inc.mttr}s source={inc.restore_source}")
            time.sleep(detect_period_sec)
