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

import json
import time
import uuid
from pathlib import Path
from typing import Callable, Optional, Tuple

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

    # ---- attack attribution (what makes MTTD measurable in daemon mode) ---
    def _consume_attack_marker(self) -> Tuple[Optional[float], str]:
        """
        Read and clear the harness's attack marker, if present.

        In daemon mode the controller is a separate process from the experiment harness,
        so it cannot be passed `t_attack` as an argument. Without this handoff every
        daemon-mode detection has t_attack=None, which makes MTTD unmeasurable *and*
        trips the "detection with no injected attack" rule so every real incident is
        mislabelled a false positive. The harness writes the marker immediately before
        injecting; we consume it on the detection that follows.
        """
        p = Path(self.cfg.attack_marker_path)
        if not p.exists():
            return None, ""
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return float(data["t_attack"]), str(data.get("scenario", ""))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None, ""
        finally:
            p.unlink(missing_ok=True)

    # ---- one detection tick (also the unit the experiment harness calls) --
    def tick(self, t_attack: Optional[float] = None, scenario: str = "") -> Optional[Incident]:
        """
        Run Monitor -> Analyse; if a breach is confirmed, run Plan -> Execute and
        record the incident. `t_attack` lets us compute MTTD: it is passed directly by
        in-process callers (tests), or picked up from the attack marker file that the
        out-of-process experiment harness writes.
        Returns the Incident if one occurred, else None.
        """
        window = self.sensor_fn()
        event = self.detector.evaluate(window)
        if event is None:
            return None

        if t_attack is None:
            t_attack, marked_scenario = self._consume_attack_marker()
            scenario = scenario or marked_scenario

        incident_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self._breach_active = True
        result = self.healer.heal(incident_id, event.detail)
        self._breach_active = False
        # Discard signals raised while the heal was in flight: they describe state this
        # heal has already remediated. Without this the run is credited with phantom
        # incidents that have no attack marker, polluting the false-positive rate.
        self.detector.clear_signals()

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
                      f"MTTD={inc.mttd}s MTTR={inc.mttr}s source={inc.restore_source}")
            time.sleep(detect_period_sec)
