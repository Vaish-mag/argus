"""
detector.py
===========
The "gate" decision layer. It fuses two independent evidence sources and emits a
single BreachEvent the controller can act on:

  1. Signature / FIM evidence from Wazuh. Wazuh's active-response writes a flag file
     (breach.flag) and/or appends to an alerts JSON stream when a rule fires
     (e.g. FIM detects an unexpected file in the web root). We tail that.
  2. Anomaly evidence from anomaly.py over the current behaviour window.

Fusing them is what lets you test the core hypothesis: signature-only vs.
signature+anomaly detection. The `detected_by` field records which source fired,
so the Results chapter can report detection coverage per source.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .anomaly import AnomalyDetector, Window
from .config import ArgusConfig


@dataclass
class BreachEvent:
    t_detect: float
    detected_by: str          # "signature" | "anomaly" | "both"
    detail: str


class Detector:
    def __init__(self, cfg: ArgusConfig, anomaly: Optional[AnomalyDetector] = None):
        self.cfg = cfg
        self.anomaly = anomaly
        self._last_alert_offset = 0

    # ---- signature / FIM --------------------------------------------------
    def _signature_hit(self) -> Optional[str]:
        """
        Returns a short detail string if Wazuh flagged a breach, else None.

        Two mechanisms, either sufficient:
          * a breach.flag file dropped by Wazuh active-response (fast path), or
          * a new rule alert appended to the tailed alerts JSON stream.
        """
        flag = Path(self.cfg.breach_signal_path)
        if flag.exists():
            detail = flag.read_text(encoding="utf-8").strip() or "wazuh active-response flag"
            flag.unlink(missing_ok=True)  # consume the edge
            return detail

        alerts = Path(self.cfg.wazuh_alerts_path)
        if alerts.exists():
            lines = alerts.read_text(encoding="utf-8").splitlines()
            new = lines[self._last_alert_offset:]
            self._last_alert_offset = len(lines)
            for line in new:
                try:
                    a = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # FIM rule group or high-severity level -> treat as a breach signal
                level = a.get("rule", {}).get("level", 0)
                groups = a.get("rule", {}).get("groups", [])
                if level >= 7 or "syscheck" in groups or "ossec" in groups:
                    return f"wazuh rule {a.get('rule', {}).get('id')} lvl {level}"
        return None

    # ---- anomaly ----------------------------------------------------------
    def _anomaly_hit(self, window: Optional[Window]) -> Optional[str]:
        if self.anomaly is None or window is None:
            return None
        score = self.anomaly.score(window)
        if score < self.cfg.anomaly_threshold:
            return f"anomaly score {score:.3f} < {self.cfg.anomaly_threshold}"
        return None

    # ---- fusion -----------------------------------------------------------
    def evaluate(self, window: Optional[Window] = None) -> Optional[BreachEvent]:
        sig = self._signature_hit()
        ano = self._anomaly_hit(window)
        if sig and ano:
            return BreachEvent(time.time(), "both", f"{sig}; {ano}")
        if sig:
            return BreachEvent(time.time(), "signature", sig)
        if ano:
            return BreachEvent(time.time(), "anomaly", ano)
        return None
