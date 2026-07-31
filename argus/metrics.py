"""
metrics.py
==========
The experimental heart of the project. Every incident is timestamped at four points
so the two headline resilience metrics fall straight out of the arithmetic:

    t_attack   - when the (simulated) attack artefact was injected  [known to harness]
    t_detect   - when Argus raised the breach signal
    t_restored - when a verified-clean instance passed its health check
    t_promoted - when that instance became the new main

    MTTD = t_detect  - t_attack     (Mean Time To Detect)
    MTTR = t_promoted - t_detect    (Mean Time To Recover)

False positives are logged separately: a detection fired during a benign-traffic run
where no attack was injected. FPR = false_positives / (false_positives + true_negatives_windows).

Pure Python + csv; unit-tested without Docker.
"""
from __future__ import annotations

import csv
import statistics
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from typing import List, Optional


@dataclass
class Incident:
    incident_id: str
    scenario: str                 # e.g. "webshell", "deface", "benign"
    t_attack: Optional[float]     # None for benign/FP runs
    t_detect: Optional[float]
    t_restored: Optional[float]
    t_promoted: Optional[float]
    detected_by: str = ""         # "signature" | "anomaly" | "both" | ""
    false_positive: bool = False
    restore_source: str = ""      # "snapshot:<ts>" | "golden"

    @property
    def mttd(self) -> Optional[float]:
        if self.t_attack is None or self.t_detect is None:
            return None
        return round(self.t_detect - self.t_attack, 3)

    @property
    def mttr(self) -> Optional[float]:
        if self.t_detect is None or self.t_promoted is None:
            return None
        return round(self.t_promoted - self.t_detect, 3)


class MetricsLog:
    """Append-only incident log with a summary reducer for the Results chapter."""

    HEADER = [f.name for f in fields(Incident)] + ["mttd", "mttr"]

    def __init__(self, csv_path: str | Path):
        self.path = Path(csv_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            with open(self.path, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(self.HEADER)

    def record(self, inc: Incident) -> None:
        row = asdict(inc)
        row["mttd"] = inc.mttd
        row["mttr"] = inc.mttr
        with open(self.path, "a", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=self.HEADER).writerow(row)

    # ---- reducers used by the Results chapter -----------------------------
    def load(self) -> List[dict]:
        with open(self.path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    @staticmethod
    def summary(values: List[float]) -> dict:
        """Descriptive stats an examiner expects: n, mean, median, stdev, min, max."""
        if not values:
            return {"n": 0}
        return {
            "n": len(values),
            "mean": round(statistics.mean(values), 3),
            "median": round(statistics.median(values), 3),
            "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
            "min": round(min(values), 3),
            "max": round(max(values), 3),
        }

    def report(self) -> dict:
        rows = self.load()
        mttd = [float(r["mttd"]) for r in rows if r.get("mttd") not in ("", "None", None)]
        mttr = [float(r["mttr"]) for r in rows if r.get("mttr") not in ("", "None", None)]
        fps = sum(1 for r in rows if r.get("false_positive") in ("True", "true", True))
        detections = sum(1 for r in rows if r.get("t_detect") not in ("", "None", None))
        return {
            "MTTD_sec": self.summary(mttd),
            "MTTR_sec": self.summary(mttr),
            "detections": detections,
            "false_positives": fps,
            "false_positive_rate": round(fps / detections, 4) if detections else 0.0,
        }
