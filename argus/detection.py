"""
detection.py
============
The "Monitor + Analyse" half of the MAPE-K loop: everything that watches the protected
service and decides whether something is wrong. Four things live here, in this order:

  1. Window/AnomalyDetector  -- the ML layer (IsolationForest over host behaviour)
  2. BreachEvent/Detector    -- fuses signature + anomaly evidence into one decision
  3. HostSensor               -- turns raw host observations into a Window
  4. FIMWatcher                -- the lightweight, Wazuh-free file-integrity monitor

Detector is the only piece the controller talks to directly; everything else in this file
feeds it evidence (a Window for the anomaly path, a `breach.flag` file for the signature
path -- FIMWatcher and Wazuh are interchangeable writers of that one file).

This file used to be four separate modules (anomaly.py, detector.py, sensors.py,
fim_watch.py). They were merged because they are the two ends of one job -- observing the
system and deciding if it's compromised -- and none of them stands alone: sensors.py only
existed to feed anomaly.py, and detector.py only existed to consume both. The section
banners below mark where each former module starts.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    import joblib
    _HAVE_SKLEARN = True
except ImportError:  # pragma: no cover
    _HAVE_SKLEARN = False

from .config import ArgusConfig
from .storage import Manifest


# ============================================================================
# Anomaly -- the ML layer (formerly anomaly.py)
# ============================================================================
# An unsupervised anomaly detector that catches attack patterns the signature engine has
# never seen.
#
# Design choices you can defend in a viva:
#   * Unsupervised (IsolationForest) -- we cannot enumerate every future attack, so we
#     model "normal" and flag deviation, rather than training on a labelled attack set
#     we do not have.
#   * IsolationForest specifically -- linear-time, tiny memory, no feature scaling
#     required, works on a laptop, and its anomaly score is directly interpretable as a
#     ranking. (An autoencoder is the natural next step; noted in Future Work.)
#   * Windowed features over the *behaviour* of the protected service, not raw packets,
#     so the model stays small and the features are explainable:
#
#         [ req_per_min, unique_paths, rate_4xx, rate_5xx,
#           file_change_events, new_process_events, cpu_pct, mem_pct, outbound_conns ]
#
# The detector is trained on baseline (normal-traffic) windows collected before any
# attack, then scores each live window. A window scoring below the configured threshold
# is emitted as an anomaly signal to Detector.

FEATURE_NAMES: List[str] = [
    "req_per_min", "unique_paths", "rate_4xx", "rate_5xx",
    "file_change_events", "new_process_events", "cpu_pct", "mem_pct", "outbound_conns",
]


@dataclass
class Window:
    """One time-window of observed behaviour."""
    values: Sequence[float]

    def vector(self) -> List[float]:
        v = list(self.values)
        if len(v) != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features, got {len(v)}")
        return v


class AnomalyDetector:
    def __init__(self, contamination: float = 0.02, random_state: int = 42):
        if not _HAVE_SKLEARN:
            raise RuntimeError("scikit-learn is required for AnomalyDetector")
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, windows: Sequence[Window]) -> "AnomalyDetector":
        X = np.array([w.vector() for w in windows], dtype=float)
        self.model.fit(X)
        self._fitted = True
        return self

    def score(self, window: Window) -> float:
        """Higher = more normal, lower (more negative) = more anomalous."""
        if not self._fitted:
            raise RuntimeError("model not fitted")
        return float(self.model.score_samples([window.vector()])[0])

    def is_anomaly(self, window: Window, threshold: float) -> bool:
        return self.score(window) < threshold

    # ---- persistence ------------------------------------------------------
    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path: str | Path, contamination: float = 0.02) -> "AnomalyDetector":
        obj = cls(contamination=contamination)
        obj.model = joblib.load(path)
        obj._fitted = True
        return obj


# ============================================================================
# Detector -- the fusion / gate layer (formerly detector.py)
# ============================================================================
# Fuses two independent evidence sources and emits a single BreachEvent the controller
# can act on:
#
#   1. Signature / FIM evidence. Wazuh's active-response writes a flag file (breach.flag)
#      and/or appends to an alerts JSON stream when a rule fires (e.g. FIM detects an
#      unexpected file in the web root); FIMWatcher below does the same thing without
#      needing Wazuh. Either way, Detector just tails breach.flag -- it has no idea which
#      one wrote it.
#   2. Anomaly evidence from the IsolationForest above, over the current behaviour window.
#
# Fusing them is what lets you test the core hypothesis: signature-only vs.
# signature+anomaly detection. The `detected_by` field records which source fired,
# so the Results chapter can report detection coverage per source.

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

    def clear_signals(self) -> None:
        """
        Drop any pending signature signal.

        Called once a heal has finished. Detection runs in a separate process from the
        healer and keeps polling throughout the heal, so it re-raises the flag for the
        artefact that is still on disk during the earlier (forensics/destroy) phases.
        Left in place, that stale edge is picked up as a second, phantom incident. This is
        safe: if the artefact somehow survived the heal, the next poll re-raises the flag
        within one detection period, so a genuinely unremediated breach is never dropped.
        """
        Path(self.cfg.breach_signal_path).unlink(missing_ok=True)

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


# ============================================================================
# HostSensor -- turns host observations into a Window (formerly sensors.py)
# ============================================================================
# On a real deployment the controller calls `HostSensor.window()` each tick.
#
# Feature sources (all laptop-cheap):
#   * req_per_min, unique_paths, rate_4xx, rate_5xx  <- tail of the DVWA/nginx access log
#   * file_change_events                              <- count of recent Wazuh syscheck alerts
#   * new_process_events                              <- count of recent Wazuh process alerts
#   * cpu_pct, mem_pct                                <- `docker stats` for the main container
#   * outbound_conns                                  <- `docker exec ... ss`/netstat count
#
# This class is intentionally forgiving: if a source is unavailable it contributes 0,
# so the controller never crashes because a log rotated. In experiments the harness can
# bypass this and hand the controller a synthetic Window directly.

_ACCESS_RE = re.compile(r'"\w+\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<code>\d{3})')


class HostSensor:
    def __init__(self, cfg: ArgusConfig, access_log: str = "runtime/webroot/access.log",
                 window_sec: int = 60):
        self.cfg = cfg
        self.access_log = Path(access_log)
        self.window_sec = window_sec
        self._log_offset = 0

    # ---- HTTP behaviour ---------------------------------------------------
    def _http_features(self) -> Tuple[float, float, float, float]:
        if not self.access_log.exists():
            return 0.0, 0.0, 0.0, 0.0
        lines = self.access_log.read_text(errors="ignore").splitlines()
        recent = lines[self._log_offset:]
        self._log_offset = len(lines)
        n = len(recent)
        if n == 0:
            return 0.0, 0.0, 0.0, 0.0
        paths, c4, c5 = set(), 0, 0
        for ln in recent:
            m = _ACCESS_RE.search(ln)
            if not m:
                continue
            paths.add(m.group("path"))
            code = m.group("code")
            if code.startswith("4"):
                c4 += 1
            elif code.startswith("5"):
                c5 += 1
        per_min = n * (60.0 / self.window_sec)
        return per_min, float(len(paths)), c4 / n, c5 / n

    # ---- Wazuh alert counts ----------------------------------------------
    def _fim_process_counts(self) -> Tuple[float, float]:
        p = Path(self.cfg.wazuh_alerts_path)
        if not p.exists():
            return 0.0, 0.0
        fim = proc = 0
        for ln in p.read_text(errors="ignore").splitlines()[-500:]:
            if "syscheck" in ln:
                fim += 1
            if "process" in ln or "audit" in ln:
                proc += 1
        return float(fim), float(proc)

    # ---- container resource use ------------------------------------------
    def _resource_features(self) -> Tuple[float, float, float]:
        try:
            out = subprocess.run(
                ["docker", "stats", "--no-stream", "--format",
                 "{{.CPUPerc}};{{.MemPerc}}", self.cfg.protected_container],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            cpu, mem = out.split(";")
            cpu_pct = float(cpu.strip().rstrip("%") or 0)
            mem_pct = float(mem.strip().rstrip("%") or 0)
        except Exception:
            cpu_pct = mem_pct = 0.0
        try:
            conns = subprocess.run(
                ["docker", "exec", self.cfg.protected_container, "sh", "-c",
                 "ss -tn state established 2>/dev/null | wc -l"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            outbound = float(conns or 0)
        except Exception:
            outbound = 0.0
        return cpu_pct, mem_pct, outbound

    # ---- assemble ---------------------------------------------------------
    def window(self) -> Optional[Window]:
        req, paths, r4, r5 = self._http_features()
        fim, proc = self._fim_process_counts()
        cpu, mem, out = self._resource_features()
        return Window([req, paths, r4, r5, fim, proc, cpu, mem, out])


# ============================================================================
# FIMWatcher -- the lightweight, Wazuh-free detection source (formerly fim_watch.py)
# ============================================================================
# Wazuh (config/wazuh/) is the enterprise-realistic detection source: a real IDS/FIM
# product watching the host in real time. This class plays the *same role* for setups
# that don't want to stand up a second Docker stack -- it polls the protected web root,
# hashes it, diffs against the golden manifest, and writes breach_signal_path on any
# deviation.
#
# Detector only cares whether breach_signal_path exists; it has no idea whether Wazuh
# or this watcher wrote it, so the two are interchangeable detection sources. Document
# which one you used and why in your report's Limitations section.

class FIMWatcher:
    def __init__(self, cfg: ArgusConfig, root: str | Path, poll_sec: float = 2.0):
        self.cfg = cfg
        self.root = Path(root)
        self.poll_sec = poll_sec
        golden_path = Path(cfg.golden_manifest)
        if not golden_path.exists():
            sys.exit(f"golden manifest not found: {golden_path} "
                      f"(run: python run_argus.py init-golden)")
        self.golden = Manifest.load(golden_path)

    def _is_volatile(self, rel_path: str) -> bool:
        return any(rel_path.startswith(v.rstrip("/")) for v in self.cfg.volatile_paths)

    def check_once(self) -> List[str]:
        """Hash the current root and diff against golden. Empty list == clean."""
        if not self.root.exists():
            return []
        current = Manifest.build(self.root, source="fim_watch")
        return [
            d for d in current.diff_against_golden(self.golden)
            if not self._is_volatile(d.split(": ", 1)[-1])
        ]

    def run(self) -> None:  # pragma: no cover -- exercised via check_once in tests
        flag = Path(self.cfg.breach_signal_path)
        flag.parent.mkdir(parents=True, exist_ok=True)
        print(f"[fim_watch] watching {self.root} every {self.poll_sec}s "
              f"against {self.cfg.golden_manifest}")
        while True:
            try:
                deviations = self.check_once()
            except Exception as exc:
                # A detection daemon must not exit on a transient filesystem error: if it
                # dies, the whole loop silently stops detecting and every later trial
                # reports a timeout that looks like a detection failure.
                print(f"[fim_watch] scan error (continuing): {exc!r}")
                time.sleep(self.poll_sec)
                continue
            if deviations and not flag.exists():
                detail = f"fim_watch: {'; '.join(deviations[:5])}"
                flag.write_text(detail, encoding="utf-8")
                print(f"[fim_watch] BREACH detected -> {flag}: {detail}")
            time.sleep(self.poll_sec)


def main() -> None:  # pragma: no cover -- thin CLI wrapper
    """Standalone entry point: `python -m argus.detection --root ... --period ...`."""
    ap = argparse.ArgumentParser(description="Lightweight FIM fallback (no Wazuh needed)")
    ap.add_argument("--config", default="config/argus.yaml")
    ap.add_argument("--root", help="host directory to watch (defaults to host_webroot)")
    ap.add_argument("--period", type=float, default=2.0)
    args = ap.parse_args()
    cfg = ArgusConfig.load(args.config)
    FIMWatcher(cfg, args.root or cfg.host_webroot, args.period).run()


if __name__ == "__main__":
    main()
