"""
baseline_recovery.py -- the STATIC control arm for the hypothesis test.
=======================================================================
This is what Argus is compared against: a functionally identical DVWA stack with NO
autonomic controller. Recovery is manual. To keep the comparison fair and reproducible
we script a *representative* manual recovery and time it, rather than relying on a human
stopwatch (which you would also report if you run a human trial for the viva).

A representative manual recovery for a defaced/backdoored web root is:
  1. notice          (fixed operator-notice delay, configurable -- see NOTICE_DELAY_SEC)
  2. stop container  docker stop argus-web
  3. restore files   copy the last known-good clone back over the web root
  4. start container docker start argus-web
  5. verify          curl the health URL

MTTR_baseline = t_verified - t_attack   (there is no separate "detect" step; a human
"detects" by noticing, folded into NOTICE_DELAY_SEC). We record it into a separate CSV
so the Results chapter can compare the two distributions.

The NOTICE_DELAY models the human-in-the-loop gap that Argus removes. Report the value
you choose and justify it (industry mean-time-to-acknowledge figures are a good anchor --
tell the reader where the number came from; do not invent one).
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from argus.config import ArgusConfig
from argus.metrics import Incident, MetricsLog
from lab.attacker.attack_lib import SCENARIOS

NOTICE_DELAY_SEC = 30.0     # placeholder: replace with a cited MTTA figure and justify it


def _last_clone(cfg: ArgusConfig) -> Path | None:
    base = Path(cfg.snapshots_dir)
    if not base.exists():
        return None
    snaps = sorted([p for p in base.iterdir() if p.is_dir()], reverse=True)
    return snaps[0] if snaps else None


def _manual_recover(cfg: ArgusConfig) -> None:
    subprocess.run(["docker", "stop", cfg.protected_container], capture_output=True)
    clone = _last_clone(cfg)
    webroot = Path(cfg.protected_path)
    if clone is not None:
        for item in webroot.iterdir():
            if item.is_file():
                item.unlink()
            else:
                shutil.rmtree(item, ignore_errors=True)
        shutil.copytree(clone, webroot, dirs_exist_ok=True)
    subprocess.run(["docker", "start", cfg.protected_container], capture_output=True)


def run_baseline_arm(cfg: ArgusConfig, scenario: str, trials: int) -> None:
    webroot = Path(cfg.protected_path)
    inject = SCENARIOS[scenario]
    log = MetricsLog(str(Path(cfg.incidents_csv).with_name("incidents_baseline.csv")))
    print(f"[exp] BASELINE arm: {trials} x {scenario} (NOTICE_DELAY={NOTICE_DELAY_SEC}s)")
    for i in range(trials):
        t_attack = inject(webroot)
        time.sleep(NOTICE_DELAY_SEC)          # human notices
        _manual_recover(cfg)
        # verify health
        healthy = False
        for _ in range(cfg.health_retries):
            out = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", cfg.health_url],
                capture_output=True, text=True).stdout.strip()
            if out in {"200", "302"}:
                healthy = True
                break
            time.sleep(cfg.health_retry_delay_sec)
        t_done = time.time()
        inc = Incident(
            incident_id=f"baseline-{i+1}", scenario=scenario,
            t_attack=t_attack, t_detect=t_attack + NOTICE_DELAY_SEC,
            t_restored=t_done if healthy else None,
            t_promoted=t_done if healthy else None,
            detected_by="manual", restore_source="manual-clone",
        )
        log.record(inc)
        print(f"  trial {i+1}: baseline MTTR={inc.mttr}s healthy={healthy}")
