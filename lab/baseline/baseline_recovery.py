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

Metric bookkeeping (this arm records into its own CSV so the two distributions can be
compared side by side):

  t_detect  = t_attack + NOTICE_DELAY_SEC   -- a human "detects" by noticing
  MTTR      = t_promoted - t_detect         -- the REPAIR phase only
  TotalRecovery = t_promoted - t_attack     -- end-to-end, includes the notice delay

Quote TotalRecovery as the headline comparison. Because MTTR starts its clock at
detection, the operator-notice delay lands in MTTD and cancels out of an MTTR-only
comparison -- making the two arms look nearly identical even though closing that human
gap is the entire point of the controller. Reporting MTTR alone understates the result.

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


def _restore_source(cfg: ArgusConfig) -> Path | None:
    """Newest clone if one exists, else the pristine golden web-root copy."""
    clone = _last_clone(cfg)
    if clone is not None:
        return clone
    golden = Path(cfg.golden_webroot)
    return golden if golden.is_dir() and any(golden.iterdir()) else None


def _manual_recover(cfg: ArgusConfig) -> None:
    subprocess.run(["docker", "stop", cfg.protected_container], capture_output=True)
    source = _restore_source(cfg)
    # HOST side of the bind mount; cfg.protected_path is the in-container path and
    # iterating/deleting it on the host would either fail or clobber the wrong directory.
    webroot = Path(cfg.host_webroot)
    if source is not None and webroot.is_dir():
        for item in webroot.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink(missing_ok=True)
            else:
                shutil.rmtree(item, ignore_errors=True)
        shutil.copytree(source, webroot, dirs_exist_ok=True)
    subprocess.run(["docker", "start", cfg.protected_container], capture_output=True)


def run_baseline_arm(cfg: ArgusConfig, scenario: str, trials: int) -> None:
    webroot = Path(cfg.host_webroot)
    if not webroot.is_dir():
        raise SystemExit(f"host web root not found: {webroot} (is the lab up?)")
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
