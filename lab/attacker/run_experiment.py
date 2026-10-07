#!/usr/bin/env python3
"""
run_experiment.py -- drives the hypothesis test.
================================================
Runs N trials per scenario against the LIVE lab and records the resilience metrics,
then prints the comparison your Results chapter needs.

Design of a single Argus trial:
  1. ensure a healthy main is running (docker-compose up web)
  2. record t_attack = inject a benign attack artefact into runtime/webroot
  3. let the running Argus controller detect + heal (it writes the incident to CSV)
  4. read back the incident -> MTTD, MTTR

Baseline trial (no self-healing controller running):
  1-2 identical, then measure MANUAL recovery: how long a scripted operator takes to
      notice + restart + restore from the last clone. See lab/baseline/baseline_recovery.py.

Because both arms share the identical attack injection, the comparison is apples-to-apples.

Usage (run FROM the argus/ project root, with the controller already running in another
terminal for the Argus arm):
  python lab/attacker/run_experiment.py --arm argus    --trials 20 --scenario webshell
  python lab/attacker/run_experiment.py --arm baseline --trials 20 --scenario webshell

Then: python lab/attacker/run_experiment.py --summary
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # project root on path

from argus.config import ArgusConfig            # noqa: E402
from argus.storage import MetricsLog            # noqa: E402
from lab.attacker.attack_lib import SCENARIOS   # noqa: E402


def _wait_for_incident(log: MetricsLog, since: int, timeout: float = 120.0):
    """Poll the incidents CSV until a new row appears (the controller healed), or time out."""
    start = time.time()
    while time.time() - start < timeout:
        rows = log.load()
        if len(rows) > since:
            return rows[-1]
        time.sleep(0.5)
    return None


def _mark_attack(cfg: ArgusConfig, t_attack: float, scenario: str) -> None:
    """
    Tell the (separate) controller process when this attack was injected.

    The controller cannot be handed `t_attack` as an argument across a process boundary,
    so without this handoff it records t_attack=None -- MTTD becomes unmeasurable and
    every genuine incident is mislabelled a false positive.
    """
    p = Path(cfg.attack_marker_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # atomic: the controller polls this file, and a half-written marker would cost the
    # trial its ground truth. Write beside it, then rename into place.
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps({"t_attack": t_attack, "scenario": scenario}), encoding="utf-8")
    os.replace(tmp, p)


def run_argus_arm(cfg: ArgusConfig, scenario: str, trials: int) -> None:
    # NOTE: the HOST side of the bind mount -- cfg.protected_path is the path *inside*
    # the container and does not exist on the host.
    webroot = Path(cfg.host_webroot)
    if not webroot.is_dir():
        sys.exit(f"host web root not found: {webroot} (is the lab up? see SETUP.md Step 5)")
    log = MetricsLog(cfg.incidents_csv)
    inject = SCENARIOS[scenario]
    print(f"[exp] ARGUS arm: {trials} x {scenario} (webroot={webroot})")
    for i in range(trials):
        before = len(log.load())
        Path(cfg.attack_marker_path).unlink(missing_ok=True)   # no stale marker from a prior trial
        t_attack = time.time()
        _mark_attack(cfg, t_attack, scenario)      # must precede the injection
        inject(webroot)
        inc = _wait_for_incident(log, before)
        if inc is None:
            # nothing consumed the marker: remove it, or the next detection would inherit
            # this trial's attack time
            Path(cfg.attack_marker_path).unlink(missing_ok=True)
            print(f"  trial {i+1}: TIMEOUT (no heal recorded)")
            continue
        print(f"  trial {i+1}: detected_by={inc.get('detected_by')} "
              f"MTTD={inc.get('mttd')}s MTTR={inc.get('mttr')}s src={inc.get('restore_source')}")
        # let the freshly promoted main settle before the next trial
        time.sleep(3)


def summary(cfg: ArgusConfig) -> None:
    log = MetricsLog(cfg.incidents_csv)
    rep = log.report()
    print("\n==== Argus incident summary ====")
    for k, v in rep.items():
        print(f"{k}: {v}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/argus.yaml")
    ap.add_argument("--arm", choices=["argus", "baseline"], default="argus")
    ap.add_argument("--scenario", choices=list(SCENARIOS), default="webshell")
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()
    cfg = ArgusConfig.load(args.config)

    if args.summary:
        summary(cfg)
        return
    if args.arm == "argus":
        run_argus_arm(cfg, args.scenario, args.trials)
    else:
        from lab.baseline.baseline_recovery import run_baseline_arm
        run_baseline_arm(cfg, args.scenario, args.trials)


if __name__ == "__main__":
    main()
