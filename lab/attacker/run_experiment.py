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
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # project root on path

from argus.config import ArgusConfig            # noqa: E402
from argus.metrics import MetricsLog            # noqa: E402
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


def run_argus_arm(cfg: ArgusConfig, scenario: str, trials: int) -> None:
    webroot = Path(cfg.protected_path)
    log = MetricsLog(cfg.incidents_csv)
    inject = SCENARIOS[scenario]
    print(f"[exp] ARGUS arm: {trials} x {scenario}")
    for i in range(trials):
        before = len(log.load())
        t_attack = inject(webroot)
        inc = _wait_for_incident(log, before)
        if inc is None:
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
