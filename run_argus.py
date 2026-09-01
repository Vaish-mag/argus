#!/usr/bin/env python3
"""
run_argus.py -- operator entrypoint.

Subcommands:
  init-golden    build config/golden_manifest.json from the current pristine web root
  train          train the IsolationForest anomaly model from a normal-traffic capture
  watch          run the lightweight FIM fallback (no Wazuh needed) -- writes breach.flag
  run            start the Argus MAPE-K controller daemon (protects the running main)

Examples:
  python run_argus.py init-golden
  python run_argus.py train --normal results/normal_windows.csv
  python run_argus.py watch
  python run_argus.py run
"""
import argparse
import csv
import shutil
import sys
from pathlib import Path

from argus.config import ArgusConfig
from argus.storage import Manifest


def cmd_init_golden(cfg: ArgusConfig, args) -> None:
    root = Path(args.root or cfg.host_webroot)
    if not root.exists():
        sys.exit(f"web root not found: {root} (start docker-compose first)")
    m = Manifest.build(root, source="golden", clean=True)
    m.save(cfg.golden_manifest)
    print(f"[argus] golden manifest written: {cfg.golden_manifest} ({len(m.files)} files)")

    # Keep a pristine CONTENT copy too. The manifest alone is only hashes, so a restore
    # would have nothing to lay down; writing both from the same source in one step is
    # what guarantees the restored files verify against the manifest.
    golden_root = Path(cfg.golden_webroot)
    if golden_root.exists():
        shutil.rmtree(golden_root, ignore_errors=True)
    shutil.copytree(root, golden_root)
    print(f"[argus] golden web root copied:  {golden_root}")


def cmd_train(cfg: ArgusConfig, args) -> None:
    from argus.detection import AnomalyDetector, Window
    rows = []
    with open(args.normal, newline="") as fh:
        for r in csv.reader(fh):
            if r and not r[0].startswith("#"):
                rows.append(Window([float(x) for x in r]))
    if len(rows) < 30:
        sys.exit("need >=30 normal windows to train a stable model")
    det = AnomalyDetector(contamination=args.contamination).fit(rows)
    det.save(cfg.anomaly_model_path)
    print(f"[argus] anomaly model trained on {len(rows)} windows -> {cfg.anomaly_model_path}")


def cmd_watch(cfg: ArgusConfig, args) -> None:
    from argus.detection import FIMWatcher
    FIMWatcher(cfg, args.root or cfg.host_webroot, args.period).run()


def cmd_run(cfg: ArgusConfig, args) -> None:
    from argus.controller import ArgusController
    from argus.docker_ops import DockerOps
    from argus.detection import AnomalyDetector, HostSensor

    anomaly = None
    if Path(cfg.anomaly_model_path).exists():
        anomaly = AnomalyDetector.load(cfg.anomaly_model_path)
        print("[argus] anomaly model loaded")
    else:
        print("[argus] no anomaly model found -> running signature-only")

    sensor = HostSensor(cfg)
    controller = ArgusController(cfg, DockerOps(), sensor_fn=sensor.window, anomaly=anomaly)
    controller.run(detect_period_sec=args.period)


def main() -> None:
    ap = argparse.ArgumentParser(description="Argus self-healing MTD controller")
    ap.add_argument("--config", default="config/argus.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("init-golden"); g.add_argument("--root")
    t = sub.add_parser("train")
    t.add_argument("--normal", required=True)
    t.add_argument("--contamination", type=float, default=0.02)
    w = sub.add_parser("watch")
    w.add_argument("--root", help="defaults to host_webroot from the config")
    w.add_argument("--period", type=float, default=2.0)
    r = sub.add_parser("run"); r.add_argument("--period", type=float, default=2.0)

    args = ap.parse_args()
    cfg = ArgusConfig.load(args.config)
    {"init-golden": cmd_init_golden, "train": cmd_train, "watch": cmd_watch,
     "run": cmd_run}[args.cmd](cfg, args)


if __name__ == "__main__":
    main()
