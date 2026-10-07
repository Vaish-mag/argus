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
    golden_root = Path(cfg.golden_webroot)
    if golden_root.resolve() == root.resolve():
        sys.exit(f"golden_webroot and the web root are the same directory ({root}); "
                 f"refusing to delete the source it would copy from")
    m = Manifest.build(root, source="golden", clean=True)
    m.save(cfg.golden_manifest)
    print(f"[argus] golden manifest written: {cfg.golden_manifest} ({len(m.files)} files)")

    # Keep a pristine CONTENT copy too. The manifest alone is only hashes, so a restore
    # would have nothing to lay down; writing both from the same source in one step is
    # what guarantees the restored files verify against the manifest.
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
    if not 0.0 < args.contamination < 0.5:
        sys.exit("--contamination must be between 0 and 0.5 (exclusive)")
    det = AnomalyDetector(contamination=args.contamination).fit(rows)
    det.save(cfg.anomaly_model_path)
    print(f"[argus] anomaly model trained on {len(rows)} windows -> {cfg.anomaly_model_path}")


def _check_period(period: float) -> None:
    if not 0.1 <= period <= 3600:
        sys.exit("--period must be between 0.1 and 3600 seconds")


def cmd_watch(cfg: ArgusConfig, args) -> None:
    from argus.detection import FIMWatcher
    _check_period(args.period)
    FIMWatcher(cfg, args.root or cfg.host_webroot, args.period).run()


def cmd_run(cfg: ArgusConfig, args) -> None:
    from argus.controller import ArgusController
    from argus.docker_ops import DockerOps
    from argus.detection import AnomalyDetector, HostSensor

    _check_period(args.period)
    anomaly = None
    if Path(cfg.anomaly_model_path).exists():
        anomaly = AnomalyDetector.load(cfg.anomaly_model_path)
        print("[argus] anomaly model loaded", flush=True)
    else:
        print("[argus] no anomaly model found -> running signature-only", flush=True)

    # The sensor shells out to docker (1-2 s per call). With no model there is nothing to
    # feed, so skip it: otherwise every tick pays that cost for a Window nobody reads, and
    # the nominal detection period quietly stretches.
    sensor_fn = HostSensor(cfg).window if anomaly is not None else None
    controller = ArgusController(cfg, DockerOps(), sensor_fn=sensor_fn, anomaly=anomaly)
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
