#!/usr/bin/env python3
"""
serve.py -- data bridge + static file server for the HTML dashboard and report.
===============================================================================
All presentation logic lives in lab/dashboard.html and lab/report.html; this file
exists only because a browser cannot do two things the dashboard needs:

  * run `docker ps` to see whether the protected container was replaced, and
  * hash the protected directory to compare it against the golden manifest.

So a background thread writes those observations to results/status.json every few
seconds, and the rest is a plain static file server. Standard library only -- the
lab machine is memory-constrained and this must not add dependencies.

Read-only with respect to the controller: it never touches the breach flag, the
manifests or the incidents CSV, so it cannot influence the run it is observing.

Run (in its own terminal, alongside `watch` and `run`):
    python lab/serve.py
then open   http://localhost:8090/lab/dashboard.html
            http://localhost:8090/lab/report.html
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from argus.config import ArgusConfig      # noqa: E402
from argus.storage import Manifest        # noqa: E402

PORT = 8090
REFRESH_SEC = 2.0


def _container(cfg: ArgusConfig) -> dict:
    try:
        out = subprocess.run(
            ["docker", "ps", "--filter", f"name={cfg.protected_container}",
             "--format", "{{.ID}}|{{.Status}}|{{.Image}}"],
            capture_output=True, text=True, timeout=4).stdout.strip()
        if out:
            cid, status, image = out.split("|", 2)
            return {"id": cid, "status": status, "image": image}
    except Exception:
        pass
    return {"id": None, "status": "not running", "image": "-"}


def _health(cfg: ArgusConfig) -> str:
    try:
        with urllib.request.urlopen(cfg.health_url, timeout=3) as r:
            return str(r.status)
    except urllib.error.HTTPError as e:      # 4xx/5xx is still a live answer
        return str(e.code)
    except Exception:
        return "down"


def _drift(cfg: ArgusConfig) -> dict:
    """Live diff of the protected directory against the trusted baseline."""
    root, gp = ROOT / cfg.host_webroot, ROOT / cfg.golden_manifest
    if not root.is_dir() or not gp.exists():
        return {"count": 0, "items": [], "files": 0}
    golden = Manifest.load(gp)
    current = Manifest.build(root, source="dashboard")
    volatile = [v.rstrip("/") for v in cfg.volatile_paths]
    devs = [d for d in current.diff_against_golden(golden)
            if not any(d.split(": ", 1)[-1].startswith(v) for v in volatile)]
    return {"count": len(devs), "items": devs[:8], "files": len(current.files)}


def _clones(cfg: ArgusConfig) -> list:
    base = ROOT / cfg.snapshots_dir
    if not base.is_dir():
        return []
    out = []
    for d in sorted([p for p in base.iterdir() if p.is_dir()], reverse=True)[:6]:
        mf = d.with_suffix(".manifest.json")
        if not mf.exists():
            continue
        try:
            m = json.loads(mf.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        out.append({"name": d.name, "files": len(m["files"]), "clean": m["clean"]})
    return out


def collect(cfg: ArgusConfig) -> dict:
    flag = ROOT / cfg.breach_signal_path
    forensics = ROOT / cfg.forensics_dir
    gp = ROOT / cfg.golden_manifest
    golden_files = len(json.loads(gp.read_text())["files"]) if gp.exists() else 0
    return {
        "generated_at": time.time(),
        "container": _container(cfg),
        "health": _health(cfg),
        "golden_files": golden_files,
        "drift": _drift(cfg),
        "clones": _clones(cfg),
        "breach": flag.exists(),
        "breach_detail": flag.read_text(errors="ignore").strip() if flag.exists() else "",
        "forensic_cases": len(list(forensics.iterdir())) if forensics.is_dir() else 0,
        "snapshot_interval_sec": cfg.snapshot_interval_sec,
    }


def writer_loop() -> None:
    out = ROOT / "results" / "status.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            cfg = ArgusConfig.load(str(ROOT / "config" / "argus.yaml"))
            tmp = out.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(collect(cfg)))
            tmp.replace(out)          # atomic, so the page never reads a half-written file
        except Exception as exc:
            print(f"[serve] status error (continuing): {exc!r}")
        time.sleep(REFRESH_SEC)


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")   # always show live data
        super().end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    threading.Thread(target=writer_loop, daemon=True).start()
    print(f"[serve] dashboard : http://localhost:{PORT}/lab/dashboard.html")
    print(f"[serve] report    : http://localhost:{PORT}/lab/report.html")
    print("[serve] Ctrl-C to stop")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT),
                            partial(Handler, directory=str(ROOT))).serve_forever()
    except KeyboardInterrupt:
        print("\n[serve] stopped")
