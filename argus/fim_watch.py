"""
fim_watch.py
============
Lightweight file-integrity-monitor fallback for the lab.

Wazuh (config/wazuh/) is the enterprise-realistic detection source: a real IDS/FIM
product watching the host in real time. This module plays the *same role* for setups
that don't want to stand up a second Docker stack -- it polls the protected web root,
hashes it, diffs against the golden manifest, and writes breach_signal_path on any
deviation.

detector.py only cares whether breach_signal_path exists; it has no idea whether Wazuh
or this watcher wrote it, so the two are interchangeable detection sources. Document
which one you used and why in your report's Limitations section.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List

from .config import ArgusConfig
from .manifest import Manifest


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
            deviations = self.check_once()
            if deviations and not flag.exists():
                detail = f"fim_watch: {'; '.join(deviations[:5])}"
                flag.write_text(detail, encoding="utf-8")
                print(f"[fim_watch] BREACH detected -> {flag}: {detail}")
            time.sleep(self.poll_sec)


def main() -> None:  # pragma: no cover -- thin CLI wrapper
    ap = argparse.ArgumentParser(description="Lightweight FIM fallback (no Wazuh needed)")
    ap.add_argument("--config", default="config/argus.yaml")
    ap.add_argument("--root", default="runtime/webroot",
                     help="host directory to watch (the DVWA bind-mount webroot)")
    ap.add_argument("--period", type=float, default=2.0)
    args = ap.parse_args()
    cfg = ArgusConfig.load(args.config)
    FIMWatcher(cfg, args.root, args.period).run()


if __name__ == "__main__":
    main()
