"""
snapshotter.py
==============
The "snapshot on a cycle" stage. Every cadence tick (10-20 min) it:

  1. copies the protected directory out of the main container to a timestamped clone,
  2. builds a SHA-256 manifest of that clone,
  3. decides whether the clone is *verified-clean* by (a) checking no breach was active
     and (b) diffing the clone's manifest against the golden manifest, ignoring paths
     explicitly declared volatile (e.g. an uploads dir),
  4. prunes old snapshots to keep the last N.

Marking a snapshot clean=False when it deviates from golden is the defence against a
slow-burn compromise silently poisoning several clone cycles: such a clone is retained
(for forensics) but is never eligible as a restore source.
"""
from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .config import ArgusConfig
from .manifest import Manifest


@dataclass
class Snapshot:
    path: Path
    manifest_path: Path
    created_at: float
    clean: bool


class Snapshotter:
    def __init__(self, cfg: ArgusConfig, copy_out_fn):
        """
        copy_out_fn(container, container_path, host_dir) -> host_dir
        is injected (DockerOps.copy_out at runtime, a fake in tests).
        """
        self.cfg = cfg
        self._copy_out = copy_out_fn
        self.base = Path(cfg.snapshots_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self.golden: Optional[Manifest] = (
            Manifest.load(cfg.golden_manifest)
            if Path(cfg.golden_manifest).exists() else None
        )

    def _is_volatile(self, rel_path: str) -> bool:
        return any(rel_path.startswith(v.rstrip("/")) for v in self.cfg.volatile_paths)

    def take(self, breach_active: bool = False) -> Snapshot:
        ts = time.strftime("%Y%m%d-%H%M%S")
        dest = self.base / ts
        self._copy_out(self.cfg.protected_container, self.cfg.protected_path, dest)

        manifest = Manifest.build(dest, source="snapshot", clean=not breach_active)

        # golden diff (ignoring declared volatile paths)
        clean = not breach_active
        if self.golden is not None and clean:
            deviations = [
                d for d in manifest.diff_against_golden(self.golden)
                if not self._is_volatile(d.split(": ", 1)[-1])
            ]
            if deviations:
                clean = False
                manifest.clean = False

        manifest.save(dest.with_suffix(".manifest.json"))
        self._prune()
        return Snapshot(dest, dest.with_suffix(".manifest.json"), time.time(), clean)

    def _prune(self) -> None:
        snaps = sorted([p for p in self.base.iterdir() if p.is_dir()])
        for old in snaps[:-self.cfg.keep_snapshots]:
            shutil.rmtree(old, ignore_errors=True)
            mf = old.with_suffix(".manifest.json")
            mf.unlink(missing_ok=True)

    def latest_clean(self) -> Optional[Snapshot]:
        """
        Return the most recent snapshot whose manifest is marked clean AND still
        verifies against its own recorded hashes (defends against on-disk tampering
        of the clone itself). Falls through to None -> caller uses golden image.
        """
        snaps = sorted([p for p in self.base.iterdir() if p.is_dir()], reverse=True)
        for snap in snaps:
            mf_path = snap.with_suffix(".manifest.json")
            if not mf_path.exists():
                continue
            manifest = Manifest.load(mf_path)
            if not manifest.clean:
                continue
            ok, _ = manifest.verify(snap)
            if ok:
                return Snapshot(snap, mf_path, manifest.created_at, True)
        return None
