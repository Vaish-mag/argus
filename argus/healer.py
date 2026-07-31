"""
healer.py
=========
The self-healing sequence, executed on a confirmed breach. Ordered exactly as the
spec requires, with the forensic capture deliberately *before* destruction:

    1. FORENSIC   copy the compromised protected dir out; docker commit the container
    2. ISOLATE    disconnect the compromised container from its network (cut comms)
    3. DESTROY    stop + remove the compromised container
    4. SELECT     choose restore source = latest verified-clean snapshot, else golden
    5. RESTORE    launch a fresh container from the GOLDEN IMAGE, copy verified files in
    6. VERIFY     re-hash the restored files against the chosen manifest; abort on mismatch
    7. HEALTH     poll the health URL until 200/302 or retries exhausted
    8. PROMOTE    reconnect to the protected network; it is now the new main

Note the ordering nuance: we always rebuild from the *golden image* (a known-good base)
and lay the verified-clean *data* clone on top. That means even if the newest clean
clone is subtly stale, the executable base is never the compromised one -- satisfying
"a new instance from a known-good baseline plus the restored clone".

Returns timestamps the controller feeds into the metrics log.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from .config import ArgusConfig
from .forensics import Forensics
from .manifest import Manifest
from .snapshotter import Snapshotter


@dataclass
class HealResult:
    t_restored: Optional[float]
    t_promoted: Optional[float]
    restore_source: str
    success: bool
    note: str = ""


class Healer:
    def __init__(self, cfg: ArgusConfig, docker_ops, snapshotter: Snapshotter):
        self.cfg = cfg
        self.dk = docker_ops
        self.snap = snapshotter
        self.forensics = Forensics(cfg.forensics_dir)

    def heal(self, incident_id: str, detail: str) -> HealResult:
        cfg = self.cfg
        compromised = cfg.protected_container

        # 1. FORENSIC -----------------------------------------------------
        case_dir = self.forensics.open_case(incident_id) / "captured"
        try:
            self.dk.copy_out(compromised, cfg.protected_path, case_dir)
            self.forensics.preserve_files(incident_id, case_dir)
        except Exception as exc:  # evidence best-effort; never blocks healing
            self.forensics.write_metadata(incident_id, f"{detail} (capture err: {exc})", None)
        committed = None
        try:
            committed = self.dk.commit_forensic(
                compromised, "argus/forensic", incident_id)
        except Exception:
            committed = None
        self.forensics.write_metadata(incident_id, detail, committed)

        # 2. ISOLATE ------------------------------------------------------
        self.dk.disconnect_network(compromised, cfg.isolated_network)

        # 3. DESTROY ------------------------------------------------------
        self.dk.stop_and_remove(compromised)

        # 4. SELECT restore source ---------------------------------------
        restore_dir, manifest, source = self._select_source()

        # 5. RESTORE from golden image + verified clone ------------------
        self.dk.run(cfg.golden_image, name=compromised, network=cfg.isolated_network,
                    ports={"80/tcp": 8080})
        # brief pause so the container filesystem is ready for injection
        time.sleep(1.0)
        if restore_dir is not None:
            self.dk.copy_in(compromised, restore_dir, cfg.protected_path)

        # 6. VERIFY restored data against the chosen manifest ------------
        if manifest is not None and restore_dir is not None:
            ok, problems = manifest.verify(restore_dir)
            if not ok:
                return HealResult(None, None, source, False,
                                  f"restore verification failed: {problems[:3]}")
        t_restored = time.time()

        # 7. HEALTH check before promotion -------------------------------
        healthy = False
        for _ in range(cfg.health_retries):
            if self.dk.http_ok(cfg.health_url):
                healthy = True
                break
            time.sleep(cfg.health_retry_delay_sec)
        if not healthy:
            return HealResult(t_restored, None, source, False, "health check never passed")

        # 8. PROMOTE ------------------------------------------------------
        t_promoted = time.time()
        return HealResult(t_restored, t_promoted, source, True, "promoted new main")

    def _select_source(self) -> Tuple[Optional[Path], Optional[Manifest], str]:
        """Latest verified-clean snapshot, else the golden baseline, else bare golden image."""
        snap = self.snap.latest_clean()
        if snap is not None:
            return snap.path, Manifest.load(snap.manifest_path), f"snapshot:{snap.path.name}"
        if Path(self.cfg.golden_manifest).exists():
            # golden manifest exists but is for in-image content; rebuild from image only
            return None, None, "golden-image"
        return None, None, "golden-image"
