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

import shutil
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
        if cfg.commit_forensic_image:
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

        # 5. RESTORE: reset the HOST web root, then relaunch from golden -----
        # The web root is a bind mount, so the host directory is the real source of
        # truth: it is what FIM watches and what the container serves. Resetting it here
        # (rather than only copying into the container) is what makes the heal durable --
        # otherwise the attacker's artefact survives on the host, the FIM gate re-fires
        # on it immediately, and the controller heals in a loop forever.
        host_root = Path(cfg.host_webroot).resolve()
        self._reset_host_webroot(host_root, restore_dir)

        self.dk.run(
            cfg.golden_image, name=compromised, network=cfg.isolated_network,
            ports={"80/tcp": cfg.host_port},
            volumes={str(host_root): {"bind": cfg.protected_path, "mode": "rw"}},
        )
        # brief pause so the container filesystem is ready
        time.sleep(1.0)

        # 6. VERIFY restored data against the chosen manifest ------------
        if manifest is not None:
            ok, problems = manifest.verify(host_root)
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

    def _reset_host_webroot(self, host_root: Path, restore_dir: Optional[Path]) -> None:
        """
        Replace the host web root's contents with known-good files.

        `restore_dir is None` means no on-disk clean source was available, so we fall all
        the way back to extracting the golden *image* -- the strongest guarantee we have
        that the executable base was never the compromised one.
        """
        host_root.mkdir(parents=True, exist_ok=True)
        for item in host_root.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink(missing_ok=True)
            else:
                shutil.rmtree(item, ignore_errors=True)
        if restore_dir is not None:
            shutil.copytree(restore_dir, host_root, dirs_exist_ok=True)
        else:
            self.dk.seed_from_image(
                self.cfg.golden_image, self.cfg.protected_path, host_root)

    def _select_source(self) -> Tuple[Optional[Path], Optional[Manifest], str]:
        """
        Preference order: latest verified-clean snapshot, else the pristine golden web-root
        copy (content that provably matches golden_manifest, since `init-golden` writes
        both together), else extract the golden image directly.
        """
        snap = self.snap.latest_clean()
        if snap is not None:
            return snap.path, Manifest.load(snap.manifest_path), f"snapshot:{snap.path.name}"

        golden_root = Path(self.cfg.golden_webroot)
        golden_mf = Path(self.cfg.golden_manifest)
        if golden_root.exists() and any(golden_root.iterdir()) and golden_mf.exists():
            return golden_root, Manifest.load(golden_mf), "golden-webroot"

        # nothing verified on disk -> rebuild straight from the image, unverified
        return None, None, "golden-image"
