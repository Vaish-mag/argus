"""
controller.py
=============
The "Plan + Execute" half of the MAPE-K loop, plus the wiring that ties the whole
autonomic loop together. Two things live here, in this order:

  1. Healer/HealResult   -- the eight-step self-healing sequence (Plan + Execute)
  2. ArgusController      -- the daemon loop: two timers, attack attribution, incident log

Argus is framed academically as a MAPE-K controller (Monitor - Analyse - Plan - Execute,
over shared Knowledge), which is the standard reference model for self-healing / autonomic
computing and gives your Design chapter a recognised backbone to cite.

    Monitor   collect the current behaviour window + tail Wazuh alerts   (detection.py)
    Analyse   fuse signature + anomaly evidence into a breach decision    (detection.Detector)
    Plan      choose the restore source                                   (Healer._select_source)
    Execute   run the heal sequence                                       (Healer.heal)
    Knowledge snapshots, manifests, golden baseline, metrics log          (storage.py)

Two cooperating timers run the main loop:
  * a fast detection tick (seconds) driving Monitor/Analyse/Execute,
  * a slow snapshot tick (10-20 min) driving the clone cadence.

`sensor_fn` is injected: on a real host it assembles the feature Window from access
logs + docker stats + FIM counts; in experiments the harness can drive it directly.

This file used to be two separate modules (controller.py, healer.py). They were merged
because Healer is the Execute half of exactly the loop ArgusController drives -- reading
them side by side is how you actually verify the heal sequence's ordering, which is the
project's central correctness claim. The section banner below marks where healer.py starts.
"""
from __future__ import annotations

import json
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

from .config import ArgusConfig
from .detection import AnomalyDetector, Detector, Window
from .storage import Forensics, Incident, Manifest, MetricsLog, Snapshotter


# ============================================================================
# Healer -- the self-healing sequence (formerly healer.py)
# ============================================================================
# Executed on a confirmed breach. Ordered exactly as the spec requires, with the
# forensic capture deliberately *before* destruction:
#
#     1. FORENSIC   copy the compromised protected dir out; docker commit the container
#     2. ISOLATE    disconnect the compromised container from its network (cut comms)
#     3. DESTROY    stop + remove the compromised container
#     4. SELECT     choose restore source = latest verified-clean snapshot, else golden
#     5. RESTORE    launch a fresh container from the GOLDEN IMAGE, copy verified files in
#     6. VERIFY     re-hash the restored files against the chosen manifest; abort on mismatch
#     7. HEALTH     poll the health URL until 200/302 or retries exhausted
#     8. PROMOTE    reconnect to the protected network; it is now the new main
#
# Note the ordering nuance: we always rebuild from the *golden image* (a known-good base)
# and lay the verified-clean *data* clone on top. That means even if the newest clean
# clone is subtly stale, the executable base is never the compromised one -- satisfying
# "a new instance from a known-good baseline plus the restored clone".
#
# Returns timestamps the controller feeds into the metrics log.

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


# ============================================================================
# ArgusController -- the autonomic loop (formerly controller.py)
# ============================================================================

class ArgusController:
    def __init__(
        self,
        cfg: ArgusConfig,
        docker_ops,
        sensor_fn: Optional[Callable[[], Optional[Window]]] = None,
        anomaly: Optional[AnomalyDetector] = None,
    ):
        self.cfg = cfg
        self.dk = docker_ops
        self.sensor_fn = sensor_fn or (lambda: None)
        self.snapshotter = Snapshotter(cfg, docker_ops.copy_out)
        self.detector = Detector(cfg, anomaly)
        self.healer = Healer(cfg, docker_ops, self.snapshotter)
        self.metrics = MetricsLog(cfg.incidents_csv)
        self._breach_active = False

    # ---- attack attribution (what makes MTTD measurable in daemon mode) ---
    def _consume_attack_marker(self) -> Tuple[Optional[float], str]:
        """
        Read and clear the harness's attack marker, if present.

        In daemon mode the controller is a separate process from the experiment harness,
        so it cannot be passed `t_attack` as an argument. Without this handoff every
        daemon-mode detection has t_attack=None, which makes MTTD unmeasurable *and*
        trips the "detection with no injected attack" rule so every real incident is
        mislabelled a false positive. The harness writes the marker immediately before
        injecting; we consume it on the detection that follows.
        """
        p = Path(self.cfg.attack_marker_path)
        if not p.exists():
            return None, ""
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return float(data["t_attack"]), str(data.get("scenario", ""))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None, ""
        finally:
            p.unlink(missing_ok=True)

    # ---- one detection tick (also the unit the experiment harness calls) --
    def tick(self, t_attack: Optional[float] = None, scenario: str = "") -> Optional[Incident]:
        """
        Run Monitor -> Analyse; if a breach is confirmed, run Plan -> Execute and
        record the incident. `t_attack` lets us compute MTTD: it is passed directly by
        in-process callers (tests), or picked up from the attack marker file that the
        out-of-process experiment harness writes.
        Returns the Incident if one occurred, else None.
        """
        window = self.sensor_fn()
        event = self.detector.evaluate(window)
        if event is None:
            return None

        if t_attack is None:
            t_attack, marked_scenario = self._consume_attack_marker()
            scenario = scenario or marked_scenario

        incident_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self._breach_active = True
        result = self.healer.heal(incident_id, event.detail)
        self._breach_active = False
        # Discard signals raised while the heal was in flight: they describe state this
        # heal has already remediated. Without this the run is credited with phantom
        # incidents that have no attack marker, polluting the false-positive rate.
        self.detector.clear_signals()

        inc = Incident(
            incident_id=incident_id,
            scenario=scenario,
            t_attack=t_attack,
            t_detect=event.t_detect,
            t_restored=result.t_restored,
            t_promoted=result.t_promoted,
            detected_by=event.detected_by,
            false_positive=(t_attack is None),  # detection with no injected attack = FP
            restore_source=result.restore_source,
        )
        self.metrics.record(inc)
        return inc

    # ---- long-running daemon mode ----------------------------------------
    def run(self, detect_period_sec: float = 2.0) -> None:  # pragma: no cover
        last_snap = 0.0
        print("[argus] controller started; entering MAPE-K loop")
        while True:
            now = time.time()
            if now - last_snap >= self.cfg.snapshot_interval_sec:
                snap = self.snapshotter.take(breach_active=self._breach_active)
                print(f"[argus] snapshot {snap.path.name} clean={snap.clean}")
                last_snap = now
            inc = self.tick()
            if inc is not None:
                print(f"[argus] INCIDENT {inc.incident_id} detected_by={inc.detected_by} "
                      f"MTTD={inc.mttd}s MTTR={inc.mttr}s source={inc.restore_source}")
            time.sleep(detect_period_sec)
