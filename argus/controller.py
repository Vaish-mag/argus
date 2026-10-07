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
#     4. SELECT     candidate restore sources, best first: latest verified-clean snapshot,
#                   then the pristine golden web-root copy, then the golden image itself
#     5. RESTORE    lay the candidate's files into the host web root
#     6. VERIFY     re-hash the restored files against that candidate's manifest; on a
#                   mismatch discard it and try the next candidate
#     7. LAUNCH     only now start a fresh container from the GOLDEN IMAGE on top of the
#                   verified web root
#     8. HEALTH     poll the health URL until 200/302 or retries exhausted
#     9. PROMOTE    health passed: the instance is the new main
#
# THE PROMOTION GATE is step 6 happening *before* step 7. The web root is a bind mount, so
# a container serves exactly the host directory it is started on; if no candidate verifies,
# no container is started at all and the service stays down (fail closed). Verified-then-
# launch makes "a poisoned clone can never become main" true by construction -- the
# earlier ordering started the container (and published its port) first and verified
# afterwards, so an unverified clone could already be serving by the time the check ran.
#
# We always rebuild from the *golden image* (a known-good base) and lay the verified data
# on top, so even a subtly stale clean clone never makes the executable base compromised.
#
# Returns timestamps the controller feeds into the metrics log.

@dataclass
class HealResult:
    t_restored: Optional[float]
    t_promoted: Optional[float]
    restore_source: str
    success: bool
    note: str = ""
    outcome: str = "healed"      # "healed" | "verify_failed" | "health_failed"


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
            # best-effort: a capture that drops an odd member still beats no evidence,
            # and evidence must never block healing
            self.dk.copy_out(compromised, cfg.protected_path, case_dir, strict=False)
            self.forensics.preserve_files(incident_id, case_dir)
        except Exception as exc:
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

        # 4-6. SELECT + RESTORE + VERIFY ----------------------------------
        # The web root is a bind mount, so the host directory is the real source of truth:
        # it is what FIM watches and what the container will serve. Resetting it (rather
        # than only copying into a container) is what makes the heal durable -- otherwise
        # the attacker's artefact survives on the host and the controller heals forever.
        host_root = Path(cfg.host_webroot).resolve()
        source, tried, last_label = None, [], "none"
        for restore_dir, manifest, label in self._candidate_sources():
            last_label = label
            self._reset_host_webroot(host_root, restore_dir)
            if manifest is None:
                source = label + "-unverified"        # nothing on disk to verify against
                break
            ok, problems = manifest.verify(host_root)
            if ok:
                source = label
                break
            tried.append(f"{label}: {problems[:2]}")
        if source is None:
            # Fail closed: nothing verified, so nothing is launched. The (unverified) host
            # web root is left in place but no container serves it.
            return HealResult(None, None, last_label, False,
                              f"no restore source verified: {tried}",
                              outcome="verify_failed")

        # 7. LAUNCH (only ever on a verified web root) ---------------------
        self.dk.run(
            cfg.golden_image, name=compromised, network=cfg.isolated_network,
            ports={"80/tcp": (cfg.host_bind, cfg.host_port)},
            volumes={str(host_root): {"bind": cfg.protected_path, "mode": "rw"}},
        )
        time.sleep(1.0)                               # let the container filesystem settle
        t_restored = time.time()

        # 8. HEALTH -------------------------------------------------------
        healthy = False
        for _ in range(cfg.health_retries):
            if self.dk.http_ok(cfg.health_url):
                healthy = True
                break
            time.sleep(cfg.health_retry_delay_sec)
        if not healthy:
            # The content is verified, so the instance is safe -- it just has not come up
            # in time. Leave it running (it may still finish starting) but do not claim a
            # promotion, and record the failure instead of letting the trial vanish.
            return HealResult(t_restored, None, source, False, "health check never passed",
                              outcome="health_failed")

        # 9. PROMOTE ------------------------------------------------------
        return HealResult(t_restored, time.time(), source, True, "promoted new main")

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

    def _candidate_sources(self):
        """
        Yield (dir, manifest, label) restore candidates, best first. The caller verifies
        each one after laying it down and moves on to the next if it does not check out,
        so one corrupted snapshot degrades to the golden copy instead of aborting the heal.

          1. the latest verified-clean snapshot (freshest data),
          2. the pristine golden web-root copy (content that provably matches
             golden_manifest, since `init-golden` writes both together),
          3. the golden *image* extracted directly -- verified against the golden manifest
             when one exists, otherwise there is nothing to verify against.
        """
        snap = self.snap.latest_clean()
        if snap is not None:
            yield snap.path, Manifest.load(snap.manifest_path), f"snapshot:{snap.path.name}"

        golden_root = Path(self.cfg.golden_webroot)
        golden_mf = Path(self.cfg.golden_manifest)
        manifest = Manifest.load(golden_mf) if golden_mf.exists() else None
        if manifest is not None and golden_root.exists() and any(golden_root.iterdir()):
            yield golden_root, manifest, "golden-webroot"
        yield None, manifest, "golden-image"


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
            t_attack, scenario = float(data["t_attack"]), str(data.get("scenario", ""))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as exc:
            print(f"[argus] unreadable attack marker ({exc!r}); detection is unattributed")
            p.unlink(missing_ok=True)
            return None, ""
        p.unlink(missing_ok=True)
        # A marker that outlived its trial (the trial timed out, nothing consumed it) must
        # not be handed to the next, unrelated detection: that would credit it with an
        # attack time from the past and inflate MTTD and total_recovery.
        age = time.time() - t_attack
        if age > self.cfg.attack_marker_max_age_sec or age < -5.0:
            print(f"[argus] discarding stale attack marker (age {age:.0f}s)")
            return None, ""
        return t_attack, scenario

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
            heal_outcome=result.outcome,
        )
        self.metrics.record(inc)
        if not result.success:
            print(f"[argus] HEAL FAILED ({result.outcome}): {result.note}", flush=True)
        return inc

    # ---- long-running daemon mode ----------------------------------------
    def run(self, detect_period_sec: float = 2.0) -> None:  # pragma: no cover
        last_snap = 0.0
        print("[argus] controller started; entering MAPE-K loop", flush=True)
        while True:
            now = time.time()
            if now - last_snap >= self.cfg.snapshot_interval_sec:
                # a raised-but-unconsumed breach flag also means "do not trust this copy"
                pending = Path(self.cfg.breach_signal_path).exists()
                try:
                    snap = self.snapshotter.take(breach_active=self._breach_active or pending)
                    print(f"[argus] snapshot {snap.path.name} clean={snap.clean}", flush=True)
                except Exception as exc:       # a failed capture must not stop detection
                    print(f"[argus] snapshot failed (continuing): {exc!r}", flush=True)
                last_snap = now
            inc = self.tick()
            if inc is not None:
                print(f"[argus] INCIDENT {inc.incident_id} detected_by={inc.detected_by} "
                      f"MTTD={inc.mttd}s MTTR={inc.mttr}s source={inc.restore_source}",
                      flush=True)
            time.sleep(detect_period_sec)
