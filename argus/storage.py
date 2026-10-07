"""
storage.py
==========
The "Knowledge" layer of the MAPE-K loop: everything about what a clean copy looks like,
where clean copies live, what happened during an incident, and the numbers that came out
of it. Four things live here, in this order:

  1. Manifest       -- SHA-256 fingerprint of a directory; the unit of "is this clean"
  2. Forensics       -- evidence capture before a compromised instance is destroyed
  3. Snapshotter     -- periodic hash-verified clones of the protected directory
  4. Incident/MetricsLog -- MTTD/MTTR/total_recovery bookkeeping for the Results chapter

None of this touches Docker or the network -- it is pure filesystem and arithmetic, which
is what makes it fully unit-testable without a daemon. Snapshotter is the one exception
that reaches outside: it takes a `copy_out_fn` callable (real Docker at runtime, a fake in
tests) rather than depending on docker_ops directly, so the seam stays mockable.

This file used to be four separate modules (manifest.py, forensics.py, snapshotter.py,
metrics.py). They were merged because none of them is more than ~120 lines and they share
one job -- being the Knowledge the other layers read and write -- so navigating four tiny
files added friction without adding clarity. The section banners below mark where each
former module starts.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import statistics
import time
from datetime import datetime
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import ArgusConfig

_CHUNK = 1 << 20  # 1 MiB read buffer -- keeps memory flat on large files

# Digest recorded for a file that exists but cannot be read (permissions, an antivirus
# lock, a stripped read bit). It never compares equal to anything -- see Manifest._same --
# so an unreadable file always surfaces as a deviation instead of vanishing from the scan.
UNREADABLE = "unreadable"


class IncompleteCapture(Exception):
    """A copy-out dropped members it could not safely or fully extract."""

    def __init__(self, skipped):
        self.skipped = list(skipped)
        super().__init__(f"{len(self.skipped)} archive member(s) not captured: "
                         f"{self.skipped[:3]}")


# ============================================================================
# Manifest -- clone-integrity layer (formerly manifest.py)
# ============================================================================
# A *manifest* is a JSON record mapping every file in a protected directory to its
# SHA-256 digest, together with metadata (when it was taken, from which source, and
# whether it was flagged clean at capture time). Manifests are what let Argus *prove*
# a clone was not tampered with before that clone is ever promoted to become the new
# "main" -- directly satisfying the "a poisoned clone can never become main" requirement.
#
# Two manifests matter downstream:
#   * per-snapshot manifests  -> written every snapshot cycle by Snapshotter
#   * the golden manifest      -> the trusted baseline the whole system is measured against

def is_volatile(rel_path: str, volatile_paths) -> bool:
    """
    True if `rel_path` lies inside one of the declared volatile paths.

    Matches on whole path components. A bare `startswith` made "uploads" also cover
    "uploads_shell.php" -- so an attacker's file only had to be named after the
    allowed directory to be waved through as legitimate churn.
    """
    rel = rel_path.strip("/")
    return any(rel == v.strip("/") or rel.startswith(v.strip("/") + "/")
               for v in volatile_paths if v.strip("/"))


def sha256_file(path: os.PathLike | str) -> str:
    """Return the hex SHA-256 digest of a single file, streamed in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


@dataclass
class Manifest:
    """An immutable-by-convention record of a directory's contents at a moment in time."""

    root: str                      # directory the manifest describes
    created_at: float              # unix epoch seconds
    source: str                    # e.g. "snapshot", "golden", "forensic"
    clean: bool = True             # False if a breach was active when this was captured
    files: Dict[str, str] = field(default_factory=dict)  # relative_path -> sha256

    # ---- construction -----------------------------------------------------
    @classmethod
    def build(cls, root: os.PathLike | str, source: str, clean: bool = True) -> "Manifest":
        """
        Walk *root* and hash every regular file, storing paths relative to root.

        Tolerates files vanishing between the directory walk and the hash: the monitored
        tree is live, and a restore replaces its whole contents, so a scan that races one
        would otherwise raise FileNotFoundError and kill the monitoring process. A file
        that disappears mid-scan is simply omitted -- the next scan sees the settled tree.

        A file that is present but UNREADABLE is a different matter and is recorded with
        the UNREADABLE sentinel rather than skipped. Skipping it would let an attacker (or
        an antivirus lock) hide a dropped file from integrity monitoring by removing its
        read permission.
        """
        root = Path(root)
        files: Dict[str, str] = {}
        for p in sorted(root.rglob("*")):
            try:
                if not p.is_file():
                    continue
                rel = p.relative_to(root).as_posix()
            except OSError:
                continue
            try:
                files[rel] = sha256_file(p)
            except FileNotFoundError:
                continue                      # vanished mid-scan; next scan settles it
            except OSError:
                files[rel] = UNREADABLE
        return cls(root=str(root), created_at=time.time(), source=source,
                   clean=clean, files=files)

    # ---- persistence ------------------------------------------------------
    def save(self, path: os.PathLike | str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: os.PathLike | str) -> "Manifest":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(**json.load(fh))

    # ---- verification -----------------------------------------------------
    @staticmethod
    def _same(a: str, b: str) -> bool:
        """Digest equality, except that an unreadable file never matches anything."""
        return a == b and a != UNREADABLE

    def verify(self, root: os.PathLike | str) -> Tuple[bool, List[str]]:
        """
        Re-hash *root* and compare against this manifest.

        Returns (ok, discrepancies). A discrepancy is any file that is missing,
        extra, or whose hash differs. This is the gate the healer calls before it
        will promote a clone: a single mismatch means the clone is rejected.
        """
        current = Manifest.build(root, source="verify", clean=True).files
        problems: List[str] = []
        for rel, digest in self.files.items():
            if rel not in current:
                problems.append(f"missing: {rel}")
            elif not self._same(current[rel], digest):
                problems.append(f"modified: {rel}")
        for rel in current:
            if rel not in self.files:
                problems.append(f"unexpected: {rel}")
        return (len(problems) == 0, problems)

    def diff_against_golden(self, golden: "Manifest") -> List[str]:
        """
        List files that deviate from the trusted golden baseline.

        Used to decide whether a *snapshot* is safe to mark clean: a snapshot that
        introduces unexpected files in the protected root (e.g. a dropped webshell)
        is refused clean status even if no live alert fired -- this is what defends
        against a slow-burn compromise quietly poisoning several clone cycles.

        Three deviation classes, mirroring `verify`: `new:` (not in golden), `changed:`
        (hash differs) and `missing:` (in golden, absent here). The last one matters:
        without it, deleting the site is invisible and a half-deleted snapshot would be
        marked clean and become eligible as a restore source.
        """
        deviations: List[str] = []
        allowed = set(golden.files)
        for rel, digest in self.files.items():
            if rel not in allowed:
                deviations.append(f"new: {rel}")
            elif not self._same(golden.files[rel], digest):
                deviations.append(f"changed: {rel}")
        for rel in golden.files:
            if rel not in self.files:
                deviations.append(f"missing: {rel}")
        return deviations


# ============================================================================
# Forensics -- evidence preservation (formerly forensics.py)
# ============================================================================
# Before the healer destroys a compromised instance, we capture its state so the Results
# chapter has *real attack data* instead of destroyed evidence.
#
# Two artefacts per incident, written to results/forensics/<incident_id>/:
#   * a filesystem snapshot of the protected path (with its own manifest, marked clean=False)
#   * a docker commit image id of the frozen container (captured via DockerOps)
#   * a metadata.json describing the incident
#
# This class owns only the filesystem side; the container commit is delegated to
# DockerOps so this stays unit-testable without a daemon.

class Forensics:
    def __init__(self, forensics_root: str | Path):
        self.root = Path(forensics_root)
        self.root.mkdir(parents=True, exist_ok=True)

    def open_case(self, incident_id: str) -> Path:
        case = self.root / incident_id
        case.mkdir(parents=True, exist_ok=True)
        return case

    def preserve_files(self, incident_id: str, captured_dir: Path) -> Path:
        """
        Given a host directory already copied out of the compromised container,
        hash it into a manifest explicitly marked NOT clean, so it can never be
        mistaken for a restore source.
        """
        case = self.open_case(incident_id)
        m = Manifest.build(captured_dir, source="forensic", clean=False)
        m.save(case / "forensic_manifest.json")
        return case / "forensic_manifest.json"

    def write_metadata(self, incident_id: str, detail: str,
                       committed_image: Optional[str]) -> Path:
        case = self.open_case(incident_id)
        meta = {
            "incident_id": incident_id,
            "captured_at": time.time(),
            "detection_detail": detail,
            "committed_image": committed_image,
        }
        path = case / "metadata.json"
        path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return path


# ============================================================================
# Snapshotter -- periodic hash-verified clones (formerly snapshotter.py)
# ============================================================================
# On every cadence tick (10-20 min) it:
#   1. copies the protected directory out of the main container to a timestamped clone,
#   2. builds a SHA-256 manifest of that clone,
#   3. decides whether the clone is *verified-clean* by (a) checking no breach was active
#      and (b) diffing the clone's manifest against the golden manifest, ignoring paths
#      explicitly declared volatile (e.g. an uploads dir),
#   4. prunes old snapshots to keep the last N.
#
# Marking a snapshot clean=False when it deviates from golden is the defence against a
# slow-burn compromise silently poisoning several clone cycles: such a clone is retained
# (for forensics) but is never eligible as a restore source.

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
        return is_volatile(rel_path, self.cfg.volatile_paths)

    def take(self, breach_active: bool = False) -> Snapshot:
        # microsecond suffix: two snapshots inside the same second must not merge
        dest = self.base / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        # A capture that had to drop archive members is incomplete, and an incomplete
        # copy can still hash consistently against itself. Keep it (evidence) but never
        # let it be a restore source.
        incomplete = False
        try:
            self._copy_out(self.cfg.protected_container, self.cfg.protected_path, dest)
        except IncompleteCapture:
            incomplete = True

        clean = not (breach_active or incomplete)
        manifest = Manifest.build(dest, source="snapshot", clean=clean)

        # golden diff (ignoring declared volatile paths)
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
        keep = max(1, self.cfg.keep_snapshots)   # 0 must not mean "keep everything"
        for old in snaps[:-keep]:
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


# ============================================================================
# Incident / MetricsLog -- the experimental record (formerly metrics.py)
# ============================================================================
# Every incident is timestamped at four points so the two headline resilience metrics
# fall straight out of the arithmetic:
#
#     t_attack   - when the (simulated) attack artefact was injected  [known to harness]
#     t_detect   - when Argus raised the breach signal
#     t_restored - when a verified-clean instance passed its health check
#     t_promoted - when that instance became the new main
#
#     MTTD = t_detect  - t_attack     (Mean Time To Detect)
#     MTTR = t_promoted - t_detect    (Mean Time To Recover)
#
# False positives are logged separately: a detection with no injected attack behind it.
# The reported rate is false_positives / detections -- the share of alarms that were false
# (a false-discovery rate). It is NOT the classical FPR, which needs a count of
# true-negative windows that the controller does not record; report it under its own name.

@dataclass
class Incident:
    incident_id: str
    scenario: str                 # e.g. "webshell", "deface", "benign"
    t_attack: Optional[float]     # None for benign/FP runs
    t_detect: Optional[float]
    t_restored: Optional[float]
    t_promoted: Optional[float]
    detected_by: str = ""         # "signature" | "anomaly" | "both" | ""
    false_positive: bool = False
    restore_source: str = ""      # "snapshot:<ts>" | "golden"
    # "healed" | "verify_failed" | "health_failed". A heal that did not end in a verified,
    # healthy, promoted instance is recorded as a row instead of vanishing from the stats.
    heal_outcome: str = ""

    @property
    def mttd(self) -> Optional[float]:
        if self.t_attack is None or self.t_detect is None:
            return None
        return round(self.t_detect - self.t_attack, 3)

    @property
    def mttr(self) -> Optional[float]:
        if self.t_detect is None or self.t_promoted is None:
            return None
        return round(self.t_promoted - self.t_detect, 3)

    @property
    def total_recovery(self) -> Optional[float]:
        """
        End-to-end exposure: attack injected -> service healthy again.

        Report this alongside MTTR, not instead of it. MTTR starts the clock at *detection*,
        so in the manual arm the operator-notice delay lands in MTTD and cancels out of the
        MTTR comparison -- which makes the two arms look nearly identical even though the
        human gap is precisely what the controller removes. This metric is where that gap
        is visible, and it is the fair arm-to-arm comparison of time-to-service-restored.
        """
        if self.t_attack is None or self.t_promoted is None:
            return None
        return round(self.t_promoted - self.t_attack, 3)


class MetricsLog:
    """Append-only incident log with a summary reducer for the Results chapter."""

    HEADER = [f.name for f in fields(Incident)] + ["mttd", "mttr", "total_recovery"]

    def __init__(self, csv_path: str | Path):
        self.path = Path(csv_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            with open(self.path, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(self.HEADER)
        else:
            self._migrate_header()

    def _migrate_header(self) -> None:
        """
        Bring a CSV written by an older version up to the current columns.

        Appending new-format rows under an old header would silently misalign every column,
        so the file is rewritten once. The original is kept alongside as `<name>.bak`
        (never overwritten): this is experimental data and must not be lost to a refactor.
        """
        with open(self.path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
            fh.seek(0)
            header = next(csv.reader(fh), [])
        if header == self.HEADER:
            return
        backup = self.path.with_name(self.path.name + ".bak")
        if not backup.exists():
            shutil.copy2(self.path, backup)
        with open(self.path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=self.HEADER, extrasaction="ignore",
                               restval="")
            w.writeheader()
            for r in rows:
                if not r.get("heal_outcome"):
                    promoted = r.get("t_promoted") not in ("", "None", None)
                    r["heal_outcome"] = "healed" if promoted else "legacy_no_outcome"
                w.writerow(r)

    def record(self, inc: Incident) -> None:
        # The file can disappear while the controller runs (an operator or a demo script
        # clearing it). Re-create the header rather than appending a headerless row, which
        # would make the first incident be read back as the column names.
        if not self.path.exists() or self.path.stat().st_size == 0:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(self.HEADER)
        row = asdict(inc)
        row["mttd"] = inc.mttd
        row["mttr"] = inc.mttr
        row["total_recovery"] = inc.total_recovery
        with open(self.path, "a", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=self.HEADER).writerow(row)

    # ---- reducers used by the Results chapter -----------------------------
    def load(self) -> List[dict]:
        with open(self.path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    @staticmethod
    def summary(values: List[float]) -> dict:
        """Descriptive stats an examiner expects: n, mean, median, stdev, min, max."""
        if not values:
            return {"n": 0}
        return {
            "n": len(values),
            "mean": round(statistics.mean(values), 3),
            "median": round(statistics.median(values), 3),
            "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
            "min": round(min(values), 3),
            "max": round(max(values), 3),
        }

    def report(self) -> dict:
        rows = self.load()
        mttd = [float(r["mttd"]) for r in rows if r.get("mttd") not in ("", "None", None)]
        mttr = [float(r["mttr"]) for r in rows if r.get("mttr") not in ("", "None", None)]
        total = [float(r["total_recovery"]) for r in rows
                 if r.get("total_recovery") not in ("", "None", None)]
        fps = sum(1 for r in rows if r.get("false_positive") in ("True", "true", True))
        detections = sum(1 for r in rows if r.get("t_detect") not in ("", "None", None))
        failed = sum(1 for r in rows
                     if r.get("heal_outcome") in ("verify_failed", "health_failed"))
        return {
            "MTTD_sec": self.summary(mttd),
            "MTTR_sec": self.summary(mttr),
            "TotalRecovery_sec": self.summary(total),
            "detections": detections,
            "false_positives": fps,
            "false_discovery_rate": round(fps / detections, 4) if detections else 0.0,
            "failed_heals": failed,
        }
