"""
manifest.py
===========
Clone-integrity layer.

A *manifest* is a JSON record mapping every file in a protected directory to its
SHA-256 digest, together with metadata (when it was taken, from which source, and
whether it was flagged clean at capture time). Manifests are what let Argus *prove*
a clone was not tampered with before that clone is ever promoted to become the new
"main" -- directly satisfying the "a poisoned clone can never become main" requirement.

Two manifests matter downstream:
  * per-snapshot manifests  -> written every snapshot cycle by snapshotter.py
  * the golden manifest      -> the trusted baseline the whole system is measured against

Nothing here touches Docker, so this module is pure and fully unit-tested.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Tuple

_CHUNK = 1 << 20  # 1 MiB read buffer -- keeps memory flat on large files


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
        """Walk *root* and hash every regular file, storing paths relative to root."""
        root = Path(root)
        files: Dict[str, str] = {}
        for p in sorted(root.rglob("*")):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                files[rel] = sha256_file(p)
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
            elif current[rel] != digest:
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
        """
        deviations: List[str] = []
        allowed = set(golden.files)
        for rel, digest in self.files.items():
            if rel not in allowed:
                deviations.append(f"new: {rel}")
            elif golden.files[rel] != digest:
                deviations.append(f"changed: {rel}")
        return deviations
