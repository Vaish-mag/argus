"""
forensics.py
============
Evidence preservation. Before the healer destroys a compromised instance, we capture
its state so the Results chapter has *real attack data* instead of destroyed evidence
(one of the built-in enhancements).

Two artefacts per incident, written to results/forensics/<incident_id>/:
  * a filesystem snapshot of the protected path (with its own manifest, marked clean=False)
  * a docker commit image id of the frozen container (captured via DockerOps)
  * a metadata.json describing the incident

This module owns only the filesystem side; the container commit is delegated to
DockerOps so this stays unit-testable without a daemon.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from .manifest import Manifest


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
