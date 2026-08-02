"""
config.py
=========
Single typed entry point for all tunables. Everything an examiner might ask you to
justify -- snapshot cadence, the anomaly threshold, health-check retries -- lives in
config/argus.yaml and is surfaced here as one dataclass, so there are no magic
numbers scattered through the codebase.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover - yaml is a hard dependency at runtime
    yaml = None


@dataclass
class ArgusConfig:
    # --- what we protect ---------------------------------------------------
    protected_container: str = "argus-web"          # name/label of the "main" instance
    golden_image: str = "argus/dvwa-golden:latest"  # known-good baseline image
    protected_path: str = "/var/www/html"           # path *inside* the container to guard
    host_webroot: str = "runtime/webroot"           # the HOST side of the bind mount
    isolated_network: str = "argus_protected"       # docker network the main sits on
    health_url: str = "http://localhost:8080/login.php"  # promotion health check
    host_port: int = 8080                           # host port published by a restored main

    # --- snapshot / clone cadence -----------------------------------------
    snapshot_interval_sec: int = 900                 # 15 min (spec: 10-20 min)
    snapshots_dir: str = "results/snapshots"
    golden_manifest: str = "config/golden_manifest.json"
    # pristine CONTENT copy of the golden web root, written by `init-golden` alongside the
    # manifest. The manifest only stores hashes, so a restore needs real files that are
    # guaranteed to match it -- both are produced from the same source in one step.
    golden_webroot: str = "runtime/golden_webroot"
    keep_snapshots: int = 12                         # retain last N cycles

    # --- detection ---------------------------------------------------------
    wazuh_alerts_path: str = "runtime/wazuh_alerts.json"  # tailed alert stream
    breach_signal_path: str = "runtime/breach.flag"       # active-response drop file
    # The experiment harness records the injection time here so the long-running daemon
    # can attribute a detection to a known attack and therefore compute MTTD. Absent this
    # marker a detection is (correctly) treated as a false positive.
    attack_marker_path: str = "runtime/attack_marker.json"
    anomaly_threshold: float = -0.15                 # IsolationForest score cutoff
    anomaly_model_path: str = "results/anomaly_model.joblib"

    # --- healing / forensics ----------------------------------------------
    forensics_dir: str = "results/forensics"
    # `docker commit` of the compromised container freezes its full filesystem state --
    # maximum evidence fidelity, but ~1 GB of image per incident, so a 20-trial run costs
    # ~20 GB. The filesystem capture of the protected path happens either way; turn this
    # off for long measurement runs and note the trade-off in your write-up.
    commit_forensic_image: bool = True
    health_retries: int = 10
    health_retry_delay_sec: float = 2.0

    # --- metrics -----------------------------------------------------------
    incidents_csv: str = "results/incidents.csv"

    # rules describing which sub-paths are allowed to change between snapshots
    # (e.g. an uploads dir) so we do not treat legitimate churn as tampering.
    volatile_paths: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path = "config/argus.yaml") -> "ArgusConfig":
        path = Path(path)
        if yaml is None or not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        known = {f: data[f] for f in cls.__dataclass_fields__ if f in data}
        return cls(**known)
