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
    isolated_network: str = "argus_protected"       # docker network the main sits on
    health_url: str = "http://localhost:8080/login.php"  # promotion health check

    # --- snapshot / clone cadence -----------------------------------------
    snapshot_interval_sec: int = 900                 # 15 min (spec: 10-20 min)
    snapshots_dir: str = "results/snapshots"
    golden_manifest: str = "config/golden_manifest.json"
    keep_snapshots: int = 12                         # retain last N cycles

    # --- detection ---------------------------------------------------------
    wazuh_alerts_path: str = "runtime/wazuh_alerts.json"  # tailed alert stream
    breach_signal_path: str = "runtime/breach.flag"       # active-response drop file
    anomaly_threshold: float = -0.15                 # IsolationForest score cutoff
    anomaly_model_path: str = "results/anomaly_model.joblib"

    # --- healing / forensics ----------------------------------------------
    forensics_dir: str = "results/forensics"
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
