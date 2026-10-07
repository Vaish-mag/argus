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
from typing import List, Optional

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
    # Interface the restored main's port binds to. Loopback by default: this is a
    # deliberately vulnerable app and must not be reachable from the LAN. Publishing to
    # "0.0.0.0" is the Docker default and is what an unqualified `ports={...: 8080}` gives.
    host_bind: str = "127.0.0.1"

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
    # IsolationForest score cutoff. None (the default) means "use the boundary the model
    # calibrated at training time" -- see detection.AnomalyDetector.cutoff. A literal number
    # is an override and must be on the score_samples scale (about -0.4 .. -0.7 for normal
    # data); the old -0.15 sat above every normal window and flagged all of them.
    anomaly_threshold: Optional[float] = None
    # An alarm triggers a destructive heal, so require this many consecutive anomalous
    # windows before acting (signature evidence is never delayed by this).
    anomaly_confirm_windows: int = 3
    # Where HostSensor reads HTTP access-log lines. Must be OUTSIDE the monitored web
    # root, or every request would read as file tampering.
    access_log_path: str = "runtime/logs/access.log"
    # An attack marker older than this is stale (a trial that timed out and was never
    # consumed) and must not be attributed to a later, unrelated detection.
    attack_marker_max_age_sec: float = 300.0
    anomaly_model_path: str = "results/anomaly_model.joblib"

    # --- healing / forensics ----------------------------------------------
    forensics_dir: str = "results/forensics"
    # `docker commit` of the compromised container freezes its full filesystem state --
    # maximum evidence fidelity, but ~1 GB of image per incident, so a 20-trial run costs
    # ~20 GB, and that growing disk/Docker load is itself a confounder for whichever
    # experiment arm runs second. Off by default; the filesystem capture of the protected
    # path happens either way. Turn it on for evidence-grade runs, and say which you used.
    commit_forensic_image: bool = False
    # 25 x 2s = 50s: DVWA needs ~15-20s for MySQL + Apache, and a cold start is slower,
    # so a 20s budget expired on the first restarts of a run and silently dropped those
    # trials from the results.
    health_retries: int = 25
    health_retry_delay_sec: float = 2.0

    # --- metrics -----------------------------------------------------------
    incidents_csv: str = "results/incidents.csv"

    # rules describing which sub-paths are allowed to change between snapshots
    # (e.g. an uploads dir) so we do not treat legitimate churn as tampering.
    volatile_paths: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path = "config/argus.yaml") -> "ArgusConfig":
        """
        Load a config file, strictly.

        A missing file or an unknown key is an error, not a fallback. Silently using the
        defaults would, for example, point `--config config/target2.yaml` (mistyped) at
        the DVWA container -- and a typo'd key would change nothing and warn about nothing.
        """
        path = Path(path)
        if yaml is None:
            raise RuntimeError("PyYAML is required to load a config file")
        if not path.exists():
            raise FileNotFoundError(f"config file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        unknown = sorted(set(data) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError(f"unknown config key(s) in {path}: {', '.join(unknown)}")
        return cls(**data)
