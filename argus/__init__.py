"""
Argus: a self-healing, moving-target-defence controller for containerised services.

The package is deliberately split so each stage of the resilience loop is a small,
independently testable unit:

    config       - typed configuration loaded from config/argus.yaml
    manifest     - SHA-256 manifest creation / verification (clone integrity)
    snapshotter  - periodic hash-verified snapshots of protected files
    anomaly      - unsupervised Isolation-Forest anomaly detector (ML layer)
    detector     - fuses Wazuh signature/FIM alerts with anomaly scores
    forensics    - captures evidence from a compromised instance before it is killed
    docker_ops   - thin, mockable wrapper over the Docker SDK
    healer       - isolate -> forensic-snapshot -> destroy -> restore -> re-promote
    metrics      - MTTD / MTTR / false-positive-rate bookkeeping
    controller   - wires everything together into the autonomic MAPE-K loop
"""

__version__ = "1.0.0"
