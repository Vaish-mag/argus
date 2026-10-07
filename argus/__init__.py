"""
Argus: a self-healing, moving-target-defence controller for containerised services.

Five modules, one per stage (or pair of stages) of the MAPE-K resilience loop:

    config       - typed configuration loaded from config/argus.yaml
    storage      - Knowledge: manifests, forensics, snapshots, MTTD/MTTR metrics
    detection    - Monitor + Analyse: anomaly model, signature/FIM fusion, sensors,
                   and the lightweight Wazuh-free file-integrity watcher
    docker_ops   - thin, mockable wrapper over the Docker SDK
    controller   - Plan + Execute: the heal sequence, and the daemon loop that
                   wires everything together

Each module's own docstring explains which former single-purpose files it absorbed
and why they were merged -- see docs/architecture.md for the full picture.
"""

__version__ = "1.0.0"
