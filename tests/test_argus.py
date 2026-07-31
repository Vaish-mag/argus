"""
Unit + integration tests for Argus.

The integration test (`test_controller_full_heal_loop`) is the important one for the
viva: it exercises detect -> forensic -> isolate -> destroy -> restore -> verify ->
promote end to end using a FakeDocker, proving the resilience logic is correct
independently of any live daemon.

Run:  cd argus && python -m pytest -q
"""
import shutil
import time
from pathlib import Path

import pytest

from argus.config import ArgusConfig
from argus.manifest import Manifest, sha256_file
from argus.metrics import Incident, MetricsLog
from argus.controller import ArgusController


# ----------------------------------------------------------------------------
# manifest
# ----------------------------------------------------------------------------
def test_manifest_build_verify_roundtrip(tmp_path):
    root = tmp_path / "web"
    root.mkdir()
    (root / "index.html").write_text("hello")
    (root / "sub").mkdir()
    (root / "sub" / "app.php").write_text("<?php echo 1; ?>")

    m = Manifest.build(root, source="test")
    ok, problems = m.verify(root)
    assert ok and problems == []

    # tamper -> must be caught
    (root / "index.html").write_text("hacked")
    ok, problems = m.verify(root)
    assert not ok and any("modified" in p for p in problems)

    # extra file -> must be caught
    (root / "index.html").write_text("hello")
    (root / "shell.php").write_text("<?php system($_GET['c']); ?>")
    ok, problems = m.verify(root)
    assert not ok and any("unexpected: shell.php" in p for p in problems)


def test_manifest_diff_against_golden(tmp_path):
    golden_root = tmp_path / "golden"
    golden_root.mkdir()
    (golden_root / "index.html").write_text("home")
    golden = Manifest.build(golden_root, source="golden")

    poisoned = tmp_path / "poison"
    poisoned.mkdir()
    (poisoned / "index.html").write_text("home")
    (poisoned / "backdoor.php").write_text("evil")
    pm = Manifest.build(poisoned, source="snapshot")

    devs = pm.diff_against_golden(golden)
    assert any("backdoor.php" in d for d in devs)


def test_manifest_save_load(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "a.txt").write_text("x")
    m = Manifest.build(root, source="test")
    p = tmp_path / "m.json"
    m.save(p)
    m2 = Manifest.load(p)
    assert m2.files == m.files and m2.source == "test"


# ----------------------------------------------------------------------------
# fim_watch (the lightweight Wazuh-free detection fallback)
# ----------------------------------------------------------------------------
def test_fim_watcher_detects_deviation(tmp_path):
    from argus.fim_watch import FIMWatcher

    golden_root = tmp_path / "golden"
    golden_root.mkdir()
    (golden_root / "index.html").write_text("hello")
    golden_manifest_path = tmp_path / "golden_manifest.json"
    Manifest.build(golden_root, source="golden").save(golden_manifest_path)

    live_root = tmp_path / "live"
    live_root.mkdir()
    (live_root / "index.html").write_text("hello")

    cfg = ArgusConfig(golden_manifest=str(golden_manifest_path),
                       breach_signal_path=str(tmp_path / "breach.flag"))
    watcher = FIMWatcher(cfg, live_root)

    assert watcher.check_once() == []  # matches golden -> clean

    (live_root / "shell.php").write_text("evil")
    deviations = watcher.check_once()
    assert any("shell.php" in d for d in deviations)


def test_fim_watcher_ignores_volatile_paths(tmp_path):
    from argus.fim_watch import FIMWatcher

    golden_root = tmp_path / "golden"
    golden_root.mkdir()
    (golden_root / "index.html").write_text("hello")
    golden_manifest_path = tmp_path / "golden_manifest.json"
    Manifest.build(golden_root, source="golden").save(golden_manifest_path)

    live_root = tmp_path / "live"
    (live_root / "uploads").mkdir(parents=True)
    (live_root / "index.html").write_text("hello")
    (live_root / "uploads" / "photo.jpg").write_text("binary-ish")

    cfg = ArgusConfig(golden_manifest=str(golden_manifest_path),
                       breach_signal_path=str(tmp_path / "breach.flag"),
                       volatile_paths=["uploads"])
    watcher = FIMWatcher(cfg, live_root)

    assert watcher.check_once() == []  # declared-volatile churn is not a breach


# ----------------------------------------------------------------------------
# metrics
# ----------------------------------------------------------------------------
def test_metrics_mttd_mttr_and_report(tmp_path):
    log = MetricsLog(tmp_path / "inc.csv")
    log.record(Incident("i1", "webshell", t_attack=100.0, t_detect=104.0,
                         t_restored=110.0, t_promoted=112.0, detected_by="signature"))
    log.record(Incident("i2", "deface", t_attack=200.0, t_detect=203.0,
                         t_restored=209.0, t_promoted=210.0, detected_by="anomaly"))
    log.record(Incident("fp1", "benign", t_attack=None, t_detect=300.0,
                        t_restored=None, t_promoted=None, false_positive=True))

    rep = log.report()
    assert rep["MTTD_sec"]["n"] == 2
    assert rep["MTTD_sec"]["mean"] == pytest.approx(3.5)
    assert rep["MTTR_sec"]["n"] == 2          # FP has no promotion -> excluded
    assert rep["false_positives"] == 1
    assert rep["detections"] == 3
    assert rep["false_positive_rate"] == pytest.approx(1 / 3, abs=1e-3)


# ----------------------------------------------------------------------------
# anomaly (skips cleanly if sklearn missing)
# ----------------------------------------------------------------------------
def test_anomaly_flags_outlier():
    sk = pytest.importorskip("sklearn")
    from argus.anomaly import AnomalyDetector, Window
    import random
    random.seed(0)
    # normal windows: low change/process counts, modest traffic
    normal = [Window([random.uniform(20, 40), random.uniform(3, 6), 0.01, 0.0,
                      0.0, 0.0, random.uniform(5, 15), random.uniform(20, 30),
                      random.uniform(1, 3)]) for _ in range(200)]
    det = AnomalyDetector(contamination=0.02).fit(normal)
    # attack window: file changes + new processes + 5xx spike
    attack = Window([80, 25, 0.2, 0.4, 30, 12, 95, 88, 40])
    normal_probe = Window([30, 4, 0.01, 0.0, 0.0, 0.0, 10, 25, 2])
    assert det.score(attack) < det.score(normal_probe)


# ----------------------------------------------------------------------------
# integration: full heal loop with a fake Docker
# ----------------------------------------------------------------------------
class FakeDocker:
    """
    Simulates a container as a host directory. copy_out/copy_in move files; run()
    recreates the 'container' web root from a golden fixture; http_ok flips to True
    once files have been restored. Enough to drive the whole healer path.
    """
    def __init__(self, golden_src: Path, live_root: Path):
        self.golden_src = golden_src
        self.live_root = live_root          # stands in for /var/www/html of the main
        self.network_connected = True
        self.removed = False
        self.committed = []

    def copy_out(self, name, container_path, host_dir):
        host_dir = Path(host_dir)
        if host_dir.exists():
            shutil.rmtree(host_dir)
        shutil.copytree(self.live_root, host_dir)
        return host_dir

    def copy_in(self, name, host_dir, container_parent):
        if self.live_root.exists():
            shutil.rmtree(self.live_root)
        shutil.copytree(host_dir, self.live_root)

    def commit_forensic(self, name, repository, tag):
        self.committed.append(tag)
        return f"sha256:{tag}"

    def disconnect_network(self, name, network):
        self.network_connected = False

    def connect_network(self, name, network):
        self.network_connected = True

    def stop_and_remove(self, name):
        self.removed = True
        if self.live_root.exists():
            shutil.rmtree(self.live_root)   # container destroyed

    def run(self, image, name, network, ports=None):
        # rebuild a pristine (empty-ish) web root from the golden image base
        self.live_root.mkdir(parents=True, exist_ok=True)
        self.removed = False
        return object()

    def http_ok(self, url, timeout=3.0):
        # healthy once index.html has been restored into the live root
        return (self.live_root / "index.html").exists()


def _write_web(root: Path, extra=None):
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text("<h1>Argus target</h1>")
    (root / "login.php").write_text("<?php /* login */ ?>")
    if extra:
        for name, content in extra.items():
            (root / name).write_text(content)


def test_controller_full_heal_loop(tmp_path, monkeypatch):
    # --- lay out a fake workspace ---
    ws = tmp_path
    (ws / "config").mkdir()
    golden_src = ws / "golden_src"
    _write_web(golden_src)                                   # pristine baseline content
    live = ws / "live_web"
    _write_web(live, extra={"index.html": "<h1>Argus target</h1>"})

    # a clean snapshot already exists on disk (the restore source)
    snaps = ws / "results" / "snapshots"
    snap_dir = snaps / "20260101-000000"
    _write_web(snap_dir)
    Manifest.build(snap_dir, source="snapshot", clean=True).save(
        snap_dir.with_suffix(".manifest.json"))

    # golden manifest
    Manifest.build(golden_src, source="golden").save(ws / "config" / "golden_manifest.json")

    cfg = ArgusConfig(
        protected_container="argus-web",
        golden_image="argus/dvwa-golden:latest",
        protected_path=str(live),
        snapshots_dir=str(snaps),
        golden_manifest=str(ws / "config" / "golden_manifest.json"),
        forensics_dir=str(ws / "results" / "forensics"),
        incidents_csv=str(ws / "results" / "incidents.csv"),
        breach_signal_path=str(ws / "runtime" / "breach.flag"),
        wazuh_alerts_path=str(ws / "runtime" / "wazuh_alerts.json"),
        health_retries=3,
        health_retry_delay_sec=0.01,
    )

    fake = FakeDocker(golden_src, live)
    controller = ArgusController(cfg, fake)

    # --- SIMULATE ATTACK: a webshell appears in the live web root, and Wazuh
    #     active-response drops a breach flag (both are pure filesystem effects) ---
    (Path(live) / "shell.php").write_text("<?php /* benign lab marker */ ?>")
    Path(cfg.breach_signal_path).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg.breach_signal_path).write_text("FIM: unexpected file shell.php in web root")

    t_attack = time.time()
    inc = controller.tick(t_attack=t_attack, scenario="webshell")

    # --- assertions: the loop healed correctly ---
    assert inc is not None, "breach should have been detected"
    assert inc.detected_by == "signature"
    assert inc.t_promoted is not None, "new main should have been promoted"
    assert inc.restore_source.startswith("snapshot:")
    assert inc.mttr is not None and inc.mttr >= 0

    # forensic evidence captured BEFORE destruction, and marked not-clean
    case = ws / "results" / "forensics" / inc.incident_id
    fm = Manifest.load(case / "forensic_manifest.json")
    assert fm.clean is False
    assert "shell.php" in fm.files, "the attack artefact must be preserved as evidence"
    assert fake.committed, "container should have been committed for forensics"

    # the restored live root is clean again (no shell.php)
    assert not (Path(live) / "shell.php").exists()
    assert (Path(live) / "index.html").exists()

    # incident persisted to CSV
    assert Path(cfg.incidents_csv).exists()
    assert len(MetricsLog(cfg.incidents_csv).load()) == 1
