"""
Unit + integration tests for Argus.

The integration test (`test_controller_full_heal_loop`) is the important one for the
viva: it exercises detect -> forensic -> isolate -> destroy -> restore -> verify ->
promote end to end using a FakeDocker, proving the resilience logic is correct
independently of any live daemon.

Run:  cd argus && python -m pytest -q
"""
import json
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from argus.config import ArgusConfig
from argus.healer import Healer
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


def test_manifest_build_survives_file_vanishing_mid_scan(tmp_path, monkeypatch):
    """
    Regression: a restore replaces the whole web root while the FIM scan is walking it.
    Manifest.build used to raise FileNotFoundError, which killed the watcher process --
    after which nothing detected anything and every later trial timed out.
    """
    import argus.manifest as manifest_mod

    root = tmp_path / "web"
    root.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (root / name).write_text(name)

    real_sha = manifest_mod.sha256_file
    state = {"n": 0}

    def flaky_sha(path):
        state["n"] += 1
        if state["n"] == 2:                       # simulate deletion mid-walk
            raise FileNotFoundError(f"vanished: {path}")
        return real_sha(path)

    monkeypatch.setattr(manifest_mod, "sha256_file", flaky_sha)

    m = manifest_mod.Manifest.build(root, source="test")
    assert len(m.files) == 2, "the vanished file is skipped, the scan still completes"


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
    # end-to-end recovery spans attack -> promoted (i1: 112-100, i2: 210-200)
    assert rep["TotalRecovery_sec"]["n"] == 2
    assert rep["TotalRecovery_sec"]["mean"] == pytest.approx(11.0)


def test_total_recovery_exposes_notice_delay_hidden_by_mttr():
    """
    The manual arm folds the operator-notice delay into MTTD, so an MTTR-only comparison
    makes the two arms look equivalent. total_recovery is what surfaces the real gap.
    """
    notice_delay = 30.0
    argus = Incident("a", "webshell", t_attack=100.0, t_detect=102.0,
                     t_restored=115.0, t_promoted=117.0, detected_by="signature")
    manual = Incident("b", "webshell", t_attack=100.0,
                      t_detect=100.0 + notice_delay,
                      t_restored=145.0, t_promoted=147.0, detected_by="manual")

    # repair phases are near-identical -> MTTR alone shows almost no benefit
    assert argus.mttr == pytest.approx(15.0)
    assert manual.mttr == pytest.approx(17.0)

    # end-to-end tells the real story: 17s vs 47s
    assert argus.total_recovery == pytest.approx(17.0)
    assert manual.total_recovery == pytest.approx(47.0)
    assert manual.total_recovery - argus.total_recovery == pytest.approx(notice_delay)


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
    Simulates the protected service. `live_root` is the HOST side of the web-root bind
    mount, which is deliberately modelled: it survives container removal (as a real bind
    mount does), so a heal that only rebuilt the container while leaving the host
    directory dirty would be visible here rather than passing silently.
    """
    def __init__(self, golden_src: Path, live_root: Path):
        self.golden_src = golden_src
        self.live_root = live_root          # host dir bind-mounted to /var/www/html
        self.network_connected = True
        self.removed = False
        self.committed = []
        self.run_calls = []                 # records image/ports/volumes per launch

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

    def seed_from_image(self, image, container_path, host_dir):
        """Extract the golden image's content -- the last-resort restore source."""
        host_dir = Path(host_dir)
        host_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.golden_src, host_dir, dirs_exist_ok=True)
        return host_dir

    def commit_forensic(self, name, repository, tag):
        self.committed.append(tag)
        return f"sha256:{tag}"

    def disconnect_network(self, name, network):
        self.network_connected = False

    def connect_network(self, name, network):
        self.network_connected = True

    def stop_and_remove(self, name):
        # The container goes away; the bind-mounted HOST directory does not.
        self.removed = True

    def run(self, image, name, network, ports=None, volumes=None):
        self.run_calls.append({"image": image, "ports": ports, "volumes": volumes})
        self.removed = False
        return object()

    def http_ok(self, url, timeout=3.0):
        # healthy once index.html is present in the (restored) web root
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
        protected_path="/var/www/html",        # path INSIDE the container
        host_webroot=str(live),                # HOST side of the bind mount
        snapshots_dir=str(snaps),
        golden_manifest=str(ws / "config" / "golden_manifest.json"),
        golden_webroot=str(golden_src),
        forensics_dir=str(ws / "results" / "forensics"),
        incidents_csv=str(ws / "results" / "incidents.csv"),
        breach_signal_path=str(ws / "runtime" / "breach.flag"),
        wazuh_alerts_path=str(ws / "runtime" / "wazuh_alerts.json"),
        attack_marker_path=str(ws / "runtime" / "attack_marker.json"),
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

    # the replacement container must keep the web-root bind mount, otherwise the host
    # directory FIM watches would drift away from what the container serves
    assert fake.run_calls, "a replacement container should have been launched"
    volumes = fake.run_calls[-1]["volumes"]
    assert volumes and str(Path(live).resolve()) in volumes
    assert volumes[str(Path(live).resolve())]["bind"] == "/var/www/html"

    # incident persisted to CSV
    assert Path(cfg.incidents_csv).exists()
    assert len(MetricsLog(cfg.incidents_csv).load()) == 1


def test_heal_leaves_no_residual_breach_signal(tmp_path):
    """
    Regression: a heal must clean the HOST web root, not just the container.

    If the attacker's artefact survives on the host, the FIM gate re-detects it on the
    very next poll and the controller heals forever. We assert the post-heal web root
    verifies clean against golden, which is exactly what the watcher checks.
    """
    from argus.fim_watch import FIMWatcher

    ws = tmp_path
    (ws / "config").mkdir()
    golden_src = ws / "golden_src"
    _write_web(golden_src)
    live = ws / "live_web"
    _write_web(live)

    golden_manifest = ws / "config" / "golden_manifest.json"
    Manifest.build(golden_src, source="golden").save(golden_manifest)

    cfg = ArgusConfig(
        protected_path="/var/www/html",
        host_webroot=str(live),
        snapshots_dir=str(ws / "results" / "snapshots"),
        golden_manifest=str(golden_manifest),
        golden_webroot=str(golden_src),
        forensics_dir=str(ws / "results" / "forensics"),
        incidents_csv=str(ws / "results" / "incidents.csv"),
        breach_signal_path=str(ws / "runtime" / "breach.flag"),
        wazuh_alerts_path=str(ws / "runtime" / "wazuh_alerts.json"),
        attack_marker_path=str(ws / "runtime" / "attack_marker.json"),
        health_retries=3,
        health_retry_delay_sec=0.01,
    )

    # attack: artefact on the host web root + a breach flag
    (live / "shell.php").write_text("<?php /* benign lab marker */ ?>")
    Path(cfg.breach_signal_path).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg.breach_signal_path).write_text("fim_watch: new: shell.php")

    fake = FakeDocker(golden_src, live)
    controller = ArgusController(cfg, fake)
    inc = controller.tick(t_attack=time.time(), scenario="webshell")
    assert inc is not None and inc.t_promoted is not None

    # the watcher must now see a clean web root -> no second breach, no heal loop
    assert FIMWatcher(cfg, live).check_once() == []
    assert controller.tick() is None, "no residual breach signal should remain"


def test_signal_raised_during_heal_does_not_double_count(tmp_path):
    """
    Regression: detection runs in its own process and keeps polling throughout a heal, so
    it re-raises the flag for an artefact that is still on disk during the early phases.
    That stale edge used to be counted as a second incident with no attack marker --
    inflating the incident count and the false-positive rate.
    """
    ws = tmp_path
    (ws / "config").mkdir()
    golden_src = ws / "golden_src"
    _write_web(golden_src)
    live = ws / "live_web"
    _write_web(live)
    Manifest.build(golden_src, source="golden").save(ws / "config" / "golden_manifest.json")

    cfg = ArgusConfig(
        protected_path="/var/www/html",
        host_webroot=str(live),
        snapshots_dir=str(ws / "results" / "snapshots"),
        golden_manifest=str(ws / "config" / "golden_manifest.json"),
        golden_webroot=str(golden_src),
        forensics_dir=str(ws / "results" / "forensics"),
        incidents_csv=str(ws / "results" / "incidents.csv"),
        breach_signal_path=str(ws / "runtime" / "breach.flag"),
        wazuh_alerts_path=str(ws / "runtime" / "wazuh_alerts.json"),
        attack_marker_path=str(ws / "runtime" / "attack_marker.json"),
        health_retries=3,
        health_retry_delay_sec=0.01,
    )

    (live / "shell.php").write_text("x")
    flag = Path(cfg.breach_signal_path)
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text("fim_watch: new: shell.php")

    fake = FakeDocker(golden_src, live)

    # simulate the watcher re-arming the flag mid-heal
    original_heal = Healer.heal

    def heal_then_rearm(self, incident_id, detail):
        result = original_heal(self, incident_id, detail)
        flag.write_text("fim_watch: new: shell.php")   # racing watcher write
        return result

    controller = ArgusController(cfg, fake)
    controller.healer.heal = heal_then_rearm.__get__(controller.healer, Healer)

    inc = controller.tick(t_attack=time.time(), scenario="webshell")
    assert inc is not None and inc.t_promoted is not None

    assert controller.tick() is None, "in-flight signal must not become a second incident"
    assert len(MetricsLog(cfg.incidents_csv).load()) == 1


def test_daemon_mode_measures_mttd_via_attack_marker(tmp_path):
    """
    Regression: in daemon mode the controller gets no t_attack argument, so without the
    marker handoff MTTD is unmeasurable and every real incident is mislabelled a false
    positive. Here tick() takes no arguments, as the daemon loop calls it.
    """
    ws = tmp_path
    (ws / "config").mkdir()
    golden_src = ws / "golden_src"
    _write_web(golden_src)
    live = ws / "live_web"
    _write_web(live)
    Manifest.build(golden_src, source="golden").save(ws / "config" / "golden_manifest.json")

    cfg = ArgusConfig(
        protected_path="/var/www/html",
        host_webroot=str(live),
        snapshots_dir=str(ws / "results" / "snapshots"),
        golden_manifest=str(ws / "config" / "golden_manifest.json"),
        golden_webroot=str(golden_src),
        forensics_dir=str(ws / "results" / "forensics"),
        incidents_csv=str(ws / "results" / "incidents.csv"),
        breach_signal_path=str(ws / "runtime" / "breach.flag"),
        wazuh_alerts_path=str(ws / "runtime" / "wazuh_alerts.json"),
        attack_marker_path=str(ws / "runtime" / "attack_marker.json"),
        health_retries=3,
        health_retry_delay_sec=0.01,
    )

    t_attack = time.time()
    marker = Path(cfg.attack_marker_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"t_attack": t_attack, "scenario": "webshell"}))

    (live / "shell.php").write_text("x")
    Path(cfg.breach_signal_path).write_text("fim_watch: new: shell.php")

    controller = ArgusController(cfg, FakeDocker(golden_src, live))
    inc = controller.tick()                      # no arguments -- as the daemon calls it

    assert inc is not None
    assert inc.mttd is not None and inc.mttd >= 0, "MTTD must be measurable in daemon mode"
    assert inc.false_positive is False, "a marked attack is not a false positive"
    assert inc.scenario == "webshell"
    assert not marker.exists(), "the marker should be consumed exactly once"


def test_copy_out_strips_docker_archive_wrapper_dir():
    """
    Regression: `docker cp`-style archives wrap contents in a directory named after the
    source path, so extracting verbatim produced manifest keys like "html/index.php".
    Those never match a golden manifest keyed "index.php", so every snapshot was marked
    unclean and the verified-clean restore path could never be selected.
    """
    import io
    import tarfile
    from argus.docker_ops import DockerOps

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, body in [("html/index.php", b"home"), ("html/sub/app.php", b"app")]:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    buf.seek(0)

    with tempfile.TemporaryDirectory() as tmp:
        out = DockerOps._extract_stripped([buf.read()], "/var/www/html", Path(tmp))
        keys = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
        assert keys == ["index.php", "sub/app.php"], f"wrapper dir not stripped: {keys}"
