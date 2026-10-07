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
import sys
import tempfile
import time
from pathlib import Path

import pytest

from argus.config import ArgusConfig
from argus.controller import ArgusController, Healer
from argus.storage import Incident, Manifest, MetricsLog


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
    (root / "shell.php").write_text("<?php /* benign lab marker */ ?>")
    ok, problems = m.verify(root)
    assert not ok and any("unexpected: shell.php" in p for p in problems)


def test_manifest_build_survives_file_vanishing_mid_scan(tmp_path, monkeypatch):
    """
    Regression: a restore replaces the whole web root while the FIM scan is walking it.
    Manifest.build used to raise FileNotFoundError, which killed the watcher process --
    after which nothing detected anything and every later trial timed out.
    """
    import argus.storage as manifest_mod

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
    from argus.detection import FIMWatcher

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
    from argus.detection import FIMWatcher

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
    # share of alarms that were false -- a false-discovery rate, named as such
    assert rep["false_discovery_rate"] == pytest.approx(1 / 3, abs=1e-3)
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
    pytest.importorskip("sklearn")
    from argus.detection import AnomalyDetector, Window
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

    def copy_out(self, name, container_path, host_dir, strict=True):
        host_dir = Path(host_dir)
        if host_dir.exists():
            shutil.rmtree(host_dir)
        shutil.copytree(self.live_root, host_dir)
        return host_dir

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
        commit_forensic_image=True,            # off by default now; this test checks it
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
    from argus.detection import FIMWatcher

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


# ============================================================================
# Audit-fix coverage
# ----------------------------------------------------------------------------
# Everything below pins one finding from docs/AUDIT-FINDINGS.md. Each test would have
# failed against the code as audited; the finding ID is in the docstring.
# ============================================================================
class RecordingDocker(FakeDocker):
    """FakeDocker that also logs the order of the operations the healer performs."""

    def __init__(self, golden_src, live_root, healthy=True):
        super().__init__(golden_src, live_root)
        self.events = []
        self.healthy = healthy              # True | False | int (healthy after N probes)
        self.probes = 0

    def copy_out(self, name, container_path, host_dir, strict=True):
        self.events.append("copy_out")
        return super().copy_out(name, container_path, host_dir, strict)

    def commit_forensic(self, name, repository, tag):
        self.events.append("commit")
        return super().commit_forensic(name, repository, tag)

    def disconnect_network(self, name, network):
        self.events.append("isolate")
        super().disconnect_network(name, network)

    def stop_and_remove(self, name):
        self.events.append("destroy")
        super().stop_and_remove(name)

    def run(self, image, name, network, ports=None, volumes=None):
        self.events.append("launch")
        return super().run(image, name, network, ports, volumes)

    def http_ok(self, url, timeout=3.0):
        self.probes += 1
        if isinstance(self.healthy, bool):
            return self.healthy
        return self.probes > self.healthy


def _workspace(tmp_path, **overrides):
    """A fake workspace + config. Returns (cfg, golden_src, live, snaps_dir)."""
    ws = tmp_path
    (ws / "config").mkdir(exist_ok=True)
    golden_src = ws / "golden_src"
    _write_web(golden_src)
    live = ws / "live_web"
    _write_web(live)
    Manifest.build(golden_src, source="golden").save(ws / "config" / "golden_manifest.json")
    snaps = ws / "results" / "snapshots"
    fields = dict(
        protected_path="/var/www/html",
        host_webroot=str(live),
        snapshots_dir=str(snaps),
        golden_manifest=str(ws / "config" / "golden_manifest.json"),
        golden_webroot=str(golden_src),
        forensics_dir=str(ws / "results" / "forensics"),
        incidents_csv=str(ws / "results" / "incidents.csv"),
        breach_signal_path=str(ws / "runtime" / "breach.flag"),
        wazuh_alerts_path=str(ws / "runtime" / "wazuh_alerts.json"),
        attack_marker_path=str(ws / "runtime" / "attack_marker.json"),
        health_retries=3,
        health_retry_delay_sec=0.0,
    )
    fields.update(overrides)
    return ArgusConfig(**fields), golden_src, live, snaps


def _breach(cfg, live, name="shell.php"):
    (live / name).write_text("x")
    flag = Path(cfg.breach_signal_path)
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text(f"fim_watch: new: {name}")


# ---- C3 / C4: the integrity monitor must not have blind spots --------------------
def test_deleting_a_golden_file_is_a_deviation(tmp_path):
    """C3: diff_against_golden reported new/changed but never missing."""
    from argus.detection import FIMWatcher
    cfg, golden_src, live, _ = _workspace(tmp_path)

    (live / "login.php").unlink()
    devs = Manifest.build(live, source="t").diff_against_golden(
        Manifest.load(cfg.golden_manifest))
    assert devs == ["missing: login.php"]
    assert FIMWatcher(cfg, live).check_once() == ["missing: login.php"]


def test_partially_deleted_snapshot_is_not_clean(tmp_path):
    """C3: a truncated site used to verify against its own hashes and be marked clean."""
    from argus.storage import Snapshotter
    cfg, golden_src, live, _ = _workspace(tmp_path)
    (live / "login.php").unlink()                        # half the site is gone

    snapper = Snapshotter(cfg, FakeDocker(golden_src, live).copy_out)
    snap = snapper.take()
    assert snap.clean is False
    assert snapper.latest_clean() is None, "a truncated clone must never be a restore source"


def test_unreadable_file_is_recorded_not_skipped(tmp_path, monkeypatch):
    """
    A file that cannot be read used to be dropped from the manifest, so removing read
    permission (or an antivirus lock) hid a dropped file from integrity monitoring.
    """
    import argus.storage as storage
    root = tmp_path / "web"
    root.mkdir()
    (root / "index.html").write_text("hello")
    clean = storage.Manifest.build(root, source="t")

    (root / "shell.php").write_text("x")
    real = storage.sha256_file

    def locked(path):
        if str(path).endswith("shell.php"):
            raise PermissionError("denied")
        return real(path)

    monkeypatch.setattr(storage, "sha256_file", locked)
    ok, problems = clean.verify(root)
    assert not ok and "unexpected: shell.php" in problems
    assert storage.Manifest.build(root, source="t").files["shell.php"] == storage.UNREADABLE


def test_unreadable_file_never_matches_even_another_unreadable(tmp_path):
    """Two unreadable files must not 'agree' -- that would hide tampering."""
    from argus.storage import UNREADABLE
    a = Manifest("r", 0.0, "golden", files={"f": UNREADABLE})
    b = Manifest("r", 0.0, "live", files={"f": UNREADABLE})
    assert b.diff_against_golden(a) == ["changed: f"]


def test_incomplete_capture_is_never_clean(tmp_path):
    """C4: a capture that dropped members used to be indistinguishable from a good one."""
    from argus.storage import IncompleteCapture, Snapshotter
    cfg, golden_src, live, _ = _workspace(tmp_path)

    def lossy_copy_out(name, path, dest, strict=True):
        shutil.copytree(live, dest)
        raise IncompleteCapture(["html/odd: permission denied"])

    snapper = Snapshotter(cfg, lossy_copy_out)
    snap = snapper.take()
    assert snap.clean is False
    assert snapper.latest_clean() is None


def test_snapshots_in_the_same_second_do_not_collide(tmp_path):
    """M15: second-granularity names silently merged two snapshots into one directory."""
    from argus.storage import Snapshotter
    cfg, golden_src, live, snaps = _workspace(tmp_path)
    snapper = Snapshotter(cfg, FakeDocker(golden_src, live).copy_out)
    a, b = snapper.take(), snapper.take()
    assert a.path != b.path and a.path.exists() and b.path.exists()


def test_keep_snapshots_zero_does_not_mean_keep_everything(tmp_path):
    """`snaps[:-0]` is an empty slice, so 0 used to disable pruning entirely."""
    from argus.storage import Snapshotter
    cfg, golden_src, live, snaps = _workspace(tmp_path, keep_snapshots=0)
    snapper = Snapshotter(cfg, FakeDocker(golden_src, live).copy_out)
    for _ in range(4):
        snapper.take()
    assert len([p for p in snaps.iterdir() if p.is_dir()]) == 1


def test_volatile_path_matches_whole_components_only():
    """'uploads' used to also cover 'uploads_shell.php' -- the lab's own attack filename."""
    from argus.storage import is_volatile
    assert is_volatile("uploads/photo.jpg", ["uploads"])
    assert is_volatile("uploads", ["uploads"])
    assert not is_volatile("uploads_shell.php", ["uploads"])
    assert not is_volatile("uploads2/x.php", ["uploads/"])


# ---- C2: archives from a compromised container are hostile input -----------------
def _tar_stream(members):
    """members: (name, body, kind) -> a get_archive-style stream (list of bytes)."""
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, body, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = body
                tar.addfile(info)
            else:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
    return [buf.getvalue()]


def test_tar_path_traversal_is_refused_and_never_written(tmp_path):
    from argus.docker_ops import DockerOps
    from argus.storage import IncompleteCapture
    dest = tmp_path / "snap"
    evil = _tar_stream([
        ("html/index.php", b"ok", "file"),
        ("html/../../escaped.txt", b"pwn", "file"),
        ("/etc/abs.txt", b"pwn", "file"),
    ])
    with pytest.raises(IncompleteCapture) as exc:
        DockerOps._extract_stripped(evil, "/var/www/html", dest, strict=True)
    assert len(exc.value.skipped) == 2
    assert not (tmp_path / "escaped.txt").exists()
    assert not list(tmp_path.rglob("abs.txt"))
    assert (dest / "index.php").read_text() == "ok", "safe members are still captured"


def test_tar_best_effort_mode_keeps_evidence_without_raising(tmp_path):
    """Forensics must not lose the whole capture over one bad member."""
    from argus.docker_ops import DockerOps
    dest = tmp_path / "case"
    stream = _tar_stream([("html/a.php", b"a", "file"), ("html/../x", b"x", "file")])
    DockerOps._extract_stripped(stream, "/var/www/html", dest, strict=False)
    assert (dest / "a.php").exists() and not (tmp_path / "x").exists()


def test_tar_symlinks_are_never_extracted(tmp_path):
    """A symlink is how a later member gets written outside the destination."""
    from argus.docker_ops import DockerOps
    dest = tmp_path / "snap"
    outside = tmp_path / "outside"
    outside.mkdir()
    stream = _tar_stream([
        ("html/link", str(outside), "symlink"),
        ("html/link/pwned.txt", b"x", "file"),
        ("html/real.php", b"r", "file"),
    ])
    DockerOps._extract_stripped(stream, "/var/www/html", dest, strict=False)
    assert not any(p.is_symlink() for p in dest.rglob("*")), "no link is ever created"
    assert (dest / "real.php").exists()
    assert not (outside / "pwned.txt").exists(), "nothing may be written through a link"


# ---- C1: the anomaly layer, validated end to end ---------------------------------
def _normal_windows(n, seed):
    import random
    from argus.detection import Window
    r = random.Random(seed)
    return [Window([r.uniform(20, 40), r.uniform(3, 6), 0.01, 0.0, 0.0, 0.0,
                    r.uniform(5, 15), r.uniform(20, 30), r.uniform(1, 3)])
            for _ in range(n)]


def test_anomaly_cutoff_is_calibrated_to_the_model_scale():
    """
    C1: score_samples sits around -0.4..-0.7 for ordinary data, so the fixed -0.15 cutoff
    flagged EVERY window -- an infinite heal loop. The calibrated cutoff must (a) leave
    held-out normal traffic almost entirely alone and (b) still catch attack-shaped windows.
    """
    pytest.importorskip("sklearn")
    from argus.detection import AnomalyDetector, Window
    det = AnomalyDetector(contamination=0.02).fit(_normal_windows(400, seed=1))
    held_out = _normal_windows(500, seed=2)           # independent draw, never trained on

    legacy_fp = sum(det.is_anomaly(w, threshold=-0.15) for w in held_out) / len(held_out)
    fp = sum(det.is_anomaly(w) for w in held_out) / len(held_out)
    assert legacy_fp > 0.99, "documents the original defect: -0.15 flags everything"
    assert fp < 0.06, f"calibrated false-alarm rate too high: {fp:.1%}"

    attacks = {
        "broad compromise":      Window([80, 25, 0.2, 0.4, 30, 12, 95, 88, 40]),
        "scan + error burst":    Window([200, 60, 0.6, 0.3, 5, 3, 70, 60, 25]),
        "file drop only":        Window([30, 4, 0.01, 0.0, 3, 0, 10, 25, 2]),
        "new process only":      Window([30, 4, 0.01, 0.0, 0, 2, 10, 25, 2]),
        "request flood only":    Window([300, 4, 0.01, 0.0, 0, 0, 10, 25, 2]),
    }
    missed = [name for name, w in attacks.items() if not det.is_anomaly(w)]
    assert not missed, f"attack-shaped windows not flagged: {missed}"


def test_forest_alone_is_blind_to_features_that_never_varied():
    """
    The blind spot the range guard exists for: file_change_events / new_process_events are
    constant 0 in normal traffic, IsolationForest cannot split on a constant feature, so a
    window where only those move is scored exactly like the most normal window.
    """
    pytest.importorskip("sklearn")
    from argus.detection import AnomalyDetector, Window
    det = AnomalyDetector().fit(_normal_windows(400, seed=1))
    file_drop = Window([30, 4, 0.01, 0.0, 3, 0, 10, 25, 2])

    assert det.score(file_drop) >= det.cutoff(), "the forest by itself does not see it"
    assert det.out_of_range(file_drop) == ["file_change_events"]
    assert det.is_anomaly(file_drop), "the range guard does"


def test_anomaly_model_roundtrip_keeps_the_range_guard(tmp_path):
    pytest.importorskip("sklearn")
    from argus.detection import AnomalyDetector, Window
    det = AnomalyDetector().fit(_normal_windows(300, seed=1))
    det.save(tmp_path / "m.joblib")
    again = AnomalyDetector.load(tmp_path / "m.joblib")

    drop = Window([30, 4, 0.01, 0.0, 3, 0, 10, 25, 2])
    assert again.is_anomaly(drop) and not again.is_anomaly(_normal_windows(1, seed=9)[0])
    assert again.cutoff() == det.cutoff()


def test_legacy_bare_model_file_still_loads(tmp_path):
    """A model saved before the range guard existed must keep working (guard just off)."""
    pytest.importorskip("sklearn")
    import joblib
    from argus.detection import AnomalyDetector
    det = AnomalyDetector().fit(_normal_windows(300, seed=1))
    joblib.dump(det.model, tmp_path / "old.joblib")
    old = AnomalyDetector.load(tmp_path / "old.joblib")
    assert old.out_of_range(_normal_windows(1, seed=2)[0]) == []
    assert old.cutoff() == det.cutoff()


def test_one_odd_window_does_not_trigger_a_heal(tmp_path):
    """An alarm triggers a destructive heal: it must persist before acting."""
    pytest.importorskip("sklearn")
    from argus.detection import AnomalyDetector, Detector, Window
    cfg, *_ = _workspace(tmp_path, anomaly_confirm_windows=3)
    det = Detector(cfg, AnomalyDetector().fit(_normal_windows(300, seed=3)))
    odd = Window([80, 25, 0.2, 0.4, 30, 12, 95, 88, 40])
    calm = _normal_windows(1, seed=4)[0]

    assert det.evaluate(odd) is None and det.evaluate(odd) is None   # 1st, 2nd
    assert det.evaluate(calm) is None                                # streak resets
    assert det.evaluate(odd) is None and det.evaluate(odd) is None
    ev = det.evaluate(odd)                                           # 3rd in a row
    assert ev is not None and ev.detected_by == "anomaly"


# ---- C5 / C6 / M14: the four resilience guarantees, at policy level ---------------
def test_forensics_are_captured_strictly_before_the_compromised_instance_is_destroyed(tmp_path):
    cfg, golden_src, live, _ = _workspace(tmp_path, commit_forensic_image=True)
    _breach(cfg, live)
    fake = RecordingDocker(golden_src, live)
    ArgusController(cfg, fake).tick(t_attack=time.time(), scenario="webshell")

    assert fake.events == ["copy_out", "commit", "isolate", "destroy", "launch"]


def test_replacement_is_launched_only_after_its_files_verify(tmp_path):
    """C5/C6: the old order started (and published) the container, then verified."""
    cfg, golden_src, live, _ = _workspace(tmp_path)
    _breach(cfg, live)

    observed = {}

    class Spy(RecordingDocker):
        def run(self, image, name, network, ports=None, volumes=None):
            # at the instant of launch the host web root must already be verified-clean
            ok, problems = Manifest.load(cfg.golden_manifest).verify(live)
            observed["verified_at_launch"] = ok
            return super().run(image, name, network, ports, volumes)

    inc = ArgusController(cfg, Spy(golden_src, live)).tick(t_attack=time.time())
    assert observed["verified_at_launch"] is True
    assert inc.heal_outcome == "healed"


def test_unverifiable_restore_never_launches_a_container(tmp_path):
    """
    C5: when verification fails the heal must fail CLOSED -- no container serves the
    unverified files -- and the failure must be recorded, not silently dropped.
    """
    cfg, golden_src, live, _ = _workspace(tmp_path)
    # every restore source is corrupt: the golden copy no longer matches its manifest
    # and the image extraction (also golden_src here) is corrupted the same way
    (golden_src / "index.html").write_text("TAMPERED AFTER MANIFEST WAS TAKEN")
    _breach(cfg, live)

    fake = RecordingDocker(golden_src, live)
    ctrl = ArgusController(cfg, fake)
    inc = ctrl.tick(t_attack=time.time(), scenario="webshell")

    assert "launch" not in fake.events, "nothing unverified may ever be started"
    assert inc is not None and inc.heal_outcome == "verify_failed"
    assert inc.t_promoted is None and inc.mttr is None
    rows = MetricsLog(cfg.incidents_csv).load()
    assert len(rows) == 1 and rows[0]["heal_outcome"] == "verify_failed"
    assert MetricsLog(cfg.incidents_csv).report()["failed_heals"] == 1


def test_corrupt_source_falls_back_to_the_next_verified_one(tmp_path):
    """A source that fails verification is discarded, not fatal: golden is tried next."""
    cfg, golden_src, live, snaps = _workspace(tmp_path)
    # golden WEBROOT copy is corrupt, the golden IMAGE (golden_src via the fake) is fine
    bad_copy = tmp_path / "golden_copy"
    shutil.copytree(golden_src, bad_copy)
    (bad_copy / "index.html").write_text("corrupt")
    cfg.golden_webroot = str(bad_copy)
    _breach(cfg, live)

    fake = RecordingDocker(golden_src, live)
    inc = ArgusController(cfg, fake).tick(t_attack=time.time())
    assert inc.heal_outcome == "healed"
    assert inc.restore_source == "golden-image"
    assert Manifest.load(cfg.golden_manifest).verify(live)[0]


def test_poisoned_snapshot_is_refused_as_a_restore_source(tmp_path):
    """A clone taken while the attacker's file was present must not be restored from."""
    from argus.storage import Snapshotter
    cfg, golden_src, live, snaps = _workspace(tmp_path)
    (live / "backdoor.php").write_text("evil")           # attacker present at capture time
    snapper = Snapshotter(cfg, FakeDocker(golden_src, live).copy_out)
    poisoned = snapper.take()
    assert poisoned.clean is False

    (live / "backdoor.php").unlink()
    good = snapper.take()
    assert good.clean is True
    assert snapper.latest_clean().path == good.path

    # and a clean snapshot tampered with on disk afterwards fails its own re-verification
    (good.path / "index.html").write_text("tampered later")
    assert snapper.latest_clean() is None


def test_health_gate_failure_is_recorded_and_not_promoted(tmp_path):
    cfg, golden_src, live, _ = _workspace(tmp_path, health_retries=4)
    _breach(cfg, live)
    fake = RecordingDocker(golden_src, live, healthy=False)
    inc = ArgusController(cfg, fake).tick(t_attack=time.time())

    assert fake.probes == 4, "the full retry budget is used before giving up"
    assert inc.heal_outcome == "health_failed"
    assert inc.t_restored is not None and inc.t_promoted is None
    assert MetricsLog(cfg.incidents_csv).load()[0]["heal_outcome"] == "health_failed"


def test_health_gate_retries_until_the_instance_comes_up(tmp_path):
    cfg, golden_src, live, _ = _workspace(tmp_path, health_retries=10)
    _breach(cfg, live)
    fake = RecordingDocker(golden_src, live, healthy=3)      # healthy from the 4th probe
    inc = ArgusController(cfg, fake).tick(t_attack=time.time())

    assert fake.probes == 4 and inc.heal_outcome == "healed" and inc.t_promoted is not None


def test_restored_instance_publishes_on_loopback_only(tmp_path):
    """M6: an unqualified port mapping binds 0.0.0.0 -- the vulnerable app on the LAN."""
    cfg, golden_src, live, _ = _workspace(tmp_path, host_port=8080)
    _breach(cfg, live)
    fake = RecordingDocker(golden_src, live)
    ArgusController(cfg, fake).tick(t_attack=time.time())
    assert fake.run_calls[-1]["ports"] == {"80/tcp": ("127.0.0.1", 8080)}


# ---- M1 / M10: attack-marker integrity -------------------------------------------
def test_stale_attack_marker_is_not_attributed_to_a_later_detection(tmp_path):
    """M1: a timed-out trial's leftover marker used to become the next detection's t_attack."""
    cfg, golden_src, live, _ = _workspace(tmp_path, attack_marker_max_age_sec=300.0)
    marker = Path(cfg.attack_marker_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"t_attack": time.time() - 3600, "scenario": "webshell"}))
    _breach(cfg, live)

    inc = ArgusController(cfg, RecordingDocker(golden_src, live)).tick()
    assert inc.t_attack is None and inc.mttd is None
    assert inc.false_positive is True, "an unattributable detection is reported as such"
    assert not marker.exists()


def test_corrupt_attack_marker_degrades_to_unattributed(tmp_path):
    cfg, golden_src, live, _ = _workspace(tmp_path)
    marker = Path(cfg.attack_marker_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text('{"t_attack": 17')                    # truncated mid-write
    _breach(cfg, live)

    inc = ArgusController(cfg, RecordingDocker(golden_src, live)).tick()
    assert inc is not None and inc.t_attack is None


# ---- M9 / minor: reporting, config, health probe ---------------------------------
def test_old_incident_csv_is_migrated_without_losing_data(tmp_path):
    """New columns must not misalign rows appended under an old header."""
    path = tmp_path / "incidents.csv"
    old_header = ("incident_id,scenario,t_attack,t_detect,t_restored,t_promoted,"
                  "detected_by,false_positive,restore_source,mttd,mttr,total_recovery\n")
    path.write_text(old_header + "i1,webshell,100.0,103.0,110.0,112.0,signature,False,"
                    "golden-webroot,3.0,9.0,12.0\n")

    log = MetricsLog(path)
    log.record(Incident("i2", "webshell", 200.0, 203.0, 210.0, 212.0, "signature",
                        restore_source="golden-webroot", heal_outcome="healed"))
    rows = log.load()
    assert [r["incident_id"] for r in rows] == ["i1", "i2"]
    assert rows[0]["mttr"] == "9.0" and rows[0]["heal_outcome"] == "healed"
    assert rows[1]["mttr"] == "9.0"
    assert (tmp_path / "incidents.csv.bak").read_text().startswith("incident_id,scenario")


def test_config_load_is_strict(tmp_path):
    bad = tmp_path / "typo.yaml"
    bad.write_text("protected_containr: oops\n")
    with pytest.raises(ValueError, match="protected_containr"):
        ArgusConfig.load(bad)
    with pytest.raises(FileNotFoundError):
        ArgusConfig.load(tmp_path / "nope.yaml")


@pytest.mark.parametrize("name", ["argus.yaml", "target2.yaml"])
def test_shipped_configs_load_and_use_the_calibrated_threshold(name):
    cfg = ArgusConfig.load(Path(__file__).resolve().parents[1] / "config" / name)
    assert cfg.anomaly_threshold is None, "a literal -0.15 is the original C1 defect"
    assert cfg.host_bind == "127.0.0.1"


def test_the_two_targets_share_no_state():
    """Two Argus instances must never read or write the same file, container or port."""
    cfg_dir = Path(__file__).resolve().parents[1] / "config"
    a, b = (ArgusConfig.load(cfg_dir / n) for n in ("argus.yaml", "target2.yaml"))
    for field in ("protected_container", "golden_image", "host_webroot", "isolated_network",
                  "host_port", "snapshots_dir", "golden_manifest", "golden_webroot",
                  "breach_signal_path", "attack_marker_path", "forensics_dir",
                  "incidents_csv", "anomaly_model_path", "access_log_path",
                  "wazuh_alerts_path"):
        assert getattr(a, field) != getattr(b, field), f"targets share {field}"


def test_http_ok_is_pure_python_and_judges_302_as_itself():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from argus.docker_ops import DockerOps

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            code = {"/ok": 200, "/redir": 302, "/boom": 500}[self.path]
            self.send_response(code)
            if code == 302:
                self.send_header("Location", "/boom")     # following it would give 500
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert DockerOps.http_ok(base + "/ok") is True
        assert DockerOps.http_ok(base + "/redir") is True      # 302 itself, not the 500 behind it
        assert DockerOps.http_ok(base + "/boom") is False
    finally:
        srv.shutdown()
        srv.server_close()
    assert DockerOps.http_ok(base + "/ok", timeout=1) is False  # nothing listening now


def test_sensor_request_rate_uses_real_elapsed_time(tmp_path):
    """M11: lines-since-last-tick were scaled as if they spanned a whole minute."""
    from argus.detection import HostSensor
    log = tmp_path / "logs" / "access.log"
    log.parent.mkdir()
    log.write_text("\n".join(
        f'1.2.3.4 - - [x] "GET /p{i} HTTP/1.1" 200 5' for i in range(10)) + "\n")
    cfg, *_ = _workspace(tmp_path)
    sensor = HostSensor(cfg, access_log=str(log))
    sensor._last_read -= 5.0                               # 5 s since the previous read
    per_min, paths, *_ = sensor._http_features()
    assert per_min == pytest.approx(120.0, rel=0.05)       # 10 lines / 5 s -> 120 per min
    assert paths == 10.0


def test_access_log_default_is_outside_the_monitored_web_root():
    """M8: a log inside the web root reads as permanent tampering."""
    cfg = ArgusConfig()
    assert not Path(cfg.access_log_path).as_posix().startswith(
        Path(cfg.host_webroot).as_posix() + "/")


def test_metrics_log_recreates_header_if_the_file_is_deleted_mid_run(tmp_path):
    """
    A demo or an operator clearing incidents.csv while the controller is running used to
    make the next record() create a headerless file, so the first incident was read back
    as the column names and the report crashed with a KeyError.
    """
    path = tmp_path / "incidents.csv"
    log = MetricsLog(path)
    path.unlink()                                          # removed behind its back
    log.record(Incident("i1", "webshell", 100.0, 103.0, 110.0, 112.0, "signature",
                        heal_outcome="healed"))
    rows = log.load()
    assert len(rows) == 1 and rows[0]["incident_id"] == "i1" and rows[0]["mttd"] == "3.0"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_extraction_keeps_world_writable_dirs_but_strips_setuid(tmp_path):
    """
    tarfile's data filter silently turned a 0777 upload directory into 0755, so after a
    restore from any snapshot the app could no longer write its own uploads (found live on
    Target #2). Ordinary permission bits must survive; setuid must not.
    """
    import io
    import tarfile
    from argus.docker_ops import DockerOps

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        d = tarfile.TarInfo("html/uploads"); d.type = tarfile.DIRTYPE; d.mode = 0o777
        tar.addfile(d)
        f = tarfile.TarInfo("html/run.sh"); f.size = 1; f.mode = 0o4755       # setuid
        tar.addfile(f, io.BytesIO(b"x"))
    out = DockerOps._extract_stripped([buf.getvalue()], "/var/www/html", tmp_path / "snap")

    assert (out / "uploads").stat().st_mode & 0o777 == 0o777, "world-writable dir preserved"
    assert (out / "run.sh").stat().st_mode & 0o7000 == 0, "setuid bit must be stripped"
