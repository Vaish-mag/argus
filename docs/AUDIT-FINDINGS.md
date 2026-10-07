# Audit findings

Four folders (`argus/`, `lab/`, config + deployment, `tests/`) were each read end to end by
an independent reviewer. This is the consolidated result **and its current status**.

Severity: **Critical** = breaks a claim the project makes, or is exploitable.
**Major** = biases a result or breaks under realistic conditions. **Minor** = correctness or
quality issue with limited blast radius.

Status: **Fixed** (a regression test pins it), **Mitigated** (reduced or disclosed, not
eliminated), **Open** (known, not addressed). Test names refer to `tests/test_argus.py`.

> Honest scope note: the original audit was done by reading. The fixes below are verified
> by the unit suite (14 tests grew to roughly 50, passing on Python 3.11 and 3.12) and by
> the live run described under "Live verification". The experiment numbers in the report
> have **not** been re-measured at scale and predate these fixes — see the last section.

---

## Critical

| # | Finding | Status | Fix / evidence |
|---|---|---|---|
| S1 | `lab/serve.py` bound `0.0.0.0` and served the whole project root (`.git/`, forensic captures containing DVWA's DB password). | **Fixed** (earlier) | Explicit allow-list handler on `127.0.0.1`. |
| C1 | `anomaly_threshold: -0.15` is on the wrong scale: `score_samples` is ≈ −0.45…−0.6 for normal data, so every window was flagged — an infinite heal loop. | **Fixed** | Default cutoff is the model's calibrated boundary (`offset_`); config value is now an optional override (`null`). 3-window confirmation. `test_anomaly_cutoff_is_calibrated_to_the_model_scale` reproduces the original defect (−0.15 flags >99% of normal windows) and asserts <6% after the fix. |
| C2 | Tar extraction from the compromised container did not check containment; the safe-extract filter was dropped in the fallback path. | **Fixed** | Members vetted before writing: `..`/absolute refused, only regular files and directories, destination must resolve inside target, modes masked. `test_tar_path_traversal_is_refused_and_never_written`, `test_tar_symlinks_are_never_extracted`. |
| C3 | `diff_against_golden` reported `new`/`changed` but never `missing`: `rm -rf` of the site raised no alarm and a truncated snapshot was marked clean. | **Fixed** | Added `missing:` class. `test_deleting_a_golden_file_is_a_deviation`, `test_partially_deleted_snapshot_is_not_clean`. |
| C4 | `_extract_stripped` silently dropped members it could not extract, so a lossy capture looked clean. | **Fixed** | Collected and raised as `IncompleteCapture` in strict (snapshot) mode; the snapshot is retained but marked unclean. `test_incomplete_capture_is_never_clean`. |
| C5 | The replacement container started serving before `manifest.verify`; on failure the unverified container stayed live and the failed trial vanished from the statistics. | **Fixed** | Order is now restore → **verify** → launch; no candidate verifying means nothing is launched (fail closed). Failed heals are rows with `heal_outcome`. `test_unverifiable_restore_never_launches_a_container`, `test_replacement_is_launched_only_after_its_files_verify`. |
| C6 | "PROMOTE" was a timestamp only; no isolation gate between restored and serving. | **Fixed** (by a different mechanism than proposed) | Because the web root is a bind mount, verifying the host directory before launching achieves the invariant directly — nothing unverified is ever started — without a staged network. See `design.md`. |

## Major

| # | Finding | Status | Fix / evidence |
|---|---|---|---|
| M1 | A timed-out trial's attack marker was never removed and was inherited by the next detection. | **Fixed** | Harness clears it at trial start and after a timeout; controller ignores markers older than `attack_marker_max_age_sec`. `test_stale_attack_marker_is_not_attributed_to_a_later_detection`. |
| M2 | The baseline arm restored from the newest snapshot with no clean check, so the two arms did not measure the same event. | **Fixed** | Baseline uses `Snapshotter.latest_clean()` and verifies the web root against the golden manifest. |
| M3 | Arms run as separate blocks, not interleaved; `commit_forensic_image: true` made disk/Docker load grow through the first arm. | **Mitigated** | `commit_forensic_image` now defaults to `false`. Interleaving is **not** implemented (the Argus arm needs the controller running, the baseline arm needs it stopped); disclose as a threat to validity. |
| M4 | `NOTICE_DELAY_SEC = 30` is a fixed constant added to every baseline row, so total-recovery significance depends on the chosen constant. | **Mitigated** | `plot_results.py` now prints a sweep over 0–120 s and the break-even delay. The constant itself is still a model assumption, and the report must say so. |
| M5 | One-sided `alternative="less"` applied to MTTR, where Argus is expected to be slower. | **Fixed** | Two-sided test for every metric. |
| M6 | DVWA and every healed container published on `0.0.0.0`. | **Fixed** | `127.0.0.1:8080:80` in compose; `host_bind` config key (default loopback) for healed containers. `test_restored_instance_publishes_on_loopback_only`. |
| M7 | Wazuh rules matched the container path; Wazuh reports the host path, so they could never fire. | **Mitigated** | Rules rewritten on the built-in FIM parents (550/553/554) with a host-path pattern. **Not exercised against a live Wazuh manager**; treat as a reference configuration. |
| M8 | The sensor's access log defaulted to inside the monitored web root. | **Fixed** | `access_log_path` (default `runtime/logs/access.log`), warning when absent. `test_access_log_default_is_outside_the_monitored_web_root`. |
| M9 | Docstring defined FPR one way, code computed another. | **Fixed** | Renamed `false_discovery_rate` (alarms that were false / all alarms) and documented. |
| M10 | A corrupt marker was silently destroyed; no age bound. | **Fixed** | Warned and treated as unattributed; atomic marker writes; age bound. `test_corrupt_attack_marker_degrades_to_unattributed`. |
| M11 | `req_per_min` scaled lines-since-last-tick as if they spanned 60 s. | **Fixed** | Rate uses real elapsed time. `test_sensor_request_rate_uses_real_elapsed_time`. |
| M12 | Every tick shelled out to `docker stats`/`exec` (1–2 s), quantising MTTD. | **Fixed** | Resource readings cached 10 s; sensor not constructed in signature-only mode. |
| M13 | Health check used `curl` + `/dev/null` through a subprocess; failure swallowed. | **Fixed** | Pure-Python probe, no redirect-following. `test_http_ok_is_pure_python_and_judges_302_as_itself`. |
| M14 | None of the four resilience guarantees were tested at policy level. | **Fixed** | Forensics-before-destroy ordering, poisoned-snapshot refusal, verification-abort, health-gate failure and retry, fallback to the next source — each has a test. |
| M15 | 1-second snapshot names collided. | **Fixed** | Microsecond-resolution names. `test_snapshots_in_the_same_second_do_not_collide`. |

## Found while fixing (not in the original audit)

| # | Finding | Status | Fix / evidence |
|---|---|---|---|
| N1 | `Manifest.build` skipped any file it could not read, so removing a file's read permission (or an antivirus lock — this was hit for real on Windows) hid it from integrity monitoring. | **Fixed** | Recorded with an `unreadable` sentinel that never matches anything. `test_unreadable_file_is_recorded_not_skipped`. |
| N2 | Volatile-path exemptions used `startswith`, so exempting `uploads` also exempted `uploads_shell.php` — the lab's own attack filename. | **Fixed** | Whole-component matching (`is_volatile`). `test_volatile_path_matches_whole_components_only`. |
| N3 | IsolationForest cannot split on a feature that never varied in training; `file_change_events` and `new_process_events` are constant 0, so a window where only those moved scored like the most ordinary one. | **Fixed** | Range guard. `test_forest_alone_is_blind_to_features_that_never_varied`. |
| N4 | `ArgusConfig.load` silently fell back to DVWA defaults for a missing file or a typo'd key — `--config config/target2.yaml` mistyped would have protected the wrong container. | **Fixed** | Strict loading. `test_config_load_is_strict`. |
| N5 | A snapshot was taken while an unconsumed breach flag was pending. | **Fixed** | A pending flag counts as "breach active" for snapshotting; a failed snapshot no longer kills the daemon. |
| N6 | `tarfile`'s safety filter strips group/other **write** bits from every member, so a world-writable upload directory (0777) became 0755 in every snapshot, and after a restore from one the app could no longer write its own uploads. **Found live** on Target #2. | **Fixed** | Safety checks kept, ordinary permission bits preserved (setuid/setgid/sticky still stripped). `test_extraction_keeps_world_writable_dirs_but_strips_setuid` (POSIX). |
| N7 | `MetricsLog.record` appended a headerless row if the incidents file was deleted while the controller ran, so the first incident read back as the column names. | **Fixed** | Header re-created. `test_metrics_log_recreates_header_if_the_file_is_deleted_mid_run`. |
| N8 | **Found live:** with verify-before-launch the container id changes before the app is up, so the demo script's fixed 3 s wait read the site too early (HTTP 000, no metrics) and the heal was recorded *after* the demo had restored the experiment CSV, leaking demo rows into the real dataset. | **Fixed** | Demos wait for the heal to be recorded, not for the id to change. |

## Minor

| Item | Status |
|---|---|
| Dead code `copy_in`, `connect_network` | **Fixed** (removed); `is_anomaly` is now used. |
| `keep_snapshots: 0` meant "keep everything" | **Fixed**, `test_keep_snapshots_zero_does_not_mean_keep_everything`. |
| Config silently dropped unknown keys | **Fixed** (N4). |
| Naive CSV parsing in `dashboard.html` / `report.html` | **Fixed** (quote-aware parser). |
| `report.html` and `plot_results.py` printed opposite signs | **Fixed** — both say "X% faster/slower". |
| `demo.sh` left its incident behind on a fresh checkout | **Fixed** (trap always registered). |
| No bounds on `--period` / `--contamination`; unguarded `init-golden` rmtree | **Fixed**. |
| `scipy` missing from `requirements.txt` | **Fixed**. |
| Trained model is a pickled scikit-learn object | **Open** — documented in `AnomalyDetector`; retrain after upgrading scikit-learn. |
| No reaper for forensic `docker commit` images or old capture dirs | **Open** — off by default now; prune manually. |
| Two independent recomputations of the statistics (HTML vs `plot_results.py`) | **Open** — a single `summary.json` would be more robust. |
| `init-golden` does not check the web root is actually pristine | **Open** — documented; run it on a freshly seeded root only. |
| The golden image is a re-tag of the upstream DVWA image | **Open** — see `architecture.md`, "the trust anchor". |

---

## Live verification

Run on the author's machine (WSL2 + Docker Desktop, 127.0.0.1-only ports), using the narrated
demos against real containers:

| Check | Observed |
|---|---|
| DVWA, real file-integrity detection + heal (3 runs) | MTTD 2.45–3.09 s, MTTR 15.3–19.0 s — in line with the earlier 10-trial results (median MTTD 3.2 s, MTTR 18.6 s); no regression |
| Evidence captured before destruction | 585 files incl. the attacker's file, manifest marked `clean=False` |
| Moving-target property | container id changes on every heal |
| Site after heal | attacker file `404`, `login.php` `200` |
| Poisoned-clone defence | a snapshot taken while the attacker file was present was marked `clean=False` and skipped; the earlier clean snapshot was used |
| Port exposure (M6) | `docker port` shows `127.0.0.1:8080` and `127.0.0.1:8081` before *and* after a heal |
| Target #2 (separate PR), real HTTP exploit (CWE-434 multipart upload) | upload `200` → detected in 1.1 s → MTTD 2.7 s, MTTR 4.4 s → file `404`, site `200`, uploads dir still writable |
| Experiment data safety | the demos left `incidents.csv` / `incidents2.csv` row counts unchanged |

**Not live-tested:** the failure paths (`verify_failed`, `health_failed`) on a real daemon —
they are covered only with the fake Docker; the anomaly layer fed by the live `HostSensor`
(no model is trained in this lab, so it ran signature-only); the Wazuh path; the baseline arm
and a full 20-trial experiment with the new code.

## What this does *not* claim

- The ML layer is validated on **generated** windows (held-out false-alarm ≈ 3% per window
  before confirmation, all five attack shapes flagged). It has not been trained or scored on
  real DVWA traffic; do not report a real-world false-positive rate for it.
- The Wazuh path (M7) is unverified against a live Wazuh. `FIMWatcher` is the tested path.
- The experiment arms are still not interleaved (M3), and the notice delay is still a model
  assumption (M4).
- **The results in the report were produced by the pre-fix code.** Detection cadence,
  heal ordering and thresholds have changed, so re-run the experiment before quoting new
  numbers; the old numbers remain valid as a description of the old code.
