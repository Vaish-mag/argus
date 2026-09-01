# Audit findings

Four folders (`argus/`, `lab/`, config + deployment, `tests/`) were each read completely,
end to end, by an independent reviewer. This is the consolidated, prioritised result.
Findings already fixed are marked so; everything else is open.

Severity: **Critical** = breaks a claim the project makes, or is exploitable.
**Major** = biases a result or breaks under realistic conditions. **Minor** = correctness
or quality issue with limited blast radius.

---

## Fixed during this audit

| # | Finding | Fix |
|---|---|---|
| S1 | `lab/serve.py` bound to `0.0.0.0` and served the entire project root with directory listings — `.git/` and `results/forensics/*/captured/` (which contains DVWA's `config.inc.php` and its database password) were downloadable by anything on the same network, unauthenticated. | Rewritten as an explicit allow-list handler bound to `127.0.0.1`. See `fix/serve-py-credential-leak`. |

---

## Critical — open

| # | Where | What | Why it matters |
|---|---|---|---|
| C1 | `argus/anomaly.py:79`, `argus/detector.py:78` | `IsolationForest.score_samples` returns values around `[-0.75,-0.35]`; `anomaly_threshold: -0.15` is on the wrong scale. Every window, normal or not, scores below threshold. | If a trained model exists, the anomaly layer fires on every tick — infinite heal loop, 100% false-positive rate. The project's ML contribution is currently untested end-to-end because nothing forces a model to exist. |
| C2 | `argus/docker_ops.py:99-104` | Tar extraction from the compromised container rewrites member paths but does not verify containment. The Python-3.12 `filter="data"` guard is dropped entirely in the `except TypeError` fallback, and both that and a subsequent bare `except Exception: continue` hide any rejection. | An attacker with write access inside DVWA — which is the entire premise of the lab — can choose filenames that escape `results/snapshots/` or `results/forensics/` during capture. Real path-traversal risk. |
| C3 | `argus/manifest.py:105-121` | `diff_against_golden` reports `new:` and `changed:` files but never `missing:`. Both callers that decide "is this tampered" (`fim_watch.check_once`, `Snapshotter.take`) rely on it. | `rm -rf /var/www/html/*` — deletion-based defacement — produces **zero** deviations and no breach signal. Worse: a snapshot taken of a partially-deleted tree still verifies against its own hashes and gets marked `clean=True`, so it becomes eligible as a restore source. Argus could "heal" by restoring a truncated site. |
| C4 | `argus/docker_ops.py:104-106` | `_extract_stripped` silently drops any tar member it can't extract, with no count and no effect on the manifest. | Combined with C3, a capture that loses half its files during a permission hiccup produces a `clean=True` manifest for what survived — a corrupted snapshot indistinguishable from a good one, and eligible to be promoted later. |
| C5 | `argus/healer.py:91-104` | The replacement container starts serving on port 8080 **before** `manifest.verify` runs. On verification failure the method just returns `HealResult(success=False)` — the unverified container keeps running as main. The failed trial then vanishes from `report()` because empty `t_promoted`/`t_restored` are filtered out silently. | Directly contradicts the stated design invariant "a poisoned clone can never become main." A failed heal currently leaves the compromised or unverified state live, with no record in the statistics that it happened. |
| C6 | `argus/healer.py:117-119`, `argus/docker_ops.py:72` | PROMOTE is a timestamp only. The container was already attached to the network and had its port published before verification. `connect_network` exists but is never called anywhere. | There is no isolation gate between "restored" and "serving live traffic." `t_promoted` currently measures nothing but "the health poll finally succeeded," not "verified, then released to the network." |

## Major — open

| # | Where | What | Why it matters |
|---|---|---|---|
| M1 (validity) | `lab/attacker/run_experiment.py` | `runtime/attack_marker.json` is only deleted when a detection consumes it. A trial that times out leaves it on disk with no expiry. | The **next** detection — a genuine false positive, or trial 1 of a later session — silently inherits that stale timestamp as its `t_attack`, gets recorded as `false_positive=False`, and its inflated duration flows straight into the MTTD/total_recovery distributions. This is plausibly the actual cause of the "VM stall" outlier seen in an earlier run, not memory pressure. |
| M2 (validity) | `lab/baseline/baseline_recovery.py:46-52` vs `argus/snapshotter.py` | Argus restores only from a snapshot whose manifest is marked `clean` and which re-verifies; the baseline arm's `_last_clone` takes the newest snapshot directory with **no clean check and no verification**, and calls it recovered on HTTP 200 alone. | The two arms are not measuring the same event. A snapshot Argus would refuse (because it deviates from golden) can still be accepted by the baseline arm and reported as a clean recovery. This is the finding most likely to be challenged in a viva. |
| M3 (validity) | `lab/attacker/run_experiment.py`, `lab/baseline/baseline_recovery.py` | Arms run as two separate full blocks, not interleaved. `commit_forensic_image: true` adds ~1GB of Docker image per Argus incident, so disk usage and Docker's own overhead grow monotonically through one entire arm before the other starts. | "Which arm" is confounded with "how full is the disk / how loaded is Docker right now." Violates the independence assumption behind the Mann-Whitney test. |
| M4 (stats) | `lab/baseline/baseline_recovery.py:35`, `lab/plot_results.py` | `NOTICE_DELAY_SEC = 30.0` is a fixed constant added to every baseline row. Total-recovery significance is tested via Mann-Whitney on distributions with a guaranteed constant additive offset. | With a fixed offset the two distributions are guaranteed to separate at any reasonable n. The current p-value is a property of the chosen constant, not empirical evidence — needs disclosing explicitly, and ideally a sensitivity sweep over the constant rather than one point estimate. |
| M5 (stats) | `lab/plot_results.py` | `mannwhitneyu(..., alternative="less")` is applied to every metric including MTTR, where the project's own documentation states Argus is expected to be *slower*. A one-sided test in the wrong tail cannot detect that. | Statistically indefensible if picked apart: you cannot pre-register "less" for a metric you expect to go the other way. |
| M6 (security) | `docker-compose.yml:25`, `argus/healer.py:93` | DVWA is published as `"8080:80"` → binds `0.0.0.0`. `healer.py`'s `dk.run(..., ports={"80/tcp": cfg.host_port})` reproduces the same defect on every replacement container after a heal. | The deliberately-vulnerable app is reachable from the LAN/Wi-Fi, not just localhost — contradicting the project's own "isolated lab network" comment in the compose file. |
| M7 (security) | `config/wazuh/local_rules.xml` vs `config/wazuh/ossec-fim.conf` | The rules match the container-internal path `/var/www/html/`; Wazuh's FIM `file` field always reports the **host** path being watched. The rules can never fire. | The entire documented Wazuh detection path is inert. Only `fim_watch.py` (the lightweight watcher) actually works. If asked to demonstrate the Wazuh path specifically in a viva, it would silently fail. |
| M8 | `argus/sensors.py:34` | The access log used for HTTP features defaults to living *inside* the monitored web root (`runtime/webroot/access.log`), with `volatile_paths: []`. | If the file exists, every scan reports it as a deviation — permanent breach signal, heal loop, and every restore verification fails. If it doesn't exist, four of the model's nine features are constant zero forever. Either way, broken. |
| M9 | `argus/metrics.py:16` vs `:122` | The docstring defines FPR as `fp / (fp + true_negative_windows)`; the code computes `fps / detections` — a different quantity (closer to false-discovery rate). | Reporting a metric under a name defined differently two files earlier is exactly the kind of inconsistency an examiner finds first. |
| M10 | `argus/controller.py:67-76` | `_consume_attack_marker`'s `finally: unlink()` runs even when JSON parsing fails, permanently destroying that trial's ground truth. No bound on marker age either. | A truncated marker (written non-atomically by the harness) silently corrupts one trial's attribution; a late detection can consume the *next* trial's marker, cascading the error. |
| M11 | `argus/sensors.py:62,71-76` | `req_per_min` multiplies line count by `60/window_sec` where the line count is actually since the *previous 2-second tick*, not over 60s — understating the feature ~30×. | Any anomaly model trained against this feature is invalid if the detection period ever changes, and the reported feature values don't mean what their name says. |
| M12 | `argus/sensors.py:81-99` | Every detection tick shells out to `docker stats` and `docker exec`, typically 1-2s combined. | The nominal 2-second detection period is really 4-5 seconds in practice — this quantises MTTD, a headline metric. |
| M13 | `argus/docker_ops.py:147` (health check) | Uses `curl -o /dev/null` via subprocess on a Windows host; if a native `curl.exe` is first on PATH, `/dev/null` is not valid there. Failure is swallowed by a bare `except: return False`. | Every heal could report "health check never passed" for a platform reason, not a real failure — and that trial silently drops out of every report. |
| M14 (test) | `tests/test_argus.py` (whole file) | 14 tests, all success-path. **None** of the four stated resilience guarantees are exercised at the policy level: forensics-strictly-before-destroy is not ordering-tested, a poisoned clone being refused promotion is never tested (`Snapshotter.take`/`_prune` are never called by any test), verification-failure-aborts-promotion is never entered, and the health-gate retry/failure path is dead code as far as the suite is concerned (the `FakeDocker` health check always succeeds on the first try). | These are the exact guarantees the dissertation claims. Currently, none of them would be caught regressing. |
| M15 (test) | `argus/snapshotter.py:56` | `time.strftime("%Y%m%d-%H%M%S")` has 1-second granularity; two snapshots in the same second silently collide and merge. | Untested latent bug — plausible on a fast machine or a short demo interval. |

## Minor — open (selected; see individual audit transcripts for the complete lists)

- Dead code: `DockerOps.copy_in`, `DockerOps.connect_network`, `AnomalyDetector.is_anomaly` are never called from production code.
- `snapshotter.py`: `keep_snapshots: 0` means "keep everything" (`snaps[:-0]` is a no-op slice), the opposite of what the name implies.
- No reaper for forensic `docker commit` images (~1GB each) or old `results/forensics/*` capture directories — unbounded growth on a disk-constrained lab machine.
- `ArgusConfig.load` silently falls back to defaults on a missing/unparseable YAML file and silently drops unknown keys — a typo'd config key changes nothing and warns about nothing.
- `dashboard.html` / `report.html` use a naive comma-split CSV parser with no quote handling; a quoted field (e.g. a `restore_source` containing a comma) would silently shift every later column.
- `report.html` and `plot_results.py` print the same reduction with **opposite signs** (`+45.0%` vs `−45.0%`) on the same page, and compute `n` differently — a genuine risk of the wrong number being quoted in the dissertation.
- `demo.sh`'s CSV-stash-and-restore only triggers if the file already exists; a fresh checkout has no file, so no trap is registered and a demo run's incident is left in the dataset it was meant to protect.
- `run_argus.py`: no bounds checking on `--period`, `--contamination`; `cmd_init_golden` does an unguarded `shutil.rmtree` + `copytree` with no check that source and destination differ.
- `requirements.txt`: `scipy` is imported by `plot_results.py` but absent from the file (degrades to "no significance test," doesn't crash — but silently). All other dependencies are unpinned `>=`, and the trained anomaly model is a pickled scikit-learn object whose load behaviour is not guaranteed stable across sklearn versions.

---

## Suggested improvements, ranked by value-for-effort (across all four folders)

1. **Fix the anomaly threshold (C1)** — a few lines; restores the project's ML contribution.
2. **Add a `missing:` class to `diff_against_golden` (C3)** — ~5 lines; closes the deletion-attack blind spot and the silent-corruption path it enables.
3. **Clear the attack marker at trial start and validate on read-back (M1)** — ~10 lines; the single highest-value fix to the experimental data's integrity.
4. **Give the baseline arm the same clean-check/verification as Argus (M2)** — reuse `Snapshotter.latest_clean()` in both arms; makes the comparison actually valid.
5. **Bind DVWA's port to loopback in both places (M6)** — two lines; the one finding that is a live network-facing security hole rather than a lab-correctness issue.
6. **Fix the Wazuh rule path and rename the misleading FPR (M7, M9)** — small edits; removes two claims that don't survive inspection.
7. **Record failed heals as first-class CSV rows instead of dropping them (C5)** — a `heal_outcome` column; silent trial loss is currently the biggest threat to the credibility of the numbers.
8. **Write the four missing policy-level tests (M14)**: poisoned-clone rejection, verification-abort, health-gate failure, and forensics-before-destroy ordering. This is the single most valuable addition to the test suite.
9. **Run measurement arms with `commit_forensic_image: false`, report both ways** — removes ~1GB of instrumentation cost from the headline MTTR and stops disk growth from confounding the comparison (M3).
10. **Two-sided significance test for MTTR; report a NOTICE_DELAY sensitivity sweep instead of one p-value for total recovery (M4, M5)** — converts the weakest part of the statistics into the most defensible.
11. **Real promotion gate**: launch on no network / unpublished port, verify + health-check via container IP, then attach and publish (C6). Biggest design win in the codebase; makes "poisoned clone can never become main" literally true rather than aspirationally true.

Everything above was found by reading, not by running — treat this document as a prioritised
punch list, not a claim that the code is broken today for every user in every configuration.
Several items (C1, M7) are currently masked by fallbacks (signature-only mode; the
lightweight watcher) and will only surface if that fallback is ever removed.
