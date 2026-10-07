# Design decisions

Why the project is shaped the way it is, and what each choice costs. Written for a viva:
every entry pairs a decision with its honest trade-off.

## Detection is a plain flag file, not a Wazuh dependency

`detection.Detector` decides "was there a breach" by checking whether `runtime/breach.flag`
exists. It does not know or care who wrote it. This means Wazuh's active-response script
and the project's own lightweight watcher (`detection.FIMWatcher`) are interchangeable detection
sources through one narrow, file-shaped interface.

**Why:** the enterprise-realistic path (Wazuh) needs a second Docker stack and roughly
8GB of free memory the lab machine (5.8GB total) does not reliably have. Making detection
source-agnostic meant a resource-driven design decision could be made without touching the
controller at all.

**Cost:** the Wazuh path is a reference configuration, not a demonstrated one. The audit
(`docs/AUDIT-FINDINGS.md`, M7) found its rules matched the container path
`/var/www/html/` while Wazuh reports the *host* path, so they could never fire; that is
corrected, but the rules have not been run against a live Wazuh manager in this project.
`FIMWatcher` is the detection path that is tested and demonstrated, and the Limitations
section should say so plainly rather than presenting Wazuh as an equal alternative.

## What the file-integrity watcher can and cannot see

`FIMWatcher` hashes the web root every poll and diffs it against the golden manifest in
three classes: `new`, `changed` and `missing`. The third was absent in the audited code, so
`rm -rf` of the site raised no alarm and a half-deleted snapshot could be marked clean.
Two further blind spots were closed in the same pass: a file that exists but cannot be
read is recorded as `unreadable` (which never matches anything) instead of being skipped
as if absent, and "volatile path" exemptions match whole path components, so exempting
`uploads/` no longer exempts a file named `uploads_shell.php`.

**Cost:** it is still a content-hash comparison. It does not look at file ownership, mode
bits or timestamps, and it polls (default 2 s) rather than using inotify, so very short
create-and-delete windows can be missed. What it detects is "the served content differs
from golden", which is exactly the property the heal restores — it is not a general
host intrusion detector.

## The anomaly layer: calibrated, range-guarded, confirmed

`AnomalyDetector` is an IsolationForest over nine behaviour features. Three design points
came out of validating it end to end (the audited code had never been run with a model):

- **Calibrated cutoff.** `score_samples` returns roughly −0.45 to −0.6 for ordinary data,
  so the original fixed cutoff of −0.15 flagged 100% of windows — an infinite heal loop.
  The default is now the model's own training-time boundary (`offset_`); the config value
  is an override, and `null` means "calibrated".
- **Range guard.** The forest cannot split on a feature that never varied in training, and
  `file_change_events` / `new_process_events` are constant zero in normal traffic — so a
  window where *only* those move scored identically to the most normal window. Any feature
  outside its trained range (plus one span of slack) is now anomalous by definition, and a
  feature that never varied tolerates no change.
- **Confirmation.** An alarm triggers a destructive heal, so the score must stay anomalous
  for `anomaly_confirm_windows` (default 3) consecutive ticks. Signature evidence is never
  delayed by this.

**Cost:** held-out normal traffic in the synthetic test is flagged at about 3% per window
before confirmation; this is validated on generated data, not on real DVWA traffic, and the
Results chapter should not claim a measured real-world false-positive rate for the ML layer.

## The heal sequence is strictly ordered, and the order is the claim

`Healer.heal` in `controller.py` runs forensics, isolate, destroy, then restore → verify
(per candidate source), launch, health-check, promote — in that literal order, because each
step depends on the previous one having happened and not yet been undone:

- Forensics before destroy, so evidence of the attack is never lost to remediation.
- Restore before verify, so verification checks the *actual* restored content rather than
  the intended source.
- **Verify before launch**, so an unverified clone can never serve a request.

The web root is a bind mount, so a container serves exactly the host directory it starts
on. The audited code started the replacement container (and published its port) *first* and
verified afterwards; on a verification failure it returned and left the unverified
container running as main. Now the candidate sources are tried best-first (latest
verified-clean snapshot, then the golden web-root copy, then the golden image extracted
directly); each is laid down and verified, and the first that passes is launched. If none
passes, **nothing is launched** and the service stays down — fail closed — and the failure
is recorded (`heal_outcome = verify_failed`) instead of vanishing from the statistics.
A health-check timeout on a *verified* container is recorded as `health_failed`; the
container is left running because its content is known-good and it may simply be slow.

**Cost:** fail-closed means a total verification failure is an outage, by choice. And
"promotion" is no longer a separate network-attach step: because nothing unverified is ever
started, the gate is the verification itself rather than a staged network.

## Archives from the compromised container are hostile input

Forensic and snapshot captures `get_archive` from a container assumed compromised, so tar
member names are attacker-controlled. `DockerOps._extract_stripped` vets every member
before writing: `..` and absolute paths are refused, only regular files and directories are
extracted (never links or devices), the resolved destination must stay inside the target,
and modes are masked. Snapshot captures are *strict*: anything refused or failing to
extract raises `IncompleteCapture`, and the snapshot is retained for evidence but marked
unclean, so a capture that silently lost files can never be a restore source. Forensics and
golden seeding are best-effort so evidence is never lost over one odd member.

**Cost:** a legitimate symlink in the web root is not captured; manifests cover regular
files only, so this does not affect verification, but a site that relies on symlinks would
need them recreated.

## Golden image + verified clone, never golden image alone

A restore always rebuilds the container from the golden image, then lays verified-clean
*content* on top from the best available source (snapshot, then `golden_webroot`, then the
image's own baked-in files as a last resort). It never trusts a clone's executable base.

**Why:** this is what defends against a slow-burn compromise — several snapshot cycles
quietly poisoned before anyone notices. Even if the newest "clean" clone is subtly stale,
the base it's laid onto was never the compromised instance.

**Cost:** the golden image itself is a re-tag of the upstream DVWA image, not an
independently built baseline (see `docs/architecture.md`, "the trust anchor"). The defence
is real for the OS/PHP layer; the actual served PHP content always comes from the host-side
web root, which is exactly what a snapshot or the golden manifest is meant to certify —
so the manifest's integrity is where the real weight of this guarantee sits.

## The web root is a bind mount, and the host side is the source of truth

`docker-compose.yml` mounts `runtime/webroot` onto `/var/www/html`. Every module that needs
to read or reset "the protected content" — `FIMWatcher`, `Snapshotter`, `Healer` — operates
on the host path, not by `docker exec`-ing into the container.

**Why:** this is what lets Argus watch and restore the web root without needing a shell
inside the (possibly compromised) container, and it's what makes host-side FIM (Wazuh's
agent, or `FIMWatcher`) able to see the files directly.

**Cost:** it also means the healer must remember to reset the *host* directory on every
heal, not just relaunch the container — the fix for the heal-loop bug documented in
`docs/AUDIT-FINDINGS.md`. And it means `protected_path` (the in-container path) and
`host_webroot` (the host path) are two different config values that must never be confused
— they were, in an earlier version of this codebase, and it broke the experiment harness
outright.

## Median, not mean, is the headline statistic

`plot_results.py` reports the median reduction as "quote this," with the mean available
separately and explicitly labelled "outlier-sensitive."

**Why:** a single stalled trial — a memory-starved VM whose wall clock kept advancing while
the container did nothing — produced a 5063-second outlier in one real run. That one value
alone turned a genuine ~56% improvement into a reported "−8085% reduction" by mean. The
median was unaffected. Median is also the statistic consistent with the rank-based
Mann-Whitney test reported alongside it — quoting a mean-based effect size next to a
rank-based p-value would be internally inconsistent.

**Cost:** medians hide *how much* an outlier cost you, which matters when the outlier
itself is informative (a stalled trial is evidence about the lab's resource constraints,
worth reporting in Limitations even though it's excluded from the headline number).

## The dashboard and report never disagree — by construction, not by discipline

`dashboard.html` and `report.html` are read-only: they compute their own statistics in
JavaScript from the same CSVs `plot_results.py` reads, rather than trusting a cached
number. `serve.py`'s background thread never writes to `breach.flag`, the manifests, or
the incidents CSV — only to `results/status.json`, its own scratch file.

**Cost:** "never disagree by construction" turned out to be aspirational rather than
actual — an audit found the two pages computed medians over different row subsets
(one excluded unattributed detections, one didn't) and produced different numbers from
identical data, since fixed. The lesson generalises: two independent recomputations of
the same statistic are two chances to disagree, not zero. A later audit found them printing the
same reduction with opposite signs; both now say "X% faster" / "X% slower". A single
`summary.json` that every view renders remains the more robust design and is listed as an open
improvement in `docs/AUDIT-FINDINGS.md`.
