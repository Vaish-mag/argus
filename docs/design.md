# Design decisions

Why the project is shaped the way it is, and what each choice costs. Written for a viva:
every entry pairs a decision with its honest trade-off.

## Detection is a plain flag file, not a Wazuh dependency

`detector.py` decides "was there a breach" by checking whether `runtime/breach.flag`
exists. It does not know or care who wrote it. This means Wazuh's active-response script
and the project's own lightweight watcher (`fim_watch.py`) are interchangeable detection
sources through one narrow, file-shaped interface.

**Why:** the enterprise-realistic path (Wazuh) needs a second Docker stack and roughly
8GB of free memory the lab machine (5.8GB total) does not reliably have. Making detection
source-agnostic meant a resource-driven design decision could be made without touching the
controller at all.

**Cost:** as found during audit (`docs/AUDIT-FINDINGS.md`, M7), the shipped Wazuh rule
files currently reference the wrong path and cannot fire — so today, `fim_watch.py` is not
a fallback, it is the *only* working detection source, and that needs saying plainly
rather than presenting Wazuh as a working alternative.

## The heal sequence is strictly ordered, and the order is the claim

`healer.py`'s eight steps — forensics, isolate, destroy, restore, verify, health-check,
promote — run in that literal order, not because it reads better, but because each step
depends on the previous one having happened and not yet been undone:

- Forensics before destroy, so evidence of the attack is never lost to remediation.
- Restore before verify, so verification checks the *actual* restored content rather than
  the intended source.
- Verify before promote, so a hash mismatch aborts before the site goes live.

**Cost:** the sequence is currently only partially load-bearing. Audit finding C6
(`docs/AUDIT-FINDINGS.md`) shows the replacement container is attached to the network and
has its port published *before* verification runs — so "verify before promote" is true of
the timestamp recorded, not of what traffic can actually reach. This is flagged as the
single highest-value design fix available: making promotion a real gate (launch
unpublished, verify, then attach) would make the "poisoned clone can never become main"
claim literally true rather than aspirationally true.

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
to read or reset "the protected content" — `fim_watch`, `snapshotter`, `healer` — operates
on the host path, not by `docker exec`-ing into the container.

**Why:** this is what lets Argus watch and restore the web root without needing a shell
inside the (possibly compromised) container, and it's what makes host-side FIM (Wazuh's
agent, or `fim_watch.py`) able to see the files directly.

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
the same statistic are two chances to disagree, not zero. A single `summary.json` that
both pages render, rather than two implementations of the same arithmetic, is the more
robust design and is listed as an open improvement in `docs/AUDIT-FINDINGS.md`.
