# Flow

Two flows matter: the detect→heal cycle that runs continuously, and the experiment that
measures it. Both are described here as they actually execute, file by file.

## Detect → heal, one incident

```mermaid
sequenceDiagram
    participant Attacker as attack_lib.py
    participant Root as runtime/webroot (host)
    participant Watch as fim_watch.py
    participant Detector as detector.py
    participant Healer as healer.py
    participant Docker as Docker engine
    participant Metrics as incidents.csv

    Attacker->>Root: write/delete a file
    loop every 2s
        Watch->>Root: hash every file
        Watch->>Watch: diff against golden_manifest.json
    end
    Watch->>Root: write runtime/breach.flag
    Detector->>Root: read + unlink breach.flag
    Detector->>Detector: fuse with anomaly score (if a model is loaded)
    Detector->>Healer: BreachEvent(detected_by, detail)
    Healer->>Docker: copy_out (forensics) -- BEFORE destruction
    Healer->>Healer: docker commit (optional, ~1GB)
    Healer->>Docker: disconnect_network (isolate)
    Healer->>Docker: stop_and_remove (destroy)
    Healer->>Healer: select restore source: snapshot > golden_webroot > golden image
    Healer->>Root: wipe + repopulate host web root
    Healer->>Docker: run golden image, re-attach bind mount + network
    Healer->>Healer: verify restored root against chosen manifest
    Healer->>Docker: poll health_url up to health_retries times
    Healer->>Metrics: record Incident (mttd, mttr, total_recovery, restore_source)
    Detector->>Root: clear_signals() -- drop any signal raised mid-heal
```

Two things about this sequence that are easy to miss reading the code top to bottom:

- **Forensic capture happens before isolation, which happens before destruction.** This
  ordering is the entire point of the "preserve evidence first" requirement, and it is why
  `copy_out` is the very first Docker call in `heal()`.
- **The healer, not `docker compose`, owns the replacement container's lifecycle.** After
  the first heal, `argus-web` is a container the healer created directly via the Docker
  SDK. Running `docker compose up -d web` again afterwards will report a name conflict —
  expected, not a bug (see `docs/RUNNING-LOCALLY.md`, Phase C.3).

## The experiment: two arms, one comparison

```mermaid
sequenceDiagram
    participant Harness as run_experiment.py
    participant Marker as attack_marker.json
    participant Controller as controller.py (Argus arm only)
    participant Manual as baseline_recovery.py (baseline arm only)
    participant CSV as incidents*.csv

    Note over Harness: ARGUS ARM
    loop N trials
        Harness->>Marker: write {t_attack, scenario}
        Harness->>Harness: inject artefact
        Controller->>Controller: detect + heal (see previous diagram)
        Controller->>CSV: record into incidents.csv
        Harness->>CSV: poll for the new row
    end

    Note over Harness: controller stopped (Ctrl-C) so recovery is genuinely manual

    Note over Manual: BASELINE ARM
    loop N trials
        Manual->>Manual: inject artefact, record t_attack
        Manual->>Manual: sleep NOTICE_DELAY_SEC (models human MTTA)
        Manual->>Manual: docker stop, copy last clone back, docker start
        Manual->>Manual: poll health_url
        Manual->>CSV: record into incidents_baseline.csv
    end

    Note over Harness: python lab/plot_results.py reads both CSVs, writes summary.txt + figures
```

### Where each metric's clock starts and stops

```mermaid
gantt
    dateFormat  s
    axisFormat %Ss
    section Argus arm
    MTTD (attack -> detect)      :0, 3
    MTTR (detect -> promoted)    :3, 15
    section Baseline arm
    MTTD (modelled notice delay) :0, 30
    MTTR (detect -> healthy)     :30, 44
```

`total_recovery` spans the whole bar in both rows: attack to healthy, the fair
arm-to-arm comparison. Quoting MTTR alone hides the notice delay the controller removes —
see `docs/AUDIT-FINDINGS.md` M4 for why the total-recovery *significance test* still needs
a caveat even so.

### Known fragility in this flow

Two things worth knowing before trusting a dataset produced by this flow, detailed fully
in `docs/AUDIT-FINDINGS.md`:

- `attack_marker.json` is only deleted when a detection consumes it — a timed-out trial
  leaves it on disk, and the next detection (possibly hours later) can silently inherit
  the stale timestamp.
- The Argus arm's restore source is hash-verified against the golden baseline; the
  baseline arm's is not. The two arms do not currently share a definition of "recovered."

## Presentation data flow

```mermaid
flowchart LR
    Controller[controller.py] -->|writes| CSV[(incidents.csv)]
    Serve[serve.py background thread] -->|docker ps, hash webroot, every 2s| Status[(results/status.json)]
    CSV --> Dashboard[dashboard.html]
    Status --> Dashboard
    CSV --> Report[report.html]
    Baseline[(incidents_baseline.csv)] --> Report
    Summary[(summary.txt)] --> Report
    PNG[(fig_*.png)] --> Report
    PlotResults[plot_results.py] --> Summary
    PlotResults --> PNG
```

`dashboard.html` and `report.html` are plain HTML+JS with no build step; `serve.py` exists
only because a browser cannot run `docker ps` or hash a directory. It now serves an
explicit allow-list of files bound to `127.0.0.1` — see `docs/AUDIT-FINDINGS.md`, fixed
finding S1, for what it used to expose.
