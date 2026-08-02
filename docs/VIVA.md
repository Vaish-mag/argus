# Argus — running it, and defending it

Two things in one place: exactly how to execute the project, and how to explain and defend
it. Figures quoted here come from `results/summary.txt` — regenerate and re-read them
before you present, rather than trusting the numbers written down at any moment.

---

# Part 1 — How to run it

Everything happens in the **Ubuntu terminal** (Start → type `ubuntu`). You will open
**four** windows; to open another, click Start → Ubuntu again.

**Every window begins with this line, without exception:**

```bash
cd ~/argus && source .venv/bin/activate
```

Your prompt must then show `(.venv)`. If it does not, `python` will not be found and
nothing will work. This is the single most common way the run goes wrong.

Two more rules, both learned the hard way:

- **Never type while a command is running.** Keystrokes are buffered and execute the
  moment it finishes — which has previously torn the lab down mid-experiment.
- **Only press Ctrl+C where step 8 says to.** Stopping the controller early means nothing
  heals, and every remaining trial times out.

## Step 1 — T1: bring up the lab

```bash
docker rm -f argus-web; docker compose up -d web && sleep 20 && curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/login.php
```

Expect `200`. The `docker rm -f` is required because the healer creates replacement
containers through the Docker SDK rather than compose, so the name collides on the next
`docker compose up`. This is expected after any heal, not a fault.

If the web root is ever empty, the bind mount hides DVWA's files and every page returns
404. Re-seed it:

```bash
mkdir -p runtime/webroot && docker run -d --name argus_seed vulnerables/web-dvwa:latest sleep 300 && sleep 2 && docker cp argus_seed:/var/www/html/. runtime/webroot/ && docker rm -f argus_seed
```

## Step 2 — T1: reset to a clean slate

```bash
rm -f results/incidents.csv results/incidents_baseline.csv runtime/breach.flag runtime/attack_marker.json && rm -rf results/snapshots results/forensics && echo clean
```

## Step 3 — T1: build the golden baseline

```bash
docker tag vulnerables/web-dvwa:latest argus/dvwa-golden:latest && python run_argus.py init-golden
```

Expect `584 files` **and** `golden web root copied`. Both commands matter: the manifest
holds the hashes, the image tag is what replacement containers are built from, and the
content copy is what a golden-source restore actually lays down.

The web root must be clean at this moment — this command defines "trusted" for the whole
run. A stray file here is silently baked into the baseline and detection stops working.

## Step 4 — T1: start the watcher — leave running

```bash
python run_argus.py watch
```

## Step 5 — T2: start the controller — leave running

```bash
python run_argus.py run
```

## Step 6 — T3: start the dashboard server — leave running

```bash
python lab/serve.py
```

Then open in a browser:

- live dashboard — <http://localhost:8090/lab/dashboard.html>
- results report — <http://localhost:8090/lab/report.html>

## Step 7 — T4: the Argus arm

```bash
python lab/attacker/run_experiment.py --arm argus --trials 20 --scenario webshell
```

Takes roughly eight minutes. Wait for the `(.venv)` prompt to return.

## Step 8 — T2: stop the controller

Click on **T2** and press **Ctrl+C**. The controller must be dead so that baseline
recovery is genuinely manual — this is the whole basis of the comparison.

## Step 9 — T4: the baseline arm

```bash
python lab/attacker/run_experiment.py --arm baseline --trials 20 --scenario webshell
```

Roughly fifteen minutes: each trial carries a deliberate 30-second operator-notice delay.

## Step 10 — T4: generate the results

```bash
python lab/plot_results.py
```

Read the line marked `reduction (median, quote this)`. Then reload the report page.

## Step 11 — back up the results

`results/` is generated data and deliberately not in Git, so nothing else is protecting it.

```bash
cp -r ~/argus/results ~/argus-results-FINAL && cd ~/argus-results-FINAL && explorer.exe .
```

## Which window does what

| Window | Runs | Touch again? |
|---|---|---|
| T1 | watcher | no |
| T2 | controller | only Ctrl+C at step 8 |
| T3 | dashboard server | no |
| T4 | experiments, plotting | yes — everything else |

## The live demo

For a demo, clones must appear inside the demo window, so shorten the cycle first:

```bash
sed -i 's/^snapshot_interval_sec: 900/snapshot_interval_sec: 60/' config/argus.yaml
```

Restart the controller, wait about seventy seconds for a clone, then:

```bash
bash lab/demo.sh
```

It pauses at each stage so you can narrate, and prints the artefact that proves each one.
Keep the dashboard on screen: the audience watches drift turn red, the breach signal fire,
the container identity change, and the incident row appear.

**Set the interval back to 900 afterwards** — the brief specifies a 10–20 minute cadence.

---

# Part 2 — Defending it

## The pitch

> Argus is an autonomic controller that protects a containerised web application. It keeps
> SHA-256-verified clean copies of the site, monitors file integrity continuously, and on
> tampering it preserves forensic evidence, isolates and destroys the compromised
> container, rebuilds from a verified-clean source, health-checks it, and promotes the
> replacement — with no human in the loop. It is structured as a MAPE-K loop. Measured
> against a scripted manual recovery, detection falls from thirty seconds to a few, and
> end-to-end recovery roughly halves.

## Architecture — know this without notes

MAPE-K: Monitor, Analyse, Plan, Execute, over shared Knowledge.

| Stage | Where it lives |
|---|---|
| Monitor | `fim_watch.py`, `sensors.py` |
| Analyse | `detector.py` — fuses signature and anomaly evidence |
| Plan | `healer._select_source` |
| Execute | `healer.heal` |
| Knowledge | `manifest.py`, the snapshots, the golden baseline |

The heal sequence, in order — and the order is the point:

**forensics → isolate → destroy → restore → verify → health-check → promote**

Evidence is captured *before* destruction. The executable base is always the golden image,
never the compromised one, so even a subtly stale clean clone cannot reintroduce the
compromise.

## The metrics, and which one to quote

- `MTTD` — attack to detection
- `MTTR` — detection to promotion
- `TotalRecovery` — attack to service healthy again

**Quote TotalRecovery.** MTTR starts its clock at detection, so the manual arm's
operator-notice delay lands in MTTD and cancels out of an MTTR-only comparison. Reporting
MTTR alone understates the result — at one point it showed the two arms as near-identical
when end-to-end they differed by the entire notice delay.

## Questions you will be asked

**"Is that a real attack?"** No — volunteer this before they ask. `attack_lib.py` writes an
inert PHP comment that reproduces the *filesystem observable* of a webshell upload: no
payload, no code execution, no callback. Detection is file-integrity monitoring, so the two
are equivalent from the detector's point of view. No exploit fidelity is claimed.

**"Where does the thirty-second delay come from?"** This is the weakest point in the whole
project. `NOTICE_DELAY_SEC` models human mean-time-to-acknowledge and drives the entire
comparison. Justify it against a cited industry figure, or state plainly that it is a
modelled parameter and show how the result behaves at other values.

**"What stops a poisoned backup being restored?"** Two gates. `diff_against_golden` refuses
clean status to any clone deviating from the baseline, so it is retained for forensics but
never promoted. And the executable base is always the golden image. The dashboard's clone
table shows refused clones directly — point at it.

**"What if the attacker edits the golden manifest?"** It cannot currently be defended: it is
a trust anchor sitting on the same host. Say so. Inventing a defence you did not build is
far worse than naming the gap.

**"Why is MTTR only modestly better?"** Because the controller does strictly more work per
recovery — forensic capture, network isolation, hash verification of every restored file,
and a health gate before promotion. The scripted manual recovery only stops the container,
copies files back, and restarts it. The advantage is in detection, and in evidence
preservation the manual process never performs at all.

**"Why is Wazuh documented but not used?"** Wazuh is the enterprise detection path and needs
around 8 GB of free memory; the lab machine has 5.8 GB total. Detection is consumed as a
plain flag file, so the built-in watcher is interchangeable with it. A resource-driven
design decision, documented rather than hidden.

**"Does this only work with DVWA?"** No. `protected_container`, `protected_path` and
`host_webroot` in `config/argus.yaml` point it at any container with a bind-mounted
directory. The loop never inspects the application.

## What DVWA is, if asked

Damn Vulnerable Web Application: an open-source PHP/MySQL application built deliberately
insecure so that security work can be practised legally and reproducibly. It is the
standard teaching target in this field. It is the patient, not the contribution. Attacking
a real application would be illegal and unethical; DVWA exists to be the substitute. It is
also unrepresentative of a hardened production target — which affects the realism of the
breach, not the validity of the recovery measurements.

## Your strongest material

Five real defects were found by *running* the system, not by reading it, and each is now
covered by a regression test:

1. MTTD was never measured — the daemon had no channel to learn when the attack happened,
   and every genuine incident was consequently mislabelled a false positive.
2. Snapshots could never be marked clean. Docker's archive format wraps contents in a
   directory named after the source path, so manifest keys read `html/index.php` against a
   golden baseline keyed `index.php`; every file looked new, so the verified-clean restore
   path was unreachable and every heal silently fell back to the golden image.
3. Restored containers silently lost the web-root bind mount, so the directory being
   monitored drifted away from what the container served.
4. One attack produced an endless heal loop: the container was rebuilt but the host web
   root was never cleaned, so the monitor re-detected the same artefact forever.
5. The experiment harness used a container-internal path as a host path and crashed on the
   first trial; in the baseline arm the same bug would have deleted the wrong directory.

Then a measurement bug worth telling on its own: a single stalled trial — the VM starved of
memory while wall-clock time continued — produced a 5063-second outlier that dragged the
mean into reporting a *negative* improvement, concealing a real one of roughly 56%. Fixed
by reporting medians, which is also the statistic consistent with the rank-based
Mann-Whitney test already being used. Quoting a mean-based effect size beside a rank-based
p-value was incoherent.

This narrative demonstrates empirical rigour far more convincingly than tidy code does.

## Limitations to raise before they are found

- Single WSL2 host: network isolation is logical, not physical
- Benign attack markers rather than live exploit traffic
- The operator-notice delay is modelled, not observed
- DVWA is deliberately vulnerable and unrepresentative of production
- Filesystem-only detection; no live process or memory capture
- IsolationForest over nine host features; an autoencoder is future work
- A third-party Docker image is itself a supply-chain assumption
- Trial counts are small, and the lab machine is memory-constrained enough that a stalled
  trial is a real measurement threat — report the hardware conditions alongside the numbers
