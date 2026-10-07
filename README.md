# Argus — Self-Healing Moving-Target-Defence for Containerised Services

**One-sentence version:** Argus watches over a website and, the moment someone tampers
with it, automatically repairs it back to a clean, trusted copy — with no human in the
loop.

Argus is an autonomic controller that protects a containerised web service and, on a
confirmed breach, heals itself: it preserves forensic evidence, isolates and destroys
the compromised instance, and re-promotes a fresh instance built from a **known-good
golden image plus the most recent hash-verified clean clone**. It is built for an MSc
research project and is measured on two resilience metrics: **Mean-Time-To-Detect
(MTTD)** and **Mean-Time-To-Recover (MTTR)**.

> ⚠️ **Lab-only.** Argus protects a *deliberately vulnerable* app (DVWA) and the attack
> harness contains *benign* simulations. Run the whole thing on the isolated Docker
> networks defined here — never on a real or production network.

## What problem does it solve?

When a website gets hacked — say an attacker sneaks a bad file onto it or defaces a
page — the usual response is slow: a person has to *notice*, then *investigate*, then
*fix* it by hand. That gap can last hours. Argus closes that gap to **seconds**. It
constantly keeps clean, verified copies of the website, spots tampering instantly, saves
evidence, throws away the damaged version, and puts a fresh clean one back in its place.
This idea is called **self-healing**, and rotating in a fresh copy each time is a
security technique called **moving-target defence**.

A separate security tool called **Wazuh** acts as the smoke-alarm (it spots the
tampering); Argus is the fire-brigade (it does the repair). Keeping those two jobs
separate makes the whole thing easy to explain and to trust.

## Is this safe? Is it legal?

Yes. Everything runs **only on your own computer**, sealed off from the internet and
from any real network. The "attacks" in the practice lab are **harmless imitations** —
they create the same *visible trace* a real attack would (like a stray file appearing),
but contain **no actual harmful code** (see `lab/attacker/attack_lib.py`). The website we
protect (**DVWA**) is a training tool built specifically for this kind of safe, legal
security practice.

## The resilience loop (maps 1:1 to the brief)

Argus is structured as a **MAPE-K** autonomic loop (Monitor–Analyse–Plan–Execute over
shared Knowledge) — the standard self-healing reference model — see `argus/controller.py`.

| Stage | Spec requirement | Where it lives |
|-------|------------------|-----------------|
| Prevent | hardened gate: IDS/IPS + FIM watches traffic & files | `detection.FIMWatcher` (default, no extra infra) or Wazuh (`config/wazuh/`, optional, reference config) + `detection.Detector` |
| Snapshot on a cycle | clone every protected file every 10–20 min, hash-verified | `storage.Snapshotter` + `storage.Manifest` |
| Detect & isolate | flag a breach, cut the container's network immediately | `detection.Detector` → `controller.Healer` (isolate) |
| Destroy & restore | terminate compromised instance, restore from newest verified-clean clone | `controller.Healer` |
| Re-promote | verify the restored files, *then* start a new instance from the known-good baseline, health-check, promote | `controller.Healer` (restore→verify→launch→health) |
| Forensics first | snapshot the attacked instance to isolated forensics *before* deletion | `storage.Forensics` |
| Hash-manifest gate | verify every clone against a manifest before promotion | `storage.Manifest.verify` (before any container is launched) |
| Golden-image fallback | keep a golden baseline so a slow-burn compromise can't be re-promoted | `Manifest.diff_against_golden` + `Healer._candidate_sources` |
| MTTD / MTTR | core experimental metrics, graphed | `storage.MetricsLog` + `lab/plot_results.py` |
| End-to-end recovery | attack → healthy again, the comparison that includes the human notice delay | `storage.Incident.total_recovery` |
| Anomaly (ML) layer | catch unseen patterns, not just signatures | `detection.AnomalyDetector` (IsolationForest + range guard) |

## What's in this folder?

| Folder / file | What it's for |
|---|---|
| **SETUP.md** | 👉 **Start here.** The step-by-step install guide. |
| **argus/** | The "brain" — the program that does the watching and repairing. |
| **config/** | Settings, and the alarm rules for Wazuh. You rarely need to touch these. |
| **lab/** | The safe practice attacks, the manual-recovery baseline, and the results-plotting tool. |
| **tests/** | A built-in self-test that proves the brain works. |
| **results/** | Where your numbers and charts appear after you run the experiment. |
| **run_argus.py** | The single command you use to start Argus. |

```
argus/
├── argus/            # the controller library (one module per loop stage)
├── config/           # argus.yaml + Wazuh rules/active-response
├── lab/              # benign attack harness, static baseline, results plotting
├── tests/            # unit + end-to-end integration tests
├── docker-compose.yml
├── run_argus.py      # operator entrypoint (init-golden / train / run)
├── SETUP.md          # from-scratch install guide
└── requirements.txt
```

## Quick start (after completing `SETUP.md`)

Every terminal you open for this project starts with the same line — it moves you into
the project root *and* activates the virtual environment. Skipping the `cd` is the most
common cause of `.venv/bin/activate: No such file or directory`.

```bash
# 0. every new terminal starts here
cd ~/argus && source .venv/bin/activate

# 1. bring up the lab target (see SETUP.md Step 5 if the web root needs seeding first)
docker compose up -d web

# 2. tag the golden baseline image, then build the golden manifest + a pristine content
#    copy from the current (clean!) web root — both are written by this one command
docker tag vulnerables/web-dvwa:latest argus/dvwa-golden:latest
python run_argus.py init-golden

# 3. start the lightweight FIM watcher (replaces Wazuh for a fast setup; leave running)
python run_argus.py watch

# 4. (optional) train the anomaly model from a normal-traffic capture
python run_argus.py train --normal results/normal_windows.csv

# 5. in another terminal (repeat step 0 first): start the self-healing controller (leave running)
python run_argus.py run

# 6. in a third terminal (repeat step 0 first): watch it work, live
python lab/serve.py
#    then open http://localhost:8090/lab/dashboard.html in a browser

# 7. run a single narrated attack -> detect -> heal cycle (needs steps 3 and 5 running)
bash lab/demo.sh

# 8. or run the full measured experiment instead of/after the demo
python lab/attacker/run_experiment.py --arm argus    --trials 20 --scenario webshell
python lab/attacker/run_experiment.py --arm baseline --trials 20 --scenario webshell
python lab/plot_results.py
#    then open http://localhost:8090/lab/report.html for the presentable results
```

See [docs/RUNNING-LOCALLY.md](docs/RUNNING-LOCALLY.md) for the same steps in full detail,
lettered A.1–I.4, including which terminal each command goes in and how to recover from
the failures that actually happen (a stale container name after a heal, an unseeded web
root, WSL running out of memory).

## Tests

```bash
python -m pytest -q      # 14 tests incl. a full detect→heal integration test (no daemon needed)
```

All 14 should pass, including a full detect-and-repair run, the FIM-watcher unit tests,
and regression tests for defects found during development (see
[docs/AUDIT-FINDINGS.md](docs/AUDIT-FINDINGS.md)) — none of it needs the heavy
infrastructure (Docker/Wazuh) to run, which is handy for checking the core logic on its
own.

## A second target: MiniGallery (proof that Argus is target-agnostic)

DVWA is someone else's app. To show the controller is not tied to it, `lab/target2_app/`
is a small PHP photo gallery written for this project with a real, deliberately unfixed
vulnerability — **CWE-434 unrestricted file upload** in `upload.php`. A second, fully
independent Argus instance protects it using **only a config file** (`config/target2.yaml`):
no code in `argus/` changes.

One-time setup (from the project root, inside WSL, venv active):

```bash
mkdir -p runtime/webroot2 && cp -r lab/target2_app/. runtime/webroot2/
chmod 777 runtime/webroot2/uploads            # Apache runs as www-data; this dir is yours
docker tag php:8.2-apache argus/target2-golden:latest
docker compose up -d target2                  # http://localhost:8081
python run_argus.py --config config/target2.yaml init-golden
```

Then, in three terminals (each after `source .venv/bin/activate`):

```bash
python run_argus.py --config config/target2.yaml watch      # T1: detection
python run_argus.py --config config/target2.yaml run        # T2: controller
bash lab/demo_target2.sh                                    # T3: real HTTP exploit -> detect -> heal
```

The demo attacks with a genuine `curl -F "upload=@pwn.php" http://localhost:8081/upload.php`
multipart request (the payload is an inert marker), then shows the evidence preserved, the
container replaced, and the site healthy again. Both targets listen on `127.0.0.1` only.

## For the technical reader: how detection actually fires

`detection.Detector` fuses two independent evidence sources into one `BreachEvent`:

1. **Signature/FIM** — either `detection.FIMWatcher` (the default, no-extra-infra option:
   polls the web root, hashes it, diffs against the golden manifest) or Wazuh's
   active-response (optional, `config/wazuh/`) writes a `breach.flag` file and/or appends
   to an alerts JSON stream when a rule fires. Argus tails whichever is present.
2. **Anomaly** — `detection.AnomalyDetector` (an IsolationForest, calibrated at training
   time, plus a range guard for features that never varied) scores the current 9-feature
   behaviour window from `detection.HostSensor`. It must stay anomalous for
   `anomaly_confirm_windows` consecutive ticks before it triggers a heal.

Because `breach_signal_path` (`runtime/breach.flag`) is just a plain file, **anything**
that can write to it counts as a valid detection source — Wazuh is the enterprise-realism
option, not a hard requirement of the architecture. See `SETUP.md` Step 7 (default) vs.
Step 11 (optional Wazuh) for what that implies about setup effort.
