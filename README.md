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
| Prevent | hardened gate: IDS/IPS + FIM watches traffic & files | `argus/fim_watch.py` (default, no extra infra) or Wazuh (`config/wazuh/`, optional) + `detector.py` |
| Snapshot on a cycle | clone every protected file every 10–20 min, hash-verified | `snapshotter.py` + `manifest.py` |
| Detect & isolate | flag a breach, cut the container's network immediately | `detector.py` → `healer.py` (isolate) |
| Destroy & restore | terminate compromised instance, restore from newest verified-clean clone | `healer.py` |
| Re-promote | new instance from known-good baseline + restored clone, health-check, promote | `healer.py` (restore→health→promote) |
| Forensics first | snapshot the attacked instance to isolated forensics *before* deletion | `forensics.py` |
| Hash-manifest gate | verify every clone against a manifest before promotion | `manifest.py` (`verify`) |
| Golden-image fallback | keep a golden baseline so a slow-burn compromise can't be re-promoted | `snapshotter.diff_against_golden` + `healer._select_source` |
| MTTD / MTTR | core experimental metrics, graphed | `metrics.py` + `lab/plot_results.py` |
| Anomaly (ML) layer | catch unseen patterns, not just signatures | `anomaly.py` (IsolationForest) |

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

```bash
# 0. from the project root, inside your WSL2 venv
source .venv/bin/activate

# 1. bring up the lab target
docker compose up -d web

# 2. tag the golden baseline image, then build the golden manifest from the pristine web root
docker tag vulnerables/web-dvwa:latest argus/dvwa-golden:latest
python run_argus.py init-golden

# 3. start the lightweight FIM watcher (replaces Wazuh for a fast setup; leave running)
python run_argus.py watch

# 4. (optional) train the anomaly model from a normal-traffic capture
python run_argus.py train --normal results/normal_windows.csv

# 5. in another terminal: start the self-healing controller (leave running)
python run_argus.py run

# 6. in a third terminal: run the experiment
python lab/attacker/run_experiment.py --arm argus    --trials 20 --scenario webshell
python lab/attacker/run_experiment.py --arm baseline --trials 20 --scenario webshell

# 7. generate the Results-chapter figures
python lab/plot_results.py
```

## Tests

```bash
python -m pytest -q      # 8 tests incl. a full detect→heal integration test (no daemon needed)
```

Eight tests should pass, including a full detect-and-repair run and the FIM-watcher unit
tests — all work without any of the heavy infrastructure (Docker/Wazuh), handy for
checking the core logic on its own.

## For the technical reader: how detection actually fires

`detector.py` fuses two independent evidence sources into one `BreachEvent`:

1. **Signature/FIM** — either `argus/fim_watch.py` (the default, no-extra-infra option:
   polls the web root, hashes it, diffs against the golden manifest) or Wazuh's
   active-response (optional, `config/wazuh/`) writes a `breach.flag` file and/or appends
   to an alerts JSON stream when a rule fires. Argus tails whichever is present.
2. **Anomaly** — `anomaly.py`'s IsolationForest scores the current 9-feature behaviour
   window (`argus/sensors.py`) and flags a deviation from learned-normal.

Because `breach_signal_path` (`runtime/breach.flag`) is just a plain file, **anything**
that can write to it counts as a valid detection source — Wazuh is the enterprise-realism
option, not a hard requirement of the architecture. See `SETUP.md` Step 7 (default) vs.
Step 11 (optional Wazuh) for what that implies about setup effort.
