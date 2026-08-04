# Running Argus locally

Step-by-step from a clean machine to a finished experiment. Steps are lettered by phase:
**A** prerequisites, **B** install, **C** lab setup, **D** baseline, **E** running the
controller, **F** the experiment, **G** the visual layer, **H** demonstrating it,
**I** shutdown and troubleshooting.

Every command runs in the **Ubuntu terminal** (Start → type `ubuntu`) unless marked
`PowerShell`.

---

## Three rules that break runs

These have each cost a broken run. They are not optional.

1. **Every terminal starts with `cd ~/argus && source .venv/bin/activate`.** Your prompt
   must then show `(.venv)`. Without it, `python` is not found.
2. **Never type while a command is running.** Keystrokes are buffered and execute the
   instant it finishes — which has previously torn the lab down mid-experiment.
3. **Only stop the controller where step F.3 says to.** Stopping it early means nothing
   heals and every remaining trial times out.

---

## Phase A — Prerequisites

### A.1 — Check the hardware

8 GB RAM installed, ~3 GB genuinely free at start, ~6 GB disk. The project runs on less,
but timing measurements become unreliable: a memory-starved VM can stall while wall-clock
time continues, producing outliers of minutes.

### A.2 — Confirm virtualization is enabled

```powershell
Get-ComputerInfo -Property "HyperVRequirementVirtualizationFirmwareEnabled"
```

Expect `True`. If `False`, enable Intel VT-x / AMD-V in BIOS first.

### A.3 — Install WSL2 + Ubuntu

```powershell
wsl --install -d Ubuntu-24.04
```

Reboot, then launch Ubuntu once from the Start menu to create your Linux user.

### A.4 — Verify

```powershell
wsl --list --verbose
```

`Ubuntu-24.04` must show `VERSION 2`.

### A.5 — Install Docker Desktop

Install it, then in **Settings → General** tick *Use the WSL 2 based engine*, and in
**Settings → Resources → WSL Integration** enable **Ubuntu-24.04**. Apply & Restart.

### A.6 — Verify Docker reaches WSL

```bash
docker run --rm hello-world
```

If this says `command not found`, the WSL integration switch in A.5 is off.

---

## Phase B — Install the project

### B.1 — System packages

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git curl build-essential
```

### B.2 — Clone the repository

Place it in your Linux home, **not** under `/mnt/c` — filesystem watching is far faster on
native ext4.

```bash
cd ~ && git clone https://github.com/Vaish-mag/argus.git && cd ~/argus
```

### B.3 — Create the virtual environment

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

### B.4 — Run the test suite

```bash
python -m pytest -q
```

Expect **14 passed**. This exercises the whole detect→heal loop with a Docker test double,
so it proves the core logic before any infrastructure exists. If this fails, stop here.

---

## Phase C — Bring up the lab

### C.1 — Seed the web root

**This step is mandatory and easy to miss.** `docker-compose.yml` bind-mounts
`./runtime/webroot` over the container's `/var/www/html`. An *empty* host directory
therefore **hides** DVWA's own files, and the image's startup script never copies them
out — so without seeding, every page returns **404**.

```bash
mkdir -p runtime/webroot && docker run -d --name argus_seed vulnerables/web-dvwa:latest sleep 300 && sleep 2 && docker cp argus_seed:/var/www/html/. runtime/webroot/ && docker rm -f argus_seed
```

### C.2 — Verify the seeding worked

```bash
ls runtime/webroot | head
```

You should see `login.php`, `index.php`, `dvwa/`, `vulnerabilities/` and similar.

### C.3 — Start the protected service

```bash
docker rm -f argus-web; docker compose up -d web && sleep 20 && curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/login.php
```

Expect **200**.

The leading `docker rm -f` is deliberate: the healer creates replacement containers through
the Docker SDK rather than compose, so after any heal the name `argus-web` belongs to a
container compose does not manage and `docker compose up` refuses it. This is expected
behaviour, not a fault.

### C.4 — Initialise DVWA's database

Open <http://localhost:8080> in a browser and click **Create / Reset Database** once.

---

## Phase D — Build the trusted baseline

### D.1 — Confirm the web root is clean

```bash
ls runtime/webroot | wc -l
```

The next step defines "trusted" for the entire run. A stray file present now is silently
baked into the baseline and detection will not fire on it afterwards.

### D.2 — Tag the golden image and build the baseline

```bash
docker tag vulnerables/web-dvwa:latest argus/dvwa-golden:latest && python run_argus.py init-golden
```

Expect `golden manifest written … (584 files)` **and** `golden web root copied`.

All three artefacts matter and serve different purposes:

| Artefact | Purpose |
|---|---|
| `argus/dvwa-golden:latest` | the image replacement containers are built from |
| `config/golden_manifest.json` | SHA-256 hashes used to verify any restore |
| `runtime/golden_webroot/` | pristine file content laid down by a golden-source restore |

---

## Phase E — Start the controller

Open a second terminal (**T2**). Remember rule 1.

### E.1 — T1: start the integrity monitor

```bash
python run_argus.py watch
```

Prints `[fim_watch] watching …` and stays running. Leave this window alone.

### E.2 — T2: start the controller

```bash
python run_argus.py run
```

Prints `controller started; entering MAPE-K loop`. Leave this window alone until F.3.

### E.3 — Prove the loop works before measuring anything

In a third terminal (**T4** — T3 is reserved for the dashboard):

```bash
echo "test" > runtime/webroot/surprise.php
```

Within a few seconds T2 prints an `INCIDENT` line with MTTD and MTTR, and the file is gone.
Clean up before continuing so the file does not pollute your dataset:

```bash
rm -f runtime/webroot/surprise.php runtime/breach.flag
```

---

## Phase F — Run the experiment

### F.1 — Reset to a clean dataset

```bash
rm -f results/incidents.csv results/incidents_baseline.csv runtime/breach.flag runtime/attack_marker.json && rm -rf results/snapshots results/forensics && echo clean
```

### F.2 — T4: run the Argus arm

```bash
python lab/attacker/run_experiment.py --arm argus --trials 20 --scenario webshell
```

Roughly eight minutes. **Wait for the `(.venv)` prompt to return before touching the
keyboard.**

Before a long run, consider setting `commit_forensic_image: false` in
`config/argus.yaml`: each incident otherwise `docker commit`s roughly 1 GB of image, so
20 trials costs about 20 GB of disk and inflates MTTR.

### F.3 — T2: stop the controller

Click on **T2** and press **Ctrl+C**.

This is the only Ctrl+C in the procedure. The controller must be dead so baseline recovery
is genuinely manual — that is the entire basis of the comparison.

### F.4 — T4: run the baseline arm

```bash
python lab/attacker/run_experiment.py --arm baseline --trials 20 --scenario webshell
```

Roughly fifteen minutes: each trial carries a deliberate 30-second operator-notice delay.

### F.5 — T4: generate the results

```bash
python lab/plot_results.py
```

Read the line marked `reduction (median, quote this)`. Median is the headline because it is
robust to a stalled trial and is the statistic consistent with the rank-based Mann-Whitney
test printed beside it.

### F.6 — Back up the results

`results/` is generated data and deliberately excluded from Git, so nothing else protects
it.

```bash
cp -r ~/argus/results ~/argus-results-FINAL && cd ~/argus-results-FINAL && explorer.exe .
```

---

## Phase G — The visual layer

### G.1 — T3: start the server

```bash
python lab/serve.py
```

### G.2 — Open the pages

| Page | URL |
|---|---|
| Live dashboard | <http://localhost:8090/lab/dashboard.html> |
| Results report | <http://localhost:8090/lab/report.html> |

The dashboard polls every 1.5s. The report reads the same files `plot_results.py` writes,
so the two cannot disagree, and has a print-to-PDF button.

---

## Phase H — Demonstrating it live

### H.1 — Shorten the clone cadence

Clones are taken every 15 minutes by default, which is longer than any demo. For a demo
only:

```bash
sed -i 's/^snapshot_interval_sec: 900/snapshot_interval_sec: 60/' config/argus.yaml
```

Restart the controller and wait about seventy seconds so at least one clean clone exists.

### H.2 — Run the narrated demo

```bash
bash lab/demo.sh
```

It pauses at each stage and prints the artefact that proves it: the breach signal, the
forensic capture taken *before* destruction, the container identity change, and the restore
source. Keep the dashboard on screen while it runs.

### H.3 — Restore the cadence

```bash
sed -i 's/^snapshot_interval_sec: 60/snapshot_interval_sec: 900/' config/argus.yaml
```

The 10–20 minute cadence is a stated project requirement; 60s is a demo affordance only.

---

## Phase I — Shutdown and troubleshooting

### I.1 — Stop everything

```bash
pkill -f run_argus.py; pkill -f serve.py; docker compose down
```

### I.2 — Reclaim disk from forensic images

```bash
docker rmi -f $(docker images 'argus/forensic' -q)
```

### I.3 — Common failures

| Symptom | Cause and fix |
|---|---|
| `python: command not found` | venv not activated — rule 1 |
| Every DVWA page returns 404 | web root not seeded — redo C.1 |
| `Conflict. The container name "/argus-web" is already in use` | leftover container from a heal — prefix with `docker rm -f argus-web` |
| First heal fails with "no such image" | `docker tag` in D.2 was skipped |
| `golden manifest not found` | `init-golden` (D.2) not run |
| `Insufficient system resources … CreateVm/HCS/0x800705aa` | Windows cannot allocate the WSL VM. Free RAM or cap it: create `C:\Users\<you>\.wslconfig` with `[wsl2]` and `memory=3GB`, then `wsl --shutdown` |
| Trials report `TIMEOUT` | the controller died or the VM stalled. Stop — the rest of the run is worthless |
| An MTTR of minutes | the VM stalled under memory pressure. Discard and re-run on an idle machine |

### I.4 — Which window does what

| Window | Runs | Touch again? |
|---|---|---|
| T1 | integrity monitor | no |
| T2 | controller | only Ctrl+C at F.3 |
| T3 | dashboard server | no |
| T4 | experiments, plotting, demos | yes — everything else |
