# Argus — Setup Guide (Windows 11)

This guide sets up the whole Argus project on a **Windows 11** computer, one step at a
time. You do **not** need to be a programmer — if you can copy text, paste it, and press
**Enter**, you can do this. Every step ends with a **✅ Verify/Check** you must pass
before moving on; don't skip these, they tell you whether the last step actually worked.

> **Honest heads-up.** Nothing here can harm your computer. A full working demo — Docker,
> DVWA, detection, and self-healing — takes about **45–60 minutes**, mostly waiting on
> downloads, and does **not** require Wazuh (Step 11 is optional). If your brief or
> supervisor specifically wants a real IDS/IPS product in the loop, budget another
> **1–1.5 hours** and **≥ 8 GB RAM free** / ~15 GB disk for that optional step. Every
> laptop-vs-enterprise simplification is flagged with a **⚠️ Limitations** box so you can
> address it honestly in your report.

Commands prefixed `PS>` run in **Windows PowerShell (Admin)**; commands prefixed `$` run
**inside your WSL2 Ubuntu shell**.

---

## Before you start: what you need

- A **Windows 11** (64-bit) laptop or PC you can install software on, with virtualization
  enabled in BIOS/UEFI, and an admin account (most personal laptops already qualify).
- **8 GB of RAM installed** (with ~3 GB genuinely *free* when you start) and about **6 GB
  of free disk space**. The optional Wazuh step (Step 11) needs **8 GB free** on top of
  that, so it is out of reach on most student laptops — this is exactly why the default
  detection path is the built-in watcher in Step 7.
  > ⚠️ **On a 6 GB machine this is tight.** WSL2 claims ~50% of total RAM on startup, so
  > with little free memory it fails with
  > `Insufficient system resources … CreateVm/HCS/0x800705aa` and can take the running
  > containers down with it. If you hit that, see **Troubleshooting → "WSL won't start"**.
- A steady **internet connection** and **about an hour**, mostly spent waiting on
  downloads.
- The **Argus project folder** (the one containing this file) — keep it somewhere easy to
  find, like your Desktop, for now.

### Words you'll see

| Word | What it really means |
|---|---|
| **Terminal** ("command line") | A plain text window where you type an instruction and press Enter, instead of clicking buttons. |
| **WSL / Ubuntu** | A second, lightweight Linux OS running *inside* Windows. Our tools prefer it. |
| **Docker** | Software that runs apps inside sealed boxes called **containers**. |
| **Container** | One of those sealed boxes with an app inside — we run the practice website in one. |
| **Image** | The "recipe" a container is built from. A **golden image** is our trusted, clean recipe. |
| **DVWA** | A practice website that is *deliberately* full of weaknesses, made for security learning. We protect it. |
| **Wazuh** | A security-guard program that watches files for changes and raises an alarm. Optional here — Argus ships a lighter built-in watcher that does the same job (Step 7); Wazuh (Step 11) is only needed if your brief wants a real IDS product in the loop. |
| **Python** | The language Argus is written in — you only *run* it, you don't write any. |

### The three actions you'll repeat

**Action A — Open PowerShell as Administrator:** Start → type `powershell` → click
**"Run as administrator"** → **Yes** if prompted.

**Action B — Open the Ubuntu terminal:** Start → type `ubuntu` → click the **Ubuntu**
app. First time, it may ask you to invent a **username** and **password** — write these
down.

**Action C — Run a command:** copy it from this guide (Ctrl+C), click inside the
terminal, paste (**Ctrl+V** in PowerShell; right-click or **Ctrl+Shift+V** in Ubuntu),
press **Enter**, then wait for the prompt to return before running the next one. In the
Ubuntu terminal, a password prompt shows **nothing** as you type — that's normal.

---

## Step 0 — Prerequisites check

**✅ Verify** virtualization is on:
```
PS> Get-ComputerInfo -Property "HyperVRequirementVirtualizationFirmwareEnabled"
```
Expect `True`. If `False`, enable Intel VT-x / AMD-V in BIOS first (restart, press
F2/F10/Del during boot — the screen tells you which — find **Virtualization**, turn it
**On**, save and exit).

---

## Step 1 — WSL2 + Ubuntu

**What this does:** installs the clean Ubuntu workshop our tools like to run in.

Open **PowerShell as Administrator** (Action A) and run one at a time (Action C):
```
PS> wsl --install -d Ubuntu-24.04
PS> wsl --set-default-version 2
PS> wsl --update
```
Reboot when prompted, then open **Ubuntu** from the Start menu once to finish setup
(invent a username and password — write them down).

**✅ Verify:**
```
PS> wsl --list --verbose
```
Ubuntu-24.04 must show `VERSION 2` and `STATE Running`.

**If it didn't work:** the most common cause is virtualization being off — see Step 0.

⚠️ **Limitations:** WSL2 is a single-kernel VM sharing your host — not the multi-host
network segmentation of a real cluster. Note this when you discuss network isolation.

---

## Step 2 — Docker Desktop

**What this does:** lets us run the practice website safely in its own box.

1. Download **Docker Desktop for Windows** from the official Docker site and install
   with the defaults.
2. Start Docker Desktop; wait for the whale icon near the clock to stop animating.
3. **Settings → General** → tick **"Use the WSL 2 based engine."**
4. **Settings → Resources → WSL Integration** → enable **Ubuntu-24.04**.
5. **Apply & Restart.**

**✅ Verify (from inside Ubuntu, Action B):**
```
$ docker run --rm hello-world
$ docker compose version
```
The first prints "Hello from Docker!"; the second prints a version number.

**If it didn't work:** make sure Docker Desktop is running (whale icon present) and the
Ubuntu switch from step 4 is on, then retry.

---

## Step 3 — System packages, Python, Git (inside Ubuntu)

**What this does:** installs the language Argus runs on, plus a couple of helpers.

```
$ sudo apt update && sudo apt -y upgrade
$ sudo apt install -y python3 python3-venv python3-pip git curl build-essential
```

**✅ Verify:**
```
$ python3 --version    # expect 3.10+
$ git --version
$ curl --version | head -1
```

---

## Step 4 — Get Argus and run the test suite

**What this does:** copies the project into the Ubuntu workshop and runs its built-in
self-test, so you know the "brain" works before adding Docker or Wazuh.

Place the project inside your Linux home (`~`), **not** under `/mnt/c` — filesystem
watching (needed for real-time FIM and snapshots) is far faster on the native ext4 side.
The easy way to copy it in: run `explorer.exe .` from the Ubuntu terminal — a normal
Windows Explorer window opens on your Ubuntu home folder — then drag-and-drop the
`argus` folder into it. (Or `git clone <your repo> argus` if it's in a repo.)

```
$ cd ~/argus
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
$ python -m pytest -q
```

**✅ Verify:** ends with **`8 passed`**. This proves the whole detect→heal loop (and the
lightweight FIM watcher from Step 7) works before you add Docker or Wazuh — a clean
baseline for debugging later. 🎉

> **Note:** every time you open a **new** Ubuntu terminal for this project, first run:
> ```
> cd ~/argus && source .venv/bin/activate
> ```

---

## Step 5 — Bring up the protected target (DVWA)

**What this does:** starts DVWA, the practice website, in its own sealed box.

First, **pull the image and seed the web root.** This seeding step is required and easy to
miss: `docker-compose.yml` bind-mounts `./runtime/webroot` over the container's
`/var/www/html`, and an *empty* host folder therefore **hides** DVWA's built-in files.
The image's startup script (`/main.sh`) only starts MySQL and Apache — it never copies its
own files out — so without seeding, every page returns **404**. We copy the files out of a
throwaway container once, then let the mount take over:

```
$ cd ~/argus
$ mkdir -p runtime/webroot
$ docker compose pull web
$ docker run -d --name argus_seed vulnerables/web-dvwa:latest sleep 300
$ sleep 2 && docker cp argus_seed:/var/www/html/. runtime/webroot/
$ docker rm -f argus_seed
```

**✅ Verify the seeding worked** before starting the real service — you should see DVWA's
files (`login.php`, `index.php`, `dvwa/`, …):
```
$ ls runtime/webroot | head
```

Now start the protected service on top of the seeded web root:
```
$ docker compose up -d web
```

**✅ Verify:** (allow ~15s for MySQL and Apache to finish starting)
```
$ sleep 15
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/login.php   # expect 200 or 302
```
Then open `http://localhost:8080` in a browser and click **"Create / Reset Database"**
once so the app is fully live.

**If it didn't work:** a **404** means the web root wasn't seeded — redo the seeding block
above. A **000**/connection-refused usually just means the container is still booting;
wait 15s and retry the curl.

⚠️ **Limitations:** DVWA is intentionally vulnerable and must stay on the isolated lab
networks defined in `docker-compose.yml`. A production target would be a hardened app;
the detection/healing loop is identical, but the *attack surface* here is deliberately
wide.

---

## Step 6 — Build the golden baseline

**What this does:** saves a known-good, trusted copy of the website that Argus rebuilds
from every time it repairs damage. **Both commands are required** — the manifest records
file hashes, but the healer also launches fresh containers directly from the
`argus/dvwa-golden:latest` image tag, so skipping the `docker tag` line will make the
first heal fail with "no such image."

```
$ docker tag vulnerables/web-dvwa:latest argus/dvwa-golden:latest
$ python run_argus.py init-golden
```

**✅ Verify:** the second command prints **"golden manifest written … (N files)."**

---

## Step 7 — Turn on detection (no Wazuh needed)

**What this does:** starts the built-in lightweight file-integrity watcher
(`argus/fim_watch.py`). It polls `runtime/webroot`, hashes it, compares against your
golden manifest from Step 6, and writes `runtime/breach.flag` the moment something
doesn't match. `detector.py` doesn't care *how* that flag file gets written — Wazuh
(Step 11, optional) and this watcher are interchangeable detection sources — so this is
the fast path to a fully working demo without a second Docker stack.

In a **second** Ubuntu terminal (project active — see the note in Step 4), start the
watcher and leave it running:
```
$ python run_argus.py watch
```
It prints `[fim_watch] watching …` and waits.

**✅ Verify:** in a **third** terminal (project active), drop an unexpected file and
watch the flag appear on its own within a couple of seconds:
```
$ echo "test" > runtime/webroot/probe.php
$ sleep 3
$ cat runtime/breach.flag       # a line starting "fim_watch: new: probe.php" should appear
$ rm -f runtime/webroot/probe.php runtime/breach.flag
```

⚠️ **Limitations:** this watcher polls on a fixed interval and only sees filesystem
state, not live process/network behaviour — a real IDS like Wazuh (Step 11) also
correlates syscalls, log patterns, and can react faster via kernel-level hooks. Document
this as a resource-driven design choice: same detection *contract* (writes
`breach.flag`), lighter *implementation*.

---

## Step 8 — See Argus detect and heal, end to end

**What this does:** proves the whole detect-and-repair loop works with the watcher from
Step 7 doing real detection (not a manual trigger).

In your **first** Ubuntu terminal (project active), start Argus and leave it running:
```
$ python run_argus.py run
```
It prints `controller started` and waits, watching. Make sure the Step 7 watcher is
still running in its own terminal.

In a **third** Ubuntu terminal (project active), pretend to be an attacker:
```
$ echo "test" > runtime/webroot/surprise.php
```

**✅ Verify:** within a few seconds the **first** terminal prints an **INCIDENT** line
showing `detected_by=signature` and the recovery time, and `surprise.php` is gone —
replaced by a freshly re-promoted, clean container. That's the self-healing loop working
end to end, with no Wazuh involved. 🎉

Leave both the watcher and the controller running for the next step, or press **Ctrl+C**
in each terminal to stop them for now.

---

## Step 9 — Run the experiment and generate figures

**What this does:** produces the numbers and charts for your report — how fast Argus
detects and repairs damage, versus doing it by hand.

Make sure the **watcher** (Step 7) and the **controller** (Step 8) are both running in
their own terminals. In another terminal (project active):
```
$ python lab/attacker/run_experiment.py --arm argus    --trials 20 --scenario webshell
$ python lab/attacker/run_experiment.py --arm argus    --trials 20 --scenario deface
```
Then, to measure the manual/baseline arm for comparison, **stop the controller** (Ctrl-C
in its terminal) so recovery is truly manual — the watcher can keep running, it's
harmless without the controller to act on its flag — and run:
```
$ python lab/attacker/run_experiment.py --arm baseline --trials 20 --scenario webshell
```
Finally, turn the numbers into charts:
```
$ python lab/plot_results.py
```

**✅ Verify:** `results/summary.txt` reports MTTD/MTTR/FPR and the **% MTTR reduction**,
and `results/fig_*.png` are written — these go straight into your Results chapter. 🎉🎉

---

## Step 10 — Done (for most setups)

If Steps 1–9 all passed, you have a fully working, self-contained Argus demo and a
`results` folder full of report-ready numbers. **You do not need Wazuh.** Only continue
to Step 11 if your brief specifically asks for a real IDS/IPS product in the loop, or you
want the enterprise-realism talking point for your report.

---

## Step 11 (optional) — Deploy Wazuh instead of/alongside the watcher

> **This is the longest and most technical step, and it's optional.** Go slowly and copy
> carefully. If your laptop is low on memory, use **Option 11B** instead of 11A.

**What this does:** installs Wazuh, a real commercial-grade IDS/FIM product, as an
alternative or complement to the Step 7 watcher — both write the same `breach.flag`,
so you can run either, or both side by side.

### Option 11A — Full Wazuh (needs ~8 GB RAM free)

```
$ sudo sysctl -w vm.max_map_count=262144
$ cd ~
$ git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.6
```
> If that version tag ever fails, check `git tag -l` or the official
> **documentation.wazuh.com/current/deployment-options/docker/** page for the current
> tag and any changed steps.
```
$ cd wazuh-docker/single-node
$ docker compose -f generate-indexer-certs.yml run --rm generator
$ docker compose up -d
```
First start takes several minutes (pulls indexer + manager + dashboard).

**✅ Verify:**
```
$ docker compose ps         # manager, indexer, dashboard all "running"/"healthy"
```
Then open **https://localhost** ("advanced → proceed" past the self-signed cert
warning). Log in with `admin` / `SecretPassword` and **change it immediately** (Wazuh's
docs show the hash-reset procedure).

⚠️ **Limitations:** a single-node Wazuh with self-signed certs and default-then-changed
credentials is a lab simplification. Enterprises run a multi-node HA indexer cluster with
proper PKI. Say so — and note the RAM cost forced the single node.

### Option 11B — Lighter Wazuh (if RAM-constrained)

Run only the **Wazuh manager** container (skip indexer/dashboard) and point
`wazuh_alerts_path` in `config/argus.yaml` at the manager's `alerts.json`. You lose the
dashboard UI but keep detection. Document this as a resource-driven design choice.

### Wire Wazuh's alarm into Argus

Copy the Argus config pieces into the running **manager** container. If the container
name below doesn't match yours, run `docker ps` and use the real name (look for one
containing `manager`):
```
$ docker cp ~/argus/config/wazuh/local_rules.xml \
    single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
$ docker cp ~/argus/config/wazuh/argus-quarantine.sh \
    single-node-wazuh.manager-1:/var/ossec/active-response/bin/argus-quarantine.sh
$ docker exec single-node-wazuh.manager-1 \
    chmod 750 /var/ossec/active-response/bin/argus-quarantine.sh
```

Install the Wazuh **agent** inside Ubuntu so it can watch your real files. The exact
install commands change per release, so follow the current
**"Install Wazuh agent on Linux (Debian/Ubuntu)"** page:
`documentation.wazuh.com/current/installation-guide/wazuh-agent/`. When it asks for the
manager address, use `127.0.0.1`.

WSL2 doesn't run systemd by default, so start the agent by hand:
```
$ sudo /var/ossec/bin/wazuh-control start
$ sudo /var/ossec/bin/agent_control -l   # (run on the manager) agent shows "Active"
```

Open `config/wazuh/ossec-fim.conf`, merge its FIM + active-response blocks into the
**agent's** `/var/ossec/etc/ossec.conf`, and change the `<directories>` line to your real
webroot path (usually `/home/YOUR-UBUNTU-USERNAME/argus/runtime/webroot`). Restart both:
```
$ sudo /var/ossec/bin/wazuh-control restart                 # agent
$ docker restart single-node-wazuh.manager-1                # manager
```

**✅ Verify** the FIM → active-response chain end-to-end (stop the Step 7 watcher first
so you can tell which source fired):
```
$ echo "test" > ~/argus/runtime/webroot/fim_probe.php
$ sleep 5
$ cat ~/argus/runtime/breach.flag       # a line should appear
$ rm ~/argus/runtime/webroot/fim_probe.php
```
If `breach.flag` was written, the automatic gate works. 🎉 (If not, check the agent's
`ossec.log` and that rule IDs 100200–100202 loaded on the manager.)

⚠️ **Limitations:** monitoring the host-mounted web root (rather than an in-container
agent per service) is a laptop simplification. In production you'd ship an agent inside
each container image or use a sidecar. It assumes the bind mount faithfully reflects
container state (it does for DVWA).

---

## Troubleshooting

- **"WSL won't install" / a virtualization error.** Enable virtualization in BIOS (see
  Step 0), then redo Step 1.
- **"docker: command not found" or the whale icon is missing.** Docker Desktop isn't
  running or the Ubuntu integration switch is off — see Step 2.
- **A command "hangs" and does nothing.** Long downloads look frozen; give it a few
  minutes before worrying.
- **A password prompt shows nothing as I type.** Normal in the Ubuntu terminal — type it
  and press Enter.
- **"Permission denied."** You probably left off `sudo` at the start of the line — add it
  and retry.
- **`python run_argus.py watch` exits immediately with "golden manifest not found."**
  You skipped Step 6 — run `python run_argus.py init-golden` first.
- **`docker cp ... single-node-wazuh.manager-1 ...` fails with "no such container."** The
  container has a different name on your machine — run `docker ps`, find the one
  containing `manager`, and use that exact name. (Only relevant if you did Step 11.)
- **The website won't open at http://localhost:8080.** Rerun `docker compose up -d web`,
  wait a minute, refresh.
- **Every DVWA page returns 404 (but the container is `Up`).** The web root wasn't seeded,
  so the empty bind mount is hiding DVWA's files. Redo the seeding block in Step 5. Check
  with `ls runtime/webroot` — if it's empty, that's the cause.
- **`Insufficient system resources … Wsl/Service/CreateInstance/CreateVm/HCS/0x800705aa`
  ("WSL won't start").** Windows can't allocate the WSL2 VM because too little RAM is
  free. Either free memory (close browsers/editors, or reboot), or cap what WSL asks for
  by creating `C:\Users\<you>\.wslconfig` with:
  ```
  [wsl2]
  memory=2GB
  processors=2
  ```
  then run `wsl --shutdown` in PowerShell and start again. Note this failure can stop
  already-running containers, so re-check Step 5 afterwards with `docker ps`.
- **First heal fails with "no such image."** You skipped the `docker tag` command in
  Step 6 — the golden image tag is required, not optional.
- **Still stuck?** Note the exact red error text and show it to your supervisor — it
  usually points straight at the fix.

---

## Consolidated Limitations (for your report)

| Simplification (laptop) | Enterprise equivalent | Where it bites |
|---|---|---|
| Single WSL2 host | Multi-host cluster / K8s | network isolation is logical, not physical |
| Polling FIM watcher (`fim_watch.py`) by default, instead of a real IDS | Wazuh/enterprise IDS with kernel-level hooks, log correlation, threat intel | detection is filesystem-only and interval-based, not real-time or behaviour-aware — mitigated by the anomaly layer (`anomaly.py`) and the optional Wazuh path (Step 11) |
| Single-node Wazuh, self-signed certs *(if you enable Step 11)* | HA indexer cluster + PKI | availability, cert trust |
| Host-mounted web root for FIM | per-container/sidecar agents | assumes mount == container state |
| Docker bind-mount snapshots | volume/CSI snapshots or CRIU | no live-process capture, only filesystem |
| Fixed `NOTICE_DELAY` in baseline | real human MTTA distribution | control arm is modelled, not measured (run a human trial too if you can) |
| Benign attack markers | live exploit traffic | detection is FIM-observable-equivalent, not full exploit fidelity |
| IsolationForest on 9 host features | deep models on rich telemetry | anomaly ceiling; autoencoder is Future Work |

Address each of these explicitly in the **Limitations** section and every laptop
constraint becomes a defensible, examiner-proof design decision — because this runs on a
single laptop, it's normal and expected to simplify scale, not the underlying mechanism.

Note for your report: this file also documents *how* setup was simplified. Point back to
it if asked to justify a shortcut.
