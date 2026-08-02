#!/bin/bash
# ---------------------------------------------------------------------------
# demo.sh -- narrated walkthrough of one attack -> heal cycle.
#
# Purpose: the heal completes in seconds and most of it leaves no trace on
# screen, so a live audience sees "a file vanished" and has to take the rest on
# trust. This script pauses at each stage and prints the artefact that proves
# what just happened -- the breach signal, the forensic capture taken *before*
# destruction, the container identity change, and the manifest the restore was
# verified against.
#
# Prerequisites (two other terminals, each after `source .venv/bin/activate`):
#     T1:  python run_argus.py watch
#     T2:  python run_argus.py run
#
# Run:      bash lab/demo.sh
# No pauses (for a recording or a smoke test):   PAUSE=0 bash lab/demo.sh
# ---------------------------------------------------------------------------
set -u
cd "$(dirname "$0")/.." || exit 1

PAUSE=${PAUSE:-1}
ATTACK_FILE="uploads_shell.php"
WEBROOT="runtime/webroot"

blue()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
pause() { [ "$PAUSE" = "1" ] && { printf '\n\033[0;33m   [Enter to continue]\033[0m'; read -r _; } || true; }

py() { python - "$@"; }

# --- preflight -------------------------------------------------------------
pgrep -f "run_argus.py watch" >/dev/null || { red "watcher not running -- start it in T1: python run_argus.py watch"; exit 1; }
pgrep -f "run_argus.py run"   >/dev/null || { red "controller not running -- start it in T2: python run_argus.py run"; exit 1; }

# The controller appends every heal to the incidents CSV, so a demo run lands in the same
# file as the measured trials and quietly contaminates the dataset the results are drawn
# from. Set aside anything already there and restore it when the demo finishes.
INCIDENTS="results/incidents.csv"
STASH="results/incidents.pre-demo.csv"
if [ -f "$INCIDENTS" ]; then
  cp "$INCIDENTS" "$STASH"
  echo "  (experiment data set aside in $STASH; restored when this demo exits)"
  trap 'mv -f "$STASH" "$INCIDENTS" 2>/dev/null && echo && echo "  experiment data restored to $INCIDENTS"' EXIT
  rm -f "$INCIDENTS"
fi

rm -f "$WEBROOT/$ATTACK_FILE" runtime/breach.flag 2>/dev/null

# ===========================================================================
blue "STAGE 0 -- the service we are protecting"
echo "  A containerised web app (DVWA). Note the container ID; it matters later."
docker ps --filter name=argus-web --format '  container : {{.Names}}   id={{.ID}}   {{.Status}}'
BEFORE_ID=$(docker ps --filter name=argus-web --format '{{.ID}}')
printf '  health    : HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/login.php)"
printf '  web root  : %s files on disk\n' "$(find $WEBROOT -type f | wc -l)"
py <<'PY'
import json
m = json.load(open("config/golden_manifest.json"))
print(f"  baseline  : {len(m['files'])} files fingerprinted with SHA-256 (the golden manifest)")
PY
pause

# ===========================================================================
blue "STAGE 1 -- the clean clones Argus keeps on a cycle"
echo "  Every snapshot cycle the protected directory is cloned and hashed. A clone"
echo "  is only eligible for restore if it still verifies AND matches the golden"
echo "  baseline -- that is what stops a poisoned clone being promoted."
if compgen -G "results/snapshots/*.manifest.json" >/dev/null; then
  py <<'PY'
import glob, json, os
for f in sorted(glob.glob("results/snapshots/*.manifest.json"))[-3:]:
    m = json.load(open(f))
    print(f"  clone {os.path.basename(f).replace('.manifest.json','')}: "
          f"{len(m['files'])} files, verified-clean={m['clean']}")
PY
else
  echo "  (no clone taken yet -- the first one lands on the next cycle)"
fi
pause

# ===========================================================================
blue "STAGE 2 -- THE ATTACK"
echo "  A webshell upload leaves one observable trace: an unexpected .php file"
echo "  appears in the web root. That is exactly what we reproduce (inert marker,"
echo "  no payload, no code execution)."
echo
echo "  \$ echo '<?php ... ?>' > $WEBROOT/$ATTACK_FILE"
# Record the injection time first, exactly as the experiment harness does, so the
# controller can attribute the detection to a known attack and report a real MTTD
# instead of logging it as an unattributed (false-positive) detection.
py <<'PY'
import json, time, pathlib
p = pathlib.Path("runtime/attack_marker.json")
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps({"t_attack": time.time(), "scenario": "webshell"}))
PY
echo '<?php /* ARGUS-LAB BENIGN MARKER -- stands in for a webshell */ ?>' > "$WEBROOT/$ATTACK_FILE"
T_ATTACK=$(date +%s.%N)
green "  planted at $(date +%H:%M:%S) -- the site is now serving an attacker file:"
printf '  http://localhost:8080/%s -> HTTP %s\n' "$ATTACK_FILE" \
  "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/$ATTACK_FILE)"
pause

# ===========================================================================
blue "STAGE 3 -- DETECTION (watch it happen)"
echo "  The monitor re-hashes the web root every 2s and compares against the"
echo "  golden manifest. Waiting for it to raise the breach signal..."
for _ in $(seq 1 40); do
  [ -f runtime/breach.flag ] && break
  sleep 0.5
done
if [ -f runtime/breach.flag ]; then
  green "  breach signal raised after $(py <<PY
print(f"{$(date +%s.%N) - $T_ATTACK:.2f}s")
PY
)"
  echo "  runtime/breach.flag contains:"
  sed 's/^/      /' runtime/breach.flag
else
  echo "  (signal already consumed by the controller -- it healed that fast)"
fi
pause

# ===========================================================================
blue "STAGE 4 -- HEALING (forensics -> isolate -> destroy -> restore -> promote)"
echo "  Waiting for the controller to finish the sequence..."
for _ in $(seq 1 90); do
  NOW_ID=$(docker ps --filter name=argus-web --format '{{.ID}}')
  [ -n "$NOW_ID" ] && [ "$NOW_ID" != "$BEFORE_ID" ] && break
  sleep 1
done
sleep 3
AFTER_ID=$(docker ps --filter name=argus-web --format '{{.ID}}')
pause

# ===========================================================================
blue "STAGE 5 -- PROOF 1: evidence was preserved BEFORE anything was destroyed"
CASE=$(ls -1t results/forensics 2>/dev/null | head -1)
if [ -n "${CASE:-}" ]; then
  echo "  forensic case: results/forensics/$CASE"
  py <<PY
import json, pathlib
p = pathlib.Path("results/forensics/$CASE/forensic_manifest.json")
if p.exists():
    m = json.load(open(p))
    print(f"  captured {len(m['files'])} files, marked clean={m['clean']}")
    hit = [f for f in m['files'] if "$ATTACK_FILE" in f]
    print(f"  attacker artefact preserved as evidence: {hit if hit else 'NOT FOUND'}")
PY
else
  echo "  (no forensic case found)"
fi
pause

# ===========================================================================
blue "STAGE 6 -- PROOF 2: this is a DIFFERENT container (moving-target defence)"
echo "  before attack : $BEFORE_ID"
echo "  after heal    : $AFTER_ID"
if [ "$BEFORE_ID" != "$AFTER_ID" ]; then
  green "  the compromised instance was destroyed and replaced from the golden image"
else
  red   "  container unchanged -- heal may not have completed"
fi
pause

# ===========================================================================
blue "STAGE 7 -- PROOF 3: the site is clean and healthy again"
printf '  attacker file: %s\n' "$([ -f "$WEBROOT/$ATTACK_FILE" ] && echo 'STILL PRESENT' || echo 'removed from the web root')"
printf '  http://localhost:8080/%s -> HTTP %s (404 = gone)\n' "$ATTACK_FILE" \
  "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/$ATTACK_FILE)"
printf '  http://localhost:8080/login.php     -> HTTP %s (200 = service restored)\n' \
  "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/login.php)"
pause

# ===========================================================================
blue "STAGE 8 -- PROOF 4: what it cost, measured"
py <<'PY'
import csv, pathlib
p = pathlib.Path("results/incidents.csv")
if p.exists():
    rows = list(csv.DictReader(open(p)))
    if rows:
        r = rows[-1]
        print(f"  incident      : {r['incident_id']}")
        print(f"  detected by   : {r['detected_by']}")
        print(f"  MTTD          : {r['mttd'] or 'n/a (no attack marker -> logged as false positive)'}")
        print(f"  MTTR          : {r['mttr']}s")
        print(f"  restored from : {r['restore_source']}")
PY
blue "Summary of what the audience just saw"
cat <<'TXT'
  1. an attacker file appeared in the web root and was live over HTTP
  2. file-integrity monitoring detected it within seconds, unaided
  3. evidence was captured BEFORE the compromised instance was destroyed
  4. a fresh instance was built from a known-good baseline (new container ID)
  5. every restored file was verified against a SHA-256 manifest before promotion
  6. the service returned healthy, with detection and recovery times recorded
TXT
