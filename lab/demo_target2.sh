#!/bin/bash
# ---------------------------------------------------------------------------
# demo_target2.sh -- narrated attack -> heal cycle against MiniGallery (Target #2).
#
# This is the twin of lab/demo.sh, but for the second demo target
# (lab/target2_app/), and the attack here is a REAL exploit: a genuine HTTP
# multipart upload to the app's actual (unfixed) upload.php vulnerability,
# not a simulated file write. That is the point of this second target --
# lab/demo.sh's DVWA attack reproduces an observable; this one is the real
# CWE-434 request/response round trip.
#
# Prerequisites (two other terminals, each after `source .venv/bin/activate`):
#     T1:  python run_argus.py --config config/target2.yaml watch
#     T2:  python run_argus.py --config config/target2.yaml run
#
# Run:      bash lab/demo_target2.sh
# No pauses (for a recording or a smoke test):   PAUSE=0 bash lab/demo_target2.sh
# ---------------------------------------------------------------------------
set -u
cd "$(dirname "$0")/.." || exit 1

PAUSE=${PAUSE:-1}
CFG="config/target2.yaml"
PORT=8081
CONTAINER="argus-target2"
WEBROOT="runtime/webroot2"
ATTACK_FILE="pwn.php"

blue()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
pause() { [ "$PAUSE" = "1" ] && { printf '\n\033[0;33m   [Enter to continue]\033[0m'; read -r _; } || true; }

py_cfg() {
  python - "$@" <<'PY'
import sys
sys.path.insert(0, ".")
from argus.config import ArgusConfig
cfg = ArgusConfig.load("config/target2.yaml")
print(getattr(cfg, sys.argv[1]))
PY
}

# --- preflight -------------------------------------------------------------
pgrep -f "run_argus.py --config $CFG watch" >/dev/null || { red "watcher not running -- start it in T1: python run_argus.py --config $CFG watch"; exit 1; }
pgrep -f "run_argus.py --config $CFG run"   >/dev/null || { red "controller not running -- start it in T2: python run_argus.py --config $CFG run"; exit 1; }

INCIDENTS="results/incidents2.csv"
STASH="results/incidents2.pre-demo.csv"
if [ -f "$INCIDENTS" ]; then
  cp "$INCIDENTS" "$STASH"
  echo "  (target-2 experiment data set aside in $STASH; restored when this demo exits)"
  trap 'mv -f "$STASH" "$INCIDENTS" 2>/dev/null && echo && echo "  target-2 experiment data restored to $INCIDENTS"' EXIT INT TERM
  rm -f "$INCIDENTS"
else
  trap 'rm -f "$INCIDENTS" && echo && echo "  demo incident removed (no prior experiment data existed)"' EXIT INT TERM
fi

rm -f "$WEBROOT/uploads/$ATTACK_FILE" runtime/breach2.flag 2>/dev/null

# ===========================================================================
blue "STAGE 0 -- the second target we are protecting: MiniGallery"
echo "  A small PHP app we wrote ourselves (lab/target2_app/), NOT DVWA."
echo "  It has a real, unfixed vulnerability: upload.php accepts any file"
echo "  with no validation and saves it into the web-served uploads/ dir."
docker ps --filter name=$CONTAINER --format '  container : {{.Names}}   id={{.ID}}   {{.Status}}'
BEFORE_ID=$(docker ps --filter name=$CONTAINER --format '{{.ID}}')
printf '  health    : HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:$PORT/index.php)"
printf '  web root  : %s files on disk\n' "$(find $WEBROOT -type f | wc -l)"
pause

# ===========================================================================
blue "STAGE 1 -- config diff: this is the ONLY thing different from DVWA"
echo "  Same controller code, zero changes to argus/. Just a second config file:"
diff <(grep -v '^#\|^$' config/argus.yaml) <(grep -v '^#\|^$' config/target2.yaml) | head -20
pause

# ===========================================================================
blue "STAGE 2 -- THE ATTACK: a real HTTP exploit of upload.php"
echo "  Uploading an inert marker file via a genuine multipart POST request --"
echo "  the actual request/response round trip a real attacker would send."
echo
echo "  \$ curl -F 'upload=@pwn.php' http://localhost:$PORT/upload.php"
TMPFILE=$(mktemp --suffix=.php)
echo '<?php /* ARGUS-LAB BENIGN MARKER -- inert, no functionality, stands in for a webshell */ ?>' > "$TMPFILE"
T_ATTACK=$(date +%s.%N)
# Tell the (separate) controller process when the attack began, exactly as the experiment
# harness does, so the incident gets a measurable MTTD instead of an unattributed one.
# Written atomically: the controller polls this file.
mkdir -p runtime
printf '{"t_attack": %s, "scenario": "upload"}' "$T_ATTACK" > runtime/attack_marker2.json.tmp   && mv -f runtime/attack_marker2.json.tmp runtime/attack_marker2.json
curl -s -o /dev/null -F "upload=@${TMPFILE};filename=${ATTACK_FILE}" "http://localhost:$PORT/upload.php"
rm -f "$TMPFILE"
green "  uploaded at $(date +%H:%M:%S) -- the attacker's file is now live and being served:"
printf '  http://localhost:%s/uploads/%s -> HTTP %s\n' "$PORT" "$ATTACK_FILE" \
  "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:$PORT/uploads/$ATTACK_FILE)"
pause

# ===========================================================================
blue "STAGE 3 -- DETECTION"
echo "  Waiting for the target-2 watcher to raise the breach signal..."
for _ in $(seq 1 40); do
  [ -f runtime/breach2.flag ] && break
  sleep 0.5
done
if [ -f runtime/breach2.flag ]; then
  green "  breach signal raised after $(python -c "print(f'{$(date +%s.%N) - $T_ATTACK:.2f}s')")"
  sed 's/^/      /' runtime/breach2.flag
else
  echo "  (signal already consumed by the controller -- it healed that fast)"
fi
pause

# ===========================================================================
blue "STAGE 4 -- HEALING"
echo "  Waiting for the controller to finish forensics -> isolate -> destroy ->"
echo "  restore -> verify -> health -> promote..."
# Wait for the heal to be RECORDED, not merely for the container id to change: the
# replacement is launched only after its files verify, then health-checked.
for _ in $(seq 1 150); do
  [ -f "$INCIDENTS" ] && [ "$(wc -l < "$INCIDENTS")" -ge 2 ] && break
  sleep 1
done
sleep 1
AFTER_ID=$(docker ps --filter name=$CONTAINER --format '{{.ID}}')
pause

# ===========================================================================
blue "STAGE 5 -- PROOF: evidence preserved, container replaced, service clean"
CASE=$(ls -1t results/forensics2 2>/dev/null | head -1)
if [ -n "${CASE:-}" ]; then
  echo "  forensic case: results/forensics2/$CASE"
  python -c "
import json
m = json.load(open('results/forensics2/$CASE/forensic_manifest.json'))
print(f'  captured {len(m[\"files\"])} files, marked clean={m[\"clean\"]}')
hit = [f for f in m['files'] if '$ATTACK_FILE' in f]
print(f'  attacker artefact preserved as evidence: {hit if hit else \"NOT FOUND\"}')"
fi
echo "  before attack : $BEFORE_ID"
echo "  after heal    : $AFTER_ID"
[ "$BEFORE_ID" != "$AFTER_ID" ] && green "  the compromised instance was destroyed and replaced from the golden image" \
                                  || red "  container unchanged -- heal may not have completed"
printf '  http://localhost:%s/uploads/%s -> HTTP %s (404 = gone)\n' "$PORT" "$ATTACK_FILE" \
  "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:$PORT/uploads/$ATTACK_FILE)"
printf '  http://localhost:%s/index.php -> HTTP %s (200 = service restored)\n' "$PORT" \
  "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:$PORT/index.php)"

CASE2=$(ls -1t results/incidents2.csv 2>/dev/null)
if [ -n "${CASE2:-}" ]; then
  python -c "
import csv
rows = list(csv.DictReader(open('results/incidents2.csv')))
if rows:
    r = rows[-1]
    print(f'  MTTD={r[\"mttd\"]}s  MTTR={r[\"mttr\"]}s  restored from={r[\"restore_source\"]}')"
fi

blue "Summary: same controller, a different real application, one config file."
