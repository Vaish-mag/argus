#!/bin/sh
# argus-quarantine.sh
# -------------------
# Wazuh active-response script. Install to:
#   /var/ossec/active-response/bin/argus-quarantine.sh   (chmod 750, owner root:wazuh)
#
# Wazuh runs this when an argus_breach rule fires. Its ONLY job is to signal Argus by
# writing a breach flag; all healing is done by the Argus controller. Keeping this
# script trivial means the detection->healing boundary is auditable.
#
# Wazuh passes the triggering alert on stdin (JSON). We record a short reason.

ARGUS_HOME="${ARGUS_HOME:-/home/$(logname 2>/dev/null || echo user)/argus}"
FLAG="${ARGUS_HOME}/runtime/breach.flag"

mkdir -p "$(dirname "$FLAG")"
# read the alert (best effort) and write a one-line reason
REASON=$(head -c 400 2>/dev/null || echo "wazuh active-response")
printf 'wazuh active-response %s :: %s\n' "$(date -u +%FT%TZ)" "$REASON" > "$FLAG"
exit 0
